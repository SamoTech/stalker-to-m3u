"""
api/validate.py  —  Vercel serverless function

GET  /api/validate  — health check
POST /api/validate  — probe M3U stream URLs

POST body (JSON):
  m3u         : str   required  raw M3U text OR a URL to an M3U file
  timeout     : int   optional  per-stream HTTP timeout in seconds  (default 5)
  workers     : int   optional  parallel workers                     (default 20, max 40)
  existing_m3u: str   optional  existing M3U; matching URLs returned as status='cached'

Response:
  { total, live, dead, uncheckable, cached, results, filtered_m3u }
"""

from http.server import BaseHTTPRequestHandler
import json, re, threading
import urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

from stalker import sanitize_url, classify_stream_type, is_uncheckable

VERSION = '1.2'

DEAD_CONTENT_TYPES = [
    'text/html', 'text/xml', 'application/xml',
    'application/json', 'text/plain',
]

USER_AGENT = (
    'Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 '
    '(KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3'
)


# ── M3U parser ────────────────────────────────────────────────────────────────

def parse_m3u(content: str) -> list:
    channels = []
    lines = content.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith('#EXTINF'):
            info = line
            j = i + 1
            while j < len(lines) and lines[j].strip().startswith('#'):
                j += 1
            url = lines[j].strip() if j < len(lines) else ''
            if url and re.match(r'^https?://', url, re.IGNORECASE):
                name  = (re.search(r',(.+)$', info) or type('', (), {'group': lambda s, n: 'Unknown'})()).group(1)
                if callable(name):
                    name = name.strip() if isinstance(name, str) else 'Unknown'
                else:
                    name = name.strip() if isinstance(name, str) else 'Unknown'
                name_m  = re.search(r',(.+)$', info)
                name    = name_m.group(1).strip() if name_m else 'Unknown'
                group_m = re.search(r'group-title="([^"]*)"', info, re.IGNORECASE)
                group   = group_m.group(1).strip() if group_m else 'General'
                logo_m  = re.search(r'tvg-logo="([^"]*)"', info, re.IGNORECASE)
                logo    = logo_m.group(1) if logo_m else ''
                epg_m   = re.search(r'tvg-id="([^"]*)"', info, re.IGNORECASE)
                epg_id  = epg_m.group(1) if epg_m else ''
                channels.append({
                    'name': name, 'url': sanitize_url(url),
                    'group': group, 'logo': logo, 'epg_id': epg_id,
                    'original_extinf': info,
                })
            i = j + 1
        else:
            i += 1
    return channels


# ── Stream probe ──────────────────────────────────────────────────────────────

def probe_stream(ch: dict, timeout: int) -> dict:
    url  = ch['url']
    unch = is_uncheckable(url)
    if unch:
        return {**ch, 'status': 'uncheckable',
                'reason': 'Token/auth URL — skipped',
                'stream_type': classify_stream_type(url)}
    try:
        req = urllib.request.Request(url, method='HEAD')
        req.add_header('User-Agent', USER_AGENT)
        req.add_header('Accept', '*/*')
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            sc = resp.status
            ct = resp.headers.get('Content-Type', '').lower()
        if 200 <= sc < 300:
            if any(ct.startswith(d) for d in DEAD_CONTENT_TYPES):
                return {**ch, 'status': 'dead',
                        'reason': f'HTTP {sc} but Content-Type: {ct}',
                        'stream_type': classify_stream_type(url)}
            return {**ch, 'status': 'live', 'reason': f'HTTP {sc}',
                    'stream_type': classify_stream_type(url)}
        if sc in (301, 302, 303, 307, 308):
            return {**ch, 'status': 'live', 'reason': f'HTTP {sc} redirect',
                    'stream_type': classify_stream_type(url)}
        return {**ch, 'status': 'dead', 'reason': f'HTTP {sc}',
                'stream_type': classify_stream_type(url)}
    except urllib.error.HTTPError as e:
        return {**ch, 'status': 'dead', 'reason': f'HTTP {e.code}',
                'stream_type': classify_stream_type(url)}
    except Exception as e:
        return {**ch, 'status': 'dead', 'reason': str(e)[:80],
                'stream_type': classify_stream_type(url)}


# ── M3U output builder ────────────────────────────────────────────────────────

def build_filtered_m3u(results: list) -> str:
    lines = ['#EXTM3U']
    for ch in results:
        if ch['status'] == 'dead':
            continue
        group = ('\u26a0 Auth Required'
                 if ch['status'] == 'uncheckable'
                 else ch['group'])
        stype    = ch.get('stream_type', '')
        type_tag = f' tvg-type="{stype}"' if stype else ''
        lines.append(
            f'#EXTINF:-1 tvg-id="{ch["epg_id"]}" tvg-name="{ch["name"]}" '
            f'tvg-logo="{ch["logo"]}" group-title="{group}"{type_tag},{ch["name"]}'
        )
        lines.append(ch['url'])
    return '\n'.join(lines) + '\n'


# ── Vercel handler ────────────────────────────────────────────────────────────

class handler(BaseHTTPRequestHandler):

    def log_message(self, *a): pass

    def _cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    def send_json(self, status: int, data: dict):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        self.send_json(200, {
            'status': 'ok', 'version': VERSION,
            'endpoints': [
                {'method': 'GET',  'path': '/api/validate', 'description': 'Health check'},
                {'method': 'POST', 'path': '/api/validate', 'description': 'Probe M3U stream URLs'},
                {'method': 'POST', 'path': '/api/convert',  'description': 'Convert Stalker portal to M3U'},
                {'method': 'POST', 'path': '/api/test',     'description': 'Inspect Stalker portal'},
            ],
        })

    def do_POST(self):
        try:
            length  = int(self.headers.get('Content-Length', 0))
            payload = json.loads(self.rfile.read(length))
        except Exception:
            return self.send_json(400, {'error': 'Invalid JSON body'})

        m3u_input    = str(payload.get('m3u') or '').strip()
        timeout      = min(int(payload.get('timeout') or 5), 15)
        workers      = min(int(payload.get('workers') or 20), 40)
        existing_m3u = str(payload.get('existing_m3u') or '').strip()

        if not m3u_input:
            return self.send_json(400, {'error': 'Missing required field: m3u'})

        # Fetch M3U from URL if needed
        if re.match(r'^https?://', m3u_input, re.IGNORECASE):
            try:
                req = urllib.request.Request(m3u_input)
                req.add_header('User-Agent', USER_AGENT)
                with urllib.request.urlopen(req, timeout=20) as resp:
                    m3u_input = resp.read().decode('utf-8', errors='replace')
            except Exception as e:
                return self.send_json(502, {'error': f'Could not fetch M3U URL: {e}'})

        channels = parse_m3u(m3u_input)
        if not channels:
            return self.send_json(400, {'error': 'No channels found in M3U input'})

        known_live_urls: set = set()
        if existing_m3u:
            known_live_urls = {ch['url'] for ch in parse_m3u(existing_m3u)}

        results = []
        lock    = threading.Lock()

        def process(ch):
            if ch['url'] in known_live_urls:
                return {**ch, 'status': 'cached',
                        'reason': 'Already in existing playlist',
                        'stream_type': classify_stream_type(ch['url'])}
            return probe_stream(ch, timeout)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(process, ch): ch for ch in channels}
            for fut in as_completed(futures):
                try:
                    r = fut.result()
                except Exception as e:
                    ch = futures[fut]
                    r  = {**ch, 'status': 'dead', 'reason': str(e)[:80],
                          'stream_type': classify_stream_type(ch.get('url', ''))}
                with lock:
                    results.append(r)

        url_order = {ch['url']: idx for idx, ch in enumerate(channels)}
        results.sort(key=lambda r: url_order.get(r['url'], 9999))

        counts = {'live': 0, 'dead': 0, 'uncheckable': 0, 'cached': 0}
        for r in results:
            counts[r['status']] = counts.get(r['status'], 0) + 1

        self.send_json(200, {
            'total':        len(results),
            'live':         counts['live'],
            'dead':         counts['dead'],
            'uncheckable':  counts['uncheckable'],
            'cached':       counts['cached'],
            'results':      results,
            'filtered_m3u': build_filtered_m3u(results),
        })
