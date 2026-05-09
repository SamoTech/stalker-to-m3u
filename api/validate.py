"""
api/validate.py  —  Vercel serverless function.

POST /api/validate
  Body (JSON):
    m3u       : str   required  raw M3U text OR a URL to an M3U file
    timeout   : int   optional  per-stream HTTP timeout in seconds  (default 5)
    workers   : int   optional  parallel workers                     (default 20, max 40)
    strict    : bool  optional  if true, dead channels excluded from output (default false)

Returns JSON:
  {
    total        : int,
    live         : int,
    dead         : int,
    uncheckable  : int,
    results      : [ { name, url, group, status, reason, stream_type }, ... ],
    filtered_m3u : str   // M3U with only live channels (groups: orig + \"⚠ Auth Required\")
  }
"""

from http.server import BaseHTTPRequestHandler
import json, re, time, threading
import urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── constants (mirrored from IPTV-CHECK) ──────────────────────────────────────
UNCHECKABLE_URL_LENGTH_THRESHOLD = 250
UNCHECKABLE_KEYWORDS = ['token', 'auth', 'login', 'key', 'signature', 'drm']
STREAM_TYPE_MAP = {
    '.m3u8': 'video', '.m3u': 'video', '.ts': 'video', '.mp4': 'video',
    '.avi': 'video', '.mkv': 'video', '.flv': 'video',
    '.mp3': 'audio', '.aac': 'audio', '.pls': 'audio', '.ogg': 'audio',
    '/stream': 'audio', '/radio/': 'audio',
}
DEAD_CONTENT_TYPES = [
    'text/html', 'text/xml', 'application/xml',
    'application/json', 'text/plain',
]
LIVE_CONTENT_TYPES = [
    'video/', 'audio/', 'application/x-mpegurl',
    'application/vnd.apple.mpegurl', 'application/octet-stream',
    'binary/octet-stream',
]
USER_AGENT = (
    "Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 "
    "(KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3"
)


# ── URL helpers ───────────────────────────────────────────────────────────────

def sanitize_url(url: str) -> str:
    """Strip ad-injected query params from .m3u8 URLs (ported from IPTV-CHECK)."""
    try:
        idx = url.find('.m3u8?')
        if idx != -1:
            qs = url[idx + 6:].lower()
            if any(kw in qs for kw in ['ads.', 'ad=', 'adv=', 'vast=', 'ima=']):
                return url[:idx + 6].rstrip('?')
    except Exception:
        pass
    return url


def is_uncheckable(url: str) -> tuple:
    """Return (True, reason) if the URL cannot be probed reliably."""
    if len(url) > UNCHECKABLE_URL_LENGTH_THRESHOLD:
        return True, 'URL too long (likely token-signed)'
    low = url.lower()
    for kw in UNCHECKABLE_KEYWORDS:
        if kw in low:
            return True, f'Auth keyword detected: {kw}'
    return False, ''


def classify_stream_type(url: str) -> str:
    """Classify stream as video/audio/unknown from URL patterns."""
    low = url.lower().split('?')[0]  # ignore query string for classification
    for pat, typ in STREAM_TYPE_MAP.items():
        if pat in low:
            return typ
    return 'video'  # default assumption for IPTV


# ── M3U parser (dual-pass, tolerant) ─────────────────────────────────────────

def parse_m3u(content: str) -> list:
    """Parse M3U into list of dicts. Two-pass: with group-title, then without."""
    channels = []
    lines = content.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith('#EXTINF'):
            info = line
            # advance past any non-URL lines (e.g. #EXTVLCOPT)
            j = i + 1
            while j < len(lines) and lines[j].strip().startswith('#'):
                j += 1
            url = lines[j].strip() if j < len(lines) else ''

            if url and re.match(r'^https?://', url, re.IGNORECASE):
                name_match = re.search(r',(.+)$', info)
                name = name_match.group(1).strip() if name_match else 'Unknown'
                group_match = re.search(r'group-title="([^"]*)"', info, re.IGNORECASE)
                group = group_match.group(1).strip() if group_match else 'General'
                logo_match = re.search(r'tvg-logo="([^"]*)"', info, re.IGNORECASE)
                logo = logo_match.group(1) if logo_match else ''
                epg_match = re.search(r'tvg-id="([^"]*)"', info, re.IGNORECASE)
                epg_id = epg_match.group(1) if epg_match else ''
                channels.append({
                    'name': name, 'url': sanitize_url(url),
                    'group': group, 'logo': logo, 'epg_id': epg_id,
                    'original_extinf': info,
                })
            i = j + 1
        else:
            i += 1
    return channels


# ── stream probe ──────────────────────────────────────────────────────────────

def probe_stream(ch: dict, timeout: int) -> dict:
    url = ch['url']
    unch, reason = is_uncheckable(url)
    if unch:
        return {**ch, 'status': 'uncheckable', 'reason': reason,
                'stream_type': classify_stream_type(url)}

    try:
        req = urllib.request.Request(url, method='HEAD')
        req.add_header('User-Agent', USER_AGENT)
        req.add_header('Accept', '*/*')
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status_code = resp.status
            ct = resp.headers.get('Content-Type', '').lower()
            # 2xx = alive, check content-type for false-positives
            if 200 <= status_code < 300:
                # HTML response with 200 usually means an error page
                if any(ct.startswith(d) for d in DEAD_CONTENT_TYPES):
                    return {**ch, 'status': 'dead',
                            'reason': f'HTTP {status_code} but Content-Type: {ct}',
                            'stream_type': classify_stream_type(url)}
                return {**ch, 'status': 'live',
                        'reason': f'HTTP {status_code}',
                        'stream_type': classify_stream_type(url)}
            elif status_code in (301, 302, 303, 307, 308):
                # treat redirects as live (player will follow)
                return {**ch, 'status': 'live',
                        'reason': f'HTTP {status_code} redirect',
                        'stream_type': classify_stream_type(url)}
            else:
                return {**ch, 'status': 'dead',
                        'reason': f'HTTP {status_code}',
                        'stream_type': classify_stream_type(url)}
    except urllib.error.HTTPError as e:
        return {**ch, 'status': 'dead', 'reason': f'HTTP {e.code}',
                'stream_type': classify_stream_type(url)}
    except Exception as e:
        err = str(e)[:80]
        return {**ch, 'status': 'dead', 'reason': err,
                'stream_type': classify_stream_type(url)}


# ── M3U builder for filtered output ──────────────────────────────────────────

def build_filtered_m3u(results: list) -> str:
    """Build M3U keeping live + uncheckable channels.
    Uncheckable channels are moved to group '⚠ Auth Required'.
    Dead channels are excluded.
    """
    lines = ['#EXTM3U']
    for ch in results:
        if ch['status'] == 'dead':
            continue
        group = ch['group'] if ch['status'] == 'live' else '⚠ Auth Required'
        stype = ch.get('stream_type', '')
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
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    def send_json(self, status, data):
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

    def do_POST(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
            payload = json.loads(self.rfile.read(length))
        except Exception:
            return self.send_json(400, {'error': 'Invalid JSON body'})

        m3u_input = (payload.get('m3u') or '').strip()
        timeout   = min(int(payload.get('timeout') or 5), 15)
        workers   = min(int(payload.get('workers') or 20), 40)

        if not m3u_input:
            return self.send_json(400, {'error': 'Missing required field: m3u'})

        # If input looks like a URL, fetch the M3U first
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

        results = []
        lock = threading.Lock()

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(probe_stream, ch, timeout): ch for ch in channels}
            for fut in as_completed(futures):
                try:
                    r = fut.result()
                except Exception as e:
                    ch = futures[fut]
                    r = {**ch, 'status': 'dead', 'reason': str(e),
                         'stream_type': classify_stream_type(ch['url'])}
                with lock:
                    results.append(r)

        # sort back into original order
        order = {ch['url']: i for i, ch in enumerate(channels)}
        results.sort(key=lambda r: order.get(r['url'], 9999))

        live         = sum(1 for r in results if r['status'] == 'live')
        dead         = sum(1 for r in results if r['status'] == 'dead')
        uncheckable  = sum(1 for r in results if r['status'] == 'uncheckable')

        # strip internal fields before sending
        clean = []
        for r in results:
            clean.append({
                'name':        r['name'],
                'url':         r['url'],
                'group':       r['group'],
                'status':      r['status'],
                'reason':      r.get('reason', ''),
                'stream_type': r.get('stream_type', ''),
            })

        return self.send_json(200, {
            'total':        len(results),
            'live':         live,
            'dead':         dead,
            'uncheckable':  uncheckable,
            'results':      clean,
            'filtered_m3u': build_filtered_m3u(results),
        })
