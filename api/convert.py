"""
api/convert.py  —  Vercel serverless function  POST /api/convert

Body (JSON):
  portal      : str   required  http://HOST:PORT
  mac         : str   required  00:1A:79:XX:XX:XX
  types       : list  optional  ["live","vod","series"]  default ["live"]
  maxPages    : int   optional  default 50
  epgUrl      : str   optional
  format      : str   optional  "m3u" | "json"           default "m3u"
  skipKnown   : str   optional  existing M3U text for recheck / diff mode

Response modes
  format=m3u  — buffered M3U file download
  format=json — NDJSON stream (one JSON object per line)

NDJSON event types
  {"event":"meta",     ...}
  {"event":"profile",  "profile":{...}}
  {"event":"channel",  "count":N, "channel":{...}}
  {"event":"progress", "scope":"live"|"vod"|"series", "page":N,
                        "count":N, "typeCount":N, "estimatedTotal":N, "done":bool}
  {"event":"error",    "scope":..., "message":..., "page":N}
  {"event":"done",     "total":N, "errors":[...], "profile":{...}, "epgUrl":"..."}
"""

from http.server import BaseHTTPRequestHandler
import json, re

from stalker import (
    is_ssrf_safe, extract_known_urls,
    handshake, get_profile,
    fetch_genres, fetch_page, build_channel, fetch_all, build_m3u,
)


class handler(BaseHTTPRequestHandler):

    def log_message(self, *a): pass

    def _cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    def send_json(self, status: int, data: dict):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def send_m3u(self, content: str):
        body = content.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/x-mpegurl; charset=utf-8')
        self.send_header('Content-Disposition', 'attachment; filename="playlist.m3u"')
        self.send_header('Content-Length', str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def start_ndjson(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/x-ndjson; charset=utf-8')
        self.send_header('Cache-Control', 'no-cache, no-transform')
        self.send_header('X-Accel-Buffering', 'no')
        self._cors()
        self.end_headers()

    def emit(self, payload: dict):
        line = (json.dumps(payload, ensure_ascii=False) + '\n').encode('utf-8')
        self.wfile.write(line)
        self.wfile.flush()

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_POST(self):
        # ── Parse body ────────────────────────────────────────────────────────
        try:
            length  = int(self.headers.get('Content-Length', 0))
            payload = json.loads(self.rfile.read(length))
        except Exception:
            return self.send_json(400, {'error': 'Invalid JSON body'})

        portal     = str(payload.get('portal')    or '').strip().rstrip('/')
        mac        = str(payload.get('mac')       or '').strip()
        types      = payload.get('types')          or ['live']
        max_pgs    = int(payload.get('maxPages')   or 50)
        epg_url    = str(payload.get('epgUrl')     or '').strip()
        fmt        = str(payload.get('format')     or 'm3u').lower()
        skip_known = str(payload.get('skipKnown')  or '').strip()

        # ── Validation ────────────────────────────────────────────────────────
        if not portal or not mac:
            return self.send_json(400, {'error': 'Missing required fields: portal, mac'})
        if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac):
            return self.send_json(400, {'error': f'Invalid MAC address: {mac}'})

        ssrf_ok, ssrf_reason = is_ssrf_safe(portal)
        if not ssrf_ok:
            return self.send_json(400, {'error': f'Blocked portal URL: {ssrf_reason}'})

        known_urls = extract_known_urls(skip_known)

        # ── Auth ──────────────────────────────────────────────────────────────
        try:
            token, resolved = handshake(portal, mac)
        except Exception as e:
            return self.send_json(502, {'error': f'Handshake failed: {e}'})

        profile = {}
        try:
            profile = get_profile(resolved, mac, token)
        except Exception:
            pass

        # ── format=m3u  (buffered) ────────────────────────────────────────────
        if fmt != 'json':
            all_channels, errors = [], []
            for t in types:
                try:
                    all_channels.extend(fetch_all(resolved, mac, token, t, max_pgs, known_urls))
                except Exception as e:
                    errors.append(f'{t}: {e}')
            if not all_channels and errors:
                return self.send_json(502, {'error': 'No channels fetched', 'details': errors})
            return self.send_m3u(build_m3u(all_channels, epg_url))

        # ── format=json  (NDJSON streaming) ───────────────────────────────────
        self.start_ndjson()
        self.emit({
            'event': 'meta',
            'portal': portal, 'types': types,
            'maxPages': max_pgs, 'epgUrl': epg_url,
            'knownUrls': len(known_urls),
        })
        self.emit({'event': 'profile', 'profile': profile})

        sent   = 0
        errors = []
        estimated_total = max(len(types) * max_pgs * 20, 20)

        for media_type in types:
            genres    = fetch_genres(resolved, mac, token, media_type)
            seen: set = set()
            type_sent = 0

            for page in range(1, max_pgs + 1):
                try:
                    items, total_items = fetch_page(resolved, mac, token, media_type, page)
                except Exception as e:
                    msg = str(e)
                    errors.append(f'{media_type} p{page}: {msg}')
                    self.emit({'event': 'error', 'scope': media_type, 'message': msg, 'page': page})
                    break

                if total_items:
                    estimated_total = max(estimated_total, sent + total_items)
                if not items:
                    break

                for ch in items:
                    cid = str(ch.get('id', '') or ch.get('cmd', ''))
                    if cid in seen:
                        continue
                    seen.add(cid)
                    built = build_channel(
                        ch, genres, media_type, resolved, mac, token, known_urls, sent + 1
                    )
                    if not built:
                        continue
                    sent      += 1
                    type_sent += 1
                    self.emit({'event': 'channel', 'count': sent, 'channel': built})

                self.emit({
                    'event': 'progress', 'scope': media_type,
                    'page': page, 'count': sent, 'typeCount': type_sent,
                    'estimatedTotal': estimated_total, 'done': False,
                })

            self.emit({
                'event': 'progress', 'scope': media_type,
                'count': sent, 'typeCount': type_sent,
                'estimatedTotal': estimated_total, 'done': True,
            })

        self.emit({
            'event': 'done', 'total': sent,
            'errors': errors, 'profile': profile, 'epgUrl': epg_url,
        })
