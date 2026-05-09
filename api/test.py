"""
api/test.py — Vercel serverless function.

POST /api/test  body: {"portal": "http://HOST:PORT", "mac": "00:1A:79:XX:XX:XX"}
GET  /api/test?portal=http://HOST:PORT&mac=00:1A:79:XX:XX:XX

Full portal inspector: runs the complete Stalker auth flow and
returns portal health, subscriber info, and content counts.
"""

from http.server import BaseHTTPRequestHandler
import json, time, re
import urllib.request, urllib.error
from urllib.parse import urlparse, parse_qs

# Re-use all shared helpers from convert.py — single source of truth
from convert import (
    build_headers, portal_url, http_get,
    mac_to_serial, mac_to_device_id, mac_to_signature,
    resolve_portal_base, _is_ssrf_safe,
    fetch_genres,
)


# ── helpers local to test only ─────────────────────────────────────────────────

def count_items(base, mac, token, media_type):
    """Fetch page 1 and return total_items reported by portal."""
    t = {'live': 'itv', 'vod': 'vod', 'series': 'series'}.get(media_type, 'itv')
    try:
        url = portal_url(base, 'get_ordered_list',
            type=t, genre='*', force_ch_link_check=0, fav=0,
            sortby='number', hd=0, p=1,
            JsHttpRequest=f'{int(time.time() * 1000)}-xml')
        js = http_get(url, build_headers(mac, token)).get('js', {})
        if isinstance(js, list):
            return len(js)
        return int(js.get('total_items') or js.get('total') or 0)
    except Exception:
        return -1


# ── Vercel handler ─────────────────────────────────────────────────────────────

class handler(BaseHTTPRequestHandler):

    def log_message(self, *a): pass

    def _cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
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

    def do_GET(self):
        qs     = parse_qs(urlparse(self.path).query)
        portal = (qs.get('portal', [''])[0]).strip().rstrip('/')
        mac    = (qs.get('mac',    [''])[0]).strip()
        self._handle(portal, mac)

    def do_POST(self):
        """Frontend sends POST with JSON body {portal, mac}."""
        length = int(self.headers.get('Content-Length', 0))
        try:
            body   = json.loads(self.rfile.read(length) if length else b'{}')
        except Exception:
            return self.send_json(400, {'ok': False, 'error': 'Invalid JSON body'})
        portal = str(body.get('portal', '')).strip().rstrip('/')
        mac    = str(body.get('mac',    '')).strip()
        self._handle(portal, mac)

    def _handle(self, portal, mac):
        if not portal:
            return self.send_json(400, {'ok': False, 'error': 'Missing portal param'})

        if mac and not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac):
            return self.send_json(400, {'ok': False, 'error': f'Invalid MAC: {mac}'})

        # SSRF guard
        ssrf_ok, ssrf_reason = _is_ssrf_safe(portal)
        if not ssrf_ok:
            return self.send_json(400, {'ok': False, 'error': f'Blocked portal URL: {ssrf_reason}'})

        t0 = time.time()

        # ── Step 1: resolve portal path + reachability ────────────────────────
        try:
            if mac:
                resolved = resolve_portal_base(portal, mac)
            else:
                # No MAC — just try /portal.php for a basic reachability check
                resolved = portal

            probe_url = portal_url(resolved, 'handshake', type='stb', prehash=0)
            req = urllib.request.Request(
                probe_url,
                headers={'User-Agent': 'stalker-to-m3u/1.0'}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                reach_status = resp.status
        except urllib.error.HTTPError as e:
            reach_status = e.code
        except Exception as e:
            return self.send_json(200, {
                'ok': False, 'reachable': False,
                'error': str(e),
                'ms': int((time.time() - t0) * 1000),
            })

        reach_ms = int((time.time() - t0) * 1000)
        result = {
            'ok':          True,
            'reachable':   True,
            'status':      reach_status,
            'ms':          reach_ms,
            'resolved_path': resolved,
        }

        # ── Step 2: full auth flow (only if MAC provided) ─────────────────
        if not mac:
            result['note'] = 'Provide mac param for full portal inspection'
            return self.send_json(200, result)

        try:
            # Handshake (resolve_portal_base already called above)
            t1   = time.time()
            data = http_get(
                portal_url(resolved, 'handshake', type='stb', prehash=0),
                build_headers(mac)
            )
            token = data.get('js', {}).get('token') or data.get('token')
            if not token:
                raise RuntimeError('No token in handshake response')
            result['handshake_ms'] = int((time.time() - t1) * 1000)
            result['token_prefix'] = token[:8] + '…'

            # Profile
            t2      = time.time()
            profile = http_get(
                portal_url(resolved, 'get_profile',
                    hd=1, ver='ImageDescription: 0.2.18-r14-pub-250;',
                    num_banks=2, sn=mac_to_serial(mac), stb_type='MAG200',
                    image_version=218, video_out='hdmi',
                    device_id=mac_to_device_id(mac), device_id2=mac_to_device_id(mac),
                    signature=mac_to_signature(mac), auth_second_step=1,
                    hw_version='1.7-BD-00', not_valid_token=0,
                    client_type='STB', hw_version_2=mac_to_serial(mac)),
                build_headers(mac, token)
            ).get('js', {})
            result['profile_ms'] = int((time.time() - t2) * 1000)
            result['profile'] = {
                'name':          profile.get('name') or profile.get('login') or '',
                'tariff':        profile.get('tariff_expired_date') or profile.get('tariff') or '',
                'expiry':        profile.get('expire_billing_date') or '',
                'account_info':  profile.get('account_info') or '',
                'phone':         profile.get('phone') or '',
                'status':        profile.get('status') or '',
                'stb_type':      profile.get('stb_type') or 'MAG200',
                'image_version': profile.get('image_version') or '',
            }

            # Content counts
            t3 = time.time()
            result['content'] = {
                'live':   count_items(resolved, mac, token, 'live'),
                'vod':    count_items(resolved, mac, token, 'vod'),
                'series': count_items(resolved, mac, token, 'series'),
            }
            result['content_ms'] = int((time.time() - t3) * 1000)
            result['total_ms']   = int((time.time() - t0) * 1000)

            # Map fields to what the frontend inspector panel expects
            info = profile
            result['token'] = token
            result['info']  = {
                'name':        info.get('name') or info.get('login') or '',
                'login':       info.get('login') or '',
                'password':    info.get('password') or '',
                'email':       info.get('email') or '',
                'phone':       info.get('phone') or '',
                'ip':          info.get('ip') or '',
                'mac':         mac,
                'status':      info.get('status') or '',
                'tariff':      info.get('tariff_plan') or info.get('tariff') or '',
                'start_date':  info.get('start_date') or '',
                'end_date':    info.get('expire_billing_date') or info.get('tariff_expired_date') or '',
                'server_time': info.get('cur_time') or '',
                'services':    info.get('services') or '',
                'keep_alive':  str(info.get('keep_alive') or ''),
            }
            result['counts'] = result['content']
            result['account'] = profile

        except Exception as e:
            result['auth_error'] = str(e)
            result['ok'] = False
            result['error'] = str(e)

        return self.send_json(200, result)
