"""
api/test.py  —  Vercel serverless function  POST /api/test

Full portal inspector: resolves path, authenticates, returns
subscriber profile and content counts.

POST body (JSON): { portal, mac }
GET  query params: ?portal=...&mac=...
"""

from http.server import BaseHTTPRequestHandler
import json, re, time
import urllib.request, urllib.error
from urllib.parse import urlparse, parse_qs

from stalker import (
    is_ssrf_safe, build_headers, portal_url, http_get,
    mac_to_serial, mac_to_device_id, mac_to_signature,
    resolve_portal_base, count_items,
)


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
        qs     = parse_qs(urlparse(self.path).query)
        portal = (qs.get('portal', [''])[0]).strip().rstrip('/')
        mac    = (qs.get('mac',    [''])[0]).strip()
        self._handle(portal, mac)

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        try:
            body = json.loads(self.rfile.read(length) if length else b'{}')
        except Exception:
            return self.send_json(400, {'ok': False, 'error': 'Invalid JSON body'})
        portal = str(body.get('portal', '')).strip().rstrip('/')
        mac    = str(body.get('mac',    '')).strip()
        self._handle(portal, mac)

    def _handle(self, portal: str, mac: str):
        if not portal:
            return self.send_json(400, {'ok': False, 'error': 'Missing portal param'})
        if mac and not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac):
            return self.send_json(400, {'ok': False, 'error': f'Invalid MAC: {mac}'})

        ssrf_ok, reason = is_ssrf_safe(portal)
        if not ssrf_ok:
            return self.send_json(400, {'ok': False, 'error': f'Blocked portal URL: {reason}'})

        t0 = time.time()

        # ── Step 1: resolve path + reachability probe ─────────────────────────
        try:
            resolved = resolve_portal_base(portal, mac) if mac else portal
            probe_url = portal_url(resolved, 'handshake', type='stb', prehash=0)
            req = urllib.request.Request(probe_url, headers=build_headers(mac or 'AA:BB:CC:DD:EE:FF'))
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

        result = {
            'ok':           True,
            'reachable':    True,
            'status':       reach_status,
            'ms':           int((time.time() - t0) * 1000),
            'resolved_path': resolved,
        }

        if not mac:
            result['note'] = 'Provide mac param for full portal inspection'
            return self.send_json(200, result)

        # ── Step 2: full auth + profile + counts ──────────────────────────────
        try:
            t1   = time.time()
            data = http_get(
                portal_url(resolved, 'handshake', type='stb', prehash=0),
                build_headers(mac),
            )
            token = (data.get('js') or {}).get('token') or data.get('token')
            if not token:
                raise RuntimeError('No token in handshake response')
            result['handshake_ms']  = int((time.time() - t1) * 1000)
            result['token_prefix']  = token[:8] + '…'
            result['token']         = token

            t2 = time.time()
            raw_profile = http_get(
                portal_url(
                    resolved, 'get_profile',
                    hd=1, ver='ImageDescription: 0.2.18-r14-pub-250;',
                    num_banks=2, sn=mac_to_serial(mac), stb_type='MAG200',
                    image_version=218, video_out='hdmi',
                    device_id=mac_to_device_id(mac), device_id2=mac_to_device_id(mac),
                    signature=mac_to_signature(mac), auth_second_step=1,
                    hw_version='1.7-BD-00', not_valid_token=0,
                    client_type='STB', hw_version_2=mac_to_serial(mac),
                ),
                build_headers(mac, token),
            ).get('js', {})
            result['profile_ms'] = int((time.time() - t2) * 1000)

            profile = {
                'name':     raw_profile.get('name') or raw_profile.get('login') or '',
                'tariff':   raw_profile.get('tariff_expired_date') or raw_profile.get('tariff') or '',
                'expiry':   raw_profile.get('expire_billing_date') or '',
                'phone':    raw_profile.get('phone') or '',
                'status':   raw_profile.get('status') or '',
                'stb_type': raw_profile.get('stb_type') or 'MAG200',
            }
            result['profile'] = profile

            # Fields expected by the frontend inspector panel
            result['info'] = {
                'name':        raw_profile.get('name') or raw_profile.get('login') or '',
                'login':       raw_profile.get('login') or '',
                'password':    raw_profile.get('password') or '',
                'email':       raw_profile.get('email') or '',
                'phone':       raw_profile.get('phone') or '',
                'ip':          raw_profile.get('ip') or '',
                'mac':         mac,
                'status':      raw_profile.get('status') or '',
                'tariff':      raw_profile.get('tariff_plan') or raw_profile.get('tariff') or '',
                'start_date':  raw_profile.get('start_date') or '',
                'end_date':    (raw_profile.get('expire_billing_date')
                                or raw_profile.get('tariff_expired_date') or ''),
                'server_time': raw_profile.get('cur_time') or '',
                'services':    raw_profile.get('services') or '',
                'keep_alive':  str(raw_profile.get('keep_alive') or ''),
            }
            result['account'] = raw_profile

            t3 = time.time()
            counts = {
                'live':   count_items(resolved, mac, token, 'live'),
                'vod':    count_items(resolved, mac, token, 'vod'),
                'series': count_items(resolved, mac, token, 'series'),
            }
            result['content']    = counts
            result['counts']     = counts
            result['content_ms'] = int((time.time() - t3) * 1000)
            result['total_ms']   = int((time.time() - t0) * 1000)

        except Exception as e:
            result['auth_error'] = str(e)
            result['ok']    = False
            result['error'] = str(e)

        return self.send_json(200, result)
