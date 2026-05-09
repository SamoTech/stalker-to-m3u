"""
api/test.py — Vercel serverless function.

GET /api/test?portal=http://HOST:PORT&mac=00:1A:79:XX:XX:XX

Full portal inspector: runs the complete Stalker auth flow and
returns portal health, subscriber info, and content counts.
"""

from http.server import BaseHTTPRequestHandler
import json, hashlib, time, re
import urllib.request, urllib.error, urllib.parse
from urllib.parse import urlencode, urlparse, parse_qs


# ── Stalker helpers (minimal, no shared deps needed here) ─────────────────────

def mac_to_serial(mac):
    import hashlib
    return hashlib.md5(mac.replace(':', '').upper().encode()).hexdigest()[:13].upper()

def mac_to_device_id(mac):
    import hashlib
    return hashlib.sha256(mac.replace(':', '').upper().encode()).hexdigest()[:64].upper()

def mac_to_signature(mac):
    import hashlib
    return hashlib.sha256((mac.replace(':', '').upper() + 'stalker').encode()).hexdigest()[:64].upper()

def build_headers(mac, token=''):
    h = {
        'User-Agent': ('Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 '
                       '(KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3'),
        'X-User-Agent': 'Model: MAG200; Link: Ethernet',
        'Cookie': f'mac={mac}; stb_lang=en; timezone=Europe/London',
        'Accept': '*/*',
    }
    if token:
        h['Authorization'] = f'Bearer {token}'
    return h

def portal_url(base, action, **params):
    params['action'] = action
    return f"{base.rstrip('/')}/portal.php?{urlencode(params)}"

def http_get(url, headers, timeout=15):
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode('utf-8', errors='replace'))

def count_items(base, mac, token, media_type, page=1):
    """Fetch page 1 and return total_items reported by portal."""
    t = {'live': 'itv', 'vod': 'vod', 'series': 'series'}.get(media_type, 'itv')
    try:
        url = portal_url(base, 'get_ordered_list',
            type=t, genre='*', force_ch_link_check=0, fav=0,
            sortby='number', hd=0, p=page,
            JsHttpRequest=f'{int(time.time() * 1000)}-xml')
        js = http_get(url, build_headers(mac, token)).get('js', {})
        if isinstance(js, list):
            return len(js)
        return int(js.get('total_items') or js.get('total') or 0)
    except Exception:
        return -1


# ── Vercel handler ────────────────────────────────────────────────────────────

class handler(BaseHTTPRequestHandler):

    def log_message(self, *a): pass

    def _cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
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

        if not portal:
            return self.send_json(400, {'ok': False, 'error': 'Missing portal param'})

        if mac and not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac):
            return self.send_json(400, {'ok': False, 'error': f'Invalid MAC: {mac}'})

        # ── Step 1: portal reachability ───────────────────────────────────────
        t0 = time.time()
        try:
            req = urllib.request.Request(
                f"{portal}/portal.php",
                headers={'User-Agent': 'stalker-to-m3u/1.0'}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                reach_status = resp.status
        except urllib.error.HTTPError as e:
            reach_status = e.code
        except Exception as e:
            return self.send_json(200, {
                'ok': False, 'reachable': False,
                'error': str(e), 'ms': int((time.time() - t0) * 1000)
            })
        reach_ms = int((time.time() - t0) * 1000)

        result = {
            'ok':        True,
            'reachable': True,
            'status':    reach_status,
            'ms':        reach_ms,
        }

        # ── Step 2: full auth flow (only if MAC provided) ─────────────────────
        if not mac:
            result['note'] = 'Provide mac param for full portal inspection'
            return self.send_json(200, result)

        try:
            # Handshake
            t1    = time.time()
            data  = http_get(portal_url(portal, 'handshake', type='stb', prehash=0),
                             build_headers(mac))
            token = data.get('js', {}).get('token') or data.get('token')
            if not token:
                raise RuntimeError('No token in handshake response')
            result['handshake_ms'] = int((time.time() - t1) * 1000)
            result['token_prefix'] = token[:8] + '…'

            # Profile
            t2      = time.time()
            profile = http_get(
                portal_url(portal, 'get_profile',
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
                'live':   count_items(portal, mac, token, 'live'),
                'vod':    count_items(portal, mac, token, 'vod'),
                'series': count_items(portal, mac, token, 'series'),
            }
            result['content_ms'] = int((time.time() - t3) * 1000)
            result['total_ms']   = int((time.time() - t0) * 1000)

        except Exception as e:
            result['auth_error'] = str(e)

        return self.send_json(200, result)
