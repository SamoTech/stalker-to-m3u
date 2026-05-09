"""
api/test.py  —  Real portal inspector.

POST /api/test
  Body (JSON):
    portal  : str  required  http://HOST:PORT
    mac     : str  required  00:1A:79:XX:XX:XX

Response (JSON):
  {
    ok        : bool,
    portal    : str,
    auth      : { token: bool },
    account   : { login, name, status, tariff, start_date, end_date,
                  phone, email, created, last_change, balance,
                  max_connections, ...all readable fields },
    counts    : { live: int, vod: int, series: int },
    server    : { time, timezone, version, ...all readable fields },
    raw       : { profile: {...}, account: {...}, server: {...} },
    error     : str   (only on failure)
  }
"""

from http.server import BaseHTTPRequestHandler
import json, hashlib, re, time
import urllib.request, urllib.parse, urllib.error
from urllib.parse import urlencode

config = {"maxDuration": 25}


# ── Stalker auth helpers (mirrors convert.py) ─────────────────────────────────

def mac_to_serial(mac):
    return hashlib.md5(mac.replace(":", "").upper().encode()).hexdigest()[:13].upper()

def mac_to_device_id(mac):
    return hashlib.sha256(mac.replace(":", "").upper().encode()).hexdigest()[:64].upper()

def mac_to_signature(mac):
    return hashlib.sha256((mac.replace(":", "").upper() + "stalker").encode()).hexdigest()[:64].upper()

def build_headers(mac, token=""):
    h = {
        "User-Agent": ("Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 "
                       "(KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3"),
        "X-User-Agent": "Model: MAG200; Link: Ethernet",
        "Cookie": f"mac={mac}; stb_lang=en; timezone=Europe/London",
        "Accept": "*/*",
    }
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h

def portal_url(base, action, **params):
    params["action"] = action
    return f"{base.rstrip('/')}/portal.php?{urlencode(params)}"

def http_get(url, headers, timeout=12):
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))

def do_handshake(base, mac):
    data  = http_get(portal_url(base, "handshake", type="stb", prehash=0), build_headers(mac))
    token = data.get("js", {}).get("token") or data.get("token")
    if not token:
        raise RuntimeError("No token returned by handshake")
    return token

def do_profile(base, mac, token):
    url = portal_url(base, "get_profile",
        hd=1, ver="ImageDescription: 0.2.18-r14-pub-250;",
        num_banks=2, sn=mac_to_serial(mac), stb_type="MAG200",
        image_version=218, video_out="hdmi",
        device_id=mac_to_device_id(mac), device_id2=mac_to_device_id(mac),
        signature=mac_to_signature(mac), auth_second_step=1,
        hw_version="1.7-BD-00", not_valid_token=0,
        client_type="STB", hw_version_2=mac_to_serial(mac))
    return http_get(url, build_headers(mac, token)).get("js", {})

def do_account_info(base, mac, token):
    """Try the dedicated account_info endpoint (not available on all portals)."""
    try:
        data = http_get(portal_url(base, "get_account_info"), build_headers(mac, token))
        return data.get("js") or {}
    except Exception:
        return {}

def do_server_info(base, mac, token):
    """Try get_server_info / get_settings for server/portal metadata."""
    result = {}
    for action in ("get_server_info", "get_settings"):
        try:
            data = http_get(portal_url(base, action), build_headers(mac, token))
            js   = data.get("js") or {}
            if isinstance(js, dict):
                result.update(js)
        except Exception:
            pass
    return result

def count_type(base, mac, token, media_type, timeout=10):
    """Return total channel/VOD count for the given media type.
    Uses page 1 total_items field from get_ordered_list.
    """
    t = {"live": "itv", "vod": "vod", "series": "series"}.get(media_type, "itv")
    try:
        url = portal_url(base, "get_ordered_list",
            type=t, genre="*", force_ch_link_check=0, fav=0,
            sortby="number", hd=0, p=1,
            JsHttpRequest=f"{int(time.time() * 1000)}-xml")
        data = http_get(url, build_headers(mac, token), timeout=timeout)
        js   = data.get("js") or {}
        if isinstance(js, dict):
            total = js.get("total_items") or js.get("total") or 0
            return int(total)
        if isinstance(js, list):
            return len(js)
    except Exception:
        pass
    return None

def safe_str(v):
    if v is None:
        return None
    return str(v).strip() or None

def extract_account(profile, account_raw):
    """Merge profile + account_info into a clean normalized dict."""
    src = {}
    if isinstance(profile, dict):
        src.update(profile)
    if isinstance(account_raw, dict):
        src.update(account_raw)

    def pick(*keys):
        for k in keys:
            v = src.get(k)
            if v not in (None, "", 0, "0", "null", "undefined"):
                return str(v).strip()
        return None

    return {
        k: v for k, v in {
            "login":           pick("login", "username", "user_login"),
            "name":            pick("fname", "full_name", "name", "real_name"),
            "status":          pick("status", "account_status", "subscriber_status"),
            "tariff":          pick("tariff_plan", "tariff", "package", "plan"),
            "start_date":      pick("start_date", "activation_date", "created_at", "reg_date"),
            "end_date":        pick("end_date", "expire_date", "expiry", "expiry_date", "exp_date"),
            "phone":           pick("phone", "mobile", "phone_number"),
            "email":           pick("email", "mail"),
            "balance":         pick("balance", "credit"),
            "max_connections": pick("max_connections", "simultaneous_sessions"),
            "blocked":         pick("blocked", "is_blocked"),
            "comment":         pick("comment", "note", "notes"),
            "created":         pick("created", "created_at", "reg_date"),
            "last_modified":   pick("last_modified", "last_change", "updated_at"),
            "timezone":        pick("timezone", "time_zone"),
            "locale":          pick("locale", "language", "lang"),
            "stb_type":        pick("stb_type", "device_type"),
            "serial_number":   pick("sn", "serial", "serial_number"),
            "isp":             pick("isp", "provider"),
            "country":         pick("country", "country_code"),
        }.items() if v is not None
    }


# ── Handler ────────────────────────────────────────────────────────────────────

class handler(BaseHTTPRequestHandler):

    def log_message(self, *a): pass

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def send_json(self, status, data):
        body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        self.send_json(200, {
            "status": "ok",
            "endpoint": "POST /api/test",
            "body": {"portal": "http://HOST:PORT", "mac": "00:1A:79:XX:XX:XX"},
        })

    def do_POST(self):
        try:
            length  = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length))
        except Exception:
            return self.send_json(400, {"ok": False, "error": "Invalid JSON body"})

        portal = (payload.get("portal") or "").strip().rstrip("/")
        mac    = (payload.get("mac")    or "").strip()

        if not portal:
            return self.send_json(400, {"ok": False, "error": "portal is required"})
        if not mac:
            return self.send_json(400, {"ok": False, "error": "mac is required"})
        if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac):
            return self.send_json(400, {"ok": False, "error": f"Invalid MAC format: {mac}"})

        # ── Step 1: Handshake ─────────────────────────────────────────────────
        try:
            token = do_handshake(portal, mac)
        except Exception as e:
            return self.send_json(502, {
                "ok": False,
                "portal": portal,
                "error": f"Handshake failed: {e}",
                "step": "handshake",
            })

        # ── Step 2: Profile ───────────────────────────────────────────────────
        profile_raw = {}
        try:
            profile_raw = do_profile(portal, mac, token)
        except Exception as e:
            profile_raw = {"_error": str(e)}

        # ── Step 3: Account info (best-effort) ────────────────────────────────
        account_raw = {}
        try:
            account_raw = do_account_info(portal, mac, token)
        except Exception:
            pass

        # ── Step 4: Server / settings info (best-effort) ─────────────────────
        server_raw = {}
        try:
            server_raw = do_server_info(portal, mac, token)
        except Exception:
            pass

        # ── Step 5: Content counts (parallel best-effort) ────────────────────
        counts = {}
        for mt in ("live", "vod", "series"):
            n = count_type(portal, mac, token, mt)
            if n is not None:
                counts[mt] = n

        # ── Normalize ─────────────────────────────────────────────────────────
        account = extract_account(profile_raw, account_raw)

        server = {k: v for k, v in {
            "time":     safe_str(server_raw.get("servertime") or server_raw.get("server_time") or server_raw.get("time")),
            "timezone": safe_str(server_raw.get("timezone") or server_raw.get("server_timezone")),
            "version":  safe_str(server_raw.get("version") or server_raw.get("portal_version")),
            "portal":   safe_str(server_raw.get("portal") or server_raw.get("portal_url")),
        }.items() if v is not None}

        return self.send_json(200, {
            "ok":     True,
            "portal": portal,
            "auth":   {"token": bool(token)},
            "account": account,
            "counts":  counts,
            "server":  server,
            "raw": {
                "profile": profile_raw,
                "account": account_raw,
                "server":  server_raw,
            },
        })
