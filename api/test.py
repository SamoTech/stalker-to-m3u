"""
api/test.py  —  Portal Inspector.

POST /api/test
  Body (JSON):
    portal : str  required  http://HOST:PORT
    mac    : str  required  00:1A:79:XX:XX:XX

Response (JSON):
  {
    ok        : bool,
    portal    : str,
    mac       : str,
    token     : str | null,
    profile   : dict,        # raw get_profile js block
    account   : dict,        # raw get_account_info js block (if available)
    info      : {
      name, login, status, tariff,
      start_date, end_date,
      phone, email,
      server_time, mac, ip,
      keep_alive_use, stb_active_services
    },
    counts    : { live, vod, series },
    error     : str | null
  }
"""

from http.server import BaseHTTPRequestHandler
import json, hashlib, re, time
import urllib.request, urllib.parse, urllib.error
from urllib.parse import urlencode

config = {"maxDuration": 30}


# ── Shared portal helpers (mirrors convert.py) ─────────────────────────────────

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

def handshake(base, mac):
    data  = http_get(portal_url(base, "handshake", type="stb", prehash=0), build_headers(mac))
    token = data.get("js", {}).get("token") or data.get("token")
    if not token:
        raise RuntimeError("No token in handshake response")
    return token

def get_profile(base, mac, token):
    url = portal_url(base, "get_profile",
        hd=1, ver="ImageDescription: 0.2.18-r14-pub-250;",
        num_banks=2, sn=mac_to_serial(mac), stb_type="MAG200",
        image_version=218, video_out="hdmi",
        device_id=mac_to_device_id(mac), device_id2=mac_to_device_id(mac),
        signature=mac_to_signature(mac), auth_second_step=1,
        hw_version="1.7-BD-00", not_valid_token=0,
        client_type="STB", hw_version_2=mac_to_serial(mac))
    return http_get(url, build_headers(mac, token))

def get_account_info(base, mac, token):
    """Try several known account info endpoints — return first that works."""
    actions = ["get_account_info", "account_info", "get_user", "get_subscriber_info"]
    for action in actions:
        try:
            data = http_get(portal_url(base, action), build_headers(mac, token))
            js   = data.get("js")
            if js and isinstance(js, dict) and js:
                return js, action
        except Exception:
            continue
    return {}, None

def count_content(base, mac, token, media_type):
    """Return total item count for a media type using total_items from first page."""
    t_map = {"live": "itv", "vod": "vod", "series": "series"}
    t = t_map.get(media_type, "itv")
    try:
        url  = portal_url(base, "get_ordered_list",
                          type=t, genre="*", p=1, fav=0, sortby="number",
                          JsHttpRequest=f"{int(time.time()*1000)}-xml")
        data = http_get(url, build_headers(mac, token))
        js   = data.get("js", {})
        if isinstance(js, dict):
            total = int(js.get("total_items") or js.get("total") or 0)
            if total:
                return total
            # fallback: count items on page 1
            items = js.get("data") or []
        elif isinstance(js, list):
            items = js
            total = 0
        else:
            return 0
        # if total_items not present, sum page items as a lower-bound
        return len(items) if items else 0
    except Exception:
        return 0

def count_categories(base, mac, token, media_type):
    """Return category count as a secondary indicator if content count is 0."""
    action = "get_genres" if media_type == "live" else "get_categories"
    t = {"live": "itv", "vod": "vod", "series": "series"}.get(media_type, "itv")
    try:
        data = http_get(portal_url(base, action, type=t), build_headers(mac, token))
        js   = data.get("js") or []
        if isinstance(js, dict):
            js = list(js.values())
        return len([g for g in js if g.get("id")])
    except Exception:
        return 0


def extract_info(profile_js, account_js):
    """Merge profile + account blobs into a flat readable dict."""
    p = profile_js or {}
    a = account_js or {}

    def pick(*keys, sources=None):
        for src in (sources or [p, a]):
            for k in keys:
                v = src.get(k)
                if v not in (None, "", 0, "0"):
                    return str(v).strip()
        return None

    return {
        "name":         pick("name", "fname", "full_name", "subscriber_name"),
        "login":        pick("login", "username", "user", "stb_login"),
        "password":     pick("password", "pass", "stb_password"),   # rarely present
        "status":       pick("status", "account_status", "stb_status"),
        "tariff":       pick("tariff_plan", "tariff", "plan", "package",
                             "service_name", "subscription"),
        "start_date":   pick("start_date", "created", "created_at",
                             "activation_date", "reg_date"),
        "end_date":     pick("end_date", "expire_date", "expiry",
                             "subscription_end", "valid_till", "expire"),
        "phone":        pick("phone", "mobile", "telephone"),
        "email":        pick("email", "mail"),
        "ip":           pick("ip", "last_ip", "remote_ip"),
        "mac":          pick("mac", "stb_mac"),
        "server_time":  pick("servertime", "server_time", "time"),
        "keep_alive":   pick("keep_alive_use", "keepalive"),
        "services":     pick("stb_active_services", "active_services", "services"),
    }


# ── Vercel handler ─────────────────────────────────────────────────────────────

class handler(BaseHTTPRequestHandler):

    def log_message(self, *a): pass

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
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

        result = {
            "ok":      False,
            "portal":  portal,
            "mac":     mac,
            "token":   None,
            "profile": {},
            "account": {},
            "account_endpoint": None,
            "info":    {},
            "counts":  {"live": 0, "vod": 0, "series": 0},
            "error":   None,
        }

        # 1. Handshake
        try:
            token = handshake(portal, mac)
            result["token"] = token[:12] + "…"  # partial — never expose full token
            result["ok"]    = True
        except Exception as e:
            result["error"] = f"Handshake failed: {e}"
            return self.send_json(502, result)

        # 2. Profile
        try:
            raw_profile    = get_profile(portal, mac, token)
            result["profile"] = raw_profile.get("js", raw_profile)
        except Exception as e:
            result["profile"] = {}
            result["error"]   = f"get_profile failed: {e}"

        # 3. Account info
        try:
            acct, endpoint = get_account_info(portal, mac, token)
            result["account"]          = acct
            result["account_endpoint"] = endpoint
        except Exception:
            pass

        # 4. Merge into flat readable info
        result["info"] = extract_info(result["profile"], result["account"])

        # 5. Content counts (live, vod, series)
        for mt in ("live", "vod", "series"):
            n = count_content(portal, mac, token, mt)
            if n == 0:
                n = count_categories(portal, mac, token, mt)  # fallback: category count
            result["counts"][mt] = n

        return self.send_json(200, result)
