"""
api/convert.py  —  Vercel serverless function.

POST /api/convert
  Body (JSON):
    portal      : str   required  http://HOST:PORT
    mac         : str   required  00:1A:79:XX:XX:XX
    types       : list  optional  ["live","vod","series"]  default ["live"]
    maxPages    : int   optional  default 50
    epgUrl      : str   optional
    format      : str   optional  "m3u" | "json"           default "m3u"
    skipKnown   : str   optional  existing M3U text; channels whose URLs already
                                  appear in it will be omitted (diff / recheck mode)
"""

from http.server import BaseHTTPRequestHandler
import json, hashlib, re, time
import urllib.request, urllib.parse, urllib.error
from urllib.parse import urlencode


# ── Stream-type classification (ported from IPTV-CHECK) ────────────────────────
STREAM_TYPE_MAP = {
    '.m3u8': 'video', '.m3u': 'video', '.ts': 'video', '.mp4': 'video',
    '.avi': 'video', '.mkv': 'video', '.flv': 'video',
    '.mp3': 'audio', '.aac': 'audio', '.pls': 'audio', '.ogg': 'audio',
    '/stream': 'audio', '/radio/': 'audio',
}

def classify_stream_type(url: str) -> str:
    low = url.lower().split('?')[0]
    for pat, typ in STREAM_TYPE_MAP.items():
        if pat in low:
            return typ
    return 'video'


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


def is_uncheckable(url: str) -> bool:
    """True if the URL likely cannot be probed (token-signed, auth-gated)."""
    UNCHECKABLE_KEYWORDS = ['token', 'auth', 'login', 'key', 'signature', 'drm']
    if len(url) > 250:
        return True
    low = url.lower()
    return any(kw in low for kw in UNCHECKABLE_KEYWORDS)


# ── M3U helpers ───────────────────────────────────────────────────────────────

def extract_known_urls(m3u_text: str) -> set:
    """Return set of stream URLs already present in an existing M3U."""
    if not m3u_text:
        return set()
    return {line.strip() for line in m3u_text.splitlines()
            if line.strip() and not line.strip().startswith('#')}


# ── Stalker portal helpers ────────────────────────────────────────────────────

def mac_to_serial(mac):
    return hashlib.md5(mac.replace(":","").upper().encode()).hexdigest()[:13].upper()

def mac_to_device_id(mac):
    return hashlib.sha256(mac.replace(":","").upper().encode()).hexdigest()[:64].upper()

def mac_to_signature(mac):
    return hashlib.sha256((mac.replace(":","").upper()+"stalker").encode()).hexdigest()[:64].upper()

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

def http_get(url, headers, timeout=20):
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))

def handshake(base, mac):
    data = http_get(portal_url(base, "handshake", type="stb", prehash=0), build_headers(mac))
    token = data.get("js",{}).get("token") or data.get("token")
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
    return http_get(url, build_headers(mac, token)).get("js", {})

def fetch_genres(base, mac, token, media_type):
    action = "get_genres" if media_type == "live" else "get_categories"
    t = {"live":"itv","vod":"vod","series":"series"}.get(media_type, "itv")
    try:
        data = http_get(portal_url(base, action, type=t), build_headers(mac, token))
        js = data.get("js") or []
        if isinstance(js, dict):
            js = list(js.values())
        return {str(g.get("id","")): (g.get("title") or g.get("name","")).strip()
                for g in js if g.get("id")}
    except Exception:
        return {}

def clean_cmd(cmd):
    """Strip ffmpeg/auto prefix and return the real URL, or empty string."""
    if not cmd:
        return ""
    cmd = cmd.strip()
    if re.match(r'^https?://', cmd) or cmd.startswith("rtsp://"):
        return sanitize_url(cmd)
    m = re.match(r'^(?:ffmpeg|auto)\s+(https?://\S+|rtsp://\S+)', cmd)
    if m:
        return sanitize_url(m.group(1))
    return cmd

def fetch_page(base, mac, token, media_type, page):
    t = {"live":"itv","vod":"vod","series":"series"}.get(media_type, "itv")
    url = portal_url(base, "get_ordered_list",
        type=t,
        genre="*",
        force_ch_link_check=0, fav=0, sortby="number", hd=0,
        p=page, JsHttpRequest=f"{int(time.time()*1000)}-xml")
    js = http_get(url, build_headers(mac, token)).get("js", {})
    if isinstance(js, list):
        return js, len(js)
    data = js.get("data") or []
    total = int(js.get("total_items") or js.get("total") or 0)
    return data, total

def create_link(base, mac, token, cmd):
    """Ask the portal to resolve a non-http cmd into a playable URL."""
    try:
        url = portal_url(base, "create_link", type="itv",
                         cmd=urllib.parse.quote(cmd, safe=""),
                         JsHttpRequest=f"{int(time.time()*1000)}-xml")
        raw = http_get(url, build_headers(mac, token)).get("js",{}).get("cmd","")
        return clean_cmd(raw)
    except Exception:
        return ""

def fetch_all(base, mac, token, media_type, max_pages=50, known_urls=None):
    genres = fetch_genres(base, mac, token, media_type)
    channels, seen, total = [], set(), None
    known_urls = known_urls or set()

    for page in range(1, max_pages + 1):
        try:
            items, total_items = fetch_page(base, mac, token, media_type, page)
        except Exception:
            break
        if total is None and total_items:
            total = total_items
        if not items:
            break

        for ch in items:
            cid = str(ch.get("id","") or ch.get("cmd",""))
            if cid in seen:
                continue
            seen.add(cid)

            genre_id = str(ch.get("tv_genre_id") or ch.get("category_id") or "")
            raw_cmd  = ch.get("cmd") or ""
            stream   = clean_cmd(raw_cmd)

            if not stream and raw_cmd and media_type == "live":
                stream = create_link(base, mac, token, raw_cmd)

            # Diff / recheck mode: skip channels already in existing playlist
            if stream and stream in known_urls:
                continue

            channels.append({
                "name":        (ch.get("name") or ch.get("title") or "Unknown").strip(),
                "logo":        ch.get("logo") or ch.get("screenshot_uri") or "",
                "group":       genres.get(genre_id, "Uncategorized"),
                "number":      ch.get("number") or ch.get("ch_number") or len(channels)+1,
                "stream_url":  stream,
                "epg_id":      ch.get("xmltv_id") or ch.get("tvg_id") or "",
                "raw_cmd":     raw_cmd,
                "uncheckable": is_uncheckable(stream) if stream else False,
            })

        if total and len(channels) >= total:
            break

    return channels

def build_m3u(channels, epg_url=""):
    lines = [f'#EXTM3U url-tvg="{epg_url}"' if epg_url else "#EXTM3U"]
    for ch in channels:
        url = ch.get("stream_url") or ch.get("raw_cmd") or ""
        if not url:
            continue
        name = ch["name"]
        stype = classify_stream_type(url)
        # Tag uncheckable channels with a warning group
        group = ch.get("group", "Uncategorized")
        if ch.get("uncheckable"):
            group = "⚠ Auth Required"
        lines.append(
            f'#EXTINF:-1 tvg-id="{ch["epg_id"]}" tvg-name="{name}" '
            f'tvg-logo="{ch["logo"]}" group-title="{group}" '
            f'tvg-chno="{ch["number"]}" tvg-type="{stype}",{name}'
        )
        lines.append(url)
    return "\n".join(lines) + "\n"


# ── Vercel handler ────────────────────────────────────────────────────────────

class handler(BaseHTTPRequestHandler):

    def log_message(self, *a): pass

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def send_json(self, status, data):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def send_m3u(self, content):
        body = content.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/x-mpegurl; charset=utf-8")
        self.send_header("Content-Disposition", 'attachment; filename="playlist.m3u"')
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
            length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length))
        except Exception:
            return self.send_json(400, {"error": "Invalid JSON body"})

        portal     = (payload.get("portal")    or "").strip().rstrip("/")
        mac        = (payload.get("mac")       or "").strip()
        types      = payload.get("types")      or ["live"]
        max_pgs    = int(payload.get("maxPages") or 50)
        epg_url    = (payload.get("epgUrl")    or "").strip()
        fmt        = (payload.get("format")    or "m3u").lower()
        skip_known = (payload.get("skipKnown") or "").strip()

        if not portal or not mac:
            return self.send_json(400, {"error": "Missing required fields: portal, mac"})
        if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac):
            return self.send_json(400, {"error": f"Invalid MAC: {mac}"})

        known_urls = extract_known_urls(skip_known)

        try:
            token = handshake(portal, mac)
        except Exception as e:
            return self.send_json(502, {"error": f"Handshake failed: {e}"})

        profile = {}
        try:
            profile = get_profile(portal, mac, token)
        except Exception:
            pass

        all_channels, errors = [], []
        for t in types:
            try:
                chs = fetch_all(portal, mac, token, t, max_pgs, known_urls)
                all_channels.extend(chs)
            except Exception as e:
                errors.append(f"{t}: {e}")

        if not all_channels and errors:
            return self.send_json(502, {"error": "No channels fetched", "details": errors})

        if fmt == "json":
            return self.send_json(200, {
                "total":    len(all_channels),
                "profile":  profile,
                "channels": all_channels,
                "errors":   errors,
                "skipped":  len(known_urls),
            })

        self.send_m3u(build_m3u(all_channels, epg_url))
