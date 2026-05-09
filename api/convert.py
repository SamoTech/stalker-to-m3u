from http.server import BaseHTTPRequestHandler
import json
import hashlib
import re
import time
import urllib.request
import urllib.parse
import urllib.error
from urllib.parse import urlencode


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def mac_to_serial(mac):
    clean = mac.replace(":", "").upper()
    return hashlib.md5(clean.encode()).hexdigest()[:13].upper()

def mac_to_device_id(mac):
    clean = mac.replace(":", "").upper()
    return hashlib.sha256(clean.encode()).hexdigest()[:64].upper()

def mac_to_signature(mac):
    clean = mac.replace(":", "").upper()
    return hashlib.sha256((clean + "stalker").encode()).hexdigest()[:64].upper()

def build_headers(mac, token=""):
    headers = {
        "User-Agent": "Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3",
        "X-User-Agent": "Model: MAG200; Link: Ethernet",
        "Cookie": f"mac={mac}; stb_lang=en; timezone=Europe/London",
        "Accept": "*/*",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers

def portal_url(base, action, **params):
    base = base.rstrip("/")
    params["action"] = action
    qs = urlencode(params)
    return f"{base}/portal.php?{qs}"

def http_get(url, headers, timeout=20):
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
    return json.loads(raw.decode("utf-8", errors="replace"))


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def handshake(base, mac):
    url = portal_url(base, "handshake", type="stb", prehash=0)
    data = http_get(url, build_headers(mac))
    token = data.get("js", {}).get("token") or data.get("token")
    if not token:
        raise RuntimeError(f"No token in handshake response")
    return token

def get_profile(base, mac, token):
    url = portal_url(
        base, "get_profile",
        hd=1, ver="ImageDescription: 0.2.18-r14-pub-250;",
        num_banks=2, sn=mac_to_serial(mac), stb_type="MAG200",
        image_version=218, video_out="hdmi",
        device_id=mac_to_device_id(mac), device_id2=mac_to_device_id(mac),
        signature=mac_to_signature(mac), auth_second_step=1,
        hw_version="1.7-BD-00", not_valid_token=0,
        client_type="STB", hw_version_2=mac_to_serial(mac)
    )
    data = http_get(url, build_headers(mac, token))
    return data.get("js", {})


# ---------------------------------------------------------------------------
# Channels
# ---------------------------------------------------------------------------

def fetch_genres(base, mac, token, media_type):
    action = "get_genres" if media_type == "live" else "get_categories"
    t = {"live": "itv", "vod": "vod", "series": "series"}.get(media_type, "itv")
    url = portal_url(base, action, type=t)
    data = http_get(url, build_headers(mac, token))
    genres = {}
    for g in data.get("js", []):
        gid = str(g.get("id", ""))
        gname = (g.get("title") or g.get("name") or "").strip()
        if gid and gname:
            genres[gid] = gname
    return genres

def fetch_page(base, mac, token, media_type, page):
    t = {"live": "itv", "vod": "vod", "series": "series"}.get(media_type, "itv")
    url = portal_url(
        base, "get_ordered_list",
        type=t, action="get_ordered_list",
        genre=0, force_ch_link_check=0,
        fav=0, sortby="number", hd=0,
        p=page, JsHttpRequest=f"{int(time.time()*1000)}-xml"
    )
    data = http_get(url, build_headers(mac, token))
    js = data.get("js", {})
    return js.get("data", []), int(js.get("total_items", 0) or js.get("total", 0))

def extract_stream_url(base, mac, token, cmd):
    if cmd.startswith(("http://", "https://", "rtsp://")):
        return cmd
    clean = re.sub(r'^(ffmpeg|auto)\s+', '', cmd).strip()
    if clean.startswith(("http", "rtsp")):
        return clean
    try:
        url = portal_url(base, "create_link", type="itv",
                         cmd=urllib.parse.quote(cmd),
                         JsHttpRequest=f"{int(time.time()*1000)}-xml")
        data = http_get(url, build_headers(mac, token), timeout=10)
        link = re.sub(r'^(ffmpeg|auto)\s+', '', data.get("js", {}).get("cmd", "")).strip()
        return link or clean
    except Exception:
        return clean

def fetch_all(base, mac, token, media_type, max_pages=50):
    genres = {}
    try:
        genres = fetch_genres(base, mac, token, media_type)
    except Exception:
        pass

    channels = []
    seen = set()
    total = None

    for page in range(1, max_pages + 1):
        try:
            items, total_items = fetch_page(base, mac, token, media_type, page)
        except Exception as e:
            break
        if total is None and total_items:
            total = total_items
        if not items:
            break
        for ch in items:
            cid = str(ch.get("id", ""))
            if cid in seen:
                continue
            seen.add(cid)
            genre_id = str(ch.get("tv_genre_id") or ch.get("category_id") or "")
            cmd = ch.get("cmd", "")
            stream_url = extract_stream_url(base, mac, token, cmd) if cmd else ""
            channels.append({
                "name": (ch.get("name") or ch.get("title") or "").strip(),
                "logo": ch.get("logo") or ch.get("screenshot_uri") or "",
                "group": genres.get(genre_id, "Uncategorized"),
                "number": ch.get("number") or ch.get("ch_number") or page,
                "stream_url": stream_url,
                "epg_id": ch.get("xmltv_id") or ch.get("tvg_id") or "",
            })
        if total and len(channels) >= total:
            break
    return channels


# ---------------------------------------------------------------------------
# M3U builder
# ---------------------------------------------------------------------------

def build_m3u(channels, epg_url=""):
    lines = []
    header = "#EXTM3U"
    if epg_url:
        header += f' url-tvg="{epg_url}"'
    lines.append(header)
    for ch in channels:
        if not ch.get("stream_url"):
            continue
        name = ch["name"] or "Unknown"
        lines.append(
            f'#EXTINF:-1 tvg-id="{ch["epg_id"]}" tvg-name="{name}" '
            f'tvg-logo="{ch["logo"]}" group-title="{ch["group"]}" '
            f'tvg-chno="{ch["number"]}",{name}'
        )
        lines.append(ch["stream_url"])
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Vercel handler
# ---------------------------------------------------------------------------

class handler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass  # silence access log

    def send_json(self, status, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def send_m3u(self, content, filename="playlist.m3u"):
        body = content.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/x-mpegurl")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            payload = json.loads(body)
        except Exception:
            return self.send_json(400, {"error": "Invalid JSON body"})

        portal = (payload.get("portal") or "").strip().rstrip("/")
        mac = (payload.get("mac") or "").strip()
        types = payload.get("types") or ["live"]
        max_pages = int(payload.get("maxPages") or 50)
        epg_url = (payload.get("epgUrl") or "").strip()
        fmt = (payload.get("format") or "m3u").lower()

        if not portal or not mac:
            return self.send_json(400, {"error": "Missing required fields: portal, mac"})

        if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac):
            return self.send_json(400, {"error": f"Invalid MAC address: {mac}"})

        try:
            token = handshake(portal, mac)
        except Exception as e:
            return self.send_json(502, {"error": f"Handshake failed: {e}"})

        profile = {}
        try:
            profile = get_profile(portal, mac, token)
        except Exception:
            pass

        all_channels = []
        errors = []
        for t in types:
            try:
                chs = fetch_all(portal, mac, token, t, max_pages)
                all_channels.extend(chs)
            except Exception as e:
                errors.append(f"{t}: {e}")

        if not all_channels and errors:
            return self.send_json(502, {"error": "No channels fetched", "details": errors})

        m3u = build_m3u(all_channels, epg_url)

        if fmt == "json":
            return self.send_json(200, {
                "total": len(all_channels),
                "profile": profile,
                "channels": all_channels,
                "errors": errors,
            })

        self.send_m3u(m3u)
