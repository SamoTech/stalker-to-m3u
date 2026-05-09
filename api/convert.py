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

Response modes
  format=m3u  (default) — buffered M3U file download, backward-compatible.
  format=json           — NDJSON stream; one JSON object per line.

NDJSON event types (format=json)
  {"event":"meta",     "portal":…, "types":…, "maxPages":…, "epgUrl":…, "knownUrls":N}
  {"event":"profile",  "profile":{…}}
  {"event":"channel",  "count":N, "channel":{name,logo,group,number,stream_url,
                                             epg_id,raw_cmd,uncheckable,stream_type,media_type}}
  {"event":"progress", "scope":"live"|"vod"|"series", "page":N,
                        "count":N, "typeCount":N, "estimatedTotal":N,
                        "done":true|false}
  {"event":"error",    "scope":…, "message":…, "page":N}
  {"event":"done",     "total":N, "errors":[…], "profile":{…}, "epgUrl":"…"}
"""

from http.server import BaseHTTPRequestHandler
import json, hashlib, re, time, ipaddress
import urllib.request, urllib.parse, urllib.error
from urllib.parse import urlencode, urlparse

# Shared utilities — single source of truth
from sanitize import sanitize_url, classify_stream_type, is_uncheckable


# ── SSRF guard ────────────────────────────────────────────────────────────────

_BLOCKED_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),   # link-local / AWS metadata
    ipaddress.ip_network('100.64.0.0/10'),    # Carrier-grade NAT
    ipaddress.ip_network('::1/128'),          # IPv6 loopback
    ipaddress.ip_network('fc00::/7'),         # IPv6 ULA
    ipaddress.ip_network('fe80::/10'),        # IPv6 link-local
]

def _is_ssrf_safe(url: str) -> tuple:
    """
    Return (True, '') if the URL is safe to fetch, or (False, reason) if blocked.
    Blocks private/loopback/link-local addresses and known cloud metadata endpoints.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False, f'Scheme not allowed: {parsed.scheme}'
        host = parsed.hostname or ''
        metadata_hosts = [
            'metadata.google.internal',
            'metadata.goog',
            'instance-data',
        ]
        if any(host == mh or host.endswith('.' + mh) for mh in metadata_hosts):
            return False, f'Blocked metadata host: {host}'
        try:
            ip = ipaddress.ip_address(host)
            for blocked in _BLOCKED_RANGES:
                if ip in blocked:
                    return False, f'Blocked private/internal address: {host}'
        except ValueError:
            pass
        return True, ''
    except Exception as e:
        return False, f'URL parse error: {e}'


# ── Portal path auto-detection ────────────────────────────────────────────────
#
# Stalker/Ministra portals are deployed at many different sub-paths.
# We probe these in order and cache the first one that returns JSON.
#
# Common paths seen in the wild:
#   /portal.php                     — classic Stalker
#   /c/portal.php                   — Ministra default
#   /stalker_portal/c/portal.php    — self-hosted Ministra
#   /server/load.php                — older MAG firmware target
#   /c/                             — some rebranded panels
#   /stalker_portal/server/load.php — alternate self-hosted
#   /api/                           — modern XC / hybrid panels

_PORTAL_PATH_CANDIDATES = [
    "/portal.php",
    "/c/portal.php",
    "/stalker_portal/c/portal.php",
    "/server/load.php",
    "/c/",
    "/stalker_portal/server/load.php",
    "/api/",
]

_resolved_bases: dict = {}   # cache: raw_base → resolved_base (per process lifetime)


def _probe_one(base: str, path: str, mac: str) -> bool:
    """Return True if GET base+path?action=handshake returns valid JSON with a token."""
    try:
        url = f"{base}{path}?{urlencode({'action': 'handshake', 'type': 'stb', 'prehash': 0})}"
        req = urllib.request.Request(url, headers=build_headers(mac))
        with urllib.request.urlopen(req, timeout=8) as resp:
            ct = resp.headers.get('Content-Type', '')
            raw = resp.read(512)          # read only first 512 bytes for probe
            # Reject HTML responses immediately
            if raw.lstrip()[:1] in (b'<', b'\xef'):   # HTML or BOM
                return False
            if 'html' in ct.lower():
                return False
            # Try to parse as JSON and check for token
            try:
                data = json.loads(raw + resp.read())   # read remainder
            except Exception:
                return False
            token = (data.get('js') or {}).get('token') or data.get('token')
            return bool(token)
    except Exception:
        return False


def resolve_portal_base(raw_base: str, mac: str) -> str:
    """
    Return a resolved base URL that includes the correct portal sub-path,
    e.g. "http://host:8080/c" instead of "http://host:8080".

    If the caller already included a sub-path (URL does not end at just host:port)
    we honour it directly without probing.

    Raises RuntimeError listing all tried paths if none succeed.
    """
    if raw_base in _resolved_bases:
        return _resolved_bases[raw_base]

    parsed = urlparse(raw_base)
    existing_path = parsed.path.rstrip('/')

    # If the user typed a path beyond the root, trust it (strip trailing /portal.php if present)
    if existing_path and existing_path not in ('', '/'):
        resolved = raw_base.rstrip('/')
        _resolved_bases[raw_base] = resolved
        return resolved

    # Auto-probe
    origin = f"{parsed.scheme}://{parsed.netloc}"   # scheme + host + port only
    tried = []
    for path in _PORTAL_PATH_CANDIDATES:
        # Derive a clean base from origin + path prefix (drop the filename part)
        base_candidate = origin + path.rstrip('/').rsplit('/', 1)[0]   # directory
        full_path = path
        if _probe_one(origin, full_path, mac):
            # resolved base = origin + directory of the working path
            resolved = (origin + path.rstrip('/').rsplit('/', 1)[0]).rstrip('/')
            # Store the actual file suffix so portal_url() can use it
            # We encode it by returning origin+full_directory and letting
            # portal_url() append /portal.php — BUT if the working path
            # is NOT portal.php we need a different suffix.
            # Simplest: store the full working prefix as resolved_base.
            suffix_file = path.split('/')[-1]   # e.g. "portal.php"
            if suffix_file and suffix_file.endswith('.php'):
                resolved_base = origin + '/'.join(path.split('/')[:-1])  # dir only
            else:
                resolved_base = origin + path.rstrip('/')
            resolved_base = resolved_base.rstrip('/')
            _resolved_bases[raw_base] = resolved_base
            return resolved_base
        tried.append(path)

    raise RuntimeError(
        f"Portal did not respond to any known path. Tried: {', '.join(tried)}. "
        "Check the URL and make sure the portal is reachable."
    )


# ── M3U helpers ────────────────────────────────────────────────────────────────

def extract_known_urls(m3u_text: str) -> set:
    if not m3u_text:
        return set()
    return {line.strip() for line in m3u_text.splitlines()
            if line.strip() and not line.strip().startswith('#')}


# ── Stalker portal helpers ─────────────────────────────────────────────────────

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
    """
    Build a full portal API URL.
    `base` is already resolved (includes sub-path directory).
    We always append /portal.php unless base already ends with a .php or trailing path.
    """
    params["action"] = action
    base = base.rstrip('/')
    # If base ends with a known script name, use it directly
    if base.endswith('.php') or base.endswith('/'):
        script = base
    else:
        script = f"{base}/portal.php"
    return f"{script}?{urlencode(params)}"

def http_get(url, headers, timeout=20):
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
        # Detect HTML error pages before attempting JSON parse
        snippet = raw.lstrip()[:50]
        if snippet.startswith(b'<') or snippet.lower().startswith(b'<!doctype'):
            raise ValueError(
                "Portal returned an HTML page instead of JSON. "
                "The path may be wrong, the MAC may be banned, or the portal requires a VPN."
            )
        return json.loads(raw.decode("utf-8", errors="replace"))

def handshake(base, mac):
    """Resolve portal path, perform handshake, return token."""
    resolved = resolve_portal_base(base, mac)
    data = http_get(portal_url(resolved, "handshake", type="stb", prehash=0), build_headers(mac))
    token = data.get("js", {}).get("token") or data.get("token")
    if not token:
        raise RuntimeError("No token in handshake response")
    # Update cache with resolved base so subsequent calls reuse it
    _resolved_bases[base] = resolved
    return token, resolved

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
    t = {"live": "itv", "vod": "vod", "series": "series"}.get(media_type, "itv")
    try:
        data = http_get(portal_url(base, action, type=t), build_headers(mac, token))
        js = data.get("js") or []
        if isinstance(js, dict):
            js = list(js.values())
        return {str(g.get("id", "")): (g.get("title") or g.get("name", "")).strip()
                for g in js if g.get("id")}
    except Exception:
        return {}

def clean_cmd(cmd):
    """Strip ffmpeg/auto prefix; return a plain URL or empty string."""
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
    t = {"live": "itv", "vod": "vod", "series": "series"}.get(media_type, "itv")
    url = portal_url(base, "get_ordered_list",
        type=t, genre="*",
        force_ch_link_check=0, fav=0, sortby="number", hd=0,
        p=page, JsHttpRequest=f"{int(time.time() * 1000)}-xml")
    js = http_get(url, build_headers(mac, token)).get("js", {})
    if isinstance(js, list):
        return js, len(js)
    data  = js.get("data") or []
    total = int(js.get("total_items") or js.get("total") or 0)
    return data, total

def create_link(base, mac, token, cmd):
    try:
        url = portal_url(base, "create_link", type="itv",
                         cmd=urllib.parse.quote(cmd, safe=""),
                         JsHttpRequest=f"{int(time.time() * 1000)}-xml")
        raw = http_get(url, build_headers(mac, token)).get("js", {}).get("cmd", "")
        return clean_cmd(raw)
    except Exception:
        return ""

def build_channel(ch, genres, media_type, base, mac, token, known_urls, fallback_number):
    """Normalize one raw portal channel dict into our schema.
    Returns None if the channel should be skipped (already in known_urls).
    """
    genre_id = str(ch.get("tv_genre_id") or ch.get("category_id") or "")
    raw_cmd  = ch.get("cmd") or ""
    stream   = clean_cmd(raw_cmd)

    if not stream and raw_cmd and media_type == "live":
        stream = create_link(base, mac, token, raw_cmd)

    if stream and stream in known_urls:
        return None

    return {
        "name":        (ch.get("name") or ch.get("title") or "Unknown").strip(),
        "logo":        ch.get("logo") or ch.get("screenshot_uri") or "",
        "group":       genres.get(genre_id, "Uncategorized"),
        "number":      ch.get("number") or ch.get("ch_number") or fallback_number,
        "stream_url":  stream,
        "epg_id":      ch.get("xmltv_id") or ch.get("tvg_id") or "",
        "raw_cmd":     raw_cmd,
        "uncheckable": is_uncheckable(stream) if stream else False,
        "stream_type": classify_stream_type(stream or raw_cmd or ""),
        "media_type":  media_type,
    }

def fetch_all(base, mac, token, media_type, max_pages=50, known_urls=None):
    """Buffered fetch — used by format=m3u path."""
    genres     = fetch_genres(base, mac, token, media_type)
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
            cid = str(ch.get("id", "") or ch.get("cmd", ""))
            if cid in seen:
                continue
            seen.add(cid)
            built = build_channel(ch, genres, media_type, base, mac, token, known_urls, len(channels) + 1)
            if built:
                channels.append(built)
        if total and len(channels) >= total:
            break

    return channels

def build_m3u(channels, epg_url=""):
    lines = [f'#EXTM3U url-tvg="{epg_url}"' if epg_url else "#EXTM3U"]
    for ch in channels:
        url = ch.get("stream_url") or ch.get("raw_cmd") or ""
        if not url:
            continue
        name  = ch["name"]
        stype = classify_stream_type(url)
        group = ch.get("group", "Uncategorized")
        if ch.get("uncheckable"):
            group = "\u26a0 Auth Required"
        lines.append(
            f'#EXTINF:-1 tvg-id="{ch["epg_id"]}" tvg-name="{name}" '
            f'tvg-logo="{ch["logo"]}" group-title="{group}" '
            f'tvg-chno="{ch["number"]}" tvg-type="{stype}",{name}'
        )
        lines.append(url)
    return "\n".join(lines) + "\n"


# ── Vercel handler ─────────────────────────────────────────────────────────────

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

    def start_ndjson(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-transform")
        self.send_header("X-Accel-Buffering", "no")
        self._cors()
        self.end_headers()

    def emit(self, payload: dict):
        line = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
        self.wfile.write(line)
        self.wfile.flush()

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_POST(self):
        try:
            length  = int(self.headers.get("Content-Length", 0))
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

        # ── SSRF guard — must pass before any network call ─────────────────────
        ssrf_ok, ssrf_reason = _is_ssrf_safe(portal)
        if not ssrf_ok:
            return self.send_json(400, {"error": f"Blocked portal URL: {ssrf_reason}"})

        known_urls = extract_known_urls(skip_known)

        try:
            token, resolved_portal = handshake(portal, mac)
        except Exception as e:
            return self.send_json(502, {"error": f"Handshake failed: {e}"})

        profile = {}
        try:
            profile = get_profile(resolved_portal, mac, token)
        except Exception:
            pass

        # ── format=m3u  (buffered, backward-compatible) ────────────────────────
        if fmt != "json":
            all_channels, errors = [], []
            for t in types:
                try:
                    all_channels.extend(fetch_all(resolved_portal, mac, token, t, max_pgs, known_urls))
                except Exception as e:
                    errors.append(f"{t}: {e}")
            if not all_channels and errors:
                return self.send_json(502, {"error": "No channels fetched", "details": errors})
            return self.send_m3u(build_m3u(all_channels, epg_url))

        # ── format=json  (NDJSON streaming) ───────────────────────────────────
        self.start_ndjson()
        self.emit({
            "event":     "meta",
            "portal":    portal,
            "types":     types,
            "maxPages":  max_pgs,
            "epgUrl":    epg_url,
            "knownUrls": len(known_urls),
        })
        self.emit({"event": "profile", "profile": profile})

        sent   = 0
        errors = []
        estimated_total = max(len(types) * max_pgs * 20, 20)

        for media_type in types:
            genres    = fetch_genres(resolved_portal, mac, token, media_type)
            seen      = set()
            type_sent = 0

            for page in range(1, max_pgs + 1):
                try:
                    items, total_items = fetch_page(resolved_portal, mac, token, media_type, page)
                except Exception as e:
                    err_msg = str(e)
                    errors.append(f"{media_type} p{page}: {err_msg}")
                    self.emit({"event": "error", "scope": media_type,
                               "message": err_msg, "page": page})
                    break

                if total_items:
                    estimated_total = max(estimated_total, sent + total_items)

                if not items:
                    break

                for ch in items:
                    cid = str(ch.get("id", "") or ch.get("cmd", ""))
                    if cid in seen:
                        continue
                    seen.add(cid)
                    built = build_channel(ch, genres, media_type,
                                          resolved_portal, mac, token, known_urls, sent + 1)
                    if not built:
                        continue
                    sent      += 1
                    type_sent += 1
                    self.emit({"event": "channel", "count": sent, "channel": built})

                self.emit({
                    "event":          "progress",
                    "scope":          media_type,
                    "page":           page,
                    "count":          sent,
                    "typeCount":      type_sent,
                    "estimatedTotal": estimated_total,
                    "done":           False,
                })

            self.emit({
                "event":          "progress",
                "scope":          media_type,
                "count":          sent,
                "typeCount":      type_sent,
                "estimatedTotal": estimated_total,
                "done":           True,
            })

        self.emit({
            "event":   "done",
            "total":   sent,
            "errors":  errors,
            "profile": profile,
            "epgUrl":  epg_url,
        })
