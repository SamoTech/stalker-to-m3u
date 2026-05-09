"""
api/stalker.py  —  Shared Stalker/Ministra protocol library.

All portal auth, API calls, URL utilities, and M3U building live here.
Each handler (convert.py, test.py, validate.py) imports from this module.
Nothing in this file does any HTTP serving.
"""

import hashlib, json, re, time, ipaddress
import urllib.request, urllib.error, urllib.parse
from urllib.parse import urlencode, urlparse
from typing import Optional


# ══════════════════════════════════════════════════════════════════════════════
# URL utilities
# ══════════════════════════════════════════════════════════════════════════════

STREAM_TYPE_MAP = {
    '.m3u8': 'video', '.m3u': 'video', '.ts': 'video', '.mp4': 'video',
    '.avi': 'video', '.mkv': 'video', '.flv': 'video',
    '.mp3': 'audio', '.aac': 'audio', '.pls': 'audio', '.ogg': 'audio',
    '/stream': 'audio', '/radio/': 'audio',
}

UNCHECKABLE_KEYWORDS = ['token', 'auth', 'login', 'key', 'signature', 'drm']


def classify_stream_type(url: str) -> str:
    low = url.lower().split('?')[0]
    for pat, typ in STREAM_TYPE_MAP.items():
        if pat in low:
            return typ
    return 'video'


def sanitize_url(url: str) -> str:
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
    if len(url) > 250:
        return True
    low = url.lower()
    return any(kw in low for kw in UNCHECKABLE_KEYWORDS)


def extract_known_urls(m3u_text: str) -> set:
    if not m3u_text:
        return set()
    return {
        line.strip()
        for line in m3u_text.splitlines()
        if line.strip() and not line.strip().startswith('#')
    }


# ══════════════════════════════════════════════════════════════════════════════
# SSRF guard
# ══════════════════════════════════════════════════════════════════════════════

_BLOCKED_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('100.64.0.0/10'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('fe80::/10'),
]

_METADATA_HOSTS = [
    'metadata.google.internal',
    'metadata.goog',
    'instance-data',
]


def is_ssrf_safe(url: str) -> tuple:
    """
    Return (True, '') if safe, or (False, reason) if blocked.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False, f'Scheme not allowed: {parsed.scheme}'
        host = parsed.hostname or ''
        if any(host == mh or host.endswith('.' + mh) for mh in _METADATA_HOSTS):
            return False, f'Blocked metadata host: {host}'
        try:
            ip = ipaddress.ip_address(host)
            for blocked in _BLOCKED_RANGES:
                if ip in blocked:
                    return False, f'Blocked private/internal address: {host}'
        except ValueError:
            pass   # hostname — OK
        return True, ''
    except Exception as e:
        return False, f'URL parse error: {e}'


# ══════════════════════════════════════════════════════════════════════════════
# MAG / Stalker credential helpers
# ══════════════════════════════════════════════════════════════════════════════

def mac_to_serial(mac: str) -> str:
    return hashlib.md5(mac.replace(':', '').upper().encode()).hexdigest()[:13].upper()


def mac_to_device_id(mac: str) -> str:
    return hashlib.sha256(mac.replace(':', '').upper().encode()).hexdigest()[:64].upper()


def mac_to_signature(mac: str) -> str:
    return hashlib.sha256((mac.replace(':', '').upper() + 'stalker').encode()).hexdigest()[:64].upper()


def build_headers(mac: str, token: str = '') -> dict:
    h = {
        'User-Agent': (
            'Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 '
            '(KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3'
        ),
        'X-User-Agent': 'Model: MAG200; Link: Ethernet',
        'Cookie': f'mac={mac}; stb_lang=en; timezone=Europe/London',
        'Accept': '*/*',
    }
    if token:
        h['Authorization'] = f'Bearer {token}'
    return h


# ══════════════════════════════════════════════════════════════════════════════
# Portal path auto-detection
# ══════════════════════════════════════════════════════════════════════════════

# Paths tried in order; first one that returns a valid handshake JSON wins.
_PATH_CANDIDATES = [
    '/portal.php',
    '/c/portal.php',
    '/stalker_portal/c/portal.php',
    '/server/load.php',
    '/c/',
    '/stalker_portal/server/load.php',
    '/api/',
]

# Single-segment stub paths that look like sub-paths but are actually
# just the portal root directory prefix (e.g. /c, /stalker_portal).
# When the user supplies one of these, we treat the origin as base and probe.
_STUB_PATHS = {'/c', '/stalker_portal', '/server', '/api', '/portal'}

# Process-lifetime cache: raw_base → resolved_base
_resolved_bases: dict = {}


def _portal_script(base: str) -> str:
    """
    Return the full URL of the portal script for a resolved base.
    If base already ends with .php we use it directly; otherwise we
    append /portal.php.
    """
    base = base.rstrip('/')
    if base.endswith('.php'):
        return base
    return f'{base}/portal.php'


def portal_url(base: str, action: str, **params) -> str:
    params['action'] = action
    return f'{_portal_script(base)}?{urlencode(params)}'


def _probe_path(origin: str, path: str, mac: str) -> bool:
    """
    Return True if GET origin+path?action=handshake yields a valid token.
    Reads the ENTIRE response body inside the `with` block to avoid
    ValueError when accessing a closed socket after __exit__.
    """
    try:
        url = (
            f'{origin}{path}'
            f'?{urlencode({"action": "handshake", "type": "stb", "prehash": 0})}'
        )
        req = urllib.request.Request(url, headers=build_headers(mac))
        with urllib.request.urlopen(req, timeout=8) as resp:
            ct  = resp.headers.get('Content-Type', '').lower()
            raw = resp.read()                  # ← full read INSIDE the with block
        # Reject HTML
        snippet = raw.lstrip()[:9].lower()
        if snippet.startswith(b'<!doctype') or snippet.startswith(b'<html'):
            return False
        if 'html' in ct:
            return False
        data  = json.loads(raw)
        token = (data.get('js') or {}).get('token') or data.get('token')
        return bool(token)
    except Exception:
        return False


def resolve_portal_base(raw_base: str, mac: str) -> str:
    """
    Return a resolved base URL (includes the correct sub-path directory).

    Strategy:
    - If the user-supplied path is a known stub (e.g. /c, /stalker_portal)
      we strip it and probe from the origin — the stub will be found again
      via _PATH_CANDIDATES.
    - If the user supplied a deeper non-root path (e.g. /some/deep/path)
      we honour it directly.
    - If path is root or empty, we probe all candidates from the origin.

    Raises RuntimeError if nothing responds with a valid handshake.
    """
    if raw_base in _resolved_bases:
        return _resolved_bases[raw_base]

    parsed   = urlparse(raw_base)
    origin   = f'{parsed.scheme}://{parsed.netloc}'
    existing = parsed.path.rstrip('/')

    # Trust the path only if it's a deep, non-stub path
    if existing and existing != '/' and existing not in _STUB_PATHS:
        resolved = raw_base.rstrip('/')
        _resolved_bases[raw_base] = resolved
        return resolved

    # Auto-probe candidates (covers root paths AND stub paths like /c)
    tried = []
    for path in _PATH_CANDIDATES:
        if _probe_path(origin, path, mac):
            # Resolved base = origin + directory portion of the working path
            parts    = path.rstrip('/').split('/')
            last     = parts[-1]
            dir_path = '/'.join(parts[:-1]) if last.endswith('.php') else path.rstrip('/')
            resolved = (origin + dir_path).rstrip('/')
            _resolved_bases[raw_base] = resolved
            return resolved
        tried.append(path)

    raise RuntimeError(
        f'Portal did not respond to any known path. '
        f'Tried: {", ".join(tried)}. '
        'Check the URL and make sure the portal is reachable from the internet.'
    )


# ══════════════════════════════════════════════════════════════════════════════
# HTTP helpers
# ══════════════════════════════════════════════════════════════════════════════

def http_get(url: str, headers: dict, timeout: int = 20) -> dict:
    """
    Perform a GET request and return parsed JSON.
    Raises ValueError for HTML responses, json.JSONDecodeError for bad JSON.
    """
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()                      # full read inside context
    snippet = raw.lstrip()[:9].lower()
    if snippet.startswith(b'<!doctype') or snippet.startswith(b'<html'):
        raise ValueError(
            'Portal returned an HTML page instead of JSON. '
            'The sub-path may be wrong, the MAC may be banned, '
            'or the portal requires a VPN.'
        )
    return json.loads(raw.decode('utf-8', errors='replace'))


# ══════════════════════════════════════════════════════════════════════════════
# Stalker auth flow
# ══════════════════════════════════════════════════════════════════════════════

def handshake(raw_base: str, mac: str) -> tuple:
    """
    Resolve the portal path, perform the Stalker handshake, return (token, resolved_base).
    """
    resolved = resolve_portal_base(raw_base, mac)
    data     = http_get(portal_url(resolved, 'handshake', type='stb', prehash=0),
                        build_headers(mac))
    token    = (data.get('js') or {}).get('token') or data.get('token')
    if not token:
        raise RuntimeError('No token in handshake response')
    return token, resolved


def get_profile(base: str, mac: str, token: str) -> dict:
    url = portal_url(
        base, 'get_profile',
        hd=1, ver='ImageDescription: 0.2.18-r14-pub-250;',
        num_banks=2, sn=mac_to_serial(mac), stb_type='MAG200',
        image_version=218, video_out='hdmi',
        device_id=mac_to_device_id(mac), device_id2=mac_to_device_id(mac),
        signature=mac_to_signature(mac), auth_second_step=1,
        hw_version='1.7-BD-00', not_valid_token=0,
        client_type='STB', hw_version_2=mac_to_serial(mac),
    )
    return http_get(url, build_headers(mac, token)).get('js', {})


# ══════════════════════════════════════════════════════════════════════════════
# Portal API helpers
# ══════════════════════════════════════════════════════════════════════════════

def fetch_genres(base: str, mac: str, token: str, media_type: str) -> dict:
    action = 'get_genres' if media_type == 'live' else 'get_categories'
    t      = {'live': 'itv', 'vod': 'vod', 'series': 'series'}.get(media_type, 'itv')
    try:
        data = http_get(portal_url(base, action, type=t), build_headers(mac, token))
        js   = data.get('js') or []
        if isinstance(js, dict):
            js = list(js.values())
        return {
            str(g.get('id', '')): (g.get('title') or g.get('name', '')).strip()
            for g in js if g.get('id')
        }
    except Exception:
        return {}


def fetch_page(base: str, mac: str, token: str, media_type: str, page: int) -> tuple:
    t   = {'live': 'itv', 'vod': 'vod', 'series': 'series'}.get(media_type, 'itv')
    url = portal_url(
        base, 'get_ordered_list',
        type=t, genre='*', force_ch_link_check=0, fav=0,
        sortby='number', hd=0, p=page,
        JsHttpRequest=f'{int(time.time() * 1000)}-xml',
    )
    js = http_get(url, build_headers(mac, token)).get('js', {})
    if isinstance(js, list):
        return js, len(js)
    data  = js.get('data') or []
    total = int(js.get('total_items') or js.get('total') or 0)
    return data, total


def clean_cmd(cmd: str) -> str:
    """Strip ffmpeg/auto prefix; return a plain URL or empty string."""
    if not cmd:
        return ''
    cmd = cmd.strip()
    if re.match(r'^https?://', cmd) or cmd.startswith('rtsp://'):
        return sanitize_url(cmd)
    m = re.match(r'^(?:ffmpeg|auto)\s+(https?://\S+|rtsp://\S+)', cmd)
    if m:
        return sanitize_url(m.group(1))
    return cmd


def create_link(base: str, mac: str, token: str, cmd: str) -> str:
    try:
        url = portal_url(
            base, 'create_link',
            type='itv',
            cmd=urllib.parse.quote(cmd, safe=''),
            JsHttpRequest=f'{int(time.time() * 1000)}-xml',
        )
        raw = http_get(url, build_headers(mac, token)).get('js', {}).get('cmd', '')
        return clean_cmd(raw)
    except Exception:
        return ''


def count_items(base: str, mac: str, token: str, media_type: str) -> int:
    """Return total_items from page 1 of get_ordered_list."""
    t = {'live': 'itv', 'vod': 'vod', 'series': 'series'}.get(media_type, 'itv')
    try:
        url = portal_url(
            base, 'get_ordered_list',
            type=t, genre='*', force_ch_link_check=0, fav=0,
            sortby='number', hd=0, p=1,
            JsHttpRequest=f'{int(time.time() * 1000)}-xml',
        )
        js = http_get(url, build_headers(mac, token)).get('js', {})
        if isinstance(js, list):
            return len(js)
        return int(js.get('total_items') or js.get('total') or 0)
    except Exception:
        return -1


# ══════════════════════════════════════════════════════════════════════════════
# Channel building
# ══════════════════════════════════════════════════════════════════════════════

def build_channel(
    ch: dict,
    genres: dict,
    media_type: str,
    base: str,
    mac: str,
    token: str,
    known_urls: set,
    fallback_number: int,
) -> Optional[dict]:
    """
    Normalize a raw portal channel dict into our internal schema.
    Returns None if the channel should be skipped (already in known_urls).
    """
    genre_id = str(ch.get('tv_genre_id') or ch.get('category_id') or '')
    raw_cmd  = ch.get('cmd') or ''
    stream   = clean_cmd(raw_cmd)

    if not stream and raw_cmd and media_type == 'live':
        stream = create_link(base, mac, token, raw_cmd)

    if stream and stream in known_urls:
        return None

    return {
        'name':        (ch.get('name') or ch.get('title') or 'Unknown').strip(),
        'logo':        ch.get('logo') or ch.get('screenshot_uri') or '',
        'group':       genres.get(genre_id, 'Uncategorized'),
        'number':      ch.get('number') or ch.get('ch_number') or fallback_number,
        'stream_url':  stream or '',
        'epg_id':      ch.get('xmltv_id') or ch.get('tvg_id') or '',
        'raw_cmd':     raw_cmd,
        'uncheckable': is_uncheckable(stream) if stream else False,
        'stream_type': classify_stream_type(stream or raw_cmd or ''),
        'media_type':  media_type,
    }


def fetch_all(
    base: str,
    mac: str,
    token: str,
    media_type: str,
    max_pages: int = 50,
    known_urls: Optional[set] = None,
) -> list:
    """Buffered fetch of all pages for one media type."""
    genres     = fetch_genres(base, mac, token, media_type)
    channels   = []
    seen: set  = set()
    total      = None
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
            cid = str(ch.get('id', '') or ch.get('cmd', ''))
            if cid in seen:
                continue
            seen.add(cid)
            built = build_channel(
                ch, genres, media_type, base, mac, token, known_urls, len(channels) + 1
            )
            if built:
                channels.append(built)
        if total and len(channels) >= total:
            break

    return channels


# ══════════════════════════════════════════════════════════════════════════════
# M3U builder
# ══════════════════════════════════════════════════════════════════════════════

def build_m3u(channels: list, epg_url: str = '') -> str:
    lines = [f'#EXTM3U url-tvg="{epg_url}"' if epg_url else '#EXTM3U']
    for ch in channels:
        url = ch.get('stream_url') or ch.get('raw_cmd') or ''
        if not url:
            continue
        name  = ch['name']
        group = ch.get('group', 'Uncategorized')
        if ch.get('uncheckable'):
            group = '\u26a0 Auth Required'
        stype = classify_stream_type(url)
        lines.append(
            f'#EXTINF:-1 tvg-id="{ch["epg_id"]}" tvg-name="{name}" '
            f'tvg-logo="{ch["logo"]}" group-title="{group}" '
            f'tvg-chno="{ch["number"]}" tvg-type="{stype}",{name}'
        )
        lines.append(url)
    return '\n'.join(lines) + '\n'
