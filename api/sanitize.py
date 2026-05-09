"""
api/sanitize.py  —  Shared URL utilities imported by convert.py and validate.py.

Exports:
    STREAM_TYPE_MAP          dict
    UNCHECKABLE_KEYWORDS     list
    UNCHECKABLE_URL_LENGTH_THRESHOLD  int
    sanitize_url(url)        -> str
    classify_stream_type(url)-> str
    is_uncheckable(url)      -> tuple[bool, str]
"""

# ── Constants ─────────────────────────────────────────────────────────────────

UNCHECKABLE_URL_LENGTH_THRESHOLD = 250

UNCHECKABLE_KEYWORDS = ['token', 'auth', 'login', 'key', 'signature', 'drm']

STREAM_TYPE_MAP = {
    '.m3u8': 'video', '.m3u': 'video', '.ts': 'video', '.mp4': 'video',
    '.avi': 'video', '.mkv': 'video', '.flv': 'video',
    '.mp3': 'audio', '.aac': 'audio', '.pls': 'audio', '.ogg': 'audio',
    '/stream': 'audio', '/radio/': 'audio',
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def sanitize_url(url: str) -> str:
    """Strip ad-injected query params from .m3u8 URLs.

    Some portals append ad-network query strings to .m3u8 stream URLs
    (e.g. ?ads.adserver=...&vast=...). These cause players to fail.
    We strip them while preserving any legitimate auth params.
    """
    try:
        idx = url.find('.m3u8?')
        if idx != -1:
            qs = url[idx + 6:].lower()
            if any(kw in qs for kw in ['ads.', 'ad=', 'adv=', 'vast=', 'ima=']):
                return url[:idx + 6].rstrip('?')
    except Exception:
        pass
    return url


def classify_stream_type(url: str) -> str:
    """Classify a stream URL as 'video', 'audio', or 'video' (default).

    Uses file extension and path patterns. Query strings are ignored.
    Defaults to 'video' since the majority of IPTV streams are video.
    """
    low = url.lower().split('?')[0]  # strip query string before matching
    for pat, typ in STREAM_TYPE_MAP.items():
        if pat in low:
            return typ
    return 'video'


def is_uncheckable(url: str) -> tuple:
    """Return (True, reason_str) if the URL cannot be reliably probed.

    URLs are uncheckable when:
    - They are excessively long (likely token-signed / per-session)
    - They contain auth-related keywords (token, key, signature, drm, ...)

    Probing these would produce false negatives because:
    - The HEAD request would fail due to missing session context
    - The token may have already expired
    """
    if len(url) > UNCHECKABLE_URL_LENGTH_THRESHOLD:
        return True, 'URL too long (likely token-signed)'
    low = url.lower()
    for kw in UNCHECKABLE_KEYWORDS:
        if kw in low:
            return True, f'Auth keyword detected: {kw}'
    return False, ''
