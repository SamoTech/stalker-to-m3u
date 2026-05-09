"""
api/sanitize.py — shared URL utilities used by convert.py and validate.py.

All functions are pure (no I/O) and importable via:
    from sanitize import sanitize_url, classify_stream_type, is_uncheckable
"""

import re

# ── Stream-type classification ────────────────────────────────────────────────

STREAM_TYPE_MAP = {
    '.m3u8': 'video', '.m3u': 'video', '.ts': 'video', '.mp4': 'video',
    '.avi': 'video', '.mkv': 'video', '.flv': 'video',
    '.mp3': 'audio', '.aac': 'audio', '.pls': 'audio', '.ogg': 'audio',
    '/stream': 'audio', '/radio/': 'audio',
}

UNCHECKABLE_KEYWORDS = ['token', 'auth', 'login', 'key', 'signature', 'drm']


def classify_stream_type(url: str) -> str:
    """Return 'video' or 'audio' based on URL patterns."""
    low = url.lower().split('?')[0]
    for pat, typ in STREAM_TYPE_MAP.items():
        if pat in low:
            return typ
    return 'video'


def sanitize_url(url: str) -> str:
    """Strip ad-injected query params from .m3u8 URLs."""
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
    """Return True if the URL should not be probed (token-signed, auth, DRM, too long)."""
    if len(url) > 250:
        return True
    low = url.lower()
    return any(kw in low for kw in UNCHECKABLE_KEYWORDS)
