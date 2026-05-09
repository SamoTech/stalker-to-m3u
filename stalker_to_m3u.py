#!/usr/bin/env python3
"""
stalker_to_m3u.py — Convert Stalker/Ministra IPTV portal (MAC-based) to M3U playlist.

Usage:
    python stalker_to_m3u.py --portal http://HOST:PORT --mac 00:1A:79:XX:XX:XX
    python stalker_to_m3u.py --portal http://HOST:PORT --mac 00:1A:79:XX:XX:XX --output playlist.m3u
    python stalker_to_m3u.py --portal http://HOST:PORT --mac 00:1A:79:XX:XX:XX --types live vod series
    python stalker_to_m3u.py --portal http://HOST:PORT --mac 00:1A:79:XX:XX:XX --max-pages 100

Requirements:
    pip install requests
"""

import argparse
import hashlib
import json
import re
import sys
import time
from urllib.parse import urlparse, urljoin

try:
    import requests
except ImportError:
    print("[ERROR] 'requests' library not found. Install it with: pip install requests")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def mac_to_serial(mac: str) -> str:
    """Derive a serial-number-like string from the MAC address."""
    clean = mac.replace(":", "").upper()
    return hashlib.md5(clean.encode()).hexdigest()[:13].upper()


def mac_to_device_id(mac: str) -> str:
    """Derive a device-id string from the MAC address."""
    clean = mac.replace(":", "").upper()
    return hashlib.sha256(clean.encode()).hexdigest()[:64].upper()


def mac_to_signature(mac: str) -> str:
    """Derive a signature string from the MAC address."""
    clean = mac.replace(":", "").upper()
    return hashlib.sha256((clean + "stalker").encode()).hexdigest()[:64].upper()


def build_headers(mac: str, token: str = "") -> dict:
    serial = mac_to_serial(mac)
    device_id = mac_to_device_id(mac)
    sig = mac_to_signature(mac)
    headers = {
        "User-Agent": "Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 "
                      "(KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3",
        "X-User-Agent": "Model: MAG200; Link: Ethernet",
        "Cookie": f"mac={mac}; stb_lang=en; timezone=Europe/London",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def portal_url(base: str, action: str, **params) -> str:
    """Build a Stalker portal API URL."""
    base = base.rstrip("/")
    qs = "&".join(f"{k}={v}" for k, v in params.items())
    return f"{base}/portal.php?action={action}&{qs}" if qs else f"{base}/portal.php?action={action}"


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def handshake(session: requests.Session, base: str, mac: str) -> str:
    """Perform the Stalker handshake and return the token."""
    url = portal_url(base, "handshake", type="stb", prehash=0)
    resp = session.get(url, headers=build_headers(mac), timeout=15)
    resp.raise_for_status()
    data = resp.json()
    token = data.get("js", {}).get("token") or data.get("token")
    if not token:
        raise RuntimeError(f"Handshake failed — no token in response: {resp.text[:300]}")
    return token


def get_profile(session: requests.Session, base: str, mac: str, token: str) -> dict:
    """Fetch the subscriber profile."""
    url = portal_url(base, "get_profile", hd=1, ver="ImageDescription: 0.2.18-r14-pub-250;",
                     num_banks=2, sn=mac_to_serial(mac), stb_type="MAG200",
                     image_version=218, video_out="hdmi", device_id=mac_to_device_id(mac),
                     device_id2=mac_to_device_id(mac), signature=mac_to_signature(mac),
                     auth_second_step=1, hw_version="1.7-BD-00", not_valid_token=0,
                     client_type="STB", hw_version_2=mac_to_serial(mac))
    resp = session.get(url, headers=build_headers(mac, token), timeout=15)
    resp.raise_for_status()
    return resp.json().get("js", {})


# ---------------------------------------------------------------------------
# Channel fetching
# ---------------------------------------------------------------------------

def fetch_genres(session: requests.Session, base: str, mac: str, token: str, media_type: str) -> dict:
    """Return a dict of genre_id -> genre_name."""
    action_map = {"live": "get_genres", "vod": "get_categories", "series": "get_categories"}
    type_map = {"live": "itv", "vod": "vod", "series": "series"}
    action = action_map.get(media_type, "get_genres")
    t = type_map.get(media_type, "itv")
    url = portal_url(base, action, type=t)
    resp = session.get(url, headers=build_headers(mac, token), timeout=15)
    resp.raise_for_status()
    genres = {}
    for g in resp.json().get("js", []):
        gid = str(g.get("id", ""))
        gname = g.get("title") or g.get("name", "").strip()
        if gid and gname:
            genres[gid] = gname
    return genres


def fetch_channels_page(
    session: requests.Session,
    base: str,
    mac: str,
    token: str,
    media_type: str,
    page: int,
    genre_id: int = 0,
) -> tuple[list, int]:
    """
    Fetch one page of channels. Returns (channels_list, total_items).
    """
    action_map = {"live": "get_ordered_list", "vod": "get_ordered_list", "series": "get_ordered_list"}
    type_map = {"live": "itv", "vod": "vod", "series": "series"}
    action = action_map.get(media_type)
    t = type_map.get(media_type, "itv")
    url = portal_url(
        base, action,
        type=t, action="get_ordered_list",
        genre=genre_id, force_ch_link_check=0,
        fav=0, sortby="number", hd=0,
        p=page, JsHttpRequest=f"{int(time.time() * 1000)}-xml"
    )
    resp = session.get(url, headers=build_headers(mac, token), timeout=20)
    resp.raise_for_status()
    js = resp.json().get("js", {})
    channels = js.get("data", [])
    total = int(js.get("total_items", 0) or js.get("total", 0))
    return channels, total


def fetch_stream_url(
    session: requests.Session,
    base: str,
    mac: str,
    token: str,
    cmd: str,
) -> str:
    """Create a stream link from the raw cmd field."""
    # If cmd already looks like a full URL, use it directly
    if cmd.startswith("http://") or cmd.startswith("https://") or cmd.startswith("rtsp://"):
        return cmd

    # Strip common Stalker prefixes: "ffmpeg " or "auto "
    clean = re.sub(r'^(ffmpeg|auto)\s+', '', cmd).strip()
    if clean.startswith("http") or clean.startswith("rtsp"):
        return clean

    # Fall back to create_link API call
    url = portal_url(base, "create_link", type="itv", cmd=requests.utils.quote(cmd),
                     JsHttpRequest=f"{int(time.time() * 1000)}-xml")
    try:
        resp = session.get(url, headers=build_headers(mac, token), timeout=15)
        resp.raise_for_status()
        link = resp.json().get("js", {}).get("cmd", "")
        link = re.sub(r'^(ffmpeg|auto)\s+', '', link).strip()
        return link or clean
    except Exception:
        return clean


def fetch_all_channels(
    session: requests.Session,
    base: str,
    mac: str,
    token: str,
    media_type: str,
    max_pages: int,
    verbose: bool,
) -> list:
    """Paginate through all channels of the given type."""
    genres = {}
    try:
        genres = fetch_genres(session, base, mac, token, media_type)
        if verbose:
            print(f"  Loaded {len(genres)} genres/categories")
    except Exception as e:
        if verbose:
            print(f"  [warn] Could not load genres: {e}")

    all_channels = []
    page = 1
    total = None
    seen_ids = set()

    while page <= max_pages:
        try:
            channels, total_items = fetch_channels_page(session, base, mac, token, media_type, page)
        except Exception as e:
            print(f"  [warn] Page {page} error: {e}")
            break

        if total is None and total_items:
            total = total_items

        if not channels:
            break

        for ch in channels:
            ch_id = str(ch.get("id", ""))
            if ch_id in seen_ids:
                continue
            seen_ids.add(ch_id)

            genre_id = str(ch.get("tv_genre_id") or ch.get("category_id") or "")
            group = genres.get(genre_id, "Uncategorized")

            cmd = ch.get("cmd", "")
            stream_url = fetch_stream_url(session, base, mac, token, cmd) if cmd else ""

            all_channels.append({
                "id": ch_id,
                "name": (ch.get("name") or ch.get("title") or "").strip(),
                "logo": ch.get("logo") or ch.get("screenshot_uri") or "",
                "group": group,
                "number": ch.get("number") or ch.get("ch_number") or page,
                "stream_url": stream_url,
                "epg_id": ch.get("xmltv_id") or ch.get("tvg_id") or "",
                "media_type": media_type,
            })

        fetched = len(all_channels)
        if verbose:
            progress = f"{fetched}/{total}" if total else str(fetched)
            print(f"  Page {page}: {len(channels)} items (total so far: {progress})", end="\r")

        if total and fetched >= total:
            break

        page += 1

    if verbose:
        print()  # newline after \r
    return all_channels


# ---------------------------------------------------------------------------
# M3U generation
# ---------------------------------------------------------------------------

def build_m3u(channels: list, epg_url: str = "") -> str:
    lines = []
    header = "#EXTM3U"
    if epg_url:
        header += f' url-tvg="{epg_url}"'
    lines.append(header)

    for ch in channels:
        if not ch.get("stream_url"):
            continue
        name = ch["name"] or "Unknown"
        logo = ch.get("logo", "")
        group = ch.get("group", "")
        epg_id = ch.get("epg_id", "")
        ch_num = ch.get("number", "")

        extinf = f'#EXTINF:-1 tvg-id="{epg_id}" tvg-name="{name}" tvg-logo="{logo}" group-title="{group}" tvg-chno="{ch_num}",{name}'
        lines.append(extinf)
        lines.append(ch["stream_url"])

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Convert Stalker/Ministra IPTV portal to M3U playlist",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python stalker_to_m3u.py --portal http://my.provider.com:8080 --mac 00:1A:79:AA:BB:CC
  python stalker_to_m3u.py --portal http://my.provider.com:8080 --mac 00:1A:79:AA:BB:CC --output my_list.m3u
  python stalker_to_m3u.py --portal http://192.168.1.1:80 --mac 00:1A:79:AA:BB:CC --types live vod --max-pages 200
  python stalker_to_m3u.py --portal http://my.provider.com:8080 --mac 00:1A:79:AA:BB:CC --epg http://epg.example.com/epg.xml
        """,
    )
    parser.add_argument("--portal", required=True, help="Portal base URL, e.g. http://host:8080")
    parser.add_argument("--mac", required=True, help="MAC address, e.g. 00:1A:79:AA:BB:CC")
    parser.add_argument(
        "--types",
        nargs="+",
        default=["live"],
        choices=["live", "vod", "series"],
        help="Content types to fetch (default: live)",
    )
    parser.add_argument("--max-pages", type=int, default=50, help="Max pages per type (default: 50)")
    parser.add_argument("--output", default="playlist.m3u", help="Output file name (default: playlist.m3u)")
    parser.add_argument("--epg", default="", help="Optional EPG URL to embed in M3U header")
    parser.add_argument("--no-stream-url", action="store_true", help="Skip individual create_link calls (faster, URLs may need refresh)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed progress")
    parser.add_argument("--timeout", type=int, default=15, help="HTTP request timeout in seconds (default: 15)")
    args = parser.parse_args()

    portal = args.portal.rstrip("/")
    mac = args.mac.strip()

    # Validate MAC
    if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac):
        print(f"[ERROR] Invalid MAC address format: '{mac}'")
        print("        Expected format: 00:1A:79:XX:XX:XX")
        sys.exit(1)

    # Validate portal URL
    parsed = urlparse(portal)
    if not parsed.scheme or not parsed.netloc:
        print(f"[ERROR] Invalid portal URL: '{portal}'")
        sys.exit(1)

    print(f"\n{'='*55}")
    print(f"  Stalker → M3U Converter")
    print(f"{'='*55}")
    print(f"  Portal : {portal}")
    print(f"  MAC    : {mac}")
    print(f"  Types  : {', '.join(args.types)}")
    print(f"  Output : {args.output}")
    print(f"{'='*55}\n")

    session = requests.Session()
    session.request = lambda method, url, **kwargs: requests.Session.request(
        session, method, url, **{**kwargs, "timeout": kwargs.get("timeout", args.timeout)}
    )

    # Step 1: Handshake
    print("[1/3] Authenticating with portal...")
    try:
        token = handshake(session, portal, mac)
        print(f"      Token obtained: {token[:20]}...")
    except Exception as e:
        print(f"[ERROR] Handshake failed: {e}")
        sys.exit(1)

    # Step 2: Profile
    print("[2/3] Fetching subscriber profile...")
    try:
        profile = get_profile(session, portal, mac, token)
        name = profile.get("name") or profile.get("login") or "Unknown"
        expiry = profile.get("end_date") or profile.get("expire") or "N/A"
        print(f"      Subscriber : {name}")
        print(f"      Expiry     : {expiry}")
    except Exception as e:
        print(f"      [warn] Could not fetch profile: {e}")

    # Step 3: Fetch channels
    print("[3/3] Fetching channels...")
    all_channels = []
    for media_type in args.types:
        print(f"\n  [{media_type.upper()}]")
        try:
            channels = fetch_all_channels(
                session, portal, mac, token,
                media_type, args.max_pages, args.verbose
            )
            print(f"  → {len(channels)} items fetched")
            all_channels.extend(channels)
        except Exception as e:
            print(f"  [ERROR] Failed to fetch {media_type}: {e}")

    if not all_channels:
        print("\n[ERROR] No channels were fetched. Check portal URL and MAC.")
        sys.exit(1)

    # Filter channels without a stream URL
    valid = [ch for ch in all_channels if ch.get("stream_url")]
    skipped = len(all_channels) - len(valid)

    print(f"\n  Total   : {len(all_channels)} channels")
    print(f"  Valid   : {len(valid)} (with stream URL)")
    if skipped:
        print(f"  Skipped : {skipped} (no stream URL)")

    # Generate M3U
    m3u_content = build_m3u(valid, epg_url=args.epg)

    output_path = args.output
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(m3u_content)

    print(f"\n✓ Playlist saved → {output_path}")
    print(f"  Lines: {m3u_content.count(chr(10))}")
    print()


if __name__ == "__main__":
    main()
