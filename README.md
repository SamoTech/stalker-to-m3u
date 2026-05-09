# stalker-to-m3u

Convert a **Stalker / Ministra IPTV portal** (MAC-based auth) to a standard `.m3u` playlist.

Available as:
- **Web app** — hosted on Vercel, browser UI + Python serverless API
- **Python CLI** — run locally, no proxy needed

---

## Web App (Vercel)

Deploy to Vercel in one click:

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/SamoTech/stalker-to-m3u)

Or manually:

```bash
npm i -g vercel
vercel
```

### How it works

The frontend (`public/index.html`) sends a `POST /api/convert` request with your portal URL and MAC.
The Python serverless function (`api/convert.py`) runs **server-to-server** directly against the Stalker portal — no CORS proxy needed. The M3U file is streamed back to the browser for download.

Endpoints:
- `POST /api/convert` — full conversion, returns `.m3u` file
- `GET /api/test?portal=http://HOST:PORT` — test portal reachability

---

## Python CLI

```bash
pip install requests

# Fetch live TV
python stalker_to_m3u.py --portal http://HOST:PORT --mac 00:1A:79:XX:XX:XX

# Fetch live + VOD + series
python stalker_to_m3u.py --portal http://HOST:PORT --mac 00:1A:79:XX:XX:XX \
  --types live vod series --output my_playlist.m3u

# Verbose + more pages
python stalker_to_m3u.py --portal http://HOST:PORT --mac 00:1A:79:XX:XX:XX \
  --max-pages 200 -v
```

### All CLI arguments

| Argument | Default | Description |
|---|---|---|
| `--portal` | *(required)* | Portal base URL |
| `--mac` | *(required)* | MAC address (`00:1A:79:XX:XX:XX`) |
| `--types` | `live` | `live`, `vod`, `series` |
| `--max-pages` | `50` | Max pages per type |
| `--output` | `playlist.m3u` | Output file |
| `--epg` | *(empty)* | EPG URL for M3U header |
| `--timeout` | `15` | Request timeout (seconds) |
| `--verbose` / `-v` | off | Per-page progress |

---

## M3U Output Format

```m3u
#EXTM3U
#EXTINF:-1 tvg-id="" tvg-name="BBC One" tvg-logo="http://..." group-title="Entertainment" tvg-chno="1",BBC One
http://host:port/play/...
```

---

## Auth Flow

1. **Handshake** — MAG200 headers + MAC cookie → bearer token
2. **Profile** — subscriber name + expiry
3. **Genres/Categories** — map `genre_id` → group name
4. **Paginated channels** — all pages, deduplicated
5. **Stream URL** — strip `ffmpeg`/`auto` prefix or call `create_link`
6. **M3U** — standard EXTM3U with all metadata
