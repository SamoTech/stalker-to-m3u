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

---

## API Reference

### `POST /api/convert`

Authenticates with a Stalker/Ministra portal and returns all channels as an M3U playlist.

**Request body (JSON):**

| Field | Type | Required | Description |
|---|---|---|---|
| `portal` | string | ✅ | Portal base URL, e.g. `http://host:port` |
| `mac` | string | ✅ | MAC address in `00:1A:79:XX:XX:XX` format |
| `types` | array | — | Channel types to fetch: `live`, `vod`, `series` (default: `["live"]`) |
| `maxPages` | int | — | Max pages to fetch per type (default: `50`) |
| `epgUrl` | string | — | EPG URL added to `#EXTM3U` header |
| `format` | string | — | `"m3u"` (default) returns a file download; `"json"` streams NDJSON events |
| `skipKnown` | string | — | Existing M3U text — channels whose URLs already appear in it are skipped |

**Response (`format=m3u`):** `.m3u` file download with `Content-Disposition: attachment`.

**Response (`format=json`):** NDJSON stream — one JSON object per line:

```
{"event":"meta",     "portal":"...", "types":[...], "maxPages":50}
{"event":"profile",  "profile":{"name":"...", "expiry":"..."}}
{"event":"channel",  "count":1, "channel":{"name":"...", "group":"...", "stream_url":"...", "tvg_type":"video", ...}}
{"event":"progress", "scope":"live", "page":2, "count":40, "done":false}
{"event":"done",     "total":512, "errors":[], "epgUrl":"..."}
```

---

### `POST /api/validate`

Probes each stream URL in an M3U playlist and classifies it as `live`, `dead`, or `uncheckable`.

**Request body (JSON):**

| Field | Type | Required | Description |
|---|---|---|---|
| `m3u` | string | ✅ | Raw M3U text **or** a URL pointing to an M3U file |
| `timeout` | int | — | Per-stream HTTP timeout in seconds (default: `5`, max: `15`) |
| `workers` | int | — | Parallel probe workers (default: `20`, max: `40`) |
| `existing_m3u` | string | — | Existing M3U for diff/recheck mode — URLs already present are returned as `cached` without re-probing |

**Response (JSON):**

```json
{
  "total": 200,
  "live": 153,
  "dead": 31,
  "uncheckable": 12,
  "cached": 4,
  "results": [
    {
      "name": "BBC One",
      "url": "http://host/play/...",
      "group": "Entertainment",
      "status": "live",
      "reason": "HTTP 200",
      "stream_type": "video"
    }
  ],
  "filtered_m3u": "#EXTM3U\n#EXTINF:-1 ..."
}
```

**Status values:**

| Status | Meaning |
|---|---|
| `live` | Stream responded with a valid HTTP 2xx or redirect |
| `dead` | Stream returned an error, timeout, or HTML error page |
| `uncheckable` | URL is token-signed or contains auth keywords — skipped to avoid false negatives |
| `cached` | URL was found in `existing_m3u` — skipped, assumed still live |

**Health check — `GET /api/validate`:**

```json
{ "status": "ok", "version": "1.0", "endpoints": [...] }
```

---

### `GET /api/test`

Tests whether a Stalker portal is reachable before attempting a full conversion.

**Query params:**

| Param | Required | Description |
|---|---|---|
| `portal` | ✅ | Portal base URL, e.g. `http://host:port` |

**Response (JSON):**

```json
{ "ok": true, "status": 200, "ms": 143 }
```

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

```
#EXTM3U
#EXTINF:-1 tvg-id="" tvg-name="BBC One" tvg-logo="http://..." group-title="Entertainment" tvg-type="video" tvg-chno="1",BBC One
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

---

## Project Structure

```
api/
  convert.py     POST /api/convert  — Stalker portal → M3U
  validate.py    POST /api/validate — probe stream URLs
  test.py        GET  /api/test     — portal reachability check
  sanitize.py    shared URL utilities (sanitize_url, classify_stream_type, is_uncheckable)
public/
  index.html     browser UI
stalker_to_m3u.py  Python CLI
```

---

## About

Convert Stalker/Ministra IPTV portal (MAC-based) to M3U playlist — browser-based tool with full portal auth, channel filtering, stream validation, and M3U export.

## License

MIT
