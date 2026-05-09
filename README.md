# stalker-to-m3u

Convert a **Stalker / Ministra IPTV portal** (MAC-based auth) to a standard `.m3u` playlist — using a simple Python CLI script. No proxy needed, no browser, runs directly from your terminal.

---

## Requirements

- Python 3.10+
- `requests` library

```bash
pip install requests
# or
pip install -r requirements.txt
```

---

## Usage

### Basic — fetch Live TV

```bash
python stalker_to_m3u.py --portal http://HOST:PORT --mac 00:1A:79:XX:XX:XX
```

Outputs `playlist.m3u` in the current directory.

### Custom output file

```bash
python stalker_to_m3u.py --portal http://HOST:PORT --mac 00:1A:79:XX:XX:XX --output my_tv.m3u
```

### Fetch Live + VOD + Series

```bash
python stalker_to_m3u.py --portal http://HOST:PORT --mac 00:1A:79:XX:XX:XX --types live vod series
```

### Set max pages (each page ≈ 14–20 channels)

```bash
python stalker_to_m3u.py --portal http://HOST:PORT --mac 00:1A:79:XX:XX:XX --max-pages 200
```

### Add EPG URL to M3U header

```bash
python stalker_to_m3u.py --portal http://HOST:PORT --mac 00:1A:79:XX:XX:XX --epg http://epg.example.com/epg.xml
```

### Verbose output

```bash
python stalker_to_m3u.py --portal http://HOST:PORT --mac 00:1A:79:XX:XX:XX -v
```

---

## All Arguments

| Argument | Default | Description |
|---|---|---|
| `--portal` | *(required)* | Portal base URL, e.g. `http://host:8080` |
| `--mac` | *(required)* | MAC address in `00:1A:79:XX:XX:XX` format |
| `--types` | `live` | Space-separated: `live`, `vod`, `series` |
| `--max-pages` | `50` | Max pages to fetch per type |
| `--output` | `playlist.m3u` | Output `.m3u` file path |
| `--epg` | *(empty)* | EPG URL to embed in M3U header |
| `--timeout` | `15` | HTTP request timeout in seconds |
| `--verbose` / `-v` | off | Show per-page progress |

---

## How It Works

The script replicates exactly what a **MAG200 set-top box** sends to the portal:

1. **Handshake** — sends the MAC in a cookie, gets an auth token back
2. **Profile** — fetches subscriber info (name, expiry date)
3. **Genres/Categories** — maps `genre_id` → group name for M3U `group-title`
4. **Paginated channel list** — iterates all pages until done
5. **Stream URL extraction** — strips Stalker's internal `ffmpeg`/`auto` prefix from `cmd` field; falls back to `create_link` API if needed
6. **M3U generation** — writes standard EXTM3U with `tvg-id`, `tvg-name`, `tvg-logo`, `group-title`, `tvg-chno`

---

## Output Format

```m3u
#EXTM3U
#EXTINF:-1 tvg-id="" tvg-name="BBC One" tvg-logo="http://..." group-title="Entertainment" tvg-chno="1",BBC One
http://host:port/play/...
```

---

## Notes

- The script talks **directly** to the portal — no CORS proxy needed (pure Python HTTP)
- Works on Windows, Linux, macOS
- Stream URLs expire when the token expires — re-run the script to refresh
- Use `--max-pages 999` if you want to guarantee all channels are fetched
