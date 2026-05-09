# Stalker → M3U Converter

> Convert **Stalker/Ministra IPTV portal** (MAC-based authentication) into a standard **M3U playlist** — runs entirely in your browser, no server or install needed.

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-blue?style=flat-square)](https://samotech.github.io/stalker-to-m3u/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

---

## ✨ Features

- 🔐 **Full Stalker Auth Flow** — Handshake → Bearer Token → Profile
- 📡 **Fetch Live TV, VOD & Series** — paginated, auto-detects total pages
- 🎛️ **Channel Editor** — searchable table, per-channel & per-group toggles
- 📄 **M3U Export** — `tvg-id`, `tvg-logo`, `group-title`, custom EPG URL
- 🌓 **Dark / Light Mode** — auto-detects system preference
- 🔄 **CORS Proxy Support** — works with corsproxy.io, allorigins.win, or your own proxy
- 💾 **Download or Copy** — one-click `.m3u` download or clipboard copy
- 🎭 **Demo Mode** — test the full UI without a real portal

---

## 🚀 Usage

### Option A — GitHub Pages

```
https://samotech.github.io/stalker-to-m3u/
```

### Option B — Local

```bash
git clone https://github.com/SamoTech/stalker-to-m3u.git
cd stalker-to-m3u
open stalker-to-m3u.html
```

---

## 🛠️ Setup Guide

### Step 1 — Portal Configuration

| Field | Description |
|---|---|
| **Portal URL** | Your provider's portal address, e.g. `http://provider.com:8080` |
| **MAC Address** | Your registered device MAC, e.g. `00:1A:79:XX:XX:XX` |
| **CORS Proxy** | Required for browser requests — use `https://corsproxy.io/?` |

### Step 2 — Fetch Channels

Select channel types (Live TV / VOD / Series) and click **Fetch Channels**. The tool paginates through all results automatically.

### Step 3 — Edit & Export

- **Channels tab** — search, filter by group, enable/disable individual channels
- **Groups tab** — toggle entire groups
- **M3U Output tab** — configure export options and download/copy your playlist

---

## 🔑 How Stalker Authentication Works

```
1. GET /portal.php?action=handshake
   Headers: Cookie: mac=<MAC>; User-Agent: MAG200 stbapp...
   → Returns: { js: { token: "..." } }

2. GET /portal.php?action=get_profile
   Headers: Authorization: Bearer <token>
   → Returns: account info, expiry, tariff

3. GET /portal.php?action=get_all_channels&type=itv&p=1
   Headers: Authorization: Bearer <token>
   → Returns: paginated channel list with cmd URLs
```

The stream `cmd` field uses format `ffmpeg http://...` — the converter strips the prefix automatically.

---

## 🌐 CORS Proxy Options

| Proxy | URL Pattern |
|---|---|
| corsproxy.io | `https://corsproxy.io/?<url>` |
| allorigins.win | `https://api.allorigins.win/raw?url=<url>` |
| thingproxy | `https://thingproxy.freeboard.io/fetch/<url>` |

---

## ⚠️ Disclaimer

This tool is for **personal use only** with IPTV services you are legally subscribed to.

---

## 📄 License

MIT © [Ossama Hashim](https://github.com/SamoTech)
