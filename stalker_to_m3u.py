#!/usr/bin/env python3
"""
stalker_to_m3u.py — Stalker/Ministra IPTV → M3U converter.

GUI mode  : python stalker_to_m3u.py
CLI mode  : python stalker_to_m3u.py --cli --portal http://HOST:PORT --mac 00:1A:79:XX:XX:XX

Requirements:
    pip install requests
    tkinter is included with standard Python on Windows/macOS/most Linux distros.
"""

import argparse
import hashlib
import json
import re
import sys
import time
import threading
import os
from urllib.parse import urlparse, urlencode

try:
    import requests
except ImportError:
    try:
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk(); root.withdraw()
        messagebox.showerror("Missing dependency",
            "The 'requests' library is not installed.\n\nRun:  pip install requests")
        sys.exit(1)
    except Exception:
        print("[ERROR] 'requests' not found. Run: pip install requests")
        sys.exit(1)

# ─────────────────────────────────────────────────────────────
#  Core logic (shared by GUI and CLI)
# ─────────────────────────────────────────────────────────────

def mac_to_serial(mac):
    return hashlib.md5(mac.replace(":", "").upper().encode()).hexdigest()[:13].upper()

def mac_to_device_id(mac):
    return hashlib.sha256(mac.replace(":", "").upper().encode()).hexdigest()[:64].upper()

def mac_to_signature(mac):
    return hashlib.sha256((mac.replace(":", "").upper() + "stalker").encode()).hexdigest()[:64].upper()

def build_headers(mac, token=""):
    h = {
        "User-Agent": "Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 "
                      "(KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3",
        "X-User-Agent": "Model: MAG200; Link: Ethernet",
        "Cookie": f"mac={mac}; stb_lang=en; timezone=Europe/London",
        "Accept": "*/*",
    }
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h

def portal_url(base, action, **params):
    params["action"] = action
    return f"{base.rstrip('/')}/portal.php?{urlencode(params)}"

def handshake(session, base, mac):
    url = portal_url(base, "handshake", type="stb", prehash=0)
    r = session.get(url, headers=build_headers(mac), timeout=15)
    r.raise_for_status()
    token = r.json().get("js", {}).get("token") or r.json().get("token")
    if not token:
        raise RuntimeError(f"No token in handshake response")
    return token

def get_profile(session, base, mac, token):
    url = portal_url(base, "get_profile",
        hd=1, ver="ImageDescription: 0.2.18-r14-pub-250;",
        num_banks=2, sn=mac_to_serial(mac), stb_type="MAG200",
        image_version=218, video_out="hdmi",
        device_id=mac_to_device_id(mac), device_id2=mac_to_device_id(mac),
        signature=mac_to_signature(mac), auth_second_step=1,
        hw_version="1.7-BD-00", not_valid_token=0,
        client_type="STB", hw_version_2=mac_to_serial(mac))
    r = session.get(url, headers=build_headers(mac, token), timeout=15)
    r.raise_for_status()
    return r.json().get("js", {})

def fetch_genres(session, base, mac, token, media_type):
    action = "get_genres" if media_type == "live" else "get_categories"
    t = {"live": "itv", "vod": "vod", "series": "series"}.get(media_type, "itv")
    r = session.get(portal_url(base, action, type=t),
                    headers=build_headers(mac, token), timeout=15)
    r.raise_for_status()
    return {str(g.get("id","")): (g.get("title") or g.get("name","")).strip()
            for g in r.json().get("js", []) if g.get("id")}

def fetch_page(session, base, mac, token, media_type, page):
    t = {"live": "itv", "vod": "vod", "series": "series"}.get(media_type, "itv")
    url = portal_url(base, "get_ordered_list",
        type=t, action="get_ordered_list",
        genre=0, force_ch_link_check=0, fav=0, sortby="number", hd=0,
        p=page, JsHttpRequest=f"{int(time.time()*1000)}-xml")
    r = session.get(url, headers=build_headers(mac, token), timeout=20)
    r.raise_for_status()
    js = r.json().get("js", {})
    return js.get("data", []), int(js.get("total_items", 0) or js.get("total", 0))

def extract_stream_url(session, base, mac, token, cmd):
    if cmd.startswith(("http://", "https://", "rtsp://")):
        return cmd
    clean = re.sub(r'^(ffmpeg|auto)\s+', '', cmd).strip()
    if clean.startswith(("http", "rtsp")):
        return clean
    try:
        url = portal_url(base, "create_link", type="itv",
                         cmd=requests.utils.quote(cmd),
                         JsHttpRequest=f"{int(time.time()*1000)}-xml")
        r = session.get(url, headers=build_headers(mac, token), timeout=10)
        r.raise_for_status()
        link = re.sub(r'^(ffmpeg|auto)\s+', '',
                      r.json().get("js", {}).get("cmd", "")).strip()
        return link or clean
    except Exception:
        return clean

def fetch_all_channels(session, base, mac, token, media_type,
                        max_pages, log_fn, stop_event):
    genres = {}
    try:
        genres = fetch_genres(session, base, mac, token, media_type)
        log_fn(f"  Loaded {len(genres)} groups")
    except Exception as e:
        log_fn(f"  [warn] genres: {e}")

    channels, seen, total = [], set(), None
    for page in range(1, max_pages + 1):
        if stop_event and stop_event.is_set():
            log_fn("  Cancelled.")
            break
        try:
            items, total_items = fetch_page(session, base, mac, token, media_type, page)
        except Exception as e:
            log_fn(f"  [warn] page {page}: {e}")
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
            channels.append({
                "name":       (ch.get("name") or ch.get("title") or "").strip(),
                "logo":       ch.get("logo") or ch.get("screenshot_uri") or "",
                "group":      genres.get(genre_id, "Uncategorized"),
                "number":     ch.get("number") or ch.get("ch_number") or page,
                "stream_url": extract_stream_url(session, base, mac, token, cmd) if cmd else "",
                "epg_id":     ch.get("xmltv_id") or ch.get("tvg_id") or "",
            })
        pct = f"{len(channels)}/{total}" if total else str(len(channels))
        log_fn(f"  [{media_type.upper()}] page {page} — {pct} channels")
        if total and len(channels) >= total:
            break
    return channels

def build_m3u(channels, epg_url=""):
    lines = [f'#EXTM3U url-tvg="{epg_url}"' if epg_url else "#EXTM3U"]
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

def run_conversion(portal, mac, types, max_pages, epg_url, timeout,
                   log_fn, done_fn, stop_event):
    """Runs in a background thread. Calls log_fn(str) and done_fn(m3u|None, error_str)."""
    try:
        session = requests.Session()
        session.request = lambda m, u, **kw: requests.Session.request(
            session, m, u, **{**kw, "timeout": kw.get("timeout", timeout)})

        log_fn("→ Connecting to portal…")
        token = handshake(session, portal, mac)
        log_fn(f"✓ Token: {token[:18]}…")

        log_fn("→ Fetching profile…")
        try:
            profile = get_profile(session, portal, mac, token)
            name    = profile.get("name") or profile.get("login") or "—"
            expiry  = profile.get("end_date") or profile.get("expire") or "—"
            log_fn(f"  Subscriber : {name}")
            log_fn(f"  Expiry     : {expiry}")
        except Exception as e:
            log_fn(f"  [warn] profile: {e}")

        all_channels = []
        for t in types:
            if stop_event.is_set():
                done_fn(None, "Cancelled by user.")
                return
            log_fn(f"\n→ Fetching [{t.upper()}]…")
            try:
                chs = fetch_all_channels(session, portal, mac, token,
                                         t, max_pages, log_fn, stop_event)
                log_fn(f"  ✓ {len(chs)} items")
                all_channels.extend(chs)
            except Exception as e:
                log_fn(f"  [ERROR] {t}: {e}")

        valid = [c for c in all_channels if c.get("stream_url")]
        log_fn(f"\n✓ Done — {len(valid)} valid channels (of {len(all_channels)} total)")
        done_fn(build_m3u(valid, epg_url), None)
    except Exception as e:
        done_fn(None, str(e))


# ─────────────────────────────────────────────────────────────
#  GUI
# ─────────────────────────────────────────────────────────────

DARK = {
    "bg":        "#111110",
    "surface":   "#1a1917",
    "surface2":  "#222120",
    "border":    "#333230",
    "text":      "#d6d4d0",
    "muted":     "#7a7876",
    "primary":   "#4f98a3",
    "success":   "#6daa45",
    "error":     "#d163a7",
    "warn":      "#fdab43",
    "entry_bg":  "#0d0d0c",
    "log_bg":    "#0d0d0c",
}

LIGHT = {
    "bg":        "#f7f6f2",
    "surface":   "#f0efea",
    "surface2":  "#e8e6e0",
    "border":    "#d4d1ca",
    "text":      "#1c1a14",
    "muted":     "#6b6a65",
    "primary":   "#01696f",
    "success":   "#437a22",
    "error":     "#a12c7b",
    "warn":      "#964219",
    "entry_bg":  "#ffffff",
    "log_bg":    "#fafaf7",
}


def launch_gui():
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, font as tkfont

    theme = DARK
    m3u_result = {"data": None}
    stop_event  = threading.Event()
    worker      = {"thread": None}

    root = tk.Tk()
    root.title("Stalker → M3U Converter")
    root.resizable(True, True)
    root.minsize(620, 560)

    # ── try to set a reasonable window size and center it ──
    W, H = 700, 720
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    root.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")

    # ── fonts ──
    try:
        base_font   = tkfont.Font(family="Segoe UI",    size=10)
        mono_font   = tkfont.Font(family="Consolas",    size=9)
        title_font  = tkfont.Font(family="Segoe UI",    size=13, weight="bold")
        label_font  = tkfont.Font(family="Segoe UI",    size=9)
        btn_font    = tkfont.Font(family="Segoe UI",    size=10, weight="bold")
    except Exception:
        base_font   = tkfont.nametofont("TkDefaultFont")
        mono_font   = tkfont.nametofont("TkFixedFont")
        title_font  = base_font
        label_font  = base_font
        btn_font    = base_font

    # ── apply theme to all widgets ──
    def apply_theme(t):
        nonlocal theme
        theme = t
        root.configure(bg=t["bg"])
        style = ttk.Style()
        style.theme_use("clam")

        # frame / label
        style.configure("TFrame",       background=t["bg"])
        style.configure("Card.TFrame",  background=t["surface"],
                        relief="flat", borderwidth=1)
        style.configure("TLabel",       background=t["bg"],
                        foreground=t["text"],  font=base_font)
        style.configure("Card.TLabel",  background=t["surface"],
                        foreground=t["text"],  font=base_font)
        style.configure("Muted.TLabel", background=t["surface"],
                        foreground=t["muted"], font=label_font)
        style.configure("Title.TLabel", background=t["bg"],
                        foreground=t["text"],  font=title_font)

        # checkbutton
        style.configure("TCheckbutton", background=t["surface"],
                        foreground=t["text"], font=base_font,
                        indicatorcolor=t["primary"])
        style.map("TCheckbutton",
                  background=[("active", t["surface2"])],
                  foreground=[("active", t["text"])])

        # scale
        style.configure("TScale",       background=t["surface"],
                        troughcolor=t["border"], sliderlength=18)

        # progressbar
        style.configure("TProgressbar", troughcolor=t["border"],
                        background=t["primary"], thickness=6)

        # primary button
        style.configure("Primary.TButton",
                        background=t["primary"], foreground="#ffffff",
                        font=btn_font, relief="flat", padding=(16, 8))
        style.map("Primary.TButton",
                  background=[("active",   t["primary"]),
                               ("disabled", t["border"])],
                  foreground=[("disabled", t["muted"])])

        # ghost button
        style.configure("Ghost.TButton",
                        background=t["surface2"], foreground=t["muted"],
                        font=label_font, relief="flat", padding=(10, 6))
        style.map("Ghost.TButton",
                  background=[("active", t["border"])],
                  foreground=[("active", t["text"])])

        # entry
        style.configure("TEntry",
                        fieldbackground=t["entry_bg"],
                        foreground=t["text"],
                        insertcolor=t["text"],
                        bordercolor=t["border"],
                        lightcolor=t["border"],
                        darkcolor=t["border"],
                        font=mono_font)
        style.map("TEntry",
                  bordercolor=[("focus", t["primary"])],
                  lightcolor=[("focus", t["primary"])])

        # re-colour existing text widgets (log box etc.)
        for w in _text_widgets:
            w.configure(bg=t["log_bg"], fg=t["text"],
                        insertbackground=t["text"],
                        selectbackground=t["primary"])

    _text_widgets = []

    # ────────────────────────────────────────────────────────
    #  Layout
    # ────────────────────────────────────────────────────────

    root_pad = ttk.Frame(root, style="TFrame", padding=(20, 16, 20, 16))
    root_pad.pack(fill="both", expand=True)

    # ── header row ──
    hdr = ttk.Frame(root_pad, style="TFrame")
    hdr.pack(fill="x", pady=(0, 18))

    ttk.Label(hdr, text="Stalker → M3U", style="Title.TLabel").pack(side="left")

    def toggle_theme():
        apply_theme(LIGHT if theme is DARK else DARK)

    ttk.Button(hdr, text="☀ / ☾", style="Ghost.TButton",
               command=toggle_theme).pack(side="right")

    # ── card ──
    card = ttk.Frame(root_pad, style="Card.TFrame", padding=(18, 16))
    card.pack(fill="x")

    def lbl(parent, text):
        ttk.Label(parent, text=text, style="Muted.TLabel").pack(anchor="w", pady=(8, 2))

    def entry(parent, placeholder="", show=""):
        var = tk.StringVar()
        e = ttk.Entry(parent, textvariable=var, font=mono_font, show=show)
        e.pack(fill="x")
        if placeholder:
            def _in(ev): 
                if e.get() == placeholder:
                    e.delete(0, "end")
                    e.configure(style="TEntry")
            def _out(ev):
                if not e.get():
                    e.insert(0, placeholder)
                    e.configure(style="TEntry")
            e.insert(0, placeholder)
            e.bind("<FocusIn>",  _in)
            e.bind("<FocusOut>", _out)
        return var, e

    lbl(card, "Portal URL")
    portal_var, portal_entry = entry(card, "http://provider.com:8080")

    lbl(card, "MAC Address")
    mac_var, mac_entry = entry(card, "00:1A:79:XX:XX:XX")

    # auto-format MAC
    def on_mac_key(*_):
        raw = re.sub(r'[^0-9A-Fa-f]', '', mac_var.get())
        parts = [raw[i:i+2] for i in range(0, min(len(raw), 12), 2)]
        new = ":".join(parts)
        pos = mac_entry.index("insert")
        mac_var.set(new)
        mac_entry.icursor(min(pos, len(new)))
    mac_entry.bind("<KeyRelease>", on_mac_key)

    lbl(card, "EPG URL  (optional)")
    epg_var, _ = entry(card, "http://epg.example.com/epg.xml")

    # content types
    lbl(card, "Content Types")
    checks_frame = ttk.Frame(card, style="Card.TFrame")
    checks_frame.pack(fill="x", pady=(0, 4))
    live_var   = tk.BooleanVar(value=True)
    vod_var    = tk.BooleanVar(value=False)
    series_var = tk.BooleanVar(value=False)
    for txt, var in [("Live TV", live_var), ("VOD", vod_var), ("Series", series_var)]:
        ttk.Checkbutton(checks_frame, text=txt, variable=var,
                        style="TCheckbutton").pack(side="left", padx=(0, 16))

    # max pages
    lbl(card, "Max Pages per type")
    pages_row = ttk.Frame(card, style="Card.TFrame")
    pages_row.pack(fill="x")
    pages_var = tk.IntVar(value=50)
    pages_lbl = ttk.Label(pages_row, text="50", style="Muted.TLabel", width=4)
    pages_lbl.pack(side="right")
    def on_pages(v):
        pages_var.set(int(float(v)))
        pages_lbl.configure(text=str(pages_var.get()))
    scale = ttk.Scale(pages_row, from_=1, to=500, variable=pages_var,
                      orient="horizontal", command=on_pages)
    scale.pack(side="left", fill="x", expand=True)

    # ── action buttons ──
    btn_row = ttk.Frame(root_pad, style="TFrame")
    btn_row.pack(fill="x", pady=(14, 0))

    convert_btn = ttk.Button(btn_row, text="▶  Convert to M3U",
                              style="Primary.TButton")
    convert_btn.pack(side="left")

    test_btn = ttk.Button(btn_row, text="Test Portal",
                           style="Ghost.TButton")
    test_btn.pack(side="left", padx=(10, 0))

    cancel_btn = ttk.Button(btn_row, text="Cancel",
                             style="Ghost.TButton", state="disabled")
    cancel_btn.pack(side="left", padx=(10, 0))

    save_btn = ttk.Button(btn_row, text="💾  Save .m3u",
                           style="Primary.TButton", state="disabled")
    save_btn.pack(side="right")

    copy_btn = ttk.Button(btn_row, text="Copy text",
                           style="Ghost.TButton", state="disabled")
    copy_btn.pack(side="right", padx=(0, 10))

    # ── progress bar ──
    progress_var = tk.DoubleVar(value=0)
    progress_bar = ttk.Progressbar(root_pad, variable=progress_var,
                                   maximum=100, mode="indeterminate",
                                   style="TProgressbar")
    progress_bar.pack(fill="x", pady=(10, 0))

    # ── status label ──
    status_var = tk.StringVar(value="Ready.")
    status_lbl = ttk.Label(root_pad, textvariable=status_var,
                            style="Muted.TLabel", wraplength=640)
    status_lbl.pack(anchor="w", pady=(4, 6))

    # ── log box ──
    log_frame = ttk.Frame(root_pad, style="TFrame")
    log_frame.pack(fill="both", expand=True, pady=(4, 0))

    log_box = tk.Text(log_frame, height=12, font=mono_font,
                      wrap="word", state="disabled",
                      relief="flat", borderwidth=1,
                      padx=10, pady=8)
    log_box.pack(side="left", fill="both", expand=True)
    _text_widgets.append(log_box)

    scrollbar = ttk.Scrollbar(log_frame, command=log_box.yview)
    scrollbar.pack(side="right", fill="y")
    log_box.configure(yscrollcommand=scrollbar.set)

    # colour tags
    def setup_tags():
        log_box.tag_configure("ok",    foreground=theme["success"])
        log_box.tag_configure("warn",  foreground=theme["warn"])
        log_box.tag_configure("err",   foreground=theme["error"])
        log_box.tag_configure("info",  foreground=theme["primary"])
        log_box.tag_configure("plain", foreground=theme["text"])

    setup_tags()

    def log(msg, tag="plain"):
        def _do():
            log_box.configure(state="normal")
            log_box.insert("end", msg + "\n", tag)
            log_box.see("end")
            log_box.configure(state="disabled")
            setup_tags()
        root.after(0, _do)

    def clear_log():
        log_box.configure(state="normal")
        log_box.delete("1.0", "end")
        log_box.configure(state="disabled")

    def set_status(msg, color=None):
        root.after(0, lambda: status_var.set(msg))

    # ────────────────────────────────────────────────────────
    #  Conversion worker
    # ────────────────────────────────────────────────────────

    def get_inputs():
        portal = portal_var.get().strip()
        mac    = mac_var.get().strip()
        epg    = epg_var.get().strip()
        # strip placeholders
        if portal == "http://provider.com:8080":   portal = ""
        if mac == "00:1A:79:XX:XX:XX":             mac    = ""
        if epg == "http://epg.example.com/epg.xml": epg   = ""
        types = []
        if live_var.get():   types.append("live")
        if vod_var.get():    types.append("vod")
        if series_var.get(): types.append("series")
        return portal, mac, epg, types

    def validate():
        portal, mac, epg, types = get_inputs()
        if not portal:
            messagebox.showwarning("Missing input", "Portal URL is required.")
            return False
        if not mac:
            messagebox.showwarning("Missing input", "MAC address is required.")
            return False
        if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac):
            messagebox.showwarning("Invalid MAC",
                "MAC address format must be  00:1A:79:XX:XX:XX")
            return False
        if not types:
            messagebox.showwarning("No types", "Select at least one content type.")
            return False
        return True

    def set_busy(busy):
        state_busy = "disabled" if busy else "normal"
        state_idle = "normal"  if busy else "disabled"
        convert_btn.configure(state=state_busy)
        test_btn.configure(state=state_busy)
        cancel_btn.configure(state=state_idle)
        if busy:
            progress_bar.configure(mode="indeterminate")
            progress_bar.start(12)
        else:
            progress_bar.stop()
            progress_bar.configure(mode="determinate")
            progress_var.set(0)

    def on_done(m3u, error):
        def _ui():
            set_busy(False)
            stop_event.clear()
            if error:
                set_status(f"✗  {error}")
                log(f"ERROR: {error}", "err")
            else:
                m3u_result["data"] = m3u
                lines = m3u.count("\n#EXTINF")
                set_status(f"✓  {lines} channels ready — click Save .m3u")
                log(f"✓ Playlist built — {lines} channels", "ok")
                save_btn.configure(state="normal")
                copy_btn.configure(state="normal")
        root.after(0, _ui)

    def on_convert():
        if not validate():
            return
        portal, mac, epg, types = get_inputs()
        m3u_result["data"] = None
        save_btn.configure(state="disabled")
        copy_btn.configure(state="disabled")
        stop_event.clear()
        clear_log()
        set_status("Running…")
        log(f"Portal : {portal}", "info")
        log(f"MAC    : {mac}",    "info")
        log(f"Types  : {', '.join(types)}", "info")
        log(f"Pages  : {pages_var.get()} per type\n", "info")
        set_busy(True)

        def target():
            run_conversion(
                portal, mac, types, pages_var.get(), epg, 15,
                lambda msg: log(msg, "ok" if msg.startswith("✓") else
                                     "err" if "ERROR" in msg.upper() else
                                     "warn" if "[warn]" in msg else "plain"),
                on_done,
                stop_event,
            )
        t = threading.Thread(target=target, daemon=True)
        worker["thread"] = t
        t.start()

    def on_cancel():
        stop_event.set()
        set_status("Cancelling…")
        log("⚠ Cancel requested.", "warn")

    def on_test():
        portal, *_ = get_inputs()
        if not portal:
            messagebox.showwarning("Missing input", "Enter a portal URL first.")
            return
        set_status("Testing portal…")
        clear_log()
        log(f"Testing: {portal}", "info")
        def _test():
            try:
                r = requests.get(
                    f"{portal.rstrip('/')}/portal.php?action=handshake&type=stb&prehash=0",
                    headers={"User-Agent": "MAG200", "Accept": "*/*"},
                    timeout=8
                )
                r.raise_for_status()
                root.after(0, lambda: [
                    set_status("✓ Portal is reachable!"),
                    log("✓ Portal responded OK", "ok")
                ])
            except Exception as e:
                root.after(0, lambda err=e: [
                    set_status(f"✗ Unreachable: {err}"),
                    log(f"✗ {err}", "err")
                ])
        threading.Thread(target=_test, daemon=True).start()

    def on_save():
        data = m3u_result.get("data")
        if not data:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".m3u",
            filetypes=[("M3U Playlist", "*.m3u"), ("All files", "*.*")],
            initialfile="playlist.m3u",
            title="Save M3U playlist",
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(data)
        set_status(f"✓ Saved → {path}")
        log(f"✓ Saved: {path}", "ok")

    def on_copy():
        data = m3u_result.get("data")
        if not data:
            return
        root.clipboard_clear()
        root.clipboard_append(data)
        set_status("✓ Copied to clipboard!")

    convert_btn.configure(command=on_convert)
    cancel_btn.configure(command=on_cancel)
    test_btn.configure(command=on_test)
    save_btn.configure(command=on_save)
    copy_btn.configure(command=on_copy)

    # initial theme
    apply_theme(DARK)

    root.mainloop()


# ─────────────────────────────────────────────────────────────
#  CLI mode (unchanged logic, new shared core)
# ─────────────────────────────────────────────────────────────

def run_cli():
    parser = argparse.ArgumentParser(
        description="Stalker/Ministra IPTV → M3U (CLI mode)",
        epilog="Omit --cli to launch the GUI instead."
    )
    parser.add_argument("--cli",       action="store_true", help="Run in CLI mode")
    parser.add_argument("--portal",    required=True)
    parser.add_argument("--mac",       required=True)
    parser.add_argument("--types",     nargs="+", default=["live"],
                        choices=["live","vod","series"])
    parser.add_argument("--max-pages", type=int, default=50)
    parser.add_argument("--output",    default="playlist.m3u")
    parser.add_argument("--epg",       default="")
    parser.add_argument("--timeout",   type=int, default=15)
    parser.add_argument("--verbose",   "-v", action="store_true")
    args = parser.parse_args()

    portal = args.portal.rstrip("/")
    mac    = args.mac.strip()

    if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac):
        print(f"[ERROR] Invalid MAC: {mac}")
        sys.exit(1)

    stop = threading.Event()
    log  = print if args.verbose else lambda m: print(m) if m.startswith(("→","✓","ERROR")) else None

    def done(m3u, err):
        if err:
            print(f"\n[ERROR] {err}")
            sys.exit(1)
        valid = m3u.count("\n#EXTINF")
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(m3u)
        print(f"\n✓ Saved {valid} channels → {args.output}")

    run_conversion(portal, mac, args.types, args.max_pages,
                   args.epg, args.timeout, log, done, stop)


# ─────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if "--cli" in sys.argv:
        run_cli()
    else:
        launch_gui()
