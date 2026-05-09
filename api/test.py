from http.server import BaseHTTPRequestHandler
import json
import urllib.request
import urllib.parse


class handler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        portal = (qs.get("portal", [""])[0]).strip().rstrip("/")
        if not portal:
            body = json.dumps({"error": "Missing ?portal=... query param"}).encode()
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
            return

        try:
            url = f"{portal}/portal.php?action=handshake&type=stb&prehash=0"
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3",
                "Accept": "*/*"
            })
            with urllib.request.urlopen(req, timeout=8) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            body = json.dumps({"ok": True, "reachable": True, "response": raw[:500]}).encode()
            status = 200
        except Exception as e:
            body = json.dumps({"ok": False, "reachable": False, "error": str(e)}).encode()
            status = 502

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)
