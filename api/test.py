"""
api/test.py  —  Quick portal reachability check.

POST /api/test   { "portal": "http://HOST:PORT" }
"""

from http.server import BaseHTTPRequestHandler
import json, urllib.request

# Vercel per-function config
config = {
    "maxDuration": 15,
}

class handler(BaseHTTPRequestHandler):

    def log_message(self, *a): pass

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def send_json(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204); self._cors(); self.end_headers()

    def do_POST(self):
        try:
            payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length",0))))
        except Exception:
            return self.send_json(400, {"ok": False, "error": "Invalid JSON"})

        portal = (payload.get("portal") or "").strip().rstrip("/")
        if not portal:
            return self.send_json(400, {"ok": False, "error": "portal is required"})

        url = f"{portal}/portal.php?action=handshake&type=stb&prehash=0"
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "MAG200", "Accept": "*/*"
            })
            with urllib.request.urlopen(req, timeout=8) as resp:
                body = resp.read().decode("utf-8", errors="replace")
            self.send_json(200, {"ok": True, "status": resp.status, "preview": body[:200]})
        except Exception as e:
            self.send_json(502, {"ok": False, "error": str(e)})
