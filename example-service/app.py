"""Example A/D service: store a flag under a password, read it back.

Used as a stand-in target for testing the load balancer.

  POST /flag/set  flag, password -> 200   (flag kept for FLAG_TTL seconds)
  POST /flag/get  password       -> 200 flag | 403 unknown password
  anything else                  -> 404

Parameters come as application/x-www-form-urlencoded or a JSON object.

PATCHED=0 (default) is the vulnerable build: the hardcoded password
"backdoor85359714" lists every stored flag. PATCHED=1 removes that.
"""
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

PORT = int(os.environ.get("PORT", "31337"))
PATCHED = os.environ.get("PATCHED", "0").lower() in ("1", "true", "yes")
FLAG_TTL = float(os.environ.get("FLAG_TTL", "180"))  # 3 minutes = 1 tick
BACKDOOR = "backdoor85359714"
MAX_BODY = 64 * 1024

flags = {}  # password -> (flag, expires_at)
lock = threading.Lock()


def live_flags() -> dict:
    now = time.monotonic()
    with lock:
        for pw in [p for p, (_, exp) in flags.items() if exp <= now]:
            del flags[pw]
        return {pw: flag for pw, (flag, _) in flags.items()}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive, closer to real services

    def version_string(self) -> str:  # Server: header
        return "Example-Flag-Service"

    def reply(self, status: int, text: str) -> None:
        body = (text + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def params(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            return None
        raw = self.rfile.read(length) if length else b""
        if "json" in self.headers.get("Content-Type", ""):
            try:
                data = json.loads(raw or b"{}")
            except ValueError:
                return None
            return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else None
        return {k: v[0] for k, v in parse_qs(raw.decode("utf-8", "replace")).items()}

    def do_GET(self) -> None:
        self.reply(404, "not found")

    do_HEAD = do_GET

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        params = self.params()
        if path not in ("/flag/set", "/flag/get"):
            return self.reply(404, "not found")
        if params is None:
            return self.reply(400, "bad request")
        password = params.get("password", "")

        if path == "/flag/set":
            flag = params.get("flag", "")
            if not flag or not password:
                return self.reply(400, "need flag and password")
            with lock:
                flags[password] = (flag, time.monotonic() + FLAG_TTL)
            return self.reply(200, "ok")

        stored = live_flags()
        if password in stored:
            return self.reply(200, stored[password])
        if not PATCHED and password == BACKDOOR:
            return self.reply(200, "\n".join(stored.values()))
        return self.reply(403, "wrong password")


if __name__ == "__main__":
    mode = "patched" if PATCHED else "UNPATCHED (backdoor enabled)"
    print(f"listening on 0.0.0.0:{PORT}, {mode}, flag ttl {FLAG_TTL:g}s", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
