"""Fake game server for testing the submitter.

    python3 teams_server.py [http_port] [submit_port]     # default 8000, 8001

HTTP  GET /teams.json -> teams 1..TEAMS, service SERVICE, empty flag ids
TCP   flag submission: one flag per line, answers "OK" to every line
"""
import json
import socketserver
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HTTP_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
SUBMIT_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8001
TEAMS = 8
SERVICE = "flagstore"


def teams_json() -> bytes:
    teams = list(range(1, TEAMS + 1))
    return json.dumps({
        "teams": teams,
        "flag_ids": {SERVICE: {str(t): [] for t in teams}},
    }).encode()


class TeamsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.split("?", 1)[0] != "/teams.json":
            return self.send_error(404)
        body = teams_json()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class SubmitHandler(socketserver.StreamRequestHandler):
    def handle(self):
        for line in self.rfile:
            flag = line.decode("utf-8", "replace").strip()
            print(f"submit {self.client_address[0]}: {flag} -> OK", flush=True)
            self.wfile.write(b"OK\n")


class SubmitServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    print(f"teams.json ({TEAMS} teams, service {SERVICE!r}) at "
          f"http://0.0.0.0:{HTTP_PORT}/teams.json", flush=True)
    print(f"flag submission (always OK) on tcp 0.0.0.0:{SUBMIT_PORT}", flush=True)
    submit = SubmitServer(("0.0.0.0", SUBMIT_PORT), SubmitHandler)
    threading.Thread(target=submit.serve_forever, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), TeamsHandler).serve_forever()
