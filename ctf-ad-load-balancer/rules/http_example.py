"""Example rule for example-service: patched vs honeypot routing.

One file = one listener. Edit and save: the balancer reloads it on the fly.
"""
import re

from balancer import Close, Drop, HTTPHandler, Respond, Route

PATCHED = Route("svc-patched", 31337)
HONEYPOT = Route("svc-honeypot", 31337)

SUSPICIOUS = re.compile(
    rb"backdoor\d+|\.\./|union\s+select|/etc/passwd|\{\{.*\}\}|;\s*(cat|ls|id)\b", re.I)


class HttpExample(HTTPHandler):
    PORT = 31337

    def session_key(self, req):
        # Read-only request. Every key returned is linked to the same session,
        # so a later request matching any one of them finds it again.
        keys = []
        if sid := req.cookies.get("session"):
            keys.append("sid:" + sid)
        if user := req.form().get("username", [None])[0]:
            keys.append("user:" + user)
        return keys

    async def handle(self, req):
        # Group by session when we can tell who it is, otherwise by connection.
        group = req.session or req.ctx
        if group.sticky is not None:
            return Route(*group.sticky)

        blob = req.path.encode("latin-1") + b"\n" + req.body
        if SUSPICIOUS.search(blob):
            self.log.info("suspicious %s %s -> honeypot (%s)", req.method, req.path,
                          req.session.id if req.session else "no session")
            group.sticky = (HONEYPOT.host, HONEYPOT.port)
            return HONEYPOT
        if req.path.startswith("/admin"):
            return Close()            # FIN, no reply
        if req.headers.get("User-Agent", "").startswith("sqlmap"):
            return Drop()             # nothing at all, connection hangs
        if req.path == "/robots.txt":
            # Answered here, no backend; still passes through on_response().
            return Respond("User-agent: *\nDisallow: /\n",
                           headers={"Content-Type": "text/plain"})
        return PATCHED

    async def on_response(self, req, resp):
        # Login response: tie the freshly issued cookie to the session that
        # was keyed by username, so cookie-only requests land in it too.
        if req.session is not None and (sid := resp.cookies.get("session")):
            req.session.add_key("sid:" + sid)
        return resp
