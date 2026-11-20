"""Example TCP rule: raw stream proxy to the honeypot.

No HTTP parsing: bytes are piped as-is, with optional rewrite hooks.
"""
from balancer import Drop, Respond, Route, TCPHandler


class TcpExample(TCPHandler):
    PORT = 31339
    HISTORY = 1 << 20  # keep the last 1 MiB per direction for ctx.search() etc.

    async def handle(self, ctx):
        # Optional look-ahead: wait up to 1s for the first client line. Skip
        # this for server-speaks-first protocols (banner before input).
        first = await ctx.read_until(b"\n", timeout=1.0)  # whole buffer so far
        # Global shared store (visible to every rule): count connections, 1h TTL
        # starting at the first one.
        n = self.shared.incr("tcp_example:connections", ttl=3600)
        self.log.info("%s connection #%d, first bytes: %r", ctx.src_ip, n, first[:60])
        if first.startswith(b"GET /health "):
            # Answered here with raw bytes, no backend. Goes through
            # server_to_client() (which logs the User-Agent), then FIN.
            return Respond(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n"
                           b"Connection: close\r\n\r\nok\n")
        return Route("svc-honeypot", 31337)

    async def client_to_server(self, ctx, data):
        # The history already includes `data`, so a pattern split across
        # packets ("/bi" + "n/sh") still matches.
        if ctx.search(rb"/bin/sh", "client"):
            return Drop()          # never forwarded, client hangs
        return data

    async def server_to_client(self, ctx, data):
        # On the return path: an HTTP/1.1 response is coming back, so look up
        # the User-Agent the client sent earlier on this connection.
        if data.startswith(b"HTTP/1.1 "):
            ua = ctx.search(rb"(?im)^User-Agent:[ \t]*([^\r\n]*)", "client")
            status = data.split(b"\r\n", 1)[0].decode("latin-1")
            self.log.info("%s %s  User-Agent: %s", ctx.src_ip, status,
                          ua.group(1).decode("latin-1") if ua else "-")

        # Correlate both directions: the client used the backdoor earlier on
        # this connection and the backend is now answering with flags.
        if b"FLAG{" in data and ctx.search(rb"backdoor\d+", "client"):
            self.log.info("%s got flags via backdoor (%d bytes sent, %d received)",
                          ctx.src_ip, ctx.total_client, ctx.total_server)
        return data
