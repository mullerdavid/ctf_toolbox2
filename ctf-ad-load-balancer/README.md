# ctf-ad-load-balancer

Hot-reloaded Python rules in front of A/D services. Run each service twice
(**patched** + **honeypot**) and let a rule decide, per request or per
connection, where the traffic goes — or close/drop it.

Stdlib-only Python 3.12, runs as one container.

```
attacker / checker ──► balancer :PORT ──┬──► svc-patched  (internal only)
                                        └──► svc-honeypot (internal only)
```

## Quick start

Balancer only, no backend services:

```bash
docker compose up -d --build
docker compose logs -f balancer
```

With demo backends (`svc-patched` + `svc-honeypot`):

```bash
docker compose -f docker-compose.example.yml up -d --build
```

Both mount `rules/`. Edit a rule and save; the balancer picks it up.
The demo rules, one per protocol — delete or `_`-prefix them once you write
your own:

| Rule | Port | Routes to |
|---|---|---|
| `rules/http_example.py` | 31337 | `svc-patched`, suspicious requests to `svc-honeypot` |
| `rules/https_example.py` | 31338 | `svc-patched` (TLS ends at the balancer, plain HTTP behind) |
| `rules/tcp_example.py` | 31339 | `svc-honeypot` (raw stream) |

The HTTPS rule needs a cert in `certs/` (not committed). Create a self-signed
one first, or it is skipped with a load error:

```bash
./gen-cert.sh
```

## Rules

One `.py` file in `rules/` = one listener. It defines exactly one subclass of
`HTTPHandler`, `HTTPSHandler` or `TCPHandler`. Files starting with `_` or `.`
are ignored: add `_` to disable a rule, remove it to enable it again. That's
also where shared helpers go (`_common.py`; rules can `import _common`,
but helpers are not hot-reloaded themselves — touch the rule after editing one).

### Actions

| Return | Effect |
|---|---|
| `Route(host, port, tls=False, sni=None, verify=False)` | forward to backend |
| `Close()` | close the socket without a reply (FIN) |
| `Close(reset=True)` | abort with TCP RST |
| `Drop()` | send **nothing**: no reply, no FIN, no RST — the client hangs. See below. |
| `Respond(body=b"", status=200, headers=None, reason="")` | answer directly, **no backend** (see below) |

`return Close` / `return Drop` / `return Respond` (the class) also works.

**Respond** goes through the same return hook as a backend reply:

- HTTP/HTTPS: becomes a `Response` (reason defaults to the standard phrase,
  `headers` is a dict or list of pairs, `Content-Length` is set for you),
  passes through `on_response(req, resp)` — which can still rewrite it or
  return `Close()`/`Drop()` — and keep-alive continues as usual.
- TCP: `body` is sent as raw bytes through `server_to_client(ctx, data)`, then
  the connection is closed (FIN). `status`/`headers`/`reason` are ignored. In
  the stream history the body counts as server data, and any peeked client
  bytes as client data.
- A `str` body is UTF-8 encoded. Log line: `-> RESPOND 200 (27 bytes)` (HTTP)
  or `-> RESPOND (27 bytes)` (TCP).

Return hooks can return `Respond` too, to replace what the backend sent
(e.g. swap a leaking reply for a fake flag):

- `on_response(req, resp)` → `Respond(...)` replaces the response; the
  connection stays alive.
- `client_to_server` / `server_to_client` → `Respond(b"...")` sends those
  bytes to the client instead of the current chunk, then closes both sides
  (FIN). Nothing more is forwarded.

```python
if req.path == "/robots.txt":
    return Respond("User-agent: *\nDisallow: /\n", headers={"Content-Type": "text/plain"})
```

**How Drop stays silent.** A dropped socket is held open and anything the
client sends is read and discarded (the kernel still ACKs it, as TCP must).
There are two modes; startup logs which one is active (`drop mode: ...`).

*Manual hold* (default, no extra privileges): the socket is simply kept open,
client EOF is ignored, and it's only closed after `DROP_TIMEOUT` (600 s) or
when more than 2048 sockets are held (oldest first). That close is the only
time the kernel sends a FIN.

*Silent* (optional, needs **`CAP_NET_ADMIN`** — `cap_add: [NET_ADMIN]`, enabled
in both compose files): before `close()` the socket is switched to Linux
`TCP_REPAIR` mode, so the kernel just forgets it and sends nothing.

- client closes first (the usual case: its exploit times out) → our kernel ACKs
  its FIN, the socket is forgotten 1 s later; the client is left in FIN-WAIT-2
  and never sees a FIN or RST. Verified with a packet capture.
- client still connected at `DROP_TIMEOUT`, or cap eviction → forgotten
  silently, but if that client later closes or sends, its packet hits an
  unknown connection and the kernel answers RST. It has given up by then.
- if `TCP_REPAIR` is refused for a particular socket, that socket falls back
  to manual hold.

### HTTP / HTTPS

```python
from balancer import HTTPHandler, Route, Close, Drop

class Notes(HTTPHandler):          # HTTPSHandler: also set CERT / KEY
    PORT = 31337

    async def handle(self, req):   # once per request (keep-alive aware)
        if req.ctx.sticky is not None:            # your own per-connection state
            return Route(*req.ctx.sticky)
        if b"../" in req.body or "union" in req.path.lower():
            req.ctx.sticky = ("svc-honeypot", 31337)
            return Route("svc-honeypot", 31337)
        req.headers["X-Foo"] = "bar"     # rewrite anything before forwarding
        return Route("svc-patched", 31337)

    async def on_response(self, req, resp):   # optional
        resp.body = resp.body.replace(b"secret", b"xxxxxx")
        return resp                           # or Close() / Drop()
```

`req`: `method`, `path` (full target), `path_only`, `query`, `headers`,
`body`, `text`, `json()`, `form()`, `cookies`, `src`, `ctx`, `session`, `raw()`.
`resp`: `status`, `reason`, `headers`, `body`, `text`, `json()`, `cookies`.
Headers are case-insensitive: `h["X"]`, `h.get()`, `h.get_all()`, `h.add()`, `del h["X"]`.

Bodies are fully buffered and re-sent with a correct `Content-Length`, so you
can rewrite them freely (chunked is de-chunked). `Expect: 100-continue` is
removed and never answered (a `100 Continue` would break Drop/Close before
`handle()` decides); clients send the body after a short wait (curl: 1 s).
WebSocket/Upgrade requests are routed by `handle()` and then piped raw.

The latest rule version applies to every request, including requests on
existing keep-alive connections.

### Connection context (`req.ctx` / `ctx`)

One object per client connection, shared by every request on it (and passed
to every TCP hook). The balancer doesn't interpret it — it's yours:

- built in: `ctx.src`, `ctx.src_ip`, `ctx.src_port`, `ctx.id`, `ctx.tls`, `ctx.requests`, `ctx.state` (dict)
- set any attribute you like: `ctx.sticky = ("svc-honeypot", 31337)`, `ctx.user = ...`
- reading an attribute you never set returns `None`, so `if ctx.sticky is not None:` works on the first request

### Sessions across connections (`session_key` / `req.session`)

Attackers open a new TCP connection per request or per exploit step, so `ctx`
alone can't follow them. Implement `session_key()` to group requests by your
own logic:

```python
class Notes(HTTPHandler):
    PORT = 31337
    SESSION_TTL = 1800      # idle seconds before a session expires (default)
    SESSION_MAX = 10000     # live sessions kept, least recently used evicted

    def session_key(self, req):                 # READ-ONLY request, may be async
        keys = []
        if sid := req.cookies.get("session"):
            keys.append("sid:" + sid)
        if user := req.form().get("username", [None])[0]:
            keys.append("user:" + user)
        return keys                             # str, list of str, or None

    async def handle(self, req):
        s = req.session                         # same object for every matching request
        if s and s.flagged:
            return Route("svc-honeypot", 31337)
        ...

    async def on_response(self, req, resp):
        if req.session and (sid := resp.cookies.get("session")):
            req.session.add_key("sid:" + sid)   # link the cookie issued at login
        return resp
```

- `session_key()` runs before `handle()` on every request, with a read-only
  copy: changing headers/attributes raises `TypeError`. If it raises, the
  error is logged and `req.session` is `None`.
- The first returned key that already belongs to a live session selects it;
  otherwise a new session is created. All returned keys are then linked to it.
  `session.add_key(k)` links more later (a key moves if it pointed elsewhere).
- `Session`: `id`, `keys`, `created`, `last_seen`, `requests`, `connections`,
  `state` (dict), plus any attribute you set (unset ones read as `None`).
- `self.sessions` is the rule's store: `self.sessions.get("user:alice")`,
  `for s in self.sessions: ...`, `len(self.sessions)`.
- Sessions live per rule file and survive reloads (also protocol/port
  changes); deleting the rule file discards them.
- Helpers: `req.cookies` (Cookie header → dict), `resp.cookies` (Set-Cookie → dict).

### Global shared store with TTL (`self.shared`)

One key/value store for the whole balancer, visible to every rule (HTTP,
HTTPS, TCP) and every connection. Each entry has its own TTL; expired entries
are invisible immediately and removed by a background sweep (every 5 s,
`LB_SWEEP` / `--sweep`). It survives rule reloads, not balancer restarts.

```python
# in any handler: self.shared, or `from balancer import shared`
self.shared.set("ban:alice", True, ttl=300)        # ttl in seconds, default 1800
if self.shared.get("ban:alice"):
    return Drop()

n = self.shared.incr("hits:" + user, ttl=60)      # counter; TTL starts at first incr
seen = self.shared.setdefault("users", set(), ttl=600)
seen.add(user)                                     # mutable values are shared by reference
```

| Method | |
|---|---|
| `set(key, value=True, ttl=None)` / `shared[key] = value` | store (default TTL 1800 s) |
| `get(key, default=None)` / `shared[key]` / `key in shared` | read live value |
| `setdefault(key, value, ttl=None)` | get, or store and return `value` |
| `incr(key, amount=1, ttl=None)` | counter; existing entry keeps its expiry |
| `touch(key, ttl=None)` | restart a live entry's TTL |
| `ttl(key)` | seconds left, or `None` |
| `delete(key)` / `pop(key, default)` | remove |
| `keys(prefix="")`, `items(prefix="")`, `clear(prefix="")`, `len(shared)` | bulk |

Capped at 100k entries (the soonest-expiring are evicted beyond that).
Use key prefixes (`"ban:"`, `"hits:"`) to keep rules from colliding.

### TCP

```python
from balancer import TCPHandler, Route, Drop

class Raw(TCPHandler):
    PORT = 4444

    async def handle(self, ctx):                        # once per connection
        first = await ctx.read_until(b"\n", timeout=1)  # optional look-ahead
        if b"%n" in first:
            return Route("svc-honeypot", 4444)
        return Route("svc-patched", 4444)

    async def client_to_server(self, ctx, data):        # optional
        return Drop() if b"/bin/sh" in data else data

    async def server_to_client(self, ctx, data):        # optional
        return data
```

`ctx.peek(min_bytes=1, timeout=1.0)` and `ctx.read_until(sep, timeout, limit)`
return what has been buffered; those bytes are still forwarded after routing.
For server-speaks-first protocols don't peek — decide immediately.
Rewrite hooks get whatever chunk arrived (no message framing).

**Stream history.** Every chunk is recorded per direction as it arrives
(before your rewrite hook, so the current chunk is included), keeping the last
`HISTORY` bytes per direction (default 1 MiB, `0` disables):

| | |
|---|---|
| `ctx.client_bytes` / `ctx.server_bytes` | retained bytes from the client / backend |
| `ctx.transcript()` | `[("client" \| "server", bytes), ...]` in arrival order |
| `ctx.search(pattern, direction="both")` | regex (bytes/str/compiled, like `re.search`) over the history → `re.Match` / `None`; matches across packet boundaries. Literal: `re.escape(b"...")` |
| `ctx.total_client` / `ctx.total_server` | byte totals for the whole connection |

```python
async def client_to_server(self, ctx, data):
    if ctx.search(rb"/bin/sh", "client"):      # catches "/bi" + "n/sh" too
        return Drop()
    return data

async def server_to_client(self, ctx, data):
    if data.startswith(b"HTTP/1.1 "):          # response: who asked?
        ua = ctx.search(rb"(?im)^User-Agent:[ \t]*([^\r\n]*)", "client")
        self.log.info("UA %s", ua.group(1) if ua else b"-")
    return data
```

History is held per connection, so worst case it costs `2 × HISTORY` bytes
of memory per open connection.

### Class attributes

| Attribute | Default | |
|---|---|---|
| `PORT` | required | listen port |
| `HOST` | `0.0.0.0` | bind address |
| `CERT`, `KEY` | `/certs/cert.pem`, `/certs/key.pem` | HTTPS only |
| `DEFAULT` | `None` | action used when `handle()` raises or returns junk (`None` → `Close()`) |
| `CONNECT_TIMEOUT` | 5 | backend connect |
| `UPSTREAM_TIMEOUT` | 30 | backend response (HTTP) |
| `IDLE_TIMEOUT` | 120 | waiting for the next client request (HTTP) |
| `DROP_TIMEOUT` | 600 | how long dropped sockets are held |
| `TCP_TIMEOUT` | `None` | idle timeout of raw pipes (TCP rules, upgraded HTTP): no data either way for this long → close (FIN). `None` = `LB_TCP_TIMEOUT` (180), `0` = never |

Optional `on_load(self, previous)` runs before a new version goes live;
`previous` is the old handler instance (carry state over). Raising rejects it.
`self.log.info(...)` logs with the rule name as prefix. `self.name`,
`self.log`, `self.sessions` and `self.shared` are already set in `__init__`.

### Errors

- `handle()` raises → traceback logged, `DEFAULT` or `Close()`.
- A rewrite hook (`on_response`, `client_to_server`, `server_to_client`) raises
  → traceback logged, data passes **unchanged** (fail-open for SLA).
- Backend unreachable/timeout → warning logged, client closed.

## Hot reload

Changes are detected by **inotify** and a **poll every 5 s** (file size +
mtime), whichever is first. Docker Desktop on Windows/macOS doesn't propagate
inotify for bind mounts, so there the poll catches it; on the Linux vulnbox
inotify reacts instantly.

On change the file is imported into a fresh module and validated (one handler
class, valid `PORT`, cert loads, no port clash with another rule, `on_load`
OK). Only then is it swapped in:

- same protocol/host/port/cert → handler replaced in place, no rebind
- protocol, host, port or cert changed → listener restarted (if binding fails,
  the old listener is restored)
- file deleted → listener stopped
- any error → logged, **old version keeps running**

Open connections are never cut by a reload. TCP connections finish on the
handler version they started with.

Env/flags: `LB_RULES` / `--rules` (default `/rules`), `LB_POLL` / `--poll`
(default 5), `LB_SWEEP` / `--sweep` (shared store sweep, default 5),
`LB_TCP_TIMEOUT` / `--tcp-timeout` (TCP idle timeout, default 180, `0` = off),
`LB_LOG_LEVEL` / `--log-level`.

## Logging

One line per HTTP request / TCP connection:

```
2026-11-20 10:13:14 INFO  [example:31337] 10.60.3.2:50532 -> ROUTE svc-honeypot:31337
2026-11-20 10:13:14 INFO  [example:31337] 10.60.3.2:50548 -> CLOSE
2026-11-20 10:13:15 INFO  [raw:4444] 10.60.7.2:45328 -> DROP (client_to_server)
```

Anything else: log it yourself in the handler.

## Deploying on the vulnbox

1. Duplicate each service in its `docker-compose.yml` (e.g. `notes-patched`,
   `notes-honeypot`), and **remove their `ports:`** so only the balancer is
   exposed. Give the honeypot its own volumes/DB.
2. Either run this repo's `docker-compose.yml` (balancer only) joined to the
   services' network (see the commented `networks:` block in it), or add the
   balancer service to the services' compose file:

   ```yaml
   balancer:
     build: /path/to/ctf-ad-load-balancer
     ports: ["8080:8080", "4444:4444"]   # every port your rules listen on
     volumes:
       - /path/to/rules:/rules:ro
       - /path/to/certs:/certs:ro
     cap_add: [NET_ADMIN]                # optional: silent Drop (TCP_REPAIR)
     restart: unless-stopped
   ```

   Compose only forwards the ports listed. If a rule moves to a port that
   isn't published, use `network_mode: host` instead and route to the
   backends' published `127.0.0.1:` ports.
3. Write one rule per service routing everything to `*-patched`, check the
   checker stays green, then start sending suspicious traffic to the honeypot.

For HTTPS services: put the fixed cert in `certs/` (`./gen-cert.sh` makes a
self-signed one) and use `Route(..., tls=True)` if the backend itself speaks TLS.

## Layout

```
balancer/      the proxy (actions, handlers, http parser, listeners, reloader, inotify)
docker-compose.yml          balancer only
docker-compose.example.yml  balancer + demo backends (svc-patched, svc-honeypot)
rules/                      mounted rule files (both compose files)
  http_example.py           demo rule, HTTP (31337)
  https_example.py          demo rule, HTTPS -> plain HTTP backend (31338)
  tcp_example.py            demo rule, raw TCP (31339)
certs/                      cert.pem + key.pem for HTTPS rules (gitignored)
```
