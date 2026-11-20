"""Listeners and per-connection serving logic for TCP and HTTP(S)."""
from __future__ import annotations

import asyncio
import heapq
import inspect
import itertools
import logging
import os
import re
import socket
import ssl
import struct
from collections import OrderedDict, deque
from contextlib import suppress
from http import HTTPStatus

from . import http as h
from .actions import ACTIONS, Close, Drop, Respond, Route, normalize
from .sessions import normalize_keys

log = logging.getLogger("lb")

STREAM_LIMIT = 1 << 20      # max single line length for the HTTP parser
READ_CHUNK = 65536
DROP_CAP = 2048             # max silently held sockets; oldest evicted beyond this
EOF_GRACE = 1.0             # after client FIN, wait this long before silently releasing
# Idle timeout for TCP pipes (TCP rules and upgraded HTTP connections): no data in
# either direction for this long -> close. 0 disables. Rules override via TCP_TIMEOUT.
TCP_TIMEOUT = float(os.environ.get("LB_TCP_TIMEOUT", "180"))

_conn_ids = itertools.count(1)


def fmt_addr(addr) -> str:
    if not addr:
        return "?"
    host, port = addr[0], addr[1]
    return f"[{host}]:{port}" if ":" in str(host) else f"{host}:{port}"


async def maybe_await(value):
    if inspect.isawaitable(value):
        return await value
    return value


# --------------------------------------------------------------------------- context

class Context:
    """Per-client-connection context, shared by every request on it.

    Attributes:
        id      unique connection number
        src     (ip, port) of the client
        tls     True if the client connected over TLS
        state   free-form dict for handlers

    Any other attribute can be set freely (ctx.sticky = ("svc-honeypot", 31337));
    reading one that was never set returns None instead of raising.
    """

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.id = next(_conn_ids)
        self.reader = reader
        self.writer = writer
        peer = writer.get_extra_info("peername") or ("?", 0)
        self.src = (peer[0], peer[1])
        self.tls = writer.get_extra_info("ssl_object") is not None
        self.state: dict = {}
        self.requests = 0           # HTTP requests seen on this connection
        self.buffer = bytearray()   # TCP: bytes read by peek()/read_until(), forwarded on route
        self.eof = False
        # TCP stream history: per direction, (seq, chunk) oldest first, capped at history_limit.
        self.history_limit = 0
        self._hist = {"client": deque(), "server": deque()}
        self._hist_size = {"client": 0, "server": 0}
        self._hist_seq = 0
        self.total_client = 0       # bytes received from the client (whole connection)
        self.total_server = 0       # bytes received from the backend (whole connection)

    def __getattr__(self, name: str):
        # Only called for attributes that don't exist: unset custom fields read as None.
        if name.startswith("__"):
            raise AttributeError(name)
        return None

    @property
    def src_ip(self) -> str:
        return self.src[0]

    @property
    def src_port(self) -> int:
        return self.src[1]

    # --- TCP look-ahead -------------------------------------------------------
    async def _read_more(self, timeout: float) -> bool:
        if self.eof:
            return False
        try:
            data = await asyncio.wait_for(self.reader.read(READ_CHUNK), timeout)
        except (TimeoutError, ConnectionError, OSError):
            return False
        if not data:
            self.eof = True
            return False
        self.buffer += data
        return True

    async def peek(self, min_bytes: int = 1, timeout: float = 1.0) -> bytes:
        """Wait until at least `min_bytes` are buffered (or timeout/EOF); return the buffer.

        Nothing is consumed: buffered bytes are forwarded once routed.
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while len(self.buffer) < min_bytes:
            remaining = deadline - loop.time()
            if remaining <= 0 or not await self._read_more(remaining):
                break
        return bytes(self.buffer)

    async def read_until(self, sep: bytes, timeout: float = 1.0, limit: int = 65536) -> bytes:
        """Wait until `sep` appears in the buffer (or timeout/EOF/limit); return the buffer."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while sep not in self.buffer and len(self.buffer) < limit:
            remaining = deadline - loop.time()
            if remaining <= 0 or not await self._read_more(remaining):
                break
        return bytes(self.buffer)

    # --- TCP stream history ----------------------------------------------------
    def _record(self, direction: str, data: bytes) -> None:
        if direction == "client":
            self.total_client += len(data)
        else:
            self.total_server += len(data)
        limit = self.history_limit
        if limit <= 0 or not data:
            return
        if len(data) > limit:
            data = data[-limit:]
        chunks = self._hist[direction]
        self._hist_seq += 1
        chunks.append((self._hist_seq, bytes(data)))
        size = self._hist_size[direction] + len(data)
        while size > limit:  # drop/trim the oldest bytes of this direction
            seq, oldest = chunks[0]
            excess = size - limit
            if len(oldest) <= excess:
                chunks.popleft()
                size -= len(oldest)
            else:
                chunks[0] = (seq, oldest[excess:])
                size -= excess
        self._hist_size[direction] = size

    @property
    def client_bytes(self) -> bytes:
        """Last HISTORY bytes the client sent on this connection (before rewrite hooks)."""
        return b"".join(c for _, c in self._hist["client"])

    @property
    def server_bytes(self) -> bytes:
        """Last HISTORY bytes the backend sent on this connection (before rewrite hooks)."""
        return b"".join(c for _, c in self._hist["server"])

    def transcript(self) -> list[tuple[str, bytes]]:
        """Retained history of both directions in arrival order: [("client"|"server", bytes)]."""
        merged = heapq.merge(
            ((seq, "client", c) for seq, c in self._hist["client"]),
            ((seq, "server", c) for seq, c in self._hist["server"]))
        return [(d, c) for _, d, c in merged]

    def search(self, pattern, direction: str = "both"):
        """Regex-search the history (like re.search). `pattern`: bytes, str or compiled.

        For a literal match pass re.escape(b"..."). direction: "client",
        "server" or "both" (client first). Returns the re.Match or None.
        Matches span chunk/packet boundaries.
        """
        if isinstance(pattern, (bytes, bytearray)):
            pattern = re.compile(bytes(pattern))
        elif isinstance(pattern, str):
            pattern = re.compile(pattern.encode("latin-1"))
        elif isinstance(pattern, re.Pattern) and isinstance(pattern.pattern, str):
            # compiled str regex -> bytes regex with the same flags (UNICODE is str-only)
            pattern = re.compile(pattern.pattern.encode("latin-1"), pattern.flags & ~re.UNICODE)
        if direction not in ("client", "server", "both"):
            raise ValueError("direction must be 'client', 'server' or 'both'")
        for d in ("client", "server"):
            if direction in (d, "both"):
                m = pattern.search(self.client_bytes if d == "client" else self.server_bytes)
                if m:
                    return m
        return None

    def __repr__(self) -> str:
        return f"<Context #{self.id} {fmt_addr(self.src)}>"


# --------------------------------------------------------------------------- socket ends

async def close_stream(writer: asyncio.StreamWriter | None, reset: bool = False) -> None:
    if writer is None:
        return
    try:
        if reset:
            sock = writer.get_extra_info("socket")
            if sock is not None:
                with suppress(OSError):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            writer.transport.abort()
        else:
            writer.close()
            with suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), 5)
    except Exception:
        pass


TCP_REPAIR = 19  # linux/tcp.h; not exported by the socket module


def _probe_tcp_repair() -> bool:
    """TCP_REPAIR needs CAP_NET_ADMIN (docker: cap_add: [NET_ADMIN])."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return False
    try:
        s.setsockopt(socket.IPPROTO_TCP, TCP_REPAIR, 1)
        return True
    except OSError:
        return False
    finally:
        s.close()


# With TCP_REPAIR on, close() just forgets the connection: no FIN, no RST.
SILENT_DROP = _probe_tcp_repair()


def enable_repair(writer: asyncio.StreamWriter) -> bool:
    """Put the socket in TCP_REPAIR mode so close() sends nothing. False if not possible."""
    if not SILENT_DROP:
        return False
    sock = writer.get_extra_info("socket")
    if sock is None:
        return False
    try:
        sock.setsockopt(socket.IPPROTO_TCP, TCP_REPAIR, 1)
        return True
    except OSError:
        return False


class Blackhole:
    """Holds dropped sockets without ever writing to them.

    Incoming data is read (the kernel ACKs it) and discarded.

    Silent mode (TCP_REPAIR works, needs CAP_NET_ADMIN): once the client sends
    FIN the socket is forgotten after EOF_GRACE, without FIN/RST.

    Manual mode (no TCP_REPAIR, or it fails for this socket): client EOF is
    ignored and the socket is simply held until DROP_TIMEOUT (or cap eviction);
    only then does the kernel send FIN.
    """

    def __init__(self, cap: int = DROP_CAP):
        self.cap = cap
        self.held: OrderedDict[int, asyncio.Event] = OrderedDict()

    @staticmethod
    async def _discard(reader: asyncio.StreamReader) -> None:
        with suppress(Exception):
            while await reader.read(READ_CHUNK):
                pass

    async def hold(self, reader, writer, timeout: float) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        key = id(writer)
        release = asyncio.Event()  # set on cap eviction
        self.held[key] = release
        while len(self.held) > self.cap:
            _, ev = self.held.popitem(last=False)
            ev.set()

        drain = asyncio.create_task(self._discard(reader))
        released = asyncio.create_task(release.wait())
        repaired = False
        try:
            waiters = {released, drain} if SILENT_DROP else {released}
            done, _ = await asyncio.wait(waiters, timeout=timeout,
                                         return_when=asyncio.FIRST_COMPLETED)
            if drain in done and not release.is_set():
                # Client sent FIN. Give the kernel time to ACK it before we forget
                # the socket, or the client retransmits the FIN and gets an RST.
                await asyncio.wait({released}, timeout=EOF_GRACE)
                if not release.is_set():
                    repaired = enable_repair(writer)
                    if not repaired:  # repair refused for this socket: hold manually
                        await asyncio.wait({released},
                                           timeout=max(0.0, deadline - loop.time()))
        finally:
            released.cancel()
            drain.cancel()
            self.held.pop(key, None)
            if not repaired:
                repaired = enable_repair(writer)
            if not repaired:
                log.debug("dropped socket released with FIN (manual hold mode)")
            writer.transport.abort()


BLACKHOLE = Blackhole()


async def terminate(ctx: Context, action, handler) -> None:
    if isinstance(action, Drop):
        await BLACKHOLE.hold(ctx.reader, ctx.writer, handler.DROP_TIMEOUT)
    else:
        await close_stream(ctx.writer, reset=action.reset)


# --------------------------------------------------------------------------- upstream

_client_ssl: dict[bool, ssl.SSLContext] = {}


def _upstream_ssl(verify: bool) -> ssl.SSLContext:
    if verify not in _client_ssl:
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        _client_ssl[verify] = ctx
    return _client_ssl[verify]


async def open_upstream(route: Route, timeout: float):
    kwargs = {}
    if route.tls:
        kwargs["ssl"] = _upstream_ssl(route.verify)
        kwargs["server_hostname"] = route.sni or route.host
    return await asyncio.wait_for(
        asyncio.open_connection(route.host, route.port, limit=STREAM_LIMIT, **kwargs), timeout)


# --------------------------------------------------------------------------- handler calls

async def decide(listener, handler, arg, src) -> Route | Close | Drop | Respond:
    """Run handler.handle(arg); fall back to DEFAULT / Close() on error."""
    try:
        action = normalize(await maybe_await(handler.handle(arg)))
        if isinstance(action, ACTIONS):
            return action
        log.error("[%s] %s handle() returned %r (expected Route/Close/Drop/Respond)",
                  listener.label, fmt_addr(src), action)
    except Exception:
        log.exception("[%s] %s handle() raised", listener.label, fmt_addr(src))
    return normalize(handler.DEFAULT) if handler.DEFAULT is not None else Close()


async def run_hook(listener, fn, src, *args):
    """Run a rewrite hook. Errors are logged and the original data passes through."""
    try:
        return normalize(await maybe_await(fn(*args)))
    except Exception:
        log.exception("[%s] %s %s() raised; passing data unchanged",
                      listener.label, fmt_addr(src), fn.__name__)
        return args[-1]


def _overridden(handler, name: str, base) -> bool:
    return getattr(type(handler), name) is not getattr(base, name)


# --------------------------------------------------------------------------- TCP

async def serve_tcp(listener, reader, writer) -> None:
    from .handlers import TCPHandler

    ctx = Context(reader, writer)
    handler = listener.handler  # one decision per connection: pin this version
    ctx.history_limit = int(getattr(handler, "HISTORY", 0) or 0)
    src = fmt_addr(ctx.src)

    action = await decide(listener, handler, ctx, ctx.src)
    if isinstance(action, Respond):
        log.info("[%s] %s -> RESPOND (%d bytes)", listener.label, src, len(action.data))
        await _tcp_respond(listener, handler, ctx, action)
        return
    log.info("[%s] %s -> %s", listener.label, src, action)
    if not isinstance(action, Route):
        await terminate(ctx, action, handler)
        return

    try:
        up_r, up_w = await open_upstream(action, handler.CONNECT_TIMEOUT)
    except Exception as e:
        log.warning("[%s] %s -> %s failed: %s", listener.label, src, action,
                    str(e) or type(e).__name__)
        await close_stream(writer)
        return

    c2s = handler.client_to_server if _overridden(handler, "client_to_server", TCPHandler) else None
    s2c = handler.server_to_client if _overridden(handler, "server_to_client", TCPHandler) else None
    await pipe(listener, handler, ctx, up_r, up_w, c2s, s2c)


async def _tcp_respond(listener, handler, ctx: Context, action: Respond) -> None:
    """Send action.data to the client (through server_to_client), then FIN."""
    from .handlers import TCPHandler

    if ctx.buffer:  # peeked client bytes: never forwarded, but keep them in the history
        ctx._record("client", bytes(ctx.buffer))
        ctx.buffer.clear()
    data = action.data
    ctx._record("server", data)  # history shows what the client is answered with
    if _overridden(handler, "server_to_client", TCPHandler):
        out = await run_hook(listener, handler.server_to_client, ctx.src, ctx, data)
        if isinstance(out, (Close, Drop)):
            log.info("[%s] %s -> %s (server_to_client)", listener.label, fmt_addr(ctx.src), out)
            await terminate(ctx, out, handler)
            return
        data = out.data if isinstance(out, Respond) else (out or b"")
    try:
        if data:
            ctx.writer.write(data)
            await ctx.writer.drain()
    except (ConnectionError, OSError):
        pass
    await close_stream(ctx.writer)


async def pipe(listener, handler, ctx: Context, up_r, up_w, c2s=None, s2c=None) -> None:
    """Bidirectional copy with optional rewrite hooks."""
    final = None  # Close/Drop requested by a hook

    loop = asyncio.get_running_loop()
    timeout = getattr(handler, "TCP_TIMEOUT", None)
    timeout = TCP_TIMEOUT if timeout is None else float(timeout)
    last_io = loop.time()

    async def watchdog():
        """Close the pipe after `timeout` seconds without data in either direction."""
        while True:
            remaining = last_io + timeout - loop.time()
            if remaining <= 0:
                log.info("[%s] %s -> CLOSE (idle %gs)", listener.label, fmt_addr(ctx.src), timeout)
                return True
            await asyncio.sleep(remaining)

    async def pump(src_r, dst_w, hook, direction: str, initial: bytes = b""):
        nonlocal final, last_io
        data = initial
        while True:
            if not data:
                data = await src_r.read(READ_CHUNK)
                if not data:  # EOF: half-close the other side if possible
                    with suppress(Exception):
                        if dst_w.can_write_eof():
                            dst_w.write_eof()
                        else:
                            dst_w.close()
                    return False
            last_io = loop.time()
            ctx._record(direction, data)  # before the hook: it can search this chunk too
            if hook is not None:
                out = await run_hook(listener, hook, ctx.src, ctx, data)
                if isinstance(out, (Close, Drop, Respond)):
                    final = out
                    log.info("[%s] %s -> %s (%s)", listener.label, fmt_addr(ctx.src),
                             out, hook.__name__)
                    return True
                data = out or b""
            if data:
                dst_w.write(data)
                await dst_w.drain()
                last_io = loop.time()  # a slow peer blocking drain() is not "idle"
            data = b""

    initial = bytes(ctx.buffer)
    ctx.buffer.clear()
    pumps = {
        asyncio.create_task(pump(ctx.reader, up_w, c2s, "client", initial)),
        asyncio.create_task(pump(up_r, ctx.writer, s2c, "server")),
    }
    tasks = set(pumps)
    if timeout > 0:
        tasks.add(asyncio.create_task(watchdog()))
    try:
        pending = set(tasks)
        while pending & pumps:  # until both directions are done, or something stops it
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            stop = any(t.cancelled() or t.exception() is not None or t.result() for t in done)
            if stop:
                break
    finally:
        for t in tasks:
            t.cancel()
        await close_stream(up_w)
        if isinstance(final, Drop):
            await BLACKHOLE.hold(ctx.reader, ctx.writer, handler.DROP_TIMEOUT)
        elif isinstance(final, Respond):  # a hook answered: send its bytes, then FIN
            ctx._record("server", final.data)
            with suppress(ConnectionError, OSError):
                if final.data:
                    ctx.writer.write(final.data)
                    await ctx.writer.drain()
            await close_stream(ctx.writer)
        else:
            await close_stream(ctx.writer, reset=bool(final and final.reset))


# --------------------------------------------------------------------------- HTTP

class UpstreamError(Exception):
    pass


class _Upstream:
    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer


async def _forward(handler, pool: dict, route: Route, req: h.Request, upgrade: bool):
    """Send req to the backend, return (Response, upstream, reusable)."""
    key = (route.host, route.port, route.tls)
    up = pool.pop(key, None)
    reused = up is not None
    payload = h.serialize_request(req, upgrade=upgrade)

    for attempt in (0, 1):
        try:
            if up is None:
                up = _Upstream(*await open_upstream(route, handler.CONNECT_TIMEOUT))
            up.writer.write(payload)
            await up.writer.drain()
            head = await asyncio.wait_for(h.read_head(up.reader), handler.UPSTREAM_TIMEOUT)
            if head is None:
                raise ConnectionResetError("backend closed connection")
            break
        except TimeoutError:  # before OSError (its base class): a slow backend is never retried
            await close_stream(up.writer if up else None)
            raise UpstreamError("timeout") from None
        except (ConnectionError, OSError, h.HTTPError) as e:
            await close_stream(up.writer if up else None)
            up = None
            if reused and attempt == 0:  # stale keep-alive connection: retry once fresh
                reused = False
                continue
            raise UpstreamError(str(e) or type(e).__name__) from None

    try:
        while True:
            version, status, reason = h.parse_status_line(head[0])
            if 100 <= status < 200 and status != 101:  # skip interim responses
                head = await asyncio.wait_for(h.read_head(up.reader), handler.UPSTREAM_TIMEOUT)
                if head is None:
                    raise UpstreamError("backend closed connection")
                continue
            break
        headers = head[1]
        resp = h.Response(status, reason, headers, b"", version)
        if status == 101:
            return resp, up, False
        reusable = True
        if h.response_has_body(status, req.method):
            resp.body, reusable = await asyncio.wait_for(
                h.read_body(up.reader, headers, until_eof=True), handler.UPSTREAM_TIMEOUT)
        conn_tokens = headers.tokens("Connection")
        if "close" in conn_tokens or (version == "HTTP/1.0" and "keep-alive" not in conn_tokens):
            reusable = False
        return resp, up, reusable
    except UpstreamError:
        await close_stream(up.writer)
        raise
    except (ConnectionError, OSError, h.HTTPError, TimeoutError) as e:
        await close_stream(up.writer)
        raise UpstreamError(str(e) or type(e).__name__) from None


async def _close_pool(pool: dict) -> None:
    for up in pool.values():
        await close_stream(up.writer)
    pool.clear()


def _make_response(action: Respond) -> h.Response:
    headers = h.Headers(action.headers or ())
    reason = action.reason
    if not reason:
        with suppress(ValueError):
            reason = HTTPStatus(action.status).phrase
    return h.Response(action.status, reason, headers, action.data)


def _client_keep_alive(req: h.Request) -> bool:
    tokens = req.headers.tokens("Connection")
    if req.version == "HTTP/1.0":
        return "keep-alive" in tokens
    return "close" not in tokens


async def serve_http(listener, reader, writer) -> None:
    from .handlers import HTTPHandler

    ctx = Context(reader, writer)
    src = fmt_addr(ctx.src)
    pool: dict[tuple, _Upstream] = {}
    try:
        while True:
            handler = listener.handler  # latest version applies to every request
            try:
                head = await asyncio.wait_for(h.read_head(reader), handler.IDLE_TIMEOUT)
                if head is None:
                    return
                method, path, version = h.parse_request_line(head[0])
                req = h.Request(method, path, version, head[1], b"", ctx)
                # Never answer "100 Continue": handle() hasn't decided yet, and a reply
                # would break Drop/Close. Clients send the body anyway after a short wait
                # (curl: 1s).
                del req.headers["Expect"]
                req.body, _ = await asyncio.wait_for(
                    h.read_body(reader, req.headers), handler.IDLE_TIMEOUT)
            except h.HTTPError as e:
                log.info("[%s] %s -> CLOSE (bad request: %s)", listener.label, src, e)
                return
            except (TimeoutError, ConnectionError, OSError):
                return
            ctx.requests += 1

            if handler.sessions is not None and _overridden(handler, "session_key", HTTPHandler):
                try:
                    keys = normalize_keys(await maybe_await(handler.session_key(h.RequestView(req))))
                except Exception:
                    log.exception("[%s] %s session_key() raised; no session", listener.label, src)
                    keys = []
                if keys:
                    store = handler.sessions
                    store.ttl, store.max_sessions = handler.SESSION_TTL, handler.SESSION_MAX
                    req.session = store.touch(keys, ctx.id)

            action = await decide(listener, handler, req, ctx.src)
            log.info("[%s] %s -> %s", listener.label, src, action)

            if isinstance(action, Respond):
                resp = _make_response(action)  # no backend; still goes through on_response
            elif not isinstance(action, Route):
                await _close_pool(pool)  # don't keep backend sockets open while holding a Drop
                await terminate(ctx, action, handler)
                return
            else:
                upgrade = req.wants_upgrade
                try:
                    resp, up, reusable = await _forward(handler, pool, action, req, upgrade)
                except UpstreamError as e:
                    log.warning("[%s] %s -> %s failed: %s", listener.label, src, action, e)
                    return

                if resp.status == 101:  # protocol switch (websocket etc.): raw pipe from here on
                    writer.write(h.serialize_upgrade_response(resp))
                    await writer.drain()
                    await pipe(listener, handler, ctx, up.reader, up.writer)
                    return

                key = (action.host, action.port, action.tls)
                if reusable:
                    old = pool.pop(key, None)
                    if old is not None and old is not up:
                        await close_stream(old.writer)
                    pool[key] = up
                else:
                    await close_stream(up.writer)

            if _overridden(handler, "on_response", HTTPHandler):
                out = await run_hook(listener, handler.on_response, ctx.src, req, resp)
                if out is None:
                    out = resp
                if isinstance(out, Respond):  # replace the reply entirely
                    log.info("[%s] %s -> %s (on_response)", listener.label, src, out)
                    out = _make_response(out)
                if isinstance(out, (Close, Drop)):
                    log.info("[%s] %s -> %s (on_response)", listener.label, src, out)
                    await _close_pool(pool)
                    await terminate(ctx, out, handler)
                    return
                if not isinstance(out, h.Response):
                    log.error("[%s] %s on_response() returned %r; sending original",
                              listener.label, src, out)
                    out = resp
                resp = out

            keep_alive = _client_keep_alive(req)
            try:
                writer.write(h.serialize_response(resp, keep_alive, req.method))
                await writer.drain()
            except (ConnectionError, OSError):
                return
            if not keep_alive:
                return
    finally:
        await _close_pool(pool)
        if not writer.transport.is_closing():
            await close_stream(writer)


# --------------------------------------------------------------------------- listener

class Listener:
    """One bound socket serving one rule. `rule` is swapped in place on reload."""

    def __init__(self, rule):
        self.rule = rule
        self.server: asyncio.base_events.Server | None = None
        self._tasks: set[asyncio.Task] = set()

    @property
    def handler(self):
        return self.rule.handler

    @property
    def label(self) -> str:
        return self.rule.label

    async def start(self) -> None:
        rule = self.rule
        serve = serve_tcp if rule.protocol == "tcp" else serve_http
        kwargs = {}
        if rule.protocol == "https":
            kwargs = {"ssl": rule.ssl_ctx, "ssl_handshake_timeout": 10}

        async def on_client(reader, writer):
            task = asyncio.current_task()
            self._tasks.add(task)
            try:
                await serve(self, reader, writer)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("[%s] unhandled error", self.label)
                await close_stream(writer)
            finally:
                self._tasks.discard(task)

        self.server = await asyncio.start_server(
            on_client, host=rule.host, port=rule.port, limit=STREAM_LIMIT,
            reuse_address=True, **kwargs)

    def stop(self) -> None:
        """Stop accepting; in-flight connections finish on their own."""
        if self.server is not None:
            self.server.close()
            self.server = None
