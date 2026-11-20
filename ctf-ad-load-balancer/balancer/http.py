"""Minimal HTTP/1.x message model, parser and serializer.

Bodies are always fully buffered (Content-Length, chunked, or read-to-EOF)
and re-sent with a fresh Content-Length, so handlers can freely rewrite them.
"""
from __future__ import annotations

import asyncio
import json as _json
from urllib.parse import parse_qs, urlsplit

MAX_HEADERS = 256
MAX_BODY = 64 * 1024 * 1024

# Headers that only apply to a single hop; never forwarded as-is.
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-connection", "te", "trailer",
    "transfer-encoding", "upgrade",
}


class HTTPError(Exception):
    """Malformed HTTP message."""


class Headers:
    """Ordered, case-insensitive, multi-value header list."""

    def __init__(self, items=None):
        self._items: list[tuple[str, str]] = []
        if items:
            if isinstance(items, dict):
                items = items.items()
            for k, v in items:
                self._items.append((str(k), str(v)))

    def __getitem__(self, name: str) -> str:
        n = name.lower()
        for k, v in self._items:
            if k.lower() == n:
                return v
        raise KeyError(name)

    def get(self, name: str, default=None):
        try:
            return self[name]
        except KeyError:
            return default

    def get_all(self, name: str) -> list[str]:
        n = name.lower()
        return [v for k, v in self._items if k.lower() == n]

    def __setitem__(self, name: str, value) -> None:
        """Replace all headers called `name` with a single value."""
        n = name.lower()
        out, placed = [], False
        for k, v in self._items:
            if k.lower() == n:
                if not placed:
                    out.append((k, str(value)))
                    placed = True
            else:
                out.append((k, v))
        if not placed:
            out.append((name, str(value)))
        self._items = out

    def add(self, name: str, value) -> None:
        self._items.append((name, str(value)))

    def __delitem__(self, name: str) -> None:
        """Remove all headers called `name` (no error if missing)."""
        n = name.lower()
        self._items = [(k, v) for k, v in self._items if k.lower() != n]

    def pop(self, name: str, default=None):
        value = self.get(name, default)
        del self[name]
        return value

    def __contains__(self, name) -> bool:
        n = str(name).lower()
        return any(k.lower() == n for k, _ in self._items)

    def __iter__(self):
        return (k for k, _ in self._items)

    def __len__(self) -> int:
        return len(self._items)

    def items(self) -> list[tuple[str, str]]:
        return list(self._items)

    def copy(self) -> "Headers":
        return Headers(self._items)

    def tokens(self, name: str) -> set[str]:
        """Comma-separated tokens of a header, lowercased (e.g. Connection)."""
        out = set()
        for v in self.get_all(name):
            out.update(t.strip().lower() for t in v.split(",") if t.strip())
        return out

    def __repr__(self) -> str:
        return f"Headers({self._items!r})"


class _Message:
    headers: Headers
    body: bytes

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def json(self):
        return _json.loads(self.body)


class Request(_Message):
    def __init__(self, method: str, path: str, version: str, headers: Headers,
                 body: bytes = b"", ctx=None):
        self.method = method
        self.path = path          # full request target, including query string
        self.version = version
        self.headers = headers
        self.body = body
        self.ctx = ctx            # per-connection Context
        self.session = None       # cross-connection Session (from session_key), or None

    @property
    def src(self):
        return self.ctx.src if self.ctx else None

    @property
    def cookies(self) -> dict[str, str]:
        """Cookies from the Cookie header(s), name -> value."""
        out = {}
        for header in self.headers.get_all("Cookie"):
            for part in header.split(";"):
                name, sep, value = part.strip().partition("=")
                if sep and name:
                    out.setdefault(name, value)
        return out

    @property
    def path_only(self) -> str:
        return urlsplit(self.path).path

    @property
    def query(self) -> dict[str, list[str]]:
        return parse_qs(urlsplit(self.path).query, keep_blank_values=True)

    def form(self) -> dict[str, list[str]]:
        return parse_qs(self.body.decode("latin-1"), keep_blank_values=True)

    @property
    def wants_upgrade(self) -> bool:
        return "upgrade" in self.headers.tokens("Connection") and "Upgrade" in self.headers

    def raw(self) -> bytes:
        """Serialized form (as it will be forwarded); handy for logging."""
        return serialize_request(self)

    def __repr__(self) -> str:
        return f"<Request {self.method} {self.path}>"


class Response(_Message):
    def __init__(self, status: int, reason: str = "", headers: Headers | None = None,
                 body: bytes = b"", version: str = "HTTP/1.1"):
        self.status = status
        self.reason = reason
        self.headers = headers if headers is not None else Headers()
        self.body = body
        self.version = version

    @property
    def cookies(self) -> dict[str, str]:
        """Cookies set by Set-Cookie header(s), name -> value (attributes dropped)."""
        out = {}
        for header in self.headers.get_all("Set-Cookie"):
            name, sep, value = header.split(";", 1)[0].strip().partition("=")
            if sep and name:
                out[name] = value
        return out

    def raw(self) -> bytes:
        return serialize_response(self, keep_alive=True)

    def __repr__(self) -> str:
        return f"<Response {self.status} {self.reason}>"


# --------------------------------------------------------------------------- read-only view

class FrozenHeaders(Headers):
    def _read_only(self, *args, **kwargs):
        raise TypeError("headers are read-only here")

    __setitem__ = __delitem__ = add = pop = _read_only


class RequestView(Request):
    """Immutable snapshot of a request, passed to session_key()."""

    def __init__(self, req: Request):
        set_ = object.__setattr__
        set_(self, "method", req.method)
        set_(self, "path", req.path)
        set_(self, "version", req.version)
        set_(self, "headers", FrozenHeaders(req.headers.items()))
        set_(self, "body", bytes(req.body))
        set_(self, "ctx", None)
        set_(self, "session", None)
        set_(self, "_src", req.src)

    @property
    def src(self):
        return self._src

    def __setattr__(self, name, value):
        raise TypeError("request is read-only in session_key()")

    def __delattr__(self, name):
        raise TypeError("request is read-only in session_key()")


# --------------------------------------------------------------------------- parsing

async def read_head(reader: asyncio.StreamReader):
    """Read start line + headers. Returns (start_line, Headers) or None on clean EOF."""
    line = b""
    for _ in range(8):  # tolerate a few stray empty lines between requests
        try:
            line = await reader.readuntil(b"\n")
        except asyncio.IncompleteReadError as e:
            if not e.partial.strip():
                return None
            raise HTTPError("truncated start line") from None
        except asyncio.LimitOverrunError:
            raise HTTPError("start line too long") from None
        if line.strip():
            break
    else:
        return None

    start = line.rstrip(b"\r\n").decode("latin-1")
    headers = Headers()
    while True:
        try:
            raw = await reader.readuntil(b"\n")
        except asyncio.IncompleteReadError:
            raise HTTPError("truncated headers") from None
        except asyncio.LimitOverrunError:
            raise HTTPError("header line too long") from None
        raw = raw.rstrip(b"\r\n")
        if not raw:
            break
        if len(headers) >= MAX_HEADERS:
            raise HTTPError("too many headers")
        if raw[:1] in (b" ", b"\t") and headers._items:  # obsolete line folding
            k, v = headers._items[-1]
            headers._items[-1] = (k, v + " " + raw.strip().decode("latin-1"))
            continue
        name, sep, value = raw.partition(b":")
        if not sep or not name.strip():
            raise HTTPError("bad header line")
        headers.add(name.decode("latin-1").strip(), value.decode("latin-1").strip())
    return start, headers


def parse_request_line(start: str) -> tuple[str, str, str]:
    parts = start.split()
    if len(parts) != 3 or not parts[2].startswith("HTTP/"):
        raise HTTPError(f"bad request line: {start[:80]!r}")
    return parts[0], parts[1], parts[2]


def parse_status_line(start: str) -> tuple[str, int, str]:
    parts = start.split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        raise HTTPError(f"bad status line: {start[:80]!r}")
    try:
        status = int(parts[1])
    except ValueError:
        raise HTTPError(f"bad status code: {parts[1][:20]!r}") from None
    return parts[0], status, parts[2] if len(parts) > 2 else ""


def _content_length(headers: Headers) -> int | None:
    values = headers.get_all("Content-Length")
    if not values:
        return None
    nums = {v.strip() for val in values for v in val.split(",")}
    if len(nums) != 1:
        raise HTTPError("conflicting Content-Length")
    try:
        n = int(nums.pop())
    except ValueError:
        raise HTTPError("bad Content-Length") from None
    if n < 0 or n > MAX_BODY:
        raise HTTPError("Content-Length out of range")
    return n


async def read_body(reader: asyncio.StreamReader, headers: Headers, until_eof: bool = False):
    """Read a message body. Returns (body, delimited).

    delimited=False means the body ran to EOF (connection not reusable).
    """
    try:
        if "chunked" in headers.tokens("Transfer-Encoding"):
            return await _read_chunked(reader), True
        n = _content_length(headers)
        if n is not None:
            return await reader.readexactly(n), True
        if until_eof:
            buf = bytearray()
            while chunk := await reader.read(65536):
                buf += chunk
                if len(buf) > MAX_BODY:
                    raise HTTPError("body too large")
            return bytes(buf), False
        return b"", True
    except asyncio.IncompleteReadError:
        raise HTTPError("truncated body") from None
    except asyncio.LimitOverrunError:
        raise HTTPError("chunk line too long") from None


async def _read_chunked(reader: asyncio.StreamReader) -> bytes:
    body = bytearray()
    while True:
        line = (await reader.readuntil(b"\n")).strip()
        try:
            size = int(line.split(b";", 1)[0], 16)
        except ValueError:
            raise HTTPError("bad chunk size") from None
        if size == 0:
            while (await reader.readuntil(b"\n")).strip():  # trailers, discarded
                pass
            return bytes(body)
        if len(body) + size > MAX_BODY:
            raise HTTPError("body too large")
        body += await reader.readexactly(size)
        await reader.readuntil(b"\n")  # CRLF after chunk data


# --------------------------------------------------------------------------- serializing

def _head_bytes(start: str, headers: list[tuple[str, str]]) -> bytes:
    lines = [start] + [f"{k}: {v}" for k, v in headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "replace")


def serialize_request(req: Request, upgrade: bool = False) -> bytes:
    headers = [(k, v) for k, v in req.headers.items()
               if k.lower() not in HOP_BY_HOP and k.lower() != "content-length"]
    if upgrade:
        headers.append(("Connection", "Upgrade"))
        headers.append(("Upgrade", req.headers.get("Upgrade", "")))
    else:
        headers.append(("Connection", "keep-alive"))
    if req.body or req.method.upper() in ("POST", "PUT", "PATCH"):
        headers.append(("Content-Length", str(len(req.body))))
    return _head_bytes(f"{req.method} {req.path} HTTP/1.1", headers) + req.body


def response_has_body(status: int, method: str) -> bool:
    return not (method.upper() == "HEAD" or 100 <= status < 200 or status in (204, 304))


def serialize_response(resp: Response, keep_alive: bool, method: str = "GET") -> bytes:
    has_body = response_has_body(resp.status, method)
    keep_cl = method.upper() == "HEAD" or resp.status == 304  # describes the GET body
    headers = [(k, v) for k, v in resp.headers.items()
               if k.lower() not in HOP_BY_HOP and (keep_cl or k.lower() != "content-length")]
    if has_body:
        headers.append(("Content-Length", str(len(resp.body))))
    elif method.upper() == "HEAD" and resp.body and "Content-Length" not in resp.headers:
        headers.append(("Content-Length", str(len(resp.body))))  # e.g. Respond(): size of GET body
    headers.append(("Connection", "keep-alive" if keep_alive else "close"))
    reason = resp.reason or ""
    return _head_bytes(f"HTTP/1.1 {resp.status} {reason}".rstrip(), headers) + (
        resp.body if has_body else b"")


def serialize_upgrade_response(resp: Response) -> bytes:
    """101 Switching Protocols: forwarded with its headers untouched."""
    return _head_bytes(f"HTTP/1.1 {resp.status} {resp.reason}".rstrip(), resp.headers.items())
