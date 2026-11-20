"""Abstract bases that rule files subclass.

Each rule file in the rules directory defines exactly one concrete subclass of
TCPHandler, HTTPHandler or HTTPSHandler. Its class attributes are the listener
config; its methods are the routing logic.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from .shared import shared as _shared


class Handler(ABC):
    PROTOCOL: str = ""

    # --- listener config ---------------------------------------------------
    PORT: int | None = None          # required
    HOST: str = "0.0.0.0"            # bind address

    # --- behaviour -----------------------------------------------------------
    DEFAULT = None                   # action used if handle() raises/returns junk; None -> Close()
    CONNECT_TIMEOUT: float = 5.0     # connecting to a backend
    UPSTREAM_TIMEOUT: float = 30.0   # waiting for a backend response (HTTP)
    IDLE_TIMEOUT: float = 120.0      # waiting for the next client request (HTTP keep-alive)
    DROP_TIMEOUT: float = 600.0      # how long a dropped socket is held silently
    TCP_TIMEOUT: float | None = None # idle timeout of raw pipes (TCP rules, upgraded HTTP);
                                     # None -> LB_TCP_TIMEOUT (default 180), 0 -> no timeout

    # Global TTL key/value store shared by all rules (same object as balancer.shared).
    shared = _shared

    # Set by the loader after instantiation.
    name: str = ""
    log: logging.LoggerAdapter

    def on_load(self, previous: "Handler | None") -> None:
        """Called after a successful load, before the handler goes live.

        `previous` is the handler instance being replaced (or None), so state
        can be carried across reloads. Raising here rejects the new version.
        """


class TCPHandler(Handler):
    PROTOCOL = "tcp"

    # Bytes of stream history kept per direction for ctx.client_bytes /
    # ctx.server_bytes / ctx.transcript() / ctx.search(). 0 disables.
    HISTORY: int = 1 << 20

    @abstractmethod
    async def handle(self, ctx):
        """Decide once per connection. Return Route(...), Close() or Drop().

        Use `await ctx.peek(...)` / `await ctx.read_until(...)` to look at the
        first client bytes before deciding (they are still forwarded).
        """

    async def client_to_server(self, ctx, data: bytes):
        """Rewrite client->backend data. Return bytes, Close() or Drop()."""
        return data

    async def server_to_client(self, ctx, data: bytes):
        """Rewrite backend->client data. Return bytes, Close() or Drop()."""
        return data


class HTTPHandler(Handler):
    PROTOCOL = "http"

    SESSION_TTL: float = 1800.0      # seconds without requests before a session expires
    SESSION_MAX: int = 10000         # max live sessions (least recently used evicted)

    # Set by the loader: this rule's SessionStore (survives reloads).
    # self.sessions.get("user:alice") -> Session | None; iterate for all.
    sessions = None

    def session_key(self, req):
        """Optional: group requests across connections.

        Called before handle() with a READ-ONLY copy of the request. Return a
        key (str), several keys (list), or None. Requests sharing any key get
        the same `req.session`; all returned keys are linked to it. May be async.
        """
        return None

    @abstractmethod
    async def handle(self, req):
        """Decide once per request. Mutate `req` to rewrite it, then return
        Route(...), Close() or Drop(). req.ctx is shared by all requests on
        the same client connection."""

    async def on_response(self, req, resp):
        """Rewrite the backend response. Return a Response, Close() or Drop()."""
        return resp


class HTTPSHandler(HTTPHandler):
    PROTOCOL = "https"
    CERT: str = "/certs/cert.pem"
    KEY: str = "/certs/key.pem"
