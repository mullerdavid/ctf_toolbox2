"""Actions a handler can return."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Route:
    """Forward the request/connection to a backend."""

    host: str
    port: int
    tls: bool = False          # talk TLS to the backend
    sni: str | None = None     # TLS server name (defaults to host)
    verify: bool = False       # verify the backend certificate

    def __str__(self) -> str:
        return f"ROUTE {self.host}:{self.port}" + (" (tls)" if self.tls else "")


@dataclass(frozen=True)
class Close:
    """Close the client socket without a reply.

    reset=False -> normal close (FIN), reset=True -> abort with TCP RST.
    """

    reset: bool = False

    def __str__(self) -> str:
        return "CLOSE (rst)" if self.reset else "CLOSE"


@dataclass(frozen=True)
class Drop:
    """Send nothing at all: no reply, no FIN, no RST.

    The socket is held open and incoming data is discarded until the client
    gives up or the handler's DROP_TIMEOUT expires, then released via
    TCP_REPAIR so the kernel sends nothing (needs CAP_NET_ADMIN).
    """

    def __str__(self) -> str:
        return "DROP"


@dataclass(frozen=True)
class Respond:
    """Answer the client directly; no backend is contacted.

    HTTP/HTTPS: becomes a Response(status, reason, headers, body) that goes
    through on_response() like a backend reply; keep-alive continues.
    TCP: `body` is sent raw (through server_to_client()), then the
    connection is closed with FIN. status/reason/headers are ignored.
    A str body is UTF-8 encoded.
    """

    body: bytes | str = b""
    status: int = 200
    headers: dict | list | None = None
    reason: str = ""

    @property
    def data(self) -> bytes:
        return self.body.encode() if isinstance(self.body, str) else bytes(self.body)

    def __str__(self) -> str:
        return f"RESPOND {self.status} ({len(self.data)} bytes)"


ACTIONS = (Route, Close, Drop, Respond)


def normalize(action):
    """Allow `return Close` / `return Drop` / `return Respond` (the class) as shorthand."""
    if action is Close or action is Drop or action is Respond:
        return action()
    return action
