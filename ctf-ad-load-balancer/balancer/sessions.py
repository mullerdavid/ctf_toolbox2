"""Cross-connection sessions: group requests by keys a handler derives from them."""
from __future__ import annotations

import itertools
import time
from collections import OrderedDict
from collections.abc import Iterable

_session_ids = itertools.count(1)


class Session:
    """State shared by every request that maps to one of this session's keys.

    Attributes:
        id          short unique id (handy in your own log lines)
        keys        keys pointing at this session
        created     unix time of creation
        last_seen   unix time of the last request
        requests    number of requests seen
        connections number of distinct client connections seen
        state       free-form dict

    Any other attribute can be set freely; reading one never set returns None.
    """

    def __init__(self, store: "SessionStore"):
        self._store = store
        self.id = f"s{next(_session_ids)}"
        self.keys: set[str] = set()
        self.created = time.time()
        self.last_seen = self.created
        self._seen_mono = time.monotonic()
        self.requests = 0
        self._conn_ids: set[int] = set()
        self.state: dict = {}

    def __getattr__(self, name: str):
        if name.startswith("__"):
            raise AttributeError(name)
        return None

    @property
    def connections(self) -> int:
        return len(self._conn_ids)

    def add_key(self, key: str) -> None:
        """Link another key to this session (e.g. a cookie issued in a response)."""
        if key:
            self._store.link(self, str(key))

    def __repr__(self) -> str:
        return f"<Session {self.id} keys={sorted(self.keys)} requests={self.requests}>"


class SessionStore:
    """Sessions of one rule. Survives rule reloads; LRU + TTL bounded."""

    def __init__(self, ttl: float = 1800.0, max_sessions: int = 10000):
        self.ttl = ttl
        self.max_sessions = max_sessions
        self._sessions: OrderedDict[str, Session] = OrderedDict()  # LRU order
        self._index: dict[str, Session] = {}

    def __len__(self) -> int:
        return len(self._sessions)

    def __iter__(self):
        return iter(list(self._sessions.values()))

    def get(self, key: str) -> Session | None:
        """Look up a live session by key without touching it."""
        self._expire()
        return self._index.get(key)

    def link(self, session: Session, key: str) -> None:
        old = self._index.get(key)
        if old is not None and old is not session:
            old.keys.discard(key)  # key moves to the newer session
        self._index[key] = session
        session.keys.add(key)

    def _drop(self, session: Session) -> None:
        self._sessions.pop(session.id, None)
        for key in session.keys:
            if self._index.get(key) is session:
                del self._index[key]

    def _expire(self) -> None:
        cutoff = time.monotonic() - self.ttl
        while self._sessions:
            oldest = next(iter(self._sessions.values()))
            if oldest._seen_mono >= cutoff:
                break
            self._drop(oldest)

    def touch(self, keys: Iterable[str], conn_id: int) -> Session:
        """Find (first matching key wins) or create the session; link all keys."""
        self._expire()
        session = None
        for key in keys:
            session = self._index.get(key)
            if session is not None:
                break
        if session is None:
            session = Session(self)
            self._sessions[session.id] = session
        for key in keys:
            if key not in session.keys:
                self.link(session, key)
        session.last_seen = time.time()
        session._seen_mono = time.monotonic()
        session.requests += 1
        session._conn_ids.add(conn_id)
        self._sessions.move_to_end(session.id)
        while len(self._sessions) > self.max_sessions:
            self._drop(next(iter(self._sessions.values())))
        return session


_stores: dict[str, SessionStore] = {}


def store_for(rule_name: str) -> SessionStore:
    """One store per rule file name, kept across reloads."""
    if rule_name not in _stores:
        _stores[rule_name] = SessionStore()
    return _stores[rule_name]


def drop_store(rule_name: str) -> None:
    _stores.pop(rule_name, None)


def normalize_keys(result) -> list[str]:
    """session_key() may return None, a str, or an iterable of str."""
    if result is None:
        return []
    if isinstance(result, (str, bytes)):
        result = [result]
    keys = []
    for k in result:
        if k:
            k = k.decode("latin-1") if isinstance(k, bytes) else str(k)
            if k not in keys:
                keys.append(k)
    return keys
