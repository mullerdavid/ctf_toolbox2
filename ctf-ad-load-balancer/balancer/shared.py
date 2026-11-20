"""Global key/value store shared by all rules and connections, with per-entry TTL.

Expired entries are invisible immediately (checked on access) and removed by a
background sweeper. The store lives in the balancer process, so it survives
rule reloads; it is lost when the balancer restarts.
"""
from __future__ import annotations

import asyncio
import heapq
import logging
import time

log = logging.getLogger("lb")

_MISSING = object()


class TTLStore:
    def __init__(self, default_ttl: float = 1800.0, max_entries: int = 100_000):
        self.default_ttl = default_ttl
        self.max_entries = max_entries
        self._data: dict[str, tuple[object, float]] = {}   # key -> (value, expires_at)
        self._heap: list[tuple[float, str]] = []           # (expires_at, key), lazily pruned

    # --- internals ------------------------------------------------------------
    @staticmethod
    def _now() -> float:
        return time.monotonic()

    def _ttl(self, ttl) -> float:
        ttl = self.default_ttl if ttl is None else float(ttl)
        if ttl <= 0:
            raise ValueError("ttl must be > 0")
        return ttl

    def _put(self, key: str, value, expires: float) -> None:
        self._data[key] = (value, expires)
        heapq.heappush(self._heap, (expires, key))
        if len(self._data) > self.max_entries:
            self.sweep()
            while len(self._data) > self.max_entries and self._heap:  # evict soonest-expiring
                exp, k = heapq.heappop(self._heap)
                entry = self._data.get(k)
                if entry is not None and entry[1] == exp:
                    del self._data[k]

    def _live(self, key: str):
        entry = self._data.get(key)
        if entry is None:
            return None
        if entry[1] <= self._now():
            del self._data[key]
            return None
        return entry

    # --- API ------------------------------------------------------------------
    def set(self, key: str, value=True, ttl: float | None = None) -> None:
        """Store value for ttl seconds (default: default_ttl)."""
        self._put(key, value, self._now() + self._ttl(ttl))

    def get(self, key: str, default=None):
        entry = self._live(key)
        return default if entry is None else entry[0]

    def __getitem__(self, key: str):
        entry = self._live(key)
        if entry is None:
            raise KeyError(key)
        return entry[0]

    def __setitem__(self, key: str, value) -> None:
        self.set(key, value)

    def __contains__(self, key: str) -> bool:
        return self._live(key) is not None

    def delete(self, key: str) -> bool:
        return self._data.pop(key, None) is not None

    __delitem__ = delete

    def pop(self, key: str, default=None):
        entry = self._live(key)
        if entry is None:
            return default
        del self._data[key]
        return entry[0]

    def setdefault(self, key: str, value, ttl: float | None = None):
        """Return the live value, or store `value` with ttl and return it."""
        entry = self._live(key)
        if entry is not None:
            return entry[0]
        self.set(key, value, ttl)
        return value

    def incr(self, key: str, amount: int = 1, ttl: float | None = None) -> int:
        """Add to a counter. A new counter gets ttl; an existing one keeps its expiry."""
        entry = self._live(key)
        if entry is None:
            self.set(key, amount, ttl)
            return amount
        value = entry[0] + amount
        self._data[key] = (value, entry[1])
        return value

    def touch(self, key: str, ttl: float | None = None) -> bool:
        """Restart the TTL of a live entry. False if missing/expired."""
        entry = self._live(key)
        if entry is None:
            return False
        self._put(key, entry[0], self._now() + self._ttl(ttl))
        return True

    def ttl(self, key: str) -> float | None:
        """Seconds left, or None if missing/expired."""
        entry = self._live(key)
        return None if entry is None else entry[1] - self._now()

    def keys(self, prefix: str = "") -> list[str]:
        now = self._now()
        return [k for k, (_, exp) in self._data.items() if exp > now and k.startswith(prefix)]

    def items(self, prefix: str = "") -> list[tuple[str, object]]:
        now = self._now()
        return [(k, v) for k, (v, exp) in self._data.items() if exp > now and k.startswith(prefix)]

    def clear(self, prefix: str = "") -> int:
        doomed = [k for k in self._data if k.startswith(prefix)]
        for k in doomed:
            del self._data[k]
        return len(doomed)

    def __len__(self) -> int:
        now = self._now()
        return sum(1 for _, exp in self._data.values() if exp > now)

    def sweep(self) -> int:
        """Remove expired entries. Returns how many were removed."""
        now = self._now()
        removed = 0
        while self._heap and self._heap[0][0] <= now:
            exp, key = heapq.heappop(self._heap)
            entry = self._data.get(key)
            if entry is not None and entry[1] == exp:  # stale heap items are skipped
                del self._data[key]
                removed += 1
        # Drop heap garbage from overwritten keys once it dominates.
        if len(self._heap) > 2 * len(self._data) + 1024:
            self._heap = [(exp, k) for k, (_, exp) in self._data.items()]
            heapq.heapify(self._heap)
        return removed

    async def sweeper(self, interval: float = 5.0) -> None:
        while True:
            await asyncio.sleep(interval)
            removed = self.sweep()
            if removed:
                log.debug("shared: swept %d expired entries (%d left)", removed, len(self._data))

    def __repr__(self) -> str:
        return f"<TTLStore {len(self)} live entries>"


# The one global instance: `from balancer import shared` or `self.shared` in a handler.
shared = TTLStore()
