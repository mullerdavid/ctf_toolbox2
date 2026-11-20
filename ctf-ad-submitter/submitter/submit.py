"""Flag submission over the line-based TCP protocol.

One flag per line, one answer line per flag, in order, no greeting. Flags are
deduplicated locally (also across restarts via STATE_FILE) and retried while
they are still inside the validity window.
"""
import asyncio
import json
import logging
import os
import time
from collections import Counter, defaultdict

log = logging.getLogger("submit")

FINAL = {"OK", "DUPLICATE", "OWN", "OLD", "INVALID"}       # never resent
RETRY = {"ERROR", "GAME_NOT_OPEN", "INVALID_SENDER", "SPAM"}
BATCH = 200
READ_TIMEOUT = 15
SAVE_EVERY = 10


def parse_status(line: str) -> str:
    """First known status word on the line ('OK', 'FLAG{..} OK', ...)."""
    for tok in line.replace(":", " ").split():
        t = tok.strip().upper()
        if t in FINAL or t in RETRY:
            return t
    return "UNKNOWN"


class Submitter:
    def __init__(self, get_cfg):
        self.get_cfg = get_cfg              # returns the current Config (reloadable)
        self.pending = {}                   # flag -> {"exploit", "first", "next", "tries"}
        self.done = {}                      # flag -> time it got a final answer
        self.wake = asyncio.Event()
        self.reader = self.writer = None
        self.addr = None
        self.dirty = False
        self.last_save = 0.0
        self.local_dups = Counter()

    # ---- public -----------------------------------------------------------
    def add(self, flag: str, exploit: str) -> None:
        if flag in self.done or flag in self.pending:
            self.local_dups[exploit] += 1
            return
        now = time.time()
        self.pending[flag] = {"exploit": exploit, "first": now, "next": 0.0, "tries": 0}
        self.dirty = True
        self.wake.set()

    # ---- state file -------------------------------------------------------
    def lifetime(self) -> float:
        cfg = self.get_cfg()
        return cfg.FLAG_LIFETIME_TICKS * cfg.TICK_LENGTH + cfg.TICK_LENGTH

    def load_state(self) -> None:
        path = self.get_cfg().STATE_FILE
        try:
            with open(path) as f:
                data = json.load(f)
        except FileNotFoundError:
            return
        except (OSError, ValueError) as e:
            log.warning("ignoring state file %s: %s", path, e)
            return
        cutoff = time.time() - self.lifetime()
        self.done = {k: v for k, v in data.get("done", {}).items() if v > cutoff}
        for flag, p in data.get("pending", {}).items():
            if p.get("first", 0) > cutoff:
                self.pending[flag] = {"exploit": p.get("exploit", "?"),
                                      "first": p["first"], "next": 0.0, "tries": 0}
        log.info("state: %d submitted flags remembered, %d pending", len(self.done),
                 len(self.pending))
        if self.pending:
            self.wake.set()

    def save_state(self, force=False) -> None:
        now = time.time()
        if not (self.dirty and (force or now - self.last_save >= SAVE_EVERY)):
            return
        cutoff = now - self.lifetime()
        self.done = {k: v for k, v in self.done.items() if v > cutoff}
        data = {"done": self.done,
                "pending": {k: {"exploit": v["exploit"], "first": v["first"]}
                            for k, v in self.pending.items()}}
        path = self.get_cfg().STATE_FILE
        tmp = path + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump(data, f)
            os.replace(tmp, path)
            self.dirty, self.last_save = False, now
        except OSError as e:
            log.warning("could not save state to %s: %s", path, e)

    # ---- connection -------------------------------------------------------
    async def _connect(self):
        cfg = self.get_cfg()
        addr = (cfg.SUBMIT_HOST, int(cfg.SUBMIT_PORT))
        if self.writer and addr == self.addr and not self.writer.is_closing():
            return
        await self._close()
        self.reader, self.writer = await asyncio.wait_for(
            asyncio.open_connection(*addr), 10)
        self.addr = addr
        log.debug("connected to %s:%d", *addr)

    async def _close(self):
        if self.writer:
            self.writer.close()
            try:
                await asyncio.wait_for(self.writer.wait_closed(), 2)
            except Exception:
                pass
        self.reader = self.writer = None

    # ---- main loop --------------------------------------------------------
    def _due(self, now):
        cutoff = now - self.lifetime()
        for flag in [f for f, p in self.pending.items() if p["first"] < cutoff]:
            p = self.pending.pop(flag)
            log.warning("[%s] gave up on %s after %d tries (expired)", p["exploit"],
                        flag, p["tries"])
            self.dirty = True
        return [f for f, p in self.pending.items() if p["next"] <= now][:BATCH]

    async def run(self):
        backoff = 1.0
        while True:
            now = time.time()
            batch = self._due(now)
            self.save_state()
            if not batch:
                nexts = [p["next"] for p in self.pending.values()]
                wait = min([max(0.2, n - now) for n in nexts] + [SAVE_EVERY])
                self.wake.clear()
                try:
                    await asyncio.wait_for(self.wake.wait(), wait)
                except asyncio.TimeoutError:
                    pass
                continue
            try:
                await self._connect()
                answered = await self._send(batch)
                backoff = 1.0
            except (OSError, asyncio.TimeoutError, ConnectionError) as e:
                cfg = self.get_cfg()
                log.warning("submission to %s:%s failed: %s (retry in %.0fs)",
                            cfg.SUBMIT_HOST, cfg.SUBMIT_PORT,
                            str(e) or type(e).__name__, backoff)
                await self._close()
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30)
                continue
            if answered < len(batch):       # server closed mid-batch: reconnect
                await self._close()

    async def _send(self, batch) -> int:
        self.writer.write("".join(f + "\n" for f in batch).encode())
        await self.writer.drain()
        per_exploit = defaultdict(Counter)
        raw_unknown = []
        answered = 0
        try:
            for flag in batch:
                line = await asyncio.wait_for(self.reader.readline(), READ_TIMEOUT)
                if not line:
                    break
                answered += 1
                text = line.decode("utf-8", "replace").strip()
                status = parse_status(text)
                p = self.pending.get(flag)
                if p is None:
                    continue
                per_exploit[p["exploit"]][status] += 1
                p["tries"] += 1
                if status in FINAL:
                    del self.pending[flag]
                    self.done[flag] = time.time()
                else:
                    if status == "UNKNOWN":
                        raw_unknown.append(text)
                    p["next"] = time.time() + min(5 * 2 ** (p["tries"] - 1), 60)
                self.dirty = True
        finally:
            for exploit, counts in sorted(per_exploit.items()):
                summary = ", ".join(f"{n} {s}" for s, n in counts.most_common())
                bad = counts.keys() & {"INVALID_SENDER", "ERROR", "UNKNOWN"}
                (log.warning if bad else log.info)("[%s] submitted: %s", exploit, summary)
            if "INVALID_SENDER" in {s for c in per_exploit.values() for s in c}:
                log.error("INVALID_SENDER: source IP not a team address, is the VPN up?")
            for text in raw_unknown[:3]:
                log.warning("unrecognized answer: %r", text[:200])
        return answered
