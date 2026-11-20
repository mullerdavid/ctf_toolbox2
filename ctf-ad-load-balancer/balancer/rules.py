"""Rule loading, listener lifecycle and change detection (inotify + polling)."""
from __future__ import annotations

import asyncio
import inspect
import itertools
import logging
import os
import ssl
import sys
import traceback
import types
from dataclasses import dataclass, field
from pathlib import Path

from .handlers import Handler, HTTPHandler, HTTPSHandler
from .sessions import drop_store, store_for
from .inotify import GONE_MASK, IN_Q_OVERFLOW, Inotify
from .listeners import Listener

log = logging.getLogger("lb")
_module_ids = itertools.count(1)


class RuleError(Exception):
    pass


@dataclass
class LoadedRule:
    path: Path
    name: str
    cls: type
    handler: Handler
    protocol: str
    host: str
    port: int
    ssl_ctx: ssl.SSLContext | None = None
    tls_id: tuple | None = None        # cert/key identity: change -> rebind
    module_name: str = field(default="", repr=False)

    @property
    def label(self) -> str:
        return f"{self.name}:{self.port}"

    @property
    def bind_id(self) -> tuple:
        """Anything in here changing requires restarting the listener."""
        return (self.protocol, self.host, self.port, self.tls_id)


def _file_id(path: str) -> tuple:
    st = os.stat(path)
    return (os.path.abspath(path), st.st_size, st.st_mtime_ns)


def load_rule(path: Path) -> LoadedRule:
    """Import a rule file into a fresh module and validate it. Raises on any problem."""
    name = path.stem
    module_name = f"lbrule_{name}_{next(_module_ids)}"
    module = types.ModuleType(module_name)
    module.__file__ = str(path)
    sys.modules[module_name] = module
    try:
        code = compile(path.read_bytes(), str(path), "exec")
        exec(code, module.__dict__)

        classes = [obj for obj in vars(module).values()
                   if isinstance(obj, type) and issubclass(obj, Handler)
                   and obj.__module__ == module_name]
        concrete = [c for c in classes if not inspect.isabstract(c)]
        if not concrete:
            missing = {c.__name__: sorted(c.__abstractmethods__) for c in classes}
            raise RuleError("no concrete TCPHandler/HTTPHandler/HTTPSHandler subclass"
                            + (f" (unimplemented: {missing})" if missing else ""))
        if len(concrete) > 1:
            raise RuleError(f"more than one handler class: {[c.__name__ for c in concrete]}")
        cls = concrete[0]

        port = getattr(cls, "PORT", None)
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise RuleError(f"{cls.__name__}.PORT must be an int 1-65535, got {port!r}")
        if cls.PROTOCOL not in ("tcp", "http", "https"):
            raise RuleError(f"unknown PROTOCOL {cls.PROTOCOL!r}")

        ssl_ctx = tls_id = None
        if issubclass(cls, HTTPSHandler):
            cert, key = cls.CERT, cls.KEY
            try:
                ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ssl_ctx.load_cert_chain(cert, key)
                tls_id = (_file_id(cert), _file_id(key))
            except (OSError, ssl.SSLError) as e:
                raise RuleError(f"cannot load CERT={cert!r} KEY={key!r}: {e}") from None

        # Set name/log/sessions before __init__ so the rule can use them there.
        handler = cls.__new__(cls)
        handler.name = name
        if issubclass(cls, HTTPHandler):
            handler.sessions = store_for(name)
        handler.log = logging.LoggerAdapter(logging.getLogger(f"rule.{name}"), {})
        handler.log.process = lambda msg, kw, _n=name: (f"[{_n}] {msg}", kw)
        handler.__init__()

        return LoadedRule(path, name, cls, handler, cls.PROTOCOL, cls.HOST, port,
                          ssl_ctx, tls_id, module_name)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise


def _short_error(exc: BaseException) -> str:
    if isinstance(exc, RuleError):
        return str(exc)
    if isinstance(exc, SyntaxError):
        return f"SyntaxError: {exc.msg} (line {exc.lineno})"
    tb = traceback.format_exception(exc)
    return "".join(tb[-3:]).strip()


class Manager:
    def __init__(self, rules_dir: Path):
        self.rules_dir = rules_dir
        self.listeners: dict[Path, Listener] = {}
        self.snapshot: dict[Path, tuple[int, int]] = {}   # path -> (size, mtime_ns)
        self.lock = asyncio.Lock()

    def _current_files(self) -> dict[Path, tuple[int, int]] | None:
        try:
            entries = list(os.scandir(self.rules_dir))
        except OSError as e:
            log.warning("cannot read rules dir %s: %s (keeping current listeners)", self.rules_dir, e)
            return None
        files = {}
        for entry in entries:
            if not entry.name.endswith(".py") or entry.name.startswith((".", "_")):
                continue
            try:
                st = entry.stat()
            except OSError:
                continue
            if entry.is_file():
                files[Path(entry.path)] = (st.st_size, st.st_mtime_ns)
        return files

    async def scan(self, source: str) -> None:
        async with self.lock:
            current = self._current_files()
            if current is None:
                return
            for path in sorted(set(self.snapshot) - set(current)):
                log.info("change detected by %s: %s removed", source, path.name)
                del self.snapshot[path]
                self._remove(path)
                # A freed port may unblock files that failed earlier: retry them.
                for p in [p for p in self.snapshot if p not in self.listeners]:
                    del self.snapshot[p]
            for path in sorted(current):
                if self.snapshot.get(path) == current[path]:
                    continue
                log.info("change detected by %s: %s", source, path.name)
                self.snapshot[path] = current[path]
                await self._apply(path)

    def _remove(self, path: Path) -> None:
        listener = self.listeners.pop(path, None)
        if listener:
            listener.stop()
            sys.modules.pop(listener.rule.module_name, None)
            drop_store(listener.rule.name)
            log.info("[%s] listener stopped (rule file removed)", listener.label)

    async def _apply(self, path: Path) -> None:
        old = self.listeners.get(path)
        keep = " - keeping previous version" if old else ""
        new = None
        try:
            new = load_rule(path)
            for other_path, other in self.listeners.items():
                if other_path != path and other.rule.port == new.port:
                    raise RuleError(f"port {new.port} already used by {other_path.name}")
        except Exception as e:
            if new is not None:
                sys.modules.pop(new.module_name, None)
            log.error("failed to load %s: %s%s", path.name, _short_error(e), keep)
            return

        def run_on_load() -> bool:
            """on_load runs right before the new version goes live; raising rejects it."""
            try:
                new.handler.on_load(old.handler if old else None)
                return True
            except Exception as e:
                sys.modules.pop(new.module_name, None)
                log.error("failed to load %s: on_load() raised: %s%s", path.name,
                          _short_error(e), keep)
                return False

        if old and old.rule.bind_id == new.bind_id:
            if not run_on_load():
                return
            prev = old.rule
            old.rule = new  # new connections/requests use the new handler immediately
            sys.modules.pop(prev.module_name, None)
            log.info("[%s] reloaded %s (%s)", new.label, new.cls.__name__, new.protocol)
            return

        # Listener must be (re)bound: new file, protocol change, port/host change, new cert.
        same_port = old is not None and (old.rule.host, old.rule.port) == (new.host, new.port)
        if same_port:
            old.stop()
        listener = Listener(new)
        try:
            await listener.start()
        except OSError as e:
            log.error("[%s] cannot listen on %s:%d: %s%s", new.label, new.host, new.port, e, keep)
            sys.modules.pop(new.module_name, None)
            if same_port:
                try:
                    await old.start()
                except OSError as e2:
                    log.error("[%s] could not restore previous listener: %s", old.label, e2)
                    self.listeners.pop(path, None)
            return
        # No await between start() and here: no client can be served before on_load ran.
        if not run_on_load():
            listener.stop()
            if same_port:
                try:
                    await old.start()
                except OSError as e2:
                    log.error("[%s] could not restore previous listener: %s", old.label, e2)
                    self.listeners.pop(path, None)
            return
        if old is not None:
            if not same_port:
                old.stop()
            sys.modules.pop(old.rule.module_name, None)
            log.info("[%s] listener restarted: %s -> %s/%s on %s:%d", new.label,
                     old.rule.protocol, new.cls.__name__, new.protocol, new.host, new.port)
        else:
            log.info("[%s] listening: %s/%s on %s:%d", new.label, new.cls.__name__,
                     new.protocol, new.host, new.port)
        self.listeners[path] = listener


class Watcher:
    """Triggers Manager.scan() from inotify events and a periodic poll, whichever is first."""

    def __init__(self, manager: Manager, interval: float = 5.0, debounce: float = 0.3):
        self.manager = manager
        self.interval = interval
        self.debounce = debounce
        self.ino: Inotify | None = None
        self._timer: asyncio.TimerHandle | None = None
        self._tasks: set[asyncio.Task] = set()

    def _start_inotify(self) -> bool:
        loop = asyncio.get_running_loop()
        try:
            self.ino = Inotify(str(self.manager.rules_dir))
            loop.add_reader(self.ino.fd, self._on_inotify)
            return True
        except Exception as e:
            self.ino = None
            log.debug("inotify unavailable: %s", e)
            return False

    def _stop_inotify(self) -> None:
        if self.ino is not None:
            with_loop = asyncio.get_running_loop()
            with_loop.remove_reader(self.ino.fd)
            self.ino.close()
            self.ino = None

    def _on_inotify(self) -> None:
        events = self.ino.read_events()
        relevant = False
        for mask, name in events:
            if mask & GONE_MASK:
                log.warning("rules dir watch lost; polling only until it is back")
                self._stop_inotify()
                relevant = True
                break
            if mask & IN_Q_OVERFLOW or name.endswith(".py"):
                relevant = True
        if relevant:
            self._schedule()

    def _schedule(self) -> None:
        if self._timer is not None:
            self._timer.cancel()
        loop = asyncio.get_running_loop()
        self._timer = loop.call_later(self.debounce, self._fire)

    def _fire(self) -> None:
        self._timer = None
        task = asyncio.create_task(self.manager.scan("inotify"))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def run(self) -> None:
        if self._start_inotify():
            log.info("watching %s (inotify + poll every %gs)", self.manager.rules_dir, self.interval)
        else:
            log.warning("inotify unavailable; polling %s every %gs", self.manager.rules_dir,
                        self.interval)
        while True:
            await asyncio.sleep(self.interval)
            if self.ino is None and self.manager.rules_dir.is_dir() and self._start_inotify():
                log.info("inotify watch re-established")
            await self.manager.scan("poll")
