"""Entry point: python -m balancer --rules /rules"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
from pathlib import Path

from . import listeners
from .listeners import SILENT_DROP
from .rules import Manager, Watcher
from .shared import shared

log = logging.getLogger("lb")


def _quiet_loop_errors(loop, context) -> None:
    # TLS handshake failures, resets during accept etc. are normal noise in a CTF.
    exc = context.get("exception")
    if isinstance(exc, (ConnectionError, OSError, TimeoutError)) or "SSL" in context.get("message", ""):
        log.debug("loop: %s", context.get("message"))
        return
    loop.default_exception_handler(context)


async def main(args) -> None:
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(_quiet_loop_errors)
    main_task = asyncio.current_task()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, main_task.cancel)
        except (NotImplementedError, RuntimeError):
            pass  # Windows

    rules_dir = Path(args.rules).resolve()
    # Let rule files import shared helpers (e.g. rules/_common.py).
    sys.path.insert(0, str(rules_dir))

    if SILENT_DROP:
        log.info("drop mode: silent (TCP_REPAIR) - dropped sockets are released without FIN/RST")
    else:
        log.info("drop mode: manual hold - dropped sockets are held until DROP_TIMEOUT "
                 "(optional: cap_add NET_ADMIN enables silent release)")

    sweeper = asyncio.create_task(shared.sweeper(args.sweep))  # noqa: F841 (kept alive)
    listeners.TCP_TIMEOUT = args.tcp_timeout
    log.info("tcp idle timeout: %s", f"{args.tcp_timeout:g}s" if args.tcp_timeout > 0 else "off")

    manager = Manager(rules_dir)
    await manager.scan("startup")
    if not manager.listeners:
        log.warning("no rules loaded from %s yet", rules_dir)
    try:
        await Watcher(manager, interval=args.poll).run()
    except asyncio.CancelledError:
        log.info("shutting down")


def cli() -> None:
    p = argparse.ArgumentParser(prog="balancer")
    p.add_argument("--rules", default=os.environ.get("LB_RULES", "/rules"),
                   help="directory with rule .py files (env LB_RULES)")
    p.add_argument("--poll", type=float, default=float(os.environ.get("LB_POLL", "5")),
                   help="poll interval in seconds, in addition to inotify (env LB_POLL)")
    p.add_argument("--sweep", type=float, default=float(os.environ.get("LB_SWEEP", "5")),
                   help="seconds between sweeps of expired shared entries (env LB_SWEEP)")
    p.add_argument("--tcp-timeout", type=float,
                   default=float(os.environ.get("LB_TCP_TIMEOUT", "180")),
                   help="idle timeout in seconds for TCP pipes, 0 = none (env LB_TCP_TIMEOUT)")
    p.add_argument("--log-level", default=os.environ.get("LB_LOG_LEVEL", "INFO"))
    args = p.parse_args()

    logging.basicConfig(level=args.log_level.upper(),
                        format="%(asctime)s %(levelname)-5s %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S", stream=sys.stdout)
    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    cli()
