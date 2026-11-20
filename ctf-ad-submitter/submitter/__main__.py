"""CTF A/D exploit runner + flag submitter.

    python -m submitter --config /etc/ctf-submitter/config.py

Every tick (start + TICK_OFFSET): fetch teams.json, start every configured
exploit with its service's targets as JSON on stdin, submit the flags it
prints. SIGHUP reloads the config (used from the next tick on).
"""
import argparse
import asyncio
import logging
import os
import signal
import sys
import time

from . import config as config_mod
from . import game
from .runner import run_exploit
from .submit import Submitter

log = logging.getLogger("main")


class App:
    def __init__(self, path: str):
        self.path = path
        self.cfg = config_mod.load(path)
        self.submitter = Submitter(lambda: self.cfg)
        self.running = {}        # exploit name -> task
        self.teams = None        # last good teams.json
        self.stop = asyncio.Event()

    # ---- config -----------------------------------------------------------
    def reload(self):
        try:
            new = config_mod.load(self.path)
        except Exception as e:
            log.error("config reload failed, keeping the old one: %s: %s",
                      type(e).__name__, e)
            return
        old = {e.name for e in self.cfg.exploits}
        cur = {e.name for e in new.exploits}
        self.cfg = new
        set_level(new.LOG_LEVEL)
        added, removed = sorted(cur - old), sorted(old - cur)
        log.info("config reloaded: %d exploits%s%s (applies from the next tick)",
                 len(new.exploits),
                 f", added {', '.join(added)}" if added else "",
                 f", removed {', '.join(removed)}" if removed else "")

    # ---- one tick ---------------------------------------------------------
    async def run_tick(self, tick: int):
        cfg = self.cfg                       # one config for the whole tick
        deadline = game.tick_time(cfg, tick + 1) - 1
        teams = await game.fetch_teams(cfg, tick, give_up_at=deadline)
        if teams is None:
            if self.teams is None:
                log.error("tick %d: no teams.json yet, skipping", tick)
                return
            log.warning("tick %d: using teams.json from an earlier tick", tick)
            teams = self.teams
        self.teams = teams

        if not cfg.exploits:
            log.info("tick %d: no exploits configured", tick)
            return
        known = game.services_in(teams)
        sem = asyncio.Semaphore(max(1, cfg.MAX_PARALLEL))
        started = 0
        for exploit in cfg.exploits:
            prev = self.running.get(exploit.name)
            if prev and not prev.done():
                log.warning("[%s] previous run still going, skipping tick %d",
                            exploit.name, tick)
                continue
            if known and exploit.service not in known:
                log.warning("[%s] service %r not in teams.json (has: %s)", exploit.name,
                            exploit.service, ", ".join(sorted(known)))
            payload = {"service": exploit.service, "tick": tick,
                       "targets": game.targets_for(cfg, teams, exploit.service)}
            self.running[exploit.name] = asyncio.create_task(
                self._run_one(sem, exploit, payload, cfg, tick))
            started += 1
        log.info("tick %d: started %d exploits against %d teams", tick, started,
                 len(game.targets_for(cfg, teams, "")))

    async def _run_one(self, sem, exploit, payload, cfg, tick):
        async with sem:
            try:
                await run_exploit(exploit, payload, cfg.flag_re, self.submitter.add, tick)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("[%s] runner crashed", exploit.name)
        dups = self.submitter.local_dups.pop(exploit.name, 0)
        if dups:
            log.info("[%s] %d flags skipped, already submitted", exploit.name, dups)

    # ---- main loop --------------------------------------------------------
    async def _tick_or_stop(self, tick):
        """run_tick (fetch + spawn), abandoned if a stop signal arrives first."""
        work = asyncio.create_task(self.run_tick(tick))
        stop = asyncio.create_task(self.stop.wait())
        await asyncio.wait({work, stop}, return_when=asyncio.FIRST_COMPLETED)
        for t in (work, stop):
            t.cancel()
        await asyncio.gather(work, stop, return_exceptions=True)

    async def main(self):
        loop = asyncio.get_running_loop()
        if sys.platform != "win32":
            loop.add_signal_handler(signal.SIGHUP, self.reload)
            loop.add_signal_handler(signal.SIGTERM, self.stop.set)
            loop.add_signal_handler(signal.SIGINT, self.stop.set)
        self.submitter.load_state()
        sub_task = asyncio.create_task(self.submitter.run())
        cfg = self.cfg
        log.info("team %s, %d exploits, tick 0 at %s, %ds ticks, submit to %s:%s",
                 cfg.TEAM_ID, len(cfg.exploits), cfg.tick_start.isoformat(timespec="seconds"),
                 cfg.TICK_LENGTH, cfg.SUBMIT_HOST, cfg.SUBMIT_PORT)

        # Started mid-tick: run right away, flags stay valid for several ticks.
        tick = game.current_tick(self.cfg)
        if tick < 0:
            tick = 0
        elif time.time() >= game.tick_time(self.cfg, tick):
            await self._tick_or_stop(tick)
            tick += 1
        while not self.stop.is_set():
            at = game.tick_time(self.cfg, tick)
            wait = at - time.time()
            if wait > 0:
                if wait > 60:
                    log.info("next run: tick %d in %.0fs", tick, wait)
                try:
                    await asyncio.wait_for(self.stop.wait(), wait)
                    break
                except asyncio.TimeoutError:
                    pass
            now_tick = game.current_tick(self.cfg)
            if now_tick > tick:              # slept through ticks (suspend, clock jump)
                log.warning("skipped ticks %d..%d", tick, now_tick - 1)
                tick = now_tick
            await self._tick_or_stop(tick)
            tick += 1

        log.info("stopping")
        for t in self.running.values():
            t.cancel()
        await asyncio.gather(*self.running.values(), return_exceptions=True)
        sub_task.cancel()
        self.submitter.save_state(force=True)


def set_level(level):
    logging.getLogger().setLevel(getattr(logging, str(level).upper(), logging.INFO))


def main():
    ap = argparse.ArgumentParser(prog="python -m submitter")
    ap.add_argument("--config", default=os.environ.get("SUBMITTER_CONFIG", "config.py"))
    args = ap.parse_args()

    # Under systemd the journal timestamps every line already.
    fmt = "%(levelname)-7s %(name)s: %(message)s"
    if not os.environ.get("JOURNAL_STREAM"):
        fmt = "%(asctime)s " + fmt
    logging.basicConfig(format=fmt, datefmt="%H:%M:%S", stream=sys.stdout)
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    try:
        app = App(args.config)
    except Exception as e:
        logging.getLogger("main").error("cannot load config %s: %s: %s", args.config,
                                        type(e).__name__, e)
        sys.exit(1)
    set_level(app.cfg.LOG_LEVEL)
    try:
        asyncio.run(app.main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
