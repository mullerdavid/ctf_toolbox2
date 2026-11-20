"""Runs one exploit as a subprocess and streams its output.

stdin  <- JSON payload, then closed
stdout -> scanned line by line for flags; the rest is logged at DEBUG
stderr -> logged at INFO, prefixed with the exploit name
"""
import asyncio
import json
import logging
import os
import signal
import sys
import time

log = logging.getLogger("run")
MAX_LINE = 1000          # longer log lines are cut
CHUNK = 64 * 1024


async def _lines(stream):
    """Yields decoded lines; a trailing line without newline is yielded at EOF."""
    buf = b""
    while True:
        chunk = await stream.read(CHUNK)
        if not chunk:
            break
        buf += chunk
        *lines, buf = buf.split(b"\n")
        for line in lines:
            yield line.decode("utf-8", "replace").rstrip("\r")
        if len(buf) > 1 << 20:               # a megabyte with no newline
            yield buf.decode("utf-8", "replace")
            buf = b""
    if buf:
        yield buf.decode("utf-8", "replace").rstrip("\r")


def _cut(s: str) -> str:
    return s if len(s) <= MAX_LINE else s[:MAX_LINE] + f"... (+{len(s) - MAX_LINE})"


def _kill(proc, sig):
    try:
        if sys.platform == "win32":
            proc.kill()
        else:
            os.killpg(proc.pid, sig)          # the exploit and anything it started
    except (ProcessLookupError, PermissionError):
        pass


async def run_exploit(exploit, payload: dict, flag_re, on_flag, tick: int) -> dict:
    """Runs `exploit` once. `on_flag(flag, exploit_name)` is called for every flag
    found on stdout (duplicates within the run are skipped). Returns run stats."""
    name = exploit.name
    started = time.monotonic()
    env = {**os.environ, **exploit.env}
    stats = {"flags": 0, "rc": None, "timeout": False}
    try:
        proc = await asyncio.create_subprocess_exec(
            *exploit.cmd, cwd=exploit.cwd, env=env,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=(sys.platform != "win32"))
    except OSError as e:
        log.error("[%s] could not start %s: %s", name, exploit.cmd, e)
        stats["rc"] = "spawn-failed"
        return stats

    seen = set()

    async def feed():
        try:
            proc.stdin.write(json.dumps(payload).encode() + b"\n")
            await proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass                                # exploit doesn't read stdin
        finally:
            try:
                proc.stdin.close()
            except Exception:
                pass

    async def read_stdout():
        async for line in _lines(proc.stdout):
            found = flag_re.findall(line)
            for flag in found:
                if flag not in seen:
                    seen.add(flag)
                    stats["flags"] += 1
                    on_flag(flag, name)
            if not found and line.strip():
                log.debug("[%s] stdout: %s", name, _cut(line))

    async def read_stderr():
        async for line in _lines(proc.stderr):
            if line.strip():
                log.info("[%s] %s", name, _cut(line))

    io = asyncio.gather(feed(), read_stdout(), read_stderr())
    try:
        await asyncio.wait_for(asyncio.shield(io), exploit.timeout)
        stats["rc"] = await proc.wait()
    except asyncio.TimeoutError:
        stats["timeout"] = True
        _kill(proc, signal.SIGTERM)
        try:
            await asyncio.wait_for(proc.wait(), 2)
        except asyncio.TimeoutError:
            _kill(proc, signal.SIGKILL)
        stats["rc"] = await proc.wait()
        # A child that kept the pipes open would keep the readers alive.
        try:
            await asyncio.wait_for(io, 2)
        except asyncio.TimeoutError:
            io.cancel()
    except asyncio.CancelledError:
        _kill(proc, signal.SIGKILL)
        io.cancel()
        raise

    took = time.monotonic() - started
    end = f"killed after {exploit.timeout:g}s timeout" if stats["timeout"] else f"exit {stats['rc']}"
    log.info("[%s] tick %d: %s in %.1fs, %d flags", name, tick, end, took, stats["flags"])
    return stats
