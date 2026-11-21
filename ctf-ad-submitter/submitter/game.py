"""Tick clock and teams.json handling."""
import asyncio
import json
import logging
import math
import os
import time
import urllib.request
from datetime import datetime

log = logging.getLogger("game")


def current_tick(cfg, now=None) -> int:
    """Tick number at `now` (negative before the game starts)."""
    now = time.time() if now is None else now
    return math.floor((now - cfg.tick_start.timestamp()) / cfg.TICK_LENGTH)


def tick_time(cfg, tick: int) -> float:
    """Unix time when exploits for `tick` should start (tick start + offset)."""
    return cfg.tick_start.timestamp() + tick * cfg.TICK_LENGTH + cfg.TICK_OFFSET


def archive(directory: str, raw: bytes, tick: int) -> None:
    """Saves one download as <dir>/teams-YYYYmmdd-HHMMSS-tick<N>.json."""
    try:
        os.makedirs(directory, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = os.path.join(directory, f"teams-{stamp}-tick{tick}.json")
        n = 2
        while os.path.exists(path):          # retried within the same second
            path = os.path.join(directory, f"teams-{stamp}-tick{tick}-{n}.json")
            n += 1
        with open(path, "wb") as f:
            f.write(raw)
    except OSError as e:
        log.warning("could not archive teams.json in %s: %s", directory, e)


def _fetch(url: str, timeout: float, archive_dir, tick: int) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "ctf-submitter"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()
    if archive_dir:
        archive(archive_dir, raw, tick)      # also keeps broken responses
    data = json.loads(raw)
    if not isinstance(data, dict) or not isinstance(data.get("teams"), list):
        raise ValueError("no 'teams' list in response")
    return data


async def fetch_teams(cfg, tick: int, give_up_at: float):
    """teams.json, retried FETCH_RETRIES times but never past `give_up_at`."""
    for attempt in range(1, cfg.FETCH_RETRIES + 1):
        try:
            return await asyncio.to_thread(_fetch, cfg.TEAMS_URL, cfg.FETCH_TIMEOUT,
                                           cfg.TEAMS_ARCHIVE, tick)
        except Exception as e:
            log.warning("teams.json fetch %d/%d failed: %s", attempt,
                        cfg.FETCH_RETRIES, str(e) or type(e).__name__)
        if attempt < cfg.FETCH_RETRIES:
            delay = min(5 * attempt, give_up_at - time.time())
            if delay <= 0:
                break
            await asyncio.sleep(delay)
    return None


def targets_for(cfg, teams: dict, service: str) -> list:
    """Build stdin payload targets for one service from the teams payload."""

    team_records = teams.get("teams") or []
    service_flags = (teams.get("flags") or {}).get(service) or {}

    out = []

    for team in team_records:
        if not isinstance(team, dict):
            continue

        try:
            team_id = int(team.get("id"))
        except (TypeError, ValueError):
            continue

        address = team.get("address")
        if not address:
            continue

        if team_id == cfg.TEAM_ID:
            continue

        if team_id == cfg.NOP_TEAM and not cfg.ATTACK_NOP:
            continue

        ticks = service_flags.get(address) or {}
        if not isinstance(ticks, dict):
            continue

        if cfg.LAST_TICKS:
            tick_keys = sorted(ticks, key=lambda value: int(value))[-cfg.LAST_TICKS:]
        else:
            tick_keys = sorted(ticks, key=lambda value: int(value))

        flag_ids: list[str] = []

        for tick in tick_keys:
            vulnerabilities = ticks.get(tick) or {}
            if not isinstance(vulnerabilities, dict):
                continue

            for ids in vulnerabilities.values():
                if isinstance(ids, list):
                    flag_ids.extend(str(flag_id) for flag_id in ids)
                elif ids is not None:
                    flag_ids.append(str(ids))

        out.append({
            "team": team_id,
            "ip": address,
            "flag_ids": flag_ids,
        })

    return out


def services_in(teams: dict) -> set:
    return set((teams.get("flag_ids") or {}).keys())
