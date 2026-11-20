# ctf-ad-submitter

Exploit runner and flag submitter for the A/D game, run as a systemd service.

Every tick (tick start + a few seconds) it:

1. fetches `teams.json` (FAUST format),
2. starts every configured exploit as its own subprocess, with that
   service's targets as JSON on **stdin**,
3. pulls flag-shaped strings (`FLAG_RE`) out of the exploit's **stdout** while
   it runs and submits them over the line-based TCP protocol,
4. logs the exploit's **stderr** to the journal, prefixed with its name.

Stdlib only, Python 3.9+. Exploits can be in any language; the helper library
is Python.

## Install

```sh
sudo cp -r ctf-ad-submitter /opt/
cd /opt/ctf-ad-submitter
sudo cp config.example.py config.py      # edit: TEAM_ID, TEAMS_URL, SUBMIT_HOST, TEAM_IP, EXPLOITS
sudo cp ctf-submitter.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ctf-submitter
journalctl -u ctf-submitter -f
```

Without systemd (e.g. WSL), use the SysV init script. It runs
`/opt/ctf-ad-submitter` (change `DIR` at the top or in
`/etc/default/ctf-submitter`) and logs to `/tmp/ctf-submitter.log`:

```sh
sudo cp ctf-submitter.sh /etc/init.d/ctf-submitter && sudo chmod +x /etc/init.d/ctf-submitter
sudo service ctf-submitter start     # stop | restart | reload | status | logs [lines]
```

Optional virtualenv for exploit dependencies (pwntools, requests, ...):
`python3 -m venv .venv && .venv/bin/pip install requests`, then use
`.venv/bin/python3` in the exploit `cmd`.

The machine must have the game VPN up: the submission server identifies the
team by source IP (`INVALID_SENDER` otherwise).

Run in the foreground for testing: `python3 -m submitter --config config.py`.

## Config

`config.py` is plain Python. See [config.example.py](config.example.py) for
every setting. Exploits are a list of dicts; one service can have several:

```python
EXPLOITS = [
    {"name": "flagstore-backdoor", "service": "flagstore",
     "cmd": [PY, f"{EX}/example_flagstore.py"]},
    {"name": "flagstore-sqli", "service": "flagstore",
     "cmd": [PY, f"{EX}/flagstore_sqli.py", "--threads", "32"], "timeout": 60},
    {"name": "notes-rce", "service": "notes", "cmd": [f"{EX}/notes_rce"],
     "cwd": EX, "env": {"X": "1"}, "enabled": False},
]
```

| key | |
|---|---|
| `name` | unique name, used in the logs (required) |
| `service` | key in `teams.json` `flag_ids` (required) |
| `cmd` | argument list, run without a shell (required) |
| `timeout` | seconds, default `DEFAULT_TIMEOUT` (150) |
| `cwd`, `env` | working directory, extra environment variables |
| `enabled` | `False` skips it |

**Reload:** `sudo systemctl reload ctf-submitter` (SIGHUP). The new file is
used from the next tick on. If it fails to load, the error is logged and the
old config stays.

**Ticks** are computed from `TICK_START` and `TICK_LENGTH` (180 s), so keep
the clock NTP-synced. `TICK_START` is required and must be a full date and
time, so tick numbers keep counting across days:
`datetime(2026, 11, 28, 10, 0)` (naive = local time) or an ISO string like
`"2026-11-28T10:00+01:00"`. Before it, the service waits; started in the
middle of a tick, it runs the exploits right away.

**teams.json archive:** every download is saved as-is to `TEAMS_ARCHIVE`
(default `teams-archive/`) as `teams-YYYYmmdd-HHMMSS-tick<N>.json`, including
responses that failed to parse. `TEAMS_ARCHIVE = None` turns it off.

## Exploit input

```json
{"service": "flagstore", "tick": 42,
 "targets": [{"team": 1, "ip": "10.0.1.2", "flag_ids": ["alice", "bob"]},
             {"team": 3, "ip": "10.0.3.2", "flag_ids": []}]}
```

- Your own team (`TEAM_ID`) is never included; NOP (`NOP_TEAM`) only with
  `ATTACK_NOP = True`.
- `flag_ids` is the team's list for that service from `teams.json`, as given
  (entries may be strings or objects). `LAST_TICKS = N` keeps only the last N.
- Every team in `teams.json` is listed, with `[]` when it has no flag ids.

## Exploit output

- **stdout:** anything; every `FLAG_RE` match is submitted, the rest is logged
  at `DEBUG`.
- **stderr:** logged at `INFO` as `[exploit name] line`.
- Exit code and run time are logged. After `timeout` the process group gets
  SIGTERM, then SIGKILL 2 s later. Flags printed before that still count.
- If an exploit's previous run is still going at the next tick, that tick is
  skipped for it.

## Submission

- One connection, flags pipelined in batches, one answer line per flag.
- `OK`, `DUPLICATE`, `OWN`, `OLD`, `INVALID` are final.
- `ERROR`, `GAME_NOT_OPEN`, `INVALID_SENDER`, `SPAM` and unrecognized answers are
  retried with backoff (5 s doubling to 60 s) until the flag expires
  (`FLAG_LIFETIME_TICKS` + 1 tick).
- Flags already submitted are skipped. The list (and pending flags) is kept in
  `STATE_FILE`, so a restart doesn't resend.
- Each batch is logged per exploit, e.g. `[flagstore-backdoor] submitted: 12 OK, 2 DUPLICATE`.

## Python helper: `exploits/exploitlib.py`

```python
import exploitlib as x

async def attack(t):              # once per team, as asyncio tasks
    t.log.info("%d flag ids", len(t.flag_ids))      # stderr, prefixed with the team
    r = await x.ahttp("POST", f"http://{t.ip}:{t.port or 8080}/api", data={"q": "..."})
    x.flag(r.text)                # optional: hand over flags right away
    return r.text                 # flags are also extracted from the return value

if __name__ == "__main__":
    x.run(attack, threads=16, timeout=20, deadline=120)
```

- `attack` can be `async def` (one event loop, up to `threads` teams at once)
  or a plain `def` (a thread per team, up to `threads`).
- `Target`: `team`, `ip`, `flag_ids`, `service`, `tick`, `port` (from `--port`, else
  `None`), `log`.
- `run()` reads stdin, calls `attack` per team, logs each team's exception
  without stopping the others, prints each flag once, and logs a summary.
  - `timeout`: per team, async only (the task is cancelled). Threads can't be
    killed, so sync attacks should use their own socket timeouts.
  - `deadline`: the whole run; teams still going then are reported and abandoned.
- stdout and stderr are line-synchronized: `print()` and logging from many
  threads never mix within a line.
- `flag(*values)`, `flags_in(value)`: extract flags from str/bytes/lists/dicts.
- `http(method, url, data=, json_body=, headers=, timeout=)`: minimal urllib
  wrapper returning `.status`, `.text`, `.headers`, no exception on 4xx/5xx.
  `await ahttp(...)` is the same in a worker thread, for async attacks. Use
  httpx/aiohttp from a venv if one team needs many concurrent requests.

Manual testing without the submitter:

```sh
python3 exploits/example_flagstore.py --target 10.0.0.2 -v              # NOP box
python3 exploits/example_flagstore.py --target 127.0.0.1 --port 31337 --flag-id alice
python3 exploits/example_flagstore.py --input targets.json --threads 4
```

Options: `--target HOST` (repeatable), `--team N`, `--port P`, `--flag-id ID`
(repeatable, JSON values parsed), `--input FILE`, `--threads N`,
`--timeout S`, `--deadline S`, `-v`.
