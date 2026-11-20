# Submitter config. Plain Python, executed on start and on every reload:
#   systemctl reload ctf-submitter      (sends SIGHUP)
# A file that fails to load is rejected and the old config stays active.
# Changes apply from the next tick; running exploits are not touched.

from datetime import datetime

TICK_START = datetime(2026, 11, 28, 10, 0)    # start of tick 0, local time (set the real date)
TEAM_ID = 7                                   # own team, never attacked
TEAMS_URL = "http://10.0.0.1/api/teams.json"  # from the portal
SUBMIT_HOST = "10.0.0.1"                      # Team -> Connection on the portal
SUBMIT_PORT = 31337
TEAM_IP = "10.0.{team}.2"                     # vulnbox address of team N

# NOP_TEAM = 0          # organizers' unpatched box; its flags score nothing
# ATTACK_NOP = False

# FLAG_RE = r"FLAG\{[^}\s]+\}"
# TICK_LENGTH = 180
# TICK_OFFSET = 5       # seconds after tick start
# LAST_TICKS = None     # keep only the last N flag ids per team
# DEFAULT_TIMEOUT = 150 # per exploit run, keep it under TICK_LENGTH
# MAX_PARALLEL = 16     # exploit processes at once
# STATE_FILE = "state.json"
# TEAMS_ARCHIVE = "teams-archive"  # every teams.json download, timestamped (None = off)
# LOG_LEVEL = "INFO"    # DEBUG also logs exploits' non-flag stdout lines

EX = "/opt/ctf-ad-submitter/exploits"
PY = "/opt/ctf-ad-submitter/.venv/bin/python3"   # or "python3"

# One entry per exploit; a service can have several.
#   name     unique name for the logs (required)
#   service  key in teams.json flag_ids (required)
#   cmd      argument list, no shell (required)
#   timeout  seconds, defaults to DEFAULT_TIMEOUT
#   cwd, env (dict, added to the environment), enabled (default True)
EXPLOITS = [
    {"name": "flagstore-backdoor", "service": "flagstore",
     "cmd": [PY, f"{EX}/example_flagstore.py"]},
    # {"name": "flagstore-sqli", "service": "flagstore",
    #  "cmd": [PY, f"{EX}/flagstore_sqli.py", "--threads", "32"], "timeout": 60},
    # {"name": "notes-rce", "service": "notes", "cmd": [f"{EX}/notes_rce"],
    #  "cwd": EX, "enabled": False},
]
