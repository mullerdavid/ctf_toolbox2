# example-service

Tiny A/D-style target for testing the load balancer: store a flag under a
password, read it back with that password. Python stdlib only, port 31337.

| Endpoint | Params (POST, form or JSON) | Response |
|---|---|---|
| `POST /flag/set` | `flag`, `password` | `200 ok` |
| `POST /flag/get` | `password` | `200` + flag, `403` unknown password |
| anything else | | `404` |

The password works like an id: one flag per password, kept for 3 minutes
(`FLAG_TTL`, seconds); setting the same password again replaces the flag.

**The vulnerability:** unless `PATCHED=1`, the hardcoded password
`backdoor85359714` lists every stored flag.

| Env | Default | |
|---|---|---|
| `PATCHED` | `0` | `1` removes the backdoor |
| `FLAG_TTL` | `180` | flag lifetime in seconds |
| `PORT` | `31337` | listen port |

## Run

```bash
docker compose up -d --build
```

## curl examples

Store a flag:

```bash
curl -s -X POST localhost:31337/flag/set -d 'flag=FLAG{test123}' -d password=s3cret
```

Same as JSON:

```bash
curl -s -X POST localhost:31337/flag/set -H 'Content-Type: application/json' -d '{"flag": "FLAG{test123}", "password": "s3cret"}'
```

Read it back (`200 FLAG{test123}`):

```bash
curl -s -X POST localhost:31337/flag/get -d password=s3cret
```

Unknown password (`403`):

```bash
curl -si -X POST localhost:31337/flag/get -d password=nope
```

Backdoor: lists all flags on the unpatched build, `403` with `PATCHED=1`:

```bash
curl -s -X POST localhost:31337/flag/get -d password=backdoor85359714
```

Anything else is `404`:

```bash
curl -si localhost:31337/
```

## Fake game server

[teams_server.py](teams_server.py) stands in for the game infrastructure when
testing the submitter:

- `http://localhost:8000/teams.json`: generated FAUST-style teams.json (teams
  1–8, service `flagstore`, empty flag ids). Change `TEAMS` / `SERVICE` at the
  top of the file.
- `tcp 8001`: flag submission, one flag per line, answers `OK` to everything
  and prints each flag.

```bash
python3 teams_server.py          # or: python3 teams_server.py <http_port> <submit_port>
```
