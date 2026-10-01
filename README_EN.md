# tokshelf

[中文](README.md) | [English](README_EN.md)

**Credential Lifespan Sentinel** — tokens buried in git remotes never warn you before they expire. They wait until the night of a release, then return 401.

cronguard watches cron jobs ([cronguard](https://github.com/tomlen045/cronguard)), capguard watches disk ([capguard](https://github.com/tomlen045/capguard)), bakcheck watches backups ([bakcheck](https://github.com/tomlen045/bakcheck)) — **tokshelf watches your credentials**.

Four commands: scan them out / probe them / lease them / report them.

[![tests](https://img.shields.io/badge/self--tests-26%2F26-green)]() [![deps](https://img.shields.io/badge/deps-zero-yellow)]() [![license](https://img.shields.io/badge/license-MIT-blue)]()

---

## The problem it solves

* A token in a remote dies silently; you find out mid-release → **probe** verifies liveness with one minimal read-only GET per credential (Gitee / GitHub): 200 = alive, 401/403 = dead
* Tokens scattered across .git/config, .env, .netrc — nobody can count them → **scan** inventories by shape: Gitee-32hex / GitHub-ghp_ / OpenAI-sk- / generic hex32
* "Is the old token still good?" — no evidence, only vibes → **fingerprint ledger**: output is always first4…last4 (`ghp_x…9f2`), safe to screenshot
* A network hiccup gets misread as "token dead", wasted rotation → **unknown is a separate class**: timeouts never count as dead
* "When does this token expire?" — memory only → **lease**: register expiry dates, get warned N days ahead
* Reports say what's dead but not what to do → **report** outputs recommended actions: rotation order, renewal scheduling, re-probe list

## Install

```bash
# Single file, stdlib only, Python 3.8+
curl -fsSLO https://raw.githubusercontent.com/tomlen045/tokshelf/main/tokshelf.py
```

## Quick start (30 seconds)

```bash
# 1) Inventory: how many credentials are buried here, and of what shape
python3 tokshelf.py scan ~/projects

# 2) Probe: which are alive, which died long ago (read-only GETs, small concurrency)
python3 tokshelf.py probe ~/projects

# 3) Register lifespan: record an expiry date per token
python3 tokshelf.py lease add --label gitee-main --expires 2026-12-01

# 4) Report: alive/dead/unknown + recommended actions (cron-friendly; exit 1 on dead)
python3 tokshelf.py report ~/projects --json
```

## Verdict rules

| Status | Trigger | Meaning |
|---|---|---|
| alive | probe HTTP 200 | credential currently works |
| dead | probe HTTP 401/403 | rejected server-side; rotate now |
| unknown | timeout / network error / 5xx | **network failure ≠ bad credential**; fix connectivity and re-probe |
| unprobed | no equivalent read-only probe | honestly labeled; never force-probed |
| EXPIRING | within N days of lease expiry (default 14) | schedule renewal |
| EXPIRED | past lease expiry | close it if rotated; replace if still in use |

## Four invariants

1. **Read-only probing** — probe issues GETs only; never a write with your credentials
2. **Redacted output** — fingerprints only (first4…last4), never plaintext; audit JSONL likewise
3. **Network failure ≠ bad credential** — unknown is its own class
4. **Audit never stores plaintext** — logs/JSONL record fingerprints, counts, shapes only

## Design boundaries

* probe covers Gitee / GitHub only (they have a minimal read-only GET); OpenAI keys and netrc passwords are labeled unprobed — **never force-probed**, since verifying a credential with a write request is an incident by itself
* lease is *your* ledger: the tool warns, humans renew
* scan works by file shape (`.git/config`, `.env`, `.netrc`), not full-content entropy scanning
* skew-friendly: credentials are rare among files; scan never extrapolates statistically — use `--baseline` for a manual fallback list

## Self-test

```bash
python3 tokshelf.py selftest   # 26/26 green (mock triple-state, skewed e2e, redaction asserts)
```

## LICENSE

MIT
