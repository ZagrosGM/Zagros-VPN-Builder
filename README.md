# Zagros-VPN-Builder

Build workers for Zagros white-label applications. A worker takes one
platform job at a time from Redis/RQ, checks out the **pinned** client
source, runs the client repo's contract script, checksums and uploads the
release files, and reports back to the panel.

This repository is deliberately separate from the panel: the panel never
imports this code (it enqueues `zagros_builder.worker.run_build` **by
string**), and this code never imports the panel. The two sides meet only
through:

* the versioned RQ payload (`{"v": 2, build_public_id, platform, arch,
  job_token}` — v2 since Phase 14: the job document carries a pinned
  `sdk_source` next to `source`, and v1 documents are refused),
* the worker HTTP API (`/api/zagros/builder/...`, token authenticated),
* the Redis live-log streams (`zagros:build:log:{build}:{platform}:{arch}`).

## Lifecycle of one platform job

1. Panel creates the build row + per-platform job rows, mints one job
   token per platform, and enqueues one RQ job per platform on the pool
   queue (`builder:linux`, `builder:macos`, `builder:windows`).
2. `run_build` validates the payload, **claims** the job (job token +
   worker API token — both proofs required), and fetches the full job
   document (app + SDK source pins, canonical `build_config`, decrypted
   credentials attached to this build plus the worker's own credentials).
3. The worker creates an isolated workspace, clones the app source to
   `src/` and the pinned SDK source to the sibling `Zagros-VPN-SDK/`,
   checks out both pinned commits, and **verifies `HEAD == revision`**
   on each before doing anything else. The sibling directory name is a
   pinned convention both sides test: the client pubspecs resolve
   `zagros_vpn_sdk` via `../../../Zagros-VPN-SDK` (client unit test),
   and this worker clones exactly there (`SDK_CHECKOUT_DIRNAME`).
4. It runs the contract script `tool/white_label_build.py` from the
   checkout (`--config/--platform/--arch/--out`). Build output streams
   to Redis (live) and to a local transcript (durable), both redacted.
5. Output files are checksummed and uploaded to the panel; the final
   transcript is uploaded with the terminal status report.
6. The workspace is destroyed (local `rmtree` / remote `rm -rf`).

## Executor selection

* No SSH credential attached → **local** execution (native pools: macOS
  workers build iOS/macOS, Windows workers build Windows, etc.).
* An `ssh_password`/`ssh_key` credential with `{host, username, ...}`
  material attached → **remote** execution on that POSIX host over SSH.
* `ZAGROS_BUILD_EXECUTOR=local|ssh` forces one side; ambiguous setups
  (SSH-assigned job on a local-only worker and vice versa) fail loudly
  instead of building on the wrong machine.

SSH host trust fails closed: `host_key_pin` (`sha256:...` as printed by
`ssh-keygen -l -E sha256 -f <hostkey>`) or a `known_hosts` file is
required; the pinned key is verified **before** any credential is sent.
`accept_new_hostkeys` exists for tests only.

## Setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

# 1. panel admin creates the worker + issues a register token
#    POST /api/zagros/builder/workers
#    POST /api/zagros/builder/workers/{id}/register-token

# 2. enroll (API token lands in a 0600 file, never on screen)
python -m zagros_builder.cli enroll \
  --panel-url https://panel.example.com \
  --worker-id linux-pool-01 \
  --register-token '<from step 1>' \
  --token-file ~/.zagros/worker.token

# 3. listen
python -m zagros_builder.cli listen \
  --panel-url https://panel.example.com \
  --worker-id linux-pool-01 \
  --token-file ~/.zagros/worker.token \
  --redis-url redis://127.0.0.1:6379/0 \
  --labels linux
```

Environment knobs: `ZAGROS_PANEL_URL`, `ZAGROS_WORKER_ID`,
`ZAGROS_WORKER_API_TOKEN` / `ZAGROS_WORKER_TOKEN_FILE`,
`ZAGROS_REDIS_URL`, `ZAGROS_BUILD_WORKSPACE`,
`ZAGROS_REMOTE_WORKSPACE_BASE`, `ZAGROS_BUILD_EXECUTOR`,
`ZAGROS_BUILD_TIMEOUT` (default 18000s), `ZAGROS_CLONE_TIMEOUT` (900s).

## Client-repo contract (v1)

The checked-out source must provide an executable-by-python3
`tool/white_label_build.py` accepting `--config <build_config.json>
--platform <slug> --arch <slug> --out <dir>` and writing finished
release files directly into `--out` (top level only). Exit 0 with no
outputs is reported as `no_artifacts`, not success.

> Status (Phase 13, 2026-09-08): the Zagros-VPN client repo now
> implements this script (`tool/white_label_build.py`: strict config
> validation, branding via `--dart-define`, per-platform staging,
> `white-label-build-receipt.json`). Proven with a real linux/x64
> `flutter build` whose AOT library contains the config branding, plus
> 20 unit tests and an opt-in live test
> (`ZAGROS_LIVE_BUILD=1 pytest tool/tests/`). Workers still need
> provisioned toolchains per platform (Flutter SDK + Android SDK/NDK,
> Xcode, or Linux/Windows build deps) and ≥4 GB RAM for cold AOT
> compiles. Fixture-contract tests remain in `tests/`.

## Security properties and honest limitations

* Single-job tokens: short-lived, single-platform, invalidated the
  moment the job turns terminal or is cancelled; a cancelled job's
  further callbacks 401, which is also what stops a running worker.
* Build secrets are never RQ payloads, never logs (rejected in
  `build_config` up front; redacted best-effort in free text on both
  sides), and decrypted only inside the worker that needs them.
* Redis must be private/authenticated: job tokens transit through it.
  The panel API must be TLS: decrypted credentials travel to workers.
* RQ cannot kill work already executing: cancelling a *running* job
  relies on token invalidation (the worker aborts at its next callback).
* If the panel is unreachable mid-build, the worker raises loudly (RQ
  failed registry) but the SQL row may stay `running` until an operator
  cancels it — there is no silent redispatch yet.
* Worker uploads hold one artifact in RAM (1 GiB cap); the panel side
  streams to disk.
