"""Shared fixtures: real git fixture repos implementing the v1 contract."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

CONTRACT_SCRIPT = """#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--config")
parser.add_argument("--platform")
parser.add_argument("--arch")
parser.add_argument("--artifact", default="apk")
parser.add_argument("--out")
ns = parser.parse_args()
if ns.artifact != "apk":
    print(f"contract artifact={ns.artifact}", flush=True)
config = json.loads(Path(ns.config).read_text(encoding="utf-8"))
out = Path(ns.out)
out.mkdir(parents=True, exist_ok=True)
print(f"building {ns.platform}/{ns.arch}", flush=True)
sdk = Path(__file__).resolve().parents[2] / "Zagros-VPN-SDK"
marker = sdk / "sdk-marker.txt"
if not marker.is_file():
    print(f"sdk sibling missing: {sdk}", file=sys.stderr, flush=True)
    raise SystemExit(4)
print(f"sdk sibling ok: {marker.read_text(encoding='utf-8').strip()}",
      flush=True)
print("token=ghp_FIXTURESECRET0123456789abcdef (must be redacted)", flush=True)
mode = config.get("mode", "success")
if mode == "fail":
    print("boom happened", file=sys.stderr, flush=True)
    raise SystemExit(3)
if mode == "quiet":
    raise SystemExit(0)
for name, content in (config.get("files")
                      or {"app.apk": "fixture-bytes"}).items():
    (out / name).write_text(content, encoding="utf-8")
print("outputs written", flush=True)
"""


def make_repo(base: Path, *, script: str | None = CONTRACT_SCRIPT,
              extra_files: dict[str, str] | None = None) -> tuple[Path, str]:
    """Init a real git repo with the contract script; returns (dir, sha)."""
    repo = base / "fixture-repo"
    (repo / "tool").mkdir(parents=True)
    if script is not None:
        (repo / "tool" / "white_label_build.py").write_text(
            script, encoding="utf-8")
    (repo / "README.md").write_text("fixture\n", encoding="utf-8")
    for name, content in (extra_files or {}).items():
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "fixture",
        "GIT_AUTHOR_EMAIL": "fixture@test",
        "GIT_COMMITTER_NAME": "fixture",
        "GIT_COMMITTER_EMAIL": "fixture@test",
        "GIT_INIT_DEFAULT_BRANCH": "main",
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    subprocess.run(["git", "init"], cwd=repo, env=env, check=True,
                   capture_output=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, env=env, check=True,
                   capture_output=True)
    subprocess.run(["git", "commit", "-m", "fixture"], cwd=repo, env=env,
                   check=True, capture_output=True)
    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, env=env, check=True,
        capture_output=True, text=True).stdout.strip()
    return repo, sha


def config_digest(config: dict) -> str:
    canonical = json.dumps(config, ensure_ascii=False, sort_keys=True,
                           separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


requires_git = pytest.mark.skipif(
    shutil.which("git") is None, reason="git is not installed")

# The worker's 0.2.0 pre-build resource guard is env-gated product behavior.
# These tests exercise build mechanics on small CI hosts, so the guard runs in
# its explicit off mode here (the worker logs "snapshot only"); the guard's
# own decisions get dedicated coverage in tests/test_guard.py.
os.environ.setdefault("ZAGROS_GUARD_DISABLE", "1")
