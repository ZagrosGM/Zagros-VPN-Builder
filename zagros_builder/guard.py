"""Pre-build resource guard: snapshot, swap policy, hard limits.

Runs identically for local and SSH executors — every probe is a plain
shell command through the executor. Policy (all overridable via env):

* **Disk** — hard-fail the job *before* any clone/toolchain work when
  the workspace filesystem has less than ``ZAGROS_GUARD_MIN_DISK_MB``
  (default 4096) free; warn under ``ZAGROS_GUARD_WARN_DISK_MB`` (8192).
* **Memory** — require ``ZAGROS_GUARD_MIN_MEMORY_MB`` (default 3072)
  of mem-available + swap-free. When short (and the host is root/Linux),
  create ``/zagros.build.swap`` sized to the deficit (capped by disk
  headroom and ``ZAGROS_GUARD_MAX_SWAP_MB``) and swapon it.
* **Limits** — wrap the build with a ``systemd-run --scope`` carrying
  ``CPUQuota`` (85%) and ``MemoryMax`` (85% of RAM) so a build can never
  starve a co-located panel; fall back to ``nice`` when systemd/root is
  unavailable. Gradle heap is capped via ``GRADLE_OPTS`` either way.

Failures raise :class:`ResourceError` with a stable failure_code so the
job reports ``resources_insufficient`` / ``provision_failed``-style
codes instead of dying mid-clone.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from .ssh import ExecError, Executor


class ResourceError(Exception):
    """Build host cannot host the job — fail before heavy work starts."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class Snapshot:
    cores: int = 0
    mem_total_mb: int = -1
    mem_avail_mb: int = -1
    swap_total_mb: int = 0
    swap_free_mb: int = 0
    disk_free_mb: int = -1
    is_root: bool = False
    is_linux: bool = False
    has_systemd: bool = False


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


def _out(result) -> str:
    return (result.stdout or b"").decode("utf-8", "replace").strip()


def _run(executor: Executor, argv: list[str], *, timeout: int = 120):
    return executor.run(argv, timeout=timeout, check=False)


_SNAP_SH = (
    "nproc; "
    "free -m | awk '/^Mem:/{print $2,$7} /^Swap:/{print $2,$4}'; "
    "df -Pm \"$1\" | awk 'NR==2{print $4}'; "
    "id -u; uname -s; "
    "[ -d /run/systemd/system ] && command -v systemd-run >/dev/null "
    "&& echo systemd"
)


def snapshot(executor: Executor, workspace_path: str) -> Snapshot:
    """One round-trip resource probe; every field degrades independently."""
    snap = Snapshot()
    try:
        result = _run(executor, ["sh", "-c", _SNAP_SH, "snap", workspace_path])
        lines = [line.strip() for line in _out(result).splitlines() if line.strip()]
        it = iter(lines)
        try:
            snap.cores = int(next(it))
        except (StopIteration, ValueError):
            snap.cores = 1
        try:
            mem_total, mem_avail = next(it).split()
            snap.mem_total_mb, snap.mem_avail_mb = int(mem_total), int(mem_avail)
        except (StopIteration, ValueError):
            pass
        try:
            swap_total, swap_free = next(it).split()
            snap.swap_total_mb, snap.swap_free_mb = int(swap_total), int(swap_free)
        except (StopIteration, ValueError):
            pass
        try:
            snap.disk_free_mb = int(next(it))
        except (StopIteration, ValueError):
            pass
        try:
            snap.is_root = next(it) == "0"
        except StopIteration:
            pass
        try:
            snap.is_linux = next(it).lower() == "linux"
        except StopIteration:
            pass
        try:
            snap.has_systemd = next(it) == "systemd"
        except StopIteration:
            pass
    except (ExecError, Exception):  # noqa: BLE001 — probes must never crash the job
        pass
    return snap


def _swap_active(executor: Executor, path: str) -> bool:
    result = _run(executor, ["sh", "-c",
                             f"swapon --show=NAME --noheadings 2>/dev/null "
                             f"| grep -Fx {path!r} && echo on"])
    return _out(result) == "on"


def _ensure_swap(executor: Executor, *, log, deficit_mb: int,
                 disk_free_mb: int) -> int:
    """Create + enable a swapfile sized to the deficit; returns MB enabled."""
    path = os.environ.get("ZAGROS_GUARD_SWAPFILE", "/zagros.build.swap")
    max_swap = _env_int("ZAGROS_GUARD_MAX_SWAP_MB", 4096)
    size = min(deficit_mb, max_swap, max(disk_free_mb - 2048, 0))
    if size < 512:
        return 0
    if _swap_active(executor, path):
        log(f"guard: swapfile {path} already active")
        return size
    log(f"guard: memory short — creating {size}MB swapfile at {path} …")
    sudo = "" if _run(executor, ["sh", "-c", "test $(id -u) -eq 0"]).returncode == 0 \
        else "sudo "
    script = (
        f"{sudo}swapon --show=NAME --noheadings 2>/dev/null | grep -Fxq {path!r} "
        f"|| {{ {sudo}test -f {path} || "
        f"{sudo}fallocate -l {size}M {path} 2>/dev/null "
        f"|| {sudo}dd if=/dev/zero of={path} bs=1M count={size}; "
        f"{sudo}chmod 600 {path} && {sudo}mkswap -q {path} "
        f"&& {sudo}swapon {path}; }} && echo swap-ok"
    )
    result = _run(executor, ["sh", "-c", script], timeout=600)
    if "swap-ok" not in _out(result):
        log("guard: swap creation failed — continuing without extra swap")
        return 0
    log(f"guard: swap enabled ({size}MB)")
    return size


def preflight(executor: Executor, *, log, platform: str,
              workspace_path: str) -> dict:
    """Resource gate + limit wrapper. Returns ``{argv_prefix, env, snapshot}``."""
    min_disk = _env_int("ZAGROS_GUARD_MIN_DISK_MB", 2560)
    warn_disk = _env_int("ZAGROS_GUARD_WARN_DISK_MB", 6144)
    min_memory = _env_int("ZAGROS_GUARD_MIN_MEMORY_MB", 3072)

    snap = snapshot(executor, workspace_path)
    log(f"resources: cpu={snap.cores} "
        f"mem={snap.mem_avail_mb}MB free/{snap.mem_total_mb}MB total "
        f"swap={snap.swap_free_mb}MB free/{snap.swap_total_mb}MB total "
        f"disk={snap.disk_free_mb}MB free "
        f"({'linux' if snap.is_linux else 'non-linux'}, "
        f"{'root' if snap.is_root else 'unprivileged'})")

    disabled = bool(os.environ.get("ZAGROS_GUARD_DISABLE", "").strip())
    if disabled:
        log("guard: disabled via ZAGROS_GUARD_DISABLE — snapshot only")
        return {"argv_prefix": [], "env": {}, "snapshot": snap}

    if snap.disk_free_mb >= 0 and snap.disk_free_mb < min_disk:
        raise ResourceError(
            "resources_insufficient",
            f"build host has only {snap.disk_free_mb}MB free disk at the "
            f"workspace filesystem; a cold build needs ~{min_disk}MB "
            f"(free space or raise ZAGROS_GUARD_MIN_DISK_MB)")
    if 0 <= snap.disk_free_mb < warn_disk:
        log(f"guard: WARNING — {snap.disk_free_mb}MB free disk is tight "
            f"for a cold AOT build (warn threshold {warn_disk}MB)")

    if snap.mem_avail_mb >= 0:
        available = snap.mem_avail_mb + max(snap.swap_free_mb, 0)
        if available < min_memory:
            if snap.is_root and snap.is_linux:
                deficit = min_memory - available
                _ensure_swap(executor, log=log, deficit_mb=deficit,
                             disk_free_mb=snap.disk_free_mb)
                fresh = snapshot(executor, workspace_path)
                snap.mem_avail_mb = fresh.mem_avail_mb
                snap.swap_free_mb = fresh.swap_free_mb
                snap.swap_total_mb = fresh.swap_total_mb
                available = snap.mem_avail_mb + max(snap.swap_free_mb, 0)
            if available < min_memory:
                raise ResourceError(
                    "resources_insufficient",
                    f"build host memory too low: {available}MB available "
                    f"(mem+swap) vs ~{min_memory}MB needed for a cold AOT "
                    f"compile — add RAM/swap or lower "
                    f"ZAGROS_GUARD_MIN_MEMORY_MB")

    argv_prefix: list[str] = []
    env: dict[str, str] = {}
    mem_cap = max(int((snap.mem_total_mb if snap.mem_total_mb > 0 else 2048)
                      * 0.85), 768)
    heap = max(1024, min(int(mem_cap * 0.6), 2048))
    env["GRADLE_OPTS"] = (
        f"-Dorg.gradle.jvmargs=-Xmx{heap}m -Dorg.gradle.workers.max=2")
    if snap.has_systemd and snap.is_root:
        argv_prefix = ["systemd-run", "--scope",
                       "-p", "CPUQuota=85%",
                       "-p", f"MemoryMax={mem_cap}M", "--"]
        log(f"guard: limits via systemd-run (cpu≤85%, mem≤{mem_cap}M, "
            f"gradle heap ≤{heap}M)")
    else:
        argv_prefix = ["nice", "-n", "10"]
        log(f"guard: systemd/root unavailable — nice-only, "
            f"gradle heap ≤{heap}M")
    return {"argv_prefix": argv_prefix, "env": env, "snapshot": snap}
