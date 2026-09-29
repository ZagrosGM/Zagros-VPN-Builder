"""Guard decisions against a stub executor with canned probe output."""
from __future__ import annotations

import pytest

from zagros_builder.guard import ResourceError, preflight, snapshot
from zagros_builder.ssh import ExecResult


class StubExecutor:
    """Answer the single snapshot probe script with canned stdout."""

    is_local = False

    def __init__(self, stdout: bytes):
        self._stdout = stdout
        self.calls: list[list[str]] = []

    def run(self, argv, *, cwd=None, env=None, timeout=3600,
            output=None, check=False):
        self.calls.append(list(argv))
        return ExecResult(argv=list(argv), returncode=0, stdout=self._stdout)

    def list_dir(self, path):
        return []

    def exists(self, path):
        return False

    def put_file(self, local, remote):
        raise AssertionError("guard must not upload")

    def get_file(self, remote, local):
        raise AssertionError("guard must not download")


def _snap_stdout(*, cores=8, mem="16000 12000", swap="0 0", disk=50000,
                 user="0", system="Linux", systemd="systemd"):
    lines = [str(cores), mem, swap, str(disk), user, system, systemd]
    return ("\n".join(lines) + "\n").encode()


def _logs():
    out: list[str] = []
    return out.append


def test_snapshot_parses_every_field_independently():
    ex = StubExecutor(_snap_stdout())
    snap = snapshot(ex, "/ws")
    assert (snap.cores, snap.mem_total_mb, snap.mem_avail_mb) == (8, 16000, 12000)
    assert (snap.swap_total_mb, snap.swap_free_mb) == (0, 0)
    assert snap.disk_free_mb == 50000
    assert snap.is_root is True and snap.is_linux is True
    assert snap.has_systemd is True


def test_snapshot_degrades_gracefully_on_garbage():
    # blank lines are dropped; a 1-value mem line degrades to -1 and the
    # remaining fields fall through independently
    ex = StubExecutor(b"2\n\n\n\n1000\nLinux\n")
    snap = snapshot(ex, "/ws")
    assert snap.cores == 2
    assert snap.mem_total_mb == -1  # missing line degrades, never crashes
    assert snap.disk_free_mb == -1
    assert snap.is_root is False  # nothing left to parse for id -u


def test_low_disk_fails_before_any_clone(monkeypatch):
    monkeypatch.setenv("ZAGROS_GUARD_DISABLE", "")  # guard ACTIVE
    ex = StubExecutor(_snap_stdout(disk=1024))
    with pytest.raises(ResourceError) as exc:
        preflight(ex, log=_logs(), platform="android", workspace_path="/ws")
    assert exc.value.code == "resources_insufficient"
    assert "1024MB free disk" in str(exc.value)


def test_healthy_host_gets_limit_wrapper(monkeypatch):
    monkeypatch.setenv("ZAGROS_GUARD_DISABLE", "")  # guard ACTIVE
    ex = StubExecutor(_snap_stdout())
    info = preflight(ex, log=_logs(), platform="android", workspace_path="/ws")
    assert "argv_prefix" in info and "snapshot" in info
    # root + linux + systemd => the systemd-run scope wrapper
    assert info["argv_prefix"], "root+linux+systemd must wrap the build"
    assert "systemd-run" in " ".join(info["argv_prefix"])


def test_disable_switch_keeps_snapshot_only():
    import os
    old = os.environ.get("ZAGROS_GUARD_DISABLE")
    os.environ["ZAGROS_GUARD_DISABLE"] = "1"
    try:
        ex = StubExecutor(_snap_stdout(disk=10))  # would hard-fail if active
        info = preflight(ex, log=_logs(), platform="android",
                         workspace_path="/ws")
        assert info["argv_prefix"] == []
        assert info["env"] == {}
    finally:
        if old is None:
            os.environ.pop("ZAGROS_GUARD_DISABLE", None)
        else:
            os.environ["ZAGROS_GUARD_DISABLE"] = old


def test_low_memory_unprivileged_refuses(monkeypatch):
    monkeypatch.setenv("ZAGROS_GUARD_DISABLE", "")  # guard ACTIVE
    ex = StubExecutor(_snap_stdout(mem="2000 300", swap="0 0", user="1000"))
    with pytest.raises(ResourceError) as exc:
        preflight(ex, log=_logs(), platform="android", workspace_path="/ws")
    assert exc.value.code == "resources_insufficient"
    assert "memory too low" in str(exc.value)
