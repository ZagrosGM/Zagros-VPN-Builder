"""ParamikoSSHExecutor against a real local sshd (key auth + pinning)."""
from __future__ import annotations

import base64
import getpass
import hashlib
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("paramiko")

from zagros_builder.ssh import (  # noqa: E402
    ExecError,
    ExecTimeout,
    HostKeyMismatch,
    ParamikoSSHExecutor,
    SSHConfigError,
    SSHOptions,
)

SSHD = shutil.which("sshd") or "/usr/sbin/sshd"
KEYGEN = shutil.which("ssh-keygen")
NEEDS_SSHD = pytest.mark.skipif(
    not (os.path.exists(SSHD) and KEYGEN),
    reason="openssh-server/ssh-keygen not installed")


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _openssh_pin(public_key_path: Path) -> str:
    """sha256 pin computed independently, cross-checked with ssh-keygen."""
    parts = public_key_path.read_text().split()
    raw = base64.b64decode(parts[1])
    ours = "sha256:" + base64.b64encode(
        hashlib.sha256(raw).digest()).decode().rstrip("=")
    probe = subprocess.run(
        [KEYGEN, "-l", "-E", "sha256", "-f", str(public_key_path)],
        check=True, capture_output=True, text=True)
    assert ours[7:] in probe.stdout  # matches OpenSSH's own fingerprint
    return ours


@pytest.fixture(scope="module")
def sshd_server(tmp_path_factory):
    user = getpass.getuser()
    base = tmp_path_factory.mktemp("sshd")
    subprocess.run([KEYGEN, "-t", "ed25519", "-N", "",
                    "-f", str(base / "hostkey")],
                   check=True, capture_output=True)
    subprocess.run([KEYGEN, "-t", "ed25519", "-N", "",
                    "-f", str(base / "id_ed25519")],
                   check=True, capture_output=True)
    auth_keys = base / "authorized_keys"
    auth_keys.write_text((base / "id_ed25519.pub").read_text())
    os.chmod(auth_keys, 0o600)
    Path("/run/sshd").mkdir(parents=True, exist_ok=True)
    sftp_server = next(
        (candidate for candidate in (
            "/usr/lib/openssh/sftp-server",
            "/usr/libexec/sftp-server",
            "/usr/lib/ssh/sftp-server",
        ) if os.path.exists(candidate)), None)
    if sftp_server is None:
        pytest.skip("no sftp-server binary for the test sshd")
    port = _free_port()
    config = base / "sshd_config"
    config.write_text(
        f"Port {port}\nListenAddress 127.0.0.1\n"
        f"HostKey {base / 'hostkey'}\n"
        f"PidFile {base / 'sshd.pid'}\n"
        f"Subsystem sftp {sftp_server}\n"
        f"AuthorizedKeysFile {auth_keys}\n"
        "PasswordAuthentication no\n"
        "ChallengeResponseAuthentication no\n"
        "UsePAM no\nPubkeyAuthentication yes\n"
        "PermitRootLogin prohibit-password\n"
        "StrictModes no\n"
        f"AllowUsers {user}\n")
    proc = subprocess.Popen(
        [SSHD, "-D", "-e", "-f", str(config)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port),
                                     timeout=1).close()
            break
        except OSError:
            time.sleep(0.2)
    else:
        proc.terminate()
        pytest.skip("test sshd did not start")
    pin = _openssh_pin(base / "hostkey.pub")
    yield SimpleNamespace(
        port=port, pin=pin, user=user, base=base,
        key_material=(base / "id_ed25519").read_text())
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


@NEEDS_SSHD
def _options(sshd_server, **overrides) -> SSHOptions:
    params = {
        "host": "127.0.0.1", "port": sshd_server.port,
        "username": sshd_server.user,
        "private_key": sshd_server.key_material,
        "host_key_pin": sshd_server.pin,
    }
    params.update(overrides)
    return SSHOptions(**params)


@NEEDS_SSHD
def test_key_auth_with_pin_executes_and_streams(sshd_server, tmp_path):
    executor = ParamikoSSHExecutor(_options(sshd_server))
    try:
        result = executor.run(["echo", "hello-ssh"])
        assert result.returncode == 0
        assert result.stdout == b"hello-ssh\n"
        chunks: list[bytes] = []
        result = executor.run(
            ["sh", "-c", "echo out; echo err >&2"],
            output=lambda kind, chunk: chunks.append((kind, chunk)))
        assert result.returncode == 0
        kinds = {kind for kind, _ in chunks}
        assert kinds == {"stdout", "stderr"}
        result = executor.run(["sh", "-c", "echo $MARK"],
                              env={"MARK": "env-ok"})
        assert result.stdout == b"env-ok\n"
        assert executor.exists("/tmp") is True
        assert executor.exists("/no/such/path-xyz") is False
        assert "tmp" in executor.list_dir("/")
        local = tmp_path / "up.txt"
        local.write_text("payload")
        executor.put_file(local, "/tmp/zagros-ssh-test-up.txt")
        down = tmp_path / "down.txt"
        executor.get_file("/tmp/zagros-ssh-test-up.txt", down)
        assert down.read_text() == "payload"
    finally:
        executor.close()


@NEEDS_SSHD
def test_argv_is_quoted_never_interpreted(sshd_server, tmp_path):
    marker = tmp_path / "pwned"
    executor = ParamikoSSHExecutor(_options(sshd_server))
    try:
        evil = f"a;touch {marker};echo pwned"
        result = executor.run(["echo", evil])
        assert result.stdout.decode().strip() == evil
        assert not marker.exists()
    finally:
        executor.close()


@NEEDS_SSHD
def test_wrong_pin_refuses_before_auth(sshd_server):
    executor = ParamikoSSHExecutor(
        _options(sshd_server, host_key_pin="sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
    try:
        with pytest.raises(HostKeyMismatch):
            executor.run(["echo", "hi"])
    finally:
        executor.close()


@NEEDS_SSHD
def test_known_hosts_mode_accepts_and_rejects(sshd_server, tmp_path):
    scan = subprocess.run(
        ["ssh-keyscan", "-p", str(sshd_server.port), "-t", "ed25519",
         "127.0.0.1"],
        check=True, capture_output=True, text=True)
    known = tmp_path / "known_hosts"
    known.write_text(scan.stdout)
    options = _options(sshd_server, host_key_pin=None,
                       known_hosts=str(known))
    executor = ParamikoSSHExecutor(options)
    try:
        assert executor.run(["echo", "kh"]).stdout == b"kh\n"
    finally:
        executor.close()
    known.write_text("127.0.0.1 ssh-ed25519 " + "A" * 68 + "\n")
    executor = ParamikoSSHExecutor(
        _options(sshd_server, host_key_pin=None,
                 known_hosts=str(known)))
    try:
        with pytest.raises(HostKeyMismatch):
            executor.run(["echo", "hi"])
    finally:
        executor.close()


@NEEDS_SSHD
def test_missing_trust_fails_closed_and_wrong_key_fails_auth(sshd_server):
    executor = ParamikoSSHExecutor(
        _options(sshd_server, host_key_pin=None))
    try:
        with pytest.raises(SSHConfigError):
            executor.run(["echo", "hi"])
    finally:
        executor.close()
    import paramiko
    bad_key = subprocess.run(
        [KEYGEN, "-t", "ed25519", "-N", "", "-f",
         str(sshd_server.base / "wrong")],
        check=True, capture_output=True)
    assert bad_key.returncode == 0
    executor = ParamikoSSHExecutor(_options(
        sshd_server,
        private_key=(sshd_server.base / "wrong").read_text()))
    try:
        with pytest.raises(paramiko.AuthenticationException):
            executor.run(["echo", "hi"])
    finally:
        executor.close()


@NEEDS_SSHD
def test_exit_codes_and_timeouts(sshd_server):
    executor = ParamikoSSHExecutor(_options(sshd_server))
    try:
        result = executor.run(["sh", "-c", "exit 9"])
        assert result.returncode == 9
        with pytest.raises(ExecError):
            executor.run(["sh", "-c", "exit 9"], check=True)
        with pytest.raises(ExecTimeout):
            executor.run(["sleep", "30"], timeout=1)
    finally:
        executor.close()


@NEEDS_SSHD
def test_from_material_builds_options():
    options = SSHOptions.from_material({
        "host": "10.0.0.9", "username": "builder", "port": 2222,
        "private_key": "PEM", "host_key_pin": "sha256:abc"})
    assert options.host == "10.0.0.9"
    assert options.port == 2222
    with pytest.raises(SSHConfigError):
        SSHOptions.from_material({"host": "h"})
