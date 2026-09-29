"""Command execution: local (native pools) or SSH (linux build VPSs).

Contract rules, enforced by construction:

* ``argv`` is always a list — the local executor never touches a shell,
  and the SSH executor shell-quotes every element (the SSH exec channel
  always runs server-side through a shell; quoting, never concatenation,
  is the honest boundary there).
* Secrets travel via environment/files, never inside ``argv`` (argv leaks
  into process listings, RQ payloads and logs on both ends).
* Host trust fails closed: SSH requires a host-key pin, a known-hosts
  file, or an explicit accept-new-keys flag (tests only). With a pin, the
  key is verified BEFORE any credential bytes are sent.
* Remote execution targets POSIX hosts in this phase — Windows/macOS
  platform jobs run on native-pool workers via the local executor.
"""
from __future__ import annotations

import base64
import hashlib
import os
import shlex
import socket
import subprocess
import tempfile
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

OutputCallback = Callable[[str, bytes], None]


class ExecError(Exception):
    def __init__(self, argv: list[str], returncode: int,
                 stdout_tail: bytes = b"", stderr_tail: bytes = b"") -> None:
        self.argv = argv
        self.returncode = returncode
        self.stdout_tail = stdout_tail[-4000:]
        self.stderr_tail = stderr_tail[-4000:]
        super().__init__(
            f"command exited {returncode}: {' '.join(argv[:4])}"
            f"{'…' if len(argv) > 4 else ''}")


class ExecTimeout(ExecError):
    def __init__(self, argv: list[str], timeout: int) -> None:
        super().__init__(argv, -1)
        self.timeout = timeout
        self.args = (f"command timed out after {timeout}s: "
                     f"{' '.join(argv[:4])}",)


class HostKeyMismatch(Exception):
    pass


class SSHConfigError(ValueError):
    pass


@dataclass
class ExecResult:
    argv: list[str]
    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""


class Executor(ABC):
    is_local = False

    @abstractmethod
    def run(self, argv: list[str], *, cwd: str | None = None,
            env: dict[str, str] | None = None, timeout: int = 3600,
            output: OutputCallback | None = None,
            check: bool = False) -> ExecResult:
        ...

    @abstractmethod
    def list_dir(self, path: str) -> list[str]:
        ...

    @abstractmethod
    def exists(self, path: str) -> bool:
        ...

    @abstractmethod
    def put_file(self, local: Path, remote: str) -> None:
        ...

    @abstractmethod
    def get_file(self, remote: str, local: Path) -> None:
        ...

    @abstractmethod
    def close(self) -> None:
        ...


def _validate_argv(argv: list[str] | tuple[str, ...]) -> list[str]:
    cleaned = list(argv)
    if not cleaned or not all(isinstance(a, str) and a for a in cleaned):
        raise ValueError("argv must be a non-empty list of strings")
    return cleaned


class LocalExecutor(Executor):
    """Subprocess execution on the worker host (native pools)."""

    is_local = True

    def run(self, argv, *, cwd=None, env=None, timeout=3600,
            output=None, check=False) -> ExecResult:
        argv = _validate_argv(argv)
        merged = dict(os.environ)
        if env:
            merged.update(env)
        proc = subprocess.Popen(
            argv, cwd=cwd, env=merged,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert proc.stdout is not None and proc.stderr is not None
        buffers: dict[str, bytearray] = {
            "stdout": bytearray(), "stderr": bytearray()}

        def _pump(kind: str, stream) -> None:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    return
                buffers[kind].extend(chunk)
                if output is not None:
                    output(kind, chunk)

        threads = [
            threading.Thread(target=_pump, args=("stdout", proc.stdout)),
            threading.Thread(target=_pump, args=("stderr", proc.stderr)),
        ]
        for thread in threads:
            thread.start()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            for thread in threads:
                thread.join(timeout=10)
            raise ExecTimeout(argv, timeout) from None
        for thread in threads:
            thread.join(timeout=30)
        result = ExecResult(
            argv=argv, returncode=proc.returncode,
            stdout=bytes(buffers["stdout"]),
            stderr=bytes(buffers["stderr"]))
        if check and result.returncode != 0:
            raise ExecError(argv, result.returncode,
                            result.stdout, result.stderr)
        return result

    def list_dir(self, path: str) -> list[str]:
        return sorted(os.listdir(path))

    def exists(self, path: str) -> bool:
        return Path(path).exists()

    def put_file(self, local: Path, remote: str) -> None:
        import shutil
        dest = Path(remote)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(local, dest)

    def get_file(self, remote: str, local: Path) -> None:
        import shutil
        local = Path(local)
        local.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(remote, local)

    def close(self) -> None:
        pass


@dataclass
class SSHOptions:
    host: str
    username: str
    port: int = 22
    password: str | None = None
    private_key: str | None = None  # key file *content*
    private_key_path: str | None = None
    private_key_passphrase: str | None = None
    host_key_pin: str | None = None  # "ssh-ed25519:BASE64" or "sha256:BASE64"
    known_hosts: str | None = None
    connect_timeout: int = 15
    accept_new_hostkeys: bool = False

    @classmethod
    def from_material(cls, material: dict) -> "SSHOptions":
        if not isinstance(material, dict):
            raise SSHConfigError("ssh credential material must be an object")
        host = material.get("host")
        username = material.get("username")
        if not host or not username:
            raise SSHConfigError(
                "ssh credential material needs 'host' and 'username'")
        return cls(
            host=str(host), username=str(username),
            port=int(material.get("port", 22) or 22),
            password=material.get("password"),
            private_key=material.get("private_key"),
            private_key_passphrase=material.get("private_key_passphrase"),
            host_key_pin=material.get("host_key_pin"),
            known_hosts=material.get("known_hosts"),
            accept_new_hostkeys=bool(material.get(
                "accept_new_hostkeys", False)))


def _openssh_sha256_fingerprint(key) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "sha256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def verify_host_key_pin(key, pin: str) -> None:
    """Compare a server key against an explicit pin (before auth)."""
    pin = (pin or "").strip()
    candidates = {_openssh_sha256_fingerprint(key)}
    try:
        candidates.add(f"{key.get_name()}:"
                       f"{base64.b64encode(key.asbytes()).decode('ascii')}")
    except Exception:
        pass
    if pin not in candidates:
        raise HostKeyMismatch(
            "SSH host key does not match the pinned value — refusing to "
            "send credentials (possible MITM or rebuilt host)")


class ParamikoSSHExecutor(Executor):
    """SSH execution on a POSIX build host (paramiko transport)."""

    is_local = False

    def __init__(self, options: SSHOptions) -> None:
        self._options = options
        self._transport = None
        self._sftp = None
        self._key_file: str | None = None

    # ---------------------------------------------------------- #
    # connection (pin verified before any credential is sent)
    # ---------------------------------------------------------- #
    def _ensure(self):
        if self._transport is not None:
            return self._transport
        try:
            import paramiko
        except ImportError as exc:
            raise SSHConfigError(
                "the 'paramiko' package is not installed") from exc
        options = self._options
        if (not options.host_key_pin and not options.known_hosts
                and not options.accept_new_hostkeys):
            raise SSHConfigError(
                "no SSH host-key trust configured: set host_key_pin or "
                "known_hosts (accept_new_hostkeys exists for tests only)")
        sock = socket.create_connection(
            (options.host, options.port), timeout=options.connect_timeout)
        transport = paramiko.Transport(sock)
        stored = None
        try:
            if options.known_hosts:
                stored = paramiko.HostKeys()
                stored.load(options.known_hosts)
            transport.start_client(timeout=options.connect_timeout)
            server_key = transport.get_remote_server_key()
            if options.host_key_pin:
                verify_host_key_pin(server_key, options.host_key_pin)
            elif options.known_hosts:
                assert stored is not None
                # ssh-keyscan records non-standard ports as [host]:port.
                candidates = [options.host,
                              f"[{options.host}]:{options.port}"]
                known = None
                for candidate in candidates:
                    entry = stored.get(candidate, {}).get(
                        server_key.get_name())
                    if entry is not None:
                        known = entry
                        break
                if known is None or (
                        known.asbytes() != server_key.asbytes()):
                    raise HostKeyMismatch(
                        "SSH host key is not in the known-hosts file")
            # Trust established — authenticate now.
            pkey = self._load_pkey(paramiko)
            if pkey is not None:
                transport.auth_publickey(options.username, pkey)
            elif options.password is not None:
                transport.auth_password(options.username, options.password)
            else:
                raise SSHConfigError(
                    "ssh credential has neither private_key nor password")
        except Exception:
            transport.close()
            raise
        self._transport = transport
        return transport

    def _load_pkey(self, paramiko):
        options = self._options
        if options.private_key_path:
            return paramiko.RSAKey.from_private_key_file(
                options.private_key_path,
                password=options.private_key_passphrase)
        if options.private_key:
            handle, self._key_file = tempfile.mkstemp(prefix="zagros-ssh-")
            os.fchmod(handle, 0o600)
            with os.fdopen(handle, "w") as stream:
                stream.write(options.private_key)
                if not options.private_key.endswith("\n"):
                    stream.write("\n")
            try:
                last: Exception | None = None
                for key_type in (paramiko.RSAKey, paramiko.Ed25519Key,
                                 paramiko.ECDSAKey):
                    try:
                        return key_type.from_private_key_file(
                            self._key_file,
                            password=options.private_key_passphrase)
                    except Exception as exc:  # try the next key type
                        last = exc
                raise SSHConfigError(
                    f"unusable private key material: {last}")
            finally:
                try:
                    os.unlink(self._key_file)
                except OSError:
                    pass
                self._key_file = None
        return None

    # ---------------------------------------------------------- #
    # execution
    # ---------------------------------------------------------- #
    def _command(self, argv: list[str], cwd: str | None,
                 env: dict[str, str] | None) -> str:
        parts = []
        if cwd:
            parts.append(f"cd {shlex.quote(cwd)} &&")
        if env:
            parts.append(" ".join(
                f"{name}={shlex.quote(value)}"
                for name, value in env.items()))
        parts.append(" ".join(shlex.quote(arg) for arg in argv))
        return " ".join(part for part in parts if part)

    def run(self, argv, *, cwd=None, env=None, timeout=3600,
            output=None, check=False) -> ExecResult:
        import time
        argv = _validate_argv(argv)
        transport = self._ensure()
        command = self._command(argv, cwd, env)
        channel = transport.open_session()
        channel.set_combine_stderr(False)
        stdout = bytearray()
        stderr = bytearray()
        try:
            channel.exec_command(command)
            channel.settimeout(1.0)
            deadline = time.monotonic() + timeout
            while True:
                if channel.recv_ready():
                    chunk = channel.recv(65536)
                    stdout.extend(chunk)
                    if output is not None:
                        output("stdout", chunk)
                if channel.recv_stderr_ready():
                    chunk = channel.recv_stderr(65536)
                    stderr.extend(chunk)
                    if output is not None:
                        output("stderr", chunk)
                if channel.exit_status_ready():
                    while channel.recv_ready():
                        chunk = channel.recv(65536)
                        stdout.extend(chunk)
                        if output is not None:
                            output("stdout", chunk)
                    while channel.recv_stderr_ready():
                        chunk = channel.recv_stderr(65536)
                        stderr.extend(chunk)
                        if output is not None:
                            output("stderr", chunk)
                    break
                if time.monotonic() > deadline:
                    raise ExecTimeout(argv, timeout)
                time.sleep(0.05)
            returncode = channel.recv_exit_status()
        finally:
            channel.close()
        result = ExecResult(argv=argv, returncode=returncode,
                            stdout=bytes(stdout), stderr=bytes(stderr))
        if check and returncode != 0:
            raise ExecError(argv, returncode, result.stdout, result.stderr)
        return result

    def _sftp_client(self):
        if self._sftp is None:
            import paramiko
            self._sftp = paramiko.SFTPClient.from_transport(self._ensure())
        return self._sftp

    def list_dir(self, path: str) -> list[str]:
        entries = self._sftp_client().listdir(path)
        return sorted(entries)

    def exists(self, path: str) -> bool:
        try:
            self._sftp_client().stat(path)
        except OSError:
            return False
        return True

    def put_file(self, local: Path, remote: str) -> None:
        self._sftp_client().put(str(local), remote)

    def get_file(self, remote: str, local: Path) -> None:
        local = Path(local)
        local.parent.mkdir(parents=True, exist_ok=True)
        self._sftp_client().get(remote, str(local))

    def close(self) -> None:
        if self._sftp is not None:
            try:
                self._sftp.close()
            except Exception:
                pass
            self._sftp = None
        if self._transport is not None:
            try:
                self._transport.close()
            except Exception:
                pass
            self._transport = None
