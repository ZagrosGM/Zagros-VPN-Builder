"""Pinned-source checkout plus workspace lifecycle.

Every build clones the exact pinned commit and verifies ``HEAD`` afterwards:
a branch, a tag or a drifting default branch can never be built, and a
corrupt/truncated clone fails at verify time instead of producing an
unreproducible artifact.
"""
from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

from zagros_builder.ssh import ExecError, Executor


class CloneError(Exception):
    def __init__(self, stage: str, message: str) -> None:
        self.stage = stage  # clone | checkout | verify
        super().__init__(f"{stage}: {message}")


def create_workspace(base: Path | str, build_public_id: str,
                     platform: str, arch: str) -> Path:
    """Fresh isolated local directory for one platform job (mode 0700)."""
    base = Path(base)
    base.mkdir(parents=True, exist_ok=True)
    short = "".join(
        c for c in build_public_id[:8] if c.isalnum()) or "build"
    path = Path(tempfile.mkdtemp(
        prefix=f"zagros-{short}-{platform}-{arch}-", dir=str(base)))
    os.chmod(path, 0o700)
    return path


class GitOps:
    def __init__(self, executor: Executor, *, scratch: Path) -> None:
        self._exec = executor
        self._scratch = Path(scratch)
        self._scratch.mkdir(parents=True, exist_ok=True)

    @property
    def is_local(self) -> bool:
        return self._exec.is_local

    def prepare_dir(self, path: str) -> None:
        if self.is_local:
            Path(path).mkdir(parents=True, exist_ok=True)
        else:
            result = self._exec.run(["mkdir", "-p", path], timeout=60)
            if result.returncode != 0:
                raise CloneError(
                    "clone", f"cannot create remote directory '{path}'")

    def clone(self, repo: str, revision: str, dest: str, *,
              output=None, timeout: int = 900) -> None:
        try:
            cloned = self._exec.run(
                ["git", "clone", "--no-checkout", repo, dest],
                timeout=timeout, output=output)
        except OSError as exc:
            raise CloneError(
                "clone", f"git executable not available: {exc}") from exc
        if cloned.returncode != 0:
            raise CloneError(
                "clone", _tail(cloned.stderr) or "git clone failed")
        checked = self._exec.run(
            ["git", "-C", dest, "checkout", revision],
            timeout=300, output=output)
        if checked.returncode != 0:
            raise CloneError(
                "checkout", _tail(checked.stderr) or "git checkout failed")
        verified = self._exec.run(
            ["git", "-C", dest, "rev-parse", "HEAD"], timeout=60)
        head = verified.stdout.decode("utf-8", "replace").strip().lower()
        if verified.returncode != 0 or head != revision.strip().lower():
            raise CloneError(
                "verify", f"HEAD '{head}' != pinned '{revision}'")

    def write_text_file(self, path: str, content: str) -> None:
        if self.is_local:
            target = Path(path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            return
        handle, tmp = tempfile.mkstemp(
            prefix="zagros-put-", dir=str(self._scratch))
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                stream.write(content)
            parent = path.rsplit("/", 1)[0]
            if parent:
                self._exec.run(["mkdir", "-p", parent], timeout=60)
            self._exec.put_file(Path(tmp), path)
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def cleanup(self, path: str) -> None:
        try:
            if self.is_local:
                shutil.rmtree(path, ignore_errors=True)
            else:
                self._exec.run(["rm", "-rf", path], timeout=300)
        except Exception:
            pass


def _tail(data: bytes, limit: int = 2000) -> str:
    text = data.decode("utf-8", "replace").strip()
    lines = text.splitlines()
    return "\n".join(lines[-20:])[:limit]
