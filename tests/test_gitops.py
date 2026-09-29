"""GitOps against real git repos (init/commit/clone/checkout/verify)."""
from __future__ import annotations

import pytest

from conftest import make_repo, requires_git
from zagros_builder.gitops import CloneError, GitOps, create_workspace
from zagros_builder.ssh import LocalExecutor

pytestmark = requires_git


@pytest.fixture()
def gitops(tmp_path):
    executor = LocalExecutor()
    yield GitOps(executor, scratch=tmp_path / "scratch")
    executor.close()


def test_clone_checks_out_and_verifies_the_pinned_sha(gitops, tmp_path):
    repo, sha = make_repo(tmp_path)
    dest = str(tmp_path / "work" / "src")
    chunks: list[bytes] = []
    gitops.clone(f"file://{repo}", sha, dest,
                 output=lambda kind, chunk: chunks.append(chunk))
    assert (tmp_path / "work" / "src" / "tool"
            / "white_label_build.py").is_file()
    # local clones are usually quiet — the callback contract itself is
    # pinned by the executor streaming tests; here it must at least not
    # break the clone.
    assert isinstance(chunks, list)


def test_clone_rejects_unknown_revision(gitops, tmp_path):
    repo, _ = make_repo(tmp_path)
    with pytest.raises(CloneError) as error:
        gitops.clone(f"file://{repo}", "0" * 40,
                     str(tmp_path / "work" / "src"))
    assert error.value.stage in ("checkout", "verify")


def test_clone_rejects_missing_repo(gitops, tmp_path):
    with pytest.raises(CloneError) as error:
        gitops.clone("file:///does/not/exist.git", "0" * 40,
                     str(tmp_path / "work" / "src"))
    assert error.value.stage == "clone"


def test_workspace_is_private_and_cleanup_removes(gitops, tmp_path):
    root = create_workspace(tmp_path, "build-1234", "linux", "x64")
    assert root.is_dir()
    assert (root.stat().st_mode & 0o777) == 0o700
    (root / "junk.txt").write_text("x")
    gitops.cleanup(str(root))
    assert not root.exists()


def test_write_text_file_local(gitops, tmp_path):
    gitops.write_text_file(
        str(tmp_path / "w" / "cfg.json"), '{"a": 1}')
    assert (tmp_path / "w" / "cfg.json").read_text() == '{"a": 1}'
