"""LocalExecutor: real subprocesses (no shell, argv-only)."""
from __future__ import annotations

import sys

import pytest

from zagros_builder.ssh import ExecError, ExecTimeout, LocalExecutor


@pytest.fixture()
def executor():
    worker = LocalExecutor()
    yield worker
    worker.close()


def test_run_captures_output_and_exit_codes(executor, tmp_path):
    result = executor.run(
        [sys.executable, "-c",
         "import sys;print('out');print('err', file=sys.stderr)"],
        cwd=str(tmp_path))
    assert result.returncode == 0
    assert result.stdout == b"out\n"
    assert result.stderr == b"err\n"
    failed = executor.run([sys.executable, "-c", "raise SystemExit(4)"])
    assert failed.returncode == 4


def test_run_passes_env_and_cwd_without_shell(executor, tmp_path):
    result = executor.run(
        [sys.executable, "-c",
         "import os;print(os.environ.get('MARK'));print(os.getcwd())"],
        cwd=str(tmp_path), env={"MARK": "a b; rm -rf /"})
    assert b"a b; rm -rf /" in result.stdout  # never interpreted
    assert str(tmp_path).encode() in result.stdout


def test_run_streams_chunks_incrementally(executor):
    seen: list[tuple[str, bytes]] = []
    result = executor.run(
        [sys.executable, "-c",
         "import sys;sys.stdout.write('x'*70000);sys.stdout.flush()"],
        output=lambda kind, chunk: seen.append((kind, chunk)))
    assert result.returncode == 0
    assert sum(len(chunk) for _, chunk in seen) == 70000


def test_run_check_raises_with_tails_and_timeout_kills(executor):
    with pytest.raises(ExecError) as error:
        executor.run([sys.executable, "-c", "raise SystemExit(7)"],
                     check=True)
    assert error.value.returncode == 7
    with pytest.raises(ExecTimeout):
        executor.run([sys.executable, "-c", "import time;time.sleep(30)"],
                     timeout=1)


def test_rejects_empty_or_nonstring_argv(executor):
    with pytest.raises(ValueError):
        executor.run([])
    with pytest.raises(ValueError):
        executor.run(["echo", 123])


def test_file_helpers_round_trip(executor, tmp_path):
    source = tmp_path / "a.txt"
    source.write_text("hello")
    executor.put_file(source, str(tmp_path / "sub" / "b.txt"))
    assert (tmp_path / "sub" / "b.txt").read_text() == "hello"
    executor.get_file(str(tmp_path / "sub" / "b.txt"),
                      tmp_path / "c.txt")
    assert (tmp_path / "c.txt").read_text() == "hello"
    assert executor.list_dir(str(tmp_path / "sub")) == ["b.txt"]
    assert executor.exists(str(tmp_path / "sub" / "b.txt")) is True
    assert executor.exists(str(tmp_path / "missing")) is False
