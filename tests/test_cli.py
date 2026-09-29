"""CLI: enroll stores a 0600 token; listen guards its inputs."""
from __future__ import annotations

import os
import stat

import pytest

from test_panel_client import _Stub
from zagros_builder.cli import main


@pytest.fixture()
def stub():
    server = _Stub()
    yield server
    server.close()


def test_enroll_saves_token_0600_without_printing_it(stub, tmp_path,
                                                     capsys):
    stub.routes[("POST",
                 "/api/zagros/builder/workers/register")] = (
        200, {"api_token": "SECRET-API-TOKEN", "status": "active"})
    token_file = tmp_path / "w.token"
    code = main(["enroll", "--panel-url", stub.url, "--worker-id", "w-1",
                 "--register-token", "reg", "--token-file", str(token_file)])
    assert code == 0
    assert token_file.read_text() == "SECRET-API-TOKEN\n"
    assert stat.S_IMODE(token_file.stat().st_mode) == 0o600
    out = capsys.readouterr().out
    assert "SECRET-API-TOKEN" not in out
    assert "w-1" in out


def test_enroll_failure_returns_1(stub, tmp_path):
    stub.routes[("POST",
                 "/api/zagros/builder/workers/register")] = (
        401, {"detail": {"error": "worker_authentication_failed",
                         "message": "bad"}})
    code = main(["enroll", "--panel-url", stub.url, "--worker-id", "w-1",
                 "--register-token", "bad",
                 "--token-file", str(tmp_path / "w.token")])
    assert code == 1


def test_listen_refuses_missing_and_loose_token_files(tmp_path):
    missing = tmp_path / "nope.token"
    assert main(["listen", "--panel-url", "http://x", "--worker-id",
                 "w", "--token-file", str(missing), "--redis-url",
                 "redis://x/0", "--labels", "linux"]) == 1
    loose = tmp_path / "loose.token"
    loose.write_text("t")
    os.chmod(loose, 0o644)
    with pytest.raises(SystemExit) as exit:
        main(["listen", "--panel-url", "http://x", "--worker-id", "w",
              "--token-file", str(loose), "--redis-url", "redis://x/0",
              "--labels", "linux"])
    assert exit.value.code == 2


def test_help_exits_zero():
    with pytest.raises(SystemExit) as exit:
        main(["--help"])
    assert exit.value.code == 0
