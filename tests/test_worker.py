"""run_build end to end with a fake panel and real git checkouts."""
from __future__ import annotations

import hashlib

import pytest

from conftest import config_digest, make_repo, requires_git
from zagros_builder.panel import PanelError
from zagros_builder.worker import run_build

pytestmark = requires_git

REDIS_URL = "redis://127.0.0.1:6379/15"


class FakePanel:
    def __init__(self, doc, *, claim_error=None):
        self.worker_id = "test-worker"
        self._doc = doc
        self._claim_error = claim_error
        self.claims: list = []
        self.fetches: list = []
        self.reports: list = []
        self.uploads: list = []
        self.report_error = None
        self.fetch_error = None

    def claim(self, build, platform, arch, *, artifact="apk"):
        if self._claim_error is not None:
            raise self._claim_error
        self.claims.append((build, platform, arch, artifact))
        return {"status": "running", "worker_id": self.worker_id}

    def fetch_job(self, build, platform, arch, *, artifact="apk"):
        if self.fetch_error is not None:
            raise self.fetch_error
        self.fetches.append((build, platform, arch, artifact))
        return self._doc

    def report_status(self, build, platform, arch, *, artifact="apk",
                      status, failure_code=None, failure_message=None,
                      final_log=None):
        if self.report_error is not None:
            raise self.report_error
        self.reports.append({"artifact": artifact, "status": status,
                             "failure_code": failure_code,
                             "failure_message": failure_message,
                             "final_log": final_log or ""})
        return {"status": status}

    def upload_artifact(self, build, platform, arch, *, artifact="apk",
                        filename, content, sha256, size_bytes,
                        toolchain=None):
        assert hashlib.sha256(content).hexdigest() == sha256
        assert len(content) == size_bytes
        self.uploads.append({"artifact": artifact, "filename": filename,
                             "content": content, "toolchain": toolchain})
        return {"filename": filename}

    def close(self):
        pass


def _payload(**overrides):
    body = {"v": 2, "build_public_id": "b-1", "platform": "linux",
            "arch": "x64", "job_token": "tok"}
    body.update(overrides)
    return body


def _sdk_repo(tmp_path):
    return make_repo(tmp_path / "sdk", script=None,
                     extra_files={"sdk-marker.txt": "sdk-pin-ok"})


def _doc(repo, sha, config, sdk, **overrides):
    sdk_repo, sdk_sha = sdk
    doc = {"v": 2, "build_public_id": "b-1", "version": "1.0.0",
           "build_number": 1, "platform": "linux", "arch": "x64",
           "source": {"repo": f"file://{repo}", "revision": sha},
           "sdk_source": {"repo": f"file://{sdk_repo}",
                          "revision": sdk_sha},
           "build_config": config,
           "config_digest": config_digest(config),
           "credentials": [], "log_stream": "test-stream",
           "application": {"public_id": "app", "name": "App"}}
    doc.update(overrides)
    return doc


def test_success_uploads_outputs_and_redacts_transcript(tmp_path,
                                                        monkeypatch):
    monkeypatch.setenv("ZAGROS_BUILD_EXECUTOR", "local")
    repo, sha = make_repo(tmp_path)
    sdk = _sdk_repo(tmp_path)
    panel = FakePanel(_doc(
        repo, sha, {"display_name": "T", "files": {"app.apk": "PAYLOAD"}},
        sdk))
    result = run_build(_payload(), panel=panel,
                       workspace_base=tmp_path / "ws")
    assert result["ok"] is True
    assert result["reported"] is True
    assert result["artifacts"] == 1
    assert len(panel.claims) == 1
    (upload,) = panel.uploads
    assert upload["filename"] == "app.apk"
    assert upload["content"] == b"PAYLOAD"
    assert upload["toolchain"]["executor"] == "local"
    (report,) = panel.reports
    assert report["status"] == "success"
    assert "ghp_FIXTURESECRET" not in report["final_log"]
    assert "***REDACTED***" in report["final_log"]
    assert "outputs written" in report["final_log"]
    assert "sdk sibling ok: sdk-pin-ok" in report["final_log"]
    assert list((tmp_path / "ws").iterdir()) == []  # workspace destroyed


def test_failing_script_reports_build_failed(tmp_path, monkeypatch):
    monkeypatch.setenv("ZAGROS_BUILD_EXECUTOR", "local")
    repo, sha = make_repo(tmp_path)
    sdk = _sdk_repo(tmp_path)
    panel = FakePanel(_doc(repo, sha, {"display_name": "T",
                                       "mode": "fail"}, sdk))
    result = run_build(_payload(), panel=panel,
                       workspace_base=tmp_path / "ws")
    assert result == {"ok": False, "reported": True,
                      "failure_code": "build_failed",
                      "error": result["error"]}
    assert panel.uploads == []
    (report,) = panel.reports
    assert report["status"] == "failed"
    assert "boom" in report["final_log"]


def test_empty_output_is_no_artifacts_not_success(tmp_path, monkeypatch):
    monkeypatch.setenv("ZAGROS_BUILD_EXECUTOR", "local")
    repo, sha = make_repo(tmp_path)
    sdk = _sdk_repo(tmp_path)
    panel = FakePanel(_doc(repo, sha, {"display_name": "T",
                                       "mode": "quiet"}, sdk))
    result = run_build(_payload(), panel=panel,
                       workspace_base=tmp_path / "ws")
    assert result["failure_code"] == "no_artifacts"
    assert result["reported"] is True


def test_missing_contract_script_is_config_invalid(tmp_path, monkeypatch):
    monkeypatch.setenv("ZAGROS_BUILD_EXECUTOR", "local")
    repo, sha = make_repo(tmp_path, script=None)
    sdk = _sdk_repo(tmp_path)
    panel = FakePanel(_doc(repo, sha, {"display_name": "T"}, sdk))
    result = run_build(_payload(), panel=panel,
                       workspace_base=tmp_path / "ws")
    assert result["failure_code"] == "config_invalid"
    assert result["reported"] is True


def test_invalid_payload_never_touches_the_panel(tmp_path):
    panel = FakePanel({})
    result = run_build({"v": 99}, panel=panel,
                       workspace_base=tmp_path / "ws")
    assert result["reported"] is False
    assert panel.claims == []


def test_rejected_claim_returns_unreported(tmp_path):
    panel = FakePanel(
        {}, claim_error=PanelError("bad token", status_code=401,
                                   error_code="worker_authentication_failed"))
    result = run_build(_payload(), panel=panel,
                       workspace_base=tmp_path / "ws")
    assert result["reported"] is False
    assert panel.reports == []


def test_revoked_credential_at_fetch_reports_failed_instead_of_sticking(
        tmp_path):
    panel = FakePanel({})
    panel.fetch_error = PanelError(
        "credential revoked", status_code=409,
        error_code="build_credential_revoked")
    result = run_build(_payload(), panel=panel,
                       workspace_base=tmp_path / "ws")
    assert result["reported"] is True
    assert result["failure_code"] == "credential_revoked"
    (report,) = panel.reports
    assert report["status"] == "failed"


def test_panel_outage_at_report_raises_loudly(tmp_path, monkeypatch):
    monkeypatch.setenv("ZAGROS_BUILD_EXECUTOR", "local")
    repo, sha = make_repo(tmp_path)
    sdk = _sdk_repo(tmp_path)
    panel = FakePanel(_doc(repo, sha, {"display_name": "T"}, sdk))
    panel.report_error = PanelError("down", status_code=503,
                                    error_code="panel_unreachable")
    with pytest.raises(PanelError):
        run_build(_payload(), panel=panel,
                  workspace_base=tmp_path / "ws")


def test_ssh_assigned_job_on_local_only_worker_refuses(tmp_path,
                                                        monkeypatch):
    monkeypatch.setenv("ZAGROS_BUILD_EXECUTOR", "local")
    repo, sha = make_repo(tmp_path)
    sdk = _sdk_repo(tmp_path)
    panel = FakePanel(_doc(
        repo, sha, {"display_name": "T"}, sdk,
        credentials=[{"public_id": "c", "kind": "ssh_password",
                      "label": "vps",
                      "material": {"host": "10.0.0.9",
                                  "username": "b"}}]))
    result = run_build(_payload(), panel=panel,
                       workspace_base=tmp_path / "ws")
    assert result["failure_code"] == "config_invalid"
    assert result["reported"] is True


def test_live_lines_stream_to_redis(tmp_path, monkeypatch):
    redis = pytest.importorskip("redis")
    client = redis.Redis.from_url(REDIS_URL)
    try:
        client.ping()
    except Exception:
        pytest.skip("local Redis is not running")
    client.flushdb()
    monkeypatch.setenv("ZAGROS_BUILD_EXECUTOR", "local")
    repo, sha = make_repo(tmp_path)
    sdk = _sdk_repo(tmp_path)
    stream = "zagros:test-worker-live"
    panel = FakePanel(_doc(repo, sha, {"display_name": "T"}, sdk,
                           log_stream=stream))
    result = run_build(_payload(), panel=panel,
                       workspace_base=tmp_path / "ws",
                       redis_url=REDIS_URL)
    assert result["ok"] is True
    entries = client.xrange(stream, "-", "+")
    texts = [fields[b"text"].decode() for _, fields in entries]
    assert any("building linux/x64" in text for text in texts)
    assert not any("ghp_FIXTURESECRET" in text for text in texts)
    client.flushdb()
    client.close()


def test_rq_executes_the_panel_string_reference(tmp_path, monkeypatch):
    rq = pytest.importorskip("rq")
    redis = pytest.importorskip("redis")
    client = redis.Redis.from_url(REDIS_URL)
    try:
        client.ping()
    except Exception:
        pytest.skip("local Redis is not running")
    client.flushdb()
    monkeypatch.setenv("ZAGROS_BUILD_EXECUTOR", "local")
    repo, sha = make_repo(tmp_path)
    sdk = _sdk_repo(tmp_path)
    panel = FakePanel(_doc(repo, sha, {"display_name": "T"}, sdk))
    # the panel enqueues by bare string (it cannot import this package);
    # RQ resolves + executes it inside the worker process.
    monkeypatch.setattr(
        "zagros_builder.worker.PanelClient.from_env",
        classmethod(lambda cls, **kwargs: panel))
    queue = rq.Queue("builder:test-ref", connection=client)
    job = queue.enqueue("zagros_builder.worker.run_build", _payload(),
                        job_timeout=300)
    rq.SimpleWorker([queue], connection=client).work(burst=True)
    job.refresh()
    assert job.is_finished
    assert job.return_value()["ok"] is True
    assert job.return_value()["reported"] is True
    client.flushdb()
    client.close()


def test_v1_document_without_sdk_source_is_config_invalid(tmp_path,
                                                          monkeypatch):
    monkeypatch.setenv("ZAGROS_BUILD_EXECUTOR", "local")
    repo, sha = make_repo(tmp_path)
    sdk = _sdk_repo(tmp_path)
    doc = _doc(repo, sha, {"display_name": "T"}, sdk)
    del doc["sdk_source"]  # what a v1 panel (or a truncated doc) serves
    panel = FakePanel(doc)
    result = run_build(_payload(), panel=panel,
                       workspace_base=tmp_path / "ws")
    assert result["failure_code"] == "config_invalid"
    assert result["reported"] is True
    assert "sdk_source" in result["error"]
    assert panel.uploads == []


def test_unresolvable_sdk_pin_fails_checkout_loudly(tmp_path, monkeypatch):
    monkeypatch.setenv("ZAGROS_BUILD_EXECUTOR", "local")
    repo, sha = make_repo(tmp_path)
    sdk_repo, _ = _sdk_repo(tmp_path)
    panel = FakePanel(_doc(
        repo, sha, {"display_name": "T"},
        (sdk_repo, "e" * 40)))  # well-formed pin, absent from the repo
    result = run_build(_payload(), panel=panel,
                       workspace_base=tmp_path / "ws")
    assert result["failure_code"] == "checkout_failed"
    assert result["reported"] is True
    assert panel.uploads == []


_AAB_ARGV_SCRIPT = """#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
parser = argparse.ArgumentParser()
parser.add_argument("--config")
parser.add_argument("--platform")
parser.add_argument("--arch")
parser.add_argument("--artifact", default="apk")
parser.add_argument("--out")
ns = parser.parse_args()
assert ns.artifact == "aab", f"want aab, script got {ns.artifact!r}"
assert ns.platform == "android" and ns.arch == "arm64-v8a", (
    ns.platform, ns.arch)
config = json.loads(Path(ns.config).read_text(encoding="utf-8"))
out = Path(ns.out)
out.mkdir(parents=True, exist_ok=True)
sdk = Path(__file__).resolve().parents[2] / "Zagros-VPN-SDK"
if not (sdk / "sdk-marker.txt").is_file():
    raise SystemExit(4)
for name, content in (config.get("files") or {}).items():
    (out / name).write_text(content, encoding="utf-8")
print("aab outputs written", flush=True)
"""


def test_aab_job_threads_artifact_to_panel_and_script(tmp_path,
                                                       monkeypatch):
    monkeypatch.setenv("ZAGROS_BUILD_EXECUTOR", "local")
    repo, sha = make_repo(tmp_path, script=_AAB_ARGV_SCRIPT)
    sdk = _sdk_repo(tmp_path)
    panel = FakePanel(_doc(
        repo, sha,
        {"display_name": "T", "files": {"app.aab": "AAB-PAYLOAD"}}, sdk,
        platform="android", arch="arm64-v8a", artifact="aab"))
    result = run_build(
        _payload(platform="android", arch="arm64-v8a", artifact="aab"),
        panel=panel, workspace_base=tmp_path / "ws")
    assert result["ok"] is True
    assert panel.claims == [("b-1", "android", "arm64-v8a", "aab")]
    assert panel.fetches == [("b-1", "android", "arm64-v8a", "aab")]
    (upload,) = panel.uploads
    assert upload["artifact"] == "aab"
    assert upload["filename"] == "app.aab"
    assert upload["content"] == b"AAB-PAYLOAD"
    (report,) = panel.reports
    assert report["artifact"] == "aab"
    assert report["status"] == "success"
    assert "aab outputs written" in report["final_log"]
