"""PanelClient against a stub HTTP server: paths, auth, payloads, errors."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from zagros_builder.panel import PanelClient, PanelError


class _Stub:
    def __init__(self):
        self.routes: dict[tuple[str, str], tuple[int, dict]] = {}
        self.bytes_routes: dict[tuple[str, str], tuple[int, bytes]] = {}
        self.requests: list[dict] = []
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def _handler(self):
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def _serve(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                stub.requests.append({
                    "method": self.command, "path": self.path,
                    "authorization": self.headers.get("Authorization"),
                    "worker_id": self.headers.get("X-Zagros-Worker-Id"),
                    "content_type": self.headers.get("Content-Type"),
                    "body": body,
                })
                if (self.command, self.path) in stub.bytes_routes:
                    status, data = stub.bytes_routes[
                        (self.command, self.path)]
                    self.send_response(status)
                    self.send_header("Content-Type", "application/zip")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
                status, payload = stub.routes.get(
                    (self.command, self.path),
                    (404, {"detail": {"error": "not_found",
                                      "message": "no route"}}))
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = _serve
            do_POST = _serve

            def log_message(self, *args):  # quiet
                pass

        return Handler

    @property
    def url(self):
        host, port = self._server.server_address
        return f"http://{host}:{port}"

    def close(self):
        self._server.shutdown()
        self._thread.join(timeout=5)


@pytest.fixture()
def stub():
    server = _Stub()
    yield server
    server.close()


def _client(stub, **overrides):
    params = {"job_token": "job-tok", "worker_id": "w-1",
              "worker_token": "w-tok"}
    params.update(overrides)
    return PanelClient(stub.url, **params)


def test_claim_posts_both_proofs(stub):
    stub.routes[("POST",
                 "/api/zagros/builder/jobs/b/android/arm64-v8a/claim")] = (
        200, {"status": "running"})
    client = _client(stub)
    try:
        assert client.claim("b", "android", "arm64-v8a") == {
            "status": "running"}
        (request,) = stub.requests
        assert request["authorization"] == "Bearer job-tok"
        assert json.loads(request["body"]) == {
            "worker_id": "w-1", "worker_token": "w-tok"}
    finally:
        client.close()


def test_fetch_status_and_heartbeat(stub):
    stub.routes[("GET",
                 "/api/zagros/builder/jobs/b/linux/x64")] = (
        200, {"v": 1})
    stub.routes[("POST",
                 "/api/zagros/builder/jobs/b/linux/x64/status")] = (
        200, {"status": "success"})
    stub.routes[("POST",
                 "/api/zagros/builder/workers/heartbeat")] = (
        200, {"status": "active"})
    client = _client(stub)
    try:
        assert client.fetch_job("b", "linux", "x64") == {"v": 1}
        assert client.report_status(
            "b", "linux", "x64", status="failed",
            failure_code="build_failed", failure_message="m",
            final_log="log")["status"] == "success"
        assert client.heartbeat()["status"] == "active"
        status_request = stub.requests[1]
        assert json.loads(status_request["body"])["final_log"] == "log"
        heartbeat = stub.requests[2]
        assert heartbeat["authorization"] == "Bearer w-tok"
        assert heartbeat["worker_id"] == "w-1"
    finally:
        client.close()


def test_upload_is_multipart_with_checksum_fields(stub):
    stub.routes[("POST",
                 "/api/zagros/builder/jobs/b/linux/x64/artifacts")] = (
        200, {"filename": "a.apk"})
    client = _client(stub)
    try:
        client.upload_artifact(
            "b", "linux", "x64", filename="a.apk", content=b"BYTES",
            sha256="0" * 64, size_bytes=5, toolchain={"builder": "0.1.0"})
        (request,) = stub.requests
        assert request["content_type"].startswith("multipart/form-data")
        assert b"a.apk" in request["body"]
        assert b"BYTES" in request["body"]
        assert b"sha256" in request["body"]
        assert b"builder" in request["body"]
    finally:
        client.close()


def test_register_and_error_mapping(stub):
    stub.routes[("POST",
                 "/api/zagros/builder/workers/register")] = (
        200, {"api_token": "tok", "status": "active"})
    enrolled = PanelClient.register(
        stub.url, "w-1", "reg-tok")
    assert enrolled["api_token"] == "tok"
    assert json.loads(stub.requests[0]["body"]) == {
        "worker_id": "w-1", "register_token": "reg-tok"}
    stub.routes[("GET", "/api/zagros/builder/jobs/b/linux/x64")] = (
        401, {"detail": {"error": "worker_authentication_failed",
                         "message": "bad token"}})
    client = _client(stub)
    try:
        with pytest.raises(PanelError) as error:
            client.fetch_job("b", "linux", "x64")
        assert error.value.status_code == 401
        assert error.value.error_code == "worker_authentication_failed"
    finally:
        client.close()


def test_unreachable_panel_maps_to_panel_unreachable():
    client = PanelClient("http://127.0.0.1:9", job_token="t",
                         timeout=2)
    try:
        with pytest.raises(PanelError) as error:
            client.fetch_job("b", "linux", "x64")
        assert error.value.error_code == "panel_unreachable"
    finally:
        client.close()


def test_from_env_requires_identity(monkeypatch, tmp_path):
    monkeypatch.setenv("ZAGROS_PANEL_URL", "http://panel.test")
    monkeypatch.delenv("ZAGROS_WORKER_ID", raising=False)
    monkeypatch.delenv("ZAGROS_WORKER_API_TOKEN", raising=False)
    with pytest.raises(PanelError):
        PanelClient.from_env(job_token="t")
    token_file = tmp_path / "w.token"
    token_file.write_text("file-token\n")
    monkeypatch.setenv("ZAGROS_WORKER_ID", "w-1")
    monkeypatch.setenv("ZAGROS_WORKER_TOKEN_FILE", str(token_file))
    client = PanelClient.from_env(job_token="t")
    assert client.worker_id == "w-1"
    client.close()


def test_aab_jobs_select_siblings_via_query(stub):
    stub.routes[("POST",
                 "/api/zagros/builder/jobs/b/android/arm64-v8a"
                 "/claim?artifact=aab")] = (200, {"status": "running"})
    stub.routes[("GET",
                 "/api/zagros/builder/jobs/b/android/arm64-v8a"
                 "?artifact=aab")] = (200, {"v": 2})
    stub.routes[("POST",
                 "/api/zagros/builder/jobs/b/android/arm64-v8a"
                 "/status?artifact=aab")] = (200, {"status": "success"})
    stub.routes[("POST",
                 "/api/zagros/builder/jobs/b/android/arm64-v8a"
                 "/artifacts?artifact=aab")] = (200, {"filename": "a.aab"})
    client = _client(stub)
    try:
        client.claim("b", "android", "arm64-v8a", artifact="aab")
        client.fetch_job("b", "android", "arm64-v8a", artifact="aab")
        client.report_status("b", "android", "arm64-v8a", artifact="aab",
                             status="success")
        client.upload_artifact("b", "android", "arm64-v8a", artifact="aab",
                               filename="a.aab", content=b"B",
                               sha256="1" * 64, size_bytes=1)
        assert [request["path"] for request in stub.requests] == [
            "/api/zagros/builder/jobs/b/android/arm64-v8a"
            "/claim?artifact=aab",
            "/api/zagros/builder/jobs/b/android/arm64-v8a?artifact=aab",
            "/api/zagros/builder/jobs/b/android/arm64-v8a"
            "/status?artifact=aab",
            "/api/zagros/builder/jobs/b/android/arm64-v8a"
            "/artifacts?artifact=aab",
        ]
    finally:
        client.close()


def test_apk_keeps_the_historical_paths(stub):
    stub.routes[("POST",
                 "/api/zagros/builder/jobs/b/android/arm64-v8a/claim")] = (
        200, {"status": "running"})
    client = _client(stub)
    try:
        client.claim("b", "android", "arm64-v8a")
        client.claim("b", "android", "arm64-v8a", artifact="apk")
        assert [request["path"] for request in stub.requests] == [
            "/api/zagros/builder/jobs/b/android/arm64-v8a/claim",
            "/api/zagros/builder/jobs/b/android/arm64-v8a/claim",
        ]
    finally:
        client.close()


def test_fetch_icon_pack_returns_raw_bytes(stub):
    blob = b"PK\x03\x04" + bytes(range(256)) * 4
    stub.bytes_routes[("GET",
                       "/api/zagros/builder/jobs/b/android/arm64-v8a/icon")] = (
        200, blob)
    client = _client(stub)
    try:
        assert client.fetch_icon_pack("b", "android", "arm64-v8a") == blob
        (request,) = stub.requests
        assert request["authorization"] == "Bearer job-tok"
    finally:
        client.close()


def test_fetch_icon_pack_maps_404(stub):
    client = _client(stub)
    try:
        with pytest.raises(PanelError) as exc_info:
            client.fetch_icon_pack("b", "android", "arm64-v8a")
        assert exc_info.value.status_code == 404
    finally:
        client.close()
