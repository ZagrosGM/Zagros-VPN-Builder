"""Full pipeline: panel -> real RQ -> worker -> real HTTP -> panel.

Needs the sibling ``Zagros`` panel checkout next to this repo (the
workspace layout); skipped otherwise. The panel API is served by a real
uvicorn over real localhost HTTP, dispatch goes through real Redis/RQ,
and the client source is a real git repo implementing the v1 contract.
"""
from __future__ import annotations

import socket
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

PANEL_ROOT = Path(__file__).resolve().parents[2] / "Zagros"

pytestmark = [
    pytest.mark.skipif(
        not (PANEL_ROOT / "app" / "builder" / "service.py").exists(),
        reason="sibling Zagros panel repo not present"),
]

REDIS_URL = "redis://127.0.0.1:6379/15"

CASES = [
    {"id": "apk", "platform": "linux", "arch": "x64", "artifact": "apk",
     "filename": "rt.apk", "payload": "ROUNDTRIP-PAYLOAD",
     "stream_suffix": ""},
    {"id": "aab", "platform": "android", "arch": "arm64-v8a",
     "artifact": "aab", "filename": "rt.aab",
     "payload": "ROUNDTRIP-AAB-PAYLOAD", "stream_suffix": ":aab"},
]


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_panel_to_redis_to_worker_to_panel(tmp_path, monkeypatch, case):
    rq = pytest.importorskip("rq")
    redis = pytest.importorskip("redis")
    uvicorn = pytest.importorskip("uvicorn")
    client = redis.Redis.from_url(REDIS_URL)
    try:
        client.ping()
    except Exception:
        pytest.skip("local Redis is not running")
    client.flushdb()
    sys.path.insert(0, str(PANEL_ROOT))

    from conftest import make_repo  # noqa: E402
    if __import__("shutil").which("git") is None:
        pytest.skip("git is not installed")

    from app.builder.artifacts import FileArtifactStore  # noqa: E402
    from app.builder.queue import BuildQueue  # noqa: E402
    from app.builder.repository import BuildRepository  # noqa: E402
    from app.builder.service import BuildService  # noqa: E402
    from app.builder.worker_router import builder_worker_router  # noqa: E402
    from app.persistence import (  # noqa: E402
        SecretsCipher,
        create_schema,
        create_session_factory,
        derive_key,
    )
    from app.persistence.models import (  # noqa: E402
        AdminModel,
        ApplicationModel,
    )
    from fastapi import FastAPI  # noqa: E402

    from zagros_builder.panel import PanelClient  # noqa: E402

    repo_dir, sha = make_repo(tmp_path)
    source_url = f"file://{repo_dir}"
    sdk_dir, sdk_sha = make_repo(
        tmp_path / "sdk", script=None,
        extra_files={"sdk-marker.txt": "sdk-pin-ok"})
    sdk_url = f"file://{sdk_dir}"
    sf = create_session_factory(f"sqlite:///{tmp_path / 'panel.db'}")
    create_schema(sf)
    service = BuildService(
        BuildRepository(sf, SecretsCipher(derive_key(
            "roundtrip-master-secret-32bytes!!",
            info=b"zagros/build-credentials/v1"))),
        BuildQueue(REDIS_URL), FileArtifactStore(tmp_path / "store"),
        source_allowlist=(source_url,), sdk_allowlist=(sdk_url,))
    with sf() as session:
        session.add(AdminModel(
            username="owner", password_hash="x", is_sudo=True))
        session.commit()
        admin_id = session.execute(
            __import__("sqlalchemy").select(AdminModel.id)).scalar_one()
        app_id = str(uuid4())
        session.add(ApplicationModel(
            public_id=app_id, owner_admin_id=admin_id, name="RT",
            status="active",
            api_base_url="https://panel.example.test/api/application/v1",
            default_lang="fa", branding={}))
        session.commit()

    service.create_worker(
        worker_id="roundtrip-w", display_name="RT",
        platform_labels=["linux"])
    register_token = service.issue_register_token(
        "roundtrip-w")["register_token"]
    api_token = service.register_worker(
        "roundtrip-w", register_token)["api_token"]
    credential = service.store_credential(
        scope="application", owner_ref=app_id, kind="signing_key",
        label="signer", material={"key": "ROUNDTRIP-SECRET"})
    build = service.create_build(
        owner_admin_id=admin_id, application_public_id=app_id,
        version="3.1.0", source_repo=source_url, source_revision=sha,
        sdk_source_repo=sdk_url, sdk_source_revision=sdk_sha,
        build_config={"display_name": "RT",
                      "files": {case["filename"]: case["payload"]}},
        targets=[{"platform": case["platform"], "arch": case["arch"],
                  "artifact": case["artifact"]}],
        credential_ids=[credential["public_id"]])
    (target,) = build["targets"]
    assert target["queue"] == "builder:linux"

    asgi = FastAPI()
    asgi.state.zagros = SimpleNamespace(build_service=service)
    asgi.include_router(builder_worker_router)
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(
        asgi, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port),
                                     timeout=1).close()
            break
        except OSError:
            time.sleep(0.2)
    else:
        pytest.fail("test panel server did not start")

    real_from_env = PanelClient.from_env.__func__

    @classmethod
    def _local_from_env(cls, **kwargs):
        return PanelClient(
            f"http://127.0.0.1:{port}",
            job_token=kwargs["job_token"], worker_id="roundtrip-w",
            worker_token=api_token)

    monkeypatch.setattr(PanelClient, "from_env", _local_from_env)
    monkeypatch.setenv("ZAGROS_BUILD_WORKSPACE", str(tmp_path / "ws"))
    monkeypatch.setenv("ZAGROS_REDIS_URL", REDIS_URL)
    monkeypatch.setenv("ZAGROS_BUILD_EXECUTOR", "local")
    try:
        queue = rq.Queue("builder:linux", connection=client)
        assert queue.count == 1  # the panel really dispatched
        rq.SimpleWorker([queue], connection=client).work(burst=True)
    finally:
        monkeypatch.setattr(PanelClient, "from_env", real_from_env)
        server.should_exit = True
        thread.join(timeout=15)

    finished = rq.job.Job.fetch(target["queue_job_id"],
                                connection=client)
    assert finished.is_finished, finished.exc_info
    assert finished.return_value()["ok"] is True

    final = service.get_build(build["public_id"])
    assert final["status"] == "success"
    assert final["progress"] == 100
    (artifact,) = final["artifacts"]
    assert artifact["filename"] == case["filename"]
    assert artifact["artifact"] == case["artifact"]
    assert artifact["provenance"]["worker_id"] == "roundtrip-w"
    assert artifact["provenance"]["sdk_source_repo"] == sdk_url
    assert artifact["provenance"]["sdk_source_revision"] == sdk_sha
    path, _ = service.download_artifact(
        build["public_id"], platform=case["platform"], arch=case["arch"],
        filename=case["filename"])
    assert path.read_bytes() == case["payload"].encode()
    stream = (f"zagros:build:log:{build['public_id']}:"
              f"{case['platform']}:{case['arch']}{case['stream_suffix']}")
    assert client.xlen(stream) > 0
    transcript = repr(client.xread({stream: 0}, count=5000, block=None))
    if case["artifact"] == "aab":
        assert "contract artifact=aab" in transcript
    else:
        assert "contract artifact=" not in transcript
    assert list((tmp_path / "ws").iterdir()) == []
    client.flushdb()
    client.close()
