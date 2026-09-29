"""Job-contract validation (worker side, trust-boundary re-checks)."""
from __future__ import annotations

import pytest

from conftest import config_digest
from zagros_builder.jobs import (
    JobValidationError,
    signing_seed,
    ssh_credentials,
    validate_icon_pack,
    validate_job_document,
    validate_rq_payload,
)


SDK = {"repo": "https://github.com/ZagrosGM/Zagros-VPN-SDK.git",
       "revision": "e" * 40}


def _payload(**overrides):
    body = {"v": 2, "build_public_id": "b1", "platform": "android",
            "arch": "arm64-v8a", "job_token": "tok"}
    body.update(overrides)
    return body


def _doc(**overrides):
    config = {"display_name": "T"}
    doc = {"v": 2, "build_public_id": "b1", "version": "1.0.0",
           "build_number": 1, "platform": "android", "arch": "arm64-v8a",
           "source": {"repo": "https://github.com/ZagrosGM/Zagros-VPN.git",
                      "revision": "d" * 40},
           "sdk_source": dict(SDK),
           "build_config": config, "config_digest": config_digest(config),
           "credentials": [], "log_stream": "s"}
    doc.update(overrides)
    return doc


def test_valid_payload_and_document_pass():
    assert validate_rq_payload(_payload())["job_token"] == "tok"
    assert validate_job_document(_doc())["build_public_id"] == "b1"


def test_payload_rejects_wrong_version_and_missing_fields():
    with pytest.raises(JobValidationError):
        validate_rq_payload(_payload(v=1))
    with pytest.raises(JobValidationError):
        validate_rq_payload(_payload(v=99))
    with pytest.raises(JobValidationError):
        validate_rq_payload(_payload(job_token=""))
    with pytest.raises(JobValidationError):
        validate_rq_payload(_payload(platform="symbian"))
    with pytest.raises(JobValidationError):
        validate_rq_payload("nope")


def test_document_rejects_unpinned_source_and_digest_mismatch():
    with pytest.raises(JobValidationError):
        validate_job_document(_doc(source={
            "repo": "https://github.com/ZagrosGM/Zagros-VPN.git",
            "revision": "main"}))
    with pytest.raises(JobValidationError):
        validate_job_document(_doc(source={
            "repo": "http://insecure.test/r.git", "revision": "d" * 40}))
    tampered = _doc()
    tampered["build_config"] = {"display_name": "Tampered"}
    with pytest.raises(JobValidationError, match="digest"):
        validate_job_document(tampered)


def test_document_accepts_file_mirrors_and_validates_credentials():
    doc = _doc(source={"repo": "file:///srv/m.git", "revision": "d" * 40},
               credentials=[{"public_id": "c", "kind": "ssh_password",
                             "label": "vps", "material": {"host": "h"}}])
    assert validate_job_document(doc)
    with pytest.raises(JobValidationError):
        validate_job_document(_doc(source={"repo": "file:relative.git",
                                           "revision": "d" * 40}))
    with pytest.raises(JobValidationError):
        validate_job_document(_doc(credentials=[{"kind": "x"}]))


def test_document_requires_a_pinned_sdk_source():
    doc = _doc()
    del doc["sdk_source"]
    with pytest.raises(JobValidationError, match="sdk_source"):
        validate_job_document(doc)
    with pytest.raises(JobValidationError, match="contract"):
        validate_job_document(_doc(v=1))
    with pytest.raises(JobValidationError, match="sdk_source"):
        validate_job_document(_doc(sdk_source={
            "repo": "https://github.com/ZagrosGM/Zagros-VPN-SDK.git",
            "revision": "main"}))
    with pytest.raises(JobValidationError, match="sdk_source"):
        validate_job_document(_doc(sdk_source={
            "repo": "http://insecure.test/sdk.git",
            "revision": "e" * 40}))
    with pytest.raises(JobValidationError, match="sdk_source"):
        validate_job_document(_doc(sdk_source=None))


def test_ssh_credentials_selects_host_assignments_only():
    doc = _doc(credentials=[
        {"kind": "ssh_password", "material": {"host": "h"}},
        {"kind": "signing_key", "material": {"key": "k"}},
        {"kind": "ssh_key", "material": {}},
    ])
    assert ssh_credentials(doc) == [
        {"kind": "ssh_password", "material": {"host": "h"}}]


def test_payload_and_document_default_artifact_to_apk():
    assert validate_rq_payload(_payload())["artifact"] == "apk"
    assert "artifact" not in _doc()  # legacy panels omit the key
    validate_job_document(_doc())  # ... and still validate


def test_payload_and_document_enforce_aab_rules():
    assert validate_rq_payload(
        _payload(artifact="aab"))["artifact"] == "aab"
    assert validate_rq_payload(
        _payload(artifact=" AAB "))["artifact"] == "aab"
    validate_job_document(_doc(artifact="aab"))
    with pytest.raises(JobValidationError):
        validate_rq_payload(_payload(artifact="abb"))
    with pytest.raises(JobValidationError):
        validate_rq_payload(_payload(artifact=""))
    with pytest.raises(JobValidationError):
        validate_rq_payload(_payload(platform="linux", arch="x64",
                                     artifact="aab"))
    with pytest.raises(JobValidationError):
        validate_job_document(_doc(platform="linux", arch="x64",
                                   artifact="aab"))
    with pytest.raises(JobValidationError):
        validate_job_document(_doc(artifact="dmg"))


def _pack_bytes():
    import hashlib
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("mipmap-mdpi/ic_launcher.png", b"\x89PNG\r\n\x1a\n" + bytes(64))
    blob = buf.getvalue()
    return blob, {"present": True, "sha256": hashlib.sha256(blob).hexdigest(),
                  "size_bytes": len(blob)}


def test_icon_pack_verifies_and_returns_bytes():
    blob, ref = _pack_bytes()
    assert validate_icon_pack(blob, ref) == blob
    assert validate_icon_pack(bytearray(blob), ref) == blob


def test_icon_pack_rejects_empty_nonzip_and_drift():
    blob, ref = _pack_bytes()
    with pytest.raises(JobValidationError, match="empty"):
        validate_icon_pack(b"", ref)
    with pytest.raises(JobValidationError, match="not a zip"):
        validate_icon_pack(b'{"not": "a zip"}', ref)
    bad = bytearray(blob)
    bad[20] ^= 0xFF
    with pytest.raises(JobValidationError, match="sha256 mismatch"):
        validate_icon_pack(bytes(bad), ref)
    with pytest.raises(JobValidationError, match="size mismatch"):
        validate_icon_pack(blob, {**ref, "size_bytes": len(blob) + 1})
    with pytest.raises(JobValidationError, match="invalid size"):
        validate_icon_pack(blob, {**ref, "size_bytes": "huge"})
    # refs without hashes still enforce the zip shape
    assert validate_icon_pack(blob, {"present": True}) == blob
    assert validate_icon_pack(blob, None) == blob


_SEED = "A" * 43  # 32 bytes, base64url unpadded


def _signing_cred(seed=_SEED):
    return {"public_id": "b1-app-signing", "kind": "signing_key",
            "label": "application attestation seed (per-job)",
            "material": {"seed": seed}}


def test_document_accepts_wellformed_signing_seed():
    doc = _doc(credentials=[_signing_cred()])
    assert validate_job_document(doc)["build_public_id"] == "b1"
    assert signing_seed(doc) == _SEED


def test_document_rejects_malformed_signing_seed():
    for bad in ("short", "A" * 42, "A" * 44, "A" * 43 + "=", "A" * 42 + "/",
                None, 12345):
        with pytest.raises(JobValidationError, match="signing_key"):
            validate_job_document(_doc(credentials=[_signing_cred(seed=bad)]))


def test_document_rejects_signing_key_without_seed_field():
    with pytest.raises(JobValidationError, match="signing_key"):
        validate_job_document(_doc(credentials=[
            {"public_id": "c", "kind": "signing_key",
             "label": "x", "material": {"key": "k"}}]))


def test_signing_seed_absent_or_ignored_for_other_kinds():
    assert signing_seed(_doc()) is None
    doc = _doc(credentials=[{"public_id": "c", "kind": "ssh_password",
                             "label": "vps", "material": {"seed": _SEED}}])
    assert validate_job_document(doc)
    assert signing_seed(doc) is None


def test_signing_seed_ignores_malformed_entry_without_validation():
    doc = _doc(credentials=[_signing_cred(seed="bogus")])
    assert signing_seed(doc) is None
