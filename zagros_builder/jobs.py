"""Job-contract validation (worker side).

The panel validates first; the worker re-validates everything it acts on
(source URL shape, pinned revision, target matrix, config digest) because
the RQ payload and the job document cross a trust boundary (Redis, HTTP).
The digest check proves the document is internally consistent (catches
corruption/truncation) — protection against *tampering* comes from TLS
plus the single-job token, not from this check.
"""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlsplit

from zagros_builder import JOB_CONTRACT_VERSION

# Client-repo build entry contract (v1): the checked-out source MUST
# provide this script; it receives --config/--platform/--arch/--out and
# writes finished release files directly into --out (top level only).
BUILD_ENTRY_SCRIPT = "tool/white_label_build.py"

PLATFORM_ARCHES: dict[str, frozenset[str]] = {
    "android": frozenset({"armeabi-v7a", "arm64-v8a", "x86_64"}),
    "ios": frozenset({"arm64"}),
    "windows": frozenset({"x64", "arm64"}),
    "linux": frozenset({"x64", "arm64"}),
    "macos": frozenset({"arm64", "x64"}),
}


# artifact kind per target (mirrors the panel + the contract script).
# Absent means "apk" (pre-Phase-17 panels); "aab" is android-only.
ARTIFACTS: tuple[str, ...] = ("apk", "aab", "zip", "tar.gz", "ipa")


class JobValidationError(ValueError):
    pass


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"))


def validate_rq_payload(payload: object) -> dict[str, str]:
    """Validate the minimal RQ payload (claim credentials only)."""
    if not isinstance(payload, dict):
        raise JobValidationError("job payload must be an object")
    if payload.get("v") != JOB_CONTRACT_VERSION:
        raise JobValidationError(
            f"unsupported job contract v{payload.get('v')} "
            f"(worker speaks v{JOB_CONTRACT_VERSION})")
    out: dict[str, str] = {}
    for field in ("build_public_id", "platform", "arch", "job_token"):
        value = payload.get(field)
        if not isinstance(value, str) or not value.strip():
            raise JobValidationError(f"job payload misses '{field}'")
        out[field] = value.strip()
    raw_artifact = payload.get("artifact", "apk")
    if not isinstance(raw_artifact, str) or not raw_artifact.strip():
        raise JobValidationError("job payload misses 'artifact'")
    out["artifact"] = raw_artifact.strip().lower()
    _check_target(out["platform"], out["arch"], out["artifact"])
    return out


def _check_pinned_source(source: object, *, what: str) -> None:
    if not isinstance(source, dict):
        raise JobValidationError(f"job document misses '{what}'")
    repo = source.get("repo")
    revision = source.get("revision")
    if not isinstance(repo, str):
        raise JobValidationError(f"job {what} repo must be a string")
    parsed = urlsplit(repo)
    if parsed.scheme == "https":
        if not parsed.hostname:
            raise JobValidationError(f"job {what} repo must be https/file")
    elif parsed.scheme == "file":
        if parsed.netloc not in ("", "localhost") or not parsed.path.startswith("/"):
            raise JobValidationError(
                f"job file:// {what} must be an absolute path")
    else:
        raise JobValidationError(
            f"job {what} repo must be an https URL or a file:// mirror")
    if (not isinstance(revision, str)
            or len(revision.strip()) != 40
            or any(c not in "0123456789abcdefABCDEF"
                   for c in revision.strip())):
        raise JobValidationError(
            f"job {what} revision must be a pinned 40-hex commit SHA")


def validate_job_document(doc: object) -> dict:
    """Validate the full job document fetched from the panel."""
    if not isinstance(doc, dict):
        raise JobValidationError("job document must be an object")
    if doc.get("v") != JOB_CONTRACT_VERSION:
        raise JobValidationError(
            f"unsupported job contract v{doc.get('v')}")
    for field in ("build_public_id", "version", "platform", "arch",
                  "config_digest", "log_stream"):
        value = doc.get(field)
        if not isinstance(value, str) or not value.strip():
            raise JobValidationError(f"job document misses '{field}'")
    raw_artifact = doc.get("artifact", "apk")
    if not isinstance(raw_artifact, str) or not raw_artifact.strip():
        raise JobValidationError("job document misses 'artifact'")
    _check_target(str(doc["platform"]), str(doc["arch"]),
                  raw_artifact.strip().lower())
    _check_pinned_source(doc.get("source"), what="source")
    # v2: no SDK pin, no build — a lone app checkout cannot resolve its
    # path dependency, so refuse here instead of failing at pub get.
    _check_pinned_source(doc.get("sdk_source"), what="sdk_source")
    config = doc.get("build_config")
    if not isinstance(config, dict):
        raise JobValidationError("job build_config must be an object")
    try:
        digest = hashlib.sha256(
            _canonical_json(config).encode("utf-8")).hexdigest()
    except (TypeError, ValueError) as exc:
        raise JobValidationError(
            f"job build_config is not JSON-serializable: {exc}") from exc
    if digest != str(doc["config_digest"]).strip().lower():
        raise JobValidationError(
            "job config_digest does not match build_config "
            "(corrupt or truncated document)")
    credentials = doc.get("credentials", [])
    if not isinstance(credentials, list):
        raise JobValidationError("job credentials must be a list")
    for entry in credentials:
        if not isinstance(entry, dict):
            raise JobValidationError("job credential must be an object")
        if not isinstance(entry.get("material"), dict):
            raise JobValidationError(
                "job credential misses its material object")
        for field in ("public_id", "kind", "label"):
            if not isinstance(entry.get(field), str):
                raise JobValidationError(
                    f"job credential misses '{field}'")
        if entry.get("kind") == "signing_key":
            seed = entry["material"].get("seed")
            if not isinstance(seed, str) or not _SEED_RE.fullmatch(seed):
                raise JobValidationError(
                    "job signing_key credential must carry a 43-char "
                    "base64url (32-byte) 'seed' in its material")
    return doc


# 32 raw bytes, base64url unpadded (43 chars) — the Ed25519 signing seed.
_SEED_RE = re.compile(r"[A-Za-z0-9_-]{43}")


def signing_seed(doc: dict) -> str | None:
    """The job's app-attestation signing seed, when the panel attached one.

    The panel only attaches it for builds of an application with an ACTIVE
    signing key, and only on the job-token-authenticated fetch; the worker
    stages it as a 0600 file and the build tool deletes it after consuming.
    """
    for entry in doc.get("credentials", []):
        if isinstance(entry, dict) and entry.get("kind") == "signing_key":
            seed = (entry.get("material") or {}).get("seed")
            if isinstance(seed, str) and _SEED_RE.fullmatch(seed):
                return seed
    return None


def validate_icon_pack(data: object, ref: object) -> bytes:
    """Verify a downloaded launcher pack against the job's icon ref.

    Returns the bytes for staging. Anything inconsistent (empty, not a
    zip, digest/size drift) fails loudly — a silently unbranded build is
    worse than a failed one.
    """
    if not isinstance(data, (bytes, bytearray)) or not data:
        raise JobValidationError("icon pack download is empty")
    blob = bytes(data)
    if blob[:4] != b"PK\x03\x04":
        raise JobValidationError("icon pack is not a zip archive")
    want = ""
    size: object = None
    if isinstance(ref, dict):
        want = str(ref.get("sha256") or "").strip().lower()
        size = ref.get("size_bytes")
    if want:
        got = hashlib.sha256(blob).hexdigest()
        if got != want:
            raise JobValidationError(
                "icon pack sha256 mismatch (corrupt download)")
    if size is not None:
        try:
            expected = int(size)
        except (TypeError, ValueError) as exc:
            raise JobValidationError(
                f"job icon ref carries an invalid size: {size!r}") from exc
        if expected != len(blob):
            raise JobValidationError(
                "icon pack size mismatch (truncated download)")
    return blob


def _check_target(platform: str, arch: str, artifact: str = "apk",
                ) -> None:
    cleaned_platform = platform.strip().lower()
    arches = PLATFORM_ARCHES.get(cleaned_platform)
    if arches is None:
        raise JobValidationError(f"unsupported platform '{platform}'")
    if arch.strip().lower() not in arches:
        raise JobValidationError(
            f"unsupported arch '{arch}' for platform '{platform}'")
    cleaned_artifact = artifact.strip().lower()
    if cleaned_artifact not in ARTIFACTS:
        raise JobValidationError(f"unsupported artifact '{artifact}'")
    if cleaned_artifact == "aab" and cleaned_platform != "android":
        raise JobValidationError(
            f"artifact 'aab' is only supported for android, "
            f"not '{platform}'")


def ssh_credentials(doc: dict) -> list[dict]:
    """Attached credentials usable as an SSH build-host assignment."""
    found = []
    for entry in doc.get("credentials", []):
        if not isinstance(entry, dict):
            continue
        if entry.get("kind") in ("ssh_password", "ssh_key"):
            material = entry.get("material")
            if isinstance(material, dict) and material.get("host"):
                found.append(entry)
    return found
