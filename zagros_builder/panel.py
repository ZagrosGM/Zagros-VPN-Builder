"""HTTP client for the panel's worker API (TLS + token authenticated)."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import httpx

from zagros_builder import BUILDER_VERSION

_USER_AGENT = f"zagros-builder/{BUILDER_VERSION}"


class PanelError(Exception):
    def __init__(self, message: str, *, status_code: int = 0,
                 error_code: str = "panel_error") -> None:
        self.status_code = status_code
        self.error_code = error_code
        super().__init__(message)


class PanelClient:
    def __init__(self, base_url: str, *, job_token: str | None = None,
                 worker_id: str | None = None,
                 worker_token: str | None = None,
                 timeout: int = 60, transport=None) -> None:
        if not base_url or not base_url.startswith(
                ("http://", "https://")):
            raise PanelError("panel base URL must be http(s)",
                             error_code="config_invalid")
        self._base_url = base_url.rstrip("/")
        self._job_token = job_token
        self._worker_id = worker_id
        self._worker_token = worker_token
        self._client = httpx.Client(
            base_url=self._base_url, timeout=timeout,
            transport=transport,
            headers={"User-Agent": _USER_AGENT})

    @classmethod
    def from_env(cls, *, job_token: str, transport=None,
                 timeout: int = 60) -> "PanelClient":
        base_url = (os.environ.get("ZAGROS_PANEL_URL") or "").strip()
        if not base_url:
            raise PanelError("ZAGROS_PANEL_URL is not set",
                             error_code="config_invalid")
        worker_id = (os.environ.get("ZAGROS_WORKER_ID") or "").strip()
        token = (os.environ.get("ZAGROS_WORKER_API_TOKEN") or "").strip()
        token_file = (os.environ.get("ZAGROS_WORKER_TOKEN_FILE") or "").strip()
        if not token and token_file:
            token = Path(token_file).read_text(
                encoding="utf-8").strip().splitlines()[0].strip()
        if not worker_id or not token:
            raise PanelError(
                "worker identity is not configured "
                "(ZAGROS_WORKER_ID + ZAGROS_WORKER_API_TOKEN/_FILE)",
                error_code="config_invalid")
        return cls(base_url, job_token=job_token, worker_id=worker_id,
                   worker_token=token, timeout=timeout, transport=transport)

    @property
    def worker_id(self) -> str | None:
        return self._worker_id

    def close(self) -> None:
        self._client.close()

    # ---------------------------------------------------------- #
    # low level
    # ---------------------------------------------------------- #
    def _request(self, method: str, path: str, *,
                 token: str | None = None, **kwargs) -> Any:
        headers = dict(kwargs.pop("headers", {}) or {})
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            response = self._client.request(
                method, path, headers=headers, **kwargs)
        except httpx.HTTPError as exc:
            raise PanelError(f"panel unreachable: {exc}",
                             error_code="panel_unreachable") from exc
        if 200 <= response.status_code < 300:
            if not response.content:
                return {}
            try:
                return response.json()
            except ValueError:
                return {"raw": response.text}
        try:
            body = response.json()
        except ValueError:
            body = {}
        if isinstance(body, dict):
            detail = body.get("detail", body)
            if isinstance(detail, dict):
                raise PanelError(
                    str(detail.get("message", response.text)),
                    status_code=response.status_code,
                    error_code=str(detail.get(
                        "error", "panel_error")))
            raise PanelError(str(detail), status_code=response.status_code,
                             error_code="panel_error")
        raise PanelError(response.text, status_code=response.status_code,
                         error_code="panel_error")

    def _request_bytes(self, method: str, path: str, *,
                       token: str | None = None, **kwargs) -> bytes:
        """Same error mapping as [_request], but returns raw bytes.

        For binary downloads (the launcher icon pack): the JSON path
        would text-decode and corrupt them.
        """
        headers = dict(kwargs.pop("headers", {}) or {})
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            response = self._client.request(
                method, path, headers=headers, **kwargs)
        except httpx.HTTPError as exc:
            raise PanelError(f"panel unreachable: {exc}",
                             error_code="panel_unreachable") from exc
        if 200 <= response.status_code < 300:
            return bytes(response.content)
        try:
            body = response.json()
        except ValueError:
            body = {}
        if isinstance(body, dict):
            detail = body.get("detail", body)
            if isinstance(detail, dict):
                raise PanelError(
                    str(detail.get("message", response.text)),
                    status_code=response.status_code,
                    error_code=str(detail.get(
                        "error", "panel_error")))
            raise PanelError(str(detail), status_code=response.status_code,
                             error_code="panel_error")
        raise PanelError(response.text, status_code=response.status_code,
                         error_code="panel_error")

    def _job_path(self, build: str, platform: str, arch: str,
                  suffix: str = "", artifact: str = "apk") -> str:
        # apk keeps the exact historical path; siblings select via query.
        query = "?artifact=aab" if artifact == "aab" else ""
        return (f"/api/zagros/builder/jobs/{build}/{platform}/{arch}"
                f"{suffix}{query}")

    # ---------------------------------------------------------- #
    # job lifecycle
    # ---------------------------------------------------------- #
    def claim(self, build: str, platform: str, arch: str, *,
                artifact: str = "apk") -> dict:
        return self._request(
            "POST", self._job_path(build, platform, arch, "/claim",
                                   artifact=artifact),
            token=self._job_token,
            json={"worker_id": self._worker_id,
                  "worker_token": self._worker_token})

    def fetch_job(self, build: str, platform: str, arch: str, *,
                    artifact: str = "apk") -> dict:
        return self._request(
            "GET", self._job_path(build, platform, arch,
                                  artifact=artifact),
            token=self._job_token)

    def fetch_icon_pack(self, build: str, platform: str, arch: str, *,
                        artifact: str = "apk") -> bytes:
        """Download the rendered launcher pack (job-token authed).

        404 means the application carries no icon; the caller fails the
        job loudly when the job document advertised one.
        """
        return self._request_bytes(
            "GET", self._job_path(build, platform, arch, "/icon",
                                  artifact=artifact),
            token=self._job_token)

    def report_status(self, build: str, platform: str, arch: str, *,
                      artifact: str = "apk", status: str,
                      failure_code: str | None = None,
                      failure_message: str | None = None,
                      final_log: str | None = None) -> dict:
        body: dict[str, Any] = {"status": status}
        if failure_code:
            body["failure_code"] = failure_code
        if failure_message:
            body["failure_message"] = failure_message
        if final_log is not None:
            body["final_log"] = final_log
        return self._request(
            "POST", self._job_path(build, platform, arch, "/status",
                                   artifact=artifact),
            token=self._job_token, json=body)

    def upload_artifact(self, build: str, platform: str, arch: str, *,
                        artifact: str = "apk", filename: str, content: bytes,
                        sha256: str, size_bytes: int,
                        toolchain: dict | None = None) -> dict:
        import json as _json
        data = {"sha256": sha256, "size_bytes": str(size_bytes)}
        if toolchain is not None:
            data["toolchain"] = _json.dumps(toolchain)
        return self._request(
            "POST", self._job_path(build, platform, arch, "/artifacts",
                                   artifact=artifact),
            token=self._job_token,
            files={"file": (filename, content,
                            "application/octet-stream")},
            data=data)

    # ---------------------------------------------------------- #
    # worker identity
    # ---------------------------------------------------------- #
    def heartbeat(self) -> dict:
        return self._request(
            "POST", "/api/zagros/builder/workers/heartbeat",
            token=self._worker_token,
            headers={"X-Zagros-Worker-Id": self._worker_id or ""})

    @staticmethod
    def register(base_url: str, worker_id: str, register_token: str, *,
                 timeout: int = 60, transport=None) -> dict:
        client = PanelClient(base_url, timeout=timeout, transport=transport)
        try:
            return client._request(
                "POST", "/api/zagros/builder/workers/register",
                json={"worker_id": worker_id,
                      "register_token": register_token})
        finally:
            client.close()
