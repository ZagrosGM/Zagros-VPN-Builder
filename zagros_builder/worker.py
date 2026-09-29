"""RQ job entry: execute one platform build end to end.

``run_build`` is referenced BY STRING from the panel
(``zagros_builder.worker.run_build``) so the panel never imports this
package. RQ calls it with a single positional argument; everything else
defaults from the worker environment, and tests inject doubles.

Reporting contract: once the panel has been told a terminal state, the
function RETURNS (does not raise) so RQ stays quiet — the panel row is
the record. It RAISES only when the panel could not be reached at all
(claim/fetch/report transport failure): loud in the RQ failed registry
instead of silently stuck. A job left ``running`` in SQL after such a
failure needs an operator cancel — redispatch from a stuck claim is a
documented gap, not a silent retry.
"""
from __future__ import annotations

import hashlib
import os
import platform as _platform
import secrets
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

from zagros_builder import BUILDER_VERSION
from zagros_builder.gitops import CloneError, GitOps, create_workspace
from zagros_builder.jobs import (
    BUILD_ENTRY_SCRIPT,
    JobValidationError,
    signing_seed,
    ssh_credentials,
    validate_icon_pack,
    validate_job_document,
    validate_rq_payload,
)
from zagros_builder.logs import (
    LineSplitter,
    MemoryLogSink,
    RedactSink,
    RedisLogSink,
    TeeLogSink,
)
from zagros_builder.guard import ResourceError, preflight
from zagros_builder.panel import PanelClient, PanelError
from zagros_builder.provision import ensure_toolchain
from zagros_builder.redact import redact_text
from zagros_builder.ssh import (
    ExecError,
    ExecTimeout,
    Executor,
    LocalExecutor,
    ParamikoSSHExecutor,
    SSHConfigError,
    SSHOptions,
)

# Directory name of the SDK checkout inside the job workspace. Pinned by
# convention, not configuration: the client repo resolves its SDK path
# dependency as a sibling directory with exactly this name
# (``../../../Zagros-VPN-SDK`` from the app/package pubspecs), so the
# worker must reproduce that layout. The client repo pins the other end
# of the convention with a unit test over its own pubspecs.
SDK_CHECKOUT_DIRNAME = "Zagros-VPN-SDK"


def toolchain_manifest(executor: Executor, host: str = "") -> dict[str, str]:
    manifest = {
        "builder": BUILDER_VERSION,
        "contract": "1",
        "python": _platform.python_version(),
        "system": f"{_platform.system()}-{_platform.machine()}",
        "executor": "local" if executor.is_local else "ssh",
    }
    if host:
        manifest["host"] = host
    return manifest


def default_executor_factory(job_doc: dict) -> Executor:
    """Local unless the job carries an SSH host assignment.

    Refuses ambiguous setups loudly instead of building on the wrong
    machine: a local-only worker never silently accepts an SSH-assigned
    job, and an ssh-forced worker never silently builds locally.
    """
    forced = os.environ.get("ZAGROS_BUILD_EXECUTOR", "").strip().lower()
    assignments = ssh_credentials(job_doc)
    if forced == "local" and assignments:
        raise JobValidationError(
            "job carries an SSH host assignment but this worker is "
            "local-only (ZAGROS_BUILD_EXECUTOR=local)")
    if forced == "ssh" or (not forced and assignments):
        if not assignments:
            raise SSHConfigError(
                "ZAGROS_BUILD_EXECUTOR=ssh but the job has no ssh "
                "credential attached")
        material = assignments[0]["material"]
        options = SSHOptions.from_material(material)
        worker = ParamikoSSHExecutor(options)
        worker._assignment_host = options.host  # noqa: SLF001 - manifest only
        return worker
    if forced and forced != "local":
        raise SSHConfigError(
            f"unknown ZAGROS_BUILD_EXECUTOR='{forced}' (want local|ssh)")
    return LocalExecutor()


def _env_int(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, "") or default))
    except ValueError:
        return default


def run_build(payload: dict, *, panel: PanelClient | None = None,
              make_executor: Callable[[dict], Executor] | None = None,
              workspace_base: str | Path | None = None,
              redis_url: str | None = None,
              close_panel: bool = True) -> dict[str, Any]:
    """Execute one platform job. See the module docstring for the contract."""
    try:
        rq_payload = validate_rq_payload(payload)
    except JobValidationError as exc:
        return {"ok": False, "reported": False,
                "failure_code": "config_invalid",
                "error": f"invalid RQ payload: {exc}"}
    build_id = rq_payload["build_public_id"]
    target_platform = rq_payload["platform"]
    arch = rq_payload["arch"]
    job_token = rq_payload["job_token"]
    artifact = rq_payload["artifact"]

    memory = MemoryLogSink()
    tee = TeeLogSink(memory)
    log = RedactSink(tee).emit
    splitter = LineSplitter(RedactSink(tee))

    def _log_line(text: str) -> None:
        log(text)

    owned_panel = panel is None
    if panel is None:
        try:
            panel = PanelClient.from_env(job_token=job_token)
        except PanelError as exc:
            return {"ok": False, "reported": False,
                    "failure_code": "config_invalid",
                    "error": f"worker misconfigured: {exc}"}
    assert panel is not None
    worker_id = panel.worker_id or ""
    claimed = False
    executor: Executor | None = None
    workdir = ""
    try:
        try:
            panel.claim(build_id, target_platform, arch,
                          artifact=artifact)
        except PanelError as exc:
            if exc.status_code in (401, 403, 404, 409) or exc.error_code in (
                    "worker_authentication_failed", "build_not_found",
                    "build_conflict"):
                # Auth/rejections are final: no claim exists to report
                # against, and retrying would fail identically.
                return {"ok": False, "reported": False,
                        "failure_code": "worker_error",
                        "error": f"claim rejected: {exc}"}
            raise
        claimed = True
        _log_line(f"claimed {build_id} {target_platform}/{arch} "
                  f"as {worker_id}" +
                  (f" artifact={artifact}" if artifact != "apk" else ""))
        try:
            job_doc = validate_job_document(
                panel.fetch_job(build_id, target_platform, arch,
                                artifact=artifact))
            # the fetched document is authoritative; tolerate legacy
            # panels that predate the artifact key (implicit apk).
            artifact = str(job_doc.get("artifact") or "apk").strip().lower()
        except PanelError as exc:
            if exc.status_code in (401, 403, 404):
                return {"ok": False, "reported": False,
                        "failure_code": "worker_error",
                        "error": f"job fetch rejected: {exc}"}
            if exc.status_code == 409:
                # Terminal conflict (e.g. an attached credential was
                # revoked after dispatch): the token still works, so
                # report instead of sticking at running.
                return _report_failure(
                    panel, memory, build_id, target_platform, arch,
                    artifact,
                    "credential_revoked", f"job fetch refused: {exc}")
            raise
        _log_line(f"source {job_doc['source']['repo']} "
                  f"@ {job_doc['source']['revision'][:12]}")
        icon_ref = job_doc.get("icon")
        icon_ref = icon_ref if isinstance(icon_ref, dict) else {}
        want_icon = bool(icon_ref.get("present"))
        if want_icon and target_platform != "android":
            # Packs only exist for android; other platforms ignore them.
            # (A loud failure here would brick every iOS/linux build of
            # an app that happens to carry an icon.)
            _log_line("launcher icon advertised but only android embeds "
                      "it — continuing with stock icons")
            want_icon = False
        icon_pack: bytes | None = None
        if want_icon:
            try:
                icon_pack = panel.fetch_icon_pack(
                    build_id, target_platform, arch, artifact=artifact)
            except PanelError as exc:
                if exc.status_code == 404:
                    return _report_failure(
                        panel, memory, build_id, target_platform, arch,
                        artifact,
                        "icon_unavailable",
                        f"job advertises a launcher icon but the panel "
                        f"serves none: {exc}")
                raise
            try:
                icon_pack = validate_icon_pack(icon_pack, icon_ref)
            except JobValidationError as exc:
                return _report_failure(
                    panel, memory, build_id, target_platform, arch,
                    artifact, "icon_corrupt", str(exc))
            _log_line(
                f"launcher icon pack verified ({len(icon_pack)} bytes, "
                f"sha256:{hashlib.sha256(icon_pack).hexdigest()[:12]}…)")
        stream = str(job_doc.get("log_stream") or "")
        redis_target = (redis_url if redis_url is not None
                        else os.environ.get("ZAGROS_REDIS_URL"))
        if stream and redis_target:
            tee.add_sink(RedisLogSink(redis_target, stream))

        factory = make_executor or default_executor_factory
        executor = factory(job_doc)
        _log_line("executor: "
                  f"{'local' if executor.is_local else 'ssh'}")

        local_base = Path(workspace_base or os.environ.get(
            "ZAGROS_BUILD_WORKSPACE", Path(tempfile.gettempdir())
            / "zagros-builds"))
        local_root = create_workspace(
            local_base, build_id, target_platform, arch)
        gitops = GitOps(executor, scratch=local_root / "scratch")
        if executor.is_local:
            workdir = str(local_root)
            src_dir = str(local_root / "src")
            sdk_dir = str(local_root / SDK_CHECKOUT_DIRNAME)
            out_dir = str(local_root / "out")
        else:
            remote_base = (os.environ.get(
                "ZAGROS_REMOTE_WORKSPACE_BASE", "/tmp").rstrip("/") or "/tmp")
            workdir = (f"{remote_base}/zagros-{build_id[:8]}-"
                       f"{target_platform}-{arch}-{secrets.token_hex(4)}")
            src_dir = f"{workdir}/src"
            sdk_dir = f"{workdir}/{SDK_CHECKOUT_DIRNAME}"
            out_dir = f"{workdir}/out"
            gitops.prepare_dir(workdir)
        _log_line(f"workspace {workdir}")

        # f-panel-1: resource gate BEFORE any clone/toolchain work —
    # snapshot cpu/mem/swap/disk, create swap when short (root
    # linux only), and produce the limit wrapper (systemd-run or
    # nice). Remote hosts also get the idempotent toolchain
    # bootstrap (apt + flutter + android cmd-tools).
        guard_info = preflight(executor, log=_log_line,
                               platform=target_platform,
                               workspace_path=workdir)
        env_overrides = dict(guard_info.get("env") or {})
        argv_prefix = list(guard_info.get("argv_prefix") or [])
        if not executor.is_local:
            env_overrides.update(ensure_toolchain(
                executor, log=_log_line, platform=target_platform))

        source = job_doc["source"]
        _log_line("cloning pinned source…")
        gitops.clone(source["repo"], source["revision"], src_dir,
                     output=splitter.feed,
                     timeout=_env_int("ZAGROS_CLONE_TIMEOUT", 900))
        splitter.flush()
        _log_line("source verified at pinned revision")
        sdk = job_doc["sdk_source"]
        _log_line(f"cloning pinned SDK source into ./{SDK_CHECKOUT_DIRNAME}…")
        gitops.clone(sdk["repo"], sdk["revision"], sdk_dir,
                     output=splitter.feed,
                     timeout=_env_int("ZAGROS_CLONE_TIMEOUT", 900))
        splitter.flush()
        _log_line("sdk source verified at pinned revision")

        import json as _json
        config_text = _json.dumps(
            job_doc["build_config"], ensure_ascii=False, indent=2,
            sort_keys=True) + "\n"
        config_path = (f"{workdir}/build_config.json"
                       if not executor.is_local
                       else str(local_root / "build_config.json"))
        gitops.write_text_file(config_path, config_text)
        extra_args: list[str] = []
        if icon_pack is not None:
            pack_name = "icon-pack.zip"
            if executor.is_local:
                pack_path = str(local_root / pack_name)
                Path(pack_path).write_bytes(icon_pack)
            else:
                staging = local_root / "up" / pack_name
                staging.parent.mkdir(parents=True, exist_ok=True)
                staging.write_bytes(icon_pack)
                pack_path = f"{workdir}/{pack_name}"
                executor.put_file(staging, pack_path)
            extra_args = ["--icon-pack", pack_path]
            _log_line(f"launcher icon pack staged at {pack_path}")

        # App-attestation seed (f-panel-8): when the panel attached the
        # application's signing seed to this job, stage it as a 0600 file
        # in the job workspace and hand the build tool a PATH — the value
        # itself never appears in argv, env, or any log line.
        seed = signing_seed(job_doc)
        seed_path: str | None = None
        if seed:
            seed_name = ".app_attestation_seed"
            seed_path = (f"{workdir}/{seed_name}" if not executor.is_local
                         else str(local_root / seed_name))
            gitops.write_text_file(seed_path, seed + "\n")
            try:
                executor.run(["chmod", "600", seed_path], timeout=60)
            except Exception:  # noqa: BLE001 — hardening is best-effort
                pass
            extra_args = extra_args + ["--signing-seed-file", seed_path]
            _log_line("app attestation seed staged for the build "
                      "(value never logged)")

        script_rel = BUILD_ENTRY_SCRIPT
        script_path = f"{src_dir}/{script_rel}"
        if not executor.exists(script_path):
            raise JobValidationError(
                f"checked-out source has no '{script_rel}' "
                f"(client repo does not implement job contract v1)")
        gitops.prepare_dir(out_dir)
        interpreter = (sys.executable if executor.is_local else "python3")
        _log_line(f"running {script_rel} for "
                  f"{target_platform}/{arch}" +
                  (f" artifact={artifact}" if artifact != "apk" else "") +
                  "…")
        try:
            contract_argv = (
                argv_prefix
                + [interpreter, script_path, "--config", config_path,
                   "--platform", target_platform, "--arch", arch,
                   "--artifact", artifact, "--out", out_dir]
                + extra_args)
            result = executor.run(
                contract_argv,
                timeout=_env_int("ZAGROS_BUILD_TIMEOUT", 18000),
                env=env_overrides or None,
                output=splitter.feed)
        finally:
            splitter.flush()
            if seed_path is not None:
                # The build tool deletes the seed file itself; this covers
                # any earlier exit so the secret never outlives the job.
                try:
                    if executor.is_local:
                        Path(seed_path).unlink(missing_ok=True)
                    else:
                        executor.run(["rm", "-f", seed_path], timeout=60)
                except Exception:  # noqa: BLE001 — best-effort cleanup
                    pass
        if result.returncode != 0:
            tail = (result.stderr or result.stdout).decode(
                "utf-8", "replace").strip().splitlines()[-20:]
            raise ExecError(
                [script_rel], result.returncode,
                stderr_tail="\n".join(tail).encode("utf-8"))
        _log_line("build script exited 0 — collecting outputs…")

        entries = [name for name in executor.list_dir(out_dir)
                   if not name.startswith(".")]
        if not entries:
            raise _NoOutputs()
        host = getattr(executor, "_assignment_host", "")
        manifest = toolchain_manifest(executor, host)
        uploaded = 0
        for name in sorted(entries):
            if executor.is_local:
                data = Path(out_dir, name).read_bytes()
            else:
                staging = local_root / "dl" / name
                executor.get_file(f"{out_dir}/{name}", staging)
                data = staging.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            panel.upload_artifact(
                build_id, target_platform, arch, artifact=artifact,
                filename=name, content=data, sha256=digest,
                size_bytes=len(data), toolchain=manifest)
            uploaded += 1
            _log_line(f"uploaded {name} ({len(data)} bytes, "
                      f"sha256:{digest[:12]}…)")
        splitter.flush()
        panel.report_status(
            build_id, target_platform, arch, artifact=artifact,
            status="success", final_log=memory.text)
        return {"ok": True, "reported": True, "artifacts": uploaded}
    except PanelError as exc:
        # Panel transport failures are LOUD (RQ failed registry): the SQL
        # row may be stuck at running and needs an operator cancel.
        if exc.error_code in ("panel_unreachable", "panel_error") and (
                exc.status_code in (0, 500, 502, 503, 504)):
            raise
        if claimed:
            return _report_failure(
                panel, memory, build_id, target_platform, arch,
                artifact,
                "panel_error", f"panel error: {exc}")
        return {"ok": False, "reported": False,
                "failure_code": "panel_error",
                "error": f"panel error before claim: {exc}"}
    except ResourceError as exc:
        return _finish_failure(
            panel, memory, claimed, build_id, target_platform, arch,
            artifact,
            exc.code, str(exc))
    except (JobValidationError, SSHConfigError) as exc:
        return _finish_failure(
            panel, memory, claimed, build_id, target_platform, arch,
            artifact,
            "config_invalid", str(exc))
    except CloneError as exc:
        code = {"clone": "clone_failed"}.get(exc.stage, "checkout_failed")
        return _finish_failure(
            panel, memory, claimed, build_id, target_platform, arch,
            artifact,
            code, str(exc))
    except _NoOutputs:
        return _finish_failure(
            panel, memory, claimed, build_id, target_platform, arch,
            artifact,
            "no_artifacts",
            "build script exited 0 but produced no output files")
    except ExecTimeout as exc:
        return _finish_failure(
            panel, memory, claimed, build_id, target_platform, arch,
            artifact,
            "timeout", str(exc))
    except ExecError as exc:
        detail = (exc.stderr_tail or exc.stdout_tail).decode(
            "utf-8", "replace").strip()
        message = f"build script failed (exit {exc.returncode})"
        if detail:
            message += f": {detail[-1500:]}"
        return _finish_failure(
            panel, memory, claimed, build_id, target_platform, arch,
            artifact,
            "build_failed", message)
    except Exception as exc:  # noqa: BLE001 - last resort: report, don't vanish
        return _finish_failure(
            panel, memory, claimed, build_id, target_platform, arch,
            artifact,
            "worker_error", f"{type(exc).__name__}: {exc}")
    finally:
        try:
            if executor is not None and workdir:
                # Local roots are fully removed (they contain the source +
                # outputs); remote workdirs are rm -rf'd over SSH.
                GitOps(executor,
                       scratch=Path(tempfile.gettempdir())).cleanup(workdir)
        except Exception:
            pass
        if executor is not None:
            try:
                executor.close()
            except Exception:
                pass
        if owned_panel and close_panel and panel is not None:
            try:
                panel.close()
            except Exception:
                pass


class _NoOutputs(Exception):
    pass


def _report_failure(panel: PanelClient, memory: MemoryLogSink, build: str,
                    platform: str, arch: str, artifact: str, code: str,
                    message: str) -> dict[str, Any]:
    safe = redact_text(message, max_bytes=2000)
    try:
        panel.report_status(
            build, platform, arch, artifact=artifact, status="failed",
            failure_code=code, failure_message=safe,
            final_log=memory.text)
    except PanelError:
        raise
    return {"ok": False, "reported": True, "failure_code": code,
            "error": safe}


def _finish_failure(panel: PanelClient, memory: MemoryLogSink,
                    claimed: bool, build: str, platform: str, arch: str,
                    artifact: str, code: str, message: str,
                    ) -> dict[str, Any]:
    if not claimed:
        return {"ok": False, "reported": False, "failure_code": code,
                "error": redact_text(message, max_bytes=2000)}
    return _report_failure(panel, memory, build, platform, arch, artifact,
                           code, message)
