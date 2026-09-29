"""Remote toolchain bootstrap for SSH build hosts (idempotent).

Only called for **non-local** executors. Installs, in fixed locations,
exactly what a cold Android/Linux AOT build needs:

* apt packages: git, curl, unzip, xz-utils, OpenJDK 17 (headless)
* Flutter SDK (stable) → ``/opt/flutter`` (clone → ``flutter --version``
  warm-up so the Dart SDK is downloaded before the real build)
* Android cmdline-tools (pinned build) → ``/opt/android-sdk`` with
  licenses accepted and platform-tools installed. Remaining platform /
  build-tools / NDK packages are auto-installed by Gradle because the
  licenses are accepted up front.

Every step logs through the build log; a failing step raises
:class:`~zagros_builder.guard.ResourceError` with
``provision_failed`` so the job reports cleanly instead of dying deep
inside Gradle with a confusing toolchain error.

Non-Android/Linux targets are refused loudly: macOS/iOS need Xcode and
Windows needs MSVC — auto-provisioning those is out of scope.
"""
from __future__ import annotations

from .guard import ResourceError, _out, snapshot
from .ssh import ExecError, Executor

FLUTTER_DIR = "/opt/flutter"
ANDROID_DIR = "/opt/android-sdk"
# Pinned Android commandline-tools build (dl.google.com official bundle).
CMDTOOLS_URL = ("https://dl.google.com/android/repository/"
                "commandlinetools-linux-11076708_latest.zip")

_SUPPORTED = {"android", "linux"}
_APT_PKGS = "git curl unzip xz-utils openjdk-17-jdk-headless ca-certificates"


def _sudo_prefix(executor: Executor) -> str:
    root = executor.run(["sh", "-c", "test $(id -u) -eq 0"], check=False)
    if root.returncode == 0:
        return ""
    sudo = executor.run(["sh", "-c", "command -v sudo"], check=False)
    if sudo.returncode == 0:
        return "sudo "
    raise ResourceError(
        "provision_failed",
        "build host user is not root and sudo is unavailable — "
        "auto-provisioning needs privileged access")


def _sh(executor: Executor, script: str, *, log, timeout: int = 900,
        what: str) -> None:
    log(f"provision: {what} …")
    result = executor.run(["sh", "-c", script], timeout=timeout, check=False)
    if result.returncode != 0:
        tail = (result.stderr or result.stdout).decode(
            "utf-8", "replace").strip().splitlines()[-12:]
        raise ResourceError(
            "provision_failed",
            f"provisioning step '{what}' failed (exit "
            f"{result.returncode}): " + "\n".join(tail)[-1200:])


def _has(executor: Executor, probe: str) -> bool:
    return executor.run(["sh", "-c", probe], check=False).returncode == 0


def ensure_toolchain(executor: Executor, *, log, platform: str) -> dict:
    """Idempotent bootstrap; returns the env dict the build must run with."""
    if platform not in _SUPPORTED:
        raise ResourceError(
            "provision_unsupported",
            f"auto-provisioning supports android/linux hosts only, "
            f"not '{platform}' (macOS needs Xcode, Windows needs MSVC)")

    sudo = _sudo_prefix(executor)
    env: dict[str, str] = {
        "ANDROID_HOME": ANDROID_DIR,
        "ANDROID_SDK_ROOT": ANDROID_DIR,
        "PATH": (f"{FLUTTER_DIR}/bin:"
                 f"{ANDROID_DIR}/cmdline-tools/latest/bin:"
                 f"{ANDROID_DIR}/platform-tools:"
                 "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
    }

    apt_front = "DEBIAN_FRONTEND=noninteractive "
    _sh(executor,
        f"{apt_front}apt-get update -qq && {apt_front}"
        f"apt-get install -y -qq {_APT_PKGS} >/dev/null && echo apt-ok "
        f"|| {{ command -v git >/dev/null && command -v java >/dev/null "
        f"&& echo apt-ok; }}",
        log=log, timeout=1200, what="apt base packages (git/curl/jdk17)")
    if not _has(executor, "command -v git && command -v curl "
                          "&& command -v unzip && command -v java"):
        raise ResourceError(
            "provision_failed",
            "base tools (git/curl/unzip/java) are still missing after apt — "
            "is this a Debian/Ubuntu host with network access?")

    if not _has(executor, f"test -x {FLUTTER_DIR}/bin/flutter"):
        log(f"provision: installing Flutter SDK (stable) → {FLUTTER_DIR} "
            f"(first run downloads several hundred MB) …")
        _sh(executor,
            f"{sudo}rm -rf {FLUTTER_DIR} && "
            f"{sudo}git clone --depth 1 -b stable "
            f"https://github.com/flutter/flutter.git {FLUTTER_DIR} "
            f">/dev/null 2>&1 && echo clone-ok",
            log=log, timeout=1800, what="flutter clone")
    _sh(executor,
        f"{FLUTTER_DIR}/bin/flutter config --no-analytics >/dev/null 2>&1; "
        f"{FLUTTER_DIR}/bin/flutter --version",
        log=log, timeout=1800, what="flutter warm-up (Dart SDK bootstrap)")
    if not _has(executor, f"test -f {FLUTTER_DIR}/bin/cache/dart-sdk.version"):
        log("provision: WARNING — flutter cache marker missing after "
            "warm-up (build may re-bootstrap)")

    if not _has(executor,
                f"test -f {ANDROID_DIR}/cmdline-tools/latest/bin/sdkmanager"):
        log("provision: installing Android cmdline-tools → "
            f"{ANDROID_DIR} …")
        _sh(executor,
            f"{sudo}mkdir -p {ANDROID_DIR}/cmdline-tools && "
            f"{sudo}curl -fsSL -o /tmp/zagros-cmdtools.zip '{CMDTOOLS_URL}' && "
            f"{sudo}unzip -q -o /tmp/zagros-cmdtools.zip "
            f"-d {ANDROID_DIR}/cmdline-tools && "
            f"{sudo}rm -f /tmp/zagros-cmdtools.zip && "
            f"{sudo}test -d {ANDROID_DIR}/cmdline-tools/cmdline-tools && "
            f"{sudo}mv {ANDROID_DIR}/cmdline-tools/cmdline-tools "
            f"{ANDROID_DIR}/cmdline-tools/latest && echo cmdtools-ok",
            log=log, timeout=1200, what="cmdline-tools download")
        _sh(executor,
            f"{sudo}yes | {ANDROID_DIR}/cmdline-tools/latest/bin/sdkmanager "
            f"--licenses >/dev/null 2>&1; "
            f"{ANDROID_DIR}/cmdline-tools/latest/bin/sdkmanager "
            f"platform-tools >/dev/null && echo sdk-ok",
            log=log, timeout=1200, what="android licenses + platform-tools")

    snap = snapshot(executor, ANDROID_DIR)
    log(f"provision: toolchain ready "
        f"(flutter + android cmd-tools; {snap.disk_free_mb}MB disk free)")
    return env
