"""Secret redaction for worker-authored text (logs, failure messages).

Deliberately independent from the panel's redactor: the builder repo
deploys on its own (no shared dependency across the trust boundary), so
both sides apply the same documented patterns and both sides are pinned
by the same planted-secret vectors. Redaction is best-effort BY DESIGN —
test the patterns, never claim completeness.
"""
from __future__ import annotations

import re

_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL)

_LABELED_SECRET = re.compile(
    r"(?i)(password|passwd|secret|token|private[_-]?key|api[_-]?key|"
    r"passphrase|credential|client[_-]?secret|auth[_-]?key|authorization)"
    r"(['\"]?\s*[:=]\s*['\"]?)((?:[Bb]earer\s+)?[^\s'\";,}]+)")

_TOKEN_PREFIXES = re.compile(
    r"\b(ghp_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|"
    r"glpat-[A-Za-z0-9_-]+|xox[bap]-[A-Za-z0-9-]+|"
    r"sk-[A-Za-z0-9]{8,}|rk-[A-Za-z0-9]{8,})\b")

_BEARER = re.compile(r"(?i)\b(Bearer)\s+([A-Za-z0-9._~+/-]+)")

_URL_USERINFO = re.compile(r"(https?://[^/\s:]+:)([^@\s/]+)(@)")

REDACTED = "***REDACTED***"


def redact_text(text: object, *, max_bytes: int = 1024 * 1024) -> str:
    if not isinstance(text, str):
        text = str(text)
    raw = text.encode("utf-8", "replace")
    truncated = len(raw) > max_bytes
    if truncated:
        text = raw[:max_bytes].decode("utf-8", "replace")
    text = _PRIVATE_KEY_BLOCK.sub(REDACTED, text)
    text = _LABELED_SECRET.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}", text)
    text = _TOKEN_PREFIXES.sub(REDACTED, text)
    text = _BEARER.sub(lambda match: f"{match.group(1)} {REDACTED}", text)
    text = _URL_USERINFO.sub(
        lambda match: f"{match.group(1)}{REDACTED}{match.group(3)}", text)
    if truncated:
        text += f"\n…[truncated to {max_bytes} bytes]"
    return text
