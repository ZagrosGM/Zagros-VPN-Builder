"""Worker-side redaction pins the same planted-secret vectors as the panel."""
from __future__ import annotations

from zagros_builder.redact import redact_text

PLANTED = {
    "password=hunter2": "hunter2",
    '"token": "abc123def456"': "abc123def456",
    "api_key: 'AKIA-EXAMPLE-KEY'": "AKIA-EXAMPLE-KEY",
    "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload": "eyJhbGciOiJIUzI1NiJ9",
    "key is ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789": "ghp_ABCDEF",
    "clone https://ci:s3cret-token@github.com/org/repo.git": "s3cret-token",
    "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAB3\n-----END OPENSSH PRIVATE KEY-----": "AAAAB3",
}


def test_redact_text_removes_every_planted_secret():
    for snippet, secret in PLANTED.items():
        cleaned = redact_text(f"prefix {snippet} suffix")
        assert secret not in cleaned, snippet
        assert "***REDACTED***" in cleaned, snippet


def test_redact_text_keeps_labels_and_truncates():
    assert "password=" in redact_text("password=hunter2")
    assert "truncated" in redact_text("x" * 100, max_bytes=10)
