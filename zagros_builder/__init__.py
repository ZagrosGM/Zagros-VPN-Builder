"""Zagros white-label build worker.

Executes one platform job per RQ invocation: claim -> fetch -> isolate ->
clone pinned sources (app + SDK) -> run the client repo's contract
script -> checksum -> upload -> report. This package never imports
panel code; the two sides meet only through the versioned job contract
(``JOB_CONTRACT_VERSION``) and the worker HTTP API.
"""
from __future__ import annotations

BUILDER_VERSION = "0.3.0"
# v2 (Phase 14): the job document carries a pinned ``sdk_source`` next to
# ``source``. Bump together with the panel — a v1 document (no SDK pin)
# must be refused loudly, never built into a pub-get failure.
JOB_CONTRACT_VERSION = 2
