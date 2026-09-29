"""Build-log sinks: live Redis stream + durable in-memory transcript.

The live stream is best-effort UX (a dead Redis degrades to a one-line
note in the transcript, never a failed build); the in-memory transcript
is the durable record uploaded to the panel with the final status.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from zagros_builder.redact import redact_text

MAX_TRANSCRIPT_BYTES = 5 * 1024 * 1024
STREAM_TRIM = 5000


class LogStreamError(Exception):
    pass


class LogSink(ABC):
    @abstractmethod
    def emit(self, line: str) -> None:
        ...

    def close(self) -> None:
        pass


class MemoryLogSink(LogSink):
    def __init__(self, cap_bytes: int = MAX_TRANSCRIPT_BYTES) -> None:
        self._chunks: list[str] = []
        self._bytes = 0
        self._cap = cap_bytes
        self.truncated = False

    def emit(self, line: str) -> None:
        if self.truncated:
            return
        encoded = (line + "\n").encode("utf-8", "replace")
        if self._bytes + len(encoded) > self._cap:
            self.truncated = True
            self._chunks.append(
                f"\n…[transcript truncated to {self._cap} bytes]\n")
            return
        self._chunks.append(line + "\n")
        self._bytes += len(encoded)

    @property
    def text(self) -> str:
        return "".join(self._chunks)


class RedisLogSink(LogSink):
    def __init__(self, redis_url: str | None = None,
                 stream: str = "", *, client=None,
                 trim: int = STREAM_TRIM) -> None:
        self._url = (redis_url or "").strip() or None
        self._stream = stream
        self._client = client
        self._trim = trim

    @property
    def enabled(self) -> bool:
        return bool(self._url or self._client)

    def _connection(self):
        if self._client is not None:
            return self._client
        if not self._url:
            raise LogStreamError("no Redis URL configured")
        try:
            import redis
        except ImportError as exc:
            raise LogStreamError(
                "the 'redis' package is not installed") from exc
        self._client = redis.Redis.from_url(
            self._url, socket_timeout=5, socket_connect_timeout=5)
        return self._client

    def emit(self, line: str) -> None:
        if not self.enabled:
            return
        try:
            self._connection().xadd(
                self._stream, {"text": line}, maxlen=self._trim,
                approximate=True)
        except Exception as exc:
            raise LogStreamError(str(exc)) from exc

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass


class TeeLogSink(LogSink):
    """Fan-out that never lets the live stream sink a build."""

    def __init__(self, *sinks: LogSink) -> None:
        self._sinks = list(sinks)
        self._stream_note_written = False

    def add_sink(self, sink: LogSink) -> None:
        self._sinks.append(sink)

    def emit(self, line: str) -> None:
        for sink in self._sinks:
            try:
                sink.emit(line)
            except LogStreamError as exc:
                self._note_stream_failure(str(exc))
            except Exception as exc:  # noqa: BLE001 - UX path, never fatal
                self._note_stream_failure(
                    f"{type(exc).__name__}: {exc}")

    def _note_stream_failure(self, reason: str) -> None:
        if self._stream_note_written:
            return
        self._stream_note_written = True
        for sink in self._sinks:
            if isinstance(sink, MemoryLogSink):
                sink.emit(f"[live log stream unavailable: {reason}]")

    @property
    def stream_healthy(self) -> bool:
        return not self._stream_note_written

    def close(self) -> None:
        for sink in self._sinks:
            try:
                sink.close()
            except Exception:
                pass


class RedactSink(LogSink):
    """Redacts every line before it reaches the wrapped sink(s)."""

    def __init__(self, sink: LogSink) -> None:
        self._sink = sink

    def emit(self, line: str) -> None:
        self._sink.emit(redact_text(line, max_bytes=256 * 1024))

    def close(self) -> None:
        self._sink.close()


class LineSplitter:
    """Turns arbitrary (kind, chunk) executor output into log lines."""

    def __init__(self, sink: LogSink) -> None:
        self._sink = sink
        self._buffers: dict[str, bytearray] = {
            "stdout": bytearray(), "stderr": bytearray()}

    def feed(self, kind: str, chunk: bytes) -> None:
        buffer = self._buffers.setdefault(kind, bytearray())
        buffer.extend(chunk)
        while True:
            newline = buffer.find(b"\n")
            if newline < 0:
                return
            line = bytes(buffer[:newline]).decode("utf-8", "replace")
            del buffer[:newline + 1]
            self._sink.emit(line)

    def flush(self) -> None:
        for buffer in self._buffers.values():
            if buffer:
                self._sink.emit(bytes(buffer).decode("utf-8", "replace"))
                buffer.clear()
