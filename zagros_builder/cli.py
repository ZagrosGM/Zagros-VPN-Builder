"""Worker CLI: enroll a worker, then listen on its pool queues.

Secrets (the API token) are written to a 0600 file and never printed.
"""
from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path


def _write_token_file(path: Path, token: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(handle, (token.strip() + "\n").encode("utf-8"))
    finally:
        os.close(handle)
    os.chmod(path, 0o600)


def _check_token_file(path: Path) -> None:
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        print(f"refusing to use world/group-accessible token file: {path} "
              f"(mode {oct(mode)} — run `chmod 600`)",
              file=sys.stderr)
        raise SystemExit(2)


def cmd_enroll(args: argparse.Namespace) -> int:
    from zagros_builder.panel import PanelClient, PanelError
    try:
        enrolled = PanelClient.register(
            args.panel_url, args.worker_id, args.register_token)
    except PanelError as exc:
        print(f"enrollment failed: {exc}", file=sys.stderr)
        return 1
    token = enrolled.get("api_token", "")
    if not token:
        print("panel did not return an API token", file=sys.stderr)
        return 1
    token_file = Path(args.token_file)
    _write_token_file(token_file, token)
    print(f"worker '{args.worker_id}' enrolled "
          f"(status={enrolled.get('status')}); API token saved to "
          f"{token_file} (mode 0600)")
    return 0


def _start_heartbeat(args: argparse.Namespace, queues: list) -> None:
    """Keep build_workers.last_seen_at fresh (f-builder-9).

    The rq queue path does not touch the panel, so the dashboard would
    otherwise never see worker liveness. A daemon thread posts the
    worker heartbeat on an interval; failures are non-fatal (the panel
    route simply marks the worker stale) and are logged once.
    """
    import threading
    import time

    from zagros_builder.panel import PanelClient, PanelError

    interval = 30
    token = Path(args.token_file).read_text(encoding="utf-8").strip()
    client = PanelClient(
        args.panel_url, worker_id=args.worker_id, worker_token=token)
    labels = ",".join(q.name for q in queues)

    def _loop() -> None:
        failures = 0
        while True:
            time.sleep(interval)
            try:
                client.heartbeat()
                failures = 0
            except Exception as exc:  # noqa: BLE001 - liveness only
                failures += 1
                if failures == 1:
                    print(f"heartbeat to {args.panel_url} failed: {exc}",
                          file=sys.stderr, flush=True)

    thread = threading.Thread(target=_loop, name="builder-heartbeat",
                              daemon=True)
    thread.start()
    print(f"heartbeat thread started ({interval}s, {labels})",
          flush=True)


def cmd_listen(args: argparse.Namespace) -> int:
    try:
        from rq import Queue, SimpleWorker, Worker
    except ImportError:
        print("the 'rq' package is not installed", file=sys.stderr)
        return 1
    try:
        import redis
    except ImportError:
        print("the 'redis' package is not installed", file=sys.stderr)
        return 1
    token_file = Path(args.token_file)
    if not token_file.is_file():
        print(f"token file not found: {token_file} (run `enroll` first)",
              file=sys.stderr)
        return 1
    _check_token_file(token_file)
    os.environ.setdefault("ZAGROS_WORKER_TOKEN_FILE", str(token_file))
    os.environ.setdefault("ZAGROS_WORKER_ID", args.worker_id)
    connection = redis.Redis.from_url(args.redis_url)
    try:
        connection.ping()
    except Exception as exc:
        print(f"Redis unreachable at {args.redis_url}: {exc}",
              file=sys.stderr)
        return 1
    queues = [Queue(f"builder:{label.strip()}", connection=connection)
              for label in args.labels.split(",") if label.strip()]
    if not queues:
        print("no labels given (e.g. --labels linux)", file=sys.stderr)
        return 1
    worker_cls = SimpleWorker if args.burst else Worker
    worker = worker_cls(queues, connection=connection,
                        name=f"zagros-builder-{args.worker_id}")
    _start_heartbeat(args, queues)
    print(f"listening as '{args.worker_id}' on "
          f"{', '.join(q.name for q in queues)}"
          f"{' (burst: exit when drained)' if args.burst else ''}")
    worker.work(burst=args.burst)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="zagros-builder",
                                     description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    enroll = sub.add_parser("enroll", help="exchange a register token")
    enroll.add_argument("--panel-url", required=True)
    enroll.add_argument("--worker-id", required=True)
    enroll.add_argument("--register-token", required=True)
    enroll.add_argument("--token-file", required=True)
    enroll.set_defaults(func=cmd_enroll)
    listen = sub.add_parser("listen", help="run the RQ worker")
    listen.add_argument("--panel-url", required=True)
    listen.add_argument("--worker-id", required=True)
    listen.add_argument("--token-file", required=True)
    listen.add_argument("--redis-url", required=True)
    listen.add_argument("--labels", required=True,
                        help="comma-separated pool labels (linux,macos,windows)")
    listen.add_argument("--burst", action="store_true",
                        help="exit when the queues drain (testing)")
    listen.set_defaults(func=cmd_listen)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "listen":
        os.environ.setdefault("ZAGROS_PANEL_URL", args.panel_url)
        os.environ.setdefault("ZAGROS_REDIS_URL", args.redis_url)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
