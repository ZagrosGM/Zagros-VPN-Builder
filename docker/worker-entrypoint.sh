#!/bin/sh
# Zero-touch worker entrypoint (f-buildzero-1): wait for the panel, enroll
# from the runtime-maintained register-token file when needed, then serve
# the linux pool. All inputs come from the compose template's environment.
set -u

PANEL="${ZAGROS_PANEL_URL:-}"
[ -n "$PANEL" ] || { echo "worker: ZAGROS_PANEL_URL is required" >&2; exit 78; }
WORKER_ID="${ZAGROS_WORKER_ID:-local-pool-01}"
LABELS="${ZAGROS_WORKER_LABELS:-linux}"
REDIS="${ZAGROS_REDIS_URL:-redis://127.0.0.1:6379/0}"
STATE_DIR="${ZAGROS_WORKER_STATE_DIR:-/var/lib/zagros/build-worker}"
TOKEN_FILE="${ZAGROS_WORKER_TOKEN_FILE:-$STATE_DIR/worker.token}"
RT_FILE="${ZAGROS_REGISTER_TOKEN_FILE:-$STATE_DIR/register-token}"

export PATH="/opt/flutter/bin:$PATH"
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-/opt/gradle-home}"
mkdir -p "$STATE_DIR" "$ZAGROS_BUILD_WORKSPACE" 2>/dev/null || true
cd /opt/zagros-builder

panel_up() {
    curl -kso /dev/null "$PANEL/dashboard/" 2>/dev/null \
      || curl -so /dev/null "$PANEL/dashboard/" 2>/dev/null
}

echo "worker: waiting for the panel at $PANEL …"
i=0
while ! panel_up; do
    i=$((i + 1))
    [ "$i" -ge 72 ] && { echo "worker: panel never came up" >&2; exit 1; }
    sleep 5
done
echo "worker: panel is up"

enroll() {
    [ -s "$RT_FILE" ] || return 1
    "/opt/worker-venv/bin/python" -m zagros_builder.cli enroll \
        --panel-url "$PANEL" \
        --worker-id "$WORKER_ID" \
        --register-token "$(cat "$RT_FILE")" \
        --token-file "$TOKEN_FILE"
}

if [ ! -s "$TOKEN_FILE" ]; then
    echo "worker: enrolling as '$WORKER_ID' …"
    ok=0
    i=0
    until enroll; do
        i=$((i + 1))
        [ "$i" -ge 72 ] && { echo "worker: enrollment never succeeded" >&2; exit 1; }
        sleep 5
    done
    echo "worker: enrolled"
fi

echo "worker: listening as '$WORKER_ID' (labels: $LABELS)"
exec "/opt/worker-venv/bin/python" -m zagros_builder.cli listen \
    --panel-url "$PANEL" \
    --worker-id "$WORKER_ID" \
    --token-file "$TOKEN_FILE" \
    --redis-url "$REDIS" \
    --labels "$LABELS"
