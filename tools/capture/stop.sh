#!/usr/bin/env bash
# Stop the capture started by start.sh.

set -euo pipefail

CAPTURE_DIR="${WACAP_DIR:-$HOME/captures}"
PORT="${WACAP_PORT:-8899}"
PID_FILE="$CAPTURE_DIR/wacap.pid"

if [[ -f "$PID_FILE" ]]; then
    pid="$(cat "$PID_FILE")"
    if kill "$pid" 2>/dev/null; then
        echo "==> Stopped mitmproxy (pid $pid)"
    fi
    for _ in $(seq 1 30); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
    done
    kill -9 "$pid" 2>/dev/null || true
    rm -f "$PID_FILE"
fi

# A stale pid file must not leave an orphan holding the port.
if [[ -n "$(ss -ltnH "sport = :$PORT" 2>/dev/null)" ]]; then
    echo "==> Freeing port $PORT"
    fuser -k "${PORT}/tcp" 2>/dev/null || true
fi

echo "Done."
