#!/usr/bin/env bash
# Run mitmproxy as a plain HTTP proxy on top of the system VPN/proxy chain.
#
#   ./tools/capture/start.sh              # web UI (mitmweb) on 8082
#   WACAP_UI=dump ./tools/capture/start.sh  # console (mitmdump)
#
# No kernel changes and no sudo: the browser points at mitmproxy explicitly,
# mitmproxy forwards to the upstream proxy that already provides egress.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CAPTURE_DIR="${WACAP_DIR:-$HOME/captures}"
PORT="${WACAP_PORT:-8899}"
WEB_PORT="${WACAP_WEB_PORT:-8082}"
UPSTREAM="${WACAP_UPSTREAM:-${https_proxy:-${HTTPS_PROXY:-http://127.0.0.1:10809}}}"
TOKEN="${WACAP_TOKEN:-wapy}"
UI="${WACAP_UI:-web}"

mkdir -p "$CAPTURE_DIR"

if [[ -n "$(ss -ltnH "sport = :$PORT" 2>/dev/null)" ]]; then
    echo "error: port $PORT is already in use; run ./tools/capture/stop.sh first" >&2
    exit 1
fi

if [[ "$UI" == "web" ]]; then
    BIN="$(command -v mitmweb || true)"
    UI_ARGS=(
        --web-port "$WEB_PORT"
        --web-host 127.0.0.1
        --no-web-open-browser
        --set "web_password=$TOKEN"
    )
else
    BIN="$(command -v mitmdump || true)"
    UI_ARGS=()
fi
if [[ -z "$BIN" ]]; then
    echo "error: mitm$([[ "$UI" == "web" ]] && echo web || echo dump) not found in PATH" >&2
    exit 1
fi

# Fail early with a clear message instead of a silent hang in the browser.
if ! curl -s -o /dev/null --max-time 5 --proxy "$UPSTREAM" https://web.whatsapp.com/; then
    echo "warning: upstream $UPSTREAM did not reach web.whatsapp.com" >&2
fi

echo "==> Starting $(basename "$BIN") on port $PORT, chaining through $UPSTREAM"
"$BIN" \
    "${UI_ARGS[@]}" \
    --mode "upstream:$UPSTREAM@$PORT" \
    --set confdir="$HOME/.mitmproxy" \
    --set connection_strategy=lazy \
    --save-stream-file "$CAPTURE_DIR/wa-flows.mitm" \
    >"$CAPTURE_DIR/mitm.log" 2>&1 &
echo "$!" > "$CAPTURE_DIR/wacap.pid"

sleep 2
if ! kill -0 "$(cat "$CAPTURE_DIR/wacap.pid")" 2>/dev/null; then
    echo "error: mitmproxy did not start, see $CAPTURE_DIR/mitm.log" >&2
    tail -5 "$CAPTURE_DIR/mitm.log" >&2
    exit 1
fi

SPKI="$(cat "$ROOT/tools/capture/ca-spki.txt")"
if [[ "$UI" == "web" ]]; then
    UI_LINE="  Web UI: http://127.0.0.1:$WEB_PORT/?token=$TOKEN"
else
    UI_LINE="  UI:     console"
fi

cat <<EOF

Capture is running.
$UI_LINE

  Browser (dedicated profile, trusts only mitmproxy's CA):
    google-chrome --user-data-dir=/tmp/wa-capture \\
      --ignore-certificate-errors-spki-list=$SPKI \\
      --proxy-server=127.0.0.1:$PORT --disable-quic --no-first-run \\
      https://web.whatsapp.com

  Flows:  $CAPTURE_DIR/wa-flows.mitm
  Log:    $CAPTURE_DIR/mitm.log
  Stop:   ./tools/capture/stop.sh
EOF
