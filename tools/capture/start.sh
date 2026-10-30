#!/usr/bin/env bash
# Capture WhatsApp Web traffic into mitmproxy.
#
# Two modes, chosen automatically:
#
#   upstream    the machine has no direct egress and uses a local proxy
#               (https_proxy / WACAP_UPSTREAM). mitmproxy chains to it and the
#               browser points at mitmproxy explicitly. No kernel changes.
#
#   transparent the machine reaches WhatsApp directly. nftables redirects
#               TCP/443 to mitmproxy at the kernel level, the browser needs no
#               proxy settings at all.
#
# Force a mode with WACAP_MODE=upstream|transparent.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CAPTURE_DIR="${WACAP_DIR:-$HOME/captures}"
HOSTS=(web.whatsapp.com g.whatsapp.com)
PORT="${WACAP_PORT:-8899}"

mkdir -p "$CAPTURE_DIR"

UPSTREAM="${WACAP_UPSTREAM:-${https_proxy:-${HTTPS_PROXY:-}}}"
MODE="${WACAP_MODE:-}"
if [[ -z "$MODE" ]]; then
    if [[ -n "$UPSTREAM" ]]; then
        MODE=upstream
    else
        MODE=transparent
    fi
fi

if [[ -n "$(ss -ltnH "sport = :$PORT" 2>/dev/null)" ]]; then
    echo "error: port $PORT is already in use" >&2
    exit 1
fi

MITMDUMP_BIN="$(command -v mitmdump || true)"
if [[ -z "$MITMDUMP_BIN" ]]; then
    echo "error: mitmdump not found in PATH" >&2
    exit 1
fi

cleanup_on_error() {
    sudo nft delete table inet wacap 2>/dev/null || true
}

if [[ "$MODE" == "upstream" && -z "$UPSTREAM" ]]; then
    echo "error: upstream mode requires WACAP_UPSTREAM or https_proxy" >&2
    exit 1
fi

if [[ "$MODE" == "transparent" ]]; then
    echo "==> Resolving WhatsApp endpoints"
    v4=()
    v6=()
    for host in "${HOSTS[@]}"; do
        while read -r ip; do
            [[ -n "$ip" ]] && v4+=("$ip")
        done < <(getent ahostsv4 "$host" | awk '{print $1}' | sort -u)
        while read -r ip; do
            [[ -n "$ip" ]] && v6+=("$ip")
        done < <(getent ahostsv6 "$host" | awk '{print $1}' | sort -u)
    done
    if [[ ${#v4[@]} -eq 0 && ${#v6[@]} -eq 0 ]]; then
        echo "error: could not resolve ${HOSTS[*]}" >&2
        exit 1
    fi
    echo "    ipv4: ${v4[*]:-none}"
    echo "    ipv6: ${v6[*]:-none}"

    echo "==> Installing nftables redirect (needs sudo)"
    sudo nft -f "$ROOT/tools/capture/wa-capture.nft"
    for ip in "${v4[@]:-}"; do
        [[ -n "$ip" ]] && sudo nft add element inet wacap wa4 "{ $ip }"
    done
    for ip in "${v6[@]:-}"; do
        [[ -n "$ip" ]] && sudo nft add element inet wacap wa6 "{ $ip }"
    done
    MITM_MODE="transparent@$PORT"
else
    echo "==> Upstream mode: chaining through $UPSTREAM"
    MITM_MODE="upstream:$UPSTREAM@$PORT"
fi

echo "==> Starting mitmdump on port $PORT ($MITM_MODE)"
sudo -E env "HOME=$HOME" "PATH=$PATH" "$MITMDUMP_BIN" \
    --mode "$MITM_MODE" \
    --listen-host 0.0.0.0 \
    --set confdir="$HOME/.mitmproxy" \
    --set connection_strategy=lazy \
    --save-stream-file "$CAPTURE_DIR/wa-flows.mitm" \
    >"$CAPTURE_DIR/mitm.log" 2>&1 &
echo "$!" | sudo tee /run/wacap.pid >/dev/null

sleep 3
if ! sudo kill -0 "$(sudo cat /run/wacap.pid)" 2>/dev/null; then
    echo "error: mitmdump did not start, see $CAPTURE_DIR/mitm.log" >&2
    cleanup_on_error
    exit 1
fi

SPKI="$(cat "$ROOT/tools/capture/ca-spki.txt")"
if [[ "$MODE" == "transparent" ]]; then
    CHROME_ARGS="--no-proxy-server"
    PROXY_NOTE="transparent: the kernel redirects traffic, no browser proxy settings."
else
    CHROME_ARGS="--proxy-server=127.0.0.1:$PORT"
    PROXY_NOTE="upstream: the browser talks to mitmproxy, mitmproxy chains to $UPSTREAM."
fi

cat <<EOF

Capture is running in $MODE mode.
  $PROXY_NOTE

  Browser (dedicated profile, trusts only mitmproxy's CA):
    google-chrome --user-data-dir=/tmp/wa-capture \\
      --ignore-certificate-errors-spki-list=$SPKI \\
      $CHROME_ARGS --disable-quic --no-first-run https://web.whatsapp.com

  Flows:  $CAPTURE_DIR/wa-flows.mitm
  Log:    $CAPTURE_DIR/mitm.log
  Stop:   ./tools/capture/stop.sh
EOF
