#!/usr/bin/env bash
# Start a kernel-level capture of WhatsApp Web traffic into mitmproxy.
#
#   ./tools/capture/start.sh
#
# Requires sudo for the nftables step. Everything is scoped to WhatsApp hosts,
# so the rest of the machine keeps working normally.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CAPTURE_DIR="${WACAP_DIR:-$HOME/captures}"
HOSTS=(web.whatsapp.com g.whatsapp.com)
PORT=8899

mkdir -p "$CAPTURE_DIR"

if ss -ltn "( sport = :$PORT )" | grep -q ":$PORT"; then
    echo "error: port $PORT is already in use" >&2
    exit 1
fi

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

echo "==> Starting mitmdump on port $PORT"
sudo -E mitmdump \
    --mode "transparent@$PORT" \
    --listen-host 0.0.0.0 \
    --set confdir="$HOME/.mitmproxy" \
    --set connection_strategy=lazy \
    --save-stream-file "$CAPTURE_DIR/wa-flows.mitm" \
    >"$CAPTURE_DIR/mitm.log" 2>&1 &
echo "$!" | sudo tee /run/wacap.pid >/dev/null

sleep 3
if ! sudo kill -0 "$(sudo cat /run/wacap.pid)" 2>/dev/null; then
    echo "error: mitmdump did not start, see $CAPTURE_DIR/mitm.log" >&2
    exit 1
fi

cat <<EOF

Capture is running.

  Browser (dedicated profile, trusts only mitmproxy's CA):
    google-chrome --user-data-dir=/tmp/wa-capture \\
      --ignore-certificate-errors-spki-list=\$(cat $ROOT/tools/capture/ca-spki.txt) \\
      --disable-quic --no-first-run https://web.whatsapp.com

  Flows:  $CAPTURE_DIR/wa-flows.mitm
  Log:    $CAPTURE_DIR/mitm.log
  Stop:   ./tools/capture/stop.sh
EOF
