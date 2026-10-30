#!/usr/bin/env bash
# Stop the capture: kill mitmdump and remove the nftables table.
# Without arguments also flushes captured IP sets, so no stale rules remain.

set -euo pipefail

echo "==> Removing nftables redirect"
sudo nft delete table inet wacap 2>/dev/null || echo "    table already absent"

if [[ -f /run/wacap.pid ]]; then
    pid="$(sudo cat /run/wacap.pid)"
    echo "==> Stopping mitmdump (pid $pid)"
    sudo kill "$pid" 2>/dev/null || true
    sudo rm -f /run/wacap.pid
fi

echo "Done."
