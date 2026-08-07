#!/usr/bin/env bash
# Compare stub QPS/latency: resolved-rs vs systemd-resolved
set -euo pipefail
TARGET="${1:-127.0.0.53}"
N="${2:-10000}"
# requires dnsperf or kdig loop
if command -v dnsperf >/dev/null; then
  echo "server ${TARGET}" > /tmp/dnsperf.query
  echo "google.com A" >> /tmp/dnsperf.query
  dnsperf -s "$TARGET" -d /tmp/dnsperf.query -c 50 -l 30
else
  for i in $(seq 1 "$N"); do
    dig @"$TARGET" example.com +time=1 +tries=1 >/dev/null || true
  done
fi
