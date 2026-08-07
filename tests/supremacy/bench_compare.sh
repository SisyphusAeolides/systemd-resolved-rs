#!/usr/bin/env bash
# Usage: ./bench_compare.sh
# Compares currently active stub @127.0.0.53 — run twice:
#   A) stock resolved  B) resolved-rs
set -euo pipefail
OUT="${1:-/tmp/resolved-bench-$(date +%s).txt}"
TARGET=127.0.0.53
echo "Bench target $TARGET → $OUT"
{
  echo "=== $(date) ==="
  systemctl is-active systemd-resolved.service 2>/dev/null || true
  systemctl is-active systemd-resolved-rs.service 2>/dev/null || true
  if command -v dnsperf >/dev/null; then
    printf 'example.com A\ngoogle.com A\ncloudflare.com AAAA\n' > /tmp/q.txt
    dnsperf -s "$TARGET" -d /tmp/q.txt -c 20 -l 20 -Q 5000 || true
  else
    echo "dnsperf missing; using dig loop"
    START=$(date +%s%N)
    ok=0
    for i in $(seq 1 500); do
      dig @"$TARGET" example.com +time=1 +tries=1 +short >/dev/null && ok=$((ok+1)) || true
    done
    END=$(date +%s%N)
    echo "dig_ok=$ok / 500  elapsed_ms=$(( (END-START)/1000000 ))"
  fi
  curl -sS "http://127.0.0.1:9990/metrics" 2>/dev/null | head -40 || echo "no metrics"
} | tee "$OUT"
