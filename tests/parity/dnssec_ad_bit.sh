#!/usr/bin/env bash
set -euo pipefail
dig @127.0.0.53 cloudflare.com A +dnssec +time=3 +tries=2 >/tmp/adbit.out
grep -q "cloudflare.com" /tmp/adbit.out
echo "OK dnssec query completed (inspect AD manually in /tmp/adbit.out)"
