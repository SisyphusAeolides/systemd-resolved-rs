#!/usr/bin/env bash
set -euo pipefail
# cloudflare.com is signed; AD may depend on mode
dig @127.0.0.53 cloudflare.com +dnssec +time=3 | tail -5
exit 0
