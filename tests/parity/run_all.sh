#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
"$DIR/../../scripts/boot-smoke.sh"
# busctl call each critical method — expand as ABI lands
busctl call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager \
  ResolveHostname 'isit' 0 example.com 0 0 0 || true
echo "parity suite finished"
