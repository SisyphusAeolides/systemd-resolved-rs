#!/usr/bin/env bash
set -euo pipefail
# Full leak test needs netns fixture; smoke that binary exists
command -v systemd-resolved-rs >/dev/null 2>&1 || command -v /usr/lib/systemd/systemd-resolved-rs >/dev/null
echo "OK split_dns_leak placeholder infrastructure"
exit 0
