#!/usr/bin/env bash
set -euo pipefail
systemctl is-active --quiet systemd-resolved-rs.service
if systemctl is-enabled systemd-resolved.service 2>/dev/null | grep -q masked; then
  exit 0
fi
# OK if stock disabled
systemctl is-active systemd-resolved.service 2>/dev/null && exit 1 || exit 0
