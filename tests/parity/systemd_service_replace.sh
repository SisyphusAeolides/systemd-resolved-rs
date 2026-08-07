#!/usr/bin/env bash
set -euo pipefail
systemctl is-active --quiet systemd-resolved-rs.service
if systemctl is-enabled systemd-resolved.service 2>/dev/null | grep -q masked; then
  echo "OK stock masked"
  exit 0
fi
if systemctl is-active --quiet systemd-resolved.service 2>/dev/null; then
  echo "FAIL stock resolved still active"
  exit 1
fi
echo "OK service_replace"
