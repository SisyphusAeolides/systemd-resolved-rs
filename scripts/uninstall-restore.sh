#!/usr/bin/env bash
set -euo pipefail
systemctl disable --now systemd-resolved-rs.service 2>/dev/null || true
systemctl unmask systemd-resolved.service 2>/dev/null || true
systemctl enable --now systemd-resolved.service
ln -sfr /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf 2>/dev/null || true
echo "Restored stock systemd-resolved"
