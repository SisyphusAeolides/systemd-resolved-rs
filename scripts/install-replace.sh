#!/usr/bin/env bash
# Replace stock systemd-resolved with systemd-resolved-rs on THIS machine.
# Run from repo root after: cargo build --release && make nss
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${ROOT}/target/release/systemd-resolved-rs"
# binary name may be resolved-rs — adjust:
if [[ ! -x "$BIN" ]]; then
  BIN="${ROOT}/target/release/resolved-rs"
fi
if [[ ! -x "$BIN" ]]; then
  echo "Build release binary first"; exit 1
fi

echo "[*] Installing binary"
install -D -m 755 "$BIN" /usr/lib/systemd/systemd-resolved-rs

echo "[*] Installing NSS"
if [[ -f "${ROOT}/nss/libnss_resolve.so.2" ]]; then
  install -m 755 "${ROOT}/nss/libnss_resolve.so.2" /usr/lib64/libnss_resolve.so.2 2>/dev/null \
    || install -m 755 "${ROOT}/nss/libnss_resolve.so.2" /usr/lib/libnss_resolve.so.2
else
  echo "WARN: nss .so missing — getent will not use you"
fi

echo "[*] Unit / polkit / tmpfiles"
install -D -m 644 "${ROOT}/packaging/systemd/systemd-resolved-rs.service" \
  /usr/lib/systemd/system/systemd-resolved-rs.service
install -D -m 644 "${ROOT}/packaging/systemd/systemd-resolved-rs.socket" \
  /usr/lib/systemd/system/systemd-resolved-rs.socket 2>/dev/null || true
install -D -m 644 "${ROOT}/packaging/polkit/org.freedesktop.resolve1.policy" \
  /usr/share/polkit-1/actions/org.freedesktop.resolve1.policy
install -D -m 644 "${ROOT}/packaging/tmpfiles/systemd-resolved-rs.conf" \
  /usr/lib/tmpfiles.d/systemd-resolved-rs.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/systemd-resolved-rs.conf || true

echo "[*] User"
getent passwd systemd-resolve >/dev/null || useradd -r -d / -s /sbin/nologin systemd-resolve

echo "[*] Stopping stock resolved"
systemctl disable --now systemd-resolved.service 2>/dev/null || true
systemctl mask systemd-resolved.service 2>/dev/null || true

echo "[*] Enabling resolved-rs"
systemctl daemon-reload
systemctl enable --now systemd-resolved-rs.service

echo "[*] resolv.conf → stub"
ln -sfr /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf 2>/dev/null \
  || ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf

echo "[*] Smoke"
sleep 1
systemctl --no-pager status systemd-resolved-rs.service || true
dig @127.0.0.53 example.com +time=2 +tries=1 || true
getent hosts example.com || true
echo "DONE. Run scripts/boot-smoke.sh"
