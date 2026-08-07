#!/usr/bin/env bash
set -euo pipefail
FAIL=0
check() {
  local name="$1"; shift
  if "$@"; then echo "OK  $name"; else echo "FAIL $name"; FAIL=1; fi
}

check service_active systemctl is-active --quiet systemd-resolved-rs.service
check bus_name busctl get-property org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager DNSEx
check stub_dig dig @127.0.0.53 example.com +short +time=2 +tries=1
check stub_file test -f /run/systemd/resolve/stub-resolv.conf
check resolv_conf test -e /etc/resolv.conf
check getent getent hosts example.com
check localhost getent hosts localhost

# optional
command -v resolvectl >/dev/null && check resolvectl resolvectl query example.com

exit $FAIL
