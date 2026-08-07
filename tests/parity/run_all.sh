#!/usr/bin/env bash
set -euo pipefail
DIR=$(cd "$(dirname "$0")" && pwd)
FAIL=0
for s in stub_dig nss_getent resolv_conf_paths systemd_service_replace; do
  if bash "$DIR/${s}.sh"; then
    echo "PASS $s"
  else
    echo "FAIL $s"
    FAIL=1
  fi
done
# optional ABI if bus up
bash "$DIR/check_dbus_abi.sh" || true
exit $FAIL
