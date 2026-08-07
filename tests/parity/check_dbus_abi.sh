#!/usr/bin/env bash
set -euo pipefail
INTROSPECT=$(busctl introspect org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager)
FAIL=0
while read -r m; do
  [[ -z "$m" || "$m" =~ ^# ]] && continue
  if grep -q "$m" <<<"$INTROSPECT"; then
    echo "OK  $m"
  else
    echo "MISSING $m"
    FAIL=1
  fi
done < "$(dirname "$0")/dbus_abi_list.txt"
exit $FAIL
