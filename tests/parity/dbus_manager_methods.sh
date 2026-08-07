#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")" && pwd)
exec bash "$ROOT/check_dbus_abi.sh"
