#!/usr/bin/env bash
set -euo pipefail
getent hosts example.com | grep -q example.com
getent hosts localhost | grep -q 127.0.0.1
