#!/usr/bin/env bash
set -euo pipefail
dig @127.0.0.53 example.com +time=2 +tries=1 +short | grep -E '^[0-9.]+$'
