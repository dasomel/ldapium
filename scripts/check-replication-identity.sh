#!/usr/bin/env bash
# Stable-CSN data visibility check. Requires Python 3 and ldapsearch, or Docker --container.
set -euo pipefail
exec python3 "$(dirname "$0")/lib/replication_identity_check.py" "$@"
