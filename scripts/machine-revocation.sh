#!/usr/bin/env bash
# Python 3 and the OpenLDAP CLI are required; credentials are file-only.
set -euo pipefail
exec python3 "$(dirname "$0")/lib/machine_revocation.py" "$@"
