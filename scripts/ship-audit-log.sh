#!/usr/bin/env bash
# Ship normalized identity audit logs (NDJSON) to a generic HTTPS sink URL
# (the SIEM adapter boundary) with at-least-once delivery semantics, cursor-based
# idempotency, batch ID header (X-Ldapium-Batch-Id), exponential backoff retry,
# and dead-letter replay. See docs/audit-event-schema.md.
#
#   ./scripts/export-audit-log.sh | ./scripts/ship-audit-log.sh --sink-url https://siem.internal/ingest
#   ./scripts/ship-audit-log.sh -f audit.ndjson --sink-url https://siem.internal/ingest --token-file /etc/siem/token
#
set -euo pipefail

lib_dir="$(cd "$(dirname "$0")/lib" && pwd)"
exec python3 "${lib_dir}/audit-ship.py" "$@"
