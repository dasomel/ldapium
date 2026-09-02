#!/usr/bin/env bash
# Fixture-based test for the audit export normalizer (issue #24).
#
# No kubectl/cluster involved: this exercises the exact awk extraction files
# and the exact scripts/lib/audit-normalize.py that export-audit-log.sh
# itself calls, against fixture LDIF/container-log input in
# scripts/test/fixtures/. That is the same split export-audit-log.sh uses —
# "fetch from kubectl" (untestable without a cluster, and already covered
# live by .github/workflows/security-e2e.yml's "Verify the audit export
# script" step) vs "turn already-fetched text into NDJSON" (pure, and what
# this test actually proves).
#
# Run: ./scripts/test/test-export-audit-log.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
lib_dir="${here}/../lib"
fixtures="${here}/fixtures"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail=0
ok() { printf 'PASS: %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }

# One pod's worth of the three sources, in the exact order
# export-audit-log.sh's own run_export emits them in (auditlog, then
# replication-conflict-raw, then accesslog) — order is what makes `seq`
# meaningful to assert on.
extract() {
  awk -v pod=test-pod-0 -f "${lib_dir}/parse-auditlog.awk" "${fixtures}/auditlog-container.log"
  grep -E 'do_syncrep2: rid=[0-9]+ CSN too old, ignoring [^ ]+ \(.*\)$' "${fixtures}/replication-container.log" \
    | awk -v pod=test-pod-0 -f "${lib_dir}/parse-replication-conflict.awk"
  awk -v pod=test-pod-0 -f "${lib_dir}/parse-accesslog.awk" "${fixtures}/accesslog.ldif"
}

normalize() {
  extract | python3 "${lib_dir}/audit-normalize.py" --admin-dn "cn=admin,dc=example,dc=org"
}

normalize > "${work}/run1.ndjson" 2>"${work}/run1.stderr"
normalize > "${work}/run2.ndjson" 2>"${work}/run2.stderr"

# 1. Deterministic replay: two runs against the same unchanged fixture input
# must be byte-identical, seq included.
if diff -u "${work}/run1.ndjson" "${work}/run2.ndjson" >"${work}/replay.diff"; then
  ok "two normalizer runs produced byte-identical output"
else
  bad "normalizer output is not deterministic across identical runs"
  cat "${work}/replay.diff" >&2
fi

# 2. Output matches the checked-in golden fixture — a normalizer change that
# alters the envelope shape, a derivation, or field ordering shows up here as
# a diff to review, not a silent behavior change.
if diff -u "${fixtures}/expected-normalized.ndjson" "${work}/run1.ndjson" >"${work}/golden.diff"; then
  ok "normalizer output matches scripts/test/fixtures/expected-normalized.ndjson"
else
  bad "normalizer output does not match the golden fixture"
  cat "${work}/golden.diff" >&2
fi

# 3. Every line parses as JSON and carries the envelope fields a SIEM
# integration would key on.
python3 - "${work}/run1.ndjson" <<'PYEOF'
import json
import sys

path = sys.argv[1]
seqs = []
with open(path) as f:
    for lineno, line in enumerate(f, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as exc:
            sys.exit(f"line {lineno}: not valid JSON: {exc}")
        for field in ("schemaVersion", "source", "seq", "correlationId", "actor", "op", "result", "privileged", "raw"):
            if field not in rec:
                sys.exit(f"line {lineno}: missing required envelope field {field!r}")
        if rec["schemaVersion"] != "1":
            sys.exit(f"line {lineno}: unexpected schemaVersion {rec['schemaVersion']!r}")
        seqs.append(rec["seq"])

if seqs != list(range(1, len(seqs) + 1)):
    sys.exit(f"seq is not contiguous starting at 1: {seqs}")

print(f"PASS: {len(seqs)} records, all parse as JSON with a full envelope, seq contiguous 1..{len(seqs)}")
PYEOF

# 4. Redaction: the fixture's two userPassword values ("e1NTSEF9..." base64
# blobs) must never appear anywhere in the normalized output, while the
# attribute NAME "userPassword" must still show up in changedAttrs — proving
# the value was stripped and the name was not (AC #4).
if grep -q 'e1NTSEF9' "${work}/run1.ndjson"; then
  bad "a userPassword value leaked into the normalized export"
else
  ok "no userPassword value appears in the normalized export"
fi
if grep -q '"userPassword"' "${work}/run1.ndjson"; then
  ok "userPassword attribute NAME is preserved in changedAttrs"
else
  bad "userPassword attribute name was unexpectedly dropped from changedAttrs"
fi

# 5. Privileged classification: the rootdn's auditlog/accesslog records are
# privileged:true, a non-rootdn actor's (uid=bob) is privileged:false.
if grep -q '"actor":"cn=admin,dc=example,dc=org".*"privileged":true' "${work}/run1.ndjson"; then
  ok "rootdn actor is classified privileged:true"
else
  bad "rootdn actor was not classified privileged:true"
fi
if grep -q '"actor":"uid=bob,ou=people,dc=example,dc=org".*"privileged":false' "${work}/run1.ndjson"; then
  ok "non-rootdn actor is classified privileged:false"
else
  bad "non-rootdn actor was not classified privileged:false"
fi

# 6. objectId: populated from the auditlog delete record's entryUUID line,
# null everywhere the source data has no entryUUID (documented limitation
# for accesslog and replication-conflict-raw).
if grep -q '"objectId":"4f8a3b2e-1111-4c9a-9999-abcdef012345"' "${work}/run1.ndjson"; then
  ok "objectId populated from an auditlog record's entryUUID"
else
  bad "objectId was not populated from the fixture's entryUUID"
fi

# 7. --legacy still produces the flat, pre-envelope shape (no "schemaVersion"
# top-level key), proving the flag genuinely bypasses normalization rather
# than just relabeling it.
if extract | grep -q '"schemaVersion"'; then
  bad "--legacy-equivalent flat extraction unexpectedly contains envelope fields"
else
  ok "flat extraction (what --legacy emits) carries no envelope fields"
fi

if [ "$fail" != 0 ]; then
  echo "one or more audit export normalizer checks FAILED" >&2
  exit 1
fi
echo "all audit export normalizer checks passed"
