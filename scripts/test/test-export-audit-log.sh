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

# One pod's worth of the three sources. Order here is deliberately NOT
# significant — audit-normalize.py sorts before assigning `seq` (see its own
# module docstring and check 8 below) — this is just the order
# export-audit-log.sh's run_export happens to fetch things in.
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

# 7. correlationId includes the pod (MED-2): two different pods must not
# collide even with the same rid/CSN or the same second/actor/target.
if grep -q '"correlationId":"auditlog:test-pod-0:' "${work}/run1.ndjson"; then
  ok "correlationId includes the pod"
else
  bad "correlationId does not include the pod"
fi

# 8. Deterministic regardless of retrieval order (MED-3): reversing the raw
# extraction stream's line order must not change the normalized output —
# the normalizer sorts by time/pod/correlationId/raw-hash itself. `sed
# '1!G;h;$!d'` reverses line order portably (no `tac` on macOS).
extract | sed '1!G;h;$!d' | python3 "${lib_dir}/audit-normalize.py" --admin-dn "cn=admin,dc=example,dc=org" > "${work}/shuffled.ndjson" 2>/dev/null
if diff -u "${work}/run1.ndjson" "${work}/shuffled.ndjson" >"${work}/shuffle.diff"; then
  ok "normalizer output is unchanged when the raw extraction stream is reversed"
else
  bad "normalizer output changed when input order was reversed — sorting is not fully deterministic"
  cat "${work}/shuffle.diff" >&2
fi

# 9. --legacy matches a golden byte-for-byte captured from the pre-#24
# script's own extraction logic run against the same fixtures (MED-4) — see
# docs/audit-event-schema.md's "Legacy mode" section. No additive keys, no
# envelope.
extract | python3 "${lib_dir}/audit-normalize.py" --legacy > "${work}/legacy.ndjson" 2>"${work}/legacy.stderr"
if diff -u "${fixtures}/expected-legacy.ndjson" "${work}/legacy.ndjson" >"${work}/legacy.diff"; then
  ok "--legacy output matches the pre-#24 golden fixture byte-for-byte"
else
  bad "--legacy output does not match the pre-#24 golden fixture"
  cat "${work}/legacy.diff" >&2
fi
if grep -q '"schemaVersion"' "${work}/legacy.ndjson"; then
  bad "--legacy output unexpectedly contains envelope fields"
else
  ok "--legacy output carries no envelope fields"
fi

# 10. Filter redaction (HIGH-1): a search filter containing a userPassword
# or token-like assertion has the VALUE redacted, attribute name kept, in
# both default and --legacy output. Exercised against a dedicated fixture
# with two sensitive filters and one benign one, so the benign filter's
# unredacted survival is checked too.
sens_extract() {
  awk -v pod=test-pod-0 -f "${lib_dir}/parse-accesslog.awk" "${fixtures}/accesslog-sensitive-filter.ldif"
}
sens_extract | python3 "${lib_dir}/audit-normalize.py" --admin-dn "cn=admin,dc=example,dc=org" > "${work}/sens-normalized.ndjson" 2>/dev/null
sens_extract | python3 "${lib_dir}/audit-normalize.py" --legacy > "${work}/sens-legacy.ndjson" 2>/dev/null
if diff -u "${fixtures}/expected-sensitive-filter-normalized.ndjson" "${work}/sens-normalized.ndjson" >"${work}/sens-normalized.diff"; then
  ok "sensitive filter values are redacted in default mode (matches golden)"
else
  bad "sensitive filter redaction (default mode) does not match golden"
  cat "${work}/sens-normalized.diff" >&2
fi
if diff -u "${fixtures}/expected-sensitive-filter-legacy.ndjson" "${work}/sens-legacy.ndjson" >"${work}/sens-legacy.diff"; then
  ok "sensitive filter values are redacted in --legacy mode (matches golden)"
else
  bad "sensitive filter redaction (--legacy mode) does not match golden"
  cat "${work}/sens-legacy.diff" >&2
fi
if grep -q 'hunter2\|abc123XYZ' "${work}/sens-normalized.ndjson" "${work}/sens-legacy.ndjson"; then
  bad "a sensitive filter assertion value leaked into output"
else
  ok "no sensitive filter assertion value leaks into either output mode"
fi
if grep -q '"filter":"(uid=alice)"' "${work}/sens-normalized.ndjson"; then
  ok "a benign filter is left unredacted"
else
  bad "a benign filter was unexpectedly altered"
fi

# 11. changedAttrs enforcement (MED-1): a malformed modify line
# ("replace: userPassword <value>" on one line, and a garbage attribute
# name) has its value stripped / the entry dropped, not merely flagged.
awk -v pod=test-pod-0 -f "${lib_dir}/parse-auditlog.awk" "${fixtures}/auditlog-malformed.log" \
  2>"${work}/malformed.stderr" | python3 "${lib_dir}/audit-normalize.py" --admin-dn "cn=admin,dc=example,dc=org" \
  > "${work}/malformed-normalized.ndjson" 2>>"${work}/malformed.stderr"
if diff -u "${fixtures}/expected-malformed-normalized.ndjson" "${work}/malformed-normalized.ndjson" >"${work}/malformed.diff"; then
  ok "malformed changedAttrs input is sanitized to match golden"
else
  bad "malformed changedAttrs handling does not match golden"
  cat "${work}/malformed.diff" >&2
fi
if grep -q 'hunter2\|leaked-on-one-line\|123bad' "${work}/malformed-normalized.ndjson"; then
  bad "a value or a malformed attribute name leaked through changedAttrs"
else
  ok "no leaked value or malformed attribute name in changedAttrs output"
fi
if grep -q 'dropping malformed changedAttrs entry' "${work}/malformed.stderr"; then
  ok "malformed changedAttrs entries are flagged to stderr"
else
  bad "no stderr warning was printed for the malformed changedAttrs entry"
fi

# 12. Malformed JSON input (HIGH-2): a corrupted line is counted, not
# silently dropped. Default mode appends an "exporter"/"summary" record
# naming the drop/emit counts and still exits 0; --legacy has no in-stream
# way to say this without adding a key, so it exits non-zero instead — one
# behavior per mode, both exercised here.
if python3 "${lib_dir}/audit-normalize.py" --admin-dn "cn=admin,dc=example,dc=org" \
     < "${fixtures}/raw-with-corrupted-line.ndjson" > "${work}/corrupted-normalized.ndjson" 2>"${work}/corrupted.stderr"; then
  ok "default mode exits 0 even with a dropped input line"
else
  bad "default mode exited non-zero on a dropped input line (should exit 0; see summary record)"
fi
if grep -q '"source":"exporter","seq":3,.*"op":"summary".*"dropped":1,"emitted":2' "${work}/corrupted-normalized.ndjson"; then
  ok "a corrupted input line produces an exporter summary record with correct counts"
else
  bad "no correct exporter summary record was produced for the corrupted input line"
  cat "${work}/corrupted-normalized.ndjson" >&2
fi
if python3 "${lib_dir}/audit-normalize.py" --legacy \
     < "${fixtures}/raw-with-corrupted-line.ndjson" > "${work}/corrupted-legacy.ndjson" 2>"${work}/corrupted-legacy.stderr"; then
  bad "--legacy exited 0 despite a dropped input line (should exit non-zero)"
else
  ok "--legacy exits non-zero when an input line is dropped"
fi

# 13. Invalid GeneralizedTime (LOW-1): a calendar-impossible timestamp
# (month 13) is rejected — time becomes null with a warning — rather than
# silently reformatted into an equally-impossible RFC3339 string.
awk -v pod=test-pod-0 -f "${lib_dir}/parse-accesslog.awk" "${fixtures}/accesslog-invalid-time.ldif" \
  | python3 "${lib_dir}/audit-normalize.py" --admin-dn "cn=admin,dc=example,dc=org" \
  > "${work}/invalid-time.ndjson" 2>"${work}/invalid-time.stderr"
if grep -q '"time":null' "${work}/invalid-time.ndjson"; then
  ok "an impossible calendar date normalizes to time:null instead of a bogus RFC3339 string"
else
  bad "an impossible calendar date was not rejected"
  cat "${work}/invalid-time.ndjson" >&2
fi
if grep -q 'could not parse time value' "${work}/invalid-time.stderr"; then
  ok "an impossible calendar date is flagged to stderr, as documented"
else
  bad "no stderr warning was printed for the impossible calendar date"
fi

if [ "$fail" != 0 ]; then
  echo "one or more audit export normalizer checks FAILED" >&2
  exit 1
fi
echo "all audit export normalizer checks passed"
