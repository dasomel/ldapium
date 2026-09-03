#!/usr/bin/env bash
# Fixture-based test for entry data drift detection (issue #121).
#
# Exercises scripts/detect-entry-drift.sh and scripts/lib/canonicalize-ldif.py
# against fixture LDIF files in scripts/test/fixtures/.
#
# Run: ./scripts/test/test-detect-entry-drift.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
scripts_dir="${here}/.."
fixtures="${here}/fixtures"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail=0
ok() { printf 'PASS: %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }

raw_fixture="${fixtures}/entry-drift-raw.ldif"
expected_fixture="${fixtures}/entry-drift-expected.ldif"
drifted_fixture="${fixtures}/entry-drift-drifted.ldif"

# 1. Baseline generation matches expected fixture
"${scripts_dir}/detect-entry-drift.sh" --input "$raw_fixture" --baseline-out "${work}/baseline1.ldif" >/dev/null
if diff -u "$expected_fixture" "${work}/baseline1.ldif" >"${work}/golden.diff"; then
  ok "baseline generation matches golden fixture"
else
  bad "baseline generation does not match golden fixture"
  cat "${work}/golden.diff" >&2
fi

# 2. Determinism across runs
"${scripts_dir}/detect-entry-drift.sh" --input "$raw_fixture" --baseline-out "${work}/baseline2.ldif" >/dev/null
if diff -u "${work}/baseline1.ldif" "${work}/baseline2.ldif" >"${work}/replay.diff"; then
  ok "two baseline runs produced byte-identical output"
else
  bad "baseline output is not deterministic across runs"
  cat "${work}/replay.diff" >&2
fi

# 3. Password redaction verification: hashes must not appear, <redacted> must appear
if grep -qE '(someHashedPasswordBlob123456|argon2id)' "${work}/baseline1.ldif"; then
  bad "password hash leaked into baseline output"
else
  ok "no password hashes leaked into baseline output"
fi

if grep -q 'userPassword: <redacted>' "${work}/baseline1.ldif"; then
  ok "userPassword values properly replaced with fixed placeholder"
else
  bad "userPassword placeholder missing from baseline output"
fi

# 4. Operational attributes stripped verification
op_attrs='^(entryUUID|entryCSN|modifiersName|modifyTimestamp|creatorsName|createTimestamp|contextCSN|structuralObjectClass):'
if grep -Eq "$op_attrs" "${work}/baseline1.ldif"; then
  bad "operational attributes leaked into baseline output"
else
  ok "all operational attributes stripped"
fi

# 5. Check mode without drift: exit 0
check_out="${work}/check-clean.txt"
if "${scripts_dir}/detect-entry-drift.sh" --input "$raw_fixture" --check "$expected_fixture" >"$check_out" 2>&1; then
  ok "--check returns 0 when no drift is present"
else
  bad "--check failed on identical input"
  cat "$check_out" >&2
fi

# 6. Check mode with drift: exit 1 and diff on stdout
set +e
"${scripts_dir}/detect-entry-drift.sh" --input "$drifted_fixture" --check "$expected_fixture" >"${work}/drift.diff" 2>"${work}/drift.stderr"
drift_code=$?
set -eu
if [ "$drift_code" -eq 1 ]; then
  ok "--check returns 1 when drift is detected"
else
  bad "--check returned $drift_code, want 1 when drift is detected"
fi

if grep -q 'bob-drifted@example.org' "${work}/drift.diff"; then
  ok "--check printed expected diff to stdout"
else
  bad "--check did not print expected diff content"
  cat "${work}/drift.diff" >&2
fi

# 7. Error handling: exit 2
set +e
"${scripts_dir}/detect-entry-drift.sh" --input "$raw_fixture" --check "${work}/nonexistent-baseline.ldif" >/dev/null 2>&1
err_code1=$?
"${scripts_dir}/detect-entry-drift.sh" >/dev/null 2>&1
err_code2=$?
"${scripts_dir}/detect-entry-drift.sh" --invalid-flag >/dev/null 2>&1
err_code3=$?
set -eu

if [ "$err_code1" -eq 2 ] && [ "$err_code2" -eq 2 ] && [ "$err_code3" -eq 2 ]; then
  ok "errors exit 2 on nonexistent baseline, missing mode, and unknown flags"
else
  bad "expected exit 2 on errors; got codes: $err_code1, $err_code2, $err_code3"
fi

if [ "$fail" -ne 0 ]; then
  echo "scripts/test/test-detect-entry-drift.sh failed" >&2
  exit 1
fi
echo "all entry drift fixture checks passed"
