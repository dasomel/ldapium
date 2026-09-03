#!/usr/bin/env bash
# Fixture-based unit test for migration dry-run reconciliation (issue #123).
#
# Validates report structure, schema analysis, attribute/objectClass detection,
# uniqueness collisions, structural objectClass validation, base-dn scoping,
# password redaction, and deterministic replay without requiring Docker.
# When Docker and ldapium:e2e are present, also executes live container dry-run.
#
# Run: ./scripts/test/test-migration-dryrun.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo_root="${here}/../.."
lib_dir="${repo_root}/scripts/lib"
fixtures="${repo_root}/scripts/testdata/migration"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail=0
ok() { printf 'PASS: %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }

# 1. Clean LDIF fixture test
set +e
python3 "${lib_dir}/migration-report.py" \
  "${fixtures}/clean-inetorgperson.ldif" \
  --base-dn "dc=example,dc=org" \
  -o "${work}/clean.json"
exit_clean=$?
set -e

if [ "$exit_clean" -eq 0 ]; then
  ok "clean fixture exited 0"
else
  bad "clean fixture exited $exit_clean (expected 0)"
fi

python3 - <<PYCHECK
import json, sys

with open("${work}/clean.json") as f:
    report = json.load(f)

assert report["summary"]["clean"] is True, "summary.clean should be True"
assert report["summary"]["findings_count"] == 0, "summary.findings_count should be 0"
assert report["summary"]["total_entries"] == 4, "total_entries should be 4"
assert len(report["unknown_object_classes"]) == 0, "unknown_object_classes should be empty"
assert len(report["unknown_attributes"]) == 0, "unknown_attributes should be empty"
assert len(report["entries_outside_base_dn"]) == 0, "entries_outside_base_dn should be empty"
assert len(report["duplicate_collisions"]["uid"]) == 0, "duplicate uid collisions should be empty"
assert len(report["duplicate_collisions"]["mail"]) == 0, "duplicate mail collisions should be empty"
assert len(report["entries_with_no_structural_object_class"]) == 0, "no-structural list should be empty"
assert len(report["errors"]) == 0, "errors should be empty"

# Ensure password hash is not exposed
raw = open("${work}/clean.json").read()
assert "cleanPasswordHash" not in raw, "userPassword hash must not appear in report"
PYCHECK
ok "clean fixture report shape and values validated"

# 2. AD-style export fixture test
set +e
python3 "${lib_dir}/migration-report.py" \
  "${fixtures}/ad-export.ldif" \
  --base-dn "dc=example,dc=org" \
  -o "${work}/ad.json"
exit_ad=$?
set -e

if [ "$exit_ad" -eq 1 ]; then
  ok "ad-style fixture exited 1 (findings detected)"
else
  bad "ad-style fixture exited $exit_ad (expected 1)"
fi

python3 - <<PYCHECK
import json, sys

with open("${work}/ad.json") as f:
    report = json.load(f)

assert report["summary"]["clean"] is False, "summary.clean should be False"
assert report["summary"]["findings_count"] > 0, "summary.findings_count should be > 0"
assert report["summary"]["total_entries"] == 4, "total_entries should be 4"

# Unknown objectClasses
assert "user" in report["unknown_object_classes"], "expected 'user' in unknown_object_classes"
assert report["unknown_object_classes"]["user"] == 2, "expected count 2 for 'user'"

# Unknown attributes
assert "sAMAccountName" in report["unknown_attributes"], "expected 'sAMAccountName' in unknown_attributes"
assert "objectGUID" in report["unknown_attributes"], "expected 'objectGUID' in unknown_attributes"
assert "userPrincipalName" in report["unknown_attributes"], "expected 'userPrincipalName' in unknown_attributes"

# Entries outside base DN
assert "cn=External Admin,ou=users,dc=foreign,dc=domain" in report["entries_outside_base_dn"], "expected outside entry"

# Duplicate collisions
mail_colls = report["duplicate_collisions"]["mail"]
assert any(c["value"] == "duplicate-mail@example.org" for c in mail_colls), "expected duplicate-mail collision"

# Entries without structural objectClass
assert "cn=Orphan Auxiliary,ou=users,dc=example,dc=org" in report["entries_with_no_structural_object_class"], "expected orphan entry"

# Errors list
assert len(report["errors"]) > 0, "errors list should not be empty"

# Password redaction check
raw = open("${work}/ad.json").read()
assert "PlaintextADSecretPassword!" not in raw, "plaintext password must be redacted"
assert "AnotherSecretPassword!" not in raw, "plaintext password must be redacted"
PYCHECK
ok "ad-style fixture report shape, findings, and password redaction validated"

# 3. Deterministic replay test
set +e
python3 "${lib_dir}/migration-report.py" \
  "${fixtures}/ad-export.ldif" \
  --base-dn "dc=example,dc=org" \
  -o "${work}/ad-replay.json"
set -e

if diff -u "${work}/ad.json" "${work}/ad-replay.json" >"${work}/diff.txt"; then
  ok "two consecutive runs against identical LDIF produced byte-identical reports"
else
  bad "reports differed across identical runs:"
  cat "${work}/diff.txt" >&2
fi

# 4. Error exit code test (missing file)
set +e
python3 "${lib_dir}/migration-report.py" "${work}/nonexistent.ldif" 2>/dev/null
exit_missing=$?
set -e
if [ "$exit_missing" -eq 2 ]; then
  ok "nonexistent file exited 2"
else
  bad "nonexistent file exited $exit_missing (expected 2)"
fi

# 5. Live Docker dry-run test (if Docker is available and ldapium:e2e exists)
if command -v docker >/dev/null 2>&1 && docker image inspect ldapium:e2e >/dev/null 2>&1; then
  echo "ldapium:e2e found — running live container dry-run test"
  set +e
  "${repo_root}/scripts/migration-dryrun.sh" \
    "${fixtures}/clean-inetorgperson.ldif" \
    --base-dn "dc=example,dc=org" \
    -o "${work}/live-clean.json"
  live_clean_exit=$?
  set -e
  if [ "$live_clean_exit" -eq 0 ]; then
    ok "live container dry-run on clean fixture exited 0"
  else
    bad "live container dry-run on clean fixture exited $live_clean_exit (expected 0)"
  fi

  set +e
  "${repo_root}/scripts/migration-dryrun.sh" \
    "${fixtures}/ad-export.ldif" \
    --base-dn "dc=example,dc=org" \
    -o "${work}/live-ad.json"
  live_ad_exit=$?
  set -e
  if [ "$live_ad_exit" -eq 1 ]; then
    ok "live container dry-run on ad fixture exited 1"
  else
    bad "live container dry-run on ad fixture exited $live_ad_exit (expected 1)"
  fi
else
  echo "NOTE: Docker or ldapium:e2e image not present locally; live slapadd dry-run verified in CI (e2e.yml)"
fi

if [ "$fail" -eq 0 ]; then
  echo "all migration dry-run tests passed"
  exit 0
else
  echo "migration dry-run tests failed" >&2
  exit 1
fi
