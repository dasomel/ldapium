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

# 5. Unparseable LDIF fixture: parse failure is itself a fatal finding — the
#    report must still carry the parse error list, but exit 2, never 0/1.
set +e
python3 "${lib_dir}/migration-report.py" \
  "${fixtures}/unparseable-garbage.ldif" \
  -o "${work}/garbage.json"
exit_garbage=$?
set -e

if [ "$exit_garbage" -eq 2 ]; then
  ok "unparseable garbage fixture exited 2"
else
  bad "unparseable garbage fixture exited $exit_garbage (expected 2)"
fi

python3 - <<PYCHECK
import json

with open("${work}/garbage.json") as f:
    report = json.load(f)

assert report["summary"]["clean"] is False, "summary.clean should be False"
assert report["summary"]["total_entries"] == 0, "total_entries should be 0 (nothing parsed)"
assert len(report["errors"]) > 0, "errors list must not be empty for unparseable input"
assert report["schema_source"] == "n/a", "schema_source should be n/a for a parse failure"
PYCHECK
ok "unparseable garbage fixture reports a non-empty error list and exits fatally"

# 6. Offline contract test for migration-dryrun.sh's docker exit-code handling
#    (P0-1) and container cleanup (P2-2), using a fake `docker` on PATH.
#    Local Docker is not required/assumed to be present or network-reachable;
#    this exercises the shell contract, not the real slapadd path (that is
#    covered live in CI's e2e.yml).
fake_bin="${work}/fakebin"
mkdir -p "$fake_bin"
call_log="${work}/docker-calls.log"
: > "$call_log"

cat > "${fake_bin}/docker" <<'FAKE_DOCKER_EOF'
#!/usr/bin/env bash
# Minimal fake `docker` for offline contract testing of migration-dryrun.sh.
# Behavior is steered entirely by FAKE_DOCKER_* environment variables so the
# test can drive each scenario without a real Docker daemon or image.
set -euo pipefail
{ printf '%s' "$1"; for a in "${@:2}"; do printf ' %s' "$a"; done; printf '\n'; } >> "${FAKE_DOCKER_CALL_LOG:-/dev/null}"

case "$1" in
  info)
    exit "${FAKE_DOCKER_INFO_EXIT:-0}" ;;
  image)
    exit "${FAKE_DOCKER_IMAGE_INSPECT_EXIT:-0}" ;;
  create)
    exit_code="${FAKE_DOCKER_CREATE_EXIT:-0}"
    if [ "$exit_code" -eq 0 ]; then
      printf '%s\n' "${FAKE_DOCKER_CONTAINER_ID:-fakecid0000}"
    else
      echo "fake docker: create failed" >&2
    fi
    exit "$exit_code" ;;
  cp)
    src="$2"
    dest="$3"
    if [[ "$dest" == *:* ]]; then
      exit "${FAKE_DOCKER_CP_PUSH_EXIT:-0}"
    elif [[ "$src" == *:* ]]; then
      exit "${FAKE_DOCKER_CP_PULL_EXIT:-1}"
    else
      exit "${FAKE_DOCKER_CP_PUSH_EXIT:-0}"
    fi ;;
  start)
    if [ -n "${FAKE_DOCKER_START_OUTPUT:-}" ]; then
      printf '%s' "${FAKE_DOCKER_START_OUTPUT}"
    fi
    exit "${FAKE_DOCKER_START_EXIT:-0}" ;;
  rm)
    exit "${FAKE_DOCKER_RM_EXIT:-0}" ;;
  *)
    echo "fake docker: unhandled subcommand: $1" >&2
    exit 1 ;;
esac
FAKE_DOCKER_EOF
chmod +x "${fake_bin}/docker"

# 6a. `docker start` (the container executing the bootstrap/slapadd script)
#     failing with a Docker-CLI-style exit code must fail the whole dry-run
#     with exit 2, showing the captured output, not fall through to a
#     report exit code (0/1).
: > "$call_log"
set +e
env PATH="${fake_bin}:${PATH}" \
  FAKE_DOCKER_CALL_LOG="$call_log" \
  FAKE_DOCKER_CONTAINER_ID="shimcid125" \
  FAKE_DOCKER_START_EXIT=125 \
  FAKE_DOCKER_START_OUTPUT="slapadd: bootstrap error: simulated fatal failure" \
  "${repo_root}/scripts/migration-dryrun.sh" \
  "${fixtures}/clean-inetorgperson.ldif" \
  --base-dn "dc=example,dc=org" \
  -o "${work}/shim-fatal.json" \
  2>"${work}/shim-fatal.err"
shim_fatal_exit=$?
set -e

if [ "$shim_fatal_exit" -eq 2 ]; then
  ok "docker exit 125 (start) propagates as migration-dryrun.sh exit 2"
else
  bad "docker exit 125 (start) produced exit $shim_fatal_exit (expected 2)"
fi

if grep -q "simulated fatal failure" "${work}/shim-fatal.err"; then
  ok "fatal docker failure surfaces the captured container output on stderr"
else
  bad "fatal docker failure did not surface captured output on stderr"
  cat "${work}/shim-fatal.err" >&2
fi

if [ ! -s "${work}/shim-fatal.json" ]; then
  ok "no report file written on a fatal docker/bootstrap failure"
else
  bad "a report file was written despite a fatal docker/bootstrap failure"
fi

if grep -q "^rm -f shimcid125" "$call_log"; then
  ok "cleanup trap removed the throwaway container after a fatal failure"
else
  bad "cleanup trap did not remove the throwaway container after a fatal failure"
  cat "$call_log" >&2
fi

# 6b. A successful container run (docker start exit 0) still feeds its log
#     to migration-report.py and still cleans up the container.
: > "$call_log"
set +e
env PATH="${fake_bin}:${PATH}" \
  FAKE_DOCKER_CALL_LOG="$call_log" \
  FAKE_DOCKER_CONTAINER_ID="shimcid000" \
  FAKE_DOCKER_START_EXIT=0 \
  FAKE_DOCKER_START_OUTPUT="" \
  "${repo_root}/scripts/migration-dryrun.sh" \
  "${fixtures}/clean-inetorgperson.ldif" \
  --base-dn "dc=example,dc=org" \
  -o "${work}/shim-clean.json"
shim_clean_exit=$?
set -e

if [ "$shim_clean_exit" -eq 0 ]; then
  ok "docker exit 0 (start) with a clean fixture reaches report exit 0"
else
  bad "docker exit 0 (start) with a clean fixture produced exit $shim_clean_exit (expected 0)"
fi

if grep -q "^rm -f shimcid000" "$call_log"; then
  ok "cleanup trap removed the throwaway container after a successful run"
else
  bad "cleanup trap did not remove the throwaway container after a successful run"
  cat "$call_log" >&2
fi

# 7. Live Docker dry-run test (if Docker is available and ldapium:e2e exists)
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
