#!/bin/sh
# Mutation self-test of the machine ACL proof (#214 unit 3). Runs
# scripts/test/test-machine-acl-readonly-live.py against deliberately broken ACL
# variants. A mutation counts as DETECTED only when the proof
#   - exited non-zero,
#   - printed no `ERROR` line (a Docker or infrastructure error is not detection),
#   - reported `RESULT: <passed> checks passed, <failed> failed` with passed > 0
#     and failed > 0, and
#   - named the specific failed check(s) expected for that mutation.
# Any mutation that is not detected fails this script. Run from the repo root;
# LDAPIUM_IMAGE / LDAPIUM_TEST_PREFIX pass through to the proof.
set -u

proof=scripts/test/test-machine-acl-readonly-live.py
fail=0

detect() {
  mutation=$1
  shift
  log="mutation-$(printf '%s' "$mutation" | tr ':' '-').log"
  if LDAPIUM_ACL_MUTATE="$mutation" LDAPIUM_ACL_CONFIGS=a python3 "$proof" >"$log" 2>&1; then
    echo "NOT DETECTED: $mutation (the proof exited 0)"
    fail=1
    return
  fi
  if grep -q '^ERROR' "$log" || grep -q '^Traceback' "$log"; then
    echo "NOT DETECTED: $mutation (the run ended in an error, not in a failed check)"
    fail=1
    return
  fi
  result=$(sed -n 's/^RESULT: \([0-9][0-9]*\) checks passed, \([0-9][0-9]*\) failed.*/\1 \2/p' "$log")
  passed=${result% *}
  failed=${result#* }
  if [ -z "$result" ] || [ "$passed" -eq 0 ] || [ "$failed" -eq 0 ]; then
    echo "NOT DETECTED: $mutation (no usable result: '$result')"
    fail=1
    return
  fi
  for want in "$@"; do
    if ! grep -qF "FAIL: $want" "$log"; then
      echo "NOT DETECTED: $mutation (expected failed check missing: $want)"
      fail=1
      return
    fi
  done
  echo "detected: $mutation ($failed failed checks, expected checks present)"
}

detect reorder \
  '[a] olcAccess read back: machine rules are exactly' \
  '[a] M self password change (delete old, add new): insufficient access'
detect widen \
  '[a] olcAccess read back: machine rules are exactly' \
  '[a] M outside B / root base: no entry beyond B'
detect nosecret \
  '[a] secret userPassword: M explicit request returns neither the attribute nor its value'
for attr in userPassword shadowLastChange pwdHistory pKCS8PrivateKey userPKCS12 oathSecret oathEncKey oathTokenPIN; do
  detect "drop:$attr" \
    "[a] secret $attr: M explicit request returns neither the attribute nor its value" \
    "[a] secret $attr: M filter ($attr=*) matches nothing"
done

exit "$fail"
