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
canonicalizer="${scripts_dir}/lib/canonicalize-ldif.py"
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

if grep -q 'userpassword: <redacted>' "${work}/baseline1.ldif"; then
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

# 8. Baseline canonicalization (H2): a raw baseline file that still has a
#    real password hash on disk must never leak that hash into --check
#    output, whether or not the comparison finds drift.
raw_as_baseline_check_out="${work}/raw-baseline-check.txt"
if "${scripts_dir}/detect-entry-drift.sh" --input "$raw_fixture" --check "$raw_fixture" >"$raw_as_baseline_check_out" 2>&1; then
  ok "--check with a raw (uncanonicalized) baseline reports no drift against an identical raw dump"
else
  bad "--check with a raw baseline unexpectedly reported drift against an identical raw dump"
  cat "$raw_as_baseline_check_out" >&2
fi
if grep -qE '(someHashedPasswordBlob123456|argon2id)' "$raw_as_baseline_check_out"; then
  bad "raw baseline's password hash leaked into --check output (no-drift case)"
else
  ok "raw baseline's password hash never appears in --check output (no-drift case)"
fi

set +e
"${scripts_dir}/detect-entry-drift.sh" --input "$drifted_fixture" --check "$raw_fixture" >"${work}/raw-baseline-drift.out" 2>"${work}/raw-baseline-drift.err"
raw_baseline_drift_code=$?
set -eu
if [ "$raw_baseline_drift_code" -eq 1 ]; then
  ok "--check against a raw baseline still detects real drift"
else
  bad "--check against a raw baseline returned $raw_baseline_drift_code, want 1"
fi
if grep -qE '(someHashedPasswordBlob123456|argon2id)' "${work}/raw-baseline-drift.out" "${work}/raw-baseline-drift.err"; then
  bad "raw baseline's password hash leaked into --check output (drift case)"
else
  ok "raw baseline's password hash never appears in --check output (drift case)"
fi

# 9. Cluster-dump shell safety (H3): base_dn and the admin password must
#    never be interpolated into a shell command string. A fake kubectl on
#    PATH records the exact argv it receives so we can assert (a) a base
#    DN containing a single quote and a space arrives as one intact argv
#    element rather than corrupting the command, and (b) the password
#    never appears in any argv a remote process's /proc/<pid>/cmdline
#    could expose.
kshim="${work}/kshim"
mkdir -p "$kshim"
argv_log="${work}/kubectl-argv.log"
: > "$argv_log"

cat > "${kshim}/kubectl" <<'KUBECTL_EOF'
#!/usr/bin/env bash
{
  for a in "$@"; do printf '%s\x1f' "$a"; done
  printf '\n'
} >> "$KUBECTL_ARGV_LOG"

is_get=0
is_exec=0
for a in "$@"; do
  case "$a" in
    get) is_get=1 ;;
    exec) is_exec=1 ;;
  esac
done

if [ "$is_get" = 1 ]; then
  exit 0
fi

if [ "$is_exec" = 1 ]; then
  cat >/dev/null
  printf 'dn: dc=example,dc=org\nobjectClass: top\nobjectClass: dcObject\ndc: example\n\n'
  exit 0
fi

exit 0
KUBECTL_EOF
chmod +x "${kshim}/kubectl"

shim_scripts="${work}/shim-scripts"
mkdir -p "${shim_scripts}/lib"
cp "${scripts_dir}/detect-entry-drift.sh" "${shim_scripts}/"
cp "$canonicalizer" "${shim_scripts}/lib/"
cat > "${shim_scripts}/get-credentials.sh" <<'CREDS_EOF'
#!/usr/bin/env bash
printf '%s' 'tr!cky pa$$word'
CREDS_EOF
chmod +x "${shim_scripts}/get-credentials.sh"

injected_base_dn="dc=ex'ample space,dc=org"
h3_out="${work}/h3-baseline.ldif"
set +e
KUBECTL_ARGV_LOG="$argv_log" PATH="${kshim}:${PATH}" \
  "${shim_scripts}/detect-entry-drift.sh" -n test-ns -r test-sts -b "$injected_base_dn" --baseline-out "$h3_out" >"${work}/h3.out" 2>"${work}/h3.err"
h3_code=$?
set -eu

if [ "$h3_code" -eq 0 ]; then
  ok "dump_cluster_ldif succeeds with a base DN containing a quote and a space"
else
  bad "dump_cluster_ldif failed ($h3_code) with a base DN containing a quote and a space"
  cat "${work}/h3.err" >&2
fi

if grep -F "BASE_DN=${injected_base_dn}"$'\x1f' "$argv_log" >/dev/null; then
  ok "base_dn reached kubectl exec as a single intact argv element (env var), not shell-interpolated"
else
  bad "base_dn did not arrive as a single intact BASE_DN=<value> argv element"
  cat "$argv_log" >&2
fi

if grep -qF "cn=admin,${injected_base_dn}" "$argv_log"; then
  bad "base_dn was interpolated directly into the ldapsearch command string"
else
  ok "the ldapsearch command string never contains the literal base_dn value (only \$BASE_DN)"
fi

# Intentionally a literal string to grep for.
# shellcheck disable=SC2016
if grep -qF '"cn=admin,$BASE_DN"' "$argv_log"; then
  ok "the ldapsearch command string references base_dn only via the remote-expanded \$BASE_DN"
else
  bad "the ldapsearch command string is missing the expected \$BASE_DN placeholder"
  cat "$argv_log" >&2
fi

# Intentionally a literal string to grep for.
# shellcheck disable=SC2016
if grep -qF 'tr!cky pa$$word' "$argv_log"; then
  bad "the admin password leaked into a kubectl exec argv"
else
  ok "the admin password never appears in any kubectl exec argv"
fi

# 10. Canonicalizer whitespace/case handling (M1).
# 10a. A folded (RFC 2849 continuation-line) value reassembles exactly.
printf 'dn: cn=fold,dc=example,dc=org\ncn: AliceInWonderl\n and\n\n' > "${work}/fold-raw.ldif"
fold_out="$(python3 "$canonicalizer" "${work}/fold-raw.ldif")"
if printf '%s\n' "$fold_out" | grep -qF 'cn: AliceInWonderland'; then
  ok "a folded continuation line reassembles exactly, with no characters lost or added"
else
  bad "a folded continuation line did not reassemble correctly"
  printf '%s\n' "$fold_out" >&2
fi

# 10b. A base64 value that decodes to a string with a significant leading
# space (unsafe as plain LDIF per RFC 2849) must round-trip unchanged.
printf 'dn: cn=b64test,dc=example,dc=org\nroomNumber:: IEZvbw==\n\n' > "${work}/b64-leading-space.ldif"
b64_out="$(python3 "$canonicalizer" "${work}/b64-leading-space.ldif")"
if printf '%s\n' "$b64_out" | grep -qF 'roomnumber:: IEZvbw=='; then
  ok "a base64 value with a significant leading space round-trips unchanged"
else
  bad "a base64 value with a significant leading space was corrupted by canonicalization"
  printf '%s\n' "$b64_out" >&2
fi

# 10c. Same entry, attribute *names* differing only in case -> no drift
# (attribute types are case-insensitive; canonicalization lowercases them).
printf 'dn: cn=Alice,dc=example,dc=org\nCN: Alice\nobjectClass: person\n\n' > "${work}/attr-case-a.ldif"
printf 'dn: cn=Alice,dc=example,dc=org\ncn: Alice\nOBJECTCLASS: person\n\n' > "${work}/attr-case-b.ldif"
"${scripts_dir}/detect-entry-drift.sh" --input "${work}/attr-case-a.ldif" --baseline-out "${work}/attr-case-a-baseline.ldif" >/dev/null
attr_case_check_out="${work}/attr-case-check.out"
if "${scripts_dir}/detect-entry-drift.sh" --input "${work}/attr-case-b.ldif" --check "${work}/attr-case-a-baseline.ldif" >"$attr_case_check_out" 2>&1; then
  ok "attribute names differing only in case are not reported as drift"
else
  bad "an attribute-name case difference was incorrectly reported as drift"
  cat "$attr_case_check_out" >&2
fi

# 10d. Same entry, DN RDN *attribute types* differing only in case -> no
# drift, while RDN *values* keep their case (documented in
# canonicalize-ldif.py's normalize_dn_case).
printf 'dn: UID=alice,OU=people,DC=example,DC=org\ncn: Alice\n\n' > "${work}/dn-case-a.ldif"
printf 'dn: uid=alice,ou=people,dc=example,dc=org\ncn: Alice\n\n' > "${work}/dn-case-b.ldif"
"${scripts_dir}/detect-entry-drift.sh" --input "${work}/dn-case-a.ldif" --baseline-out "${work}/dn-case-a-baseline.ldif" >/dev/null
dn_case_check_out="${work}/dn-case-check.out"
if "${scripts_dir}/detect-entry-drift.sh" --input "${work}/dn-case-b.ldif" --check "${work}/dn-case-a-baseline.ldif" >"$dn_case_check_out" 2>&1; then
  ok "DN RDN attribute-type case differences are not reported as drift"
else
  bad "a DN RDN attribute-type case difference was incorrectly reported as drift"
  cat "$dn_case_check_out" >&2
fi

# (Real drift on differing values, as opposed to case-only differences,
# is already exercised by sections 5-6 above.)

# 11. Attribute options must not bypass redaction/stripping (regression for
# a real userPassword;binary/userPassword;lang-en hash surviving into a
# --check diff because it compared unequal to the bare "userpassword").
printf 'dn: uid=optiontest,dc=example,dc=org\nuserPassword;binary:: aGFzaDEyMw==\ncn: Option Test\n\n' > "${work}/attr-options-baseline.ldif"
printf 'dn: uid=optiontest,dc=example,dc=org\nuserPassword;binary:: aGFzaDEyMw==\ncn: Option Test Changed\n\n' > "${work}/attr-options-current.ldif"
attr_options_check_out="${work}/attr-options-check.out"
set +e
"${scripts_dir}/detect-entry-drift.sh" --input "${work}/attr-options-current.ldif" --check "${work}/attr-options-baseline.ldif" >"$attr_options_check_out" 2>&1
attr_options_code=$?
set -eu
if [ "$attr_options_code" -eq 1 ]; then
  ok "userPassword;binary entries still detect real (non-password) drift"
else
  bad "userPassword;binary --check returned $attr_options_code, want 1 (a real cn change)"
fi
if grep -qF 'hash123' "$attr_options_check_out"; then
  bad "userPassword;binary hash leaked into --check output"
else
  ok "userPassword;binary hash never appears in --check output"
fi
if grep -qF 'userpassword;binary: <redacted>' "$attr_options_check_out" || \
   python3 "$canonicalizer" "${work}/attr-options-baseline.ldif" | grep -qF 'userpassword;binary: <redacted>'; then
  ok "userPassword;binary is redacted like bare userPassword, options preserved in the name"
else
  bad "userPassword;binary was not redacted to the expected placeholder"
fi

if [ "$fail" -ne 0 ]; then
  echo "scripts/test/test-detect-entry-drift.sh failed" >&2
  exit 1
fi
echo "all entry drift fixture checks passed"
