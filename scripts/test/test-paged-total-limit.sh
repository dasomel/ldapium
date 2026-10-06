#!/usr/bin/env bash
# Live regression test for LDAP_PAGED_TOTAL_LIMIT (issue #215, D215-14):
# image/entrypoint.sh renders `olcLimits: {0}users size.prtotal=<value>` on the
# main mdb database only when the variable is set, reconciles it on every
# start, validates it like LDAP_SIZE_LIMIT, and the resulting limit changes
# what a NON-root identity can read with a paged search. This drives the real
# entrypoint and a real slapd; it is not a fixture-only unit test.
#
# Cases:
#   1. Unset: no olcLimits at all (an existing install is unchanged), and a
#      non-root paged search stops at the server size limit with
#      sizeLimitExceeded while the rootDN still reads everything.
#   2. Invalid values (abc, 0, -5, 1.5, empty-after-trim forms) refuse to start.
#   3. `unlimited`: the non-root paged search completes; an UNPAGED search is
#      still capped by olcSizeLimit; the rootDN is unaffected.
#   4. A number below the candidate count caps the paged total at that number.
#   5. Reconcile on an existing volume: set -> present, changed -> replaced,
#      unset -> removed again, and an operator-set olcLimits of any other
#      shape is never touched.
#
# Usage: scripts/test/test-paged-total-limit.sh [image]
#   image defaults to ldapium:e2e. Requires Docker and python3.
#   PAGED_TOTAL_TIMEOUT (seconds, default 120) bounds each wait for slapd.
set -euo pipefail
# Never pipe into `grep -q` here: it exits on the first match, the writer
# gets SIGPIPE, and pipefail turns a real match into a failure. Match
# against captured variables with here-strings instead.

here="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "${here}/../.." && pwd)"
image="${1:-ldapium:e2e}"
admin_pw="pagedTotalTestPw1"
user_pw="PagedTotal-User-1!"
base="dc=example,dc=org"
ready_timeout="${PAGED_TOTAL_TIMEOUT:-120}"
# Below the default 10000 so the test stays small: the semantics are
# identical, only the threshold moves. 1200 candidates vs a 500 limit.
size_limit=500
entries=1200
db="olcDatabase={1}mdb,cn=config"
ldapi="ldapi://%2Fvar%2Flib%2Fopenldap%2Frun%2Fldapi"

suffix="$$"
containers=()
volumes=()
images=()
shim_dir=""
fail=0
ok() { printf 'PASS: %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }

# shellcheck disable=SC2317,SC2329 # invoked via the EXIT trap below (code differs by shellcheck version)
cleanup() {
  local c v
  for c in ${containers[@]+"${containers[@]}"}; do
    docker rm -f "$c" >/dev/null 2>&1 || true
  done
  for v in ${volumes[@]+"${volumes[@]}"}; do
    docker volume rm -f "$v" >/dev/null 2>&1 || true
  done
  for v in ${images[@]+"${images[@]}"}; do
    docker rmi -f "$v" >/dev/null 2>&1 || true
  done
  [ -z "$shim_dir" ] || rm -rf "$shim_dir"
}
trap cleanup EXIT

wait_ready() {
  local cid="$1" waited=0 status
  while [ "$waited" -lt "$ready_timeout" ]; do
    if docker exec "$cid" ldapwhoami -x -H ldap://localhost -D "cn=admin,${base}" -w "$admin_pw" >/dev/null 2>&1; then
      return 0
    fi
    status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo missing)"
    if [ "$status" = "exited" ] || [ "$status" = "missing" ]; then
      return 1
    fi
    sleep 1
    waited=$((waited + 1))
  done
  return 1
}

# start <name> <volume prefix> [extra docker env args...]: (re)creates the
# container on the named volumes; a second call with the same prefix and a
# different env is an "existing volume" restart.
start() {
  local name="$1" vol="$2"
  shift 2
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" \
    -v "${vol}-config:/etc/openldap/slapd.d" -v "${vol}-data:/var/lib/openldap/data" \
    -e LDAP_ROOT_DN="$base" -e LDAP_ADMIN_PASSWORD="$admin_pw" \
    -e LDAP_SIZE_LIMIT="$size_limit" "$@" "$image" >/dev/null
  containers+=("$name")
  if ! wait_ready "$name"; then
    bad "$name did not become ready"
    docker logs --tail 20 "$name" >&2 2>&1 || true
    return 1
  fi
}

new_volumes() {
  docker volume create "$1-config" >/dev/null
  docker volume create "$1-data" >/dev/null
  volumes+=("$1-config" "$1-data")
}

# olc_limits <container>: the olcLimits values on the main database, one per line.
olc_limits() {
  docker exec "$1" ldapsearch -x -LLL -o ldif-wrap=no -H "$ldapi" -D "cn=admin,cn=config" -w "$admin_pw" \
    -b "$db" -s base olcLimits 2>/dev/null | sed -n 's/^olcLimits: //p' || true
}

# paged <container> <bind dn> <password>: prints "<entries> <rc>" for a
# whole-subtree paged search (pr=100) under ou=people.
paged() {
  local out rc=0 n
  out="$(docker exec "$1" ldapsearch -x -LLL -H ldap://localhost -D "$2" -w "$3" \
    -b "ou=people,${base}" -E 'pr=100/noprompt' '(objectClass=inetOrgPerson)' dn 2>/dev/null)" || rc=$?
  n="$(grep -c '^dn:' <<<"$out" || true)"
  echo "${n} ${rc}"
}

unpaged() {
  local out rc=0 n
  out="$(docker exec "$1" ldapsearch -x -LLL -H ldap://localhost -D "$2" -w "$3" \
    -b "ou=people,${base}" '(objectClass=inetOrgPerson)' dn 2>/dev/null)" || rc=$?
  n="$(grep -c '^dn:' <<<"$out" || true)"
  echo "${n} ${rc}"
}

expect_eq() { # <label> <got> <want>
  if [ "$2" = "$3" ]; then ok "$1 (${2})"; else bad "$1: got '${2}', want '${3}'"; fi
}

admin_dn="cn=admin,${base}"
user_dn="uid=pagedtest,ou=people,${base}"
other_dn="uid=pagedother,ou=people,${base}"

# --- Case 2 first: invalid values never start slapd. ------------------------
for bad_val in abc 0 -5 1.5 01 2147483648 99999999999999999999; do
  # Detached + polled, never a foreground run: an image that ignores the
  # variable starts slapd and would block this test forever.
  cb="l3-ptl-bad-${suffix}"
  containers+=("$cb")
  docker rm -f "$cb" >/dev/null 2>&1 || true
  docker run -d --name "$cb" -e LDAP_ROOT_DN="$base" -e LDAP_ADMIN_PASSWORD="$admin_pw" \
    -e LDAP_PAGED_TOTAL_LIMIT="$bad_val" "$image" >/dev/null
  waited=0
  while [ "$waited" -lt 20 ] && [ "$(docker inspect -f '{{.State.Status}}' "$cb")" = "running" ]; do
    sleep 1
    waited=$((waited + 1))
  done
  rc="$(docker inspect -f '{{.State.ExitCode}}' "$cb")"
  out="$(docker logs "$cb" 2>&1 || true)"
  docker rm -f "$cb" >/dev/null 2>&1 || true
  if [ "$rc" != "0" ] && [[ "$out" == *"LDAP_PAGED_TOTAL_LIMIT must be"* ]]; then
    ok "invalid LDAP_PAGED_TOTAL_LIMIT='${bad_val}' refused (exit ${rc})"
  else
    bad "invalid LDAP_PAGED_TOTAL_LIMIT='${bad_val}': exit ${rc}, last log: $(tail -n 1 <<<"$out")"
  fi
done

# --- Case 1: unset -> no olcLimits, default behaviour unchanged. ------------
vol="l3-ptl-${suffix}"
new_volumes "$vol"
c="l3-ptl-${suffix}"
start "$c" "$vol"
# Bulk load through the wire (the generator emits ou=people itself). `-i` is
# required: without it docker exec silently drops the piped LDIF.
python3 "${repo_root}/scripts/bench-generate-ldif.py" --count "$entries" --base "$base" |
  docker exec -i "$c" ldapadd -x -H ldap://localhost -D "$admin_dn" -w "$admin_pw" >/dev/null
docker exec -i "$c" ldapadd -x -H ldap://localhost -D "$admin_dn" -w "$admin_pw" >/dev/null <<EOF
dn: ${user_dn}
objectClass: inetOrgPerson
uid: pagedtest
cn: Paged Test
sn: Test
EOF
docker exec "$c" ldappasswd -x -H ldap://localhost -D "$admin_dn" -w "$admin_pw" -s "$user_pw" "$user_dn" >/dev/null
# A second ordinary identity that no operator DN rule below names.
docker exec -i "$c" ldapadd -x -H ldap://localhost -D "$admin_dn" -w "$admin_pw" >/dev/null <<EOF
dn: ${other_dn}
objectClass: inetOrgPerson
uid: pagedother
cn: Paged Other
sn: Other
EOF
docker exec "$c" ldappasswd -x -H ldap://localhost -D "$admin_dn" -w "$admin_pw" -s "$user_pw" "$other_dn" >/dev/null

total="$((entries + 2))"
expect_eq "unset: no olcLimits on the main database" "$(olc_limits "$c")" ""
expect_eq "unset: rootDN paged search reads everything (entries rc)" "$(paged "$c" "$admin_dn" "$admin_pw")" "${total} 0"
expect_eq "unset: non-root paged search stops at the size limit (entries rc 4=sizeLimitExceeded)" "$(paged "$c" "$user_dn" "$user_pw")" "${size_limit} 4"

# --- Case 3: unlimited (set on the EXISTING volume: reconcile, not bootstrap) --
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=unlimited
expect_eq "unlimited: olcLimits rendered on an existing volume" "$(olc_limits "$c")" "{0}users size.prtotal=unlimited"
expect_eq "unlimited: non-root paged search completes" "$(paged "$c" "$user_dn" "$user_pw")" "${total} 0"
expect_eq "unlimited: non-root UNPAGED search is still capped by olcSizeLimit" "$(unpaged "$c" "$user_dn" "$user_pw")" "${size_limit} 4"
expect_eq "unlimited: rootDN unaffected" "$(paged "$c" "$admin_dn" "$admin_pw")" "${total} 0"

# --- Case 4: a number caps the paged total. ---------------------------------
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=900
expect_eq "900: olcLimits replaced, not duplicated" "$(olc_limits "$c")" "{0}users size.prtotal=900"
expect_eq "900: non-root paged search stops at the paged total" "$(paged "$c" "$user_dn" "$user_pw")" "900 4"

# Same value again: idempotent, still exactly one value.
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=900
expect_eq "900 again: still one value" "$(olc_limits "$c")" "{0}users size.prtotal=900"

# --- Case 5: unset again removes our value and restores the default. --------
start "$c" "$vol"
expect_eq "unset again: olcLimits removed" "$(olc_limits "$c")" ""
expect_eq "unset again: non-root paged search is back to the default cap" "$(paged "$c" "$user_dn" "$user_pw")" "${size_limit} 4"

# --- Operator rules (H1 ordering, M1 provenance). ---------------------------
# slapd applies only the FIRST olcLimits rule that matches a DN, so these cases
# are behavioural: they check which limit is actually IN FORCE, not just which
# strings are stored.
marker() { docker exec "$1" cat /etc/openldap/slapd.d/.paged-total-limit 2>/dev/null || true; }
limits_ldif() { # <operation lines...>: modify olcLimits on the main database
  { printf 'dn: %s\nchangetype: modify\n' "$db"; cat; } |
    docker exec -i "$c" ldapmodify -x -H "$ldapi" -D "cn=admin,cn=config" -w "$admin_pw" >/dev/null
}
clear_limits() { printf 'delete: olcLimits\n' | limits_ldif || true; }

# H1: an operator rule written for one DN must keep precedence over ours.
op_dn_rule="dn.exact=\"${user_dn}\" size.soft=100 size.hard=100 size.prtotal=100"
printf 'add: olcLimits\nolcLimits: {0}%s\n' "$op_dn_rule" | limits_ldif
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=unlimited
expect_eq "H1: our rule is appended after the operator's, never inserted before it" \
  "$(olc_limits "$c" | sort | tr '\n' '|')" \
  "{0}${op_dn_rule}|{1}users size.prtotal=unlimited|"
expect_eq "H1: the operator's limits are still IN FORCE for the DN they name (paged)" \
  "$(paged "$c" "$user_dn" "$user_pw")" "100 4"
expect_eq "H1: ... and unpaged" "$(unpaged "$c" "$user_dn" "$user_pw")" "100 4"
expect_eq "H1: the entrypoint recorded only its own rule" "$(marker "$c")" "users size.prtotal=unlimited"
expect_eq "H1: every other authenticated identity gets the paged total lifted" \
  "$(paged "$c" "$other_dn" "$user_pw")" "${total} 0"
start "$c" "$vol"
expect_eq "H1: unset removes only our rule" "$(olc_limits "$c")" "{0}${op_dn_rule}"
expect_eq "H1: the operator's limit still applies after our rule is gone" "$(paged "$c" "$user_dn" "$user_pw")" "100 4"
expect_eq "H1: ... and the marker is cleared" "$(marker "$c")" ""
expect_eq "H1: the other identity is back to the default cap" "$(paged "$c" "$other_dn" "$user_pw")" "${size_limit} 4"
clear_limits

# M1: an operator's own `users size.prtotal=` rule is never taken over,
# modified or removed, and with the variable unset the config is a no-op.
printf 'add: olcLimits\nolcLimits: {0}users size.prtotal=800\n' | limits_ldif
start "$c" "$vol"
expect_eq "M1: unset leaves an operator 'users size.prtotal=800' alone" "$(olc_limits "$c")" "{0}users size.prtotal=800"
expect_eq "M1: ... it is still the limit in force" "$(paged "$c" "$other_dn" "$user_pw")" "800 4"
expect_eq "M1: ... and no ownership marker was written" "$(marker "$c")" ""
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=800
expect_eq "M1: an identical operator rule is not duplicated nor claimed" "$(olc_limits "$c")" "{0}users size.prtotal=800"
expect_eq "M1: ... no marker either" "$(marker "$c")" ""
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=unlimited
expect_eq "M1: slapd allows one 'users' rule, so a different value is NOT added behind the operator's" \
  "$(olc_limits "$c")" "{0}users size.prtotal=800"
expect_eq "M1: ... the operator's rule stays the one in force" "$(paged "$c" "$other_dn" "$user_pw")" "800 4"
expect_eq "M1: ... nothing is claimed" "$(marker "$c")" ""
start "$c" "$vol"
expect_eq "M1: the next unset start still leaves the operator's rule" "$(olc_limits "$c")" "{0}users size.prtotal=800"
start "$c" "$vol"
expect_eq "M1: a further unset start changes nothing" "$(olc_limits "$c")" "{0}users size.prtotal=800"
clear_limits

# --- Fail closed: lost/corrupt state and a failed reconcile. ---------------
# A missing or damaged marker must never widen limits or drop an operator rule,
# and a reconcile step that fails must leave the previous limits in force.
printf 'add: olcLimits\nolcLimits: {0}%s\n' "$op_dn_rule" | limits_ldif

# corrupt marker (garbage, several lines) with the variable unset
docker exec "$c" sh -c "printf 'garbage line 1\nusers size.prtotal=1\n' > /etc/openldap/slapd.d/.paged-total-limit"
start "$c" "$vol"
expect_eq "fail-closed: a corrupt marker removes nothing" "$(olc_limits "$c")" "{0}${op_dn_rule}"
expect_eq "fail-closed: ... the operator's limit is still in force" "$(paged "$c" "$user_dn" "$user_pw")" "100 4"
expect_eq "fail-closed: ... the unusable marker is left as it was (ownership stays unknown)" "$(marker "$c" | head -n 1)" "garbage line 1"

# corrupt marker with the variable SET: our rule is added, ownership recorded afresh
docker exec "$c" sh -c "printf 'garbage\n' > /etc/openldap/slapd.d/.paged-total-limit"
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=unlimited
expect_eq "fail-closed: a corrupt marker with the variable set still keeps the operator rule first" \
  "$(olc_limits "$c" | sort | tr '\n' '|')" "{0}${op_dn_rule}|{1}users size.prtotal=unlimited|"
expect_eq "fail-closed: ... ownership is recorded afresh" "$(marker "$c")" "users size.prtotal=unlimited"

# lost marker, rule still there, variable unset: the rule is left (nothing is
# dropped), and the entrypoint says so
docker exec "$c" rm -f /etc/openldap/slapd.d/.paged-total-limit
start "$c" "$vol"
expect_eq "fail-closed: a lost marker leaves every rule in place" \
  "$(olc_limits "$c" | sort | tr '\n' '|')" "{0}${op_dn_rule}|{1}users size.prtotal=unlimited|"
if [[ "$(docker logs "$c" 2>&1)" == *"did not record as its own; leaving it untouched"* ]]; then
  ok "fail-closed: the lost-marker case is logged"
else
  bad "fail-closed: the lost-marker case was not logged"
fi
clear_limits
printf 'add: olcLimits\nolcLimits: {0}%s\n' "$op_dn_rule" | limits_ldif

# a failed reconcile (config file not writable): the previous limits stay in
# force, the marker is untouched, slapd still starts, and the failure is logged
cfg_file="/etc/openldap/slapd.d/cn=config/olcDatabase={1}mdb.ldif"
cfg_dir="/etc/openldap/slapd.d/cn=config"
file_mode="$(docker exec "$c" stat -c %a "$cfg_file")"
dir_mode="$(docker exec "$c" stat -c %a "$cfg_dir")"
docker exec -u root "$c" sh -c "chown root:root '$cfg_file' '$cfg_dir' && chmod 444 '$cfg_file' && chmod 555 '$cfg_dir'"
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=unlimited
expect_eq "fail-closed: a failed reconcile keeps the previous olcLimits" "$(olc_limits "$c")" "{0}${op_dn_rule}"
expect_eq "fail-closed: ... the operator's limit is still the one in force" "$(paged "$c" "$user_dn" "$user_pw")" "100 4"
expect_eq "fail-closed: ... nothing was widened for other identities" "$(paged "$c" "$other_dn" "$user_pw")" "${size_limit} 4"
expect_eq "fail-closed: ... no ownership was recorded" "$(marker "$c")" ""
if [[ "$(docker logs "$c" 2>&1)" == *"paged-total reconcile failed; the previous olcLimits rules were kept"* ]]; then
  ok "fail-closed: the failure is logged with a fixed line"
else
  bad "fail-closed: the failed reconcile was not logged"
fi
docker exec -u root "$c" sh -c "chown ldap:ldap '$cfg_file' '$cfg_dir' && chmod $file_mode '$cfg_file' && chmod $dir_mode '$cfg_dir'"
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=unlimited
expect_eq "fail-closed: once the file is writable again the reconcile succeeds" \
  "$(olc_limits "$c" | sort | tr '\n' '|')" "{0}${op_dn_rule}|{1}users size.prtotal=unlimited|"
clear_limits

# --- Re-review: marker validation, many rules, tightening, restore. ---------
real_image="$image"
start "$c" "$vol" # normalise: unset, stale marker cleared
clear_limits
set_marker() { docker exec "$c" sh -c 'printf "%b" "$1" > /etc/openldap/slapd.d/.paged-total-limit' sh "$1"; }
log_has() { [[ "$(docker logs "$c" 2>&1)" == *"$1"* ]]; }
# run_abort <image> <expected log text> [docker run args...]: the start must
# EXIT non-zero with that text, and slapd must not be serving.
run_abort() {
  local img="$1" want="$2" ca rc out waited=0
  shift 2
  ca="l3-ptl-abort-${suffix}"
  containers+=("$ca")
  docker rm -f "$ca" >/dev/null 2>&1 || true
  docker run -d --name "$ca" -v "${vol}-config:/etc/openldap/slapd.d" -v "${vol}-data:/var/lib/openldap/data" \
    -e LDAP_ROOT_DN="$base" -e LDAP_ADMIN_PASSWORD="$admin_pw" -e LDAP_SIZE_LIMIT="$size_limit" "$@" "$img" >/dev/null
  while [ "$waited" -lt 60 ] && [ "$(docker inspect -f '{{.State.Status}}' "$ca")" = "running" ]; do
    sleep 1
    waited=$((waited + 1))
  done
  rc="$(docker inspect -f '{{.State.ExitCode}}' "$ca")"
  out="$(docker logs "$ca" 2>&1 || true)"
  docker rm -f "$ca" >/dev/null 2>&1 || true
  if [ "$rc" != "0" ] && [[ "$out" == *"$want"* ]]; then
    echo "abort ok (exit ${rc})"
  else
    echo "no abort: exit ${rc}, last log: $(tail -n 1 <<<"$out")"
  fi
}
# offline view of the olcLimits values (works while slapd is not running)
offline_limits() {
  docker run --rm --user root --name "l3-ptl-off-${suffix}" --entrypoint slapcat \
    -v "${vol}-config:/etc/openldap/slapd.d" -v "${vol}-data:/var/lib/openldap/data" "$real_image" \
    -n 0 -F /etc/openldap/slapd.d -o ldif-wrap=no 2>/dev/null | sed -n 's/^olcLimits: {[0-9]*}//p' | sort | tr '\n' '|'
}

# H2: a marker is only trusted as exactly one line of the allowed form.
printf 'add: olcLimits\nolcLimits: {0}%s\n' "$op_dn_rule" | limits_ldif
set_marker "users size.prtotal=unlimited\n${op_dn_rule}\n"
start "$c" "$vol"
expect_eq "H2: a marker with a valid first line and a second line is ignored, no rule deleted" "$(olc_limits "$c")" "{0}${op_dn_rule}"
expect_eq "H2: ... and the operator's limit still applies" "$(paged "$c" "$user_dn" "$user_pw")" "100 4"
if log_has "marker is not in the expected form"; then ok "H2: ... with a fixed log line"; else bad "H2: the ignored marker was not logged"; fi
set_marker "${op_dn_rule}\n"
start "$c" "$vol"
expect_eq "H2: a marker naming the operator's own rule is ignored" "$(olc_limits "$c")" "{0}${op_dn_rule}"
set_marker "users size.prtotal=99999999999\n"
start "$c" "$vol"
expect_eq "H2: an out-of-range marker value is ignored" "$(olc_limits "$c")" "{0}${op_dn_rule}"
docker exec "$c" rm -f /etc/openldap/slapd.d/.paged-total-limit
clear_limits

# M1: no fixed index range - an owned rule behind more than 20 operator rules.
many=""
for i in $(seq 0 24); do many="${many}olcLimits: {${i}}dn.exact=\"uid=op${i},ou=people,${base}\" size.hard=50
"; done
printf 'add: olcLimits\n%s' "$many" | limits_ldif
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=unlimited
expect_eq "M1: with 25 operator rules ours is appended as the 26th" "$(olc_limits "$c" | wc -l | tr -d ' ')" "26"
expect_eq "M1: ... recorded in the marker" "$(marker "$c")" "users size.prtotal=unlimited"
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=900
expect_eq "M1: a later change replaces the owned rule at {25}" "$(olc_limits "$c" | grep -c 'users size.prtotal=900')" "1"
expect_eq "M1: ... without duplicating or losing rules" "$(olc_limits "$c" | wc -l | tr -d ' ')" "26"
start "$c" "$vol"
expect_eq "M1: unset removes it even at an index beyond 19" "$(olc_limits "$c" | grep -c 'users size.prtotal')" "0"
expect_eq "M1: ... all 25 operator rules stay" "$(olc_limits "$c" | wc -l | tr -d ' ')" "25"
expect_eq "M1: ... and the marker is cleared" "$(marker "$c")" ""
clear_limits

# Unreadable marker (root-owned, mode 000): ownership unknown, nothing is touched.
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=unlimited
expect_eq "unreadable marker: setup, our rule is in place" "$(olc_limits "$c")" "{0}users size.prtotal=unlimited"
docker exec -u root "$c" sh -c 'chown root:root /etc/openldap/slapd.d/.paged-total-limit && chmod 000 /etc/openldap/slapd.d/.paged-total-limit'
start "$c" "$vol"
expect_eq "unreadable marker: the rule is not removed" "$(olc_limits "$c")" "{0}users size.prtotal=unlimited"
if log_has "marker is not in the expected form"; then ok "unreadable marker: logged"; else bad "unreadable marker: not logged"; fi
docker exec -u root "$c" rm -f /etc/openldap/slapd.d/.paged-total-limit
clear_limits

# Tightening must not fail open: an unwritable config makes the reconcile fail.
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=unlimited
docker exec -u root "$c" sh -c "chown root:root '$cfg_file' '$cfg_dir' && chmod 444 '$cfg_file' && chmod 555 '$cfg_dir'"
docker stop "$c" >/dev/null # never run two containers on one live config
expect_eq "H3: removing a lifted rule (unset) with a failing reconcile aborts startup" \
  "$(run_abort "$real_image" "requested limit is stricter than the one in force")" "abort ok (exit 1)"
expect_eq "H3: lowering unlimited -> 900 with a failing reconcile aborts startup" \
  "$(run_abort "$real_image" "requested limit is stricter than the one in force" -e LDAP_PAGED_TOTAL_LIMIT=900)" "abort ok (exit 1)"
expect_eq "H3: the previous rule is still the stored policy" "$(offline_limits)" "users size.prtotal=unlimited|"
for cfgfix in "chown -R ldap:ldap /etc/openldap/slapd.d" "chmod ${dir_mode} ${cfg_dir}" "chmod ${file_mode} ${cfg_file}"; do
  # shellcheck disable=SC2086
  docker run --rm --user root --entrypoint "${cfgfix%% *}" -v "${vol}-config:/etc/openldap/slapd.d" "$real_image" ${cfgfix#* } >/dev/null
done

# Partial application and a failed restore, with a shim that lets the real
# slapmodify apply the paged-total change and THEN reports failure.
shim_dir="$(mktemp -d)"
cat > "${shim_dir}/slapmodify-shim" <<'SHIM'
#!/bin/sh
real=/opt/real-slapmodify/slapmodify # same basename: the tool picks its mode from argv[0]
file=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-l" ]; then file="$a"; fi
  prev="$a"
done
"$real" "$@"
rc=$?
if [ -n "$file" ] && [ -n "$FAKE_SLAPMODIFY" ] && grep -qE '^(add|delete): olcLimits$' "$file" 2>/dev/null; then
  if [ "$FAKE_SLAPMODIFY" = partial-lock ]; then chmod 555 "/etc/openldap/slapd.d/cn=config"; fi
  exit 1
fi
exit "$rc"
SHIM
cat > "${shim_dir}/Dockerfile" <<DOCKERFILE
FROM ${real_image}
USER root
COPY slapmodify-shim /tmp/slapmodify-shim
RUN p="\$(command -v slapmodify)" && mkdir /opt/real-slapmodify && mv "\$p" /opt/real-slapmodify/slapmodify && cp /tmp/slapmodify-shim "\$p" && chmod 755 "\$p"
USER ldap
DOCKERFILE
shim_image="l3-ptl-shim-${suffix}"
docker build -q -t "$shim_image" "$shim_dir" >/dev/null
images+=("$shim_image")

start "$c" "$vol"
clear_limits
printf 'add: olcLimits\nolcLimits: {0}%s\n' "$op_dn_rule" | limits_ldif
image="$shim_image"
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=unlimited -e FAKE_SLAPMODIFY=partial
image="$real_image"
expect_eq "partial application (raising): the change that was applied is rolled back" "$(olc_limits "$c")" "{0}${op_dn_rule}"
expect_eq "partial application (raising): the operator's limit is intact and nothing was widened" "$(paged "$c" "$other_dn" "$user_pw")" "${size_limit} 4"
expect_eq "partial application (raising): no ownership recorded" "$(marker "$c")" ""
if log_has "paged-total reconcile failed; the previous olcLimits rules were kept"; then ok "partial application (raising): logged"; else bad "partial application (raising): not logged"; fi

start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=unlimited
expect_eq "partial application (tightening): setup, our rule is in place" "$(olc_limits "$c" | sort | tr '\n' '|')" "{0}${op_dn_rule}|{1}users size.prtotal=unlimited|"
docker stop "$c" >/dev/null # never run two containers on one live config
expect_eq "partial application (tightening): the removal that was applied is rolled back, then startup aborts" \
  "$(run_abort "$shim_image" "requested limit is stricter than the one in force" -e FAKE_SLAPMODIFY=partial)" "abort ok (exit 1)"
expect_eq "partial application (tightening): the stored policy is the previous one" "$(offline_limits)" "dn.exact=\"${user_dn}\" size.soft=100 size.hard=100 size.prtotal=100|users size.prtotal=unlimited|"

expect_eq "failed restore: startup aborts instead of running on a half-written config" \
  "$(run_abort "$shim_image" "could not be restored; refusing to start" -e LDAP_PAGED_TOTAL_LIMIT=900 -e FAKE_SLAPMODIFY=partial-lock)" "abort ok (exit 1)"

if [ "$fail" -ne 0 ]; then
  echo "test-paged-total-limit: FAILED" >&2
  exit 1
fi
echo "test-paged-total-limit: all cases passed"
