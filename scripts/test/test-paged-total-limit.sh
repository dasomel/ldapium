#!/usr/bin/env bash
# Live regression test for LDAP_PAGED_TOTAL_LIMIT (issue #215, D215-18). The
# image reconciles `olcLimits: users size.prtotal=<value>` on the main mdb
# database as a STATELESS, explicit contract and the result changes what a
# non-root identity can read with a paged search. This drives the real
# entrypoint and a real slapd; it is not a fixture-only unit test.
#
# Contract under test:
#   unset            hands off: no olcLimits rule is read, changed or removed
#                    (and no state file exists);
#   <n>|unlimited    converge to exactly one rule `users size.prtotal=<value>`,
#                    appended after operator rules; the selector `users` is
#                    reserved while enabled (another shape there => abort);
#   off              remove exactly `users size.prtotal=<any value>`;
#   any failure to apply/verify/restore for set/off => startup aborts.
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
real_image="$image"
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
cfg_dir="/etc/openldap/slapd.d/cn=config"
cfg_file="${cfg_dir}/olcDatabase={1}mdb.ldif"
abort_msg="paged-total reconcile failed; refusing to start"

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
  local x
  for x in ${containers[@]+"${containers[@]}"}; do
    docker rm -f "$x" >/dev/null 2>&1 || true
  done
  for x in ${volumes[@]+"${volumes[@]}"}; do
    docker volume rm -f "$x" >/dev/null 2>&1 || true
  done
  for x in ${images[@]+"${images[@]}"}; do
    docker rmi -f "$x" >/dev/null 2>&1 || true
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

# start <name> <volume prefix> [extra docker args...]: (re)creates the container
# on the named volumes; a second call with the same prefix and another env is
# an "existing volume" restart. `image` may be swapped for a shim image.
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
sorted_limits() { olc_limits "$1" | sort | tr '\n' '|'; }
count_limits() { olc_limits "$1" | wc -l | tr -d ' '; }
# every olcLimits value, plain or base64 (`olcLimits::`, e.g. a rule naming a Korean DN)
count_all() {
  docker exec "$1" ldapsearch -x -LLL -o ldif-wrap=no -H "$ldapi" -D "cn=admin,cn=config" -w "$admin_pw" \
    -b "$db" -s base olcLimits 2>/dev/null | grep -c '^olcLimits::\? ' || true
}

# paged <container> <bind dn> <password>: "<entries> <rc>" of a paged search.
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

limits_ldif() { # operation lines on stdin: modify olcLimits on the main database
  { printf 'dn: %s\nchangetype: modify\n' "$db"; cat; } |
    docker exec -i "$c" ldapmodify -x -H "$ldapi" -D "cn=admin,cn=config" -w "$admin_pw" >/dev/null
}
clear_limits() { printf 'delete: olcLimits\n' | limits_ldif 2>/dev/null || true; }
add_limit() { printf 'add: olcLimits\nolcLimits: %s\n' "$1" | limits_ldif; }
log_has() { [[ "$(docker logs "$c" 2>&1)" == *"$1"* ]]; }
no_state_file() { # the stateless contract: nothing is recorded anywhere
  if docker exec "$c" test -e /etc/openldap/slapd.d/.paged-total-limit; then echo present; else echo absent; fi
}

# run_abort <image> <expected log text> [docker run args...]: the start must
# EXIT non-zero with that text. The previous container is stopped first so two
# containers never run on one live config.
run_abort() {
  local img="$1" want="$2" ca rc out waited=0
  shift 2
  docker stop "$c" >/dev/null 2>&1 || true
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
# offline view of the stored olcLimits (works while slapd is not running)
offline_limits() {
  docker run --rm --user root --name "l3-ptl-off-${suffix}" --entrypoint slapcat \
    -v "${vol}-config:/etc/openldap/slapd.d" -v "${vol}-data:/var/lib/openldap/data" "$real_image" \
    -n 0 -F /etc/openldap/slapd.d -o ldif-wrap=no 2>/dev/null | sed -n 's/^olcLimits: {[0-9]*}//p' | sort | tr '\n' '|'
}
# make the main database's config file unwritable / writable again
file_mode="" dir_mode=""
lock_cfg() {
  file_mode="$(docker exec "$c" stat -c %a "$cfg_file")"
  dir_mode="$(docker exec "$c" stat -c %a "$cfg_dir")"
  docker exec -u root "$c" sh -c "chown root:root '$cfg_file' '$cfg_dir' && chmod 444 '$cfg_file' && chmod 555 '$cfg_dir'"
}
unlock_cfg() {
  local cmd
  for cmd in "chown -R ldap:ldap /etc/openldap/slapd.d" "chmod ${dir_mode} ${cfg_dir}" "chmod ${file_mode} ${cfg_file}"; do
    # shellcheck disable=SC2086
    docker run --rm --user root --entrypoint "${cmd%% *}" -v "${vol}-config:/etc/openldap/slapd.d" "$real_image" ${cmd#* } >/dev/null
  done
}

admin_dn="cn=admin,${base}"
user_dn="uid=pagedtest,ou=people,${base}"
other_dn="uid=pagedother,ou=people,${base}"
kr_cn="한국"
kr_dn="cn=${kr_cn},ou=people,${base}"

# --- Values: anything the image cannot honour never starts slapd. -----------
for bad_val in abc 0 -5 1.5 01 2147483648 99999999999999999999 OFF Off; do
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

# --- Fixture: 1200 users, two ordinary identities. --------------------------
vol="l3-ptl-${suffix}"
new_volumes "$vol"
c="l3-ptl-${suffix}"
start "$c" "$vol"
# Bulk load through the wire (the generator emits ou=people itself). `-i` is
# required: without it docker exec silently drops the piped LDIF.
python3 "${repo_root}/scripts/bench-generate-ldif.py" --count "$entries" --base "$base" |
  docker exec -i "$c" ldapadd -x -H ldap://localhost -D "$admin_dn" -w "$admin_pw" >/dev/null
for uid in pagedtest pagedother; do
  docker exec -i "$c" ldapadd -x -H ldap://localhost -D "$admin_dn" -w "$admin_pw" >/dev/null <<EOF
dn: uid=${uid},ou=people,${base}
objectClass: inetOrgPerson
uid: ${uid}
cn: ${uid}
sn: Test
EOF
  docker exec "$c" ldappasswd -x -H ldap://localhost -D "$admin_dn" -w "$admin_pw" -s "$user_pw" "uid=${uid},ou=people,${base}" >/dev/null
done
# A non-ASCII DN: slapcat prints olcLimits rules that name it as `olcLimits:: <base64>`.
{
  printf 'dn:: %s\nobjectClass: inetOrgPerson\ncn:: %s\nsn: Han\n' \
    "$(printf '%s' "$kr_dn" | base64 | tr -d '\n')" "$(printf '%s' "$kr_cn" | base64 | tr -d '\n')"
} | docker exec -i "$c" ldapadd -x -H ldap://localhost -D "$admin_dn" -w "$admin_pw" >/dev/null
docker exec "$c" ldappasswd -x -H ldap://localhost -D "$admin_dn" -w "$admin_pw" -s "$user_pw" "$kr_dn" >/dev/null
total="$((entries + 3))"

# --- unset: hands off (olcSizeLimit-only config, then operator rules). -------
expect_eq "unset: an olcSizeLimit-only config has no olcLimits" "$(olc_limits "$c")" ""
expect_eq "unset: rootDN paged search reads everything" "$(paged "$c" "$admin_dn" "$admin_pw")" "${total} 0"
expect_eq "unset: non-root paged search stops at the size limit (rc 4=sizeLimitExceeded)" "$(paged "$c" "$user_dn" "$user_pw")" "${size_limit} 4"
expect_eq "unset: no state file exists" "$(no_state_file)" "absent"
add_limit '{0}users size.prtotal=500'
start "$c" "$vol"
expect_eq "unset: an operator 'users size.prtotal=500' is left untouched" "$(olc_limits "$c")" "{0}users size.prtotal=500"
expect_eq "unset: ... it still governs" "$(paged "$c" "$other_dn" "$user_pw")" "500 4"
add_limit '{1}dn.exact="uid=pagedtest,ou=people,dc=example,dc=org" size.soft=50'
start "$c" "$vol"
expect_eq "unset: other operator rules are untouched as well" "$(sorted_limits "$c")" '{0}users size.prtotal=500|{1}dn.exact="uid=pagedtest,ou=people,dc=example,dc=org" size.soft=50|'
expect_eq "unset: still no state file" "$(no_state_file)" "absent"
clear_limits

# --- set: converge to exactly one rule. -------------------------------------
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=unlimited
expect_eq "unlimited: the rule is added on an existing volume" "$(olc_limits "$c")" "{0}users size.prtotal=unlimited"
expect_eq "unlimited: non-root paged search completes" "$(paged "$c" "$user_dn" "$user_pw")" "${total} 0"
expect_eq "unlimited: non-root UNPAGED search is still capped by olcSizeLimit" "$(unpaged "$c" "$user_dn" "$user_pw")" "${size_limit} 4"
expect_eq "unlimited: rootDN unaffected" "$(paged "$c" "$admin_dn" "$admin_pw")" "${total} 0"
expect_eq "unlimited: no state file is written" "$(no_state_file)" "absent"
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=unlimited
expect_eq "unlimited again: idempotent, still one rule" "$(olc_limits "$c")" "{0}users size.prtotal=unlimited"
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=900
expect_eq "900: the value converges (replaced, not duplicated)" "$(olc_limits "$c")" "{0}users size.prtotal=900"
expect_eq "900: the paged total caps at 900" "$(paged "$c" "$user_dn" "$user_pw")" "900 4"
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=unlimited
expect_eq "raising 900 -> unlimited converges" "$(olc_limits "$c")" "{0}users size.prtotal=unlimited"

# --- unset after set: still hands off (the rule stays; `off` removes it). ----
start "$c" "$vol"
expect_eq "unset after set: the rule is NOT removed" "$(olc_limits "$c")" "{0}users size.prtotal=unlimited"
expect_eq "unset after set: no state file" "$(no_state_file)" "absent"

# --- off: removes exactly the feature's own shape. ---------------------------
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=off
expect_eq "off: the rule is removed" "$(olc_limits "$c")" ""
expect_eq "off: non-root is back to the default cap" "$(paged "$c" "$user_dn" "$user_pw")" "${size_limit} 4"
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=off
expect_eq "off again: a no-op" "$(olc_limits "$c")" ""

# --- reserved selector: a differently shaped `users` rule. -------------------
add_limit '{0}users size.soft=50 size.prtotal=700'
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=off
expect_eq "off: a differently shaped 'users' rule is left alone" "$(olc_limits "$c")" "{0}users size.soft=50 size.prtotal=700"
if log_has "leaving the differently shaped olcLimits rule"; then ok "off: ... and logged"; else bad "off: the left-alone rule was not logged"; fi
expect_eq "set against a differently shaped 'users' rule aborts startup" \
  "$(run_abort "$real_image" "already exists in another shape" -e LDAP_PAGED_TOTAL_LIMIT=unlimited)" "abort ok (exit 1)"
expect_eq "... and the operator's rule is untouched" "$(offline_limits)" "users size.soft=50 size.prtotal=700|"
start "$c" "$vol"
expect_eq "unset still starts with that operator rule (hands off)" "$(olc_limits "$c")" "{0}users size.soft=50 size.prtotal=700"
clear_limits

# --- operator rules keep precedence (first match wins). ----------------------
op_dn_rule="dn.exact=\"${user_dn}\" size.soft=100 size.hard=100 size.prtotal=100"
add_limit "{0}${op_dn_rule}"
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=unlimited
expect_eq "operator DN rule first, ours appended behind it" "$(sorted_limits "$c")" "{0}${op_dn_rule}|{1}users size.prtotal=unlimited|"
expect_eq "operator DN rule: its limits are still IN FORCE for that DN (paged)" "$(paged "$c" "$user_dn" "$user_pw")" "100 4"
expect_eq "operator DN rule: ... and unpaged" "$(unpaged "$c" "$user_dn" "$user_pw")" "100 4"
expect_eq "operator DN rule: every other identity gets the lifted total" "$(paged "$c" "$other_dn" "$user_pw")" "${total} 0"
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=off
expect_eq "off removes only ours, the operator's rule stays" "$(olc_limits "$c")" "{0}${op_dn_rule}"
expect_eq "off: the other identity is back to the default cap" "$(paged "$c" "$other_dn" "$user_pw")" "${size_limit} 4"
clear_limits

# --- many operator rules: no index range limit. ------------------------------
many=""
for i in $(seq 0 24); do many="${many}olcLimits: {${i}}dn.exact=\"uid=op${i},ou=people,${base}\" size.hard=50
"; done
printf 'add: olcLimits\n%s' "$many" | limits_ldif
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=unlimited
expect_eq "25 operator rules: ours is appended as the 26th" "$(count_limits "$c")" "26"
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=900
expect_eq "25 operator rules: a value change converges at the end" "$(olc_limits "$c" | grep -c 'users size.prtotal=900')" "1"
expect_eq "25 operator rules: ... still 26 rules" "$(count_limits "$c")" "26"
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=off
expect_eq "25 operator rules: off removes ours only" "$(count_limits "$c")" "25"
expect_eq "25 operator rules: ... and no 'users' rule is left" "$(olc_limits "$c" | grep -c '^{[0-9]*}users')" "0"
clear_limits

# --- converged means LAST: an operator rule behind ours would never be reached. -
# {0}users size.prtotal=unlimited, then an operator DN rule at {1}. First match
# wins, so with the variable already equal to ours the rules must be re-ordered.
add_limit '{0}users size.prtotal=unlimited'
add_limit "{1}${op_dn_rule}"
expect_eq "order setup: ours first, the operator's DN rule behind it (as written by ldapsearch)" \
  "$(olc_limits "$c" | tr '\n' '|')" "{0}users size.prtotal=unlimited|{1}${op_dn_rule}|"
expect_eq "order setup: ... so the DN's cap is ignored today" "$(paged "$c" "$user_dn" "$user_pw")" "${total} 0"
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=unlimited
expect_eq "order: the rule is re-appended behind the operator's rule (real ldapsearch order)" \
  "$(olc_limits "$c" | tr '\n' '|')" "{0}${op_dn_rule}|{1}users size.prtotal=unlimited|"
expect_eq "order: the capped DN is capped again (behavioural paged search)" "$(paged "$c" "$user_dn" "$user_pw")" "100 4"
expect_eq "order: every other identity keeps the lifted total" "$(paged "$c" "$other_dn" "$user_pw")" "${total} 0"
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=unlimited
expect_eq "order: a converged config is left alone on the next start" \
  "$(olc_limits "$c" | tr '\n' '|')" "{0}${op_dn_rule}|{1}users size.prtotal=unlimited|"
clear_limits

# --- every value form slapd accepts is the setting's own shape. ---------------
add_limit '{0}users size.prtotal=-1'
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=off
expect_eq "prtotal=-1: off removes it" "$(olc_limits "$c")" ""
expect_eq "prtotal=-1: ... and the default cap is back" "$(paged "$c" "$other_dn" "$user_pw")" "${size_limit} 4"
add_limit '{0}users size.prtotal=-1'
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=900
expect_eq "prtotal=-1: a set request converges it instead of aborting" "$(olc_limits "$c")" "{0}users size.prtotal=900"
clear_limits
add_limit '{0}users size.prtotal=disabled'
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=off
expect_eq "prtotal=disabled: off removes it" "$(olc_limits "$c")" ""
clear_limits

# --- non-ASCII operator rules (olcLimits:: base64) must count for the order. ---
kr_rule="dn.exact=\"${kr_dn}\" size.soft=100 size.hard=100 size.prtotal=100"
add_limit '{0}users size.prtotal=unlimited'
add_limit "{1}${kr_rule}"
expect_eq "base64: setup, ours first and the Korean-DN rule behind it, so the DN is NOT capped" "$(paged "$c" "$kr_dn" "$user_pw")" "${total} 0"
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=unlimited
expect_eq "base64: the owned rule was moved to the end (index 1, the base64 rule is {0})" "$(olc_limits "$c")" "{1}users size.prtotal=unlimited"
expect_eq "base64: both rules are there" "$(count_all "$c")" "2"
expect_eq "base64: the Korean DN is capped by the operator's rule again (behavioural)" "$(paged "$c" "$kr_dn" "$user_pw")" "100 4"
expect_eq "base64: every other identity keeps the lifted total" "$(paged "$c" "$other_dn" "$user_pw")" "${total} 0"
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=unlimited
expect_eq "base64: converged, left alone on the next start" "$(olc_limits "$c")" "{1}users size.prtotal=unlimited"
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=off
expect_eq "base64: off removes only ours" "$(count_all "$c")" "1"
expect_eq "base64: ... the Korean DN stays capped" "$(paged "$c" "$kr_dn" "$user_pw")" "100 4"
clear_limits

# --- parser: spellings, case, whitespace (slapd 2.6.15 accepts them all). -----
# The reserved rule is recognised SEMANTICALLY (selector `users` with only a
# size.prtotal limit), whatever the case, the whitespace or the value spelling.
specs=(
  'users size.prtotal=unlimited'
  $'users\tsize.prtotal=unlimited'
  'USERS size.prtotal=unlimited'
  'users SIZE.PRTOTAL=unlimited'
  'users   size.prtotal=unlimited'
  'users size.prtotal=-01'
  'users size.prtotal=-1'
  'users size.prtotal=NONE'
  'users size.prtotal=None'
  'users size.prtotal=+007'
  'Users Size.PrTotal=Disabled'
  $'users \t size.prtotal=HARD'
  'users size.prtotal=0100'
  'users size.prtotal=0'
  '"users" size.prtotal=unlimited'
  'users size.prtotal="unlimited"'
  'us"ers" size.prtotal=unlimited'
  'users "size.prtotal=unlimited"'
  '"USERS" Size.PrTotal="NONE"'
)
for spec in "${specs[@]}"; do
  q="$(printf '%q' "$spec")"
  add_limit "{0}${spec}"
  start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=off
  expect_eq "parser ${q}: off removes it" "$(count_all "$c")" "0"
  add_limit "{0}${spec}"
  start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=900
  expect_eq "parser ${q}: a set request converges to the one canonical rule" "$(olc_limits "$c")" "{0}users size.prtotal=900"
  expect_eq "parser ${q}: ... and nothing else is left" "$(count_all "$c")" "1"
  clear_limits
done
# Equal by VALUE (not by text) and already last: left exactly as written.
for pair in 'USERS size.prtotal=0900|900' 'users size.prtotal=NONE|unlimited' 'users size.prtotal=-01|unlimited' 'Users   Size.PrTotal=+5|5'; do
  spec="${pair%|*}"
  want="${pair#*|}"
  add_limit "{0}${spec}"
  start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT="${want}"
  expect_eq "by value: '${spec}' already equals ${want}, left untouched" "$(olc_limits "$c")" "{0}${spec}"
  clear_limits
done
# `users` with ANY other limit is not the reserved shape: conflict for set, left alone for off.
for spec in 'users size.prtotal=100 size.hard=50' 'USERS size.hard=50' 'users size.prtotal=100 time.soft=5'; do
  add_limit "{0}${spec}"
  expect_eq "other shape '${spec}': set aborts as a conflict" \
    "$(run_abort "$real_image" "already exists in another shape" -e LDAP_PAGED_TOTAL_LIMIT=unlimited)" "abort ok (exit 1)"
  expect_eq "other shape '${spec}': the rule is untouched" "$(offline_limits)" "${spec}|"
  start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=off
  expect_eq "other shape '${spec}': off leaves it alone" "$(olc_limits "$c")" "{0}${spec}"
  clear_limits
done

# A quoted DN with spaces and a comma is ONE token and never the reserved selector,
# even when its text looks like the reserved rule.
for dnrule in 'dn.exact="cn=users size.prtotal=unlimited,dc=example,dc=org" size.soft=100' \
  'dn.exact="cn=John Doe,ou=people,dc=example,dc=org" size.hard=100' \
  'dn.exact="cn=a\, b,dc=example,dc=org" size.soft=100'; do
  add_limit "{0}${dnrule}"
  start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=off
  expect_eq "quoted DN '${dnrule}': off leaves it alone" "$(olc_limits "$c")" "{0}${dnrule}"
  start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=unlimited
  expect_eq "quoted DN: set appends ours behind it" "$(sorted_limits "$c")" "{0}${dnrule}|{1}users size.prtotal=unlimited|"
  start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=off
  expect_eq "quoted DN: off removes only ours" "$(olc_limits "$c")" "{0}${dnrule}"
  clear_limits
done

# Not certain => no guessing: an unterminated quote aborts in set/off before any
# modification, and unset (hands off) never reads the config at all.
add_limit '{0}users size.prtotal="unlimited'
expect_eq "unterminated quote: set aborts" \
  "$(run_abort "$real_image" "could not be parsed with certainty" -e LDAP_PAGED_TOTAL_LIMIT=900)" "abort ok (exit 1)"
expect_eq "unterminated quote: off aborts" \
  "$(run_abort "$real_image" "could not be parsed with certainty" -e LDAP_PAGED_TOTAL_LIMIT=off)" "abort ok (exit 1)"
expect_eq "unterminated quote: nothing was modified" "$(offline_limits)" 'users size.prtotal="unlimited|'
start "$c" "$vol"
expect_eq "unterminated quote: unset never reads the rules and starts" "$(olc_limits "$c")" '{0}users size.prtotal="unlimited'
clear_limits

# --- failed apply aborts, in both directions (unwritable config). ------------
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=900
lock_cfg
expect_eq "unwritable config: lowering 900 -> 100 aborts" \
  "$(run_abort "$real_image" "$abort_msg" -e LDAP_PAGED_TOTAL_LIMIT=100)" "abort ok (exit 1)"
expect_eq "unwritable config: raising 900 -> unlimited aborts as well" \
  "$(run_abort "$real_image" "$abort_msg" -e LDAP_PAGED_TOTAL_LIMIT=unlimited)" "abort ok (exit 1)"
expect_eq "unwritable config: off aborts" \
  "$(run_abort "$real_image" "$abort_msg" -e LDAP_PAGED_TOTAL_LIMIT=off)" "abort ok (exit 1)"
expect_eq "unwritable config: the previous policy is what is stored" "$(offline_limits)" "users size.prtotal=900|"
# already converged: nothing to write, so an unwritable config is no obstacle
unlock_cfg
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=900
lock_cfg
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=900
expect_eq "idempotent: an already converged value needs no write and starts on a locked config" "$(olc_limits "$c")" "{0}users size.prtotal=900"
docker stop "$c" >/dev/null
unlock_cfg
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=900
clear_limits

# --- failed apply, partial application, failed restore, crash (shim). --------
# The shim lets the real slapmodify apply the paged-total change and THEN
# fails (partial), also locks the config directory (partial-lock), or hangs so
# the container can be killed mid-reconcile (hang).
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
if [ -n "$file" ] && [ "$FAKE_SLAPMODIFY" = noop ] && grep -qE '^(add|delete): olcLimits$' "$file" 2>/dev/null; then
  exit 0 # claims success without applying anything
fi
"$real" "$@"
rc=$?
if [ -n "$file" ] && [ -n "$FAKE_SLAPMODIFY" ] && grep -qE '^(add|delete): olcLimits$' "$file" 2>/dev/null; then
  if [ "$FAKE_SLAPMODIFY" = partial-lock ]; then chmod 555 "/etc/openldap/slapd.d/cn=config"; fi
  if [ "$FAKE_SLAPMODIFY" = hang ]; then touch /tmp/applied; sleep 600; fi
  exit 1
fi
exit "$rc"
SHIM
cat > "${shim_dir}/Dockerfile" <<DOCKERFILE
FROM ${real_image}
USER root
COPY slapmodify-shim /tmp/slapmodify-shim
COPY slapcat-shim /tmp/slapcat-shim
COPY base64-shim /tmp/base64-shim
RUN p="\$(command -v base64)" && mkdir /opt/real-base64 && cp -L "\$p" /opt/real-base64/base64 && rm -f "\$p" && cp /tmp/base64-shim "\$p" && chmod 755 "\$p"
RUN p="\$(command -v slapcat)" && mkdir /opt/real-slapcat && mv "\$p" /opt/real-slapcat/slapcat && cp /tmp/slapcat-shim "\$p" && chmod 755 "\$p"
RUN p="\$(command -v slapmodify)" && mkdir /opt/real-slapmodify && mv "\$p" /opt/real-slapmodify/slapmodify && cp /tmp/slapmodify-shim "\$p" && chmod 755 "\$p"
USER ldap
DOCKERFILE
cat > "${shim_dir}/slapcat-shim" <<'SHIM'
#!/bin/sh
real=/opt/real-slapcat/slapcat # same basename: the tool picks its mode from argv[0]
case " $* " in
  *ldif-wrap=no*)
    if [ -n "$FAKE_SLAPCAT" ]; then
      n=$(cat /tmp/slapcat.n 2>/dev/null || echo 0)
      n=$((n + 1))
      echo "$n" > /tmp/slapcat.n
      case "$FAKE_SLAPCAT" in
        fail) exit 1 ;;
        empty)
          file=""
          prev=""
          for a in "$@"; do
            if [ "$prev" = "-l" ]; then file="$a"; fi
            prev="$a"
          done
          : > "$file"
          exit 0
          ;;
        second) if [ "$n" -ge 2 ]; then exit 1; fi ;;
      esac
    fi
    ;;
esac
exec "$real" "$@"
SHIM
cat > "${shim_dir}/base64-shim" <<'SHIM'
#!/bin/sh
if [ "$FAKE_BASE64" = fail ] && [ "$1" = "-d" ]; then exit 1; fi
exec /opt/real-base64/base64 "$@"
SHIM
shim_image="l3-ptl-shim-${suffix}"
docker build -q -t "$shim_image" "$shim_dir" >/dev/null
images+=("$shim_image")

start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=900
add_limit "{1}${kr_rule}"
expect_eq "decoder fails on a valid base64 rule: set aborts before changing anything" \
  "$(run_abort "$shim_image" "$abort_msg" -e LDAP_PAGED_TOTAL_LIMIT=100 -e FAKE_BASE64=fail)" "abort ok (exit 1)"
expect_eq "decoder fails: off aborts instead of missing a rule it could not read" \
  "$(run_abort "$shim_image" "$abort_msg" -e LDAP_PAGED_TOTAL_LIMIT=off -e FAKE_BASE64=fail)" "abort ok (exit 1)"
expect_eq "decoder fails: nothing was modified" "$(offline_limits)" "users size.prtotal=900|"
image="$shim_image"
start "$c" "$vol" -e FAKE_BASE64=fail
image="$real_image"
expect_eq "decoder fails: unset never reads the rules and starts" "$(olc_limits "$c")" "{0}users size.prtotal=900"
clear_limits
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=900
expect_eq "dump read fails (slapcat exits 1): set aborts before changing anything" \
  "$(run_abort "$shim_image" "$abort_msg" -e LDAP_PAGED_TOTAL_LIMIT=100 -e FAKE_SLAPCAT=fail)" "abort ok (exit 1)"
expect_eq "dump read fails: off aborts too" \
  "$(run_abort "$shim_image" "$abort_msg" -e LDAP_PAGED_TOTAL_LIMIT=off -e FAKE_SLAPCAT=fail)" "abort ok (exit 1)"
expect_eq "dump read fails: the stored policy is untouched" "$(offline_limits)" "users size.prtotal=900|"
expect_eq "dump comes back EMPTY with exit 0: off aborts instead of reading 'no rules'" \
  "$(run_abort "$shim_image" "$abort_msg" -e LDAP_PAGED_TOTAL_LIMIT=off -e FAKE_SLAPCAT=empty)" "abort ok (exit 1)"
expect_eq "empty dump: the stored policy is untouched" "$(offline_limits)" "users size.prtotal=900|"
expect_eq "post-apply verification cannot read the dump: rolled back, then startup aborts" \
  "$(run_abort "$shim_image" "$abort_msg" -e LDAP_PAGED_TOTAL_LIMIT=100 -e FAKE_SLAPCAT=second)" "abort ok (exit 1)"
expect_eq "post-apply verification failure: the previous policy is restored" "$(offline_limits)" "users size.prtotal=900|"
expect_eq "partial application (set): the applied change is rolled back, then startup aborts" \
  "$(run_abort "$shim_image" "$abort_msg" -e LDAP_PAGED_TOTAL_LIMIT=100 -e FAKE_SLAPMODIFY=partial)" "abort ok (exit 1)"
expect_eq "partial application (set): the stored policy is the previous one" "$(offline_limits)" "users size.prtotal=900|"
expect_eq "partial application (off): rolled back, then startup aborts" \
  "$(run_abort "$shim_image" "$abort_msg" -e LDAP_PAGED_TOTAL_LIMIT=off -e FAKE_SLAPMODIFY=partial)" "abort ok (exit 1)"
expect_eq "partial application (off): the stored policy is the previous one" "$(offline_limits)" "users size.prtotal=900|"
expect_eq "off aborts loudly when the removal leaves a rule behind (shim: the delete is a no-op)" \
  "$(run_abort "$shim_image" "$abort_msg" -e LDAP_PAGED_TOTAL_LIMIT=off -e FAKE_SLAPMODIFY=noop)" "abort ok (exit 1)"
expect_eq "off aborts: ... and the rule is still stored" "$(offline_limits)" "users size.prtotal=900|"
expect_eq "partial application (raising) aborts too: nothing is served on an unproven policy" \
  "$(run_abort "$shim_image" "$abort_msg" -e LDAP_PAGED_TOTAL_LIMIT=unlimited -e FAKE_SLAPMODIFY=partial)" "abort ok (exit 1)"

# crash: the change is applied, the container is killed before anything else
docker stop "$c" >/dev/null
docker rm -f "l3-ptl-crash-${suffix}" >/dev/null 2>&1 || true
containers+=("l3-ptl-crash-${suffix}")
docker run -d --name "l3-ptl-crash-${suffix}" -v "${vol}-config:/etc/openldap/slapd.d" -v "${vol}-data:/var/lib/openldap/data" \
  -e LDAP_ROOT_DN="$base" -e LDAP_ADMIN_PASSWORD="$admin_pw" -e LDAP_SIZE_LIMIT="$size_limit" \
  -e LDAP_PAGED_TOTAL_LIMIT=100 -e FAKE_SLAPMODIFY=hang "$shim_image" >/dev/null
waited=0
until docker exec "l3-ptl-crash-${suffix}" test -e /tmp/applied 2>/dev/null || [ "$waited" -ge 60 ]; do
  sleep 1
  waited=$((waited + 1))
done
docker kill "l3-ptl-crash-${suffix}" >/dev/null
docker rm -f "l3-ptl-crash-${suffix}" >/dev/null
expect_eq "crash after apply: the change is on disk (900 became 100)" "$(offline_limits)" "users size.prtotal=100|"
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=100
expect_eq "crash after apply: the next start with the same request is a clean no-op" "$(olc_limits "$c")" "{0}users size.prtotal=100"
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=unlimited
expect_eq "crash after apply: any later request converges (no state to disagree)" "$(olc_limits "$c")" "{0}users size.prtotal=unlimited"

expect_eq "failed restore: startup aborts instead of running on a half-written config" \
  "$(run_abort "$shim_image" "could not be restored; refusing to start" -e LDAP_PAGED_TOTAL_LIMIT=900 -e FAKE_SLAPMODIFY=partial-lock)" "abort ok (exit 1)"

if [ "$fail" -ne 0 ]; then
  echo "test-paged-total-limit: FAILED" >&2
  exit 1
fi
echo "test-paged-total-limit: all cases passed"
