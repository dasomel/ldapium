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

# --- Case 2 first: invalid values never start slapd. ------------------------
for bad_val in abc 0 -5 1.5 01; do
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

total="$((entries + 1))"
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

# An operator's own olcLimits (any other shape) survives both directions.
docker exec -i "$c" ldapmodify -x -H "$ldapi" -D "cn=admin,cn=config" -w "$admin_pw" >/dev/null <<EOF
dn: ${db}
changetype: modify
add: olcLimits
olcLimits: {0}dn.exact="uid=pagedtest,ou=people,${base}" time.soft=60
EOF
start "$c" "$vol"
expect_eq "operator olcLimits untouched when the variable is unset" "$(olc_limits "$c")" "{0}dn.exact=\"uid=pagedtest,ou=people,${base}\" time.soft=60"
start "$c" "$vol" -e LDAP_PAGED_TOTAL_LIMIT=unlimited
expect_eq "operator olcLimits kept alongside ours when it is set" \
  "$(olc_limits "$c" | sort | tr '\n' '|')" \
  "{0}users size.prtotal=unlimited|{1}dn.exact=\"uid=pagedtest,ou=people,${base}\" time.soft=60|"
start "$c" "$vol"
expect_eq "unset: only ours is removed, operator's stays" "$(olc_limits "$c")" "{0}dn.exact=\"uid=pagedtest,ou=people,${base}\" time.soft=60"

if [ "$fail" -ne 0 ]; then
  echo "test-paged-total-limit: FAILED" >&2
  exit 1
fi
echo "test-paged-total-limit: all cases passed"
