#!/usr/bin/env bash
# Live test: the machine read-only ACL (#214) and the replication identity rule
# (LDAP_REPLICATION_IDENTITY=prepare, #229) on ONE slapd with a defined order
# (#277, docs/changes/machine-principal-auth D30, docs/changes/replication-identity):
#
#   olcAccess {0}  replication identity rule (always first; prepare checks this)
#   olcAccess {1}-{3}  the three machine rules
#   olcAccess {4}..    the image's own rules, in their original order
#
# Both install orders against the real entrypoint and a real slapd:
#   order A: prepare first, then the machine rules at {1}-{3} (guide section 5.1)
#   order B: the machine rules first at {0}-{2} (guide section 5), then prepare,
#            which inserts its rule at {0} and pushes the machine rules to {1}-{3}
# In each order: restarts of `prepare` with the machine rules present, the machine
# DN's read-only reach, the identity's read-only/TLS-only reach, the documented
# machine rollback (leaves the identity rule alone), and the independent rollback of
# the identity rule (leaves the machine rules alone; they move back to {0}-{2}).
# The apply and rollback commands are cut out of docs/machine-ldap-account.md, so the
# guide cannot drift from what is tested here.
#
# Usage: scripts/test/test-machine-acl-with-identity.sh [image]
#   image defaults to ldapium:e2e. Requires Docker. MACLID_TIMEOUT (seconds,
#   default 120) bounds every wait. Resources are named ldapium-maclid-* and only
#   those are removed on exit.
set -euo pipefail
# Never pipe into `grep -q` (SIGPIPE + pipefail): match captured variables.

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
image="${1:-ldapium:e2e}"
timeout_s="${MACLID_TIMEOUT:-120}"
suffix="$$"
pw="maclidAdminPw-Zq7Lm2Xv9Kd4Hs8Wt1Bn6Rc3Yf5Ug0Pe"
idpw="maclidIdentityPw-Jh6Gf3Dd9Sa2Qw8Er5Ty1Ui4Op7Lk0"
mpw="maclidMachinePw-Nn4Bb7Vv1Cc9Xx3Zz6Aa2Ss5Dd8Ff0"
hpw="maclidHumanPw-1"
base="dc=example,dc=org"
admin="cn=admin,${base}"
iddn="cn=replicator,${base}"
mdn="uid=machine,ou=system,${base}"
bdn="ou=people,${base}"
maindb="olcDatabase={1}mdb,cn=config"
ldapi='ldapi://%2Fvar%2Flib%2Fopenldap%2Frun%2Fldapi'
net="ldapium-maclid-net-${suffix}"
certs="ldapium-maclid-certs-${suffix}"
guide="${repo}/docs/machine-ldap-account.md"
ldif="${repo}/scripts/test/fixtures/machine-acl/main-database.ldif"
work="$(mktemp -d)"

fail=0
ok() { printf 'PASS: %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }
check() { # label expected actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: expected '$2', got '$3'"; fi
}

reg_containers=()
reg_vols=("$certs")
# shellcheck disable=SC2317,SC2329 # invoked via the trap below
cleanup() {
  local x
  trap - EXIT
  for x in "${reg_containers[@]}"; do docker rm -fv "$x" >/dev/null 2>&1 || true; done
  for x in "${reg_vols[@]}"; do docker volume rm -f "$x" >/dev/null 2>&1 || true; done
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

poll() {
  local w=0
  until "$@" >/dev/null 2>&1; do
    sleep 1
    w=$((w + 1))
    [ "$w" -lt "$timeout_s" ] || return 1
  done
}
# shellcheck disable=SC2317,SC2329 # invoked through poll
ready() { docker exec "$1" ldapwhoami -x -H ldap://localhost >/dev/null 2>&1; }

# The commands under test, cut out of the operator guide.
apply_cmd="$(sed -n "/^\$EXEC env MACHINE_DN=.*ALLOWED_DN=.*sh -c 'sed -e \"s|@MACHINE_DN@/s/.*sh -c '\(.*\)' < main-database.ldif\$/\1/p" "$guide")"
apply_shifted_cmd="$(sed -n "/^\$EXEC env MACHINE_DN=.*sh -c 'sed -e \"s|^olcAccess: {2}/s/.*sh -c '\(.*\)' < main-database.ldif\$/\1/p" "$guide")"
rollback_cmd="$(sed -n "/ROOT_DN=\"\$ROOT_DN\" sh -c '\$/,/^'\$/p" "$guide" | sed '1d;$d')"
if [ -z "$apply_cmd" ] || [ -z "$apply_shifted_cmd" ] || [ -z "$rollback_cmd" ]; then
  echo "cannot cut the documented commands out of ${guide}" >&2
  exit 1
fi
ok "documented apply, shifted apply and rollback commands extracted from the guide"

docker network create "$net" >/dev/null
docker volume create "$certs" >/dev/null
docker run --rm --user 0 -v "${certs}:/certs" --entrypoint openssl "$image" \
  req -x509 -newkey rsa:2048 -nodes -keyout /certs/k.pem -out /certs/c.pem -days 2 -subj /CN=localhost >/dev/null 2>&1
docker run --rm --user 0 -v "${certs}:/certs" --entrypoint chown "$image" -R 999:999 /certs
docker run --rm --user 0 -v "${certs}:/certs" --entrypoint chmod "$image" 600 /certs/k.pem

# --- helpers bound to the current node ($c) -------------------------------------
c=""
start_node() { # mode (admin|prepare) ; volumes are named after $c
  docker rm -f "$c" >/dev/null 2>&1 || true
  docker run -d --name "$c" --network "$net" --hostname "$c" \
    -v "${c}-cfg:/etc/openldap/slapd.d" -v "${c}-data:/var/lib/openldap/data" -v "${certs}:/certs:ro" \
    -e LDAP_ROOT_DN="$base" -e LDAP_ADMIN_PASSWORD="$pw" \
    -e LDAP_REPLICATION_ENABLED=true -e LDAP_SERVER_ID=1 -e LDAP_REPLICATION_PEERS="ldap://${c}:389" \
    -e LDAP_TLS_ENABLED=true -e LDAP_TLS_CERT_FILE=/certs/c.pem -e LDAP_TLS_KEY_FILE=/certs/k.pem \
    -e LDAP_REPLICATION_IDENTITY="$1" "$image" >/dev/null
  poll ready "$c" || { bad "${c}: never ready (mode $1)"; docker logs "$c" 2>&1 | tail -n 15 >&2; return 1; }
  put_pw || return 1
}
put_pw() {
  # -y uses the whole file as the password: no trailing newline
  printf '%s' "$pw" | docker exec -i "$c" sh -c 'umask 077; cat > /tmp/.pw-admin'
  printf '%s' "$mpw" | docker exec -i "$c" sh -c 'umask 077; cat > /tmp/.pw-machine'
}
restart_node() {
  docker restart "$c" >/dev/null
  poll ready "$c" || { bad "${c}: never ready after restart"; docker logs "$c" 2>&1 | tail -n 15 >&2; return 1; }
}
acl_list() { docker exec "$c" slapcat -n 0 -o ldif-wrap=no 2>/dev/null | sed -n "/^dn: ${maindb}\$/,/^\$/p" | grep '^olcAccess: ' || true; }
acl_idx() { acl_list | sed -n "s/^olcAccess: {\([0-9]*\)}.*dn.exact=\"$1\".*/\1/p" | tr '\n' ' ' | sed 's/ $//'; }
acl_norm() { acl_list | sed -e 's/^olcAccess: {[0-9]*}//'; }
lim_count() { docker exec "$c" slapcat -n 0 -o ldif-wrap=no 2>/dev/null | sed -n "/^dn: ${maindb}\$/,/^\$/p" | grep -c "^olcLimits: .*${iddn}" || true; }
cfg_env=(-e MACHINE_DN="$mdn" -e ALLOWED_DN="$bdn" -e MAIN_DB_DN="$maindb" -e CFG_URI="$ldapi" -e ROOT_DN="$base")
run_doc() { docker exec -i "${cfg_env[@]}" "$c" sh -c "$1"; }
# shellcheck disable=SC2317,SC2329 # invoked through rc_of
tlsx() { docker exec -i -e LDAPTLS_CACERT=/certs/c.pem -e LDAPTLS_REQCERT=never "$c" "$@"; }
# cnt: run an LDAP search that must SUCCEED (rc 0), then print the number of lines
# matching the pattern. A failed search is a failed check, never "nothing exposed".
cnt() { # pattern command...
  local pat="$1" out rc=0
  shift
  out="$("$@" 2>/dev/null)" || rc=$?
  if [ "$rc" -ne 0 ]; then echo "search-rc-${rc}"; return 0; fi
  printf '%s\n' "$out" | grep -c "$pat" || true
}
# hid: like cnt, for a search whose BASE the identity may not even see: slapd answers
# noSuchObject (32) for an unreadable base, which is "hidden" (0). Any other error stays a failure.
hid() {
  local r
  r="$(cnt "$@")"
  if [ "$r" = "search-rc-32" ]; then echo 0; else echo "$r"; fi
}
rc_of() { local rc=0; "$@" >/dev/null 2>&1 || rc=$?; echo "$rc"; }

seed() {
  docker exec -i "$c" ldapadd -x -H ldap://localhost -D "$admin" -w "$pw" >/dev/null <<EOF
dn: ou=system,${base}
objectClass: organizationalUnit
ou: system

dn: ${mdn}
objectClass: inetOrgPerson
uid: machine
cn: machine
sn: machine
userPassword: ${mpw}

dn: ${bdn}
objectClass: organizationalUnit
ou: people

dn: uid=alice,${bdn}
objectClass: inetOrgPerson
uid: alice
cn: alice
sn: alice
userPassword: ${hpw}

dn: ou=other,${base}
objectClass: organizationalUnit
ou: other

dn: uid=outsider,ou=other,${base}
objectClass: inetOrgPerson
uid: outsider
cn: outsider
sn: outsider
EOF
}
add_identity() {
  docker exec -i "$c" ldapadd -x -H ldap://localhost -D "$admin" -w "$pw" >/dev/null <<EOF
dn: ${iddn}
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: replicator
userPassword: ${idpw}
EOF
}

# The machine DN: reads inside B (no secrets), nothing outside B, no writes.
machine_proof() { # label
  local l="$1" m=(docker exec -i "$c")
  check "${l}: M binds" "0" "$(rc_of "${m[@]}" ldapwhoami -x -H ldap://127.0.0.1 -D "$mdn" -y /tmp/.pw-machine)"
  check "${l}: M reads alice inside B" "1" \
    "$(cnt '^uid: alice' "${m[@]}" ldapsearch -x -LLL -H ldap://127.0.0.1 -D "$mdn" -y /tmp/.pw-machine -b "$bdn" '(uid=alice)' uid)"
  check "${l}: M never sees userPassword (explicit request)" "0" \
    "$(cnt '^userPassword' "${m[@]}" ldapsearch -x -LLL -H ldap://127.0.0.1 -D "$mdn" -y /tmp/.pw-machine -b "$bdn" '(uid=alice)' userPassword)"
  check "${l}: the same request succeeds for an allowed attribute (cn)" "1" \
    "$(cnt '^cn: alice' "${m[@]}" ldapsearch -x -LLL -H ldap://127.0.0.1 -D "$mdn" -y /tmp/.pw-machine -b "$bdn" '(uid=alice)' cn)"
  check "${l}: M sees nothing outside B" "0" \
    "$(hid '^dn:' "${m[@]}" ldapsearch -x -LLL -H ldap://127.0.0.1 -D "$mdn" -y /tmp/.pw-machine -b "ou=other,${base}" -s sub dn)"
  check "${l}: control: admin sees ou=other and the identity entry" "3" \
    "$(cnt '^dn:' docker exec "$c" ldapsearch -x -LLL -H ldap://localhost -D "$admin" -w "$pw" -b "$base" -s sub '(|(ou=other)(uid=outsider)(cn=replicator))' dn)"
  check "${l}: M cannot read the identity entry" "0" \
    "$(hid '^dn:' "${m[@]}" ldapsearch -x -LLL -H ldap://127.0.0.1 -D "$mdn" -y /tmp/.pw-machine -b "$base" "(cn=replicator)" dn)"
  check "${l}: M write to another entry is refused (50)" "50" "$(rc_of "${m[@]}" ldapmodify -x -H ldap://127.0.0.1 -D "$mdn" -y /tmp/.pw-machine <<EOF
dn: uid=alice,${bdn}
changetype: modify
replace: description
description: x
EOF
)"
  check "${l}: M write to its own entry is refused (50)" "50" "$(rc_of "${m[@]}" ldapmodify -x -H ldap://127.0.0.1 -D "$mdn" -y /tmp/.pw-machine <<EOF
dn: ${mdn}
changetype: modify
replace: description
description: x
EOF
)"
  check "${l}: M read of cn=config is refused (32)" "32" \
    "$(rc_of "${m[@]}" ldapsearch -x -LLL -H ldap://127.0.0.1 -D "$mdn" -y /tmp/.pw-machine -b cn=config -s base)"
}

# The replication identity: reads hashes over TLS only, never writes. Absent
# machine rules or present, the same.
identity_proof() { # label
  local l="$1"
  check "${l}: identity (TLS) reads alice's userPassword hash" "1" \
    "$(cnt '^userPassword' docker exec -e LDAPTLS_CACERT=/certs/c.pem -e LDAPTLS_REQCERT=never "$c" ldapsearch -x -LLL -H ldaps://localhost -D "$iddn" -w "$idpw" -b "$base" '(uid=alice)' userPassword)"
  check "${l}: identity (plaintext, ssf 0) sees no entry" "0" \
    "$(hid '^dn:' docker exec "$c" ldapsearch -x -LLL -H ldap://localhost -D "$iddn" -w "$idpw" -b "$base" '(uid=alice)' uid)"
  check "${l}: the same request over TLS returns the entry (the plaintext zero is the ACL)" "1" \
    "$(cnt '^dn:' docker exec -e LDAPTLS_CACERT=/certs/c.pem -e LDAPTLS_REQCERT=never "$c" ldapsearch -x -LLL -H ldaps://localhost -D "$iddn" -w "$idpw" -b "$base" '(uid=alice)' uid)"
  check "${l}: identity (TLS) write is refused (50)" "50" "$(rc_of tlsx ldapmodify -x -H ldaps://localhost -D "$iddn" -w "$idpw" <<EOF
dn: uid=alice,${bdn}
changetype: modify
replace: description
description: x
EOF
)"
  check "${l}: identity (TLS) cannot read cn=config (32)" "32" \
    "$(rc_of tlsx ldapsearch -x -LLL -H ldaps://localhost -D "$iddn" -w "$idpw" -b cn=config -s base)"
  check "${l}: alice still changes her own description" "0" "$(rc_of docker exec -i "$c" ldapmodify -x -H ldap://localhost -D "uid=alice,${bdn}" -w "$hpw" <<EOF
dn: uid=alice,${bdn}
changetype: modify
replace: description
description: self
EOF
)"
}

# idx = acl_idx for the machine DN and the identity DN
layout() { # label expected-identity-idx expected-machine-idx
  check "$1: identity rule at olcAccess {$2}" "$2" "$(acl_idx "$iddn")"
  check "$1: machine rules at olcAccess {$3}" "$3" "$(acl_idx "$mdn")"
}

# Delete the identity rule ({0}, guarded) and its olcLimits: the independent
# rollback of the replication side (the image never removes a stored rule).
drop_identity() {
  local first
  first="$(acl_list | head -n 1)"
  case "$first" in *"dn.exact=\"${iddn}\""*) ;; *) bad "identity rollback guard: {0} is not the identity rule"; return 1 ;; esac
  local lim
  lim="$(docker exec "$c" slapcat -n 0 -o ldif-wrap=no 2>/dev/null | sed -n "/^dn: ${maindb}\$/,/^\$/p" | sed -n 's/^olcLimits: //p' | grep -F "dn.exact=\"${iddn}\"")"
  docker exec -i "$c" ldapmodify -x -H "$ldapi" -D cn=admin,cn=config -y /tmp/.pw-admin >/dev/null <<EOF
dn: ${maindb}
changetype: modify
delete: olcAccess
olcAccess: {0}
-
delete: olcLimits
olcLimits: ${lim}
EOF
}

run_order() { # A|B
  local order="$1" before_all
  c="ldapium-maclid-${order}-${suffix}"
  reg_containers+=("$c")
  reg_vols+=("${c}-cfg" "${c}-data")
  docker volume create "${c}-cfg" >/dev/null
  docker volume create "${c}-data" >/dev/null
  echo "=== order ${order} ==="
  start_node admin || return 1
  seed || return 1
  acl_norm >"${work}/${order}.original"
  before_all="$(cat "${work}/${order}.original")"
  check "${order}: admin-mode node has no identity rule" "" "$(acl_idx "$iddn")"

  if [ "$order" = A ]; then
    start_node prepare || return 1
    layout "A after prepare" "0" ""
    add_identity || return 1
    run_doc "$apply_shifted_cmd" <"$ldif" >/dev/null || bad "A: shifted apply failed"
  else
    run_doc "$apply_cmd" <"$ldif" >/dev/null || bad "B: plain apply failed"
    layout "B machine first" "" "0 1 2"
    start_node prepare || return 1
    add_identity || return 1
  fi
  layout "${order} combined" "0" "1 2 3"
  check "${order} combined: the image's own rules follow, unchanged and in order" "$before_all" "$(acl_norm | grep -vF "dn.exact=\"${mdn}\"" | grep -vF "dn.exact=\"${iddn}\"")"
  check "${order} combined: olcLimits for the identity stored once" "1" "$(lim_count)"
  machine_proof "${order} combined"
  identity_proof "${order} combined"

  # Restarts of prepare with the machine rules present.
  local snap
  snap="$(acl_norm)"
  restart_node || return 1
  check "${order} restart 1: olcAccess text and order unchanged" "$snap" "$(acl_norm)"
  layout "${order} restart 1" "0" "1 2 3"
  restart_node || return 1
  layout "${order} restart 2" "0" "1 2 3"
  start_node prepare || return 1 # recreated container, same volumes (what an orchestrator does)
  layout "${order} recreate with prepare" "0" "1 2 3"
  local log
  log="$(docker logs "$c" 2>&1)"
  if [[ "$log" == *"already installed — nothing to do"* ]]; then ok "${order} recreate: prepare logged a no-op"; else bad "${order} recreate: no no-op log"; fi
  machine_proof "${order} after restarts"
  identity_proof "${order} after restarts"

  # Independent rollback 1: the documented machine rollback leaves the identity rule.
  put_pw || return 1
  run_doc "$rollback_cmd" >/dev/null || bad "${order}: documented machine rollback failed"
  layout "${order} machine rolled back" "0" ""
  check "${order} machine rolled back: identity rule + admin-mode rules only (text)" "$(acl_norm | head -n 1)"$'\n'"${before_all}" "$(acl_norm)"
  restart_node || return 1
  layout "${order} machine rolled back, restarted" "0" ""
  identity_proof "${order} machine rolled back"
  check "${order}: a second machine rollback refuses and changes nothing" "1" "$(rc_of run_doc "$rollback_cmd")"
  check "${order}: ... and the olcAccess did not change" "$(acl_norm | head -n 1)"$'\n'"${before_all}" "$(acl_norm)"

  # Re-apply behind the identity rule, then roll the identity side back alone.
  run_doc "$apply_shifted_cmd" <"$ldif" >/dev/null || bad "${order}: re-apply failed"
  layout "${order} re-applied" "0" "1 2 3"
  drop_identity || return 1
  layout "${order} identity rolled back" "" "0 1 2"
  check "${order} identity rolled back: olcLimits gone" "0" "$(lim_count)"
  check "${order} identity rolled back: no other rule disturbed" "$before_all" "$(acl_norm | grep -vF "dn.exact=\"${mdn}\"")"
  machine_proof "${order} identity rolled back"
  # admin mode leaves the stored cn=config alone and still starts with the machine rules at {0}-{2}.
  start_node admin || return 1
  layout "${order} admin restart" "" "0 1 2"
  run_doc "$rollback_cmd" >/dev/null || bad "${order}: machine rollback at {0}-{2} failed"
  check "${order} both rolled back: olcAccess equals the original" "$before_all" "$(acl_norm)"
}

# No `|| true`: a step that fails inside an order must fail the run.
for o in A B; do
  if ! run_order "$o"; then bad "order ${o} aborted before its last check"; fi
done

if [ "$fail" -eq 0 ]; then echo "RESULT: all checks passed"; else echo "RESULT: FAILED" >&2; fi
exit "$fail"
