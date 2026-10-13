#!/usr/bin/env bash
# Live smoke: the machine WRITE ACL fragments (#285, T-020, docs/machine-write-account.md)
# on ONE slapd with the defined order, next to the machine READ fragment and with the
# replication identity rule (LDAP_REPLICATION_IDENTITY=prepare) at {0}:
#
#   olcAccess {0}      replication identity rule
#   olcAccess {1}-{3}  the three machine read rules (M)
#   olcAccess {4}-{12} the nine W_data rules   (write-data.ldif)
#   olcAccess {13}-{18} the six W_lock rules    (write-lock.ldif)
#   olcAccess {19}..   the image's own rules, in their original order
#
# It shows with ldapmodify as W_data / W_lock that the allowed attribute set works, that
# representative refusals come back as insufficient access (50), that M stays read-only,
# that the fragments' documented limits really are limits (objectClass value add passes),
# and that the documented rollback restores the original olcAccess byte for byte.
# The guide's shell commands (4.2 install, 7 rollback) are CUT OUT of the guide and run
# as written, and the guide's LDIF blocks are compared as whole blocks with the fixtures,
# so neither can drift from what is tested. All passwords here are throwaway test values.
# This is a SMALL smoke, not the T-021 proof: it is NOT wired into CI, opens no
# operation, and does not exercise the application guard (client caps, protected DNs,
# target types), which is the only protection for those.
#
# Usage: scripts/test/test-machine-write-acl-smoke.sh [image]
#   image defaults to ldapium:e2e. Requires Docker. MWACL_FIX_DIR overrides the fixture
#   directory (used to show that a mutated fragment FAILS the smoke). MWACL_TIMEOUT (seconds, default 120)
#   bounds every wait. Resources are named ldapium-mwacl-* and only those are removed on exit.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
image="${1:-ldapium:e2e}"
timeout_s="${MWACL_TIMEOUT:-120}"
suffix="$$"
pw="mwaclAdminPw-Zq7Lm2Xv9Kd4Hs8Wt1Bn6Rc3Yf5Ug0Pe"
idpw="mwaclIdentityPw-Jh6Gf3Dd9Sa2Qw8Er5Ty1Ui4Op7Lk0"
mpw="mwaclMachinePw-Nn4Bb7Vv1Cc9Xx3Zz6Aa2Ss5Dd8Ff0"
wdpw="mwaclWriteDataPw-Qa3Ws8Ed2Rf6Tg9Yh1Uj5Ik7Ol4"
wlpw="mwaclWriteLockPw-Pl8Ok3Ij6Uh9Yg2Tf5Rd1Es4Wa7"
# throwaway test values: never reuse
hpw="mwaclHumanPw-Aa1-Bb2-Cc3"
newpw="mwaclNewPw-Zz9-Yy8-Xx7"
base="dc=example,dc=org"
admin="cn=admin,${base}"
iddn="cn=replicator,${base}"
sysdn="ou=system,${base}"
mdn="uid=machine,${sysdn}"
wddn="uid=machine-write-data,${sysdn}"
wldn="uid=machine-write-lock,${sysdn}"
wrdn="ou=managed,${base}"
people="ou=people,${wrdn}"
groups="ou=groups,${wrdn}"
maindb="olcDatabase={1}mdb,cn=config"
ldapi='ldapi://%2Fvar%2Flib%2Fopenldap%2Frun%2Fldapi'
net="ldapium-mwacl-net-${suffix}"
certs="ldapium-mwacl-certs-${suffix}"
c="ldapium-mwacl-${suffix}"
envfile="$(mktemp)" # 0600: keeps the admin password out of argv
fix="${MWACL_FIX_DIR:-${repo}/scripts/test/fixtures/machine-acl}"
guide="${repo}/docs/machine-write-account.md"

# The names the guide's commands use (exported only so the eval'd guide commands and
# linters both see them used).
EXEC="docker exec -i ${c}"
MACHINE_DN="$mdn"
WDATA_DN="$wddn"
WLOCK_DN="$wldn"
SYSTEM_DN="$sysdn"
REPL_DN="$iddn"
MAIN_DB_DN="$maindb"
CFG_URI="$ldapi"
ROOT_DN="$base"
WRITE_DN="$wrdn"
export EXEC MACHINE_DN WDATA_DN WLOCK_DN SYSTEM_DN REPL_DN MAIN_DB_DN CFG_URI ROOT_DN WRITE_DN

fail=0
ok() { printf 'PASS: %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }
check() { # label expected actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: expected '$2', got '$3'"; fi
}

# shellcheck disable=SC2317,SC2329 # invoked via the trap below
cleanup() {
  trap - EXIT
  if ! docker rm -fv "$c" >/dev/null 2>&1; then echo "cleanup: container ${c} not removed" >&2; fi
  if ! docker volume rm -f "${c}-cfg" "${c}-data" "$certs" >/dev/null 2>&1; then echo "cleanup: volumes not removed" >&2; fi
  if ! docker network rm "$net" >/dev/null 2>&1; then echo "cleanup: network ${net} not removed" >&2; fi
  rm -f "$envfile"
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
ready() { docker exec "$c" ldapwhoami -x -H ldap://localhost >/dev/null 2>&1; }

# The fixtures and the guide must carry the same LDIF: the guide's Nth ```ldif block is
# the fixture's non-comment text, compared as a WHOLE block.
guide_ldif() { awk -v k="$1" '/^```ldif$/ { n++; on=(n == k); next } /^```$/ { on=0; next } on' "$guide"; }
n=0
for f in write-data.ldif write-lock.ldif; do
  n=$((n + 1))
  check "${f}: the guide embeds the fixture as one identical block" "$(awk '!/^#/' "${fix}/${f}")" "$(guide_ldif "$n")"
done
# The guide's shell blocks, run as written (cwd = the fixture directory, as the guide says).
guide_sh() { awk -v re="$1" '/^```sh$/ { on=1; buf=""; next } /^```$/ { if (on && buf ~ re) { printf "%s", buf; exit } on=0; next } on { buf = buf $0 "\n" }' "$guide"; }
install_cmd="$(guide_sh 'PRESENT=')"
rollback_cmd="$(guide_sh 'FIRST=')"
if [ -z "$install_cmd" ] || [ -z "$rollback_cmd" ]; then echo "cannot cut the install/rollback commands out of ${guide}" >&2; exit 1; fi
ok "install (4.2) and rollback (7) commands extracted from the guide"
# The reserved replication DN the index arithmetic and the REPL_DN deny rule rely on.
check "image/entrypoint.sh still reserves cn=replicator,<root> (ri_dn)" "1" \
  "$(awk 'index($0, "ri_dn=\"cn=replicator,${LDAP_ROOT_DN}\"") { n++ } END { print n + 0 }' "${repo}/image/entrypoint.sh")"

printf 'LDAP_ADMIN_PASSWORD=%s\n' "$pw" >"$envfile"
docker network create "$net" >/dev/null
docker volume create "$certs" >/dev/null
docker volume create "${c}-cfg" >/dev/null
docker volume create "${c}-data" >/dev/null
docker run --rm --user 0 -v "${certs}:/certs" --entrypoint openssl "$image" \
  req -x509 -newkey rsa:2048 -nodes -keyout /certs/k.pem -out /certs/c.pem -days 2 -subj /CN=localhost >/dev/null 2>&1
docker run --rm --user 0 -v "${certs}:/certs" --entrypoint chown "$image" -R 999:999 /certs
docker run --rm --user 0 -v "${certs}:/certs" --entrypoint chmod "$image" 600 /certs/k.pem

start_node() { # mode (admin|prepare)
  if ! docker rm -f "$c" >/dev/null 2>&1; then :; fi
  docker run -d --name "$c" --network "$net" --hostname "$c" \
    -v "${c}-cfg:/etc/openldap/slapd.d" -v "${c}-data:/var/lib/openldap/data" -v "${certs}:/certs:ro" \
    -e LDAP_ROOT_DN="$base" --env-file "$envfile" \
    -e LDAP_REPLICATION_ENABLED=true -e LDAP_SERVER_ID=1 -e LDAP_REPLICATION_PEERS="ldap://${c}:389" \
    -e LDAP_TLS_ENABLED=true -e LDAP_TLS_CERT_FILE=/certs/c.pem -e LDAP_TLS_KEY_FILE=/certs/k.pem \
    -e LDAP_REPLICATION_IDENTITY="$1" "$image" >/dev/null
  poll ready || { bad "node never ready (mode $1)"; docker logs "$c" 2>&1 | tail -n 15 >&2; return 1; }
  # -y uses the whole file as the password: no trailing newline
  local p
  for p in admin:"$pw" machine:"$mpw" wdata:"$wdpw" wlock:"$wlpw" human:"$hpw" id:"$idpw"; do
    printf '%s' "${p#*:}" | docker exec -i "$c" sh -c "umask 077; cat > /tmp/.pw-${p%%:*}"
  done
}

rc_of() { local rc=0; "$@" >/dev/null 2>&1 || rc=$?; echo "$rc"; }
# mod_as <dn> <pwfile>: LDIF on stdin, prints the ldapmodify exit code.
mod_as() { local rc=0; docker exec -i "$c" ldapmodify -x -H ldap://127.0.0.1 -D "$1" -y "$2" >/dev/null 2>&1 || rc=$?; echo "$rc"; }
# cnt <pattern> <command...>: a search that must SUCCEED (rc 0); prints the matching line count.
cnt() {
  local pat="$1" out rc=0
  shift
  out="$("$@" 2>/dev/null)" || rc=$?
  if [ "$rc" -ne 0 ]; then echo "search-rc-${rc}"; return 0; fi
  printf '%s\n' "$out" | awk -v p="$pat" '$0 ~ p { n++ } END { print n + 0 }'
}
# shellcheck disable=SC2317,SC2329 # invoked through cnt / rc_of
search_as() { # dn pwfile base filter attrs...
  local d="$1" f="$2" b="$3" fl="$4"
  shift 4
  docker exec -i "$c" ldapsearch -x -LLL -H ldap://127.0.0.1 -D "$d" -y "$f" -b "$b" "$fl" "$@"
}

acl_list() { docker exec "$c" slapcat -n 0 -o ldif-wrap=no 2>/dev/null | sed -n "/^dn: ${maindb}\$/,/^\$/p" | awk '/^olcAccess: /'; }
acl_idx() { acl_list | sed -n "s/^olcAccess: {\([0-9]*\)}.*dn.exact=\"$1\".*/\1/p" | tr '\n' ' ' | sed 's/ $//'; }
acl_norm() { acl_list | sed -e 's/^olcAccess: {[0-9]*}//'; }

# --- the commands of docs/machine-write-account.md -----------------------------------------
shift_ldif() { # base file
  awk -v b="$1" '/^olcAccess: \{[0-9]+\}/ { s=$0; sub(/^olcAccess: \{/,"",s); i=s+0; sub(/^[0-9]+\}/,"",s); print "olcAccess: {" (i+b) "}" s; next } { print }' "$2"
}
sub_tokens() { # WRITE_DN as $1
  sed -e "s|@MACHINE_DN@|${mdn}|g" -e "s|@ALLOWED_DN@|${base}|g" -e "s|@WDATA_DN@|${wddn}|g" -e "s|@WLOCK_DN@|${wldn}|g" \
    -e "s|@WRITE_DN@|$1|g" -e "s|@SYSTEM_DN@|${sysdn}|g" -e "s|@REPL_DN@|${iddn}|g" -e "s|@MAIN_DB_DN@|${maindb}|g"
}
cfg_apply() { docker exec -i "$c" ldapmodify -x -H "$ldapi" -D cn=admin,cn=config -y /tmp/.pw-admin >/dev/null; }
# The guide's commands, as written. Output (stdout+stderr) is returned for the checks.
# shellcheck disable=SC2030,SC2031 # the guide command runs in a subshell on purpose
apply_w() { # fixture who write_dn
  (cd "$fix" && export FRAG="$1" WHO="$2" WRITE_DN="$3" && eval "$install_cmd") 2>&1
}
# shellcheck disable=SC2030,SC2031
rollback_w() { # who k
  (cd "$fix" && export WHO="$1" K="$2" && eval "$rollback_cmd") 2>&1
}

seed() {
  docker exec -i "$c" ldapadd -x -H ldap://localhost -D "$admin" -y /tmp/.pw-admin >/dev/null <<EOF
dn: ${sysdn}
objectClass: organizationalUnit
ou: system

dn: ${mdn}
objectClass: inetOrgPerson
uid: machine
cn: machine
sn: machine
userPassword: ${mpw}

dn: ${wddn}
objectClass: inetOrgPerson
uid: machine-write-data
cn: machine-write-data
sn: machine-write-data
userPassword: ${wdpw}

dn: ${wldn}
objectClass: inetOrgPerson
uid: machine-write-lock
cn: machine-write-lock
sn: machine-write-lock
userPassword: ${wlpw}

dn: ${wrdn}
objectClass: organizationalUnit
ou: managed

dn: ${people}
objectClass: organizationalUnit
ou: people

dn: ${groups}
objectClass: organizationalUnit
ou: groups

dn: uid=alice,${people}
objectClass: inetOrgPerson
uid: alice
cn: alice
sn: alice
userPassword: ${hpw}

dn: cn=g1,${groups}
objectClass: groupOfNames
cn: g1
member: uid=alice,${people}

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

# The identity entry may only be added after prepare installed its rule (the entrypoint refuses otherwise).
add_identity() {
  docker exec -i "$c" ldapadd -x -H ldap://localhost -D "$admin" -y /tmp/.pw-admin >/dev/null <<EOF
dn: ${iddn}
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: replicator
userPassword: ${idpw}
EOF
}

echo "=== start: replication identity prepare, machine read fragment, write fragments ==="
start_node admin
seed
original="$(acl_norm)"
start_node prepare
add_identity
check "prepare put the replication identity rule at {0}" "0" "$(acl_idx "$iddn")"
with_identity="$(acl_norm)"

# M read fragment behind the identity rule (machine-ldap-account.md 5.1: shift by one).
shift_ldif 1 "${fix}/main-database.ldif" | sub_tokens "$base" | cfg_apply
check "M read rules at {1} {2} {3}" "1 2 3" "$(acl_idx "$mdn")"
with_machine="$(acl_norm)"

out="$(apply_w write-data.ldif "$wddn" "$wrdn")"
check "guide 4.2 computed BASE=4 (replication + M) for W_data" "4" "$(printf '%s\n' "$out" | sed -n 's/^BASE=//p')"
check "W_data rules at {4}..{12}" "4 5 6 7 8 9 10 11 12" "$(acl_idx "$wddn")"
acl_w1="$(acl_norm)"
out="$(apply_w write-data.ldif "$wddn" "$wrdn")"
case "$out" in *"refusing: "*) ok "a second W_data apply is refused by the guide's own check" ;; *) bad "a second W_data apply was not refused: $out" ;; esac
check "... and the olcAccess did not change (no duplicate rules)" "$acl_w1" "$(acl_norm)"
out="$(apply_w write-lock.ldif "$wldn" "$wrdn")"
check "guide 4.2 computed BASE=13 (also counting W_data) for W_lock" "13" "$(printf '%s\n' "$out" | sed -n 's/^BASE=//p')"
check "W_lock rules at {13}..{18}" "13 14 15 16 17 18" "$(acl_idx "$wldn")"
check "replication rule still at {0} (plus the REPL_DN deny rules {5} {14}), M rules still at {1} {2} {3}" "0 5 14|1 2 3" "$(acl_idx "$iddn")|$(acl_idx "$mdn")"
check "the image's own rules follow, unchanged and in order" "$original" "$(acl_norm | awk -v a="$wddn" -v b="$wldn" -v m="$mdn" -v r="$iddn" 'index($0, "dn.exact=\"" a "\"") == 0 && index($0, "dn.exact=\"" b "\"") == 0 && index($0, "dn.exact=\"" m "\"") == 0 && index($0, "dn.exact=\"" r "\"") == 0')"
acl_installed="$(acl_norm)"
docker restart "$c" >/dev/null
poll ready || bad "node never ready after restart"
check "restart (prepare) keeps the whole olcAccess unchanged" "$acl_installed" "$(acl_norm)"
check "restart keeps the identity rule at {0} (and the two deny rules)" "0 5 14" "$(acl_idx "$iddn")"

echo "=== W_data ==="
wd() { mod_as "$wddn" /tmp/.pw-wdata; }
check "W_data binds" "0" "$(rc_of docker exec -i "$c" ldapwhoami -x -H ldap://127.0.0.1 -D "$wddn" -y /tmp/.pw-wdata)"
check "W_data add user (fixed objectClass set + uid/cn/sn/mail) inside the subtree" "0" "$(wd <<EOF
dn: uid=bob,${people}
changetype: add
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: bob
cn: bob
sn: bob
mail: bob@example.org
givenName: Bob
departmentNumber: 7
o: Org
ou: Unit
EOF
)"
check "W_data patch mail (Replace)" "0" "$(wd <<EOF
dn: uid=bob,${people}
changetype: modify
replace: mail
mail: bob2@example.org
EOF
)"
check "W_data add group member (member)" "0" "$(wd <<EOF
dn: cn=g1,${groups}
changetype: modify
add: member
member: uid=bob,${people}
EOF
)"
check "W_data remove group member" "0" "$(wd <<EOF
dn: cn=g1,${groups}
changetype: modify
delete: member
member: uid=bob,${people}
EOF
)"
check "W_data set group description (v2b D379-5)" "0" "$(wd <<EOF
dn: cn=g1,${groups}
changetype: modify
replace: description
description: machine-set
EOF
)"
check "W_data clear group description" "0" "$(wd <<EOF
dn: cn=g1,${groups}
changetype: modify
delete: description
EOF
)"
check "W_data cannot set a USER description (#394: the rule's filter is groupOfNames) (50)" "50" "$(wd <<EOF
dn: uid=bob,${people}
changetype: modify
replace: description
description: machine-set
EOF
)"
check "admin sees the written mail" "1" "$(cnt '^mail: bob2@example.org' docker exec -i "$c" ldapsearch -x -LLL -H ldap://localhost -D "$admin" -y /tmp/.pw-admin -b "uid=bob,${people}" mail)"

echo "=== W_data refusals ==="
check "userPassword (delete old + add new, the form that reaches the ACL) refused (50)" "50" "$(wd <<EOF
dn: uid=alice,${people}
changetype: modify
delete: userPassword
userPassword: ${hpw}
-
add: userPassword
userPassword: ${newpw}
EOF
)"
check "objectClass replace refused (50)" "50" "$(wd <<EOF
dn: uid=bob,${people}
changetype: modify
replace: objectClass
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
EOF
)"
check "memberOf modify is refused by the schema, not the ACL (19)" "19" "$(wd <<EOF
dn: uid=bob,${people}
changetype: modify
replace: memberOf
memberOf: cn=g1,${groups}
EOF
)"
check "attribute outside the closed list (telephoneNumber) refused (50)" "50" "$(wd <<EOF
dn: uid=bob,${people}
changetype: modify
replace: telephoneNumber
telephoneNumber: 1
EOF
)"
check "group attribute outside the closed list (owner) refused (50)" "50" "$(wd <<EOF
dn: cn=g1,${groups}
changetype: modify
add: owner
owner: uid=alice,${people}
EOF
)"
check "pwdAccountLockedTime (W_lock's attribute) refused (50)" "50" "$(wd <<EOF
dn: uid=bob,${people}
changetype: modify
replace: pwdAccountLockedTime
pwdAccountLockedTime: 20260101000000Z
EOF
)"
check "entry outside the write subtree refused (50)" "50" "$(wd <<EOF
dn: uid=outsider,ou=other,${base}
changetype: modify
replace: mail
mail: x@example.org
EOF
)"
check "add outside the write subtree refused (50)" "50" "$(wd <<EOF
dn: uid=evil,ou=other,${base}
changetype: add
objectClass: inetOrgPerson
uid: evil
cn: evil
sn: evil
EOF
)"
check "protected DN M refused (50)" "50" "$(wd <<EOF
dn: ${mdn}
changetype: modify
replace: sn
sn: x
EOF
)"
check "protected DN W_data itself refused (50)" "50" "$(wd <<EOF
dn: ${wddn}
changetype: modify
replace: sn
sn: x
EOF
)"
check "protected DN W_lock refused (50)" "50" "$(wd <<EOF
dn: ${wldn}
changetype: modify
replace: sn
sn: x
EOF
)"
check "admin entry refused (50)" "50" "$(wd <<EOF
dn: ${admin}
changetype: modify
replace: description
description: x
EOF
)"
check "cn=config refused (50)" "50" "$(wd <<EOF
dn: ${maindb}
changetype: modify
replace: olcSizeLimit
olcSizeLimit: 5
EOF
)"
check "delete of M refused (50)" "50" "$(wd <<EOF
dn: ${mdn}
changetype: delete
EOF
)"
check "W_data does not read userPassword / memberOf of a user" "0" \
  "$(cnt '^(userPassword|memberOf):' search_as "$wddn" /tmp/.pw-wdata "$people" '(uid=alice)' userPassword memberOf)"
# A REAL locked entry (a never-locked user would make the read checks vacuous): the admin locks dave.
admin_mod() { local rc=0; docker exec -i "$c" ldapmodify -x -H ldap://localhost -D "$admin" -y /tmp/.pw-admin >/dev/null 2>&1 || rc=$?; echo "$rc"; }
check "admin creates dave and locks him (pwdAccountLockedTime)" "0" "$(admin_mod <<EOF
dn: uid=dave,${people}
changetype: add
objectClass: inetOrgPerson
uid: dave
cn: dave
sn: dave
userPassword: ${hpw}

dn: uid=dave,${people}
changetype: modify
add: pwdAccountLockedTime
pwdAccountLockedTime: 20260101000000Z
EOF
)"
check "control: admin reads dave's pwdAccountLockedTime" "1" \
  "$(cnt '^pwdAccountLockedTime:' docker exec -i "$c" ldapsearch -x -LLL -H ldap://localhost -D "$admin" -y /tmp/.pw-admin -b "uid=dave,${people}" pwdAccountLockedTime)"
check "W_data does NOT read dave's pwdAccountLockedTime" "0" \
  "$(cnt '^pwdAccountLockedTime:' search_as "$wddn" /tmp/.pw-wdata "$people" '(uid=dave)' pwdAccountLockedTime)"
check "W_lock reads dave's pwdAccountLockedTime (it owns that attribute)" "1" \
  "$(cnt '^pwdAccountLockedTime:' search_as "$wldn" /tmp/.pw-wlock "$people" '(uid=dave)' pwdAccountLockedTime)"
check "W_lock does NOT read userPassword" "0" \
  "$(cnt '^userPassword:' search_as "$wldn" /tmp/.pw-wlock "$people" '(uid=dave)' userPassword)"
check "control: admin does read alice's userPassword and memberOf" "2" \
  "$(cnt '^(userPassword|memberOf):' docker exec -i "$c" ldapsearch -x -LLL -H ldap://localhost -D "$admin" -y /tmp/.pw-admin -b "$people" '(uid=alice)' userPassword memberOf)"
check "W_data reads nothing outside the write subtree (noSuchObject 32)" "32" \
  "$(rc_of search_as "$wddn" /tmp/.pw-wdata "ou=other,${base}" '(objectClass=*)' dn)"

echo "=== documented limit: objectClass VALUE ADD passes the ACL (app guard only) ==="
check "W_data modify add objectClass value on an existing entry is NOT refused by the ACL (0)" "0" "$(wd <<EOF
dn: uid=bob,${people}
changetype: modify
add: objectClass
objectClass: extensibleObject
EOF
)"

echo "=== W_lock ==="
wl() { mod_as "$wldn" /tmp/.pw-wlock; }
check "W_lock sets pwdAccountLockedTime (add)" "0" "$(wl <<EOF
dn: uid=bob,${people}
changetype: modify
add: pwdAccountLockedTime
pwdAccountLockedTime: 20260101000000Z
EOF
)"
check "admin sees the lock" "1" "$(cnt '^pwdAccountLockedTime:' docker exec -i "$c" ldapsearch -x -LLL -H ldap://localhost -D "$admin" -y /tmp/.pw-admin -b "uid=bob,${people}" pwdAccountLockedTime)"
# #394: add-only. slapd checks delete access for Delete AND Replace, so W_lock cannot unlock.
check "W_lock cannot clear pwdAccountLockedTime (delete) (50)" "50" "$(wl <<EOF
dn: uid=bob,${people}
changetype: modify
delete: pwdAccountLockedTime
EOF
)"
check "W_lock cannot clear pwdAccountLockedTime (replace with nothing) (50)" "50" "$(wl <<EOF
dn: uid=bob,${people}
changetype: modify
replace: pwdAccountLockedTime
EOF
)"
check "W_lock cannot overwrite pwdAccountLockedTime (replace) (50)" "50" "$(wl <<EOF
dn: uid=bob,${people}
changetype: modify
replace: pwdAccountLockedTime
pwdAccountLockedTime: 000001010000Z
EOF
)"
check "... and the lock is still there" "1" "$(cnt '^pwdAccountLockedTime: 20260101000000Z' docker exec -i "$c" ldapsearch -x -LLL -H ldap://localhost -D "$admin" -y /tmp/.pw-admin -b "uid=bob,${people}" pwdAccountLockedTime)"
check "admin clears the lock" "0" "$(admin_mod <<EOF
dn: uid=bob,${people}
changetype: modify
delete: pwdAccountLockedTime
EOF
)"
check "W_lock cannot write mail (50)" "50" "$(wl <<EOF
dn: uid=bob,${people}
changetype: modify
replace: mail
mail: z@example.org
EOF
)"
check "W_lock cannot delete an entry (50)" "50" "$(wl <<EOF
dn: uid=bob,${people}
changetype: delete
EOF
)"
check "W_lock cannot write userPassword (50)" "50" "$(wl <<EOF
dn: uid=alice,${people}
changetype: modify
delete: userPassword
userPassword: ${hpw}
-
add: userPassword
userPassword: ${newpw}
EOF
)"
check "W_lock cannot touch a protected DN (50)" "50" "$(wl <<EOF
dn: ${mdn}
changetype: modify
replace: pwdAccountLockedTime
pwdAccountLockedTime: 20260101000000Z
EOF
)"

echo "=== documented limit: ModifyDN (rename AND move across containers) passes the ACL ==="
check "W_data creates carol" "0" "$(wd <<EOF
dn: uid=carol,${people}
changetype: add
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: carol
cn: carol
sn: carol
EOF
)"
check "W_data renames and MOVES carol into another container (0): the app must never expose rename/move" "0" "$(wd <<EOF
dn: uid=carol,${people}
changetype: modrdn
newrdn: uid=carol2
deleteoldrdn: 1
newsuperior: ${groups}
EOF
)"
check "W_data deletes the moved entry" "0" "$(wd <<EOF
dn: uid=carol2,${groups}
changetype: delete
EOF
)"
check "admin deletes dave" "0" "$(admin_mod <<EOF
dn: uid=dave,${people}
changetype: delete
EOF
)"

echo "=== W_data deletes the user ==="
check "W_data deletes the leaf user" "0" "$(wd <<EOF
dn: uid=bob,${people}
changetype: delete
EOF
)"

echo "=== M stays read-only; other identities unchanged ==="
mm() { mod_as "$mdn" /tmp/.pw-machine; }
check "M reads alice inside the base" "1" "$(cnt '^uid: alice' search_as "$mdn" /tmp/.pw-machine "$people" '(uid=alice)' uid)"
check "M write inside the write subtree refused (50)" "50" "$(mm <<EOF
dn: uid=alice,${people}
changetype: modify
replace: mail
mail: m@example.org
EOF
)"
check "M write to its own entry refused (50)" "50" "$(mm <<EOF
dn: ${mdn}
changetype: modify
replace: description
description: x
EOF
)"
check "M add refused (50)" "50" "$(mm <<EOF
dn: uid=mbob,${people}
changetype: add
objectClass: inetOrgPerson
uid: mbob
cn: mbob
sn: mbob
EOF
)"
check "alice (human) still changes her own description" "0" "$(mod_as "uid=alice,${people}" /tmp/.pw-human <<EOF
dn: uid=alice,${people}
changetype: modify
replace: description
description: self
EOF
)"
check "replication identity (TLS) still reads alice's userPassword hash" "1" \
  "$(cnt '^userPassword' docker exec -i -e LDAPTLS_CACERT=/certs/c.pem -e LDAPTLS_REQCERT=never "$c" ldapsearch -x -LLL -H ldaps://localhost -D "$iddn" -y /tmp/.pw-id -b "$base" '(uid=alice)' userPassword)"

echo "=== rollback (guide 7): W_lock then W_data; M and identity rules untouched ==="
out="$(rollback_w "uid=nobody,${sysdn}" 6)"
case "$out" in *"refusing: "*) ok "rollback of a not-installed fragment refuses" ;; *) bad "rollback of a not-installed fragment did not refuse: $out" ;; esac
rollback_w "$wldn" 6 >/dev/null
check "W_lock rolled back: W_data rules still contiguous" "4 5 6 7 8 9 10 11 12" "$(acl_idx "$wddn")"
rollback_w "$wddn" 9 >/dev/null
check "W_data rolled back: olcAccess equals the state before the write fragments (byte for byte)" "$with_machine" "$(acl_norm)"
check "W_data no longer writes (50)" "50" "$(wd <<EOF
dn: uid=alice,${people}
changetype: modify
replace: mail
mail: after@example.org
EOF
)"

echo "=== write subtree widened to the root: the SYSTEM_DN backstop still protects the accounts ==="
apply_w write-data.ldif "$wddn" "$base" >/dev/null
check "W_data (root subtree) still writes inside the former subtree" "0" "$(wd <<EOF
dn: uid=alice,${people}
changetype: modify
replace: mail
mail: wide@example.org
EOF
)"
check "W_data (root subtree) writes where it used to be refused (ou=other)" "0" "$(wd <<EOF
dn: uid=outsider,ou=other,${base}
changetype: modify
replace: mail
mail: wide2@example.org
EOF
)"
check "backstop: M entry still refused (50)" "50" "$(wd <<EOF
dn: ${mdn}
changetype: modify
replace: sn
sn: x
EOF
)"
check "backstop: the replication identity entry is refused (50), not shielded by SYSTEM_DN" "50" "$(wd <<EOF
dn: ${iddn}
changetype: modify
replace: description
description: x
EOF
)"
check "backstop: deleting the replication identity entry is refused (50)" "50" "$(wd <<EOF
dn: ${iddn}
changetype: delete
EOF
)"
check "backstop: W_lock entry still refused (50)" "50" "$(wd <<EOF
dn: ${wldn}
changetype: modify
replace: sn
sn: x
EOF
)"
rollback_w "$wddn" 9 >/dev/null
check "rolled back again: original image rules + identity + M only" "$with_machine" "$(acl_norm)"
check "identity-only state equals what prepare produced" "$with_identity" "$(acl_norm | awk -v m="$mdn" 'index($0, "dn.exact=\"" m "\"") == 0')"

if [ "$fail" -eq 0 ]; then echo "RESULT: all checks passed"; else echo "RESULT: FAILED" >&2; fi
exit "$fail"
