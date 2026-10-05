#!/usr/bin/env bash
# Live Keycloak LDAP-federation probe against a real ldapium image. It boots
# ldapium + Keycloak on a private docker network, configures federation with
# kcadm.sh, and answers concrete questions operators of a Keycloak <-> ldapium
# deployment hit (see docs/changes/keycloak-federation/CHANGE.md for the
# hypotheses and recorded results).
#
# Check groups (each is independent and starts its own ldapium):
#   basic         full sync, group mapper LOAD_GROUPS_BY_MEMBER_ATTRIBUTE, login
#   memberof      GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE group strategy
#   changed-sync  triggerChangedUsersSync via createTimestamp/modifyTimestamp
#   writable      edit mode WRITABLE + admin-API password reset as a non-root DN
#   scale         >olcSizeLimit users: paged sync without (control) / with LDAP_LIMITS_DNS
#   idle          server-side olcIdleTimeout vs Keycloak's pooled LDAP connection
#   tls           LDAPS with strict hostname check, throwaway CA, Keycloak truststore
#   placeholder   removing the last member of a groupOfNames (default LDAP_REFINT_NOTHING)
#   all           everything above (default)
#
# Usage: scripts/test/test-keycloak-federation-local.sh [image] [group...]
#   image defaults to ldapium:e2e. Requires docker (honours DOCKER_CONTEXT,
#   e.g. `export DOCKER_CONTEXT=colima`), curl, jq, openssl (tls group only).
#   KEYCLOAK_IMAGE overrides the pinned Keycloak image (keycloak-federation-e2e.yml's).
#   Exit status is nonzero when any check FAILs. XFAIL lines are documented
#   server-side findings kept visible on purpose; they do not fail the run.
#
# Everything created is named ldapium-kc-<pid>*; cleanup removes exactly
# those containers, the private network and the derived images on exit.
set -uo pipefail
# Never pipe into `grep -q` when the writer can be SIGPIPEd under pipefail:
# match against captured variables with here-strings instead.

LDAP_IMAGE="${1:-ldapium:e2e}"
shift || true
groups=("$@")
[ "${#groups[@]}" -gt 0 ] || groups=(all)

KC_IMAGE="${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:26.7.4}"
P="ldapium-kc-$$"
NET="$P"
BASE="dc=example,dc=org"
ADMIN_DN="cn=admin,${BASE}"
ADMIN_PW="kcFedAdminPw-1"
SVC_DN="cn=keycloak-svc,${BASE}"
SVC_PW="kcFedSvcPw-1"
WRITER_DN="cn=kc-writer,${BASE}"
WRITER_PW="kcFedWriterPw-1"
KC_ADMIN_PW="kcFedKeycloakAdminPw-1"
ALICE_PW="AlicePw-e2e-1"
BOB_PW="BobPw-e2e-1"

work="$(mktemp -d)"
containers=()
images=()
net_created=0
KC=""
KCURL=""
SHARED_KC=""
LDAP_ID=""
fails=0

ok() { printf 'PASS: %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; fails=$((fails + 1)); }
xfail() { printf 'XFAIL: %s\n' "$1"; }
info() { printf 'INFO: %s\n' "$1"; }
die() { printf 'ERROR: %s\n' "$1" >&2; exit 2; }
# check <label> <expected> <actual>
check() {
  if [ "$2" = "$3" ]; then ok "$1 (=$3)"; else bad "$1: expected [$2], got [$3]"; fi
}

# shellcheck disable=SC2317,SC2329 # invoked via the EXIT trap below
cleanup() {
  local c i
  for c in ${containers[@]+"${containers[@]}"}; do
    docker rm -f -v "$c" >/dev/null 2>&1 || true
  done
  [ "$net_created" = 1 ] && docker network rm "$NET" >/dev/null 2>&1
  for i in ${images[@]+"${images[@]}"}; do
    docker rmi -f "$i" >/dev/null 2>&1 || true
  done
  rm -rf "$work"
  return 0
}
trap cleanup EXIT
trap 'exit 130' INT TERM

docker network create "$NET" >/dev/null || die "cannot create docker network ${NET}"
net_created=1

# ---------------------------------------------------------------- ldapium ---

# ldap_start <name> [docker run args...]   (image: ${LDAP_RUN_IMAGE:-$LDAP_IMAGE})
ldap_start() {
  local n="$P-$1" i
  shift
  docker run -d --name "$n" --network "$NET" \
    -e LDAP_ROOT_DN="$BASE" -e LDAP_ADMIN_PASSWORD="$ADMIN_PW" \
    "$@" "${LDAP_RUN_IMAGE:-$LDAP_IMAGE}" >/dev/null || die "cannot start ${n}"
  containers+=("$n")
  for i in $(seq 1 60); do
    docker exec "$n" ldapwhoami -x -D "$ADMIN_DN" -w "$ADMIN_PW" >/dev/null 2>&1 && return 0
    sleep 2
  done
  docker logs --tail 30 "$n" >&2
  die "${n} never became ready"
}

lname() { printf '%s-%s' "$P" "$1"; }
# ldapium helpers; first arg is the short container name
ldap_admin_add() { docker exec -i "$(lname "$1")" ldapadd -x -D "$ADMIN_DN" -w "$ADMIN_PW" "${@:2}"; }
ldap_admin_mod() { docker exec -i "$(lname "$1")" ldapmodify -x -D "$ADMIN_DN" -w "$ADMIN_PW" "${@:2}"; }
ldap_cfg_mod() { docker exec -i "$(lname "$1")" ldapmodify -x -D "cn=admin,cn=config" -w "$ADMIN_PW"; }
# ldap_search <name> <bind-dn> <pw> <ldapsearch args...>
ldap_search() {
  local n="$1" d="$2" w="$3"
  shift 3
  docker exec "$(lname "$n")" ldapsearch -x -LLL -D "$d" -w "$w" "$@"
}
# stop_container <name>: free memory between groups
stop_container() {
  docker rm -f -v "$(lname "$1")" >/dev/null 2>&1 || true
}

# Same fixture the keycloak-federation-e2e workflow uses, plus a passwordless
# read-only service DN (organizationalRole+simpleSecurityObject, no uid/mail).
seed_basic() {
  ldap_admin_add "$1" >/dev/null <<EOF || die "seed_basic failed on $1"
dn: ou=people,${BASE}
objectClass: organizationalUnit
ou: people

dn: ou=groups,${BASE}
objectClass: organizationalUnit
ou: groups

dn: ${SVC_DN}
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: keycloak-svc
userPassword: ${SVC_PW}

dn: ${WRITER_DN}
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: kc-writer
userPassword: ${WRITER_PW}

dn: uid=alice,ou=people,${BASE}
objectClass: inetOrgPerson
uid: alice
cn: Alice Anderson
sn: Anderson
givenName: Alice
mail: alice@example.org
userPassword: ${ALICE_PW}

dn: uid=bob,ou=people,${BASE}
objectClass: inetOrgPerson
uid: bob
cn: Bob Brown
sn: Brown
givenName: Bob
mail: bob@example.org
userPassword: ${BOB_PW}

dn: cn=developers,ou=groups,${BASE}
objectClass: groupOfNames
cn: developers
member: uid=alice,ou=people,${BASE}
member: uid=bob,ou=people,${BASE}

dn: cn=marketing,ou=groups,${BASE}
objectClass: groupOfNames
cn: marketing
member: uid=alice,ou=people,${BASE}
EOF
}

# grant_writer_pw <name>: the least-privilege writer grant for password
# resets: write only on userPassword/shadowLastChange under ou=people, then fall
# through to the stock rules (no whole-base write).
grant_writer_pw() {
  ldap_cfg_mod "$1" >/dev/null <<EOF || die "grant_writer_pw failed on $1"
dn: olcDatabase={1}mdb,cn=config
changetype: modify
add: olcAccess
olcAccess: {0}to dn.subtree="ou=people,${BASE}" attrs=userPassword,shadowLastChange by dn.exact="${WRITER_DN}" write by * break
EOF
}

# grant_writer <name>: full write for ${WRITER_DN} under the base, then fall
# through (`by * break`) to the image's stock rules. Deliberately broad for
# the test; CHANGE.md recommends narrowing it.
grant_writer() {
  ldap_cfg_mod "$1" >/dev/null <<EOF || die "grant_writer failed on $1"
dn: olcDatabase={1}mdb,cn=config
changetype: modify
add: olcAccess
olcAccess: {0}to dn.subtree="${BASE}" by dn.exact="${WRITER_DN}" write by * break
EOF
}

# ---------------------------------------------------------------- keycloak ---

# kc_start <name> <image> [docker run args...]
kc_start() {
  local n="$P-$1" img="$2" p=8181
  shift 2
  while :; do
    if docker run -d --name "$n" --network "$NET" -p "127.0.0.1:${p}:8080" \
      -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD="$KC_ADMIN_PW" \
      "$@" "$img" start-dev >/dev/null 2>&1; then
      break
    fi
    docker rm -f "$n" >/dev/null 2>&1 || true # host port taken: try the next one
    p=$((p + 1))
    [ "$p" -lt 8300 ] || die "no free host port in 8181-8299"
  done
  containers+=("$n")
  KC="$n"
  KCURL="http://127.0.0.1:${p}"
  local i
  for i in $(seq 1 90); do
    curl -sf "${KCURL}/realms/master" >/dev/null 2>&1 && break
    [ "$i" -lt 90 ] || { docker logs --tail 40 "$n" >&2; die "${n} never became ready"; }
    sleep 2
  done
  kca config credentials --server http://localhost:8080 --realm master \
    --user admin --password "$KC_ADMIN_PW" >/dev/null || die "kcadm login failed on ${n}"
}

# kc_use <name>: select the Keycloak container the helpers below talk to
kc_use() {
  KC="$P-$1"
  KCURL="http://127.0.0.1:$(docker port "$KC" 8080/tcp | head -1 | sed 's/.*://')"
}

shared_kc() {
  if [ -z "$SHARED_KC" ]; then
    kc_start kc "$KC_IMAGE"
    SHARED_KC=kc
  fi
  kc_use "$SHARED_KC"
}

kca() { docker exec "$KC" /opt/keycloak/bin/kcadm.sh "$@"; }

# fed_create <realm> <ldap-url> <bind-dn> <bind-pw> <edit-mode> [extra -s args...]
# Sets LDAP_ID. Same wiring as keycloak-federation-e2e.yml.
fed_create() {
  local realm="$1" url="$2" bdn="$3" bpw="$4" mode="$5"
  shift 5
  kca create realms -s id="$realm" -s realm="$realm" -s enabled=true >/dev/null || die "create realm ${realm}"
  LDAP_ID=$(kca create components -r "$realm" -i \
    -s name=ldapium -s providerId=ldap \
    -s providerType=org.keycloak.storage.UserStorageProvider -s parentId="$realm" \
    -s 'config.enabled=["true"]' -s 'config.vendor=["other"]' \
    -s "config.connectionUrl=[\"${url}\"]" \
    -s "config.usersDn=[\"ou=people,${BASE}\"]" \
    -s 'config.authType=["simple"]' \
    -s "config.bindDn=[\"${bdn}\"]" -s "config.bindCredential=[\"${bpw}\"]" \
    -s "config.editMode=[\"${mode}\"]" \
    -s 'config.usernameLDAPAttribute=["uid"]' -s 'config.rdnLDAPAttribute=["uid"]' \
    -s 'config.uuidLDAPAttribute=["entryUUID"]' -s 'config.userObjectClasses=["inetOrgPerson"]' \
    -s 'config.searchScope=["2"]' -s 'config.pagination=["true"]' \
    -s 'config.importEnabled=["true"]' -s 'config.syncRegistrations=["false"]' \
    -s 'config.trustEmail=["true"]' "$@") || die "create LDAP provider in ${realm}"
}

# group_mapper <realm> <strategy> <mode: READ_ONLY|LDAP_ONLY>
group_mapper() {
  kca create components -r "$1" \
    -s name=groups -s providerId=group-ldap-mapper \
    -s providerType=org.keycloak.storage.ldap.mappers.LDAPStorageMapper -s parentId="$LDAP_ID" \
    -s "config.\"groups.dn\"=[\"ou=groups,${BASE}\"]" \
    -s 'config."group.name.ldap.attribute"=["cn"]' \
    -s 'config."group.object.classes"=["groupOfNames"]' \
    -s 'config."membership.ldap.attribute"=["member"]' \
    -s 'config."membership.attribute.type"=["DN"]' \
    -s 'config."membership.user.ldap.attribute"=["uid"]' \
    -s 'config."memberof.ldap.attribute"=["memberOf"]' \
    -s "config.\"mode\"=[\"$3\"]" \
    -s "config.\"user.roles.retrieve.strategy\"=[\"$2\"]" \
    -s 'config."drop.non.existing.groups.during.sync"=["false"]' >/dev/null || die "create group mapper in $1"
}

# client_create <realm>: public direct-grant client with a `groups` claim mapper
client_create() {
  local cid
  cid=$(kca create clients -r "$1" -i -s clientId=k8s-oidc-test -s publicClient=true \
    -s directAccessGrantsEnabled=true -s standardFlowEnabled=false -s enabled=true) || die "create client in $1"
  kca create "clients/${cid}/protocol-mappers/models" -r "$1" \
    -s name=groups -s protocol=openid-connect -s protocolMapper=oidc-group-membership-mapper \
    -s 'config."full.path"=false' -s 'config."id.token.claim"=true' \
    -s 'config."access.token.claim"=true' -s 'config."userinfo.token.claim"=true' \
    -s 'config."claim.name"=groups' >/dev/null || die "create groups mapper in $1"
}

# sync_full|sync_changed <realm>: prints Keycloak's sync result JSON (or error)
sync_full() { kca create "user-storage/${LDAP_ID}/sync?action=triggerFullSync" -r "$1" 2>&1; }
sync_changed() { kca create "user-storage/${LDAP_ID}/sync?action=triggerChangedUsersSync" -r "$1" 2>&1; }
user_count() { kca get users/count -r "$1" 2>/dev/null | tr -d '[:space:]'; }
usernames() { kca get users -r "$1" --fields username --format csv --noquotes 2>/dev/null | sort | paste -sd, -; }

# group_members <realm> <group> -> comma separated sorted usernames
group_members() {
  local gid
  gid=$(kca get groups -r "$1" -q "search=$2" --fields id --format csv --noquotes | head -1)
  [ -n "$gid" ] || { echo "<no such group>"; return; }
  kca get "groups/${gid}/members" -r "$1" --fields username --format csv --noquotes 2>/dev/null | sort | paste -sd, -
}

# token <realm> <user> <password>: prints the HTTP status; body in $work/token.json
token() {
  curl -s -o "$work/token.json" -w '%{http_code}' \
    -d client_id=k8s-oidc-test -d grant_type=password -d scope=openid \
    -d "username=$2" --data-urlencode "password=$3" \
    "${KCURL}/realms/$1/protocol/openid-connect/token"
}
# groups_claim <realm> <user> <password> -> sorted groups claim as JSON, from userinfo
groups_claim() {
  local st at
  st=$(token "$1" "$2" "$3")
  [ "$st" = 200 ] || { echo "<token HTTP ${st}>"; return; }
  at=$(jq -r .access_token "$work/token.json")
  curl -sf -H "Authorization: Bearer ${at}" "${KCURL}/realms/$1/protocol/openid-connect/userinfo" \
    | jq -c '(.groups // []) | sort' 2>/dev/null || echo "<userinfo failed>"
}

# ------------------------------------------------------------------ groups ---

group_basic() {
  local L=ldap-basic R=basic out
  info "== basic"
  ldap_start "$L"
  seed_basic "$L"
  shared_kc
  fed_create "$R" "ldap://$(lname "$L"):389" "$SVC_DN" "$SVC_PW" READ_ONLY
  group_mapper "$R" LOAD_GROUPS_BY_MEMBER_ATTRIBUTE READ_ONLY
  client_create "$R"
  out=$(sync_full "$R"); info "full sync: ${out//$'\n'/ }"
  check "basic: federated users" "alice,bob" "$(usernames "$R")"
  check "basic: developers members" "alice,bob" "$(group_members "$R" developers)"
  check "basic: marketing members" "alice" "$(group_members "$R" marketing)"
  check "basic: alice login" 200 "$(token "$R" alice "$ALICE_PW")"
  check "basic: wrong password rejected" 400 "$(token "$R" alice wrong-password)"
  check "basic: rejected login is invalid_grant without a token" true "$(jq -r '(.error == "invalid_grant") and (has("access_token") | not)' "$work/token.json")"
  check "basic: alice groups claim" '["developers","marketing"]' "$(groups_claim "$R" alice "$ALICE_PW")"
  stop_container "$L"
}

group_memberof() {
  local L=ldap-memberof R=memberof out mo mid
  info "== memberof (H4)"
  ldap_start "$L"
  seed_basic "$L"
  mo=$(ldap_search "$L" "$SVC_DN" "$SVC_PW" -b "uid=alice,ou=people,${BASE}" -s base memberOf | grep '^memberOf:' | sort | paste -sd'|' -)
  check "memberof: read-only service DN can read alice's memberOf" \
    "memberOf: cn=developers,ou=groups,${BASE}|memberOf: cn=marketing,ou=groups,${BASE}" "$mo"
  shared_kc
  fed_create "$R" "ldap://$(lname "$L"):389" "$SVC_DN" "$SVC_PW" READ_ONLY
  group_mapper "$R" LOAD_GROUPS_BY_MEMBER_ATTRIBUTE READ_ONLY
  client_create "$R"
  out=$(sync_full "$R"); info "full sync: ${out//$'\n'/ }"
  check "memberof: baseline (member strategy) alice claim" '["developers","marketing"]' "$(groups_claim "$R" alice "$ALICE_PW")"
  # Switch the existing mapper in place, the way an operator would.
  mid=$(kca get components -r "$R" -q "parent=${LDAP_ID}" -q type=org.keycloak.storage.ldap.mappers.LDAPStorageMapper \
    | jq -r '.[] | select(.name=="groups") | .id')
  kca update "components/${mid}" -r "$R" \
    -s 'config."user.roles.retrieve.strategy"=["GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE"]' \
    -s 'config."memberof.ldap.attribute"=["memberOf"]' >/dev/null || die "update group mapper strategy"
  check "memberof: mapper strategy now" GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE \
    "$(kca get "components/${mid}" -r "$R" | jq -r '.config["user.roles.retrieve.strategy"][0]')"
  check "memberof: alice groups claim" '["developers","marketing"]' "$(groups_claim "$R" alice "$ALICE_PW")"
  check "memberof: bob groups claim" '["developers"]' "$(groups_claim "$R" bob "$BOB_PW")"
  # memberOf is read live at login: an LDAP-side change needs no sync.
  ldap_admin_mod "$L" >/dev/null <<EOF
dn: cn=developers,ou=groups,${BASE}
changetype: modify
delete: member
member: uid=bob,ou=people,${BASE}
EOF
  check "memberof: memberof overlay dropped bob's memberOf (server side)" "" \
    "$(ldap_search "$L" "$SVC_DN" "$SVC_PW" -b "uid=bob,ou=people,${BASE}" -s base memberOf | grep '^memberOf:' | paste -sd'|' -)"
  mo=$(groups_claim "$R" bob "$BOB_PW")
  if [ "$mo" = '[]' ]; then
    ok "memberof: bob's claim follows the LDAP-side removal at the next login"
  else
    # Keycloak's own user cache serves the previous group set; not a directory issue.
    info "memberof: bob's claim is still ${mo} right after the LDAP-side removal (Keycloak user cache, not the directory)"
    kca create clear-user-cache -r "$R" >/dev/null 2>&1 || true
    check "memberof: bob's claim after clearing Keycloak's user cache" '[]' "$(groups_claim "$R" bob "$BOB_PW")"
  fi
  info "memberof: /groups/developers/members = [$(group_members "$R" developers)] (admin members listing after the LDAP-side removal)"
  stop_container "$L"
}

group_changed_sync() {
  local L=ldap-changed R=changed out
  info "== changed-sync (H5)"
  ldap_start "$L"
  seed_basic "$L"
  shared_kc
  fed_create "$R" "ldap://$(lname "$L"):389" "$SVC_DN" "$SVC_PW" READ_ONLY
  group_mapper "$R" LOAD_GROUPS_BY_MEMBER_ATTRIBUTE READ_ONLY
  out=$(sync_full "$R"); info "full sync: ${out//$'\n'/ }"
  check "changed-sync: initial users" "alice,bob" "$(usernames "$R")"
  # Keycloak compares generalized times at 1s granularity: separate the
  # baseline from the LDAP writes by a few seconds.
  sleep 4
  ldap_admin_add "$L" >/dev/null <<EOF
dn: uid=carol,ou=people,${BASE}
objectClass: inetOrgPerson
uid: carol
cn: Carol Clark
sn: Clark
givenName: Carol
mail: carol@example.org
EOF
  ldap_admin_mod "$L" >/dev/null <<EOF
dn: uid=alice,ou=people,${BASE}
changetype: modify
replace: sn
sn: Changed
EOF
  out=$(sync_changed "$R"); info "changed sync: ${out//$'\n'/ }"
  check "changed-sync: new LDAP user imported" "alice,bob,carol" "$(usernames "$R")"
  check "changed-sync: modified attribute updated" "Changed" \
    "$(kca get users -r "$R" -q username=alice --fields lastName --format csv --noquotes | head -1)"
  ldap_admin_mod "$L" >/dev/null <<EOF
dn: uid=bob,ou=people,${BASE}
changetype: delete
EOF
  sleep 2
  sync_changed "$R" >/dev/null
  info "changed-sync: after deleting bob in LDAP + changed sync, Keycloak users = $(usernames "$R") (changed sync does not see deletions; a full sync does)"
  out=$(sync_full "$R"); info "full sync after delete: ${out//$'\n'/ }"
  check "changed-sync: full sync drops deleted LDAP user" "alice,carol" "$(usernames "$R")"
  stop_container "$L"
}

# writable_reset <realm> <user> <new-pw>: password reset through the admin
# API. Prints "ok" or the trimmed Keycloak error.
writable_reset() {
  local out
  if out=$(kca set-password -r "$1" --username "$2" --new-password "$3" 2>&1); then
    echo ok
  else
    echo "${out//$'\n'/ }" | cut -c1-200
  fi
}

group_writable() {
  local L=ldap-writable R=writable res
  info "== writable (H3)"
  ldap_start "$L"
  seed_basic "$L"
  shared_kc
  # A: the read-only service DN of the workflow cannot reset passwords.
  fed_create "$R" "ldap://$(lname "$L"):389" "$SVC_DN" "$SVC_PW" WRITABLE
  sync_full "$R" >/dev/null
  res=$(writable_reset "$R" alice "AliceNew-Pw-2")
  if [ "$res" = ok ]; then bad "writable: read-only DN unexpectedly reset a password"; else ok "writable: read-only service DN cannot reset (${res})"; fi
  check "writable: alice's LDAP password unchanged" 0 \
    "$(docker exec "$(lname "$L")" ldapwhoami -x -D "uid=alice,ou=people,${BASE}" -w "$ALICE_PW" >/dev/null 2>&1; echo $?)"
  kca delete "components/${LDAP_ID}" -r "$R" >/dev/null 2>&1 || true
  kca delete "realms/${R}" >/dev/null 2>&1 || true

  # B: a dedicated writer DN with an ACL grant (the ACL alone is not enough).
  grant_writer_pw "$L"
  R=writable2
  fed_create "$R" "ldap://$(lname "$L"):389" "$WRITER_DN" "$WRITER_PW" WRITABLE
  sync_full "$R" >/dev/null
  # Mechanism, straight at the directory: the writer DN, no old password.
  res=$(docker exec "$(lname "$L")" ldappasswd -x -D "$WRITER_DN" -w "$WRITER_PW" -s "AliceNew-Pw-2" "uid=alice,ou=people,${BASE}" 2>&1)
  info "writable: ldappasswd as ${WRITER_DN} without old password -> ${res//$'\n'/ }"
  if [[ "$res" == *"old password"* ]]; then
    info "writable: default policy (pwdSafeModify TRUE) refuses a non-rootDN reset without the old password (H3)"
  elif [ -z "$res" ]; then
    ok "writable: non-rootDN password reset accepted with the default policy"
    docker exec "$(lname "$L")" ldappasswd -x -D "$WRITER_DN" -w "$WRITER_PW" -s "$ALICE_PW" "uid=alice,ou=people,${BASE}" >/dev/null 2>&1
  else
    bad "writable: unexpected ldappasswd failure: ${res}"
  fi
  # Keycloak, exop on (Use Password Modify Extended Operation) and off.
  kca update "components/${LDAP_ID}" -r "$R" -s 'config.usePasswordModifyExtendedOp=["true"]' >/dev/null 2>&1
  res=$(writable_reset "$R" alice "AliceNew-Pw-2")
  info "writable: Keycloak reset, usePasswordModifyExtendedOp=true, default policy -> ${res:0:110}"
  if [ "$res" = ok ]; then
    ok "writable: Keycloak exop reset accepted with the default policy"
  else
    xfail "writable: Keycloak's passwordless password set is refused by the default ppolicy (pwdSafeModify TRUE); intentional, H3 needs the per-user recipe below (CHANGE.md)"
  fi
  kca update "components/${LDAP_ID}" -r "$R" -s 'config.usePasswordModifyExtendedOp=["false"]' >/dev/null 2>&1
  res=$(writable_reset "$R" bob "BobNew-Pw-2")
  info "writable: Keycloak reset, usePasswordModifyExtendedOp=false, default policy -> ${res:0:110}"
  if [ "$res" = ok ]; then
    ok "writable: Keycloak plain-replace reset accepted with the default policy"
  else
    info "writable: Keycloak plain-replace reset also refused with the default policy (H3)"
  fi
  # Recipe (CHANGE.md "WRITABLE mode"; the ACL above is already the userPassword-scoped
# writer grant): a dedicated policy with pwdSafeModify FALSE, attached per user to
  # the accounts Keycloak manages; every other user keeps the strict default.
  ldap_admin_add "$L" >/dev/null <<EOF || die "kc-managed policy add failed"
dn: cn=kc-managed,ou=policies,${BASE}
objectClass: device
objectClass: pwdPolicy
cn: kc-managed
pwdAttribute: userPassword
pwdMinLength: 8
pwdSafeModify: FALSE
pwdAllowUserChange: TRUE
EOF
  ldap_admin_mod "$L" >/dev/null <<EOF
dn: uid=alice,ou=people,${BASE}
changetype: modify
replace: pwdPolicySubentry
pwdPolicySubentry: cn=kc-managed,ou=policies,${BASE}
EOF
  kca update "components/${LDAP_ID}" -r "$R" -s 'config.usePasswordModifyExtendedOp=["true"]' >/dev/null 2>&1
  res=$(writable_reset "$R" alice "AliceNew-Pw-3")
  if [ "$res" = ok ]; then
    ok "writable: exop reset works for a user on a pwdSafeModify=FALSE policy (recipe)"
    check "writable: alice binds to LDAP with the new password" 0 \
      "$(docker exec "$(lname "$L")" ldapwhoami -x -D "uid=alice,ou=people,${BASE}" -w "AliceNew-Pw-3" >/dev/null 2>&1; echo $?)"
    check "writable: alice Keycloak login with new password" 200 "$(token_public "$R" alice "AliceNew-Pw-3")"
    check "writable: old password rejected" 400 "$(token_public "$R" alice "$ALICE_PW")"
  else
    bad "writable: recipe failed, reset with per-user pwdSafeModify=FALSE policy: ${res}"
  fi
  res=$(writable_reset "$R" bob "BobNew-Pw-3")
  if [ "$res" = ok ]; then
    info "writable: bob (default policy) reset also worked (see plain-replace result above)"
  else
    ok "writable: users left on the default policy stay protected from blind resets"
  fi
  stop_container "$L"
}

# token_public <realm> ...: like token, on a realm without the groups client
token_public() {
  kca create clients -r "$1" -s clientId=k8s-oidc-test -s publicClient=true \
    -s directAccessGrantsEnabled=true -s standardFlowEnabled=false -s enabled=true >/dev/null 2>&1 || true
  token "$@"
}

# scale_load <name>: bulk-load 12000 users next to the seed (12002 total)
scale_load() {
  local L="$1"
  [ -s "$work/bulk.ldif" ] || awk -v base="$BASE" 'BEGIN {
    for (i = 1; i <= 12000; i++)
      printf "dn: uid=bulk%05d,ou=people,%s\nobjectClass: inetOrgPerson\nuid: bulk%05d\ncn: Bulk %05d\nsn: User%05d\ngivenName: Bulk\nmail: bulk%05d@example.org\n\n", i, base, i, i, i, i
  }' > "$work/bulk.ldif"
  info "loading 12000 users into ${L} ($(date +%T))"
  ldap_admin_add "$L" -c < "$work/bulk.ldif" >/dev/null 2>"$work/bulk.err" || info "ldapadd -c reported errors: $(head -c 300 "$work/bulk.err")"
  check "scale: ${L} holds seed+bulk users (admin view)" 12002 \
    "$(ldap_search "$L" "$ADMIN_DN" "$ADMIN_PW" -b "ou=people,${BASE}" "(objectClass=inetOrgPerson)" dn | grep -c '^dn:')"
}

# H1. Two runs on identical data: a control WITHOUT LDAP_LIMITS_DNS (keeps the
# problem visible: truncation at olcSizeLimit) and one WITH
# LDAP_LIMITS_DNS=<federation bind DN> (the documented fix; ';' separates DNs).
group_scale() {
  local L=ldap-scale-ctl R=scale-ctl out n_kc n_page st
  info "== scale (H1)"
  # --- control: default olcSizeLimit, no per-DN limit
  ldap_start "$L"
  seed_basic "$L"
  scale_load "$L"
  info "olcSizeLimit=$(ldap_search "$L" cn=admin,cn=config "$ADMIN_PW" -b 'olcDatabase={1}mdb,cn=config' -s base olcSizeLimit | grep -o '[0-9]*$')"
  n_page=$(ldap_search "$L" "$SVC_DN" "$SVC_PW" -b "ou=people,${BASE}" -E pr=1000/noprompt "(objectClass=inetOrgPerson)" dn 2>"$work/pr.err" | grep -c '^dn:')
  info "control (no LDAP_LIMITS_DNS): service DN paged (pr=1000): ${n_page} entries; $(tr '\n' ' ' < "$work/pr.err" | cut -c1-120)"
  check "scale: control: paged search stops at olcSizeLimit" 10000 "$n_page"
  shared_kc
  fed_create "$R" "ldap://$(lname "$L"):389" "$SVC_DN" "$SVC_PW" READ_ONLY
  st=$(date +%s)
  out=$(sync_full "$R"); info "control full sync ($(($(date +%s) - st))s): ${out//$'\n'/ }"
  n_kc=$(user_count "$R")
  info "Keycloak users after control sync: ${n_kc} of 12002"
  check "scale: control: Keycloak silently imports only the first 10000" 10000 "$n_kc"
  stop_container "$L"

  # --- fix: LDAP_LIMITS_DNS names the federation bind DN
  L=ldap-scale
  R=scale
  ldap_start "$L" -e "LDAP_LIMITS_DNS=${SVC_DN}"
  seed_basic "$L"
  scale_load "$L"
  info "olcLimits: $(ldap_search "$L" cn=admin,cn=config "$ADMIN_PW" -b 'olcDatabase={1}mdb,cn=config' -s base olcLimits | grep '^olcLimits:' | tr '\n' ' ')"
  n_page=$(ldap_search "$L" "$SVC_DN" "$SVC_PW" -b "ou=people,${BASE}" -E pr=1000/noprompt "(objectClass=inetOrgPerson)" dn 2>"$work/pr.err" | grep -c '^dn:')
  check "scale: LDAP_LIMITS_DNS: service DN paged search" 12002 "$n_page"
  n_page=$(ldap_search "$L" "$SVC_DN" "$SVC_PW" -b "ou=people,${BASE}" "(objectClass=inetOrgPerson)" dn 2>/dev/null | grep -c '^dn:')
  check "scale: LDAP_LIMITS_DNS: non-paged search by the same DN stays bounded" 10000 "$n_page"
  fed_create "$R" "ldap://$(lname "$L"):389" "$SVC_DN" "$SVC_PW" READ_ONLY
  st=$(date +%s)
  out=$(sync_full "$R"); info "full sync WITH LDAP_LIMITS_DNS ($(($(date +%s) - st))s): ${out//$'\n'/ }"
  check "scale: Keycloak users after sync WITH LDAP_LIMITS_DNS" 12002 "$(user_count "$R")"
  stop_container "$L"
}

# H2 (refuted risk): the image default is LDAP_IDLE_TIMEOUT=600 (olcIdleTimeout);
# the test uses 20 s only for speed. A server-side idle close must not break
# Keycloak: the JDK drops the dead pooled connection and reconnects.
group_idle() {
  local L=ldap-idle a=idle-default b=idle-pooltimeout c=idle-nopool
  local i realm t0 cnt acc0
  info "== idle (H2) — LDAP_IDLE_TIMEOUT=20 for test speed"
  ldap_start "$L" -e LDAP_IDLE_TIMEOUT=20 -e LDAP_LOG_LEVEL=stats
  seed_basic "$L"
  check "idle: olcIdleTimeout in effect" 20 \
    "$(ldap_search "$L" cn=admin,cn=config "$ADMIN_PW" -b cn=config -s base olcIdleTimeout | grep -o '[0-9]*$')"
  kc_start kc-idle-a "$KC_IMAGE"          # stock JVM: default pooling
  kc_start kc-idle-b "$KC_IMAGE" -e JAVA_OPTS_APPEND=-Dcom.sun.jndi.ldap.connect.pool.timeout=10000
  kc_use kc-idle-a
  fed_create "$a" "ldap://$(lname "$L"):389" "$SVC_DN" "$SVC_PW" READ_ONLY
  fed_create "$c" "ldap://$(lname "$L"):389" "$SVC_DN" "$SVC_PW" READ_ONLY -s 'config.connectionPooling=["false"]'
  kc_use kc-idle-b
  fed_create "$b" "ldap://$(lname "$L"):389" "$SVC_DN" "$SVC_PW" READ_ONLY
  # Warm: sync + an LDAP-backed lookup opens the service connection(s).
  for realm in "$a:kc-idle-a" "$c:kc-idle-a" "$b:kc-idle-b"; do
    kc_use "${realm#*:}"; sync_full "${realm%%:*}" >/dev/null
    kca get users -r "${realm%%:*}" -q username=alice -q exact=true --fields username >/dev/null 2>&1
  done
  sleep 35 # > 20s server idle timeout, > 10s pool timeout
  info "server-side idle closes so far: $(docker logs "$(lname "$L")" 2>&1 | grep -c 'closed (idletimeout)')"
  acc0=$(docker logs "$(lname "$L")" 2>&1 | grep -c ' ACCEPT from ')
  # Probe: a user that exists only in LDAP forces a service-account search.
  ldap_admin_add "$L" >/dev/null <<EOF
dn: uid=dave,ou=people,${BASE}
objectClass: inetOrgPerson
uid: dave
cn: Dave Doe
sn: Doe
givenName: Dave
mail: dave@example.org
userPassword: DavePw-e2e-1
EOF
  for realm in "$a:kc-idle-a" "$b:kc-idle-b" "$c:kc-idle-a"; do
    kc_use "${realm#*:}"
    t0=$(date +%s)
    cnt=$(kca get users -r "${realm%%:*}" -q username=dave -q exact=true --fields username --format csv --noquotes 2>&1 | grep -c '^dave$')
    if [ "$cnt" = 1 ]; then
      ok "idle: ${realm%%:*}: first LDAP lookup after >idle-timeout succeeded ($(($(date +%s) - t0))s)"
    else
      xfail "idle: ${realm%%:*}: first LDAP lookup after idle failed (H2 confirmed for this variant)"
      i=$(kca get users -r "${realm%%:*}" -q username=dave -q exact=true --fields username --format csv --noquotes 2>&1 | grep -c '^dave$')
      info "idle: ${realm%%:*}: retry immediately -> found=${i}"
    fi
    info "idle: ${realm%%:*}: new LDAP connections accepted since the idle wait: $(($(docker logs "$(lname "$L")" 2>&1 | grep -c ' ACCEPT from ') - acc0))"
  done
  stop_container "$L"
}

group_tls() {
  local L=ldap-tls R=tls out ca="$work/tls" name
  info "== tls (H6)"
  command -v openssl >/dev/null || die "openssl required for the tls group"
  name="$(lname "$L")"
  mkdir -p "$ca"
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$ca/ca.key" -out "$ca/ca.crt" \
    -subj "/CN=ldapium-kc-test-ca" -days 2 >/dev/null 2>&1 || die "openssl CA failed"
  openssl req -newkey rsa:2048 -nodes -keyout "$ca/server.key" -out "$ca/server.csr" \
    -subj "/CN=${name}" >/dev/null 2>&1 || die "openssl csr failed"
  printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$name" > "$ca/ext.cnf"
  openssl x509 -req -in "$ca/server.csr" -CA "$ca/ca.crt" -CAkey "$ca/ca.key" -CAcreateserial \
    -out "$ca/server.crt" -days 2 -extfile "$ca/ext.cnf" >/dev/null 2>&1 || die "openssl sign failed"
  # Derived images instead of bind mounts (AGENTS.md: macOS/Colima UID mapping).
  cat > "$ca/Dockerfile.ldap" <<DOCKERFILE
FROM ${LDAP_IMAGE}
USER root
COPY server.crt server.key ca.crt /etc/openldap/tls/
RUN chown -R ldap:ldap /etc/openldap/tls && chmod 600 /etc/openldap/tls/server.key
USER ldap
DOCKERFILE
  cat > "$ca/Dockerfile.kc" <<DOCKERFILE
FROM ${KC_IMAGE}
COPY --chown=1000:0 ca.crt /opt/keycloak/conf/truststores/ca.crt
DOCKERFILE
  docker build -q -t "${P}-ldap-tls:img" -f "$ca/Dockerfile.ldap" "$ca" >/dev/null || die "ldap tls image build failed"
  images+=("${P}-ldap-tls:img")
  docker build -q -t "${P}-kc-tls:img" -f "$ca/Dockerfile.kc" "$ca" >/dev/null || die "keycloak tls image build failed"
  images+=("${P}-kc-tls:img")

  LDAP_RUN_IMAGE="${P}-ldap-tls:img" ldap_start "$L" --network-alias "${P}-wrongname" \
    -e LDAP_TLS_ENABLED=true -e LDAP_TLS_CERT_FILE=/etc/openldap/tls/server.crt \
    -e LDAP_TLS_KEY_FILE=/etc/openldap/tls/server.key -e LDAP_TLS_CA_FILE=/etc/openldap/tls/ca.crt
  seed_basic "$L"
  check "tls: ldapwhoami over ldaps with the CA and matching name" 0 \
    "$(docker exec -e LDAPTLS_CACERT=/etc/openldap/tls/ca.crt "$name" ldapwhoami -x -H "ldaps://${name}:636" -D "$SVC_DN" -w "$SVC_PW" >/dev/null 2>&1; echo $?)"

  # Keycloak WITHOUT the CA: must refuse.
  shared_kc
  fed_create tls-noca "ldaps://${name}:636" "$SVC_DN" "$SVC_PW" READ_ONLY
  out=$(sync_full tls-noca); out=${out//$'\n'/ }; info "sync without truststore: ${out:0:200}"
  check "tls: Keycloak without the CA imports nothing" 0 "$(user_count tls-noca)"

  # Keycloak WITH the CA in its truststore.
  kc_start kc-tls "${P}-kc-tls:img" -e KC_TRUSTSTORE_PATHS=/opt/keycloak/conf/truststores/ca.crt
  fed_create "$R" "ldaps://${name}:636" "$SVC_DN" "$SVC_PW" READ_ONLY
  group_mapper "$R" LOAD_GROUPS_BY_MEMBER_ATTRIBUTE READ_ONLY
  client_create "$R"
  out=$(sync_full "$R"); info "sync with truststore: ${out//$'\n'/ }"
  check "tls: federated users over ldaps" "alice,bob" "$(usernames "$R")"
  check "tls: alice login over ldaps" 200 "$(token "$R" alice "$ALICE_PW")"
  check "tls: groups claim over ldaps" '["developers","marketing"]' "$(groups_claim "$R" alice "$ALICE_PW")"

  # Strict hostname check: same container, same CA-signed cert, name not in SAN.
  fed_create tls-wrongname "ldaps://${P}-wrongname:636" "$SVC_DN" "$SVC_PW" READ_ONLY
  out=$(sync_full tls-wrongname); out=${out//$'\n'/ }; info "sync via non-SAN name: ${out:0:200}"
  check "tls: hostname not in SAN is refused (strict hostname check)" 0 "$(user_count tls-wrongname)"
  stop_container "$L"
}

group_placeholder() {
  local L=ldap-placeholder R=placeholder out gid uid n
  info "== placeholder (H7)"
  ldap_start "$L"
  seed_basic "$L"
  grant_writer "$L"
  ldap_admin_add "$L" >/dev/null <<EOF
dn: uid=carol,ou=people,${BASE}
objectClass: inetOrgPerson
uid: carol
cn: Carol Clark
sn: Clark
mail: carol@example.org

dn: uid=dave,ou=people,${BASE}
objectClass: inetOrgPerson
uid: dave
cn: Dave Doe
sn: Doe
mail: dave@example.org

dn: uid=erin,ou=people,${BASE}
objectClass: inetOrgPerson
uid: erin
cn: Erin Ell
sn: Ell
mail: erin@example.org

dn: cn=solo1,ou=groups,${BASE}
objectClass: groupOfNames
cn: solo1
member: uid=carol,ou=people,${BASE}

dn: cn=solo2,ou=groups,${BASE}
objectClass: groupOfNames
cn: solo2
member: uid=dave,ou=people,${BASE}

dn: cn=solo3,ou=groups,${BASE}
objectClass: groupOfNames
cn: solo3
member: uid=erin,ou=people,${BASE}
EOF
  # 1. directory-level: deleting the only member value directly.
  out=$(ldap_admin_mod "$L" 2>&1 <<EOF
dn: cn=solo1,ou=groups,${BASE}
changetype: modify
delete: member
member: uid=carol,ou=people,${BASE}
EOF
  )
  info "delete last member value directly: ${out//$'\n'/ }"
  if [[ "$out" == *"Object class violation"* ]]; then
    ok "placeholder: schema refuses an empty groupOfNames (member is MUST)"
  else
    bad "placeholder: emptying a groupOfNames was not refused: ${out}"
  fi
  # 2. refint: deleting the user who is the sole member of solo2.
  out=$(ldap_admin_mod "$L" 2>&1 <<EOF
dn: uid=dave,ou=people,${BASE}
changetype: delete
EOF
  )
  info "delete sole-member user dave: ${out//$'\n'/ }"
  n=$(ldap_search "$L" "$ADMIN_DN" "$ADMIN_PW" -b "cn=solo2,ou=groups,${BASE}" -s base member | grep '^member:' | tr '\n' ' ')
  info "solo2 members after dave deleted: [${n}]"
  # Default LDAP_REFINT_NOTHING = cn=empty-membership-placeholder,<LDAP_ROOT_DN>
  # (olcRefintNothing): refint substitutes it instead of leaving a dangling DN.
  check "placeholder: refint substituted the default placeholder for the deleted sole member" \
    "member: cn=empty-membership-placeholder,${BASE} " "$n"
  check "placeholder: olcRefintNothing in effect" "olcRefintNothing: cn=empty-membership-placeholder,${BASE}" \
    "$(ldap_search "$L" cn=admin,cn=config "$ADMIN_PW" -b 'olcOverlay={1}refint,olcDatabase={1}mdb,cn=config' -s base olcRefintNothing | grep '^olcRefintNothing:')"
  # 3. through Keycloak (LDAP_ONLY group mapper writes membership back).
  shared_kc
  fed_create "$R" "ldap://$(lname "$L"):389" "$WRITER_DN" "$WRITER_PW" WRITABLE
  group_mapper "$R" LOAD_GROUPS_BY_MEMBER_ATTRIBUTE LDAP_ONLY
  sync_full "$R" >/dev/null
  uid=$(kca get users -r "$R" -q username=erin --fields id --format csv --noquotes | head -1)
  gid=$(kca get groups -r "$R" -q search=solo3 --fields id --format csv --noquotes | head -1)
  if [ -z "$uid" ] || [ -z "$gid" ]; then
    bad "placeholder: Keycloak did not import erin/solo3 (uid=[${uid}] gid=[${gid}])"
  else
    out=$(kca delete "users/${uid}/groups/${gid}" -r "$R" 2>&1); out=${out//$'\n'/ }
    n=$(ldap_search "$L" "$ADMIN_DN" "$ADMIN_PW" -b "cn=solo3,ou=groups,${BASE}" -s base member | grep '^member:' | tr '\n' ' ')
    info "Keycloak leave-group of last member -> [${out:-ok}]; solo3 members now: [${n}]"
    if [ -z "$n" ]; then
      bad "placeholder: Keycloak emptied solo3 (member is MUST) — directory inconsistent"
    elif [ -n "$out" ]; then
      ok "placeholder: Keycloak's removal of the last member was rejected and the group stayed intact [${n}]"
    else
      ok "placeholder: Keycloak removed the last member and the group is still consistent [${n}]"
    fi
    # Coexistence: Keycloak's own placeholder value (whatever DN it picked) stays
    # a valid member next to the server default, and the group takes a real member again.
    info "placeholder: Keycloak's own placeholder convention -> [${n}]; server default -> [cn=empty-membership-placeholder,${BASE}]"
    kca update "users/${uid}/groups/${gid}" -r "$R" -n >/dev/null 2>&1
    n=$(ldap_search "$L" "$ADMIN_DN" "$ADMIN_PW" -b "cn=solo3,ou=groups,${BASE}" -s base member | grep '^member:' | sed 's/^member: //' | sort | paste -sd'|' -)
    info "placeholder: solo3 members after erin rejoined: [${n}]"
    if [[ "$n" == *"uid=erin,ou=people,${BASE}"* ]]; then
      ok "placeholder: a real member can join the group holding the placeholder"
    else
      bad "placeholder: erin could not rejoin solo3 [${n}]"
    fi
    ldap_admin_mod "$L" >/dev/null <<EOF
dn: cn=solo3,ou=groups,${BASE}
changetype: modify
add: member
member: cn=empty-membership-placeholder,${BASE}
EOF
    n=$(ldap_search "$L" "$ADMIN_DN" "$ADMIN_PW" -b "cn=solo3,ou=groups,${BASE}" -s base member | grep -c '^member:')
    if [ "$n" -ge 2 ]; then
      ok "placeholder: server default and Keycloak placeholders coexist as member values (${n} member values)"
    else
      bad "placeholder: unexpected member count ${n} in solo3"
    fi
    check "placeholder: Keycloak still lists erin (placeholders are not users)" "erin" "$(group_members "$R" solo3)"
  fi
  stop_container "$L"
}

# -------------------------------------------------------------------- main ---

run() {
  case "$1" in
    basic) group_basic ;;
    memberof) group_memberof ;;
    changed-sync) group_changed_sync ;;
    writable) group_writable ;;
    scale) group_scale ;;
    idle) group_idle ;;
    tls) group_tls ;;
    placeholder) group_placeholder ;;
    all) for g in basic memberof changed-sync writable placeholder tls scale idle; do run "$g"; done ;;
    *) die "unknown group '$1' (basic|memberof|changed-sync|writable|scale|idle|tls|placeholder|all)" ;;
  esac
}

start_ts=$(date +%s)
for g in "${groups[@]}"; do run "$g"; done
printf '%s: %d failure(s), %ds\n' "$([ "$fails" -eq 0 ] && echo DONE || echo FAILED)" "$fails" "$(($(date +%s) - start_ts))"
[ "$fails" -eq 0 ]
