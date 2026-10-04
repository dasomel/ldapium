#!/usr/bin/env bash
# Developer helper: a throwaway Keycloak (start-dev) federated to a local
# ldapium container, wired like .github/workflows/keycloak-federation-e2e.yml.
#
#   scripts/dev/keycloak-local.sh up      start Keycloak, create the bind DN, configure federation, sync
#   scripts/dev/keycloak-local.sh down    remove ONLY the Keycloak container (network, bind DN and LDAP data stay)
#   scripts/dev/keycloak-local.sh status  show container, realm and LDAP reachability
#
# `up` is idempotent: it reuses a running container, an existing bind DN and
# an existing realm. What it changes on the directory: it creates
# cn=keycloak-svc,<root> (organizationalRole, read-only through the image's
# stock ACL: it can read everything except userPassword) and, only if
# missing, ou=people / ou=groups. It also attaches the ldapium container to
# the `ldapium-local` docker network so Keycloak can reach it by name.
#
# Environment overrides (all optional):
#   LDAP_CONTAINER       ldapium container name        (default ldapium-ldap-1)
#   LDAP_ROOT_DN         base DN                       (default: the container's, else dc=example,dc=org)
#   LDAP_ADMIN_PASSWORD  admin password for the seed   (default: read from the container's env)
#   KC_PORT              host port for Keycloak        (default 8180)
#   KEYCLOAK_IMAGE       Keycloak image                (default: the version the workflow pins)
#
# LOCAL TEST VALUES ONLY: Keycloak admin/admin-local-only and the bind DN
# password below are public, on purpose. Never point this at a shared or
# production directory. Honours DOCKER_CONTEXT (e.g. `export DOCKER_CONTEXT=colima`).
set -euo pipefail

KC_CONTAINER="ldapium-keycloak-local"
NET="ldapium-local"
LDAP_CONTAINER="${LDAP_CONTAINER:-ldapium-ldap-1}"
KC_PORT="${KC_PORT:-8180}"
KC_IMAGE="${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:26.7.4}"
KC_ADMIN_USER="admin"
KC_ADMIN_PW="admin-local-only"
REALM="ldapium-local"
CLIENT_ID="ldapium-local"
SVC_PW="keycloak-local-only-pw-1"

usage() { echo "usage: $0 up|down|status" >&2; exit 2; }
die() { echo "ERROR: $*" >&2; exit 1; }
kca() { docker exec "$KC_CONTAINER" /opt/keycloak/bin/kcadm.sh "$@"; }
running() { [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null || true)" = true ]; }

ldap_env() { docker exec "$LDAP_CONTAINER" printenv "$1" 2>/dev/null || true; }

resolve_ldap() {
  running "$LDAP_CONTAINER" || die "ldapium container '${LDAP_CONTAINER}' is not running (set LDAP_CONTAINER=...)"
  ROOT_DN="${LDAP_ROOT_DN:-$(ldap_env LDAP_ROOT_DN)}"
  ROOT_DN="${ROOT_DN:-dc=example,dc=org}"
  ADMIN_DN="$(ldap_env LDAP_ADMIN_DN)"
  ADMIN_DN="${ADMIN_DN:-cn=admin,${ROOT_DN}}"
  ADMIN_PW="${LDAP_ADMIN_PASSWORD:-$(ldap_env LDAP_ADMIN_PASSWORD)}"
  [ -n "$ADMIN_PW" ] || die "cannot read LDAP_ADMIN_PASSWORD from ${LDAP_CONTAINER}; export LDAP_ADMIN_PASSWORD"
  SVC_DN="cn=keycloak-svc,${ROOT_DN}"
  FEDERATION_BASE="${KC_LDAP_BASE_DN:-$ROOT_DN}"
  if [ -z "${KC_LDAP_BASE_DN:-}" ] && ldap_exists "ou=ldapium-testdata,${ROOT_DN}"; then
    FEDERATION_BASE="ou=ldapium-testdata,${ROOT_DN}"
  fi
}

# Captured, not piped into `grep -q`: grep exiting early SIGPIPEs the writer
# and pipefail would turn a real match into "not found".
ldap_exists() {
  local out
  out=$(docker exec "$LDAP_CONTAINER" ldapsearch -x -LLL -D "$ADMIN_DN" -w "$ADMIN_PW" -b "$1" -s base dn 2>/dev/null || true)
  [[ "$out" == dn:* ]]
}

ensure_network() {
  docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null
  local attached
  attached=$(docker inspect -f '{{range $k, $_ := .NetworkSettings.Networks}}{{$k}} {{end}}' "$LDAP_CONTAINER")
  if [[ " ${attached}" != *" ${NET} "* ]]; then
    docker network connect "$NET" "$LDAP_CONTAINER"
    echo "attached ${LDAP_CONTAINER} to network ${NET}"
  fi
}

ensure_directory_entries() {
  local ou
  for ou in people groups; do
    if ! ldap_exists "ou=${ou},${ROOT_DN}"; then
      docker exec -i "$LDAP_CONTAINER" ldapadd -x -D "$ADMIN_DN" -w "$ADMIN_PW" >/dev/null <<EOF
dn: ou=${ou},${ROOT_DN}
objectClass: organizationalUnit
ou: ${ou}
EOF
      echo "created ou=${ou},${ROOT_DN}"
    fi
  done
  if ! ldap_exists "$SVC_DN"; then
    docker exec -i "$LDAP_CONTAINER" ldapadd -x -D "$ADMIN_DN" -w "$ADMIN_PW" >/dev/null <<EOF
dn: ${SVC_DN}
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: keycloak-svc
description: Read-only bind identity for the local Keycloak LDAP federation (dev helper)
userPassword: ${SVC_PW}
EOF
    echo "created ${SVC_DN}"
  fi
  # Prove the least-privilege claim instead of assuming it.
  docker exec "$LDAP_CONTAINER" ldapwhoami -x -D "$SVC_DN" -w "$SVC_PW" >/dev/null 2>&1 \
    || die "bind as ${SVC_DN} failed: an entry with that name exists with a different password"
}

start_keycloak() {
  if running "$KC_CONTAINER"; then
    echo "${KC_CONTAINER} already running"
  else
    docker rm -f -v "$KC_CONTAINER" >/dev/null 2>&1 || true
    docker run -d --name "$KC_CONTAINER" --network "$NET" -p "127.0.0.1:${KC_PORT}:8080" \
      -e KC_BOOTSTRAP_ADMIN_USERNAME="$KC_ADMIN_USER" -e KC_BOOTSTRAP_ADMIN_PASSWORD="$KC_ADMIN_PW" \
      "$KC_IMAGE" start-dev >/dev/null
  fi
  local i
  for i in $(seq 1 90); do
    curl -sf "http://127.0.0.1:${KC_PORT}/realms/master" >/dev/null 2>&1 && break
    [ "$i" -lt 90 ] || { docker logs --tail 30 "$KC_CONTAINER" >&2; die "Keycloak never became ready"; }
    sleep 2
  done
  kca config credentials --server http://localhost:8080 --realm master \
    --user "$KC_ADMIN_USER" --password "$KC_ADMIN_PW" >/dev/null
}

configure_federation() {
  if kca get "realms/${REALM}" >/dev/null 2>&1; then
    local existing_ldap existing_groups
    existing_ldap=$(kca get components -r "$REALM" -q type=org.keycloak.storage.UserStorageProvider --fields id --format csv --noquotes | head -1)
    [ -n "$existing_ldap" ] || die "realm ${REALM} has no LDAP provider"
    existing_groups=$(kca get components -r "$REALM" -q parent="$existing_ldap" --fields id,providerId | jq -r '.[] | select(.providerId == "group-ldap-mapper") | .id')
    [ -n "$existing_groups" ] || die "realm ${REALM} has no LDAP group mapper"
    kca update "components/${existing_ldap}" -r "$REALM" \
      -s "config.connectionUrl=[\"ldap://${LDAP_CONTAINER}:389\"]" \
      -s "config.usersDn=[\"ou=people,${FEDERATION_BASE}\"]" >/dev/null
    kca update "components/${existing_groups}" -r "$REALM" \
      -s "config.\"groups.dn\"=[\"ou=groups,${FEDERATION_BASE}\"]" >/dev/null
    kca create clear-user-cache -r "$REALM" >/dev/null
    kca create "user-storage/${existing_ldap}/sync?action=triggerFullSync" -r "$REALM"
    echo "updated LDAP search bases under ${FEDERATION_BASE} and synchronized users"
    return
  fi
  kca create realms -s id="$REALM" -s realm="$REALM" -s enabled=true >/dev/null 2>&1
  local ldap_id cid
  ldap_id=$(kca create components -r "$REALM" -i \
    -s name=ldapium -s providerId=ldap \
    -s providerType=org.keycloak.storage.UserStorageProvider -s parentId="$REALM" \
    -s 'config.enabled=["true"]' -s 'config.vendor=["other"]' \
    -s "config.connectionUrl=[\"ldap://${LDAP_CONTAINER}:389\"]" \
    -s "config.usersDn=[\"ou=people,${FEDERATION_BASE}\"]" \
    -s 'config.authType=["simple"]' \
    -s "config.bindDn=[\"${SVC_DN}\"]" -s "config.bindCredential=[\"${SVC_PW}\"]" \
    -s 'config.editMode=["READ_ONLY"]' \
    -s 'config.usernameLDAPAttribute=["uid"]' -s 'config.rdnLDAPAttribute=["uid"]' \
    -s 'config.uuidLDAPAttribute=["entryUUID"]' -s 'config.userObjectClasses=["inetOrgPerson"]' \
    -s 'config.searchScope=["2"]' -s 'config.pagination=["true"]' \
    -s 'config.importEnabled=["true"]' -s 'config.syncRegistrations=["false"]' \
    -s 'config.trustEmail=["true"]')
  kca create components -r "$REALM" \
    -s name=groups -s providerId=group-ldap-mapper \
    -s providerType=org.keycloak.storage.ldap.mappers.LDAPStorageMapper -s parentId="$ldap_id" \
    -s "config.\"groups.dn\"=[\"ou=groups,${FEDERATION_BASE}\"]" \
    -s 'config."group.name.ldap.attribute"=["cn"]' \
    -s 'config."group.object.classes"=["groupOfNames"]' \
    -s 'config."membership.ldap.attribute"=["member"]' \
    -s 'config."membership.attribute.type"=["DN"]' \
    -s 'config."membership.user.ldap.attribute"=["uid"]' \
    -s 'config."mode"=["READ_ONLY"]' \
    -s 'config."user.roles.retrieve.strategy"=["LOAD_GROUPS_BY_MEMBER_ATTRIBUTE"]' \
    -s 'config."drop.non.existing.groups.during.sync"=["false"]' >/dev/null 2>&1
  cid=$(kca create clients -r "$REALM" -i -s clientId="$CLIENT_ID" -s publicClient=true \
    -s directAccessGrantsEnabled=true -s standardFlowEnabled=false -s enabled=true)
  kca create "clients/${cid}/protocol-mappers/models" -r "$REALM" \
    -s name=groups -s protocol=openid-connect -s protocolMapper=oidc-group-membership-mapper \
    -s 'config."full.path"=false' -s 'config."id.token.claim"=true' \
    -s 'config."access.token.claim"=true' -s 'config."userinfo.token.claim"=true' \
    -s 'config."claim.name"=groups' >/dev/null 2>&1
  kca create "user-storage/${ldap_id}/sync?action=triggerFullSync" -r "$REALM" >/dev/null 2>&1 \
    || echo "warning: initial full sync failed (is ou=people populated?); retry from the admin console"
}

summary() {
  cat <<EOF

Keycloak (local test values only)
  admin console : http://127.0.0.1:${KC_PORT}/admin/  (${KC_ADMIN_USER} / ${KC_ADMIN_PW}, master realm)
  realm         : ${REALM}   test client: ${CLIENT_ID} (public, direct grants; groups claim)
  LDAP provider : ldap://${LDAP_CONTAINER}:389, base ${FEDERATION_BASE}, READ_ONLY, paged
  bind DN       : ${SVC_DN} / ${SVC_PW}  (read-only via the stock ACL; cannot read userPassword)
Log in as an LDAP user:
  curl -s -d client_id=${CLIENT_ID} -d grant_type=password -d scope=openid -d username=<uid> -d password=<pw> \\
    http://127.0.0.1:${KC_PORT}/realms/${REALM}/protocol/openid-connect/token
Stop with: $0 down   (Keycloak state is in-container and is discarded)
EOF
}

case "${1:-}" in
  up)
    resolve_ldap
    ensure_network
    ensure_directory_entries
    start_keycloak
    configure_federation
    summary
    ;;
  down)
    docker rm -f -v "$KC_CONTAINER" >/dev/null 2>&1 || true
    echo "removed ${KC_CONTAINER} (network ${NET}, the bind DN and LDAP data are untouched)"
    ;;
  status)
    if running "$KC_CONTAINER"; then
      echo "${KC_CONTAINER}: running, http://127.0.0.1:${KC_PORT}/"
      if kca get "realms/${REALM}" --fields realm >/dev/null 2>&1; then
        echo "realm ${REALM}: present"
      else
        echo "realm ${REALM}: missing (run '$0 up')"
      fi
    else
      echo "${KC_CONTAINER}: not running"
    fi
    if running "$LDAP_CONTAINER"; then echo "${LDAP_CONTAINER}: running"; else echo "${LDAP_CONTAINER}: not running"; fi
    ;;
  *) usage ;;
esac
