#!/usr/bin/env bash
# Live regression test for issue #206: wiping the data/config volumes of the
# serverID-1 node of a two-node multi-provider cluster must not make peers
# delete entries that were written after the initial sync. After the wiped
# node restarts, every entry that existed before the wipe must be present on
# BOTH nodes.
#
# Usage: scripts/test/test-wiped-node-resync.sh [image]
#   image defaults to ldapium:e2e. Requires Docker. WIPED_NODE_TIMEOUT
#   (seconds, default 120) bounds each convergence wait. Resources are named
#   ldapium-hv206-* ($$-suffixed) and only those are removed on exit.
set -euo pipefail
# Never pipe into `grep -q` (SIGPIPE + pipefail): match captured variables.

image="${1:-ldapium:e2e}"
timeout_s="${WIPED_NODE_TIMEOUT:-120}"
pw="wipedNodeTestPw1"
suffix="$$"
net="ldapium-hv206-net-${suffix}"
n1="ldapium-hv206-n1-${suffix}"
n2="ldapium-hv206-n2-${suffix}"
vols=("${n1}-cfg" "${n1}-data" "${n2}-cfg" "${n2}-data")
base="dc=example,dc=org"
admin="cn=admin,${base}"

fail=0
ok() { printf 'PASS: %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }

# shellcheck disable=SC2317,SC2329 # invoked via the EXIT trap below
cleanup() {
  local x
  docker rm -f "$n1" "$n2" >/dev/null 2>&1 || true
  for x in "${vols[@]}"; do docker volume rm -f "$x" >/dev/null 2>&1 || true; done
  docker network rm "$net" >/dev/null 2>&1 || true
}
trap cleanup EXIT

start_node() { # name sid
  docker run -d --name "$1" --network "$net" --hostname "$1" \
    -v "$1-cfg:/etc/openldap/slapd.d" -v "$1-data:/var/lib/openldap/data" \
    -e LDAP_ROOT_DN="$base" -e LDAP_ADMIN_PASSWORD="$pw" \
    -e LDAP_REPLICATION_ENABLED=true -e LDAP_SERVER_ID="$2" \
    -e LDAP_REPLICATION_PEERS="ldap://${n1}:389,ldap://${n2}:389" \
    "$image" >/dev/null
}

wait_ready() {
  local w=0
  while [ "$w" -lt "$timeout_s" ]; do
    docker exec "$1" ldapwhoami -x -H ldap://localhost >/dev/null 2>&1 && return 0
    sleep 1
    w=$((w + 1))
  done
  return 1
}

uids() { # node -> sorted uid list (empty on error)
  docker exec "$1" ldapsearch -x -LLL -H ldap://localhost -D "$admin" -w "$pw" \
    -b "$base" '(objectClass=inetOrgPerson)' uid 2>/dev/null | sed -n 's/^uid: //p' | sort | tr '\n' ' ' || true
}

add_user() { # node uid
  docker exec -i "$1" ldapadd -x -H ldap://localhost -D "$admin" -w "$pw" >/dev/null <<LDIF
dn: uid=$2,${base}
objectClass: inetOrgPerson
uid: $2
cn: $2
sn: $2
LDIF
}

wait_uids() { # node "expected list" -> 0 when equal
  local w=0 got
  while [ "$w" -lt "$timeout_s" ]; do
    got="$(uids "$1")"
    [ "$got" = "$2" ] && return 0
    sleep 2
    w=$((w + 2))
  done
  return 1
}

docker network create "$net" >/dev/null
for v in "${vols[@]}"; do docker volume create "$v" >/dev/null; done

# Node 1 first (no reachable peer => it mints the base DIT), then node 2.
start_node "$n1" 1
wait_ready "$n1" || { bad "node1 never became ready"; exit 1; }
start_node "$n2" 2
wait_ready "$n2" || { bad "node2 never became ready"; exit 1; }
add_user "$n1" alice
want="alice bob eve "
wait_uids "$n2" "alice " || bad "initial sync: alice did not reach node2"
add_user "$n1" bob
add_user "$n2" eve
wait_uids "$n1" "$want" || bad "pre-wipe: bob/eve did not reach node1"
wait_uids "$n2" "$want" || bad "pre-wipe: node2 missing entries"
[ "$fail" -eq 0 ] || exit 1
ok "pre-wipe: both nodes hold: ${want}"

# Wipe node 1 (the serverID-1 node): remove container and both volumes.
docker rm -f "$n1" >/dev/null
docker volume rm -f "${n1}-cfg" "${n1}-data" >/dev/null
docker volume create "${n1}-cfg" >/dev/null
docker volume create "${n1}-data" >/dev/null
start_node "$n1" 1
wait_ready "$n1" || { bad "wiped node1 never became ready"; docker logs --tail 30 "$n1" >&2; exit 1; }

# Give replication time to converge (or to destroy data), then assert.
for n in "$n1" "$n2"; do
  if wait_uids "$n" "$want"; then
    ok "post-wipe: ${n} holds every pre-wipe entry"
  else
    bad "post-wipe: ${n} has '$(uids "$n")', expected '${want}'"
  fi
done
sleep 15 # let any late peer-driven deletion surface, then re-check
for n in "$n1" "$n2"; do
  [ "$(uids "$n")" = "$want" ] || bad "post-wipe (settled): ${n} has '$(uids "$n")', expected '${want}'"
done

# Second boot of an already-bootstrapped replicated node (offline replication
# reconcile runs again against an existing config) must still come up intact.
docker restart "$n2" >/dev/null
if wait_ready "$n2" && wait_uids "$n2" "$want"; then
  ok "restart: ${n2} came back with every entry"
else
  bad "restart: ${n2} did not come back intact"
fi

if [ "$fail" -eq 0 ]; then
  echo "wiped-node resync test passed"
  exit 0
fi
echo "wiped-node resync test FAILED" >&2
docker logs --tail 40 "$n1" >&2 2>&1 || true
exit 1
