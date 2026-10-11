#!/usr/bin/env bash
# Live verification of the check's cluster features (docs/changes/replication-identity, #375, T-014):
# the --local (slapcat) read path, automatic membership validation (D68) and the opt-in canary (D70)
# on 3 real replicating TLS nodes in `prepare` mode (admin syncrepl, read-only identity ACL).
#
# Usage: scripts/test/test-replication-identity-check-cluster.sh [image]   (default ldapium:e2e)
#   RIDC_TIMEOUT (seconds, default 120) bounds every wait. Resources are named ldapium-ridc-*.
set -euo pipefail
# Never pipe into `grep -q` (SIGPIPE + pipefail): match captured variables.

image="${1:-ldapium:e2e}"
here="$(cd "$(dirname "$0")/.." && pwd)"
timeout_s="${RIDC_TIMEOUT:-120}"
suffix="$$"
pw="ridcAdminPw-Zq7Lm2Xv9Kd4Hs8Wt1Bn6Rc3Yf5Ug0Pe"
base="dc=example,dc=org"
admin="cn=admin,${base}"
net="ldapium-ridc-net-${suffix}"
n1="ldapium-ridc-n1-${suffix}"
n2="ldapium-ridc-n2-${suffix}"
n3="ldapium-ridc-n3-${suffix}"
certs="ldapium-ridc-certs-${suffix}"
peers="ldaps://${n1}:636,ldaps://${n2}:636,ldaps://${n3}:636"
fail=0
ok() { printf 'PASS: %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: expected '$2', got '$3'"; fi; }
# shellcheck disable=SC2317,SC2329 # invoked via the trap below
cleanup() {
  local rc=$?
  trap - EXIT
  if [ "$rc" != 0 ]; then docker logs "$n1" 2>&1 | tail -n 15 >&2 || true; fi
  docker rm -fv "$n1" "$n2" "$n3" >/dev/null 2>&1 || true
  docker volume rm -f "${n1}-cfg" "${n1}-data" "${n2}-cfg" "${n2}-data" "${n3}-cfg" "${n3}-data" "$certs" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

poll() { local w=0; until "$@" >/dev/null 2>&1; do sleep 1; w=$((w + 1)); [ "$w" -lt "$timeout_s" ] || return 1; done; }
# shellcheck disable=SC2317,SC2329 # invoked through poll
ready() { docker exec "$1" ldapwhoami -x -H ldap://localhost >/dev/null 2>&1; }
# shellcheck disable=SC2317,SC2329 # invoked through poll
has_identity() { local o; o="$(docker exec "$1" ldapsearch -x -LLL -H ldap://localhost -D "$admin" -w "$pw" -b "cn=replicator,${base}" -s base cn)" || return 1; [[ "$o" == *'cn: replicator'* ]]; }
cmodify() { docker exec -i "$1" ldapmodify -x -H ldap://localhost -D cn=admin,cn=config -w "$pw" >/dev/null; }
# strays <node>: leftover canary entries on one node ("?" when the read itself failed)
strays() { local o; o="$(docker exec "$1" ldapsearch -x -LLL -H ldap://localhost -D "$admin" -w "$pw" -b "$base" '(cn=ridcheck-*)' dn)" || { echo '?'; return; }; grep -c '^dn:' <<<"$o" || true; }
# admin_binds <node>: administrator binds that reached this node, from its own log
admin_binds() { local o; o="$(docker logs "$1" 2>&1)"; awk '/BIND dn="cn=admin,dc=example,dc=org"/{n++} END {print n+0}' <<<"$o"; }
# chk <extra args...>: the checker from n1 over n2 and n3
chk() {
  "${here}/check-replication-identity.sh" --container "$n1" --uri "ldaps://${n1}:636" \
    --peer "ldaps://${n2}:636" --peer "ldaps://${n3}:636" --base "$base" \
    --admin-password-file /certs/adminpw --identity-password-file /certs/idpw --ca-file /certs/ca.pem "$@"
}
rc_of() { local x=0; "$@" >/dev/null 2>&1 || x=$?; echo "$x"; }

docker network create "$net" >/dev/null
docker volume create "$certs" >/dev/null
docker run --rm --user 0 -v "${certs}:/certs" --entrypoint sh "$image" -c '
set -e
cd /certs
printf "subjectAltName=DNS:%s,DNS:%s,DNS:%s,DNS:localhost\n" "$1" "$2" "$3" > ext.cnf
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 2 -subj /CN=ridc-ca
openssl req -newkey rsa:2048 -nodes -keyout k.pem -out s.csr -subj /CN=localhost
openssl x509 -req -in s.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out c.pem -days 2 -extfile ext.cnf
printf "%s" "$4" > adminpw
chown -R 999:999 /certs
chmod 600 k.pem ca.key adminpw
' sh "$n1" "$n2" "$n3" "$pw" >/dev/null 2>&1

# start <node> <sid> <mode>: (re)create the container on its volumes and wait for it
start() {
  docker rm -f "$1" >/dev/null 2>&1 || true
  docker run -d --name "$1" --network "$net" --hostname "$1" \
    -v "${1}-cfg:/etc/openldap/slapd.d" -v "${1}-data:/var/lib/openldap/data" -v "${certs}:/certs:ro" \
    -e LDAP_TLS_ENABLED=true -e LDAP_TLS_CERT_FILE=/certs/c.pem -e LDAP_TLS_KEY_FILE=/certs/k.pem \
    -e LDAP_TLS_CA_FILE=/certs/ca.pem -e LDAP_ROOT_DN="$base" -e LDAP_ADMIN_PASSWORD="$pw" \
    -e LDAP_REPLICATION_ENABLED=true -e LDAP_SERVER_ID="$2" -e LDAP_REPLICATION_PEERS="$peers" \
    -e LDAP_REPLICATION_IDENTITY="$3" "$image" >/dev/null
  poll ready "$1" || { bad "$1 ($3) never ready"; exit 1; }
}
# A new cluster starts in admin mode (prepare refuses to bootstrap); then each node switches to prepare.
sid=0
for n in "$n1" "$n2" "$n3"; do
  sid=$((sid + 1))
  docker volume create "${n}-cfg" >/dev/null
  docker volume create "${n}-data" >/dev/null
  start "$n" "$sid" admin
done
sid=0
for n in "$n1" "$n2" "$n3"; do sid=$((sid + 1)); start "$n" "$sid" prepare; done

# The operator creates the read-only identity on one node; it replicates to the others.
docker cp "${here}/replication-identity.sh" "${n1}:/tmp/ri.sh"
printf '%s' "$pw" | docker exec -i "$n1" sh -c 'umask 077; cat > /tmp/admin.pw'
docker exec -e LDAPTLS_CACERT=/certs/ca.pem "$n1" bash /tmp/ri.sh ensure --out /tmp/idpw \
  --uri "ldaps://${n1}:636" --base "$base" --admin-password-file /tmp/admin.pw >/dev/null
docker exec "$n1" cat /tmp/idpw | docker run --rm -i --user 0 -v "${certs}:/certs" --entrypoint sh "$image" -c 'cat > /certs/idpw; chown 999:999 /certs/idpw; chmod 600 /certs/idpw'
for n in "$n2" "$n3"; do poll has_identity "$n" || { bad "identity never replicated to $n"; exit 1; }; done
docker exec -i "$n1" ldapadd -x -H ldap://localhost -D "$admin" -w "$pw" >/dev/null <<LDIF
dn: uid=alice,${base}
objectClass: inetOrgPerson
uid: alice
cn: alice
sn: alice
userPassword: ridcAlicePw-1
LDIF
for n in "$n2" "$n3"; do
  poll docker exec "$n" ldapsearch -x -LLL -H ldap://localhost -D "$admin" -w "$pw" -b "uid=alice,${base}" -s base dn || { bad "alice never replicated to $n"; exit 1; }
done

echo "== baseline: remote check over 3 nodes"
check "remote check passes" 0 "$(rc_of chk)"

echo "== --local: the --uri node is read with slapcat, no administrator bind reaches it"
before="$(admin_binds "$n1")"
check "local check passes" 0 "$(rc_of chk --local)"
check "local check sends no administrator bind to the local node" "$before" "$(admin_binds "$n1")"
before="$(admin_binds "$n1")"
check "remote check passes again" 0 "$(rc_of chk)"
[ "$(admin_binds "$n1")" -gt "$before" ] || bad "control: the remote check did not bind to the local node"
# A real defect must still be seen through the local path: hide userPassword from the identity on n1.
cmodify "$n1" <<LDIF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
add: olcAccess
olcAccess: {0}to attrs=userPassword by dn.exact="cn=replicator,${base}" none by * break
LDIF
check "local check still fails on a hidden userPassword (rc 1)" 1 "$(rc_of chk --local)"
cmodify "$n1" <<LDIF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
delete: olcAccess
olcAccess: {0}to attrs=userPassword by dn.exact="cn=replicator,${base}" none by * break
LDIF
check "local check passes after the ACL is restored" 0 "$(rc_of chk --local)"
check "--local refuses configuration-only" 2 "$(rc_of chk --local --configuration-only --config-password-file /certs/adminpw)"

echo "== membership: every provider a node follows must be a checked target"
cfgargs=(--config-password-file /certs/adminpw)
check "full member set passes the configuration gate" 0 "$(rc_of chk "${cfgargs[@]}" --configuration-only)"
omit_n3() {
  "${here}/check-replication-identity.sh" --container "$n1" --uri "ldaps://${n1}:636" \
    --peer "ldaps://${n2}:636" --base "$base" --admin-password-file /certs/adminpw \
    --identity-password-file /certs/idpw --ca-file /certs/ca.pem "$@"
}
check "omitting a configured provider fails the configuration gate (rc 1)" 1 "$(rc_of omit_n3 "${cfgargs[@]}" --configuration-only)"
check "control: the same two-node data check without membership still passes" 0 "$(rc_of omit_n3)"

echo "== canary: one throwaway entry is written, seen everywhere, readable by the identity, deleted"
check "canary passes" 0 "$(rc_of chk --canary)"
check "no canary entry is left on any node" "0:0:0" "$(strays "$n1"):$(strays "$n2"):$(strays "$n3")"
check "--canary refuses configuration-only" 2 "$(rc_of chk --canary --configuration-only "${cfgargs[@]}")"
# n3 stops following its providers: the canary must be reported as not replicated, and cleaned up.
cmodify "$n3" <<LDIF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
delete: olcSyncrepl
LDIF
check "canary fails when a node does not receive it (rc 1)" 1 "$(rc_of chk --canary --canary-timeout 5)"
check "the failed canary is still removed everywhere" "0:0:0" "$(strays "$n1"):$(strays "$n2"):$(strays "$n3")"

[ "$fail" = 0 ] || exit 1
echo 'ALL PASS: --local slapcat path, membership validation, canary on 3 real nodes'
