#!/usr/bin/env bash
# Live test for scripts/replication-identity.sh rollback-admin (docs/changes/replication-identity,
# #352, T-013 / AC-011 c-e, D66). Two real slapd nodes replicate over verified TLS (admin ->
# prepare -> ensure -> dedicated); nothing is mocked.
#
# Covers: the gate passes on a converged, populated cluster and changes nothing; it refuses
# (exit 1, nothing created or deleted) for an empty node (a dedicated sid whose peers are
# absent creates no base DIT), a node lagging behind (its consumer removed, a write only on
# n1: the contextCSN set and entry count differ), an administrator password that is not valid
# on a listed peer, a clear-LDAP URI and a missing password file; after the refusal clears
# (the lagging node restarted and converged) it passes, and the nodes are then switched to
# administrator replication by hand: stored consumers bind as the admin DN and writes
# replicate both ways. No password reaches any output or log.
#
# Usage: scripts/test/test-replication-identity-rollback-admin.sh [image]   (default ldapium:e2e)
# Resources are named ldapium-ridrbk-* and only those are removed on exit.
set -euo pipefail
# Never pipe into `grep -q` (SIGPIPE + pipefail): match captured variables.

image="${1:-ldapium:e2e}"
here="$(cd "$(dirname "$0")/.." && pwd)"
timeout_s="${RIDRBK_TIMEOUT:-120}"
suffix="$$"
pw="ridrbkAdminPw-Zq7Lm2Xv9Kd4Hs8Wt1Bn6Rc3Yf5Ug0Pe"
alicepw="ridrbkAlicePw-1"
base="dc=example,dc=org"
admin="cn=admin,${base}"
iddn="cn=replicator,${base}"
net="ldapium-ridrbk-net-${suffix}"
n1="ldapium-ridrbk-n1-${suffix}"
n2="ldapium-ridrbk-n2-${suffix}"
n3="ldapium-ridrbk-n3-${suffix}"   # dedicated, peers absent: stays empty
n4="ldapium-ridrbk-n4-${suffix}"   # standalone, a different administrator password
certs="ldapium-ridrbk-certs-${suffix}"
peers="ldaps://${n1}:636,ldaps://${n2}:636"
work="$(mktemp -d)"

fail=0
ok() { printf 'PASS: %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: expected '$2', got '$3'"; fi; }
has() { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac; } # needle haystack

reg_containers=("$n1" "$n2" "$n3" "$n4")
reg_vols=("${n1}-cfg" "${n1}-data" "${n2}-cfg" "${n2}-data" "${n3}-cfg" "${n3}-data" "${n4}-cfg" "${n4}-data" "$certs")
# shellcheck disable=SC2317,SC2329 # invoked via the trap below
cleanup() {
  local x rc=$?
  trap - EXIT
  if [ "$rc" != 0 ]; then docker logs "$n1" 2>&1 | tail -n 15 >&2 || true; fi
  for x in "${reg_containers[@]}"; do docker rm -fv "$x" >/dev/null 2>&1 || true; done
  for x in "${reg_vols[@]}"; do docker volume rm -f "$x" >/dev/null 2>&1 || true; done
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -rf "$work"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

poll() { local w=0; until "$@" >/dev/null 2>&1; do sleep 1; w=$((w + 1)); [ "$w" -lt "$timeout_s" ] || return 1; done; }
# shellcheck disable=SC2317,SC2329 # invoked through poll
ready() { docker exec "$1" ldapwhoami -x -H ldap://localhost >/dev/null 2>&1; }
asearch() { local n="$1"; shift; docker exec "$n" ldapsearch -x -LLL -H ldap://localhost -D "$admin" -w "$pw" "$@"; }
# shellcheck disable=SC2317,SC2329 # invoked through poll
has_uid() { local o; o="$(asearch "$1" -b "$base" "(uid=$2)" uid)" || return 1; has "uid: $2" "$o"; }
# shellcheck disable=SC2317,SC2329 # invoked through poll
has_identity() { local o; o="$(asearch "$1" -b "$iddn" -s base cn)" || return 1; has "cn: replicator" "$o"; }
add_user() {
  docker exec -i "$1" ldapadd -x -H ldap://localhost -D "$admin" -w "$pw" >/dev/null <<EOF
dn: uid=$2,${base}
objectClass: inetOrgPerson
uid: $2
cn: $2
sn: $2
userPassword: ${alicepw}
EOF
}
err49() { local o; o="$(docker logs "$1" 2>&1)"; grep -c 'err=49' <<<"$o" || true; }

start_node() { # name sid mode: admin | prepare | file:<name in the certs volume>
  local name="$1" sid="$2" mode="$3" args=()
  case "$mode" in
    prepare) args+=(-e LDAP_REPLICATION_IDENTITY=prepare) ;;
    file:*) args+=(-e LDAP_REPLICATION_IDENTITY=dedicated -e "LDAP_REPLICATION_PASSWORD_FILE=/certs/${mode#file:}") ;;
  esac
  docker run -d --name "$name" --network "$net" --hostname "$name" \
    -v "${name}-cfg:/etc/openldap/slapd.d" -v "${name}-data:/var/lib/openldap/data" \
    -v "${certs}:/certs:ro" -e LDAP_TLS_ENABLED=true -e LDAP_TLS_CERT_FILE=/certs/c.pem \
    -e LDAP_TLS_KEY_FILE=/certs/k.pem -e LDAP_TLS_CA_FILE=/certs/ca.pem \
    -e LDAP_ROOT_DN="$base" -e LDAP_ADMIN_PASSWORD="$pw" \
    -e LDAP_REPLICATION_ENABLED=true -e LDAP_SERVER_ID="$sid" \
    -e LDAP_REPLICATION_PEERS="$peers" ${args[@]+"${args[@]}"} "$image" >/dev/null
}
sid_of() { if [ "$1" = "$n1" ]; then echo 1; else echo 2; fi; }
old=""
tools() { # name: operator script and the password files (all lost with every container)
  docker cp "${here}/replication-identity.sh" "${1}:/tmp/ri.sh"
  printf '%s' "$pw" | docker exec -i "$1" sh -c 'umask 077; cat > /tmp/admin.pw'
  [ -z "$old" ] || printf '%s' "$old" | docker exec -i "$1" sh -c 'umask 077; cat > /tmp/old.pw'
}
restart_node() { # name mode
  docker rm -f "$1" >/dev/null
  start_node "$1" "$(sid_of "$1")" "$2"
  poll ready "$1" || { bad "$1 (${2}) never ready"; docker logs "$1" 2>&1 | tail -n 20 >&2; exit 1; }
  tools "$1"
}
put_secret() { printf '%s' "$2" | docker run --rm -i --user 0 -v "${certs}:/certs" --entrypoint sh "$image" -c 'cat > "/certs/$1"; chmod 644 "/certs/$1"' sh "$1"; }


# ri_roll <extra args...>: rollback-admin inside n1, listing the nodes given as --peer
ri_roll() {
  docker exec -e LDAPTLS_CACERT=/certs/ca.pem "$n1" bash /tmp/ri.sh rollback-admin --uri "ldaps://${n1}:636" --base "$base" --admin-password-file /tmp/admin.pw "$@"
}
last_out="" ; last_rc=0
run() { last_rc=0; last_out="$("$@" 2>&1)" || last_rc=$?; printf '%s\n' "$last_out" >> "$work/all.out"; }
# digest of every DN on node $1 (nothing may be created or deleted by a refusal)
snap() { local o; o="$(asearch "$1" -b "$base" -s sub '(objectClass=*)' 1.1)" || { echo "?"; return; }; grep '^dn:' <<<"$o" | sort | sha256sum | cut -d' ' -f1; }
# shellcheck disable=SC2317,SC2329 # invoked through poll
roll_passes() { ri_roll --peer "ldaps://${n2}:636" >/dev/null 2>&1; }
syncrepl_binds() { local o; o="$(docker exec "$1" slapcat -n 0 -o ldif-wrap=no)" || { echo "?"; return; }; grep -c "^olcSyncrepl:.*binddn=\"$2\"" <<<"$o" || true; }

docker network create "$net" >/dev/null
for x in "${reg_vols[@]}"; do docker volume create "$x" >/dev/null; done
docker run --rm --user 0 -v "${certs}:/certs" --entrypoint sh "$image" -c '
set -e
cd /certs
printf "subjectAltName=DNS:%s,DNS:%s,DNS:%s,DNS:%s,DNS:localhost\n" "$1" "$2" "$3" "$4" > ext.cnf
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 2 -subj /CN=ridrbk-ca
openssl req -newkey rsa:2048 -nodes -keyout k.pem -out s.csr -subj /CN=localhost
openssl x509 -req -in s.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out c.pem -days 2 -extfile ext.cnf
chown -R 999:999 /certs
chmod 600 k.pem ca.key
' sh "$n1" "$n2" "$n3" "$n4" >/dev/null 2>&1

echo "== setup: admin -> prepare -> ensure -> dedicated, 2 nodes over verified TLS"
start_node "$n1" 1 admin
poll ready "$n1" || { bad "n1 never ready"; exit 1; }
start_node "$n2" 2 admin
poll ready "$n2" || { bad "n2 never ready"; exit 1; }
add_user "$n1" alice
poll has_uid "$n2" alice || bad "alice never replicated to n2"
for n in "$n1" "$n2"; do restart_node "$n" prepare; done
run docker exec -e LDAPTLS_CACERT=/certs/ca.pem "$n1" bash /tmp/ri.sh ensure --uri "ldaps://${n1}:636" --base "$base" --admin-password-file /tmp/admin.pw --out /tmp/old.pw
check "ensure creates the identity" 0 "$last_rc"
old="$(docker exec "$n1" cat /tmp/old.pw)"
put_secret idold "$old"
poll has_identity "$n2" || bad "identity never replicated to n2"
for n in "$n2" "$n1"; do restart_node "$n" file:idold; done
add_user "$n1" bob
poll has_uid "$n2" bob || bad "dedicated: bob never replicated n1 -> n2"
add_user "$n2" carol
poll has_uid "$n1" carol || bad "dedicated: carol never replicated n2 -> n1"

echo "== AC-011 c: a converged, populated cluster passes and nothing changes"
before="$(snap "$n1"):$(snap "$n2")"
run ri_roll --peer "ldaps://${n2}:636"
check "gate passes, exit 0" 0 "$last_rc"
if has "gate passed on 2 node(s)" "$last_out"; then ok "output names both nodes"; else bad "output: ${last_out:0:200}"; fi
if has "identity=admin" "$last_out"; then ok "output carries the operator steps"; else bad "operator steps missing"; fi
check "nothing created or deleted" "$before" "$(snap "$n1"):$(snap "$n2")"

echo "== AC-011 d: an empty node (sid with peers absent creates no base DIT) is refused"
docker run -d --name "$n3" --network "$net" --hostname "$n3" \
  -v "${n3}-cfg:/etc/openldap/slapd.d" -v "${n3}-data:/var/lib/openldap/data" \
  -v "${certs}:/certs:ro" -e LDAP_TLS_ENABLED=true -e LDAP_TLS_CERT_FILE=/certs/c.pem \
  -e LDAP_TLS_KEY_FILE=/certs/k.pem -e LDAP_TLS_CA_FILE=/certs/ca.pem \
  -e LDAP_ROOT_DN="$base" -e LDAP_ADMIN_PASSWORD="$pw" \
  -e LDAP_REPLICATION_ENABLED=true -e LDAP_SERVER_ID=3 \
  -e "LDAP_REPLICATION_PEERS=ldaps://ghost-a-${suffix}:636,ldaps://ghost-b-${suffix}:636,ldaps://${n3}:636" \
  -e LDAP_REPLICATION_IDENTITY=dedicated -e LDAP_REPLICATION_PASSWORD_FILE=/certs/idold "$image" >/dev/null
poll ready "$n3" || { bad "n3 never ready"; exit 1; }
x=0; docker exec "$n3" ldapsearch -x -H ldap://localhost -D "$admin" -w "$pw" -b "$base" -s base dn >/dev/null 2>&1 || x=$?
check "control: n3 really has no ${base} entry (rc 32)" 32 "$x"
run ri_roll --peer "ldaps://${n2}:636" --peer "ldaps://${n3}:636"
check "empty node: refused, exit 1" 1 "$last_rc"
if has "${n3}:636 is empty" "$last_out"; then ok "empty node: the message names it"; else bad "empty node message: ${last_out:0:300}"; fi
x=0; docker exec "$n3" ldapsearch -x -H ldap://localhost -D "$admin" -w "$pw" -b "$base" -s base dn >/dev/null 2>&1 || x=$?
check "empty node: still empty after the refusal" 32 "$x"
check "empty node: the other nodes are unchanged" "$before" "$(snap "$n1"):$(snap "$n2")"

echo "== D62: an administrator password that is not valid on a listed peer"
docker run -d --name "$n4" --network "$net" --hostname "$n4" \
  -v "${n4}-cfg:/etc/openldap/slapd.d" -v "${n4}-data:/var/lib/openldap/data" \
  -v "${certs}:/certs:ro" -e LDAP_TLS_ENABLED=true -e LDAP_TLS_CERT_FILE=/certs/c.pem \
  -e LDAP_TLS_KEY_FILE=/certs/k.pem -e LDAP_TLS_CA_FILE=/certs/ca.pem \
  -e LDAP_ROOT_DN="$base" -e LDAP_ADMIN_PASSWORD="ridrbkOtherAdminPw-Mn4Bv7Cx2Zl9Kj5Hg8Fd3Sa" "$image" >/dev/null
poll ready "$n4" || { bad "n4 never ready"; exit 1; }
run ri_roll --peer "ldaps://${n2}:636" --peer "ldaps://${n4}:636"
check "wrong administrator password on a peer: refused, exit 1" 1 "$last_rc"
if has "not valid on ldaps://${n4}:636" "$last_out"; then ok "the message names the peer"; else bad "message: ${last_out:0:300}"; fi

echo "== AC-011 d: a node that is lagging behind is refused"
saved_sync="$(docker exec "$n2" slapcat -n 0 -o ldif-wrap=no | grep '^olcSyncrepl:')"
docker exec -i "$n2" ldapmodify -x -H ldap://localhost -D cn=admin,cn=config -w "$pw" >/dev/null <<EOF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
delete: olcSyncrepl
EOF
add_user "$n1" dave
sleep 3
x=0; has_uid "$n2" dave || x=$?
check "control: dave did not reach n2 (consumer removed)" 1 "$x"
run ri_roll --peer "ldaps://${n2}:636"
check "lagging node: refused, exit 1" 1 "$last_rc"
if has "differs from" "$last_out"; then ok "lagging node: the message says it differs"; else bad "message: ${last_out:0:300}"; fi

echo "== guards"
run docker exec -e LDAPTLS_CACERT=/certs/ca.pem "$n1" bash /tmp/ri.sh rollback-admin --uri "ldap://${n1}:389" --base "$base" --admin-password-file /tmp/admin.pw
check "clear LDAP is refused" 1 "$last_rc"
run docker exec -e LDAPTLS_CACERT=/certs/ca.pem "$n1" bash /tmp/ri.sh rollback-admin --uri "ldaps://${n1}:636" --base "$base" --admin-password-file /tmp/missing.pw
check "a missing password file is refused" 1 "$last_rc"
run docker exec -e LDAPTLS_CACERT=/certs/ca.pem -e LDAPTLS_REQCERT=never "$n1" bash /tmp/ri.sh rollback-admin --uri "ldaps://${n1}:636" --base "$base" --admin-password-file /tmp/admin.pw
check "disabled certificate verification is refused" 1 "$last_rc"

echo "== recovery: the lagging node converges, the gate opens, then the switch to administrator replication"
# the same stored consumer values go back (a dedicated restart refuses a config without them)
{ printf 'dn: olcDatabase={1}mdb,cn=config\nchangetype: modify\nadd: olcSyncrepl\n%s\n' "$saved_sync"; } \
  | docker exec -i "$n2" ldapmodify -x -H ldap://localhost -D cn=admin,cn=config -w "$pw" >/dev/null
unset saved_sync
poll has_uid "$n2" dave || bad "n2 never converged after its consumer was restored"
if poll roll_passes; then ok "gate passes once the node has converged"; else bad "gate never passed after convergence"; fi
for n in "$n2" "$n1"; do restart_node "$n" admin; done
check "stored consumers bind as the admin DN, none as the identity" "1:0:1:0" \
  "$(syncrepl_binds "$n1" "$admin"):$(syncrepl_binds "$n1" "$iddn"):$(syncrepl_binds "$n2" "$admin"):$(syncrepl_binds "$n2" "$iddn")"
add_user "$n1" erin
poll has_uid "$n2" erin || bad "after the switch: erin never replicated n1 -> n2"
add_user "$n2" frank
poll has_uid "$n1" frank || bad "after the switch: frank never replicated n2 -> n1"
check "after the switch: both nodes converge on the same entries" "$(snap "$n1")" "$(snap "$n2")"

echo "== no password in any output or log"
leaks=0
for secret in "$pw" "$old"; do
  c="$(grep -c -F -e "$secret" "$work/all.out" || true)"
  leaks=$((leaks + c))
  for n in "$n1" "$n2" "$n3" "$n4"; do
    o="$(docker logs "$n" 2>&1)"
    c="$(grep -c -F -e "$secret" <<<"$o" || true)"
    leaks=$((leaks + c))
  done
done
check "no password in command output or container logs" 0 "$leaks"

if [ "$fail" = 0 ]; then echo 'ALL PASS: real verified TLS rollback-admin gate, refusals leave the directory unchanged, switch to administrator replication'; else exit 1; fi
