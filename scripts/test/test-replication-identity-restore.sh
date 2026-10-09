#!/usr/bin/env bash
# D63/AC012 live primitive: source-only backup, total populated-volume loss,
# current Secret LDAP49 control, reconcile, then fresh dedicated peers refill.
# Not a test of the pending rotate command or a complete G1/G2 recovery gate.
set -euo pipefail
image="${1:-ldapium:e2e}"
here="$(cd "$(dirname "$0")/.." && pwd)"
prefix="ldapium-ridrestore-$$"; net="$prefix-net"; certs="$prefix-certs"; backup="$prefix-backup"; helper="$prefix-helper"
nodes=("$prefix-n1" "$prefix-n2" "$prefix-n3")
base=dc=example,dc=org; admin="cn=admin,$base"; identity="cn=replicator,$base"
adminpw=ridrestoreAdminPw-Ab3Cd5Ef7Gh9Ij1Kl2Mn4Op6Qr8St0Uv
current=ridrestoreCurrentPw-Qw2Er4Ty6Ui8Op0As1Df3Gh5Jk7Lz9Xc
peers="ldaps://${nodes[0]}:636,ldaps://${nodes[1]}:636,ldaps://${nodes[2]}:636"
# shellcheck disable=SC2317,SC2329
cleanup() {
  docker rm -fv "$helper" >/dev/null 2>&1 || true
  for node in "${nodes[@]}"; do docker rm -fv "$node" >/dev/null 2>&1 || true; docker volume rm "$node-cfg" "$node-data" >/dev/null 2>&1 || true; done
  docker volume rm "$certs" "$backup" >/dev/null 2>&1 || true; docker network rm "$net" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker network create "$net" >/dev/null
for volume in "$certs" "$backup"; do docker volume create "$volume" >/dev/null; done
docker run --rm --user 0 -v "$certs:/certs" -v "$backup:/backup" --entrypoint sh "$image" -c '
set -e; cd /certs
printf "subjectAltName=DNS:%s,DNS:%s,DNS:%s,DNS:localhost\n" "$1" "$2" "$3" > ext.cnf
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 2 -subj /CN=ridrestore-ca
openssl req -newkey rsa:2048 -nodes -keyout k.pem -out s.csr -subj /CN=localhost
openssl x509 -req -in s.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out c.pem -days 2 -extfile ext.cnf
printf "%s" "$4" > adminpw; printf "%s" "$5" > current
chown -R 999:999 /certs /backup; chmod 600 k.pem ca.key adminpw current
' sh "${nodes[@]}" "$adminpw" "$current" >/dev/null 2>&1
start() {
  local node="$1" sid="$2" mode="$3"; local extra=()
  if [ "$mode" = dedicated ]; then extra=(-e LDAP_REPLICATION_PASSWORD_FILE=/certs/current); fi
  docker run -d --name "$node" --hostname "$node" --network "$net" \
    -v "$node-cfg:/etc/openldap/slapd.d" -v "$node-data:/var/lib/openldap/data" -v "$certs:/certs:ro" -v "$backup:/backup" \
    -e LDAP_ROOT_DN="$base" -e LDAP_ADMIN_PASSWORD="$adminpw" -e LDAP_REPLICATION_ENABLED=true \
    -e LDAP_SERVER_ID="$sid" -e LDAP_REPLICATION_PEERS="$peers" -e LDAP_REPLICATION_IDENTITY="$mode" \
    -e LDAP_TLS_ENABLED=true -e LDAP_TLS_CERT_FILE=/certs/c.pem -e LDAP_TLS_KEY_FILE=/certs/k.pem -e LDAP_TLS_CA_FILE=/certs/ca.pem ${extra[@]+"${extra[@]}"} "$image" >/dev/null
  local ready=0
  for ((i=0;i<120;i++)); do
    if docker exec "$node" ldapwhoami -x -H ldap://localhost >/dev/null 2>&1; then ready=1; break; fi
    [ "$(docker inspect -f '{{.State.Running}}' "$node")" = true ] || { docker logs "$node" >&2; return 1; }; sleep 1
  done
  [ "$ready" = 1 ] || { echo 'FAIL node never became ready'; return 1; }
  docker cp "$here/replication-identity.sh" "$node:/tmp/identity.sh"
}
ri() { docker exec -e LDAPTLS_CACERT=/certs/ca.pem "${nodes[0]}" bash /tmp/identity.sh "$@" --uri "ldaps://${nodes[0]}:636" --base "$base" --admin-password-file /certs/adminpw; }
bind_current() { docker exec -e LDAPTLS_CACERT=/certs/ca.pem "$1" ldapwhoami -x -H "ldaps://$1:636" -D "$identity" -y /certs/current; }
entry_uuid() { docker exec "$1" ldapsearch -x -LLL -H ldap://localhost -D "$admin" -y /certs/adminpw -b "$base" -s base entryUUID | sed -n 's/^entryUUID: //p'; }
data_hash() {
  docker exec "$1" ldapsearch -x -LLL -o ldif-wrap=no -H ldap://localhost -D "$admin" -y /certs/adminpw -b "$base" '(objectClass=*)' entryUUID userPassword objectClass uid cn sn mail | python3 -c 'import hashlib,sys; rows=["\n".join(sorted(line for line in block.splitlines() if line and not line.startswith("#"))) for block in sys.stdin.read().split("\n\n")]; print(hashlib.sha256("\n\n".join(sorted(row for row in rows if row)).encode()).hexdigest())'
}
start "${nodes[0]}" 1 admin
uuid=$(entry_uuid "${nodes[0]}"); [ -n "$uuid" ] || { echo 'FAIL baseline UUID missing'; exit 1; }
docker rm -f "${nodes[0]}" >/dev/null
start "${nodes[0]}" 1 prepare
ri ensure --out /tmp/old.pw
# A non-identity fixture proves ordinary password/data restore and propagation.
docker exec -i "${nodes[0]}" ldapadd -x -H ldap://localhost -D "$admin" -y /certs/adminpw >/dev/null <<LDIF
dn: uid=restore-probe,$base
objectClass: inetOrgPerson
uid: restore-probe
cn: Restore Probe
sn: Probe
mail: restore-probe@example.org
userPassword: FixturePasswordOnly-0123456789AbCdEf
LDIF

for script in backup.sh verify-backup.sh restore.sh; do docker cp "$here/$script" "${nodes[0]}:/tmp/$script"; done
docker exec "${nodes[0]}" bash /tmp/backup.sh --root-dn "$base" --password-file /certs/adminpw --output-dir /backup --no-record
docker rm -f "${nodes[0]}" >/dev/null
docker volume rm "${nodes[0]}-cfg" "${nodes[0]}-data" >/dev/null
docker create --name "$helper" --user 0 --entrypoint bash -v "$backup:/backup:ro" -v "${nodes[0]}-cfg:/etc/openldap/slapd.d" -v "${nodes[0]}-data:/var/lib/openldap/data" "$image" /tmp/restore.sh --backup-dir /backup --target-config /etc/openldap/slapd.d --target-data /var/lib/openldap --confirm-offline --force-empty >/dev/null
for script in restore.sh verify-backup.sh; do docker cp "$here/$script" "$helper:/tmp/$script"; done
result=0; docker start -a "$helper" || result=$?; docker rm "$helper" >/dev/null
[ "$result" = 0 ] || { echo 'FAIL restore failed'; exit 1; }
start "${nodes[0]}" 1 dedicated
result=0; bind_current "${nodes[0]}" >/dev/null 2>&1 || result=$?
[ "$result" = 49 ] || { echo "FAIL restored old hash should refuse current credential with 49, got $result"; exit 1; }
echo 'PASS: restored old credential rejects current Secret (49), all peers stopped'
ri reconcile --current-password-file /certs/current
bind_current "${nodes[0]}" >/dev/null
[ "$(entry_uuid "${nodes[0]}")" = "$uuid" ] || { echo 'FAIL restored UUID changed'; exit 1; }
expected_hash=$(data_hash "${nodes[0]}")
start "${nodes[1]}" 2 dedicated; start "${nodes[2]}" 3 dedicated
for node in "${nodes[@]}"; do
  matched=0
  for ((i=0;i<120;i++)); do
    if [ "$(entry_uuid "$node" 2>/dev/null || true)" = "$uuid" ] && bind_current "$node" >/dev/null 2>&1 && [ "$(data_hash "$node")" = "$expected_hash" ]; then matched=1; break; fi; sleep 1
  done
  [ "$matched" = 1 ] || { echo "FAIL restored data/identity did not reach $node"; exit 1; }
  echo 'PASS: preserved UUID and current TLS identity bind on a restored/dedicated node'
done
echo 'ALL PASS: real backup, total populated-volume loss, restore, 49 control, reconcile, dedicated peer refill'
