#!/usr/bin/env bash
# Real TLS slapd: D67 credential addition, repeat, refusal, and old-value preservation.
set -euo pipefail
image="${1:-ldapium:e2e}"
name="ldapium-ridrec-$$"
certs="${name}-certs"
here="$(cd "$(dirname "$0")/.." && pwd)"
operator="$here/replication-identity.sh"
base=dc=example,dc=org
admin="cn=admin,$base"
identity="cn=replicator,$base"
pw=ridrecAdminPw-Zq7Lm2Xv9Kd4Hs8Wt1Bn6Rc3Yf5Ug0Pe
# shellcheck disable=SC2317,SC2329
cleanup() { if [ "$?" != 0 ]; then docker logs "$name" >&2 || true; docker exec -e LDAPTLS_CACERT=/certs/ca.pem "$name" ldapsearch -x -H ldaps://"$name":636 -D "$admin" -y /tmp/admin.pw -b "$base" -s base dn >&2 || true; fi; docker rm -fv "$name" >/dev/null 2>&1 || true; docker volume rm "$certs" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker volume create "$certs" >/dev/null
docker run --rm --user 0 -v "$certs:/certs" --entrypoint sh "$image" -c '
set -e; cd /certs
printf "subjectAltName=DNS:localhost,DNS:%s\n" "$1" > ext.cnf
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 2 -subj /CN=ridrec-ca
openssl req -newkey rsa:2048 -nodes -keyout k.pem -out s.csr -subj /CN=localhost
openssl x509 -req -in s.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out c.pem -days 2 -extfile ext.cnf
chown -R 999:999 /certs; chmod 600 k.pem ca.key
' sh "$name" >/dev/null 2>&1
docker run -d --name "$name" --hostname "$name" -v "$certs:/certs:ro" -e LDAP_ROOT_DN="$base" -e LDAP_ADMIN_PASSWORD="$pw" -e LDAP_TLS_ENABLED=true -e LDAP_TLS_CERT_FILE=/certs/c.pem -e LDAP_TLS_KEY_FILE=/certs/k.pem -e LDAP_TLS_CA_FILE=/certs/ca.pem "$image" >/dev/null
for ((i=0;i<120;i++)); do
  if docker exec "$name" ldapwhoami -x -H ldap://localhost >/dev/null 2>&1; then break; fi
  [ "$(docker inspect -f '{{.State.Running}}' "$name")" = true ] || { docker logs "$name" >&2; exit 1; }
  sleep 1
done
docker exec "$name" ldapwhoami -x -H ldap://localhost >/dev/null
docker cp "$operator" "$name:/tmp/ri.sh"
printf '%s' "$pw" | docker exec -i "$name" sh -c 'umask 077; cat > /tmp/admin.pw'
ri() { docker exec -e LDAPTLS_CACERT=/certs/ca.pem "$name" bash /tmp/ri.sh "$@" --uri ldaps://"$name":636 --base "$base" --admin-password-file /tmp/admin.pw; }
# First install an explicit read-only identity ACL in this disposable test server.
docker exec -i "$name" ldapmodify -x -H ldap://localhost -D cn=admin,cn=config -y /tmp/admin.pw >/dev/null <<LDIF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
add: olcAccess
olcAccess: {0}to * by dn.exact="$identity" ssf=128 read by dn.exact="$identity" none by * break
-
add: olcLimits
olcLimits: dn.exact="$identity" size=unlimited time=unlimited
LDIF
"$here/check-replication-identity.sh" --container "$name" --uri "ldaps://$name:636" --base "$base" --admin-password-file /tmp/admin.pw --config-password-file /tmp/admin.pw --ca-file /certs/ca.pem --configuration-only
# A runtime proxy-auth policy mutation must close the configuration gate.
docker exec -i "$name" ldapmodify -x -H ldap://localhost -D cn=admin,cn=config -y /tmp/admin.pw >/dev/null <<LDIF
dn: cn=config
changetype: modify
add: olcAuthzPolicy
olcAuthzPolicy: to
LDIF
result=0
"$here/check-replication-identity.sh" --container "$name" --uri "ldaps://$name:636" --base "$base" --admin-password-file /tmp/admin.pw --config-password-file /tmp/admin.pw --ca-file /certs/ca.pem --configuration-only || result=$?
[ "$result" = 1 ] || { echo 'FAIL configuration checker accepted proxy authorization'; exit 1; }
docker exec -i "$name" ldapmodify -x -H ldap://localhost -D cn=admin,cn=config -y /tmp/admin.pw >/dev/null <<LDIF
dn: cn=config
changetype: modify
delete: olcAuthzPolicy
LDIF

ri ensure --out /tmp/old.pw
"$here/check-replication-identity.sh" --container "$name" --uri "ldaps://$name:636" --base "$base" --admin-password-file /tmp/admin.pw --identity-password-file /tmp/old.pw --config-password-file /tmp/admin.pw --ca-file /certs/ca.pem

# A stored consumer config is checked without claiming it connected to a live peer.
credential=$(docker exec "$name" cat /tmp/old.pw)
docker exec -i "$name" ldapmodify -x -H ldap://localhost -D cn=admin,cn=config -y /tmp/admin.pw >/dev/null <<LDIF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
add: olcSyncrepl
olcSyncrepl: rid=001 provider=ldaps://localhost:1636 bindmethod=simple binddn="$identity" credentials="$credential" searchbase="$base" type=refreshAndPersist retry="60 +" tls_reqcert=demand tls_cacert=/certs/ca.pem
LDIF
unset credential
"$here/check-replication-identity.sh" --container "$name" --uri "ldaps://$name:636" --base "$base" --admin-password-file /tmp/admin.pw --identity-password-file /tmp/old.pw --config-password-file /tmp/admin.pw --ca-file /certs/ca.pem --configuration-only --dedicated
printf '%s' 'differentCurrentCredential-0123456789AbCdEf' | docker exec -i "$name" sh -c 'cat > /tmp/other.pw'
result=0
"$here/check-replication-identity.sh" --container "$name" --uri "ldaps://$name:636" --base "$base" --admin-password-file /tmp/admin.pw --identity-password-file /tmp/other.pw --config-password-file /tmp/admin.pw --ca-file /certs/ca.pem --configuration-only --dedicated || result=$?
[ "$result" = 1 ] || { echo 'FAIL configuration checker accepted wrong consumer fingerprint'; exit 1; }
docker exec -i "$name" ldapmodify -x -H ldap://localhost -D cn=admin,cn=config -y /tmp/admin.pw >/dev/null <<LDIF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
delete: olcSyncrepl
LDIF

# Hidden stability metadata is an evidence error, not a concurrent-write warning.
docker exec -i "$name" ldapmodify -x -H ldap://localhost -D cn=admin,cn=config -y /tmp/admin.pw >/dev/null <<LDIF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
add: olcAccess
olcAccess: {0}to attrs=entryCSN by dn.exact="$identity" none by * break
LDIF
result=0
"$here/check-replication-identity.sh" --container "$name" --uri "ldaps://$name:636" --base "$base" --admin-password-file /tmp/admin.pw --identity-password-file /tmp/old.pw --ca-file /certs/ca.pem || result=$?
[ "$result" = 2 ] || { echo 'FAIL checker accepted hidden stability metadata'; exit 1; }
docker exec -i "$name" ldapmodify -x -H ldap://localhost -D cn=admin,cn=config -y /tmp/admin.pw >/dev/null <<LDIF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
delete: olcAccess
olcAccess: {0}to attrs=entryCSN by dn.exact="$identity" none by * break
LDIF

# Same CSN / hidden userPassword is a real ACL defect, not a replication outage.
docker exec -i "$name" ldapmodify -x -H ldap://localhost -D cn=admin,cn=config -y /tmp/admin.pw >/dev/null <<LDIF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
add: olcAccess
olcAccess: {0}to attrs=userPassword by dn.exact="$identity" none by * break
LDIF
result=0
"$here/check-replication-identity.sh" --container "$name" --uri "ldaps://$name:636" --base "$base" --admin-password-file /tmp/admin.pw --identity-password-file /tmp/old.pw --ca-file /certs/ca.pem || result=$?
[ "$result" = 1 ] || { echo 'FAIL checker missed real password ACL defect'; exit 1; }
echo 'ALL PASS: real TLS identity visibility and stable-CSN password defect'

