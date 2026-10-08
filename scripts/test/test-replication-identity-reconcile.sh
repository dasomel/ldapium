#!/usr/bin/env bash
# Real TLS slapd: D67 credential addition, repeat, refusal, and old-value preservation.
set -euo pipefail
image="${1:-ldapium:e2e}"
name="ldapium-ridrec-$$"
certs="${name}-certs"
here="$(cd "$(dirname "$0")/.." && pwd)"
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
docker cp "$here/replication-identity.sh" "$name:/tmp/ri.sh"
printf '%s' "$pw" | docker exec -i "$name" sh -c 'umask 077; cat > /tmp/admin.pw'
ri() { docker exec -e LDAPTLS_CACERT=/certs/ca.pem "$name" bash /tmp/ri.sh "$@" --uri ldaps://"$name":636 --base "$base" --admin-password-file /tmp/admin.pw; }
ri ensure --out /tmp/old.pw
current=ridrecCurrentPw-Ab3Cd5Ef7Gh9Ij1Kl2Mn4Op6Qr8St0Uv
printf '%s' "$current" | docker exec -i "$name" sh -c 'umask 077; cat > /tmp/current.pw'
check_rc() { local expected="$1"; shift; local actual=0; "$@" >/dev/null 2>&1 || actual=$?; [ "$actual" = "$expected" ] || { echo "FAIL expected $expected got $actual" >&2; exit 1; }; echo "PASS rc $expected"; }
bind() { docker exec -e LDAPTLS_CACERT=/certs/ca.pem "$name" ldapwhoami -x -H ldaps://"$name":636 -D "$identity" -y "$1"; }
check_rc 49 bind /tmp/current.pw
check_rc 1 ri reconcile --current-password-file /tmp/admin.pw
printf '%s"' "$current" | docker exec -i "$name" sh -c 'cat > /tmp/quote.pw'
check_rc 1 ri reconcile --current-password-file /tmp/quote.pw
ri reconcile --current-password-file /tmp/current.pw
check_rc 0 bind /tmp/current.pw
check_rc 0 bind /tmp/old.pw
count() { docker exec "$name" ldapsearch -x -LLL -H ldap://localhost -D "$admin" -y /tmp/admin.pw -b "$identity" -s base -o ldif-wrap=no userPassword | awk '/^userPassword:/{n++} END {print n+0}'; }
[ "$(count)" = 2 ] || { echo 'FAIL expected two passwords'; exit 1; }
ri reconcile --current-password-file /tmp/current.pw
[ "$(count)" = 2 ] || { echo 'FAIL repeat added password'; exit 1; }
check_rc 1 docker exec "$name" bash /tmp/ri.sh reconcile --uri ldap://localhost --base "$base" --admin-password-file /tmp/admin.pw --current-password-file /tmp/current.pw
check_rc 1 docker exec -e LDAPTLS_REQCERT=never "$name" bash /tmp/ri.sh reconcile --uri ldaps://localhost --base "$base" --admin-password-file /tmp/admin.pw --current-password-file /tmp/current.pw
printf '%s\n' "$current" | docker exec -i "$name" sh -c 'cat > /tmp/newline.pw'
check_rc 1 ri reconcile --current-password-file /tmp/newline.pw
printf '%s\0' "$current" | docker exec -i "$name" sh -c 'cat > /tmp/nul.pw'
check_rc 1 ri reconcile --current-password-file /tmp/nul.pw
printf '%s' "$current" | docker exec -i "$name" sh -c 'cat > /tmp/space.pw; printf " " >> /tmp/space.pw'
check_rc 1 ri reconcile --current-password-file /tmp/space.pw
ri retire --yes
check_rc 1 ri reconcile --current-password-file /tmp/current.pw
echo 'ALL PASS: real verified TLS, add, repeat, old credential, bytes, missing entry'
