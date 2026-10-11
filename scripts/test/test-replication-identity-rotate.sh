#!/usr/bin/env bash
# Live test for scripts/replication-identity.sh rotate (docs/changes/replication-identity, #352,
# T-013 / AC-005). Two real slapd nodes replicate over verified TLS: admin -> prepare -> ensure ->
# dedicated, then the credential is rotated R0-R4 with the consumers restarted by hand in between.
# Nothing is mocked except three throwaway ldapmodify shims that inject a failure on the command's
# own directory write (request lost / response lost / killed mid-write).
#
# Covers: R0 add, closed gate (exit 3) with nothing removed while consumers are old or only
# partly rolled, resume after a lost request and after a SIGKILL (no third value), a lost
# response resolved by directory state, R3 removal only once every node carries the new
# credential, the premature-removal recovery (a direct replace, rc 1 report, reconcile
# re-add, re-run), replication in both directions throughout, and no password in any output.
#
# Usage: scripts/test/test-replication-identity-rotate.sh [image]   (default ldapium:e2e)
# Resources are named ldapium-ridrot-* and only those are removed on exit.
set -euo pipefail
# Never pipe into `grep -q` (SIGPIPE + pipefail): match captured variables.

image="${1:-ldapium:e2e}"
here="$(cd "$(dirname "$0")/.." && pwd)"
timeout_s="${RIDROT_TIMEOUT:-120}"
suffix="$$"
pw="ridrotAdminPw-Zq7Lm2Xv9Kd4Hs8Wt1Bn6Rc3Yf5Ug0Pe"
alicepw="ridrotAlicePw-1"
base="dc=example,dc=org"
admin="cn=admin,${base}"
iddn="cn=replicator,${base}"
net="ldapium-ridrot-net-${suffix}"
n1="ldapium-ridrot-n1-${suffix}"
n2="ldapium-ridrot-n2-${suffix}"
certs="ldapium-ridrot-certs-${suffix}"
peers="ldaps://${n1}:636,ldaps://${n2}:636"
work="$(mktemp -d)"
shimpath="/tmp/shim:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

fail=0
ok() { printf 'PASS: %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: expected '$2', got '$3'"; fi; }
has() { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac; } # needle haystack

reg_containers=("$n1" "$n2")
reg_vols=("${n1}-cfg" "${n1}-data" "${n2}-cfg" "${n2}-data" "$certs")
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
# number of userPassword values on the identity as seen on node $1
vcount() { local o; o="$(asearch "$1" -b "$iddn" -s base -o ldif-wrap=no userPassword)" || { echo "?"; return; }; awk '/^userPassword:/{n++} END {print n+0}' <<<"$o"; }
# rc of an identity bind with password file $2 (inside $1) over verified TLS
idbind() { local x=0; docker exec -e LDAPTLS_CACERT=/certs/ca.pem "$1" ldapwhoami -x -H "ldaps://$1:636" -D "$iddn" -y "$2" >/dev/null 2>&1 || x=$?; echo "$x"; }
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
old="" ; new="" ; new2=""
tools() { # name: operator script and the password files (all lost with every container)
  local f v
  docker cp "${here}/replication-identity.sh" "${1}:/tmp/ri.sh"
  printf '%s' "$pw" | docker exec -i "$1" sh -c 'umask 077; cat > /tmp/admin.pw'
  for f in old new new2; do
    v="${!f}"
    [ -z "$v" ] || printf '%s' "$v" | docker exec -i "$1" sh -c "umask 077; cat > /tmp/${f}.pw"
  done
}
restart_node() { # name mode
  docker rm -f "$1" >/dev/null
  start_node "$1" "$(sid_of "$1")" "$2"
  poll ready "$1" || { bad "$1 (${2}) never ready"; docker logs "$1" 2>&1 | tail -n 20 >&2; exit 1; }
  tools "$1"
}
put_secret() { printf '%s' "$2" | docker run --rm -i --user 0 -v "${certs}:/certs" --entrypoint sh "$image" -c 'cat > "/certs/$1"; chmod 644 "/certs/$1"' sh "$1"; }

# ri <node> <args...>: the operator command inside <node>, listing both nodes
ri() {
  local n="$1"; shift
  docker exec -e LDAPTLS_CACERT=/certs/ca.pem "$n" bash /tmp/ri.sh "$@" --uri "ldaps://${n}:636" --peer "ldaps://${n2}:636" --base "$base" --admin-password-file /tmp/admin.pw
}
ri_shim() { # node args...: same, with the ldapmodify shim in front of PATH
  local n="$1"; shift
  docker exec -e PATH="$shimpath" -e LDAPTLS_CACERT=/certs/ca.pem "$n" bash /tmp/ri.sh "$@" --uri "ldaps://${n}:636" --peer "ldaps://${n2}:636" --base "$base" --admin-password-file /tmp/admin.pw
}
last_out="" ; last_rc=0
run() { last_rc=0; last_out="$("$@" 2>&1)" || last_rc=$?; printf '%s\n' "$last_out" >> "$work/all.out"; }
shim() { # mode: lost-request | lost-response | hang
  local body
  case "$1" in
    lost-request) body='cat >/dev/null; exit 255' ;;
    lost-response) body='/usr/bin/ldapmodify "$@"; exit 255' ;;
    hang) body='/usr/bin/ldapmodify "$@"; sleep 60' ;;
  esac
  printf '#!/bin/sh\n%s\n' "$body" | docker exec -i "$n1" sh -c 'mkdir -p /tmp/shim; cat > /tmp/shim/ldapmodify; chmod +x /tmp/shim/ldapmodify'
}
unshim() { docker exec "$n1" rm -rf /tmp/shim; }

docker network create "$net" >/dev/null
for x in "${reg_vols[@]}"; do docker volume create "$x" >/dev/null; done
docker run --rm --user 0 -v "${certs}:/certs" --entrypoint sh "$image" -c '
set -e
cd /certs
printf "subjectAltName=DNS:%s,DNS:%s,DNS:localhost\n" "$1" "$2" > ext.cnf
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 2 -subj /CN=ridrot-ca
openssl req -newkey rsa:2048 -nodes -keyout k.pem -out s.csr -subj /CN=localhost
openssl x509 -req -in s.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out c.pem -days 2 -extfile ext.cnf
chown -R 999:999 /certs
chmod 600 k.pem ca.key
' sh "$n1" "$n2" >/dev/null 2>&1

echo "== setup: admin -> prepare -> ensure -> dedicated, 2 nodes over verified TLS"
start_node "$n1" 1 admin
poll ready "$n1" || { bad "n1 never ready"; exit 1; }
start_node "$n2" 2 admin
poll ready "$n2" || { bad "n2 never ready"; exit 1; }
add_user "$n1" alice
poll has_uid "$n2" alice || bad "alice never replicated to n2"
for n in "$n1" "$n2"; do restart_node "$n" prepare; done
tools "$n1"
run ri "$n1" ensure --out /tmp/old.pw
check "ensure creates the identity" 0 "$last_rc"
old="$(docker exec "$n1" cat /tmp/old.pw)"
put_secret idold "$old"
poll has_identity "$n2" || bad "identity never replicated to n2"
for n in "$n2" "$n1"; do restart_node "$n" file:idold; done
add_user "$n1" bob
poll has_uid "$n2" bob || bad "dedicated: bob never replicated n1 -> n2"
add_user "$n2" carol
poll has_uid "$n1" carol || bad "dedicated: carol never replicated n2 -> n1"
check "dedicated baseline: writes replicate both ways, no err=49" "0:0" "$(err49 "$n1"):$(err49 "$n2")"

echo "== R0: a lost request writes nothing; the re-run resumes"
shim lost-request
run ri_shim "$n1" rotate --new-password-file /tmp/new.pw
check "lost request: rotate fails" 1 "$last_rc"
check "lost request: still one value, new credential does not bind" "1:49" "$(vcount "$n1"):$(idbind "$n1" /tmp/new.pw)"
unshim
echo "== R0: SIGKILL right after the add; the re-run adds no third value"
shim hang
run docker exec -e PATH="$shimpath" -e LDAPTLS_CACERT=/certs/ca.pem "$n1" timeout -s KILL 8 bash /tmp/ri.sh rotate --new-password-file /tmp/new.pw \
  --uri "ldaps://${n1}:636" --peer "ldaps://${n2}:636" --base "$base" --admin-password-file /tmp/admin.pw
check "killed mid-rotation: exit 137" 137 "$last_rc"
check "killed after the add: two values, new credential binds, old still binds" "2:0:0" "$(vcount "$n1"):$(idbind "$n1" /tmp/new.pw):$(idbind "$n1" /tmp/old.pw)"
unshim
run ri "$n1" rotate --new-password-file /tmp/new.pw
check "resume after the kill: gate closed (consumers old), exit 3" 3 "$last_rc"
check "resume: no third value" 2 "$(vcount "$n1")"
check "resume: the report names the old consumers" 2 "$(grep -c 'consumer credential=old' <<<"$last_out" || true)"
if has 'Rollback until R3' "$last_out"; then ok "resume: rollback guidance is printed"; else bad "resume: rollback guidance missing"; fi
new="$(docker exec "$n1" cat /tmp/new.pw)"
put_secret idnew "$new"
tools "$n1"
add_user "$n1" dave
poll has_uid "$n2" dave || bad "R1: dave never replicated (old consumers still work)"
check "R1: consumers on the old credential keep replicating" 0 "$(err49 "$n2")"

echo "== R2: a partly rolled cluster keeps the old value"
restart_node "$n2" file:idnew
run ri "$n1" rotate --new-password-file /tmp/new.pw
check "partial roll: refuses to remove, exit 3" 3 "$last_rc"
check "partial roll: both values remain" 2 "$(vcount "$n1")"
check "partial roll: n1 old, n2 new" "1:1" "$(grep -c -E "ridrot-n1.*consumer credential=old" <<<"$last_out" || true):$(grep -c -E "ridrot-n2.*consumer credential=new" <<<"$last_out" || true)"
check "partial roll: the old credential still binds" 0 "$(idbind "$n1" /tmp/old.pw)"

echo "== R3: failure injection on the removal, then resume"
restart_node "$n1" file:idnew
shim lost-request
run ri_shim "$n1" rotate --new-password-file /tmp/new.pw
check "gate open, request lost: fails, nothing removed" "1:2" "${last_rc}:$(vcount "$n1")"
shim lost-response
run ri_shim "$n1" rotate --new-password-file /tmp/new.pw
check "gate open, response lost: the directory state decides, exit 0" 0 "$last_rc"
check "removal done once: one value, old no longer binds, new binds" "1:49:0" "$(vcount "$n1"):$(idbind "$n1" /tmp/old.pw):$(idbind "$n1" /tmp/new.pw)"
unshim
run ri "$n1" rotate --new-password-file /tmp/new.pw
check "re-run after completion is a no-op, exit 0" 0 "$last_rc"
# shellcheck disable=SC2317,SC2329 # invoked through poll
one_value() { [ "$(vcount "$1")" = 1 ]; }
if poll one_value "$n2"; then ok "n2 sees one value too"; else bad "n2 still holds $(vcount "$n2") values"; fi
e49="$(err49 "$n1"):$(err49 "$n2")"   # the deliberate old-credential bind above is already counted
add_user "$n1" erin
poll has_uid "$n2" erin || bad "R4: erin never replicated n1 -> n2"
add_user "$n2" frank
poll has_uid "$n1" frank || bad "R4: frank never replicated n2 -> n1"
check "R4: both ways replicate with the new credential, no new err=49" "$e49" "$(err49 "$n1"):$(err49 "$n2")"

echo "== premature removal (AC-005 case 3) and recovery"
run ri "$n1" rotate --new-password-file /tmp/new2.pw
check "second rotation: new file generated, R1, exit 3" 3 "$last_rc"
check "second rotation: file mode is 0600" 600 "$(docker exec "$n1" stat -c %a /tmp/new2.pw)"
new2="$(docker exec "$n1" cat /tmp/new2.pw)"
put_secret idnew2 "$new2"
hash="$(docker exec "$n1" slappasswd -T /tmp/new2.pw)"
docker exec -i "$n1" ldapmodify -x -H ldap://localhost -D "$admin" -w "$pw" >/dev/null <<EOF
dn: ${iddn}
changetype: modify
replace: userPassword
userPassword: ${hash}
EOF
check "direct replace removed the current value early" "1:49" "$(vcount "$n1"):$(idbind "$n1" /tmp/new.pw)"
run ri "$n1" rotate --new-password-file /tmp/new2.pw
check "premature removal is reported, exit 1" 1 "$last_rc"
check "report says the nodes stall with rc 49" 1 "$(grep -c 'premature removal' <<<"$last_out" || true)"
run ri "$n1" reconcile --current-password-file /tmp/new.pw
check "reconcile re-adds the value the consumers still use" "0:2" "${last_rc}:$(vcount "$n1")"
for n in "$n2" "$n1"; do restart_node "$n" file:idnew2; done
run ri "$n1" rotate --new-password-file /tmp/new2.pw
check "second rotation completes" "0:1" "${last_rc}:$(vcount "$n1")"
add_user "$n1" gina
poll has_uid "$n2" gina || bad "after the second rotation: gina never replicated"
check "after the second rotation: only the newest credential binds" "0:49:49" "$(idbind "$n1" /tmp/new2.pw):$(idbind "$n1" /tmp/new.pw):$(idbind "$n1" /tmp/old.pw)"

echo "== refusals"
run ri "$n1" rotate --new-password-file /tmp/admin.pw
check "new credential equal to the administrator password is refused" 1 "$last_rc"
printf '%s' 'short' | docker exec -i "$n1" sh -c 'umask 077; cat > /tmp/short.pw'
run ri "$n1" rotate --new-password-file /tmp/short.pw
check "hygiene failure is refused" 1 "$last_rc"
run docker exec -e LDAPTLS_CACERT=/certs/ca.pem "$n1" bash /tmp/ri.sh rotate --uri "ldap://${n1}:389" --base "$base" --admin-password-file /tmp/admin.pw --new-password-file /tmp/new2.pw
check "clear LDAP is refused" 1 "$last_rc"

echo "== no password in any output or log"
leaks=0
for secret in "$pw" "$old" "$new" "$new2"; do
  c="$(grep -c -F -e "$secret" "$work/all.out" || true)"
  leaks=$((leaks + c))
  for n in "$n1" "$n2"; do
    o="$(docker logs "$n" 2>&1)"
    c="$(grep -c -F -e "$secret" <<<"$o" || true)"
    leaks=$((leaks + c))
  done
done
check "no password in command output or container logs" 0 "$leaks"

if [ "$fail" = 0 ]; then echo 'ALL PASS: real verified TLS rotation R0-R4, closed gate, resume, premature-removal recovery'; else exit 1; fi
