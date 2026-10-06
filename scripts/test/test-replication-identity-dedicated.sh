#!/usr/bin/env bash
# Live test for LDAP_REPLICATION_IDENTITY=dedicated (docs/changes/replication-identity,
# #229, T-012). Drives the real entrypoint against real slapd over verified TLS;
# nothing is mocked.
#
# Part 1 (cluster, 3 nodes, throwaway CA, ldaps:// peers): admin cluster -> rolling
#   `prepare` -> the identity entry created BY HAND with the admin DN (the operator
#   `ensure` command is T-013 and does not exist yet) -> nodes switched one by one to
#   `dedicated` (sid 1 last). Asserts: stored olcSyncrepl binds as the identity with
#   tls_reqcert=demand + tls_cacert and never as the admin DN, the providers' BIND
#   log shows the identity (not the admin DN) for the consumers, the password never
#   reaches the logs or /proc/1/environ, writes/password changes/deletes replicate
#   in every direction, the identity cannot write, and a wrong identity password
#   stalls one consumer (err=49) while nothing is written anywhere and the data on
#   the providers is unchanged.
# Part 2 (wipe, E8/E12 style): sid 1 wiped with a WRONG password creates no base DIT
#   and leaves the peers untouched, recovers with the right one (same base
#   entryUUID); sid 2 wiped recovers; sid 1 wiped with every peer down becomes ready
#   at once, creates nothing and recovers when the peers return.
# Part 3 (refusals): every unsafe `dedicated` start exits non-zero with a fixed
#   message, never prints a password and leaves the volume untouched (fresh volumes
#   stay empty, so no `.credentials`; existing volumes keep cn=config and the file
#   listing). Includes stored olcAuthzRegexp (service42 -> identity), olcAuthIDRewrite,
#   olcAuthzPolicy, authzTo, olcTLSVerifyClient=try, a stored rootDN equal to the
#   reserved DN, a misplaced rule and a pre-existing entry; plus the admin rollback.
# Part 4 (only with a base image): `prepare` pair is byte-identical to the base image
#   (cn=config and olcSyncrepl). The admin comparison is test-replication-identity-env.sh.
#
# NOT covered here (later units / package acceptance conditions): the operator
# ensure/rotate/retire/reconcile commands, restore.sh total-loss (D63), Kubernetes
# OrderedReady, rolling credential rotation, the checks (T-014/T-017), the chart.
#
# Usage: scripts/test/test-replication-identity-dedicated.sh [image] [base-image]
#   image defaults to ldapium:e2e. Requires Docker. RIDDED_TIMEOUT (seconds, default
#   120) bounds every wait; RIDDED_ONLY=cluster|refusals|base runs one part.
#   Resources are named ldapium-ridded-* and only those are removed on exit.
set -euo pipefail
# Never pipe into `grep -q` (SIGPIPE + pipefail): match captured variables.

image="${1:-ldapium:e2e}"
base_image="${2:-}"
timeout_s="${RIDDED_TIMEOUT:-120}"
only="${RIDDED_ONLY:-all}"
suffix="$$"
pw="riddedAdminPw-Zq7Lm2Xv9Kd4Hs8Wt1Bn6Rc3Yf5Ug0Pe"
idpw="riddedIdentityPw-Jh6Gf3Dd9Sa2Qw8Er5Ty1Ui4Op7Lk0"
badpw="riddedWrongPw-Xc8Vb2Nm5Qa1Ws4Ed7Rf0Tg3Yh6Uj9"
alicepw="riddedAlicePw-1"
base="dc=example,dc=org"
admin="cn=admin,${base}"
iddn="cn=replicator,${base}"
poldn="cn=replication-policy,${base}"
want_acl="{0}to * by dn.exact=\"${iddn}\" ssf=128 read by dn.exact=\"${iddn}\" none by * break"
net="ldapium-ridded-net-${suffix}"
n1="ldapium-ridded-n1-${suffix}"
n2="ldapium-ridded-n2-${suffix}"
n3="ldapium-ridded-n3-${suffix}"
rv="ldapium-ridded-rv-${suffix}"
certs="ldapium-ridded-certs-${suffix}"
peers="ldaps://${n1}:636,ldaps://${n2}:636,ldaps://${n3}:636"
work="$(mktemp -d)"

fail=0
ok() { printf 'PASS: %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }
# A helper that could not read the system under test records why in $fail_flag (it never prints a
# sentinel that two failed reads could "agree" on); check() stops the whole run at the first one.
fail_flag="$work/helper.fail"
helper_fail() { printf '%s\n' "$*" >> "$fail_flag"; }
check() { # label expected actual
  if [ -s "$fail_flag" ]; then
    bad "${1}: a test helper could not read the system under test: $(head -c 800 "$fail_flag")"
    exit 1
  fi
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: expected '$2', got '$3'"; fi
}
want() { [ "$only" = all ] || [ "$only" = "$1" ]; }

# Every container and volume is registered BEFORE it is created, so the trap
# removes it even when the run is interrupted mid-way.
reg_containers=("$n1" "$n2" "$n3" "$rv")
reg_vols=("${n1}-cfg" "${n1}-data" "${n2}-cfg" "${n2}-data" "${n3}-cfg" "${n3}-data" "${rv}-cfg" "${rv}-data" "$certs")

# shellcheck disable=SC2317,SC2329 # invoked via the trap below
cleanup() {
  local x rc=$?
  trap - EXIT
  if [ -s "$fail_flag" ]; then printf 'FAIL: a test helper could not read the system under test: %s\n' "$(head -c 800 "$fail_flag")" >&2; fi
  for x in "${reg_containers[@]}"; do docker rm -fv "$x" >/dev/null 2>&1 || true; done
  for x in "${reg_vols[@]}"; do docker volume rm -f "$x" >/dev/null 2>&1 || true; done
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -rf "$work"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

poll() { # command... : retry once a second until it succeeds or the deadline passes
  local w=0
  until "$@" >/dev/null 2>&1; do
    sleep 1
    w=$((w + 1))
    [ "$w" -lt "$timeout_s" ] || return 1
  done
}
# shellcheck disable=SC2317,SC2329 # invoked through poll
ready() { docker exec "$1" ldapwhoami -x -H ldap://localhost >/dev/null 2>&1; }
wait_ready() { poll ready "$1"; }
# asearch succeeds only when ldapsearch exited 0 AND printed "result: 0 Success": the empty
# output of a FAILED search must never read as "no such entry" (the default output keeps that result line).
asearch() {
  local n="$1" out rc=0
  shift
  out="$(docker exec "$n" ldapsearch -x -H ldap://localhost -D "$admin" -w "$pw" "$@" 2>&1)" || rc=$?
  [ "$rc" -eq 0 ] || return "$rc"
  case "$out" in
    *$'\nresult: 0 Success'*) ;;
    *) return 1 ;;
  esac
  printf '%s\n' "$out"
}
# shellcheck disable=SC2317,SC2329 # invoked through poll
has_uid() { local o; o="$(asearch "$1" -b "$base" "(uid=$2)" uid 2>/dev/null)" || return 1; [ -n "$(sed -n 's/^uid: //p' <<<"$o")" ]; }
# shellcheck disable=SC2317,SC2329 # invoked through poll
lacks_uid() { local o; o="$(asearch "$1" -b "$base" "(uid=$2)" uid 2>/dev/null)" || return 1; [ -z "$(sed -n 's/^uid: //p' <<<"$o")" ]; }
# shellcheck disable=SC2317,SC2329 # invoked through poll
has_identity() { local o; o="$(asearch "$1" -b "$iddn" -s base cn 2>/dev/null)" || return 1; [ -n "$(sed -n 's/^cn: //p' <<<"$o")" ]; }
# Read helpers: on failure they record the reason (helper_fail) and return 1; they never print a
# value that a second failed read could equal. *_q variants are quiet and are only used inside poll.
uids() {
  local o
  o="$(asearch "$1" -b "$base" '(objectClass=inetOrgPerson)' uid 2>&1)" || { helper_fail "uids $1: search failed: ${o:0:300}"; return 1; }
  sed -n 's/^uid: //p' <<<"$o" | sort | tr '\n' ' '
}
# shellcheck disable=SC2317,SC2329 # invoked through poll
hashof_q() {
  local o h
  o="$(asearch "$1" -b "$base" "(uid=$2)" userPassword 2>/dev/null)" || return 1
  h="$(sed -n 's/^userPassword:: *//p;s/^userPassword: *//p' <<<"$o" | head -n 1)"
  [ -n "$h" ] || return 1
  printf '%s\n' "$h"
}
hashof() { hashof_q "$@" || { helper_fail "hashof $*: search failed or no userPassword returned"; return 1; }; }
# every DN with its entryCSN and password hash as stored on the node: nothing may
# differ before and after a stalled consumer or a refused start
fingerprint() {
  local o
  o="$(docker exec "$1" slapcat -n 1 -o ldif-wrap=no 2>&1)" || { helper_fail "fingerprint $1: slapcat failed: ${o:0:300}"; return 1; }
  [ -n "$o" ] || { helper_fail "fingerprint $1: slapcat returned nothing"; return 1; }
  grep -E '^(dn|entryCSN|userPassword)' <<<"$o" | sort | cksum
}
base_uuid() {
  local o u
  o="$(asearch "$1" -b "$base" -s base entryUUID 2>&1)" || { helper_fail "base_uuid $1: search failed: ${o:0:300}"; return 1; }
  u="$(sed -n 's/^entryUUID: //p' <<<"$o")"
  [ -n "$u" ] || { helper_fail "base_uuid $1: no entryUUID returned"; return 1; }
  printf '%s\n' "$u"
}
# number of entries in the database of a node (an empty database is a successful 0)
entry_count() {
  local o
  o="$(docker exec "$1" slapcat -n 1 2>&1)" || { helper_fail "entry_count $1: slapcat failed: ${o:0:300}"; return 1; }
  grep -c "${2:-^dn:}" <<<"$o" || true
}
# count of lines of cn=config containing a fixed string
cfg_count() {
  local o
  o="$(cfg_dump "$1")" || return 1
  grep -c -F -e "$2" <<<"$o" || true
}
# container log, failing loudly instead of reading as an empty log
dlogs() {
  local o
  o="$(docker logs "$1" 2>&1)" || { helper_fail "dlogs $1: docker logs failed: ${o:0:300}"; return 1; }
  printf '%s\n' "$o"
}
add_user() { # node uid
  docker exec -i "$1" ldapadd -x -H ldap://localhost -D "$admin" -w "$pw" >/dev/null <<EOF
dn: uid=$2,${base}
objectClass: inetOrgPerson
uid: $2
cn: $2
sn: $2
userPassword: ${alicepw}
EOF
}
cfg_dump() {
  local o
  o="$(docker exec "$1" slapcat -n 0 -o ldif-wrap=no 2>&1)" || { helper_fail "cfg_dump $1: slapcat failed: ${o:0:300}"; return 1; }
  [ -n "$o" ] || { helper_fail "cfg_dump $1: slapcat returned nothing"; return 1; }
  printf '%s\n' "$o"
}
acl_list() { local d; d="$(cfg_dump "$1")" || return 1; sed -n '/^dn: olcDatabase={1}mdb,cn=config$/,/^$/p' <<<"$d" | grep '^olcAccess: ' || true; }
syncrepl_list() { local d; d="$(cfg_dump "$1")" || return 1; grep '^olcSyncrepl' <<<"$d" || true; }
norm() { grep -v -E '^(entryCSN|entryUUID|modifyTimestamp|createTimestamp|olcRootPW|userPassword)'; }
nlines() { grep -c . <<<"$1" || true; }
short() { printf '%s' "${1#ldapium-ridded-}" | sed "s/-${suffix}\$//"; }

# start_node <name> <sid> <mode: admin|prepare|dedicated|dedicated-file> [<docker args...>]
# dedicated uses ${ded_pw}; dedicated-file reads it from the certs volume.
ded_pw="$idpw"
start_node() {
  local name="$1" sid="$2" mode="$3"
  shift 3
  local args=()
  case "$mode" in
    admin) ;;
    prepare) args+=(-e LDAP_REPLICATION_IDENTITY=prepare) ;;
    dedicated) args+=(-e LDAP_REPLICATION_IDENTITY=dedicated -e "LDAP_REPLICATION_PASSWORD=${ded_pw}") ;;
    dedicated-file) args+=(-e LDAP_REPLICATION_IDENTITY=dedicated -e LDAP_REPLICATION_PASSWORD_FILE=/certs/idpw) ;;
  esac
  docker run -d --name "$name" --network "$net" --hostname "$name" \
    -v "${name}-cfg:/etc/openldap/slapd.d" -v "${name}-data:/var/lib/openldap/data" \
    -v "${certs}:/certs:ro" -e LDAP_TLS_ENABLED=true -e LDAP_TLS_CERT_FILE=/certs/c.pem \
    -e LDAP_TLS_KEY_FILE=/certs/k.pem -e LDAP_TLS_CA_FILE=/certs/ca.pem \
    -e LDAP_ROOT_DN="$base" -e LDAP_ADMIN_PASSWORD="$pw" \
    -e LDAP_REPLICATION_ENABLED=true -e LDAP_SERVER_ID="$sid" \
    -e LDAP_REPLICATION_PEERS="$peers" ${args[@]+"${args[@]}"} "$@" "$image" >/dev/null
}
sid_of() { case "$1" in "$n1") echo 1 ;; "$n2") echo 2 ;; *) echo 3 ;; esac; }
restart_node() { # name mode
  docker rm -f "$1" >/dev/null
  start_node "$1" "$(sid_of "$1")" "$2"
}
wipe_node() { # name: remove the container and recreate EMPTY config and data volumes
  docker rm -f "$1" >/dev/null
  docker volume rm -f "${1}-cfg" "${1}-data" >/dev/null
  docker volume create "${1}-cfg" >/dev/null
  docker volume create "${1}-data" >/dev/null
}
log_lines() { local o; o="$(dlogs "$1")" || return 1; wc -l <<<"$o" | tr -d ' '; }
new_log() { local o; o="$(dlogs "$1")" || return 1; tail -n +"$(($2 + 1))" <<<"$o"; } # node, lines already seen
err49() { local o; o="$(dlogs "$1")" || return 1; grep -c 'err=49' <<<"$o" || true; }
# BIND records of a log with the client address of their connection
bind_ips() {
  awk '{ for (i = 1; i <= NF; i++) { if ($i ~ /^conn=/) c = $i; if ($i == "ACCEPT" && $(i + 1) == "from") ip[c] = $(i + 2); if ($i == "BIND" && $(i + 1) ~ /^dn=/) print $(i + 1), ip[c] } }'
}

docker network create "$net" >/dev/null
for x in "${reg_vols[@]}"; do docker volume create "$x" >/dev/null; done

# Throwaway CA; one server certificate for every node name (each provider is
# verified by name: tls_reqcert=demand). The identity password sits in the same
# volume for the *_FILE variant. A single-file bind mount is unreadable for uid
# 999 on Colima (AGENTS.md), hence a named volume.
docker run --rm --user 0 -v "${certs}:/certs" --entrypoint sh "$image" -c '
set -e
cd /certs
printf "subjectAltName=DNS:%s,DNS:%s,DNS:%s,DNS:localhost\n" "$1" "$2" "$3" > ext.cnf
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 2 -subj /CN=ridded-ca
openssl req -newkey rsa:2048 -nodes -keyout k.pem -out s.csr -subj /CN=localhost
openssl x509 -req -in s.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out c.pem -days 2 -extfile ext.cnf
printf "%s" "$4" > idpw
printf "%s" "$5" > adminpw
mkfifo fifo
chown -R 999:999 /certs
chmod 600 k.pem ca.key idpw adminpw
chmod 660 fifo
' sh "$n1" "$n2" "$n3" "$idpw" "$pw" >/dev/null 2>&1

# ============================================================================
# Part 1 + 2: cluster and wipe recovery
# ============================================================================
if want cluster; then
  echo "== Part 1: admin -> prepare -> dedicated, 3 nodes over verified TLS"
  start_node "$n1" 1 admin
  wait_ready "$n1" || { bad "n1 (admin) never ready"; exit 1; }
  start_node "$n2" 2 admin
  start_node "$n3" 3 admin
  { wait_ready "$n2" && wait_ready "$n3"; } || { bad "n2/n3 (admin) never ready"; exit 1; }
  add_user "$n1" alice
  add_user "$n1" bob
  for n in "$n2" "$n3"; do poll has_uid "$n" bob || bad "admin cluster: bob never replicated to $(short "$n")"; done
  sl="$(syncrepl_list "$n1")"
  check "admin mode: stored olcSyncrepl binds as the admin DN, no TLS options" "2:2:0" \
    "$(nlines "$sl"):$(grep -c "binddn=\"${admin}\"" <<<"$sl" || true):$(grep -c 'tls_reqcert' <<<"$sl" || true)"

  for n in "$n1" "$n2" "$n3"; do
    restart_node "$n" prepare
    wait_ready "$n" || { bad "$(short "$n") (prepare) never ready"; docker logs "$n" 2>&1 | tail -n 15 >&2; exit 1; }
  done
  for n in "$n1" "$n2" "$n3"; do
    check "prepare: identity rule is the first rule on $(short "$n")" "olcAccess: ${want_acl}" "$(acl_list "$n" | head -n 1)"
  done
  poll has_uid "$n1" bob

  # The operator `ensure` command does not exist yet (T-013): create what the
  # package says it creates, by hand, with the admin DN, as an ordinary replicated write.
  docker exec -i "$n1" ldapadd -x -H ldap://localhost -D "$admin" -w "$pw" >/dev/null <<EOF
dn: ${poldn}
objectClass: device
objectClass: pwdPolicy
cn: replication-policy
pwdAttribute: userPassword
pwdLockout: FALSE
pwdMaxAge: 0
pwdAllowUserChange: FALSE

dn: ${iddn}
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: replicator
userPassword: ${idpw}
pwdPolicySubentry: ${poldn}
EOF
  for n in "$n2" "$n3"; do poll has_identity "$n" || bad "identity entry never replicated to $(short "$n")"; done

  # Rolling switch: sid 2, sid 3, then sid 1 (the node that used to be the provider-only one).
  for n in "$n2" "$n3" "$n1"; do
    mode=dedicated
    [ "$n" = "$n2" ] && mode=dedicated-file
    restart_node "$n" "$mode"
    wait_ready "$n" || { bad "$(short "$n") (${mode}) never ready"; docker logs "$n" 2>&1 | tail -n 20 >&2; exit 1; }
    sl="$(syncrepl_list "$n")"
    check "${mode} $(short "$n"): two olcSyncrepl values, all bound as the identity" "2:2" \
      "$(nlines "$sl"):$(grep -c "binddn=\"${iddn}\"" <<<"$sl" || true)"
    check "${mode} $(short "$n"): no olcSyncrepl value binds as the admin DN" "0" "$(grep -c "binddn=\"${admin}\"" <<<"$sl" || true)"
    check "${mode} $(short "$n"): tls_reqcert=demand and tls_cacert on every value" "2:2" \
      "$(grep -c 'tls_reqcert=demand' <<<"$sl" || true):$(grep -c 'tls_cacert=/certs/ca.pem' <<<"$sl" || true)"
    check "${mode} $(short "$n"): the admin password is nowhere in cn=config" "0" "$(cfg_count "$n" "$pw")"
    nlog="$(dlogs "$n")"
    check "${mode} $(short "$n"): neither password reaches the container log" "0" "$(grep -c -F -e "$pw" -e "$idpw" <<<"$nlog" || true)"
    check "${mode} $(short "$n"): neither password is in /proc/1/environ" "0" \
      "$(docker exec "$n" cat /proc/1/environ | tr '\0' '\n' | grep -c -F -e "$pw" -e "$idpw" || true)"
    check "${mode} $(short "$n"): the identity ACL is still the first rule" "olcAccess: ${want_acl}" "$(acl_list "$n" | head -n 1)"
  done
  nlog="$(dlogs "$n1")"
  # An existing volume skips the bootstrap block altogether: nothing may have been created or probed.
  check "sid 1 dedicated (existing volume): no base DIT load and no peer probe" "0:0" \
    "$(grep -c 'loading base DN' <<<"$nlog" || true):$(grep -c 'checking peers for an existing base DIT' <<<"$nlog" || true)"
  for n in "$n1" "$n2" "$n3"; do
    check "dedicated $(short "$n"): users intact" "alice bob " "$(uids "$n")"
  done

  # Writes in every direction while every consumer binds as the identity.
  add_user "$n1" carol
  add_user "$n2" dave
  add_user "$n3" erin
  for n in "$n1" "$n2" "$n3"; do
    for u in carol dave erin; do poll has_uid "$n" "$u" || bad "dedicated: ${u} never reached $(short "$n")"; done
  done
  docker exec -i "$n3" ldapmodify -x -H ldap://localhost -D "$admin" -w "$pw" >/dev/null <<EOF
dn: uid=alice,${base}
changetype: modify
replace: userPassword
userPassword: ${alicepw}-changed
EOF
  # shellcheck disable=SC2317,SC2329 # invoked through poll
  same_hash() { local a b; a="$(hashof_q "$1" alice)" && b="$(hashof_q "$n3" alice)" && [ "$a" = "$b" ]; }
  for n in "$n1" "$n2"; do poll same_hash "$n" || bad "dedicated: alice's changed hash never reached $(short "$n")"; done
  check "dedicated: the changed password authenticates on a replicated node" "0" \
    "$(rc=0; docker exec "$n1" ldapwhoami -x -H ldap://localhost -D "uid=alice,${base}" -w "${alicepw}-changed" >/dev/null 2>&1 || rc=$?; echo "$rc")"
  docker exec "$n2" ldapdelete -x -H ldap://localhost -D "$admin" -w "$pw" "uid=bob,${base}" >/dev/null
  for n in "$n1" "$n3"; do poll lacks_uid "$n" bob || bad "dedicated: the delete of bob never reached $(short "$n")"; done
  for n in "$n1" "$n2" "$n3"; do check "dedicated: user list converged on $(short "$n")" "alice carol dave erin " "$(uids "$n")"; done
  check "dedicated: every node holds the same hash for every user" "1" \
    "$(for n in "$n1" "$n2" "$n3"; do for u in alice carol dave erin; do hashof "$n" "$u"; done | cksum; done | sort -u | grep -c .)"

  # Providers log the identity for the consumers, never the admin DN from a peer.
  l1="$(log_lines "$n1")"
  l2="$(log_lines "$n2")"
  restart_node "$n3" dedicated
  wait_ready "$n3" || bad "n3 never ready after restart"
  sleep 5
  binds="$( { new_log "$n1" "$l1"; new_log "$n2" "$l2"; } | bind_ips)"
  remote="$(grep -v -e 'IP=127.0.0.1:' -e 'IP=\[::1\]:' <<<"$binds" || true)"
  check "providers log BIND as the identity from the consumer" "yes" "$([ "$(grep -c "dn=\"${iddn}\"" <<<"$remote" || true)" -gt 0 ] && echo yes || echo no)"
  check "providers log no BIND as the admin DN from any other host" "0" "$(grep -c "dn=\"${admin}\"" <<<"$remote" || true)"

  # The identity cannot write (ACL from unit 2), over TLS.
  tlsc() { docker exec -i -e LDAPTLS_CACERT=/certs/ca.pem -e LDAPTLS_REQCERT=never "$n1" "$@"; }
  idrc() { local label="$1" want_rc="$2" rc=0; shift 2; "$@" >/dev/null 2>&1 || rc=$?; check "identity (TLS): ${label}" "$want_rc" "$rc"; }
  check "identity (TLS): reads another user's userPassword hash" "1" \
    "$(tlsc ldapsearch -x -LLL -H ldaps://localhost -D "$iddn" -w "$idpw" -b "$base" '(uid=carol)' userPassword | grep -c '^userPassword' || true)"
  idrc "modify another entry is refused (50)" 50 tlsc ldapmodify -x -H ldaps://localhost -D "$iddn" -w "$idpw" <<EOF
dn: uid=carol,${base}
changetype: modify
replace: description
description: x
EOF
  idrc "add an entry is refused (50)" 50 tlsc ldapadd -x -H ldaps://localhost -D "$iddn" -w "$idpw" <<EOF
dn: uid=evil,${base}
objectClass: inetOrgPerson
uid: evil
cn: evil
sn: evil
EOF
  idrc "delete an entry is refused (50)" 50 tlsc ldapdelete -x -H ldaps://localhost -D "$iddn" -w "$idpw" "uid=carol,${base}"
  idrc "modify itself is refused (50)" 50 tlsc ldapmodify -x -H ldaps://localhost -D "$iddn" -w "$idpw" <<EOF
dn: ${iddn}
changetype: modify
replace: description
description: x
EOF
  idrc "read cn=config is refused (32)" 32 tlsc ldapsearch -x -LLL -H ldaps://localhost -D "$iddn" -w "$idpw" -b cn=config -s base
  check "the refused writes changed nothing (carol still there, no evil)" "carol,absent" \
    "$(has_uid "$n1" carol && echo carol),$(lacks_uid "$n1" evil && echo absent || echo present-or-search-failed)"

  # Wrong identity password on one consumer: it stalls with err=49, nothing is
  # written there or anywhere, the providers' data does not change.
  docker rm -f "$n3" >/dev/null
  add_user "$n1" late
  poll has_uid "$n2" late || bad "late never reached n2"
  fp1="$(fingerprint "$n1")"
  fp2="$(fingerprint "$n2")"
  e1="$(err49 "$n1")"
  e2="$(err49 "$n2")"
  ded_pw="$badpw"
  start_node "$n3" 3 dedicated
  ded_pw="$idpw"
  wait_ready "$n3" || bad "n3 (wrong password) never ready"
  # shellcheck disable=SC2317,SC2329 # invoked through poll
  saw_49() { [ $(($(err49 "$n1") + $(err49 "$n2"))) -gt $((e1 + e2)) ]; }
  if poll saw_49; then ok "wrong identity password: the providers log err=49 for the consumer"; else bad "wrong identity password: no err=49 on the providers"; fi
  sleep 5
  check "wrong identity password: the consumer did not receive the new entry" "absent" "$(lacks_uid "$n3" late && echo absent || echo present-or-search-failed)"
  check "wrong identity password: n1 unchanged (dn, entryCSN, hashes)" "$fp1" "$(fingerprint "$n1")"
  check "wrong identity password: n2 unchanged (dn, entryCSN, hashes)" "$fp2" "$(fingerprint "$n2")"
  restart_node "$n3" dedicated
  wait_ready "$n3" || bad "n3 never ready after the password was fixed"
  if poll has_uid "$n3" late; then ok "right identity password again: the consumer catches up"; else bad "the consumer never caught up after the fix"; fi

  echo "== Part 2: wipe recovery in dedicated mode"
  uuid="$(base_uuid "$n2")"
  [ -n "$uuid" ] || bad "no base entryUUID read from n2"
  all_users="alice carol dave erin late "
  # (a) sid 1 wiped, WRONG password: no new DIT, peers untouched
  fp2="$(fingerprint "$n2")"
  fp3="$(fingerprint "$n3")"
  e2="$(err49 "$n2")"
  wipe_node "$n1"
  ded_pw="$badpw"
  start_node "$n1" 1 dedicated
  ded_pw="$idpw"
  wait_ready "$n1" || { bad "wiped n1 (wrong password) never ready"; docker logs "$n1" 2>&1 | tail -n 15 >&2; exit 1; }
  # shellcheck disable=SC2317,SC2329 # invoked through poll
  saw_49_n2() { [ "$(err49 "$n2")" -gt "$e2" ]; }
  if poll saw_49_n2; then ok "wiped sid 1, wrong password: rejected with err=49"; else bad "wiped sid 1, wrong password: no err=49 on n2"; fi
  sleep 5
  check "wiped sid 1, wrong password: no base DIT and no entry was created" "0" "$(entry_count "$n1")"
  check "wiped sid 1, wrong password: n2 data unchanged" "$fp2" "$(fingerprint "$n2")"
  check "wiped sid 1, wrong password: n3 data unchanged" "$fp3" "$(fingerprint "$n3")"
  check "wiped sid 1, wrong password: n2 still has every user" "$all_users" "$(uids "$n2")"
  # (b) right password: everything comes back, same base entryUUID
  restart_node "$n1" dedicated
  wait_ready "$n1" || bad "n1 never ready after the password was fixed"
  for u in alice carol dave erin late; do poll has_uid "$n1" "$u" || bad "wiped sid 1 recovery: ${u} never came back"; done
  check "wiped sid 1 recovered: user list" "$all_users" "$(uids "$n1")"
  check "wiped sid 1 recovered: hashes equal the peer's" "$(hashof "$n2" alice)" "$(hashof "$n1" alice)"
  check "wiped sid 1 recovered: base entryUUID unchanged" "$uuid" "$(base_uuid "$n1")"
  if poll has_identity "$n1"; then ok "wiped sid 1 recovered: the identity entry replicated back"; else bad "wiped sid 1: identity entry missing"; fi
  check "wiped sid 1 recovered: identity ACL installed on the fresh config" "olcAccess: ${want_acl}" "$(acl_list "$n1" | head -n 1)"
  # (d) sid 2 wiped, right password
  wipe_node "$n2"
  start_node "$n2" 2 dedicated
  wait_ready "$n2" || bad "wiped n2 never ready"
  for u in alice carol dave erin late; do poll has_uid "$n2" "$u" || bad "wiped sid 2 recovery: ${u} never came back"; done
  check "wiped sid 2 recovered: user list" "$all_users" "$(uids "$n2")"
  check "wiped sid 2 recovered: base entryUUID unchanged" "$uuid" "$(base_uuid "$n2")"
  # (c) sid 1 wiped while every peer is down: ready at once, creates nothing, recovers when they return
  docker rm -f "$n2" "$n3" >/dev/null
  wipe_node "$n1"
  t0="$(date +%s)"
  start_node "$n1" 1 dedicated
  wait_ready "$n1" || bad "wiped n1 with peers down never ready"
  elapsed=$(($(date +%s) - t0))
  if [ "$elapsed" -le 30 ]; then ok "sid 1 wiped with every peer down: ready in ${elapsed}s (no peer wait)"; else bad "sid 1 wiped with every peer down: took ${elapsed}s to be ready"; fi
  sleep 3
  check "sid 1 wiped with every peer down: nothing was created" "0" "$(entry_count "$n1")"
  nlog="$(dlogs "$n1")"
  check "sid 1 wiped with every peer down: bootstrap logs the consumer-only decision, no peer probe, no base DIT load" "1:0:0" \
    "$(grep -c 'not creating the base DIT on any node (serverID 1)' <<<"$nlog" || true):$(grep -c 'checking peers' <<<"$nlog" || true):$(grep -c 'loading base DN' <<<"$nlog" || true)"
  start_node "$n2" 2 dedicated
  start_node "$n3" 3 dedicated
  for u in alice carol dave erin late; do poll has_uid "$n1" "$u" || bad "peers back: ${u} never reached the empty sid 1"; done
  check "peers back: sid 1 recovered the user list" "$all_users" "$(uids "$n1")"
  check "peers back: base entryUUID unchanged" "$uuid" "$(base_uuid "$n1")"
  docker rm -fv "$n1" "$n2" "$n3" >/dev/null
fi

# ============================================================================
# Part 3: refusals
# ============================================================================
if want refusals; then
  echo "== Part 3: refusals"
  # fresh_refuse <label> <message fragment> <docker args...>: a fresh volume pair must stay empty.
  common=(-e LDAP_ROOT_DN="$base" -e LDAP_ADMIN_PASSWORD="$pw" -e LDAP_REPLICATION_ENABLED=true -e LDAP_SERVER_ID=2 -e LDAP_REPLICATION_IDENTITY=dedicated)
  peers_ok=(-e LDAP_REPLICATION_PEERS="$peers")
  rpw=(-e "LDAP_REPLICATION_PASSWORD=${idpw}")
  tlsok=(-v "${certs}:/certs:ro" -e LDAP_TLS_ENABLED=true -e LDAP_TLS_CERT_FILE=/certs/c.pem -e LDAP_TLS_KEY_FILE=/certs/k.pem -e LDAP_TLS_CA_FILE=/certs/ca.pem)
  tls_noca=(-v "${certs}:/certs:ro" -e LDAP_TLS_ENABLED=true -e LDAP_TLS_CERT_FILE=/certs/c.pem -e LDAP_TLS_KEY_FILE=/certs/k.pem)
  peermsg="requires LDAP_REPLICATION_PEERS to be a comma-separated list of exactly ldaps://<host>[:<port>] entries"
  fcount=0
  fresh_refuse() {
    local label="$1" want_msg="$2" out rc w=0 state name listing
    shift 2
    fcount=$((fcount + 1))
    name="ldapium-ridded-f${fcount}-${suffix}"
    reg_containers+=("$name")
    reg_vols+=("${name}-cfg" "${name}-data")
    docker volume create "${name}-cfg" >/dev/null
    docker volume create "${name}-data" >/dev/null
    docker run -d --name "$name" --network "$net" -v "${name}-cfg:/etc/openldap/slapd.d" -v "${name}-data:/var/lib/openldap/data" \
      "${common[@]}" "$@" "$image" >/dev/null
    while [ "$w" -lt "$timeout_s" ]; do
      state="$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null || echo gone)"
      [ "$state" = "false" ] && break
      sleep 1
      w=$((w + 1))
    done
    if [ "$state" != "false" ]; then bad "${label}: still running after ${timeout_s}s, expected a refusal"; docker rm -fv "$name" >/dev/null 2>&1 || true; return; fi
    rc="$(docker inspect -f '{{.State.ExitCode}}' "$name")"
    out="$(dlogs "$name")"
    listing="$(docker run --rm --entrypoint ls -v "${name}-cfg:/c" -v "${name}-data:/d" "$image" -A /c /d 2>&1 | tr '\n' ' ')"
    docker rm -fv "$name" >/dev/null 2>&1 || true
    docker volume rm -f "${name}-cfg" "${name}-data" >/dev/null 2>&1 || true
    if [ "$rc" -eq 0 ]; then bad "${label}: exited 0, expected a refusal"; return; fi
    if [[ "$out" != *"$want_msg"* ]]; then bad "${label}: message missing '${want_msg}'; got: $(printf '%s' "$out" | tail -n 2)"; return; fi
    if [[ "$out" == *"$idpw"* || "$out" == *"$pw"* ]]; then bad "${label}: a password leaked into the output"; return; fi
    check "${label}: refused, volumes untouched (no .credentials, no marker)" "/c: /d: " "$(printf '%s' "$listing" | tr -s ' ')"
  }
  fresh_refuse "no replication password" "requires an explicit LDAP_REPLICATION_PASSWORD" "${peers_ok[@]}" "${tlsok[@]}"
  fresh_refuse "password equal to the admin password" "must differ from the admin password" "${peers_ok[@]}" "${tlsok[@]}" -e "LDAP_REPLICATION_PASSWORD=${pw}"
  fresh_refuse "31-character password" "length must be at least 32" "${peers_ok[@]}" "${tlsok[@]}" -e "LDAP_REPLICATION_PASSWORD=${idpw:0:31}"
  fresh_refuse "repeated-character password" "at least 10 distinct characters" "${peers_ok[@]}" "${tlsok[@]}" -e "LDAP_REPLICATION_PASSWORD=abababababababababababababababab"
  fresh_refuse "TLS not enabled" "requires LDAP_TLS_ENABLED=true" "${peers_ok[@]}" "${rpw[@]}"
  fresh_refuse "TLS enabled without a CA file" "requires LDAP_TLS_CA_FILE" "${peers_ok[@]}" "${rpw[@]}" "${tls_noca[@]}"
  fresh_refuse "unreadable CA file" "requires a readable LDAP_TLS_CA_FILE" "${peers_ok[@]}" "${rpw[@]}" "${tlsok[@]}" -e LDAP_TLS_CA_FILE=/certs/missing.pem
  fresh_refuse "plaintext peer" "$peermsg" "${rpw[@]}" "${tlsok[@]}" \
    -e "LDAP_REPLICATION_PEERS=ldaps://${n1}:636,ldap://${n2}:389"
  fresh_refuse "mutual TLS" "cannot be combined with LDAP_TLS_MUTUAL_AUTH" "${peers_ok[@]}" "${rpw[@]}" "${tlsok[@]}" -e LDAP_TLS_MUTUAL_AUTH=true
  fresh_refuse "custom bind DN next to the identity" "binds as the reserved replication identity" "${peers_ok[@]}" "${rpw[@]}" "${tlsok[@]}" -e "LDAP_REPLICATION_BIND_DN=cn=other,${base}"
  fresh_refuse "bind DN equal to the reserved DN" "LDAP_REPLICATION_BIND_DN must not equal" "${peers_ok[@]}" "${rpw[@]}" "${tlsok[@]}" -e "LDAP_REPLICATION_BIND_DN=CN=Replicator,${base}"
  fresh_refuse "admin DN equal to the reserved DN" "must not equal the reserved replication identity DN" "${peers_ok[@]}" "${rpw[@]}" "${tlsok[@]}" -e "LDAP_ADMIN_DN=cn=replicator, ${base}"
  fresh_refuse "quoted root DN" "without double quotes or backslashes" "${peers_ok[@]}" "${rpw[@]}" "${tlsok[@]}" -e 'LDAP_ROOT_DN=dc=a"b,dc=org'
  fresh_refuse "serverID 1 gets no special treatment: still needs the password" "requires an explicit LDAP_REPLICATION_PASSWORD" "${peers_ok[@]}" "${tlsok[@]}" -e LDAP_SERVER_ID=1

  # Peer grammar: option text smuggled through a peer value (whitespace separates olcSyncrepl
  # options, so `ldaps://h provider=ldap://x:389` would win with a SECOND provider and send the
  # identity's simple bind in clear text). Every variant is refused with the fixed message and
  # a fresh volume stays empty.
  tab=$'\t'
  nlc=$'\n'
  peer_cases=(
    "ldaps://${n2}:636 provider=ldap://${n3}:389"
    "ldaps://${n2}:636${tab}provider=ldap://${n3}:389"
    "ldaps://${n2}:636${nlc}provider=ldap://${n3}:389"
    "ldaps://${n2}:636 starttls=no"
    "ldaps://${n2}:636 bindmethod=simple"
    "ldaps://${n2}:636 binddn=cn=x"
    "ldaps://${n2}:636 credentials=x"
    "ldaps://${n2}:636 tls_reqcert=never"
    "ldaps://${n1}:636, ldaps://${n2}:636"
    "ldaps://${n1}:636 ,ldaps://${n2}:636"
    "ldaps://${n2}:636x"
    "ldaps://${n2}:636/"
    "ldaps://${n2}:636/dc=x"
    "ldaps://${n2}:636?scope=sub"
    "LDAPS://${n2}:636"
    "Ldaps://${n2}:636"
    "ldaps://user@${n2}:636"
    "ldaps://user:pw@${n2}:636"
    "ldaps://${n1}:636,,ldaps://${n2}:636"
    "ldaps://${n1}:636,"
    ",ldaps://${n1}:636"
    "ldaps://"
    "ldaps://:636"
    "ldaps://${n2}:0"
    "ldaps://${n2}:65536"
    "ldaps://${n2}:6x"
    "ldaps://${n2}:"
    "ldaps://${n2}:636:1"
    "ldaps://-${n2}:636"
    "ldaps://${n2}..x:636"
    "ldaps://${n2}\"x:636"
    "ldaps://[::1:636"
    "ldaps://[::1]x"
    "ldaps://[::1]:636x"
    "ldaps://[zz]:636"
    "ldaps://[]:636"
    "ldaps://[127.0.0.1]:636"
    "ldap://${n2}:389"
    "ldapi:///"
  )
  pc=0
  for pcase in "${peer_cases[@]}"; do
    pc=$((pc + 1))
    fresh_refuse "peer grammar #${pc}: $(printf '%s' "$pcase" | tr '\t\n' '~~')" "$peermsg" "${rpw[@]}" "${tlsok[@]}" -e "LDAP_REPLICATION_PEERS=${pcase}"
  done
  fresh_refuse "password with a double quote" "double quotes and backslashes are not allowed" "${peers_ok[@]}" "${tlsok[@]}" -e "LDAP_REPLICATION_PASSWORD=${idpw}\"provider=ldap://x:389"
  fresh_refuse "password with a backslash" "double quotes and backslashes are not allowed" "${peers_ok[@]}" "${tlsok[@]}" -e "LDAP_REPLICATION_PASSWORD=${idpw}\\x"
  retrymsg="requires LDAP_REPLICATION_RETRY to be <interval> <count> pairs"
  intervalmsg="requires LDAP_REPLICATION_INTERVAL in the form dd:hh:mm:ss"
  fresh_refuse "retry with option text" "$retrymsg" "${peers_ok[@]}" "${rpw[@]}" "${tlsok[@]}" -e 'LDAP_REPLICATION_RETRY=5 +" provider=ldap://x:389 x="'
  fresh_refuse "interval with option text" "$intervalmsg" "${peers_ok[@]}" "${rpw[@]}" "${tlsok[@]}" -e 'LDAP_REPLICATION_INTERVAL=00:00:00:10 provider=ldap://x:389'
  # Strict retry grammar: each rejected value was confirmed against slapd itself (offline
  # slapmodify stores it, the next config load fails) or is a deliberately stricter shape.
  retry_bad=('+' '5' '5 10 30' '5 3 +' '5 + 10 3' '05 3' '5 03' '0 3' '5 0' '5  3' ' 5 3' '5 3 ' '5 -3' '5 ++' '5 +3' '1000000 3' '5 10000' 'a b' '5,3')
  for rv_bad in "${retry_bad[@]}"; do
    fresh_refuse "retry '${rv_bad}'" "$retrymsg" "${peers_ok[@]}" "${rpw[@]}" "${tlsok[@]}" -e "LDAP_REPLICATION_RETRY=${rv_bad}"
  done
  interval_bad=('10' '00:10' '00:00:00:00' '00:00:00:60' '00:24:00:00' '00:00:60:00' '0:0:0:10' '00:00:00:1x' '00:00:00:10:00' ' 00:00:00:10' '00:00:00:010')
  for iv_bad in "${interval_bad[@]}"; do
    fresh_refuse "interval '${iv_bad}'" "$intervalmsg" "${peers_ok[@]}" "${rpw[@]}" "${tlsok[@]}" -e "LDAP_REPLICATION_INTERVAL=${iv_bad}"
  done

  # probe_start <docker args...>: a fresh sid-2 dedicated node (peers are not up, so its consumers retry)
  pn=0
  probe_start() {
    pn=$((pn + 1))
    probe_name="ldapium-ridded-p${pn}-${suffix}"
    reg_containers+=("$probe_name")
    reg_vols+=("${probe_name}-cfg" "${probe_name}-data")
    docker volume create "${probe_name}-cfg" >/dev/null
    docker volume create "${probe_name}-data" >/dev/null
    docker run -d --name "$probe_name" --network "$net" --hostname "$probe_name" -v "${probe_name}-cfg:/etc/openldap/slapd.d" -v "${probe_name}-data:/var/lib/openldap/data" \
      "${common[@]}" "${peers_ok[@]}" "${tlsok[@]}" "$@" "$image" >/dev/null
  }
  probe_done() { docker rm -fv "$probe_name" >/dev/null; docker volume rm -f "${probe_name}-cfg" "${probe_name}-data" >/dev/null; }
  # Accepted forms really start slapd and are stored as given.
  retry_ok=('5 +|00:00:00:10' '5 3|01:02:03:04' '1 1 60 +|00:00:01:00' '999999 9999|23:23:59:59')
  for pair in "${retry_ok[@]}"; do
    r_ok="${pair%%|*}"
    i_ok="${pair##*|}"
    probe_start "${rpw[@]}" -e "LDAP_REPLICATION_RETRY=${r_ok}" -e "LDAP_REPLICATION_INTERVAL=${i_ok}"
    if wait_ready "$probe_name"; then ok "retry '${r_ok}' / interval '${i_ok}': node starts"; else bad "retry '${r_ok}' / interval '${i_ok}': never ready"; fi
    psl="$(syncrepl_list "$probe_name")"
    check "retry '${r_ok}' / interval '${i_ok}': stored as given on both values" "2:2" \
      "$(grep -c "retry=\"${r_ok}\"" <<<"$psl" || true):$(grep -c "interval=${i_ok}" <<<"$psl" || true)"
    probe_done
  done

  # Passwords that look like syncrepl options (all allowed by the hygiene rules): the node starts and
  # the stored credentials value equals the password exactly, with exactly one ldaps:// provider
  # outside the quoted values.
  pw_odd=(
    'ValidProviderPw-Ab3Cd4Ef5Gh6provider=Ij7Kl8Mn9'
    'bindmethod=simple-Xy7Zq3Wv9Ut5Rs1Pn8Mk2Jh4'
    'starttls=critical-Xy7Zq3Wv9Ut5Rs1Pn8Mk2Jh4'
    'type=refreshOnly-Xy7Zq3Wv9Ut5Rs1Pn8Mk2Jh4'
    'tls_reqcert=never-Xy7Zq3Wv9Ut5Rs1Pn8Mk2Jh4'
    'a=b=c=d=e=f=g=h=i=j=k=l=m=n=o=p=q=r=s=t='
    "=quote'adjacent\`chars\$HOME;|&<>#!*?{}[]()~%^Aa1Bb2Cc3"
    'provider=ldap://evil:389-Xy7Zq3Wv9Ut5Rs1Pn8Mk2'
  )
  for odd in "${pw_odd[@]}"; do
    probe_start -e "LDAP_REPLICATION_PASSWORD=${odd}"
    if wait_ready "$probe_name"; then ok "password '${odd:0:24}...': node starts"; else bad "password '${odd:0:24}...': never ready"; dlogs "$probe_name" | tail -n 4 >&2 || true; fi
    psl="$(syncrepl_list "$probe_name")"
    creds="$(sed -n 's/.*credentials="\([^"]*\)".*/\1/p' <<<"$psl" | sort -u)"
    check "password '${odd:0:24}...': stored credentials equal the password" "$odd" "$creds"
    # shellcheck disable=SC2001 # a regex over a multi-line value
    noq="$(sed 's/credentials="[^"]*"//g' <<<"$psl")"
    check "password '${odd:0:24}...': two values, each with exactly one ldaps:// provider outside the quoted values" "2:2:0" \
      "$(grep -c . <<<"$noq" || true):$(grep -c -E '^olcSyncrepl: .*provider=ldaps://[^ ]+' <<<"$noq" || true):$(grep -c -E 'provider=.*provider=' <<<"$noq" || true)"
    probe_done
  done

  # A stored retry list that slapd cannot load (an offline slapmodify stores it without checking; every
  # offline tool then fails with "bad configuration directory"): the corrected environment on the SAME
  # volumes recovers the node, a bad environment value on a healthy volume is refused untouched.
  probe_start "${rpw[@]}"
  wait_ready "$probe_name" || bad "recovery: first start never ready"
  docker rm -f "$probe_name" >/dev/null
  printf 'dn: olcDatabase={1}mdb,cn=config\nchangetype: modify\nreplace: olcSyncrepl\nolcSyncrepl: rid=001 provider=ldaps://%s:636 bindmethod=simple binddn="%s" credentials="x" searchbase="%s" type=refreshAndPersist retry="+" interval=00:00:00:10\n' "$n1" "$iddn" "$base" |
    docker run --rm -i -v "${probe_name}-cfg:/etc/openldap/slapd.d" -v "${probe_name}-data:/var/lib/openldap/data" --entrypoint slapmodify "$image" -n 0 -F /etc/openldap/slapd.d >/dev/null
  rc_pre=0
  docker run --rm -v "${probe_name}-cfg:/etc/openldap/slapd.d" -v "${probe_name}-data:/var/lib/openldap/data" --entrypoint slapcat "$image" -n 0 -F /etc/openldap/slapd.d >/dev/null 2>&1 || rc_pre=$?
  if [ "$rc_pre" -ne 0 ]; then ok "recovery precondition: the stored retry list makes cn=config unloadable (slapcat rc ${rc_pre})"; else bad "recovery precondition: cn=config still loads with retry=+"; fi
  docker run -d --name "$probe_name" --network "$net" --hostname "$probe_name" -v "${probe_name}-cfg:/etc/openldap/slapd.d" -v "${probe_name}-data:/var/lib/openldap/data" \
    "${common[@]}" "${peers_ok[@]}" "${tlsok[@]}" "${rpw[@]}" "$image" >/dev/null
  if wait_ready "$probe_name"; then ok "recovery: the corrected environment on the same volumes starts the node"; else bad "recovery: node still down"; dlogs "$probe_name" | tail -n 5 >&2 || true; fi
  psl="$(syncrepl_list "$probe_name")"
  check "recovery: olcSyncrepl re-rendered from the environment (two values, identity bind, default retry)" "2:2:2" \
    "$(grep -c . <<<"$psl" || true):$(grep -c "binddn=\"${iddn}\"" <<<"$psl" || true):$(grep -c 'retry="5 10 30 +"' <<<"$psl" || true)"
  check "recovery: the start logged the removal of the unreadable stored values" "1" "$(dlogs "$probe_name" | grep -c 'removing the stored olcSyncrepl' || true)"
  probe_done

  # The reproduced input, against a plain-LDAP decoy that logs every connection: the node must
  # be refused and the decoy must never see a connection (no plaintext attempt on 389).
  decoy="ldapium-ridded-decoy-${suffix}"
  reg_containers+=("$decoy")
  reg_vols+=("${decoy}-cfg" "${decoy}-data")
  docker volume create "${decoy}-cfg" >/dev/null
  docker volume create "${decoy}-data" >/dev/null
  docker run -d --name "$decoy" --network "$net" --hostname "$decoy" -v "${decoy}-cfg:/etc/openldap/slapd.d" -v "${decoy}-data:/var/lib/openldap/data" \
    -e LDAP_ROOT_DN="$base" -e LDAP_ADMIN_PASSWORD="$pw" "$image" >/dev/null
  wait_ready "$decoy" || bad "decoy never ready"
  decoy_hits() { local o; o="$(dlogs "$decoy")" || return 1; grep 'ACCEPT from IP=' <<<"$o" | grep -c -v -e 'IP=127.0.0.1:' -e 'IP=\[::1\]:' || true; }
  check "decoy: no remote connection before the test" "0" "$(decoy_hits)"
  inj="ldaps://${n2}:636 provider=ldap://${decoy}:389"
  iname="ldapium-ridded-inj-${suffix}"
  reg_containers+=("$iname")
  reg_vols+=("${iname}-cfg" "${iname}-data")
  docker volume create "${iname}-cfg" >/dev/null
  docker volume create "${iname}-data" >/dev/null
  docker run -d --name "$iname" --network "$net" --hostname "$iname" -v "${iname}-cfg:/etc/openldap/slapd.d" -v "${iname}-data:/var/lib/openldap/data" \
    "${common[@]}" "${rpw[@]}" "${tlsok[@]}" -e "LDAP_REPLICATION_PEERS=${inj},ldaps://${n3}:636" "$image" >/dev/null
  # a vulnerable build keeps running and dials the decoy within its first retry interval
  w=0
  while [ "$w" -lt 25 ]; do
    [ "$(docker inspect -f '{{.State.Running}}' "$iname" 2>/dev/null || echo gone)" = "false" ] && break
    sleep 1
    w=$((w + 1))
  done
  check "reproduced injection: node refused (not running)" "false" "$(docker inspect -f '{{.State.Running}}' "$iname" 2>/dev/null || echo gone)"
  injout="$(dlogs "$iname")"
  if [[ "$injout" == *"$peermsg"* ]]; then ok "reproduced injection: fixed refusal message"; else bad "reproduced injection: message missing; got: $(printf '%s' "$injout" | tail -n 2)"; fi
  sleep 8
  check "reproduced injection: the decoy never saw a plaintext connection on 389" "0" "$(decoy_hits)"
  docker rm -fv "$iname" "$decoy" >/dev/null

  # Valid forms are accepted (no peer is reachable, which only keeps the consumers retrying).
  vname="ldapium-ridded-valid-${suffix}"
  reg_containers+=("$vname")
  reg_vols+=("${vname}-cfg" "${vname}-data")
  docker volume create "${vname}-cfg" >/dev/null
  docker volume create "${vname}-data" >/dev/null
  docker run -d --name "$vname" --network "$net" --hostname "$vname" -v "${vname}-cfg:/etc/openldap/slapd.d" -v "${vname}-data:/var/lib/openldap/data" \
    "${common[@]}" -e LDAP_SERVER_ID=4 "${rpw[@]}" "${tlsok[@]}" \
    -e 'LDAP_REPLICATION_PEERS=ldaps://[::1]:636,ldaps://10.0.0.1,ldaps://a-b.example.test:1,ldaps://x:65535,ldaps://self.test' "$image" >/dev/null
  if wait_ready "$vname"; then ok "valid peer forms (IPv6 literal, IPv4, no port, port 1 and 65535) are accepted"; else bad "valid peer forms refused"; docker logs "$vname" 2>&1 | tail -n 4 >&2; fi
  vsl="$(syncrepl_list "$vname")"
  check "valid peer forms: four values, each with exactly one ldaps:// provider" "4:4" \
    "$(nlines "$vsl"):$(grep -c -E 'provider=ldaps://[^ ]+ ' <<<"$vsl" || true)"
  docker rm -fv "$vname" >/dev/null

  # The secret file is read ONCE. A FIFO serves the identity password on the first read and an
  # EMPTY second read: a build that reads again would fall back to (and store) the admin password.
  fw="ldapium-ridded-fw-${suffix}"
  reg_containers+=("$fw")
  fv="ldapium-ridded-fv-${suffix}"
  reg_vols+=("${fv}-cfg" "${fv}-data")
  docker volume create "${fv}-cfg" >/dev/null
  docker volume create "${fv}-data" >/dev/null
  docker run -d --name "$fw" -v "${certs}:/certs" -e PW="$idpw" --entrypoint sh "$image" -c 'while true; do printf "%s" "$PW" > /certs/fifo; sleep 3; : > /certs/fifo; sleep 3; done' >/dev/null
  fvn="ldapium-ridded-fvn-${suffix}"
  reg_containers+=("$fvn")
  docker run -d --name "$fvn" --network "$net" --hostname "$fvn" -v "${fv}-cfg:/etc/openldap/slapd.d" -v "${fv}-data:/var/lib/openldap/data" \
    "${common[@]}" "${peers_ok[@]}" "${tlsok[@]}" -e LDAP_REPLICATION_PASSWORD_FILE=/certs/fifo "$image" >/dev/null
  if wait_ready "$fvn"; then ok "FIFO password file (first read valid, second read empty): node starts"; else bad "FIFO node never ready"; docker logs "$fvn" 2>&1 | tail -n 5 >&2; fi
  check "FIFO password file: stored credentials are the identity password, the admin password was never substituted" "2:0" \
    "$(cfg_count "$fvn" "$idpw"):$(cfg_count "$fvn" "$pw")"
  docker rm -fv "$fvn" "$fw" >/dev/null
  # a file holding the ADMIN password is refused (single read, validated value)
  fresh_refuse "password file holding the admin password" "must differ from the admin password" "${peers_ok[@]}" "${tlsok[@]}" -e LDAP_REPLICATION_PASSWORD_FILE=/certs/adminpw

  # Existing volume: a clean admin-mode sid 1 volume, then the stored conditions are
  # introduced offline one by one; cn=config and the file listing must not change.
  off() { docker run --rm -i -v "${rv}-cfg:/etc/openldap/slapd.d" -v "${rv}-data:/var/lib/openldap/data" --entrypoint "$1" "$image" "${@:2}"; }
  rv_peers="ldaps://${rv}:636,ldaps://${rv}-peer:636"
  rv_args=(--name "$rv" --network "$net" --hostname "$rv" -v "${rv}-cfg:/etc/openldap/slapd.d" -v "${rv}-data:/var/lib/openldap/data"
    -e LDAP_ROOT_DN="$base" -e LDAP_ADMIN_PASSWORD="$pw" -e LDAP_REPLICATION_ENABLED=true -e LDAP_SERVER_ID=1 -e "LDAP_REPLICATION_PEERS=${rv_peers}")
  rv_ded=(-e LDAP_REPLICATION_IDENTITY=dedicated -e "LDAP_REPLICATION_PASSWORD=${idpw}" "${tlsok[@]}")
  docker run -d "${rv_args[@]}" "$image" >/dev/null
  wait_ready "$rv" || { bad "refusal volume never ready"; exit 1; }
  docker rm -f "$rv" >/dev/null
  rv_cfg() { off slapcat -n 0 -F /etc/openldap/slapd.d -o ldif-wrap=no; }
  # Every file's size, mtime, mode and content hash. lock.mdb is excluded: the read-only
  # slapcat -n 1 behind the authzTo/entry checks rewrites that lock file (not data).
  rv_files() { docker run --rm --entrypoint sh -v "${rv}-cfg:/c" -v "${rv}-data:/d" "$image" -c 'find /c /d -type f ! -name lock.mdb -exec stat -c "%n %s %Y %a" {} + | sort; find /c /d -type f ! -name lock.mdb -exec sha256sum {} + | sort'; }
  mod_cfg() { off slapmodify -n 0 -F /etc/openldap/slapd.d >/dev/null; }
  mod_db() { off slapmodify -n 1 -F /etc/openldap/slapd.d >/dev/null; }
  refuse_stored() {
    local label="$1" want_msg="$2" cb ca fb fa out rc w=0 state
    cb="$(rv_cfg)"
    fb="$(rv_files)"
    if [ -z "$cb" ] || [ -z "$fb" ]; then bad "${label}: could not read cn=config or the file listing before the start"; return; fi
    docker run -d "${rv_args[@]}" "${rv_ded[@]}" "$image" >/dev/null
    while [ "$w" -lt "$timeout_s" ]; do
      state="$(docker inspect -f '{{.State.Running}}' "$rv" 2>/dev/null || echo gone)"
      [ "$state" = "false" ] && break
      sleep 1
      w=$((w + 1))
    done
    if [ "$state" != "false" ]; then bad "${label}: still running after ${timeout_s}s, expected a refusal"; docker rm -fv "$rv" >/dev/null 2>&1 || true; return; fi
    rc="$(docker inspect -f '{{.State.ExitCode}}' "$rv")"
    out="$(dlogs "$rv")"
    docker rm -f "$rv" >/dev/null
    ca="$(rv_cfg)"
    fa="$(rv_files)"
    if [ -z "$ca" ] || [ -z "$fa" ]; then bad "${label}: could not read cn=config or the file listing after the refusal"; return; fi
    if [ "$rc" -eq 0 ]; then bad "${label}: exited 0, expected a refusal"; return; fi
    if [[ "$out" != *"$want_msg"* ]]; then bad "${label}: message missing '${want_msg}'; got: $(printf '%s' "$out" | tail -n 2)"; return; fi
    if [[ "$out" == *"$idpw"* || "$out" == *"$pw"* ]]; then bad "${label}: a password leaked into the output"; return; fi
    if [ "$cb" != "$ca" ]; then bad "${label}: cn=config changed"; return; fi
    if [[ "$ca" == *"olcAccess: ${want_acl}"* ]]; then bad "${label}: the identity rule was stored despite the refusal"; return; fi
    if [[ "$ca" == *tls_reqcert* ]]; then bad "${label}: dedicated olcSyncrepl was rendered despite the refusal"; return; fi
    check "${label}: refused; cn=config, data and every file (size, mtime, mode, hash) unchanged" "$fb" "$fa"
  }
  mod_db <<EOF
dn: uid=proxy,${base}
changetype: add
objectClass: inetOrgPerson
objectClass: extensibleObject
uid: proxy
cn: proxy
sn: proxy
authzTo: dn:${iddn}
EOF
  refuse_stored "entry with authzTo" "an entry carries authzTo/authzFrom"
  mod_db <<EOF
dn: uid=proxy,${base}
changetype: delete
EOF
  mod_cfg <<EOF
dn: cn=config
changetype: modify
replace: olcAuthzPolicy
olcAuthzPolicy: to
EOF
  refuse_stored "olcAuthzPolicy=to" "olcAuthzPolicy is not 'none'"
  mod_cfg <<EOF
dn: cn=config
changetype: modify
delete: olcAuthzPolicy
EOF
  mod_cfg <<EOF
dn: cn=config
changetype: modify
add: olcAuthzRegexp
olcAuthzRegexp: {0}^cn=service42\$ ${iddn}
EOF
  refuse_stored "olcAuthzRegexp service42 -> identity" "olcAuthzRegexp is stored"
  mod_cfg <<EOF
dn: cn=config
changetype: modify
delete: olcAuthzRegexp
EOF
  mod_cfg <<EOF
dn: cn=config
changetype: modify
add: olcAuthIDRewrite
olcAuthIDRewrite: {0}rewriteRule "^(.*)\$" "uid=\$1,${base}" ":@"
EOF
  refuse_stored "olcAuthIDRewrite" "olcAuthIDRewrite is stored"
  mod_cfg <<EOF
dn: cn=config
changetype: modify
delete: olcAuthIDRewrite
EOF
  mod_cfg <<EOF
dn: cn=config
changetype: modify
replace: olcTLSVerifyClient
olcTLSVerifyClient: try
EOF
  refuse_stored "olcTLSVerifyClient=try" "olcTLSVerifyClient is not 'never'"
  mod_cfg <<EOF
dn: cn=config
changetype: modify
delete: olcTLSVerifyClient
EOF
  mod_cfg <<EOF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcRootDN
olcRootDN: CN=Replicator, ${base}
EOF
  refuse_stored "stored olcRootDN equal to the reserved DN (case/space variant)" "is a stored olcRootDN"
  mod_cfg <<EOF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcRootDN
olcRootDN: cn=replic\\61tor,dc=example,dc=org
EOF
  refuse_stored "stored olcRootDN equal to the reserved DN (hex escape)" "is a stored olcRootDN"
  mod_cfg <<EOF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcRootDN
olcRootDN: ${admin}
EOF
  mod_cfg <<EOF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
add: olcAccess
olcAccess: {3}to attrs=description by dn.exact="${iddn}" read
EOF
  refuse_stored "a rule for the identity that is not the first rule" "is not the first olcAccess rule"
  mod_cfg <<EOF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
delete: olcAccess
olcAccess: {3}to attrs=description by dn.exact="${iddn}" read
EOF
  mod_db <<EOF
dn: ${iddn}
changetype: add
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: replicator
userPassword: ${idpw}
EOF
  refuse_stored "entry at the reserved DN without the ACL" "already exists on this node but the identity ACL is not installed"
  mod_db <<EOF
dn: ${iddn}
changetype: delete
EOF
  # The same volume, now clean: dedicated installs the rule and starts as a consumer (no peers are up).
  docker run -d "${rv_args[@]}" "${rv_ded[@]}" "$image" >/dev/null
  if wait_ready "$rv"; then ok "clean volume: dedicated starts"; else bad "clean volume: dedicated never ready"; docker logs "$rv" 2>&1 | tail -n 10 >&2; fi
  check "clean volume: identity rule is the first rule" "olcAccess: ${want_acl}" "$(acl_list "$rv" | head -n 1)"
  check "clean volume: the base DIT entry of the existing volume is intact" "1" "$(entry_count "$rv" "^dn: ${base}\$")"
  sl="$(syncrepl_list "$rv")"
  check "clean volume: syncrepl binds as the identity over verified TLS" "1:1" \
    "$(grep -c "binddn=\"${iddn}\"" <<<"$sl" || true):$(grep -c 'tls_reqcert=demand tls_cacert=/certs/ca.pem' <<<"$sl" || true)"
  docker rm -f "$rv" >/dev/null
  # prepare refuses to follow dedicated (its stored syncrepl bind DN is the identity): roll back through admin.
  cb="$(rv_cfg)"
  docker run -d "${rv_args[@]}" -e LDAP_REPLICATION_IDENTITY=prepare "$image" >/dev/null
  w=0
  until [ "$(docker inspect -f '{{.State.Running}}' "$rv" 2>/dev/null || echo gone)" = "false" ] || [ "$w" -ge "$timeout_s" ]; do sleep 1; w=$((w + 1)); done
  out="$(dlogs "$rv")"
  docker rm -f "$rv" >/dev/null
  if [[ "$out" == *"is a stored olcRootDN or replication bind DN"* ]]; then ok "prepare after dedicated is refused (documented: roll back through admin)"; else bad "prepare after dedicated was not refused"; fi
  check "prepare after dedicated: cn=config unchanged" "$cb" "$(rv_cfg)"
  docker run -d "${rv_args[@]}" "$image" >/dev/null
  wait_ready "$rv" || bad "admin rollback never ready"
  rb="$(syncrepl_list "$rv")"
  check "admin rollback: olcSyncrepl binds as the admin DN again, without TLS options" "1:0" \
    "$(grep -c "binddn=\"${admin}\"" <<<"$rb" || true):$(grep -c 'tls_reqcert' <<<"$rb" || true)"
  docker rm -fv "$rv" >/dev/null
fi

# ============================================================================
# Part 4: prepare byte-identical to the base image
# ============================================================================
if want base; then
  if [ -n "$base_image" ]; then
    echo "== Part 4: prepare pair vs base image"
    dump() { cfg_dump "$1" | norm >"$2.cfg"; grep '^olcSyncrepl' "$2.cfg" >"$2.syncrepl" || true; }
    run_prepare_pair() { # label image
      local label="$1" img="$2" n sid
      local pp="ldap://${n1}:389,ldap://${n2}:389"
      for n in "$n1" "$n2"; do
        docker volume rm -f "${n}-cfg" "${n}-data" >/dev/null
        docker volume create "${n}-cfg" >/dev/null
        docker volume create "${n}-data" >/dev/null
      done
      for n in "$n1" "$n2"; do
        sid=2
        [ "$n" = "$n1" ] && sid=1
        docker run -d --name "$n" --network "$net" --hostname "$n" -v "${n}-cfg:/etc/openldap/slapd.d" -v "${n}-data:/var/lib/openldap/data" \
          -e LDAP_ROOT_DN="$base" -e LDAP_ADMIN_PASSWORD="$pw" -e LDAP_REPLICATION_ENABLED=true -e LDAP_SERVER_ID="$sid" \
          -e LDAP_REPLICATION_PEERS="$pp" "$img" >/dev/null
        wait_ready "$n" || { bad "${label}: $(short "$n") (admin) never ready"; return 1; }
      done
      for n in "$n1" "$n2"; do
        sid=2
        [ "$n" = "$n1" ] && sid=1
        docker rm -f "$n" >/dev/null
        docker run -d --name "$n" --network "$net" --hostname "$n" -v "${n}-cfg:/etc/openldap/slapd.d" -v "${n}-data:/var/lib/openldap/data" \
          -e LDAP_ROOT_DN="$base" -e LDAP_ADMIN_PASSWORD="$pw" -e LDAP_REPLICATION_ENABLED=true -e LDAP_SERVER_ID="$sid" \
          -e LDAP_REPLICATION_PEERS="$pp" -e LDAP_REPLICATION_IDENTITY=prepare "$img" >/dev/null
        wait_ready "$n" || { bad "${label}: $(short "$n") (prepare) never ready"; return 1; }
      done
      dump "$n1" "${work}/${label}.n1"
      dump "$n2" "${work}/${label}.n2"
      docker rm -fv "$n1" "$n2" >/dev/null
    }
    run_prepare_pair base "$base_image" || exit 1
    run_prepare_pair new "$image" || exit 1
    for part in n1 n2; do
      [ -s "${work}/base.${part}.cfg" ] || bad "${part}: empty base dump"
      if diff -u "${work}/base.${part}.cfg" "${work}/new.${part}.cfg" >"${work}/${part}.diff"; then
        ok "prepare ${part}: cn=config identical to the base image ($(wc -l <"${work}/base.${part}.cfg" | tr -d ' ') lines)"
      else
        bad "prepare ${part}: cn=config differs from the base image"
        head -n 40 "${work}/${part}.diff" >&2
      fi
      [ -s "${work}/base.${part}.syncrepl" ] || bad "${part}: no olcSyncrepl rendered"
      if diff -u "${work}/base.${part}.syncrepl" "${work}/new.${part}.syncrepl" >/dev/null; then
        ok "prepare ${part}: olcSyncrepl identical to the base image"
      else
        bad "prepare ${part}: olcSyncrepl differs from the base image"
      fi
    done
  else
    echo "SKIP: Part 4 (no base image given)"
  fi
fi

if [ "$fail" -eq 0 ]; then
  echo "replication-identity dedicated test passed"
  exit 0
fi
echo "replication-identity dedicated test FAILED" >&2
exit 1
