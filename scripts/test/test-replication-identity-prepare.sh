#!/usr/bin/env bash
# Live test for LDAP_REPLICATION_IDENTITY=prepare (docs/changes/replication-identity,
# #229, T-011). Drives the real entrypoint against real slapd; nothing is mocked.
#
# Part 1 (2-node pair, TLS on node 1): a FRESH serverID-2 volume started with
#   prepare installs the identity ACL as the first olcAccess rule plus olcLimits,
#   verified by reading cn=config back; a second start is a no-op (cn=config
#   unchanged); an EXISTING admin-mode serverID-1 volume restarted with prepare
#   gets the same rule, keeps its data, and replication still works in both
#   directions while syncrepl still binds as the admin DN.
# Part 2 (identity entry absent => harmless): the rules after {0} are exactly the
#   rules before (renumbered) and admin/anonymous/user behaviour is identical
#   before and after prepare, with and without LDAP_ANONYMOUS_READ_BASE.
# Part 3 (identity entry present, simulated by hand with the admin DN): over TLS
#   the identity reads everything including userPassword hashes (package REQ-001)
#   but cannot write, modify, self-modify, delete, add or read cn=config; over
#   plaintext it reads nothing (ssf=128); ordinary users are unaffected.
# Part 4 (refusals, existing admin-mode volume): an entry at the reserved DN
#   without the rule, authzTo/olcAuthzPolicy/olcAuthIDRewrite/olcAuthzRegexp/
#   olcTLSVerifyClient, a stored rootDN equal to the reserved DN, and a misplaced
#   rule each abort with a fixed message and leave cn=config byte-identical;
#   serverID 1 on a fresh volume, mTLS and a quoted root DN are refused before
#   any state change.
#
# Usage: scripts/test/test-replication-identity-prepare.sh [image]
#   image defaults to ldapium:e2e. Requires Docker. RIDPREP_TIMEOUT (seconds,
#   default 120) bounds every wait. Resources are named ldapium-ridprep-* and
#   only those are removed on exit.
set -euo pipefail
# Never pipe into `grep -q` (SIGPIPE + pipefail): match captured variables.

image="${1:-ldapium:e2e}"
timeout_s="${RIDPREP_TIMEOUT:-120}"
suffix="$$"
pw="ridprepAdminPw-Zq7Lm2Xv9Kd4Hs8Wt1Bn6Rc3Yf5Ug0Pe"
idpw="ridprepIdentityPw-Jh6Gf3Dd9Sa2Qw8Er5Ty1Ui4Op7Lk0"
alicepw="ridprepAlicePw-1"
base="dc=example,dc=org"
admin="cn=admin,${base}"
iddn="cn=replicator,${base}"
want_acl="{0}to * by dn.exact=\"${iddn}\" ssf=128 read by dn.exact=\"${iddn}\" none by * break"
want_lim="dn.exact=\"${iddn}\" size=unlimited time=unlimited"
net="ldapium-ridprep-net-${suffix}"
n1="ldapium-ridprep-n1-${suffix}"
n2="ldapium-ridprep-n2-${suffix}"
ab="ldapium-ridprep-anon-${suffix}"
rv="ldapium-ridprep-rv-${suffix}"
certs="ldapium-ridprep-certs-${suffix}"
peers="ldap://${n1}:389,ldap://${n2}:389"
work="$(mktemp -d)"

fail=0
ok() { printf 'PASS: %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }
check() { # label expected actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: expected '$2', got '$3'"; fi
}

# Every container and volume is registered BEFORE it is created, so the trap
# removes it even when the run is interrupted mid-way.
lv="ldapium-ridprep-lv-${suffix}"
xv="ldapium-ridprep-xv-${suffix}"
reg_containers=("$n1" "$n2" "$ab" "$rv" "$lv" "$xv")
reg_vols=("${n1}-cfg" "${n1}-data" "${n2}-cfg" "${n2}-data" "${ab}-cfg" "${ab}-data" "${rv}-cfg" "${rv}-data" "${lv}-cfg" "${lv}-data" "${xv}-cfg" "${xv}-data" "$certs")

# shellcheck disable=SC2317,SC2329 # invoked via the trap below
cleanup() {
  local x
  trap - EXIT
  for x in "${reg_containers[@]}"; do docker rm -fv "$x" >/dev/null 2>&1 || true; done
  for x in "${reg_vols[@]}"; do docker volume rm -f "$x" >/dev/null 2>&1 || true; done
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -rf "$work"
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
# admin ldapsearch on a node; extra args are attributes/filters
asearch() { local n="$1"; shift; docker exec "$n" ldapsearch -x -LLL -H ldap://localhost -D "$admin" -w "$pw" "$@"; }
# shellcheck disable=SC2317,SC2329 # invoked through poll
has_uid() { [ -n "$(asearch "$1" -b "$base" "(uid=$2)" uid 2>/dev/null | sed -n 's/^uid: //p')" ]; }
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
cfg_dump() { docker exec "$1" slapcat -n 0 -o ldif-wrap=no 2>/dev/null; }
acl_list() { cfg_dump "$1" | sed -n '/^dn: olcDatabase={1}mdb,cn=config$/,/^$/p' | grep '^olcAccess: ' || true; }
lim_list() { cfg_dump "$1" | sed -n '/^dn: olcDatabase={1}mdb,cn=config$/,/^$/p' | grep '^olcLimits: ' || true; }
# volatile attributes and secrets removed, as in test-replication-identity-env.sh; the
# restart comparison also sorts lines because slapd rewrites some overlay entries with a
# different attribute order on any restart (admin mode too); the ACL order is asserted separately
norm() { grep -v -E '^(entryCSN|entryUUID|modifyTimestamp|createTimestamp|olcRootPW|userPassword)'; }
strip_idx() { sed -e 's/^\(olc[A-Za-z]*: \){[0-9]*}/\1/'; }

start_node() { # name sid image-env... (extra docker args follow the sid)
  local name="$1" sid="$2"
  shift 2
  docker run -d --name "$name" --network "$net" --hostname "$name" \
    -v "${name}-cfg:/etc/openldap/slapd.d" -v "${name}-data:/var/lib/openldap/data" \
    -e LDAP_ROOT_DN="$base" -e LDAP_ADMIN_PASSWORD="$pw" \
    -e LDAP_REPLICATION_ENABLED=true -e LDAP_SERVER_ID="$sid" \
    -e LDAP_REPLICATION_PEERS="$peers" "$@" "$image" >/dev/null
}

docker network create "$net" >/dev/null
for x in "${reg_vols[@]}"; do docker volume create "$x" >/dev/null; done

# TLS material in a named volume (a single-file bind mount is unreadable for
# uid 999 on Colima, see AGENTS.md).
docker run --rm --user 0 -v "${certs}:/certs" --entrypoint openssl "$image" \
  req -x509 -newkey rsa:2048 -nodes -keyout /certs/k.pem -out /certs/c.pem -days 2 -subj /CN=localhost >/dev/null 2>&1
docker run --rm --user 0 -v "${certs}:/certs" --entrypoint chown "$image" -R 999:999 /certs
docker run --rm --user 0 -v "${certs}:/certs" --entrypoint chmod "$image" 600 /certs/k.pem
tls=(-v "${certs}:/certs:ro" -e LDAP_TLS_ENABLED=true -e LDAP_TLS_CERT_FILE=/certs/c.pem -e LDAP_TLS_KEY_FILE=/certs/k.pem)

# --- Part 1: fresh volume (serverID 2) and existing volume (serverID 1) ------
start_node "$n1" 1 "${tls[@]}"
wait_ready "$n1" || { bad "n1 (admin) never ready"; exit 1; }
add_user "$n1" alice
add_user "$n1" bob

probe() { # node -> deterministic behaviour summary of anonymous, user and admin access
  local n="$1" rc=0 out=""
  out+="anon_entries=$(docker exec "$n" ldapsearch -x -LLL -H ldap://localhost -b "$base" '(uid=alice)' uid 2>/dev/null | grep -c '^dn:' || true)"$'\n'
  out+="anon_userPassword=$(docker exec "$n" ldapsearch -x -LLL -H ldap://localhost -b "$base" '(uid=alice)' userPassword 2>/dev/null | grep -c '^userPassword' || true)"$'\n'
  out+="admin_userPassword=$(asearch "$n" -b "$base" '(uid=alice)' userPassword 2>/dev/null | grep -c '^userPassword' || true)"$'\n'
  docker exec "$n" ldapwhoami -x -H ldap://localhost -D "uid=alice,${base}" -w "$alicepw" >/dev/null 2>&1 || rc=$?
  out+="alice_bind_rc=${rc}"$'\n'
  out+="alice_reads_bob=$(docker exec "$n" ldapsearch -x -LLL -H ldap://localhost -D "uid=alice,${base}" -w "$alicepw" -b "$base" '(uid=bob)' uid 2>/dev/null | grep -c '^dn:' || true)"$'\n'
  out+="alice_reads_bob_password=$(docker exec "$n" ldapsearch -x -LLL -H ldap://localhost -D "uid=alice,${base}" -w "$alicepw" -b "$base" '(uid=bob)' userPassword 2>/dev/null | grep -c '^userPassword' || true)"$'\n'
  rc=0
  docker exec -i "$n" ldapmodify -x -H ldap://localhost -D "uid=alice,${base}" -w "$alicepw" >/dev/null 2>&1 <<EOF || rc=$?
dn: uid=alice,${base}
changetype: modify
replace: description
description: probe
EOF
  out+="alice_self_modify_rc=${rc}"$'\n'
  rc=0
  docker exec -i "$n" ldapmodify -x -H ldap://localhost -D "uid=alice,${base}" -w "$alicepw" >/dev/null 2>&1 <<EOF || rc=$?
dn: uid=bob,${base}
changetype: modify
replace: description
description: probe
EOF
  out+="alice_modify_bob_rc=${rc}"$'\n'
  printf '%s' "$out"
}

probe "$n1" >"${work}/n1.admin.probe"
acl_list "$n1" >"${work}/n1.admin.acl"
check "n1 admin mode: no identity rule stored" "0" "$(grep -c "$iddn" "${work}/n1.admin.acl" || true)"

start_node "$n2" 2 "${tls[@]}" -e LDAP_REPLICATION_IDENTITY=prepare
wait_ready "$n2" || { bad "n2 (prepare, fresh) never ready"; docker logs "$n2" 2>&1 | tail -n 15 >&2; exit 1; }
poll has_uid "$n2" alice || bad "n2: alice never replicated"
poll has_uid "$n2" bob || bad "n2: bob never replicated"
n2log="$(docker logs "$n2" 2>&1)"
if [[ "$n2log" == *"ACL and olcLimits for ${iddn} installed and verified"* ]]; then ok "fresh volume: install logged as verified"; else bad "fresh volume: no 'installed and verified' log"; fi
acl_list "$n2" >"${work}/n2.acl"
check "fresh volume: first olcAccess rule is the identity rule" "olcAccess: ${want_acl}" "$(head -n 1 "${work}/n2.acl")"
check "fresh volume: identity rule stored exactly once" "1" "$(grep -c "$iddn" "${work}/n2.acl" || true)"
check "fresh volume: olcLimits stored" "olcLimits: {0}${want_lim}" "$(lim_list "$n2" | head -n 1)"
check "fresh volume: olcSyncrepl still binds as the admin DN" "1" "$(cfg_dump "$n2" | grep '^olcSyncrepl' | grep -c "binddn=\"${admin}\"" || true)"
check "fresh volume: hashes replicate to the prepared node" "1" "$(asearch "$n2" -b "$base" '(uid=alice)' userPassword | grep -c '^userPassword' || true)"
probe "$n2" >"${work}/n2.probe"
check "prepared node behaves like the admin-mode node (admin, anonymous, user probes)" "$(cat "${work}/n1.admin.probe")" "$(cat "${work}/n2.probe")"

# Idempotent reboot: nothing is installed again and cn=config does not change.
cfg_dump "$n2" | norm | sort >"${work}/n2.before.cfg"
acl_before="$(acl_list "$n2")"
docker restart "$n2" >/dev/null
wait_ready "$n2" || bad "n2 never ready after restart"
cfg_dump "$n2" | norm | sort >"${work}/n2.after.cfg"
check "second start: olcAccess order and text unchanged" "$acl_before" "$(acl_list "$n2")"
if diff -u "${work}/n2.before.cfg" "${work}/n2.after.cfg" >"${work}/n2.cfg.diff"; then ok "second start: cn=config unchanged"; else bad "second start: cn=config changed"; head -n 30 "${work}/n2.cfg.diff" >&2; fi
n2log="$(docker logs "$n2" 2>&1)"
if [[ "$n2log" == *"already installed — nothing to do"* ]]; then ok "second start: logged as a no-op"; else bad "second start: no no-op log"; fi
check "second start: installed only once across both starts" "1" "$(grep -c 'installing the read-only ACL' <<<"$n2log" || true)"

# Existing admin-mode volume restarted with prepare.
users_before="$(asearch "$n1" -b "$base" '(objectClass=inetOrgPerson)' uid | sed -n 's/^uid: //p' | sort | tr '\n' ' ')"
docker rm -f "$n1" >/dev/null
start_node "$n1" 1 "${tls[@]}" -e LDAP_REPLICATION_IDENTITY=prepare
wait_ready "$n1" || { bad "n1 (prepare, existing volume) never ready"; docker logs "$n1" 2>&1 | tail -n 15 >&2; exit 1; }
acl_list "$n1" >"${work}/n1.prepare.acl"
check "existing volume: first olcAccess rule is the identity rule" "olcAccess: ${want_acl}" "$(head -n 1 "${work}/n1.prepare.acl")"
check "existing volume: olcLimits stored" "olcLimits: {0}${want_lim}" "$(lim_list "$n1" | head -n 1)"
check "existing volume: data intact" "$users_before" "$(asearch "$n1" -b "$base" '(objectClass=inetOrgPerson)' uid | sed -n 's/^uid: //p' | sort | tr '\n' ' ')"
check "existing volume: olcSyncrepl still binds as the admin DN" "1" "$(cfg_dump "$n1" | grep '^olcSyncrepl' | grep -c "binddn=\"${admin}\"" || true)"
probe "$n1" >"${work}/n1.prepare.probe"
check "existing volume: probes identical before and after prepare" "$(cat "${work}/n1.admin.probe")" "$(cat "${work}/n1.prepare.probe")"
# Part 2: the other rules are exactly what they were before, only renumbered.
check "existing volume: rules after {0} equal the rules before, renumbered" "$(strip_idx <"${work}/n1.admin.acl")" "$(tail -n +2 "${work}/n1.prepare.acl" | strip_idx)"
add_user "$n1" carol
if poll has_uid "$n2" carol; then ok "replication n1 -> n2 works after prepare"; else bad "replication n1 -> n2 broken after prepare"; fi
add_user "$n2" dave
if poll has_uid "$n1" dave; then ok "replication n2 -> n1 works after prepare"; else bad "replication n2 -> n1 broken after prepare"; fi

# --- Part 3: identity entry simulated by hand --------------------------------
docker exec -i "$n1" ldapadd -x -H ldap://localhost -D "$admin" -w "$pw" >/dev/null <<EOF
dn: ${iddn}
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: replicator
userPassword: ${idpw}
EOF
poll has_uid "$n1" alice
# shellcheck disable=SC2317,SC2329 # invoked through idrc
# The point of the TLS probes is the ssf>=128 ACL, not chain validation (libldap
# canonicalizes "localhost" to another name, so the self-signed host name check fails).
tlsc() { docker exec -i -e LDAPTLS_CACERT=/certs/c.pem -e LDAPTLS_REQCERT=never "$n1" "$@"; }
idrc() { # description, expected rc, command... (stdin LDIF is passed through)
  local label="$1" want="$2" rc=0
  shift 2
  "$@" >/dev/null 2>&1 || rc=$?
  check "identity (TLS): ${label}" "$want" "$rc"
}
check "identity (TLS): reads another user's userPassword hash (needed for replication)" "1" \
  "$(docker exec -e LDAPTLS_CACERT=/certs/c.pem -e LDAPTLS_REQCERT=never "$n1" ldapsearch -x -LLL -H ldaps://localhost -D "$iddn" -w "$idpw" -b "$base" '(uid=alice)' userPassword | grep -c '^userPassword' || true)"
check "identity (TLS): reads the operational entryCSN" "1" \
  "$(docker exec -e LDAPTLS_CACERT=/certs/c.pem -e LDAPTLS_REQCERT=never "$n1" ldapsearch -x -LLL -H ldaps://localhost -D "$iddn" -w "$idpw" -b "$base" '(uid=alice)' entryCSN | grep -c '^entryCSN' || true)"
check "identity (plaintext ldap://, ssf 0): sees no entry at all" "0" \
  "$(docker exec "$n1" ldapsearch -x -LLL -H ldap://localhost -D "$iddn" -w "$idpw" -b "$base" '(uid=alice)' uid | grep -c '^dn:' || true)"
idrc "modify its own description is refused (50)" 50 tlsc ldapmodify -x -H ldaps://localhost -D "$iddn" -w "$idpw" <<EOF
dn: ${iddn}
changetype: modify
replace: description
description: x
EOF
idrc "modify another entry is refused (50)" 50 tlsc ldapmodify -x -H ldaps://localhost -D "$iddn" -w "$idpw" <<EOF
dn: uid=alice,${base}
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
idrc "delete itself is refused (50)" 50 tlsc ldapdelete -x -H ldaps://localhost -D "$iddn" -w "$idpw" "$iddn" </dev/null
idrc "change its own password is refused (50)" 50 tlsc ldapmodify -x -H ldaps://localhost -D "$iddn" -w "$idpw" <<EOF
dn: ${iddn}
changetype: modify
replace: userPassword
userPassword: ${idpw}-new
EOF
idrc "modify its own pwd* attribute is refused (50)" 50 tlsc ldapmodify -x -H ldaps://localhost -D "$iddn" -w "$idpw" <<EOF
dn: ${iddn}
changetype: modify
replace: pwdEndTime
pwdEndTime: 20990101000000Z
EOF
idrc "read cn=config is refused (32)" 32 tlsc ldapsearch -x -LLL -H ldaps://localhost -D "$iddn" -w "$idpw" -b cn=config -s base </dev/null
check "identity entry intact after the negative attempts (still binds over TLS)" "0" \
  "$(rc=0; docker exec -e LDAPTLS_CACERT=/certs/c.pem -e LDAPTLS_REQCERT=never "$n1" ldapwhoami -x -H ldaps://localhost -D "$iddn" -w "$idpw" >/dev/null 2>&1 || rc=$?; echo "$rc")"
# Everyone else is unchanged by the presence of the entry.
check "alice can still modify herself" "0" \
  "$(rc=0; docker exec -i "$n1" ldapmodify -x -H ldap://localhost -D "uid=alice,${base}" -w "$alicepw" >/dev/null 2>&1 <<EOF || rc=$?
dn: uid=alice,${base}
changetype: modify
replace: description
description: probe2
EOF
echo "$rc")"
check "alice cannot modify the identity entry (50)" "50" \
  "$(rc=0; docker exec -i "$n1" ldapmodify -x -H ldap://localhost -D "uid=alice,${base}" -w "$alicepw" >/dev/null 2>&1 <<EOF || rc=$?
dn: ${iddn}
changetype: modify
replace: description
description: x
EOF
echo "$rc")"
check "anonymous cannot read the identity's userPassword" "0" \
  "$(docker exec "$n1" ldapsearch -x -LLL -H ldap://localhost -b "$base" "(cn=replicator)" userPassword | grep -c '^userPassword' || true)"
check "admin can still modify the identity entry (rotation path)" "0" \
  "$(rc=0; docker exec -i "$n1" ldapmodify -x -H ldap://localhost -D "$admin" -w "$pw" >/dev/null 2>&1 <<EOF || rc=$?
dn: ${iddn}
changetype: modify
replace: description
description: rotated
EOF
echo "$rc")"
# Entry present AND rule stored: the restart is an idempotent pass, not a refusal.
docker rm -f "$n1" >/dev/null
poll has_uid "$n2" alice
start_node "$n1" 1 "${tls[@]}" -e LDAP_REPLICATION_IDENTITY=prepare
if wait_ready "$n1"; then ok "entry present + rule stored: restart is accepted"; else bad "entry present + rule stored: restart refused"; fi

# --- Part 2b: LDAP_ANONYMOUS_READ_BASE interplay -----------------------------
ab_args=(-d --name "$ab" -v "${ab}-cfg:/etc/openldap/slapd.d" -v "${ab}-data:/var/lib/openldap/data"
  -e LDAP_ROOT_DN="$base" -e LDAP_ADMIN_PASSWORD="$pw" -e LDAP_ANONYMOUS_READ_BASE="$base"
  -e LDAP_REPLICATION_ENABLED=true -e LDAP_SERVER_ID=1 -e "LDAP_REPLICATION_PEERS=ldap://${ab}:389,ldap://${ab}-peer:389")
docker run "${ab_args[@]}" "$image" >/dev/null
wait_ready "$ab" || { bad "anon-base node never ready"; exit 1; }
add_user "$ab" alice
add_user "$ab" bob
probe "$ab" >"${work}/ab.admin.probe"
acl_list "$ab" >"${work}/ab.admin.acl"
docker rm -f "$ab" >/dev/null
docker run "${ab_args[@]}" -e LDAP_REPLICATION_IDENTITY=prepare "$image" >/dev/null
wait_ready "$ab" || { bad "anon-base node (prepare) never ready"; docker logs "$ab" 2>&1 | tail -n 15 >&2; exit 1; }
acl_list "$ab" >"${work}/ab.prepare.acl"
check "anonymous read base: first rule is the identity rule" "olcAccess: ${want_acl}" "$(head -n 1 "${work}/ab.prepare.acl")"
check "anonymous read base: rendered rules after {0} equal the rules before, renumbered" "$(strip_idx <"${work}/ab.admin.acl")" "$(tail -n +2 "${work}/ab.prepare.acl" | strip_idx)"
check "anonymous read base: rule count is one more" "$(($(wc -l <"${work}/ab.admin.acl") + 1))" "$(wc -l <"${work}/ab.prepare.acl" | tr -d ' ')"
probe "$ab" >"${work}/ab.prepare.probe"
check "anonymous read base: probes identical before and after prepare" "$(cat "${work}/ab.admin.probe")" "$(cat "${work}/ab.prepare.probe")"
docker rm -fv "$ab" >/dev/null

# --- Part 4: refusals ---------------------------------------------------------
# off <command...>: run an offline OpenLDAP tool on the rv volumes (stdin passes through).
off() { docker run --rm -i -v "${rv}-cfg:/etc/openldap/slapd.d" -v "${rv}-data:/var/lib/openldap/data" --entrypoint "$1" "$image" "${@:2}"; }
rv_args=(--name "$rv" -v "${rv}-cfg:/etc/openldap/slapd.d" -v "${rv}-data:/var/lib/openldap/data"
  -e LDAP_ROOT_DN="$base" -e LDAP_ADMIN_PASSWORD="$pw"
  -e LDAP_REPLICATION_ENABLED=true -e LDAP_SERVER_ID=1 -e "LDAP_REPLICATION_PEERS=ldap://${rv}:389,ldap://${rv}-peer:389")
docker run -d "${rv_args[@]}" "$image" >/dev/null
wait_ready "$rv" || { bad "refusal volume never ready"; exit 1; }
docker rm -f "$rv" >/dev/null
rv_cfg() { off slapcat -n 0 -F /etc/openldap/slapd.d -o ldif-wrap=no; }

# refuse_case <label> <message fragment> : start prepare on the rv volumes, expect a fixed refusal
# before slapd starts, cn=config byte-identical, no identity rule stored, no secret in the output.
refuse_case() {
  local label="$1" want="$2" before after out rc w=0 state
  before="$(rv_cfg)"
  docker run -d "${rv_args[@]}" -e LDAP_REPLICATION_IDENTITY=prepare "$image" >/dev/null
  while [ "$w" -lt "$timeout_s" ]; do
    state="$(docker inspect -f '{{.State.Running}}' "$rv" 2>/dev/null || echo gone)"
    [ "$state" = "false" ] && break
    sleep 1
    w=$((w + 1))
  done
  if [ "$state" != "false" ]; then
    bad "${label}: still running after ${timeout_s}s, expected a refusal"
    docker rm -fv "$rv" >/dev/null 2>&1 || true
    return
  fi
  rc="$(docker inspect -f '{{.State.ExitCode}}' "$rv")"
  out="$(docker logs "$rv" 2>&1)"
  docker rm -f "$rv" >/dev/null
  after="$(rv_cfg)"
  if [ "$rc" -eq 0 ]; then bad "${label}: exited 0, expected a refusal"; return; fi
  if [[ "$out" != *"$want"* ]]; then bad "${label}: message missing '${want}'; got: $(printf '%s' "$out" | tail -n 2)"; return; fi
  if [ "$before" != "$after" ]; then bad "${label}: refusal modified cn=config"; return; fi
  if [[ "$after" == *"olcAccess: ${want_acl}"* ]]; then bad "${label}: identity rule stored despite the refusal"; return; fi
  if [[ "$out" == *"$pw"* ]]; then bad "${label}: admin password leaked into the output"; return; fi
  ok "${label}"
}
mod_cfg() { off slapmodify -n 0 -F /etc/openldap/slapd.d >/dev/null; }
mod_db() { off slapmodify -n 1 -F /etc/openldap/slapd.d >/dev/null; }

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
refuse_case "entry with authzTo is refused" "an entry carries authzTo/authzFrom"
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
refuse_case "olcAuthzPolicy=to is refused" "olcAuthzPolicy is not 'none'"
mod_cfg <<EOF
dn: cn=config
changetype: modify
delete: olcAuthzPolicy
EOF

mod_cfg <<EOF
dn: cn=config
changetype: modify
add: olcAuthzRegexp
olcAuthzRegexp: {0}^cn=service42$ ${iddn}
EOF
refuse_case "olcAuthzRegexp is refused" "olcAuthzRegexp is stored"
mod_cfg <<EOF
dn: cn=config
changetype: modify
delete: olcAuthzRegexp
EOF

mod_cfg <<EOF
dn: cn=config
changetype: modify
add: olcAuthIDRewrite
olcAuthIDRewrite: {0}rewriteRule "^(.*)$" "uid=\$1,${base}" ":@"
EOF
refuse_case "olcAuthIDRewrite is refused" "olcAuthIDRewrite is stored"
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
refuse_case "olcTLSVerifyClient=try is refused" "olcTLSVerifyClient is not 'never'"
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
refuse_case "stored olcRootDN equal to the reserved DN (case/space variant) is refused" "is a stored olcRootDN"
mod_cfg <<EOF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcRootDN
olcRootDN: ${admin}
EOF

# Stored rootDN spelled differently from the reserved DN (Part 5, existing volume).
for variant in 'cn=replic\61tor,dc=example,dc=org' 'cn="replicator",dc=example,dc=org' 'CN=Replicator , DC=EXAMPLE , DC=ORG' 'cn=replicator,dc=example,dc=o\72g'; do
  mod_cfg <<EOF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcRootDN
olcRootDN: ${variant}
EOF
  refuse_case "stored rootDN '${variant}' equals the reserved DN" "is a stored olcRootDN or replication bind DN"
done
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
refuse_case "a rule for the identity that is not the first rule is refused" "is not the first olcAccess rule"
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
refuse_case "entry at the reserved DN without the rule is refused" "already exists on this node but the identity ACL is not installed"
mod_db <<EOF
dn: ${iddn}
changetype: delete
EOF

# The same volume, now clean: prepare installs and verifies.
docker run -d "${rv_args[@]}" -e LDAP_REPLICATION_IDENTITY=prepare "$image" >/dev/null
if wait_ready "$rv"; then ok "clean admin-mode volume: prepare starts"; else bad "clean volume: prepare never ready"; docker logs "$rv" 2>&1 | tail -n 10 >&2; fi
check "clean admin-mode volume: identity rule is the first rule" "olcAccess: ${want_acl}" "$(acl_list "$rv" | head -n 1)"
docker rm -f "$rv" >/dev/null

# Refusals that must happen before ANY state change on a fresh volume.
fresh_refuse() { # label fragment env...
  local label="$1" want="$2" out rc w=0 state name="ldapium-ridprep-f${RANDOM}-${suffix}" listing
  shift 2
  reg_containers+=("$name")
  reg_vols+=("${name}-cfg" "${name}-data")
  docker volume create "${name}-cfg" >/dev/null
  docker volume create "${name}-data" >/dev/null
  docker run -d --name "$name" -v "${name}-cfg:/etc/openldap/slapd.d" -v "${name}-data:/var/lib/openldap/data" \
    -e LDAP_ADMIN_PASSWORD="$pw" -e LDAP_REPLICATION_ENABLED=true -e LDAP_REPLICATION_PEERS="$peers" \
    -e LDAP_REPLICATION_IDENTITY=prepare "$@" "$image" >/dev/null
  while [ "$w" -lt "$timeout_s" ]; do
    state="$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null || echo gone)"
    [ "$state" = "false" ] && break
    sleep 1
    w=$((w + 1))
  done
  if [ "$state" != "false" ]; then bad "${label}: still running after ${timeout_s}s, expected a refusal"; return; fi
  rc="$(docker inspect -f '{{.State.ExitCode}}' "$name")"
  out="$(docker logs "$name" 2>&1)"
  listing="$(docker run --rm --entrypoint ls -v "${name}-cfg:/c" -v "${name}-data:/d" "$image" -A /c /d 2>&1 | tr '\n' ' ')"
  if [ "$rc" -eq 0 ]; then bad "${label}: exited 0, expected a refusal"; return; fi
  if [[ "$out" != *"$want"* ]]; then bad "${label}: message missing '${want}'; got: $(printf '%s' "$out" | tail -n 2)"; return; fi
  check "${label}: volumes untouched" "/c: /d: " "$(printf '%s' "$listing" | tr -s ' ')"
}
fresh_refuse "prepare refuses to bootstrap serverID 1" "refuses to bootstrap serverID 1" -e LDAP_ROOT_DN="$base" -e LDAP_SERVER_ID=1
fresh_refuse "prepare + LDAP_TLS_MUTUAL_AUTH is refused" "cannot be combined with LDAP_TLS_MUTUAL_AUTH" -e LDAP_ROOT_DN="$base" -e LDAP_SERVER_ID=2 -e LDAP_TLS_MUTUAL_AUTH=true
fresh_refuse "prepare + quoted LDAP_ROOT_DN is refused" "without double quotes or backslashes" -e 'LDAP_ROOT_DN=dc=a"b,dc=org' -e LDAP_SERVER_ID=2

# --- Part 5: DN equivalence is slapd's (slapdn -N), not a string compare -------
# Each of these spells the reserved DN (or the root DN) differently from the
# other side; the old string compare accepted the internal-space, hex-escape,
# quoted and multivalued-RDN-order forms, which let a rootDN alias the identity.
eqmsg="must not equal the reserved replication identity DN"
# LDAP_ADMIN_DN has to sit under LDAP_ROOT_DN (string check) and start with cn=,
# so the env-level variants differ from the reserved DN in value case, escapes,
# quotes and the space after a comma.
fresh_refuse "DN equivalence: value case" "$eqmsg" \
  -e LDAP_ROOT_DN="$base" -e 'LDAP_ADMIN_DN=cn=Replicator,dc=example,dc=org' -e LDAP_SERVER_ID=2
fresh_refuse "DN equivalence: space after a comma" "$eqmsg" \
  -e LDAP_ROOT_DN="$base" -e 'LDAP_ADMIN_DN=cn=replicator, dc=example,dc=org' -e LDAP_SERVER_ID=2
fresh_refuse "DN equivalence: hex-pair escape (replic\\61tor)" "$eqmsg" \
  -e LDAP_ROOT_DN="$base" -e 'LDAP_ADMIN_DN=cn=replic\61tor,dc=example,dc=org' -e LDAP_SERVER_ID=2
fresh_refuse "DN equivalence: quoted value" "$eqmsg" \
  -e LDAP_ROOT_DN="$base" -e 'LDAP_ADMIN_DN=cn="replicator",dc=example,dc=org' -e LDAP_SERVER_ID=2
fresh_refuse "DN equivalence: LDAP_REPLICATION_BIND_DN" "LDAP_REPLICATION_BIND_DN must not equal" \
  -e LDAP_ROOT_DN="$base" -e 'LDAP_REPLICATION_BIND_DN=CN=replicator,dc=example,DC=org' -e LDAP_SERVER_ID=2
fresh_refuse "unparseable LDAP_ADMIN_DN is refused" "cannot normalize LDAP_ADMIN_DN" \
  -e LDAP_ROOT_DN="$base" -e 'LDAP_ADMIN_DN=cn=\zz,dc=example,dc=org' -e LDAP_SERVER_ID=2
# slapd's own normalization of the forms a string compare cannot see.
dn_norm() { docker run --rm -v "${certs}:/certs:ro" --entrypoint slapdn "$image" -f /certs/s.conf -N "$1" 2>&1; }
docker run --rm --user 0 -v "${certs}:/certs" --entrypoint sh "$image" -c \
  "printf 'include /etc/openldap/schema/core.schema\ninclude /etc/openldap/schema/cosine.schema\n' > /certs/s.conf"
check "slapdn: hex escape, \\, and quoted comma are one DN" "cn=a\\2Cb,dc=x" "$(dn_norm 'cn=a\2cb,dc=x')"
check "slapdn: backslash-comma form" "cn=a\\2Cb,dc=x" "$(dn_norm 'cn=a\,b,dc=x')"
check "slapdn: quoted form" "cn=a\\2Cb,dc=x" "$(dn_norm 'cn="a,b",dc=x')"
check "slapdn: internal spaces (dc=exa mple = dc=exa  mple; the image cannot bootstrap such a suffix, so no live volume)" "$(dn_norm 'dc=exa mple')" "$(dn_norm 'dc=exa  mple')"
check "slapdn: multivalued RDN order" "$(dn_norm 'cn=a+uid=b,dc=x')" "$(dn_norm 'uid=b+cn=a,dc=x')"

# Stored rootDN equal to the reserved DN under another spelling: the repro that
# let the identity bind in plaintext. alias_case <label> <root DN> <stored rootDN>:
# bootstrap in admin mode, store the aliased rootDN offline, prove in admin mode
# that it binds in plaintext and can ADD (what the TLS-only read-only identity
# must never be able to do), then start with prepare, which must refuse.
alias_case() {
  local label="$1" root="$2" alias="$3" xw=0 xout
  local envs=(-v "${xv}-cfg:/etc/openldap/slapd.d" -v "${xv}-data:/var/lib/openldap/data" -e "LDAP_ROOT_DN=${root}" -e LDAP_ADMIN_PASSWORD="$pw"
    -e LDAP_REPLICATION_ENABLED=true -e LDAP_SERVER_ID=1 -e "LDAP_REPLICATION_PEERS=ldap://${xv}:389,ldap://${xv}-peer:389")
  docker volume rm -f "${xv}-cfg" "${xv}-data" >/dev/null
  docker volume create "${xv}-cfg" >/dev/null
  docker volume create "${xv}-data" >/dev/null
  docker run -d --name "$xv" "${envs[@]}" "$image" >/dev/null
  if ! wait_ready "$xv"; then bad "${label}: admin-mode volume never ready"; docker logs "$xv" 2>&1 | tail -n 5 >&2; docker rm -f "$xv" >/dev/null; return; fi
  docker rm -f "$xv" >/dev/null
  docker run --rm -i -v "${xv}-cfg:/etc/openldap/slapd.d" -v "${xv}-data:/var/lib/openldap/data" --entrypoint slapmodify "$image" -n 0 -F /etc/openldap/slapd.d >/dev/null <<EOF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcRootDN
olcRootDN: ${alias}
EOF
  docker run -d --name "$xv" "${envs[@]}" "$image" >/dev/null
  if ! wait_ready "$xv"; then bad "${label}: aliased admin-mode volume never ready"; docker logs "$xv" 2>&1 | tail -n 5 >&2; docker rm -f "$xv" >/dev/null; return; fi
  check "${label}: (admin mode) the aliased rootDN binds in plaintext" "0" \
    "$(rc=0; docker exec "$xv" ldapwhoami -x -H ldap://localhost -D "cn=replicator,${root}" -w "$pw" >/dev/null 2>&1 || rc=$?; echo "$rc")"
  check "${label}: (admin mode) the aliased rootDN can add entries in plaintext" "0" \
    "$(rc=0; docker exec -i "$xv" ldapadd -x -H ldap://localhost -D "cn=replicator,${root}" -w "$pw" >/dev/null 2>&1 <<EOF || rc=$?
dn: cn=evil,${root}
objectClass: organizationalRole
cn: evil
EOF
echo "$rc")"
  docker rm -f "$xv" >/dev/null
  docker run -d --name "$xv" "${envs[@]}" -e LDAP_REPLICATION_IDENTITY=prepare "$image" >/dev/null
  while [ "$(docker inspect -f '{{.State.Running}}' "$xv" 2>/dev/null || echo gone)" = "true" ] && [ "$xw" -lt "$timeout_s" ]; do sleep 1; xw=$((xw + 1)); done
  xout="$(docker logs "$xv" 2>&1)"
  check "${label}: prepare refuses to start" "1" "$(docker inspect -f '{{.State.ExitCode}}' "$xv")"
  if [[ "$xout" == *"is a stored olcRootDN or replication bind DN"* ]]; then ok "${label}: fixed refusal message"; else bad "${label}: message missing; got $(printf '%s' "$xout" | tail -n 2)"; fi
  check "${label}: no identity rule stored" "0" \
    "$(docker run --rm -v "${xv}-cfg:/etc/openldap/slapd.d" -v "${xv}-data:/var/lib/openldap/data" --entrypoint slapcat "$image" -n 0 -F /etc/openldap/slapd.d -o ldif-wrap=no | grep -c 'ssf=128' || true)"
  docker rm -f "$xv" >/dev/null
}
alias_case "alias, hex-escaped and cased RDN" 'dc=example,dc=org' 'CN=Replic\61tor,DC=Example,DC=Org'

# --- Part 6: olcLimits are first-match, so the identity rule must be first ----
offv() { docker run --rm -i -v "${lv}-cfg:/etc/openldap/slapd.d" -v "${lv}-data:/var/lib/openldap/data" --entrypoint "$1" "$image" "${@:2}"; }
lv_start() {
  docker run -d --name "$lv" -v "${lv}-cfg:/etc/openldap/slapd.d" -v "${lv}-data:/var/lib/openldap/data" \
    -v "${certs}:/certs:ro" -e LDAP_TLS_ENABLED=true -e LDAP_TLS_CERT_FILE=/certs/c.pem -e LDAP_TLS_KEY_FILE=/certs/k.pem \
    -e LDAP_ROOT_DN="$base" -e LDAP_ADMIN_PASSWORD="$pw" -e LDAP_REPLICATION_ENABLED=true -e LDAP_SERVER_ID=1 \
    -e "LDAP_REPLICATION_PEERS=ldap://${lv}:389,ldap://${lv}-peer:389" "$@" "$image" >/dev/null
  wait_ready "$lv"
}
lv_limits() { docker exec "$lv" slapcat -n 0 -o ldif-wrap=no | sed -n '/^dn: olcDatabase={1}mdb,cn=config$/,/^$/p' | grep '^olcLimits: ' || true; }
lv_search() { # bind-dn password -> "rc count" of a subtree search over TLS
  local rc=0 out
  out="$(docker exec -e LDAPTLS_CACERT=/certs/c.pem -e LDAPTLS_REQCERT=never "$lv" ldapsearch -x -LLL -H ldaps://localhost -D "$1" -w "$2" -b "$base" '(objectClass=*)' dn 2>/dev/null)" || rc=$?
  printf '%s %s' "$rc" "$(printf '%s\n' "$out" | grep -c '^dn:' || true)"
}
lv_start; docker rm -f "$lv" >/dev/null
# A global size=1 time=1 rule is already stored ahead of everything.
offv slapmodify -n 0 -F /etc/openldap/slapd.d >/dev/null <<EOF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
add: olcLimits
olcLimits: {0}* size=1 time=1
EOF
lv_start -e LDAP_REPLICATION_IDENTITY=prepare || { bad "limits: prepare with a pre-existing global rule never ready"; docker logs "$lv" 2>&1 | tail -n 8 >&2; }
check "limits: ours is the FIRST stored rule, ahead of the global size=1 rule" "olcLimits: {0}${want_lim}" "$(lv_limits | sed -n '1p')"
check "limits: the global rule is kept behind it" "olcLimits: {1}* size=1 time=1" "$(lv_limits | sed -n '2p')"
docker rm -f "$lv" >/dev/null
for u in u1 u2 u3 u4; do
  offv slapmodify -n 1 -F /etc/openldap/slapd.d >/dev/null <<EOF
dn: uid=${u},${base}
changetype: add
objectClass: inetOrgPerson
uid: ${u}
cn: ${u}
sn: ${u}
userPassword: ${alicepw}
EOF
done
offv slapmodify -n 1 -F /etc/openldap/slapd.d >/dev/null <<EOF
dn: ${iddn}
changetype: add
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: replicator
userPassword: ${idpw}
EOF
lv_start -e LDAP_REPLICATION_IDENTITY=prepare || bad "limits: restart with entry + rule never ready"
id_res="$(lv_search "$iddn" "$idpw")"
check "limits: identity gets every entry (rc 0, >1 entries) despite the global size=1 rule" "0 true" "${id_res%% *} $([ "${id_res##* }" -gt 5 ] && echo true || echo false)"
check "limits: an ordinary user still hits the size limit (rc 4)" "4" "$(lv_search "uid=u1,${base}" "$alicepw" | cut -d' ' -f1)"
docker rm -f "$lv" >/dev/null
# A pre-existing identity rule with wrong values, behind a global rule: replaced.
offv slapmodify -n 0 -F /etc/openldap/slapd.d >/dev/null <<EOF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcLimits
olcLimits: {0}* size=1 time=1
olcLimits: {1}dn.exact="${iddn}" size=1 time=1
EOF
lv_start -e LDAP_REPLICATION_IDENTITY=prepare || { bad "limits: wrong identity rule never ready"; docker logs "$lv" 2>&1 | tail -n 8 >&2; }
check "limits: wrong identity rule replaced, ours first" "olcLimits: {0}${want_lim}" "$(lv_limits | sed -n '1p')"
check "limits: exactly one rule for the identity remains" "1" "$(lv_limits | grep -c "dn.exact=\"${iddn}\"" || true)"
id_res="$(lv_search "$iddn" "$idpw")"
check "limits: identity unlimited again after the replacement" "0 true" "${id_res%% *} $([ "${id_res##* }" -gt 5 ] && echo true || echo false)"
# Correct rule already first: restart is a no-op and the limits do not change.
lim_before="$(lv_limits)"
docker restart "$lv" >/dev/null
wait_ready "$lv" || bad "limits: restart never ready"
check "limits: correct rule first, restart leaves olcLimits unchanged" "$lim_before" "$(lv_limits)"
if [[ "$(docker logs "$lv" 2>&1)" == *"already installed — nothing to do"* ]]; then ok "limits: restart logged as a no-op"; else bad "limits: restart not a no-op"; fi
docker rm -fv "$lv" >/dev/null

if [ "$fail" -eq 0 ]; then
  echo "replication-identity prepare test passed"
  exit 0
fi
echo "replication-identity prepare test FAILED" >&2
exit 1
