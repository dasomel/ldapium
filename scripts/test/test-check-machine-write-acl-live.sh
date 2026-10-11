#!/usr/bin/env bash
# Live proof of scripts/check-machine-write-acl.sh (#285, T-023) on ONE real slapd.
#
# The node runs LDAP_REPLICATION_IDENTITY=prepare (rule at {0}); the machine read fragment is
# applied behind it (docs/machine-ldap-account.md 5.1) and the W fragments with the guide's own
# install command (docs/machine-write-account.md 4.2, cut out of the guide and run as written,
# like test-machine-write-acl-smoke.sh). Then:
#   1. the correct state must exit 0 (--container, --kube-pod via a stub kubectl, --input dump)
#   2. three deliberate breakages must each exit non-zero, and the correct state is restored:
#        a. two W_data rules swapped
#        b. the W_data secrets rule removed
#        c. the W_data fragment applied twice (bypassing the guide's own refusal)
#   3. an unreadable source (no such container) must exit non-zero
# Not wired into CI (needs Docker and an image). Throwaway passwords only.
#
# Usage: scripts/test/test-check-machine-write-acl-live.sh [image]    image defaults to ldapium:e2e
# CHKACL_SAVE_DUMP=FILE additionally writes the good olcAccess list there. Resources are named ldapium-chkacl-l285o* (override the suffix with CHKACL_SUFFIX) and only
# those are removed on exit.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
image="${1:-ldapium:e2e}"
suffix="${CHKACL_SUFFIX:-l285o}"
timeout_s=120
pw="chkaclAdminPw-Zq7Lm2Xv9Kd4Hs8Wt1Bn6Rc3Yf5Ug0Pe"
base="dc=example,dc=org"
admin="cn=admin,${base}"
iddn="cn=replicator,${base}"
sysdn="ou=system,${base}"
mdn="uid=machine,${sysdn}"
wddn="uid=machine-write-data,${sysdn}"
wldn="uid=machine-write-lock,${sysdn}"
wrdn="ou=managed,${base}"
maindb="olcDatabase={1}mdb,cn=config"
ldapi='ldapi://%2Fvar%2Flib%2Fopenldap%2Frun%2Fldapi'
net="ldapium-chkacl-net-${suffix}"
certs="ldapium-chkacl-certs-${suffix}"
c="ldapium-chkacl-${suffix}"
envfile="$(mktemp)"
stubdir="$(mktemp -d)"
dump="$(mktemp)"
fix="${repo}/scripts/test/fixtures/machine-acl"
guide="${repo}/docs/machine-write-account.md"
chk="${repo}/scripts/check-machine-write-acl.sh"

EXEC="docker exec -i ${c}"
MACHINE_DN="$mdn"
WDATA_DN="$wddn"
WLOCK_DN="$wldn"
SYSTEM_DN="$sysdn"
REPL_DN="$iddn"
MAIN_DB_DN="$maindb"
CFG_URI="$ldapi"
ROOT_DN="$base"
WRITE_DN="$wrdn"
export EXEC MACHINE_DN WDATA_DN WLOCK_DN SYSTEM_DN REPL_DN MAIN_DB_DN CFG_URI ROOT_DN WRITE_DN

fail=0
ok() { printf 'PASS: %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }
expect_rc() { # label expected actual
  if [ "$2" = "$3" ]; then ok "$1 (rc $3)"; else bad "$1: expected rc $2, got rc $3"; fi
}
expect_nonzero() { # label actual
  if [ "$2" != 0 ]; then ok "$1 (rc $2)"; else bad "$1: expected a non-zero exit, got 0 (FALSE PASS)"; fi
}

# shellcheck disable=SC2317,SC2329 # invoked via the trap below
cleanup() {
  trap - EXIT
  if ! docker rm -fv "$c" >/dev/null 2>&1; then echo "cleanup: container ${c} not removed" >&2; fi
  if ! docker volume rm -f "${c}-cfg" "${c}-data" "$certs" >/dev/null 2>&1; then echo "cleanup: volumes not removed" >&2; fi
  if ! docker network rm "$net" >/dev/null 2>&1; then echo "cleanup: network ${net} not removed" >&2; fi
  rm -rf "$envfile" "$stubdir" "$dump" "${dump}.out" "${dump}.good"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

poll() {
  local w=0
  until "$@" >/dev/null 2>&1; do
    sleep 1
    w=$((w + 1))
    [ "$w" -lt "$timeout_s" ] || return 1
  done
}
# shellcheck disable=SC2317,SC2329 # invoked through poll
ready() { docker exec "$c" ldapwhoami -x -H ldap://localhost >/dev/null 2>&1; }

guide_sh() { awk -v re="$1" '/^```sh$/ { on=1; buf=""; next } /^```$/ { if (on && buf ~ re) { printf "%s", buf; exit } on=0; next } on { buf = buf $0 "\n" }' "$guide"; }
install_cmd="$(guide_sh 'PRESENT=')"
if [ -z "$install_cmd" ]; then echo "cannot cut the install command out of ${guide}" >&2; exit 1; fi

printf 'LDAP_ADMIN_PASSWORD=%s\n' "$pw" >"$envfile"
docker network create "$net" >/dev/null
docker volume create "$certs" >/dev/null
docker volume create "${c}-cfg" >/dev/null
docker volume create "${c}-data" >/dev/null
docker run --rm --user 0 -v "${certs}:/certs" --entrypoint openssl "$image" \
  req -x509 -newkey rsa:2048 -nodes -keyout /certs/k.pem -out /certs/c.pem -days 2 -subj /CN=localhost >/dev/null 2>&1
docker run --rm --user 0 -v "${certs}:/certs" --entrypoint chown "$image" -R 999:999 /certs
docker run --rm --user 0 -v "${certs}:/certs" --entrypoint chmod "$image" 600 /certs/k.pem

start_node() { # mode (admin|prepare)
  if ! docker rm -f "$c" >/dev/null 2>&1; then :; fi
  docker run -d --name "$c" --network "$net" --hostname "$c" \
    -v "${c}-cfg:/etc/openldap/slapd.d" -v "${c}-data:/var/lib/openldap/data" -v "${certs}:/certs:ro" \
    -e LDAP_ROOT_DN="$base" --env-file "$envfile" \
    -e LDAP_REPLICATION_ENABLED=true -e LDAP_SERVER_ID=1 -e LDAP_REPLICATION_PEERS="ldap://${c}:389" \
    -e LDAP_TLS_ENABLED=true -e LDAP_TLS_CERT_FILE=/certs/c.pem -e LDAP_TLS_KEY_FILE=/certs/k.pem \
    -e LDAP_REPLICATION_IDENTITY="$1" "$image" >/dev/null
  poll ready || { bad "node never ready (mode $1)"; docker logs "$c" 2>&1 | tail -n 15 >&2; return 1; }
  printf '%s' "$pw" | docker exec -i "$c" sh -c "umask 077; cat > /tmp/.pw-admin"
}

acl_list() { docker exec "$c" slapcat -n 0 -o ldif-wrap=no 2>/dev/null | sed -n "/^dn: ${maindb}\$/,/^\$/p" | awk '/^olcAccess: /'; }
cfg_apply() { docker exec -i "$c" ldapmodify -x -H "$ldapi" -D cn=admin,cn=config -y /tmp/.pw-admin >/dev/null; }
shift_ldif() { # base file
  awk -v b="$1" '/^olcAccess: \{[0-9]+\}/ { s=$0; sub(/^olcAccess: \{/,"",s); i=s+0; sub(/^[0-9]+\}/,"",s); print "olcAccess: {" (i+b) "}" s; next } { print }' "$2"
}
sub_tokens() {
  sed -e "s|@MACHINE_DN@|${mdn}|g" -e "s|@ALLOWED_DN@|${base}|g" -e "s|@WDATA_DN@|${wddn}|g" -e "s|@WLOCK_DN@|${wldn}|g" \
    -e "s|@WRITE_DN@|$1|g" -e "s|@SYSTEM_DN@|${sysdn}|g" -e "s|@REPL_DN@|${iddn}|g" -e "s|@MAIN_DB_DN@|${maindb}|g"
}
# The guide's 4.2 command, as written (cwd = the fixture directory, as the guide says).
# shellcheck disable=SC2030,SC2031 # the guide command runs in a subshell on purpose
apply_w() { # fixture who
  (cd "$fix" && export FRAG="$1" WHO="$2" && eval "$install_cmd") 2>&1
}
# Restore a saved olcAccess list exactly (replace the whole attribute).
restore_acl() { # file with the saved "olcAccess: {n}..." lines
  { printf 'dn: %s\nchangetype: modify\nreplace: olcAccess\n' "$maindb"; cat "$1"; } | cfg_apply
}

run_chk() { # extra args...; prints the output tail, returns the rc through $rc
  rc=0
  "$chk" --root-dn "$base" --machine-dn "$mdn" --system-dn "$sysdn" --write-dn "$wrdn" \
    --wdata-dn "$wddn" --wlock-dn "$wldn" --replication-identity required "$@" >"$dump.out" 2>&1 || rc=$?
  tail -n 3 "$dump.out"
}

echo "=== start: replication identity prepare, M read fragment, W fragments ==="
start_node admin
docker exec -i "$c" ldapadd -x -H ldap://localhost -D "$admin" -y /tmp/.pw-admin >/dev/null <<EOF
dn: ${sysdn}
objectClass: organizationalUnit
ou: system

dn: ${wrdn}
objectClass: organizationalUnit
ou: managed
EOF
start_node prepare
shift_ldif 1 "${fix}/main-database.ldif" | sub_tokens "$base" | cfg_apply
out="$(apply_w write-data.ldif "$wddn")"
printf '%s\n' "$out" | tail -n 1
out="$(apply_w write-lock.ldif "$wldn")"
printf '%s\n' "$out" | tail -n 1
acl_list >"${dump}.good"
# CHKACL_SAVE_DUMP=FILE keeps the good main-database olcAccess (only that entry: cn=config holds credentials) as a fixture.
if [ -n "${CHKACL_SAVE_DUMP:-}" ]; then { printf 'dn: %s\n' "$maindb"; cat "${dump}.good"; } >"$CHKACL_SAVE_DUMP"; fi
echo "--- installed olcAccess ($(wc -l <"${dump}.good" | tr -d ' ') values, first 4 and last 2) ---"
sed -n '1,4p' "${dump}.good" | cut -c1-150
tail -n 2 "${dump}.good" | cut -c1-150

echo "=== 1. correct state => 0 ==="
run_chk --container "$c"
expect_rc "--container, correct order" 0 "$rc"
docker exec "$c" slapcat -n 0 -o ldif-wrap=no >"$dump"
run_chk --input "$dump"
expect_rc "--input (slapcat dump), correct order" 0 "$rc"
cat >"${stubdir}/kubectl" <<EOF
#!/bin/sh
# stub: kubectl [-n NS] exec POD [-c C] -- CMD... => docker exec into the test container
while [ "\$1" != "--" ]; do shift; done
shift
exec docker exec ${c} "\$@"
EOF
chmod +x "${stubdir}/kubectl"
PATH="${stubdir}:${PATH}" run_chk --kube-pod ldapium-0 --namespace ldap
expect_rc "--kube-pod (stub kubectl -> this container), correct order" 0 "$rc"

breakage() { # label; the break itself is applied by the caller before this
  run_chk --container "$c"
  expect_nonzero "$1" "$rc"
  awk '/^FAIL/ && n++ < 2' "$dump.out" | cut -c1-220
}

echo "=== 2a. two W_data rules swapped ==="
# delete rules 4 and 5 of the W_data fragment and re-add them swapped.
nth() { sed -n "$(($1 + 1))p" "${dump}.good"; } # 0-based value from the saved list
idx_first="$(awk -v x="dn.exact=\"${wddn}\"" 'index($0, x) { sub(/^olcAccess: \{/, ""); print $0 + 0; exit }' "${dump}.good")"
a=$((idx_first + 3))
b=$((idx_first + 4))
{ printf 'dn: %s\nchangetype: modify\ndelete: olcAccess\nolcAccess: {%s}\nolcAccess: {%s}\n-\nadd: olcAccess\n' "$maindb" "$b" "$a"
  printf '%s\n' "$(nth "$b" | sed -e "s/^olcAccess: {[0-9]*}/olcAccess: {${a}}/")"
  printf '%s\n' "$(nth "$a" | sed -e "s/^olcAccess: {[0-9]*}/olcAccess: {${b}}/")"; } | cfg_apply
breakage "swapped rules {${a}} and {${b}}"
restore_acl "${dump}.good"
run_chk --container "$c"
expect_rc "restored after the swap" 0 "$rc"

echo "=== 2b. the W_data secrets rule removed ==="
s=$((idx_first + 2))
printf 'dn: %s\nchangetype: modify\ndelete: olcAccess\nolcAccess: {%s}\n' "$maindb" "$s" | cfg_apply
breakage "secrets rule {${s}} removed"
restore_acl "${dump}.good"
run_chk --container "$c"
expect_rc "restored after the removal" 0 "$rc"

echo "=== 2c. the W_data fragment applied twice ==="
# The guide's own command refuses a second apply; apply the fragment shifted behind W_lock (the BASE the guide would compute) to simulate a bypass.
out="$(apply_w write-data.ldif "$wddn")"
case "$out" in *"refusing: "*) ok "the guide's own command refuses a second apply" ;; *) bad "second apply not refused: $out" ;; esac
shift_ldif $((idx_first + 14)) "${fix}/write-data.ldif" | sub_tokens "$wrdn" | cfg_apply
breakage "W_data applied twice"
restore_acl "${dump}.good"
run_chk --container "$c"
expect_rc "restored after the duplicate" 0 "$rc"

echo "=== 3. unreadable source => non-zero ==="
run_chk --container "ldapium-chkacl-nonexistent-${suffix}"
expect_nonzero "no such container" "$rc"

if [ "$fail" -eq 0 ]; then echo "RESULT: all checks passed"; else echo "RESULT: FAILED" >&2; fi
exit "$fail"
