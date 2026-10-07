#!/usr/bin/env bash
# Live test for scripts/replication-identity.sh ensure|retire (docs/changes/replication-identity,
# #229, T-013 unit 1) against a real slapd; nothing is mocked except two throwaway ldapadd shims
# that inject a failure on the command's own second write. The command runs inside the container
# (ldap-utils, slapdn and bash are in the image, and slapcat -n 0 reads the stored olcRootDN there).
#
# Usage: scripts/test/test-replication-identity-ensure.sh [image]   (default ldapium:e2e)
# Resources are named ldapium-ridens-* and only those are removed on exit.
set -euo pipefail
# Never pipe into `grep -q` (SIGPIPE + pipefail): match captured variables.

image="${1:-ldapium:e2e}"
here="$(cd "$(dirname "$0")/.." && pwd)"
suffix="$$"
pw="ridensAdminPw-Zq7Lm2Xv9Kd4Hs8Wt1Bn6Rc3Yf5Ug0Pe"
base="dc=example,dc=org"
admin="cn=admin,${base}"
iddn="cn=replicator,${base}"
poldn="cn=replication-policy,${base}"
n="ldapium-ridens-n-${suffix}"
r="ldapium-ridens-r-${suffix}"   # a server whose rootDN IS the reserved DN

fail=0
ok() { printf 'PASS: %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: expected '$2', got '$3'"; fi; }

# shellcheck disable=SC2317,SC2329 # invoked via the trap below
cleanup() {
  trap - EXIT
  docker rm -fv "$n" "$r" >/dev/null 2>&1 || true
  docker volume rm -f "${n}-cfg" "${n}-data" "${r}-cfg" "${r}-data" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

start() { # name extra-env...
  local name="$1"; shift
  docker volume create "${name}-cfg" >/dev/null
  docker volume create "${name}-data" >/dev/null
  docker run -d --name "$name" -v "${name}-cfg:/etc/openldap/slapd.d" -v "${name}-data:/var/lib/openldap/data" \
    -e LDAP_ROOT_DN="$base" -e LDAP_ADMIN_PASSWORD="$pw" "$@" "$image" >/dev/null
  local w=0
  until docker exec "$name" ldapwhoami -x -H ldap://localhost >/dev/null 2>&1; do
    sleep 1; w=$((w + 1)); [ "$w" -lt 120 ] || { echo "$name never ready" >&2; docker logs "$name" 2>&1 | tail -n 20 >&2; exit 1; }
  done
  docker cp "${here}/replication-identity.sh" "${name}:/tmp/replication-identity.sh"
  # exact bytes: ldap -y does not strip a trailing newline
  docker exec "$name" sh -c "umask 077; printf '%s' '$pw' > /tmp/admin.pw"
}
start "$n"
start "$r" -e "LDAP_ADMIN_DN=${iddn}"

rc() { local x=0; "$@" >/dev/null 2>&1 || x=$?; echo "$x"; }
# search that must succeed (set -e would abort the test on a tool error, which is a failure)
asearch() { docker exec "$n" ldapsearch -x -LLL -H ldap://localhost -D "$admin" -y /tmp/admin.pw "$@"; }
# number of entries at a base-scope DN: rc 0 -> 1, rc 32 (no such object) -> 0, anything else aborts
present() {
  local x=0
  asearch -b "$1" -s base dn >/dev/null 2>&1 || x=$?
  case "$x" in 0) echo 1 ;; 32) echo 0 ;; *) echo "present($1): ldapsearch rc $x" >&2; exit 1 ;; esac
}
ri() { docker exec "$n" bash /tmp/replication-identity.sh "$@" --uri ldap://localhost --base "$base" --admin-password-file /tmp/admin.pw; }
file_exists() { check "$1" "$2" "$(rc docker exec "$n" test -e "$3")"; } # label 0|1 path

# --- D65 refusals on a CLEAN directory (no entry exists, so only the DN check can refuse) -----
check "clean state: both entries absent" "0:0" "$(present "$iddn"):$(present "$poldn")"
out="$(docker exec "$n" bash /tmp/replication-identity.sh ensure --uri ldap://localhost --base "$base" --admin-dn "CN=Replicator, ${base}" --admin-password-file /tmp/admin.pw --out /tmp/d1.pw 2>&1 || true)"
check "admin DN spelled differently (case, space) is refused by the DN check" "1" "$(grep -c 'a rootDN equals the reserved' <<<"$out" || true)"
out="$(docker exec "$n" bash /tmp/replication-identity.sh ensure --uri ldap://localhost --base "$base" --admin-dn "cn=replicator,dc=example,dc=org" --admin-password-file /tmp/admin.pw --out /tmp/d1.pw 2>&1 || true)"
check "equal admin DN is refused" "1" "$(grep -c 'a rootDN equals the reserved' <<<"$out" || true)"
out="$(docker exec "$n" bash /tmp/replication-identity.sh ensure --uri ldap://localhost --base "$base" --root-dn "cn=replicator\\,x" --root-dn "CN = replicator , dc=example, dc=org" --admin-password-file /tmp/admin.pw --out /tmp/d1.pw 2>&1 || true)"
check "an equivalent --root-dn spelling is refused" "1" "$(grep -c 'a rootDN equals the reserved' <<<"$out" || true)"
# a stored olcRootDN equal to the reserved DN, while --admin-dn is a different DN
out="$(docker exec "$r" bash /tmp/replication-identity.sh ensure --uri ldap://localhost --base "$base" --admin-dn "cn=other,${base}" --admin-password-file /tmp/admin.pw --out /tmp/d2.pw 2>&1 || true)"
check "stored olcRootDN = reserved DN is refused although --admin-dn differs" "1" "$(grep -c 'a rootDN equals the reserved' <<<"$out" || true)"
check "the refusals left no credential file" "1:1" "$(rc docker exec "$n" test -e /tmp/d1.pw):$(rc docker exec "$r" test -e /tmp/d2.pw)"
check "the refusals created nothing" "0:0" "$(present "$iddn"):$(present "$poldn")"

# --- --out handling ---------------------------------------------------------------------------
docker exec "$n" sh -c 'ln -s /tmp/victim /tmp/dangling.pw; echo keep > /tmp/old.pw; chmod 644 /tmp/old.pw'
check "dangling symlink --out: ensure is refused" "1" "$(rc ri ensure --out /tmp/dangling.pw)"
file_exists "the symlink target was not created" 1 /tmp/victim
check "existing --out: ensure is refused" "1" "$(rc ri ensure --out /tmp/old.pw)"
check "existing --out: content and mode untouched" "keep:644" "$(docker exec "$n" cat /tmp/old.pw):$(docker exec "$n" stat -c %a /tmp/old.pw)"
docker exec "$n" sh -c 'ln -s /tmp/old.pw /tmp/link.pw'
check "symlink to an existing file as --out: ensure is refused" "1" "$(rc ri ensure --out /tmp/link.pw)"
check "...and the linked file is untouched" "keep:644" "$(docker exec "$n" cat /tmp/old.pw):$(docker exec "$n" stat -c %a /tmp/old.pw)"
check "out-refusals created nothing" "0:0" "$(present "$iddn"):$(present "$poldn")"

# --- ensure -----------------------------------------------------------------------------------
check "ensure succeeds" "0" "$(rc ri ensure --out /tmp/id.pw)"
check "credential file is mode 600" "600" "$(docker exec "$n" stat -c %a /tmp/id.pw)"
idpw="$(docker exec "$n" cat /tmp/id.pw)"
check "generated password is 43 chars, >=10 distinct, alnum" "ok" \
  "$([ "${#idpw}" -eq 43 ] && [ "$(fold -w1 <<<"$idpw" | sort -u | wc -l | tr -d ' ')" -ge 10 ] && [[ "$idpw" =~ ^[A-Za-z0-9]+$ ]] && echo ok || echo no)"
docker exec "$n" sh -c "umask 077; printf '%s' '$idpw' > /tmp/id.check.pw"
ent="$(asearch -b "$iddn" -s base objectClass pwdPolicySubentry)"
check "identity entry: simpleSecurityObject with explicit pwdPolicySubentry" "1:1" \
  "$(grep -c '^objectClass: simpleSecurityObject' <<<"$ent" || true):$(grep -c "^pwdPolicySubentry: ${poldn}\$" <<<"$ent" || true)"
pol="$(asearch -b "$poldn" -s base pwdLockout pwdMaxAge pwdAllowUserChange)"
check "policy: no lockout, no expiry, no self-change" "FALSE:0:FALSE" \
  "$(sed -n 's/^pwdLockout: //p' <<<"$pol"):$(sed -n 's/^pwdMaxAge: //p' <<<"$pol"):$(sed -n 's/^pwdAllowUserChange: //p' <<<"$pol")"
check "the generated credential binds as the identity" "0" "$(rc docker exec "$n" ldapwhoami -x -H ldap://localhost -D "$iddn" -y /tmp/id.check.pw)"
cfg="$(docker exec "$n" slapcat -n 0)"   # a slapcat failure aborts (set -e) instead of passing vacuously
check "cn=config dump is real (contains the config root)" "1" "$(grep -c '^dn: cn=config$' <<<"$cfg" || true)"
check "the password is not in stored cn=config" "0" "$(grep -c -F "$idpw" <<<"$cfg" || true)"
check "ensure again is refused (entries exist)" "1" "$(rc ri ensure --out /tmp/id2.pw)"
file_exists "refused ensure left no credential file" 1 /tmp/id2.pw

# --- retire -----------------------------------------------------------------------------------
check "retire without --yes is refused" "1" "$(rc ri retire)"
check "identity still present after refused retire" "1" "$(present "$iddn")"
check "wrong admin password is refused" "1" \
  "$(rc docker exec "$n" sh -c "printf wrong > /tmp/bad.pw; bash /tmp/replication-identity.sh retire --yes --uri ldap://localhost --base '$base' --admin-password-file /tmp/bad.pw")"
check "retire --yes succeeds" "0" "$(rc ri retire --yes)"
check "both entries are gone (search rc 32, not a tool error)" "0:0" "$(present "$iddn"):$(present "$poldn")"
check "retire again is a no-op success" "0" "$(rc ri retire --yes)"

# --- partial failures (ldapadd shim: 1st call real, 2nd call per mode) ----------------------------
shim() { # mode: fail = second call writes nothing and exits 1; lost = second call writes, then exits 255
  docker exec -i "$n" sh -c "mkdir -p /tmp/shim && rm -f /tmp/shim/count && cat > /tmp/shim/ldapadd" <<EOF
#!/bin/sh
c=\$(cat /tmp/shim/count 2>/dev/null || echo 0); echo \$((c + 1)) > /tmp/shim/count
if [ "\$c" -eq 0 ]; then exec /usr/bin/ldapadd "\$@"; fi
if [ "$1" = fail ]; then cat >/dev/null; exit 1; fi
if [ "$1" = foreign ]; then sed 's/^userPassword: .*/userPassword: someoneElsesPassword0123456789abcdefgh/' | /usr/bin/ldapadd "\$@"; exit 255; fi
/usr/bin/ldapadd "\$@"; exit 255
EOF
  docker exec "$n" chmod 755 /tmp/shim/ldapadd
}
ri_shim() { docker exec "$n" env PATH="/tmp/shim:/usr/sbin:/usr/bin:/sbin:/bin" bash /tmp/replication-identity.sh "$@" --uri ldap://localhost --base "$base" --admin-password-file /tmp/admin.pw; }

shim fail
check "identity add fails: ensure fails" "1" "$(rc ri_shim ensure --out /tmp/p1.pw)"
check "identity add fails: both adds were attempted (shim reached)" "2" "$(docker exec "$n" cat /tmp/shim/count)"
check "identity add fails: policy rolled back, nothing left" "0:0" "$(present "$iddn"):$(present "$poldn")"
file_exists "identity add fails: credential file removed (identity confirmed absent)" 1 /tmp/p1.pw
check "after the rollback a plain ensure works (re-run is well defined)" "0" "$(rc ri ensure --out /tmp/p1.pw)"
check "retire clears it" "0" "$(rc ri retire --yes)"

shim lost
check "write landed but ldapadd reported failure: ensure treats it as success" "0" "$(rc ri_shim ensure --out /tmp/p2.pw)"
check "...and the identity exists" "1" "$(present "$iddn")"
file_exists "...and the credential file was KEPT, not deleted" 0 /tmp/p2.pw
docker exec "$n" sh -c "tr -d '\\n' < /tmp/p2.pw > /tmp/p2.check.pw"
check "...and the kept password binds" "0" "$(rc docker exec "$n" ldapwhoami -x -H ldap://localhost -D "$iddn" -y /tmp/p2.check.pw)"
check "retire clears it again" "0" "$(rc ri retire --yes)"

shim foreign
check "identity created by someone else with another password: ensure fails" "1" "$(rc ri_shim ensure --out /tmp/p3.pw)"
check "...the foreign identity is NOT deleted" "1" "$(present "$iddn")"
file_exists "...the credential file is KEPT (state not provably ours)" 0 /tmp/p3.pw
check "...the generated password does not bind" "49" "$(rc docker exec "$n" ldapwhoami -x -H ldap://localhost -D "$iddn" -y /tmp/p3.pw)"
check "retire clears the foreign entry on request" "0" "$(rc ri retire --yes)"
check "ensure after retire gives a NEW password" "1" "$(rc ri ensure --out /tmp/id3.pw >/dev/null; [ "$(docker exec "$n" cat /tmp/id3.pw)" != "$idpw" ] && echo 1 || echo 0)"
check "the old password no longer binds (rc 49)" "49" "$(rc docker exec "$n" ldapwhoami -x -H ldap://localhost -D "$iddn" -y /tmp/id.check.pw)"

if [ "$fail" = 0 ]; then echo "ALL PASS"; else echo "FAILURES" >&2; exit 1; fi
