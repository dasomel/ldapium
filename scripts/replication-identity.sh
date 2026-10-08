#!/usr/bin/env bash
# Operator command for the dedicated replication identity (docs/changes/replication-identity,
# #229, T-013: `ensure`, `retire`, and `reconcile`). `rotate` and `rollback-admin`
# are separate units and not implemented here.
#
#   ensure  Create cn=replication-policy,<base> and cn=replicator,<base> once, as ordinary
#           replicated writes with the admin DN, and hand the generated credential over in a
#           new 0600 file (D52, D53). Refuses when either entry already exists, or when ANY
#           rootDN (the admin DN, every stored olcRootDN) equals the reserved DN (D65, REQ-014).
#           The entrypoint never creates it.
#           Partial failure: this run rolls back what it created and deletes the credential
#           file only when the identity is confirmed absent. If the state cannot be determined
#           (connection loss) the file is KEPT and the command says so; check with ldapsearch,
#           then `retire --yes` and `ensure` again if needed. A leftover policy from an
#           earlier run makes ensure refuse; `retire --yes` clears it.
#   retire  Delete both entries. Dedicated nodes lose their bind: consumers stall with rc 49
#           until the entry is recreated, so --yes is required.
#
# Passwords come from files only (#220 convention): never argv, never stdout.
set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 ensure --base DN --admin-password-file FILE --out FILE [--uri URI] [--admin-dn DN] [--root-dn DN]...
       $0 reconcile --base DN --admin-password-file FILE --current-password-file FILE [--uri ldaps://HOST:636]
       $0 retire --base DN --admin-password-file FILE --yes [--uri URI] [--admin-dn DN]

  --uri        LDAP URI of any node (default ldaps://localhost:636; use ldap:// only on a trusted path)
  --admin-dn   default cn=admin,<base>
  --root-dn    extra olcRootDN to compare against (repeatable). Stored olcRootDN values are read with
               slapcat -n 0 (run inside the container); when that is impossible the
               command refuses unless every rootDN is supplied here (operator-asserted)
  --config-dir slapd.d directory read offline with slapcat (default /etc/openldap/slapd.d)
  --out FILE   ensure only: new file (mode 0600) that receives the generated replication password
EOF
}

die() { echo "replication-identity: $*" >&2; exit 1; }

cmd="${1:-}"
case "$cmd" in
  ensure|retire|reconcile) shift ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac

uri="ldaps://localhost:636"
base=""
admin_dn=""
pwfile=""
out=""
current_file=""
yes=0
extra_roots=()
config_dir="/etc/openldap/slapd.d"   # image CONFIG_DIR
while [ $# -gt 0 ]; do
  case "$1" in
    --uri) uri="${2:?--uri needs a value}"; shift 2 ;;
    --base) base="${2:?--base needs a DN}"; shift 2 ;;
    --admin-dn) admin_dn="${2:?--admin-dn needs a DN}"; shift 2 ;;
    --admin-password-file) pwfile="${2:?--admin-password-file needs a file}"; shift 2 ;;
    --root-dn) extra_roots+=("${2:?--root-dn needs a DN}"); shift 2 ;;
    --config-dir) config_dir="${2:?--config-dir needs a directory}"; shift 2 ;;
    --current-password-file) current_file="${2:?--current-password-file needs a file}"; shift 2 ;;
    --out) out="${2:?--out needs a file}"; shift 2 ;;
    --yes) yes=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[ -n "$base" ] || die "--base is required"
if [ -z "$pwfile" ] || [ ! -r "$pwfile" ]; then die "--admin-password-file must name a readable file"; fi
case "$base" in *'"'*|*\\*|*$'\n'*) die "--base contains a character this command refuses" ;; esac
[ -n "$admin_dn" ] || admin_dn="cn=admin,${base}"
for t in ldapsearch ldapadd ldapdelete ldapmodify ldapwhoami slappasswd slapdn slapcat; do command -v "$t" >/dev/null 2>&1 || die "$t is required"; done

iddn="cn=replicator,${base}"
poldn="cn=replication-policy,${base}"

# DN equivalence is slapd's (slapdn -N on a throwaway stock-schema config, as image/entrypoint.sh
# does): case, spaces and \2c escapes compare equal. A DN that cannot be parsed fails closed.
dn_norm() {
  local c o
  c=$(mktemp) || return 1
  printf 'include /etc/openldap/schema/core.schema\ninclude /etc/openldap/schema/cosine.schema\ninclude /etc/openldap/schema/inetorgperson.schema\n' > "$c"
  o=$(slapdn -f "$c" -N "$1" 2>/dev/null) || { rm -f "$c"; return 1; }
  rm -f "$c"
  case "$o" in *$'\n'*) return 1 ;; ?*=?*) ;; *) return 1 ;; esac
  printf '%s\n' "$o"
}

ldap_args=(-x -H "$uri" -D "$admin_dn" -y "$pwfile")
# probe: 0 = exists, 1 = absent, 2 = cannot tell
probe() {
  local rc=0
  ldapsearch "${ldap_args[@]}" -LLL -b "$1" -s base dn >/dev/null 2>&1 || rc=$?
  case "$rc" in 0) return 0 ;; 32) return 1 ;; *) return 2 ;; esac
}
exists() {
  local r=0
  probe "$1" || r=$?
  case "$r" in 0) return 0 ;; 1) return 1 ;; *) die "cannot read $1; check --uri, TLS trust and the admin credentials" ;; esac
}

# REQ-014/D65: the reserved DN must be no rootDN, whatever its spelling. Stored olcRootDN values
# come from cn=config via offline slapcat (-n 0); without them every rootDN must be given by the operator.
want="$(dn_norm "$iddn")" || die "cannot normalise ${iddn}"
roots=("$admin_dn" ${extra_roots[@]+"${extra_roots[@]}"})
if stored="$(slapcat -F "$config_dir" -n 0 -o ldif-wrap=no 2>/dev/null | grep '^olcRootDN:')" && [ -n "$stored" ]; then
  while IFS= read -r line; do
    case "$line" in 'olcRootDN:: '*) die "a stored olcRootDN is base64-encoded; cannot compare it, refusing (D65)" ;; esac
    case "$line" in 'olcRootDN: '*) roots+=("${line#olcRootDN: }") ;; esac
  done <<<"$stored"
elif [ ${#extra_roots[@]} -eq 0 ]; then
  die "cannot read the stored olcRootDN values (slapcat -n 0 failed; run this inside the container) and no --root-dn was given; refusing instead of guessing (D65)"
fi
for r in "${roots[@]}"; do
  got="$(dn_norm "$r")" || die "cannot normalise the rootDN '${r}'; refusing"
  [ "$got" != "$want" ] || die "a rootDN equals the reserved replication identity DN ${iddn}; it would bypass the identity ACL (D65)"
done

if [ "$cmd" = reconcile ]; then
  # D67: the operator isolates the restored node before reconciling. This command never
  # starts peers or deletes old hashes; failure leaves the cluster isolated for inspection.
  case "$uri" in ldaps://*) ;; *) die "reconcile requires verified LDAPS" ;; esac
  [ "${LDAPTLS_REQCERT:-demand}" = demand ] || die "reconcile requires LDAPTLS_REQCERT=demand"
  export LDAPTLS_REQCERT=demand
  [ -n "$current_file" ] && [ -f "$current_file" ] && [ -r "$current_file" ] || die "--current-password-file must name a readable regular file"
  # Check exact bytes, including trailing LF/NUL, rather than shell command substitution.
  total=$(wc -c < "$current_file" | tr -d ' ')
  printable=$(LC_ALL=C tr -cd '\040-\176' < "$current_file" | wc -c | tr -d ' ')
  distinct=$(LC_ALL=C fold -w1 < "$current_file" | sort -u | wc -l | tr -d ' ')
  [ "$total" = "$printable" ] && [ "$total" -ge 32 ] && [ "$distinct" -ge 10 ] || die "current credential fails byte hygiene (not proof of randomness)"
  cmp -s "$current_file" "$pwfile" && die "current replication credential must differ from administrator credential"
  unsafe=$(LC_ALL=C tr -cd '\042\134' < "$current_file" | wc -c | tr -d ' ')
  [ "$unsafe" = 0 ] || die "current credential contains quote or backslash unsupported by dedicated mode"
  exists "$iddn" || die "identity missing; reconcile cannot create it"
  exists "$poldn" || die "policy missing; reconcile cannot create it"
  if ! ldapwhoami -x -H "$uri" -D "$iddn" -y "$current_file" >/dev/null 2>&1; then
    hash=$(slappasswd -T "$current_file") || die "cannot hash current credential"
    rc=0
    ldapmodify "${ldap_args[@]}" >/dev/null 2>&1 <<EOF || rc=$?
dn: ${iddn}
changetype: modify
add: userPassword
userPassword: ${hash}
EOF
    unset hash
    # D67: ambiguous/lost responses are resolved by the real bind, not write exit status.
    ldapwhoami -x -H "$uri" -D "$iddn" -y "$current_file" >/dev/null 2>&1 || die "current credential does not bind after reconcile (modify rc ${rc}); keep peers stopped"
  fi
  echo "reconciled current credential; verified TLS identity bind. Keep peers stopped until the identity check passes."
elif [ "$cmd" = ensure ]; then
  [ -n "$out" ] || die "--out is required (the generated password is written there, never printed)"
  if [ -e "$out" ] || [ -L "$out" ]; then die "--out ${out} already exists (or is a symlink); refusing to overwrite a credential file"; fi
  if exists "$iddn" || exists "$poldn"; then
    die "${iddn} or ${poldn} already exists (a partial earlier run?); run retire --yes first (rotation is a separate command)"
  fi
  # 43 alphanumerics from the OS CSPRNG (~256 bits); passes the entrypoint hygiene rule.
  idpw="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 43 || true)"
  [ "${#idpw}" -eq 43 ] || die "could not generate a password"

  pending=0   # the credential file exists and the identity entry is not confirmed yet
  settled_ok=0
  # Decide by directory state, not by flags. Preconditions above proved both entries were absent
  # before this run, so an entry that exists now and cannot be shown to be ours is reported, never
  # deleted. Identity present AND binding with the generated password = ours: keep file, success.
  # Identity confirmed absent: delete the file and the policy (absent before, present now).
  # Anything else: keep the file and say so.
  settle() {
    local r=0
    [ "$pending" = 1 ] || return 0
    pending=0
    probe "$iddn" || r=$?
    case "$r" in
      0)
        if ldapwhoami -x -H "$uri" -D "$iddn" -y "$out" >/dev/null 2>&1; then
          settled_ok=1
        else
          echo "replication-identity: ${iddn} exists but the generated password does not bind (created by someone else, or not replicated yet); ${out} was KEPT, nothing was deleted. Inspect, then retire --yes and ensure again" >&2
        fi ;;
      1)
        rm -f "$out"
        if probe "$poldn"; then
          ldapdelete "${ldap_args[@]}" "$poldn" >/dev/null 2>&1 || echo "replication-identity: could not remove ${poldn}; run retire --yes" >&2
        fi ;;
      *) echo "replication-identity: state of ${iddn} unknown; ${out} was KEPT. Check with ldapsearch, then retire --yes and ensure again if it is absent" >&2 ;;
    esac
  }
  # shellcheck disable=SC2317,SC2329 # invoked via the traps
  on_exit() { trap - EXIT; settle; }
  trap on_exit EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  # ONE descriptor from an exclusive create (noclobber = O_EXCL, never follows a planted link,
  # mode 0600 from the umask); the password is written through it, never by path again.
  old_umask="$(umask)"
  umask 077
  set -C
  { exec 3>"$out"; } 2>/dev/null || { set +C; umask "$old_umask"; die "cannot create ${out} exclusively"; }
  set +C
  umask "$old_umask"
  pending=1
  printf '%s' "$idpw" >&3 || die "cannot write ${out}"
  exec 3>&-

  ldapadd "${ldap_args[@]}" >/dev/null <<EOF || die "adding the policy failed"
dn: ${poldn}
objectClass: device
objectClass: pwdPolicy
cn: replication-policy
pwdAttribute: userPassword
pwdLockout: FALSE
pwdMaxAge: 0
pwdAllowUserChange: FALSE
EOF
  add_rc=0
  ldapadd "${ldap_args[@]}" >/dev/null <<EOF || add_rc=$?
dn: ${iddn}
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: replicator
userPassword: ${idpw}
pwdPolicySubentry: ${poldn}
EOF
  settle
  [ "$settled_ok" = 1 ] || die "ensure did not complete (ldapadd rc ${add_rc}); see above"
  [ "$add_rc" = 0 ] || echo "replication-identity: ldapadd reported rc ${add_rc} but the identity exists and binds with the generated password; credential file valid" >&2
  echo "created ${iddn} and ${poldn}; replication password written to ${out} (mode 0600)"
else
  [ "$yes" = 1 ] || die "retire stalls every dedicated consumer (rc 49) until the identity is recreated; pass --yes"
  if exists "$iddn"; then ldapdelete "${ldap_args[@]}" "$iddn" >/dev/null; fi
  if exists "$poldn"; then ldapdelete "${ldap_args[@]}" "$poldn" >/dev/null; fi
  echo "retired ${iddn} and ${poldn}"
fi
