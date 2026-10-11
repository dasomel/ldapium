#!/usr/bin/env bash
# Operator command for the dedicated replication identity (docs/changes/replication-identity,
# #229, T-013: `ensure`, `retire`, `reconcile`, `rotate`, and `rollback-admin`).
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
#   rotate  Rolling credential rotation (D55, R0-R4). State is derived, never stored: the number
#           of userPassword values on the identity and, per node (--uri plus every --peer), the
#           credential fingerprint of the stored consumer olcSyncrepl rows (cn=config, read with
#           cn=admin,cn=config). R0 one value, new not present: add the new hash. R1/R2 two or
#           more values, not every node's consumer carries the new credential yet: exit 3, roll
#           the consumers, re-run. R3 every node carries it: replace with the new value only.
#           R4 one value, new binds: done. Re-running resumes at the derived step. The old value
#           is never removed while the gate is closed. --new-password-file is generated (0600)
#           when it does not exist yet and reused on every re-run.
#   rollback-admin
#           Gate before returning to administrator replication (D66): refuses unless every node
#           (--uri plus every --peer) answers the administrator password, holds the suffix entry
#           (non-empty) and is not resyncing (same contextCSN set and entry count on every
#           node, unchanged between two samples). Changes nothing; on success it prints the
#           remaining operator steps (chart values / environment, DN and Secret together).
#   retire  Delete both entries. Dedicated nodes lose their bind: consumers stall with rc 49
#           until the entry is recreated, so --yes is required.
#
# Passwords come from files only (#220 convention): never argv, never stdout.
set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 ensure --base DN --admin-password-file FILE --out FILE [--uri URI] [--admin-dn DN] [--root-dn DN]...
       $0 reconcile --base DN --admin-password-file FILE --current-password-file FILE [--uri ldaps://HOST:636]
       $0 rotate --base DN --admin-password-file FILE --new-password-file FILE [--peer ldaps://HOST:636]... [--uri ldaps://HOST:636] [--config-password-file FILE]
       $0 rollback-admin --base DN --admin-password-file FILE [--peer ldaps://HOST:636]... [--uri ldaps://HOST:636]
       $0 retire --base DN --admin-password-file FILE --yes [--uri URI] [--admin-dn DN]

  --uri        LDAP URI of any node (default ldaps://localhost:636; use ldap:// only on a trusted path)
  --admin-dn   default cn=admin,<base>
  --root-dn    extra olcRootDN to compare against (repeatable). Stored olcRootDN values are read with
               slapcat -n 0 (run inside the container); when that is impossible the
               command refuses unless every rootDN is supplied here (operator-asserted)
  --config-dir slapd.d directory read offline with slapcat (default /etc/openldap/slapd.d)
  --peer URI   rotate/rollback-admin: another node (repeatable); list EVERY node of the cluster
  --config-password-file FILE   rotate: password of cn=admin,cn=config (default: --admin-password-file)
  --new-password-file FILE      rotate: new replication credential (created 0600 when missing)
                                rotate exit codes: 0 done or progressed, 3 waiting for consumers, 1 refused/failed
  --out FILE   ensure only: new file (mode 0600) that receives the generated replication password
EOF
}

die() { echo "replication-identity: $*" >&2; exit 1; }

cmd="${1:-}"
case "$cmd" in
  ensure|retire|reconcile|rotate|rollback-admin) shift ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac

uri="ldaps://localhost:636"
base=""
admin_dn=""
pwfile=""
out=""
current_file=""
new_file=""
config_pwfile=""
peers=()
yes=0
extra_roots=()
config_dir="/etc/openldap/slapd.d"   # image CONFIG_DIR
config_dn="cn=admin,cn=config"
while [ $# -gt 0 ]; do
  case "$1" in
    --uri) uri="${2:?--uri needs a value}"; shift 2 ;;
    --base) base="${2:?--base needs a DN}"; shift 2 ;;
    --admin-dn) admin_dn="${2:?--admin-dn needs a DN}"; shift 2 ;;
    --admin-password-file) pwfile="${2:?--admin-password-file needs a file}"; shift 2 ;;
    --root-dn) extra_roots+=("${2:?--root-dn needs a DN}"); shift 2 ;;
    --config-dir) config_dir="${2:?--config-dir needs a directory}"; shift 2 ;;
    --current-password-file) current_file="${2:?--current-password-file needs a file}"; shift 2 ;;
    --new-password-file) new_file="${2:?--new-password-file needs a file}"; shift 2 ;;
    --config-password-file) config_pwfile="${2:?--config-password-file needs a file}"; shift 2 ;;
    --peer) peers+=("${2:?--peer needs a URI}"); shift 2 ;;
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

# Verified LDAPS only: the identity credential and the administrator password never cross a clear or unverified link.
require_verified_tls() {
  # One plain ldaps://host[:port] per value: a space/comma list or any URI with a path or
  # options would let the client fall back to a clear URI after a failed LDAPS connect.
  local u
  for u in "$uri" ${peers[@]+"${peers[@]}"}; do
    [[ "$u" =~ ^ldaps://[A-Za-z0-9._-]+(:[0-9]{1,5})?$ ]] || die "$cmd requires exactly one verified ldaps://host[:port] URI per value (got '${u}')"
  done
  [ "${LDAPTLS_REQCERT:-demand}" = demand ] || die "$cmd requires LDAPTLS_REQCERT=demand"
  export LDAPTLS_REQCERT=demand
}
# Check exact bytes, including trailing LF/NUL, rather than shell command substitution.
credential_hygiene() { # file label
  local f="$1" total printable distinct unsafe
  if [ ! -f "$f" ] || [ ! -r "$f" ]; then die "$2 must name a readable regular file"; fi
  total=$(wc -c < "$f" | tr -d ' ')
  printable=$(LC_ALL=C tr -cd '\041-\176' < "$f" | wc -c | tr -d ' ')
  distinct=$(LC_ALL=C fold -w1 < "$f" | sort -u | wc -l | tr -d ' ')
  if [ "$total" != "$printable" ] || [ "$total" -lt 32 ] || [ "$distinct" -lt 10 ]; then
    die "$2 fails byte hygiene (not proof of randomness)"
  fi
  cmp -s "$f" "$pwfile" && die "$2 must differ from administrator credential"
  unsafe=$(LC_ALL=C tr -cd '\042\134' < "$f" | wc -c | tr -d ' ')
  [ "$unsafe" = 0 ] || die "$2 contains quote or backslash unsupported by dedicated mode"
}

if [ "$cmd" = reconcile ]; then
  # D67: the operator isolates the restored node before reconciling. This command never
  # starts peers or deletes old hashes; failure leaves the cluster isolated for inspection.
  require_verified_tls
  credential_hygiene "$current_file" "--current-password-file"
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
elif [ "$cmd" = rotate ]; then
  require_verified_tls
  command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"
  [ -n "$new_file" ] || die "--new-password-file is required (created 0600 when missing)"
  [ -n "$config_pwfile" ] || config_pwfile="$pwfile"
  if [ ! -r "$config_pwfile" ]; then die "--config-password-file must name a readable file"; fi
  if [ ! -e "$new_file" ] && [ ! -L "$new_file" ]; then
    # 43 alphanumerics from the OS CSPRNG, created exclusively (O_EXCL) with mode 0600, as ensure does.
    newpw="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 43 || true)"
    [ "${#newpw}" -eq 43 ] || die "could not generate a password"
    old_umask="$(umask)"
    umask 077
    set -C
    { exec 3>"$new_file"; } 2>/dev/null || { set +C; umask "$old_umask"; die "cannot create ${new_file} exclusively"; }
    set +C
    umask "$old_umask"
    printf '%s' "$newpw" >&3 || die "cannot write ${new_file}"
    exec 3>&-
    unset newpw
    echo "generated the new replication credential in ${new_file} (mode 0600); keep it, a re-run resumes with it"
  fi
  credential_hygiene "$new_file" "--new-password-file"
  exists "$iddn" || die "identity missing; rotate cannot create it (use ensure)"
  nodes=("$uri" ${peers[@]+"${peers[@]}"})
  newfp="$(sha256sum < "$new_file" | cut -d' ' -f1)"

  value_count() {
    local o
    o=$(ldapsearch "${ldap_args[@]}" -LLL -o ldif-wrap=no -b "$iddn" -s base userPassword 2>/dev/null) || return 1
    awk '/^userPassword:/{n++} END {print n+0}' <<<"$o"
  }
  new_binds() { ldapwhoami -x -H "$1" -D "$iddn" -y "$new_file" >/dev/null 2>&1; }
  # new = every stored consumer row of the identity carries the new credential; old = at least one
  # row does not; none = no consumer row binds as the identity (admin-mode node). rc 2 = unreadable.
  consumer_state() {
    local out line val bd cred rows=0 hit=0
    out=$(ldapsearch -x -H "$1" -D "$config_dn" -y "$config_pwfile" -LLL -o ldif-wrap=no -b cn=config '(olcSyncrepl=*)' olcSyncrepl 2>/dev/null) || return 2
    while IFS= read -r line; do
      case "$line" in
        'olcSyncrepl:: '*) val=$(printf '%s' "${line#olcSyncrepl:: }" | base64 -d 2>/dev/null) || val="" ;;
        'olcSyncrepl: '*) val="${line#olcSyncrepl: }" ;;
        *) continue ;;
      esac
      bd=$(printf '%s' "$val" | sed -n 's/.*binddn="\([^"]*\)".*/\1/p')
      [ -n "$bd" ] && [ "$(dn_norm "$bd" || true)" = "$want" ] || continue
      rows=$((rows + 1))
      cred=$(printf '%s' "$val" | sed -n 's/.* credentials="\([^"]*\)".*/\1/p')
      if [ "$(printf '%s' "$cred" | sha256sum | cut -d' ' -f1)" = "$newfp" ]; then hit=$((hit + 1)); fi
    done <<<"$out"
    if [ "$rows" -eq 0 ]; then echo none; elif [ "$hit" -eq "$rows" ]; then echo new; else echo old; fi
  }
  # The gate: on every node the new credential binds as the identity (so it replicated) AND the
  # stored consumer configuration carries it. One fixed line per node; never a credential.
  gate_open=1
  gate_check() {
    local n s b r
    gate_open=1
    for n in "${nodes[@]}"; do
      r=0
      s=$(consumer_state "$n") || r=$?
      [ "$r" = 0 ] || die "cannot read cn=config on ${n}; check --config-password-file and TLS trust; the gate stays closed"
      if new_binds "$n"; then b=binds; else b="does-not-bind"; gate_open=0; fi
      [ "$s" = new ] || gate_open=0
      echo "  ${n}: consumer credential=${s}, new credential ${b}"
    done
  }

  count=$(value_count) || die "cannot read userPassword values of ${iddn}"
  [ "$count" -ge 1 ] || die "${iddn} has no userPassword value; use ensure/reconcile"
  if new_binds "$uri"; then bound=1; else bound=0; fi
  if [ "$count" -eq 1 ] && [ "$bound" = 0 ]; then
    echo "R0: one credential value, the new one is not present; adding it (the old value stays)"
    hash=$(slappasswd -T "$new_file") || die "cannot hash the new credential"
    rc=0
    ldapmodify "${ldap_args[@]}" >/dev/null 2>&1 <<EOT || rc=$?
dn: ${iddn}
changetype: modify
add: userPassword
userPassword: ${hash}
EOT
    unset hash
    # Ambiguous or lost responses are resolved by the directory, not by the write's exit status.
    count=$(value_count) || die "cannot read userPassword values after the add (rc ${rc}); re-run to resume"
    if [ "$count" -lt 2 ] || ! new_binds "$uri"; then die "the new value is not confirmed (modify rc ${rc}); re-run to resume"; fi
    echo "R1: the new value is added; the old value is still valid. Next: restart each consumer with the new credential, then re-run this command."
    echo "Rollback until R3: restore the old credential on the consumers and restart them; the old value is still in the entry."
    exit 3
  elif [ "$count" -ge 2 ] && [ "$bound" = 1 ]; then
    echo "${count} credential values; checking ${#nodes[@]} node(s)"
    gate_check
    if [ "$gate_open" != 1 ]; then
      echo "R2: the gate is closed, so the old value is NOT removed. Restart the consumers listed above with the new credential and re-run this command." >&2
      echo "Rollback until R3: restore the old credential on the consumers and restart them; the old value is still in the entry." >&2
      exit 3
    fi
    echo "R3: every node carries the new credential; removing the old value"
    hash=$(slappasswd -T "$new_file") || die "cannot hash the new credential"
    rc=0
    ldapmodify "${ldap_args[@]}" >/dev/null 2>&1 <<EOT || rc=$?
dn: ${iddn}
changetype: modify
replace: userPassword
userPassword: ${hash}
EOT
    unset hash
    count=$(value_count) || die "cannot read userPassword values after the removal (rc ${rc}); re-run to resume"
    if [ "$count" -ne 1 ] || ! new_binds "$uri"; then die "the removal is not confirmed (modify rc ${rc}); re-run to resume"; fi
    echo "R4: rotation complete; the entry holds only the new credential."
    echo "Rollback after R4: reconcile --current-password-file <old credential file> re-adds the old value (consumers still on it stall with rc 49 until then)."
  elif [ "$count" -eq 1 ] && [ "$bound" = 1 ]; then
    echo "one credential value, the new one; checking ${#nodes[@]} node(s)"
    gate_check
    if [ "$gate_open" != 1 ]; then
      die "the old value is already gone but a node does not carry the new credential: it stalls with rc 49 on its next reconnect (premature removal). Restore it with: reconcile --current-password-file <old credential file>, restart the consumers with the new credential, then re-run rotate"
    fi
    echo "R4: rotation complete; nothing to do."
  else
    die "${iddn} holds ${count} values and the new credential does not bind; --new-password-file is not this rotation's credential (or the write has not replicated here); refusing to modify"
  fi
elif [ "$cmd" = rollback-admin ]; then
  require_verified_tls
  nodes=("$uri" ${peers[@]+"${peers[@]}"})
  sample() { # node -> "<sorted contextCSN values>|<entry count>"
    local o c d
    o=$(ldapsearch -x -H "$1" -D "$admin_dn" -y "$pwfile" -LLL -o ldif-wrap=no -b "$base" -s base contextCSN 2>/dev/null) || return 1
    c=$(sed -n 's/^contextCSN: //p' <<<"$o" | sort | tr '\n' ',')
    d=$(ldapsearch -x -H "$1" -D "$admin_dn" -y "$pwfile" -LLL -b "$base" -s sub '(objectClass=*)' 1.1 2>/dev/null) || return 1
    printf '%s|%s\n' "$c" "$(grep -c '^dn:' <<<"$d" || true)"
  }
  for n in "${nodes[@]}"; do
    ldapwhoami -x -H "$n" -D "$admin_dn" -y "$pwfile" >/dev/null 2>&1 || die "the administrator password is not valid on ${n} (D62); a consumer would stall with rc 49 after the switch. Refusing"
    r=0
    ldapsearch -x -H "$n" -D "$admin_dn" -y "$pwfile" -LLL -b "$base" -s base dn >/dev/null 2>&1 || r=$?
    case "$r" in 0) ;; 32) die "${n} is empty (no ${base} entry); administrator mode would mint a new DIT there (E8). Let it resync under dedicated first. Refusing" ;; *) die "cannot read ${base} on ${n}; refusing" ;; esac
  done
  # Two samples a moment apart: a node that is still receiving entries changes between them, and
  # contextCSN alone is not trusted (the entry count must agree too).
  first=(); second=()
  for n in "${nodes[@]}"; do
    s=$(sample "$n") || die "cannot sample ${n}; refusing"
    case "$s" in '|'*|*'|0') die "${n} reports no contextCSN or no entries; it is empty or has not started to sync. Refusing" ;; esac
    first+=("$s")
  done
  sleep 2
  for n in "${nodes[@]}"; do
    s=$(sample "$n") || die "cannot sample ${n}; refusing"
    second+=("$s")
  done
  for i in "${!nodes[@]}"; do
    [ "${first[$i]}" = "${second[$i]}" ] || die "${nodes[$i]} changed between two samples: it is still resyncing or being written. Refusing"
    [ "${first[$i]}" = "${first[0]}" ] || die "${nodes[$i]} differs from ${nodes[0]} in contextCSN values or entry count: it is resyncing or lagging. Refusing"
  done
  echo "rollback gate passed on ${#nodes[@]} node(s): suffix present, administrator password valid, contextCSN set and entry count identical and stable."
  echo "Next (operator): set the chart values / environment to identity=admin so the DN AND the replication Secret leave together (D66), restart nodes one at a time with sid 1 last, then verify writes in both directions."
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
