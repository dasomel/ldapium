#!/bin/sh
# entrypoint.sh — bootstrap (first launch only) then exec slapd as PID 1.
#
# Layout (see image/README.md for the full env var contract):
#   CONFIG_DIR = /etc/openldap/slapd.d   (cn=config, dynamic config backend) — VOLUME
#   DATA_DIR   = /var/lib/openldap/data  (volume mount point)               — VOLUME
#   MDB_DIR    = $DATA_DIR/mdb           (actual mdb files; created & owned
#                                         by us so chmod 700 always applies)
#   RUN_DIR    = /var/lib/openldap/run   (pidfile, argsfile, ldapi socket)
#   BOOTSTRAP  = /usr/local/share/ldapium/bootstrap (baked-in templates, read-only)
#   SEED_DIR   = $LDAP_SEED_DIR, default /opt/ldifs (operator extension point)
#
# First-launch detection: CONFIG_DIR/.bootstrapped marker file.
set -eu

CONFIG_DIR="/etc/openldap/slapd.d"
DATA_DIR="/var/lib/openldap/data"
MDB_DIR="${DATA_DIR}/mdb"
RUN_DIR="/var/lib/openldap/run"
BOOTSTRAP_DIR="/usr/local/share/ldapium/bootstrap"
MARKER="${CONFIG_DIR}/.bootstrapped"

log() { printf '[entrypoint] %s\n' "$*" >&2; }
die() { printf '[entrypoint] ERROR: %s\n' "$*" >&2; exit 1; }

# A command given after the image name is a one-off maintenance task
# (scripts/backup.sh, scripts/restore.sh, a shell) and must not boot the
# directory, so run it before the env contract below is enforced — verify-backup.sh
# for instance needs no LDAP_* variables at all. Without this the arguments are
# discarded in silence and `docker run ldapium /bin/bash /scripts/backup.sh`
# starts a second slapd that never exits. The chart and docker-compose.yml pass
# no arguments, so the server path is unchanged.
if [ "$#" -gt 0 ]; then
  exec "$@"
fi

# ---------------------------------------------------------------------------
# 1. Validate the env contract. Fail fast and loudly — never fall back to a
#    default admin password.
# ---------------------------------------------------------------------------
: "${LDAP_ROOT_DN:?LDAP_ROOT_DN is required, e.g. dc=example,dc=org}"

case "$LDAP_ROOT_DN" in
  dc=*) ;;
  *) die "LDAP_ROOT_DN must start with 'dc=' (got: ${LDAP_ROOT_DN})" ;;
esac

LDAP_ROOT_DC=$(printf '%s' "$LDAP_ROOT_DN" | sed -E 's/^dc=([^,]+),.*/\1/')
LDAP_ORG_NAME="${LDAP_ORG_NAME:-$LDAP_ROOT_DC}"
LDAP_ADMIN_DN="${LDAP_ADMIN_DN:-cn=admin,${LDAP_ROOT_DN}}"

# slapd refuses olcRootPW unless olcRootDN sits under the database suffix, and
# it only says so from inside slapadd, mid-bootstrap: "<olcRootPW> can only be
# set when rootdn is under suffix" — with no hint that LDAP_ADMIN_DN is the
# variable at fault. `helm --set ldap.adminDN=cn=admin,dc=example,dc=org` walks
# straight into it, because helm splits --set on unescaped commas and only
# `cn=admin` survives. Compared case- and space-insensitively, since a DN is
# equal under both.
_admin_dn_cmp=$(printf '%s' "$LDAP_ADMIN_DN" | sed 's/, */,/g' | tr '[:upper:]' '[:lower:]')
_root_dn_cmp=$(printf '%s' "$LDAP_ROOT_DN" | sed 's/, */,/g' | tr '[:upper:]' '[:lower:]')
case "$_admin_dn_cmp" in
  "$_root_dn_cmp"|*",${_root_dn_cmp}") ;;
  *) die "LDAP_ADMIN_DN must sit under LDAP_ROOT_DN (got: ${LDAP_ADMIN_DN}, root: ${LDAP_ROOT_DN}) — if this came from 'helm --set', escape the commas: ldap.adminDN=cn=admin\\,${LDAP_ROOT_DN}" ;;
esac
unset _admin_dn_cmp _root_dn_cmp

case "$LDAP_ADMIN_DN" in
  cn=*) ;;
  *) die "LDAP_ADMIN_DN must use 'cn=' as its RDN attribute (got: ${LDAP_ADMIN_DN})" ;;
esac

LDAP_ADMIN_RDN_VALUE=$(printf '%s' "$LDAP_ADMIN_DN" | sed -E 's/^cn=([^,]+),.*/\1/')

# LDAP_ANONYMOUS_READ_BASE (default empty — no behavior change) narrows
# anonymous read from the whole DIT down to one subtree; see the
# #__ANON_READ_ACCESS__ rendering below and its comment in
# 01-cn-config.ldif for the ACL shape. Same normalization/`die` pattern as
# LDAP_ADMIN_DN above, including the same `helm --set` comma footgun.
LDAP_ANONYMOUS_READ_BASE="${LDAP_ANONYMOUS_READ_BASE:-}"
if [ -n "$LDAP_ANONYMOUS_READ_BASE" ]; then
  _anon_base_cmp=$(printf '%s' "$LDAP_ANONYMOUS_READ_BASE" | sed 's/, */,/g' | tr '[:upper:]' '[:lower:]')
  _root_dn_cmp=$(printf '%s' "$LDAP_ROOT_DN" | sed 's/, */,/g' | tr '[:upper:]' '[:lower:]')
  case "$_anon_base_cmp" in
    "$_root_dn_cmp"|*",${_root_dn_cmp}") ;;
    *) die "LDAP_ANONYMOUS_READ_BASE must sit under LDAP_ROOT_DN (got: ${LDAP_ANONYMOUS_READ_BASE}, root: ${LDAP_ROOT_DN}) — if this came from 'helm --set', escape the commas: ldap.anonymousReadBase=ou=people\\,${LDAP_ROOT_DN}" ;;
  esac
  unset _anon_base_cmp _root_dn_cmp
fi

if [ -n "${LDAP_ADMIN_PASSWORD_FILE:-}" ]; then
  [ -r "$LDAP_ADMIN_PASSWORD_FILE" ] || die "LDAP_ADMIN_PASSWORD_FILE is set but not readable: ${LDAP_ADMIN_PASSWORD_FILE}"
  LDAP_ADMIN_PASSWORD=$(cat "$LDAP_ADMIN_PASSWORD_FILE")
fi
# D40: random credentials are created once on the durable data volume. Existing
# directories must never acquire an unrelated password after a missing Secret.
GENERATED_PASSWORD_DIR="${DATA_DIR}/.credentials"
GENERATED_PASSWORD_FILE="${GENERATED_PASSWORD_DIR}/ldap-admin-password"
if [ -n "${LDAP_ADMIN_PASSWORD_FILE:-}" ]; then
  [ -n "$LDAP_ADMIN_PASSWORD" ] || die "LDAP_ADMIN_PASSWORD_FILE is empty"
elif [ -z "${LDAP_ADMIN_PASSWORD:-}" ]; then
  # D40a: replication binds as rootDN (D3) and the peer checks it against its own
  # rootpw, so every node must share one operator-supplied admin password. A
  # per-node generated value (or an explicit LDAP_REPLICATION_PASSWORD, which
  # still has to match each peer's rootpw) would make syncrepl fail silently.
  case "${LDAP_REPLICATION_ENABLED:-false}" in
    true|1) die "LDAP_REPLICATION_ENABLED requires an explicit shared LDAP_ADMIN_PASSWORD or LDAP_ADMIN_PASSWORD_FILE on every node; a generated per-node admin password would break replication authentication" ;;
  esac
  if [ -L "$GENERATED_PASSWORD_DIR" ] || [ -L "$GENERATED_PASSWORD_FILE" ]; then die "generated credential paths must not be symlinks"; fi
  if [ ! -f "$GENERATED_PASSWORD_FILE" ]; then
    if [ -f "$MARKER" ] || [ -n "$(ls -A "$CONFIG_DIR" 2>/dev/null)" ]; then die "existing LDAP configuration requires its original admin password; supply LDAP_ADMIN_PASSWORD or LDAP_ADMIN_PASSWORD_FILE"; fi
    if [ ! -d "$GENERATED_PASSWORD_DIR" ]; then
      (umask 077; mkdir -m 700 "$GENERATED_PASSWORD_DIR") || die "cannot create private credential directory"
    fi
    [ "$(stat -c '%a:%u' "$GENERATED_PASSWORD_DIR")" = "700:$(id -u)" ] || die "generated credential directory must be private and owned by the LDAP user"
    (umask 077
      temporary=$(mktemp "$GENERATED_PASSWORD_DIR/.admin-XXXXXX")
      trap 'rm -f "$temporary"' EXIT HUP INT TERM
      generated=$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
      [ "${#generated}" = 64 ] || exit 1
      # set -e is off inside this subshell, so check each write explicitly:
      # an empty/short file must never reach the publish step.
      printf '%s' "$generated" > "$temporary" || exit 1
      [ -s "$temporary" ] && [ "$(wc -c < "$temporary" | tr -d ' ')" = 64 ] || exit 1
      # Publishing a complete file by hard link avoids partial reads and races.
      ln "$temporary" "$GENERATED_PASSWORD_FILE" 2>/dev/null || [ -f "$GENERATED_PASSWORD_FILE" ]
    ) || die "cannot generate persistent admin password"
    log "admin password generated; retrieve it with scripts/get-credentials.sh --local"
  fi
  [ "$(stat -c '%a:%u' "$GENERATED_PASSWORD_DIR")" = "700:$(id -u)" ] || die "generated credential directory is not private"
  [ "$(stat -c '%a:%u' "$GENERATED_PASSWORD_FILE")" = "600:$(id -u)" ] || die "generated admin password must be private and owned by the LDAP user"
  LDAP_ADMIN_PASSWORD=$(cat "$GENERATED_PASSWORD_FILE")
fi
[ -n "$LDAP_ADMIN_PASSWORD" ] || die "LDAP_ADMIN_PASSWORD is empty"
# #220: the password reaches slappasswd -T / ldapadd -y through a private file,
# which the LDAP tools read as a single line, so an embedded newline cannot be
# represented. Refuse it rather than let it be silently truncated at bootstrap.
nl='
'
case "$LDAP_ADMIN_PASSWORD" in
  *"$nl"*) die "the admin password must not contain a newline (LDAP tools read passwords from files one line at a time)" ;;
esac

LDAP_LOG_LEVEL="${LDAP_LOG_LEVEL:-stats}"
LDAP_TLS_ENABLED="${LDAP_TLS_ENABLED:-false}"
# Mutual TLS remains opt-in even when TLS is enabled: `try` asks clients for a
# certificate without making one a prerequisite for the TLS handshake, so
# existing password/simple-bind clients keep working unchanged.
LDAP_TLS_MUTUAL_AUTH="${LDAP_TLS_MUTUAL_AUTH:-false}"
LDAP_SEED_DIR="${LDAP_SEED_DIR:-/opt/ldifs}"

# olcSizeLimit / olcTimeLimit on the mdb database (see
# image/ldifs/01-cn-config.ldif). Left unset, slapd's own compiled-in
# defaults apply — sizelimit 500, timelimit 3600s — and a directory that
# grows past 500 entries starts silently truncating search results with no
# error, which is exactly the failure this token exists to head off.
#
# LDAP_SIZE_LIMIT defaults to 10000, not `unlimited`: rootDN (the admin
# bind used by slapcat/backups/bootstrap) is exempt from this limit
# regardless of what it's set to, so raising it only affects ordinary
# application binds — and an actual `unlimited` default would remove the
# last backstop against a single authenticated client dumping the entire
# directory in one query. 10000 clears the 500-entry cliff by two orders of
# magnitude while still bounding the worst case; set LDAP_SIZE_LIMIT=unlimited
# explicitly if a deployment genuinely needs no ceiling.
#
# LDAP_TIME_LIMIT keeps slapd's own default (3600s) rather than introducing
# a new one — this token makes it configurable without changing behavior
# for anyone who doesn't set it.
LDAP_SIZE_LIMIT="${LDAP_SIZE_LIMIT:-10000}"
case "$LDAP_SIZE_LIMIT" in
  unlimited) ;;
  ''|*[!0-9]*) die "LDAP_SIZE_LIMIT must be a number or 'unlimited' (got: ${LDAP_SIZE_LIMIT})" ;;
esac

# LDAP_PAGED_TOTAL_LIMIT (opt-in): OpenLDAP applies olcSizeLimit to the TOTAL
# of an RFC 2696 paged search, so a non-root identity can never page past
# LDAP_SIZE_LIMIT entries however small the pages are (verified live: a
# 12000-entry subtree stops at exactly 10000 with sizeLimitExceeded; rootDN is
# exempt). `size.prtotal` lifts that total for paged searches only; an unpaged
# search keeps olcSizeLimit. A stateless, explicit contract (section 3b2):
#   unset            hands off. No olcLimits rule is read, changed or removed.
#   <1..2147483647>  converge to exactly one rule `users size.prtotal=<value>`,
#   or `unlimited`   appended after any operator rules. The selector `users` is
#                    RESERVED for this feature while it is enabled: a `users`
#                    rule of any other shape is a conflict and stops startup
#                    (the operator decides); a `users size.prtotal=<other>` rule
#                    is the feature's own shape and is converged to the value.
#   off              remove exactly `users size.prtotal=<any value>`; a
#                    differently shaped `users` rule aborts startup too.
# Any failure to apply, verify or restore for a set/off request aborts startup:
# nothing is served on a policy that was not proven. `users` = every
# authenticated DN, so anonymous is unaffected. Raising the total lets any
# authenticated user page through the whole readable directory (ACLs still
# apply), which weakens the "last backstop" argument above, hence opt-in.
# Positive integer without a leading zero up to 2147483647 (a signed 32-bit
# count, what slapd's limit parser holds), or `unlimited`; 0 is refused because
# its meaning varies between slapd limit keywords. Never set size.pr here: a
# per-page cap makes a client asking for a bigger page fail with
# adminLimitExceeded.
paged_total_value_ok() {
  case "$1" in
    unlimited) return 0 ;;
    ''|0*|*[!0-9]*) return 1 ;;
  esac
  [ "${#1}" -le 10 ] || return 1
  [ "$1" -le 2147483647 ]
}
LDAP_PAGED_TOTAL_LIMIT="${LDAP_PAGED_TOTAL_LIMIT:-}"
if [ -n "$LDAP_PAGED_TOTAL_LIMIT" ] && [ "$LDAP_PAGED_TOTAL_LIMIT" != off ] && ! paged_total_value_ok "$LDAP_PAGED_TOTAL_LIMIT"; then
  die "LDAP_PAGED_TOTAL_LIMIT must be a positive number up to 2147483647, 'unlimited', or 'off' (got: ${LDAP_PAGED_TOTAL_LIMIT})"
fi

LDAP_TIME_LIMIT="${LDAP_TIME_LIMIT:-3600}"
case "$LDAP_TIME_LIMIT" in
  unlimited) ;;
  ''|*[!0-9]*) die "LDAP_TIME_LIMIT must be a number or 'unlimited' (got: ${LDAP_TIME_LIMIT})" ;;
esac

# olcPasswordHash on the frontend database (see image/ldifs/01-cn-config.ldif)
# and the scheme slappasswd uses below to mint the admin hash — one token
# drives both, so there is never a hardcoded scheme out of sync with the
# other. Default {ARGON2}: slapd is built with --enable-argon2
# --with-argon2=libargon2 (see image/Dockerfile), but under --enable-modules
# that still produces a LOADABLE module (argon2.la/.so), not code linked
# into slapd — verified with `ldd /usr/lib/slapd` (no argon2 reference).
# Loaded via `olcModuleload: argon2.la` in 01-cn-config.ldif, and passed
# explicitly to the standalone `slappasswd` call below (which never reads
# cn=config, so it wouldn't know the module exists otherwise). Argon2 is
# the current OWASP-recommended password hash, unlike {SSHA} (salted
# SHA-1). Format validation only (not a live `slappasswd -h` probe, which
# would work even pre-bootstrap but adds a subprocess for no real benefit)
# — value must look like a {SCHEME} token; slapd itself is the authority
# on whether the scheme is one it actually supports.
LDAP_PASSWORD_HASH="${LDAP_PASSWORD_HASH:-{ARGON2}}"
case "$LDAP_PASSWORD_HASH" in
  '{'*'}') ;;
  *) die "LDAP_PASSWORD_HASH must look like a {SCHEME} token, e.g. {ARGON2} or {SSHA} (got: ${LDAP_PASSWORD_HASH})" ;;
esac

# Comma-separated attributes the `unique` overlay enforces uniqueness on
# (see image/ldifs/01-cn-config.ldif and image/README.md, "Uniqueness
# enforcement"). `-` (not `:-`) so an explicit empty string is honored as
# "disable the overlay entirely" rather than falling back to the default —
# that's the documented off switch, since a Keycloak-federated deployment
# that already enforces uniqueness upstream shouldn't pay for a second,
# possibly-redundant check. No format validation here: whatever isn't a
# real attribute name just makes the generated olcUniqueURI inert, which
# slaptest/slapadd will reject on its own with a clearer error than
# anything this script could produce.
LDAP_UNIQUE_ATTRIBUTES="${LDAP_UNIQUE_ATTRIBUTES-uid,mail}"
# Off by default: every write gets an LDIF record, which is a real change in
# log volume and is not always wanted. /dev/stdout rather than a path on a
# volume — see where the overlay is rendered for why.
LDAP_AUDIT_ENABLED="${LDAP_AUDIT_ENABLED:-false}"
LDAP_AUDIT_FILE="${LDAP_AUDIT_FILE:-/dev/stdout}"

# accesslog: the read-side counterpart to auditlog above. Its own mdb
# database, so — unlike auditlog's /dev/stdout — it needs its own directory
# on the same volume auditlog's sibling MDB_DIR lives on. See where it is
# created, below, for why a subdirectory rather than the mount point itself.
LDAP_ACCESSLOG_ENABLED="${LDAP_ACCESSLOG_ENABLED:-false}"
LDAP_ACCESSLOG_PURGE_DAYS="${LDAP_ACCESSLOG_PURGE_DAYS:-30}"
LDAP_ACCESSLOG_OPS="${LDAP_ACCESSLOG_OPS:-reads bind}"
ACCESSLOG_DIR="${DATA_DIR}/accesslog"

# Password policy (see image/ldifs/03-base-structure.ldif and
# image/README.md, "Password policy"). On by default: without a pwdPolicy
# entry for the ppolicy overlay to apply, lockout/expiry/reuse/complexity
# are all inert and — the concrete break this closes — self-service
# password change has no way to require proof of the current password
# (pwdSafeModify only exists on a pwdPolicy entry), so it silently accepts
# a blind overwrite of anyone's userPassword. LDAP_PASSWORD_POLICY_ENABLED
# gates BOTH the policy entries in 03-base-structure.ldif AND
# olcPPolicyDefault in 01-cn-config.ldif's ppolicy overlay — never just
# one, since olcPPolicyDefault pointing at a DN that doesn't exist is a
# dangling reference, not a graceful no-op.
LDAP_PASSWORD_POLICY_ENABLED="${LDAP_PASSWORD_POLICY_ENABLED:-true}"

# Only the three knobs an operator is likely to actually tune per
# deployment are exposed; everything else in the policy (pwdInHistory,
# pwdMaxAge=0, pwdCheckQuality, ...) is a fixed LDIF value an operator can
# still change afterward with a plain ldapmodify against
# cn=default,ou=policies,<root DN> — see README.
LDAP_PASSWORD_MIN_LENGTH="${LDAP_PASSWORD_MIN_LENGTH:-8}"
case "$LDAP_PASSWORD_MIN_LENGTH" in
  ''|*[!0-9]*) die "LDAP_PASSWORD_MIN_LENGTH must be a number (got: ${LDAP_PASSWORD_MIN_LENGTH})" ;;
esac

LDAP_PASSWORD_MAX_FAILURE="${LDAP_PASSWORD_MAX_FAILURE:-5}"
case "$LDAP_PASSWORD_MAX_FAILURE" in
  ''|*[!0-9]*) die "LDAP_PASSWORD_MAX_FAILURE must be a number (got: ${LDAP_PASSWORD_MAX_FAILURE})" ;;
esac

LDAP_PASSWORD_LOCKOUT_DURATION="${LDAP_PASSWORD_LOCKOUT_DURATION:-900}"
case "$LDAP_PASSWORD_LOCKOUT_DURATION" in
  ''|*[!0-9]*) die "LDAP_PASSWORD_LOCKOUT_DURATION must be a number of seconds (got: ${LDAP_PASSWORD_LOCKOUT_DURATION})" ;;
esac

# pwdFailureCountInterval: how long a failed bind is remembered toward
# pwdMaxFailure. Left unset the counter never ages out, so five typos spread
# over a year lock an account; 900 matches the lockout duration above.
LDAP_PASSWORD_FAILURE_INTERVAL="${LDAP_PASSWORD_FAILURE_INTERVAL:-900}"
case "$LDAP_PASSWORD_FAILURE_INTERVAL" in
  ''|*[!0-9]*) die "LDAP_PASSWORD_FAILURE_INTERVAL must be a number of seconds (got: ${LDAP_PASSWORD_FAILURE_INTERVAL})" ;;
esac

# OpenLDAP 2.6 hardening (see docs/changes/openldap-2.6-hardening/CHANGE.md).
# Group A: connection/resource limits and lastbind, on by default with the
# values below; Group B: opt-in transport/authentication requirements, off
# by default so an unset variable changes nothing. All of it is reconciled
# into cn=config on EVERY start (section 3b), unlike bootstrap-only settings,
# so an existing volume picks the values up on upgrade.
require_number() {
  eval "_rn_val=\${$1}"
  # shellcheck disable=SC2154 # assigned by the eval above
  case "$_rn_val" in
    ''|*[!0-9]*) die "$1 must be a number (got: ${_rn_val})" ;;
  esac
}
LDAP_IDLE_TIMEOUT="${LDAP_IDLE_TIMEOUT:-600}"
LDAP_WRITE_TIMEOUT="${LDAP_WRITE_TIMEOUT:-30}"
LDAP_CONN_MAX_PENDING="${LDAP_CONN_MAX_PENDING:-100}"
LDAP_CONN_MAX_PENDING_AUTH="${LDAP_CONN_MAX_PENDING_AUTH:-1000}"
LDAP_SOCKBUF_MAX_INCOMING="${LDAP_SOCKBUF_MAX_INCOMING:-262143}"
LDAP_SOCKBUF_MAX_INCOMING_AUTH="${LDAP_SOCKBUF_MAX_INCOMING_AUTH:-4194303}"
LDAP_MAX_FILTER_DEPTH="${LDAP_MAX_FILTER_DEPTH:-20}"
LDAP_LASTBIND_PRECISION="${LDAP_LASTBIND_PRECISION:-3600}"
for _rn_name in LDAP_IDLE_TIMEOUT LDAP_WRITE_TIMEOUT LDAP_CONN_MAX_PENDING LDAP_CONN_MAX_PENDING_AUTH \
  LDAP_SOCKBUF_MAX_INCOMING LDAP_SOCKBUF_MAX_INCOMING_AUTH LDAP_MAX_FILTER_DEPTH LDAP_LASTBIND_PRECISION; do
  require_number "$_rn_name"
done
unset _rn_name _rn_val
# Unset = olcTLSECName not emitted (OpenSSL's own curve negotiation). Set only
# after checking the value: it lands verbatim in cn=config and a bad curve
# name makes slapd refuse to start on the next boot.
LDAP_TLS_EC_NAME="${LDAP_TLS_EC_NAME:-}"
case "$LDAP_TLS_EC_NAME" in
  '') ;;
  *[!A-Za-z0-9_-]*) die "LDAP_TLS_EC_NAME must match [A-Za-z0-9_-]+ (got: ${LDAP_TLS_EC_NAME})" ;;
  *)
    if command -v openssl >/dev/null 2>&1 \
      && ! openssl ecparam -list_curves 2>/dev/null | grep -qE "^[[:space:]]*${LDAP_TLS_EC_NAME}[[:space:]]*:"; then
      die "LDAP_TLS_EC_NAME is not a curve known to this OpenSSL (see: openssl ecparam -list_curves): ${LDAP_TLS_EC_NAME}"
    fi
    ;;
esac
# Opt-in: whether pwdLastSuccess replicates cleanly under multi-provider has
# not been verified (Change Package D4), so it stays off until the
# replication-chaos E2E has been run with it on.
LDAP_LASTBIND_ENABLED="${LDAP_LASTBIND_ENABLED:-false}"
LDAP_REQUIRE_TLS="${LDAP_REQUIRE_TLS:-false}"
LDAP_DISALLOW_ANON_BIND="${LDAP_DISALLOW_ANON_BIND:-false}"
LDAP_REQUIRE_AUTHC="${LDAP_REQUIRE_AUTHC:-false}"

# Optional modules (Change Package D6..D9). ppm/deref/constraint default on;
# nestgroup/dynlist/sssvlv-on-main/otp are opt-in and add nothing when off.
# Reconciled into cn=config (and the default policy entry for ppm) on every
# start in section 3b, so flipping a flag off removes the overlay again.
flag_on() { [ "$1" = "true" ] || [ "$1" = "1" ]; }
require_bool() {
  eval "_rb_val=\${$1}"
  # shellcheck disable=SC2154 # assigned by the eval above
  case "$_rb_val" in
    true|1|false|0) ;;
    *) die "$1 must be true, false, 1 or 0 (got: ${_rb_val})" ;;
  esac
}
LDAP_PPM_ENABLED="${LDAP_PPM_ENABLED:-true}"
LDAP_DEREF_ENABLED="${LDAP_DEREF_ENABLED:-true}"
LDAP_CONSTRAINT_ENABLED="${LDAP_CONSTRAINT_ENABLED:-true}"
LDAP_NESTGROUP_ENABLED="${LDAP_NESTGROUP_ENABLED:-false}"
LDAP_DYNLIST_ENABLED="${LDAP_DYNLIST_ENABLED:-false}"
LDAP_SSSVLV_MAIN_ENABLED="${LDAP_SSSVLV_MAIN_ENABLED:-false}"
LDAP_OTP_ENABLED="${LDAP_OTP_ENABLED:-false}"
for _rb_name in LDAP_PPM_ENABLED LDAP_DEREF_ENABLED LDAP_CONSTRAINT_ENABLED LDAP_NESTGROUP_ENABLED \
  LDAP_DYNLIST_ENABLED LDAP_SSSVLV_MAIN_ENABLED LDAP_OTP_ENABLED LDAP_LASTBIND_ENABLED \
  LDAP_REQUIRE_TLS LDAP_DISALLOW_ANON_BIND LDAP_REQUIRE_AUTHC; do
  require_bool "$_rb_name"
done
unset _rb_name _rb_val
# Number of ppm character classes (upper, lower, digit, special) a password
# must touch. 1 is effectively permissive: only a password with no ASCII
# letter, digit or punctuation at all (e.g. only spaces) is refused.
# Remember whether the operator set it: only an explicit value is re-applied
# to the policy entry on later starts (see the ppm block in section 3c).
_ppm_min_classes_explicit=${LDAP_PPM_MIN_CLASSES:+1}
LDAP_PPM_MIN_CLASSES="${LDAP_PPM_MIN_CLASSES:-1}"
case "$LDAP_PPM_MIN_CLASSES" in
  0|1|2|3|4) ;;
  *) die "LDAP_PPM_MIN_CLASSES must be 0-4 (got: ${LDAP_PPM_MIN_CLASSES})" ;;
esac
# Applies to mail only, and only to writes made by clients (replication
# updates bypass slapo-constraint). Permissive on purpose: one @, no
# whitespace, non-empty both sides.
LDAP_CONSTRAINT_MAIL_REGEX="${LDAP_CONSTRAINT_MAIL_REGEX:-^[^@[:space:]]+@[^@[:space:]]+\$}"
LDAP_NESTGROUP_BASE="${LDAP_NESTGROUP_BASE:-$LDAP_ROOT_DN}"
LDAP_NESTGROUP_FLAGS="${LDAP_NESTGROUP_FLAGS:-member-filter memberof-filter}"
for _ng_flag in $LDAP_NESTGROUP_FLAGS; do
  case "$_ng_flag" in
    member-filter|memberof-filter|member-values|memberof-values) ;;
    *) die "LDAP_NESTGROUP_FLAGS entries must be member-filter, memberof-filter, member-values or memberof-values (got: ${_ng_flag})" ;;
  esac
done
unset _ng_flag
LDAP_DYNLIST_ATTRSET="${LDAP_DYNLIST_ATTRSET:-groupOfURLs memberURL member}"
LDAP_SSSVLV_MAX="${LDAP_SSSVLV_MAX:-10}"
LDAP_SSSVLV_MAX_KEYS="${LDAP_SSSVLV_MAX_KEYS:-5}"
LDAP_SSSVLV_MAX_PER_CONN="${LDAP_SSSVLV_MAX_PER_CONN:-5}"
for _rn_name in LDAP_SSSVLV_MAX LDAP_SSSVLV_MAX_KEYS LDAP_SSSVLV_MAX_PER_CONN; do
  require_number "$_rn_name"
done
unset _rn_name _rn_val
case "$LDAP_CONSTRAINT_MAIL_REGEX$LDAP_DYNLIST_ATTRSET$LDAP_NESTGROUP_BASE" in
  *"
"*) die "LDAP_CONSTRAINT_MAIL_REGEX / LDAP_DYNLIST_ATTRSET / LDAP_NESTGROUP_BASE must be single-line" ;;
esac

# LDAP_ANONYMOUS_READ_BASE exists to serve anonymous searches; refusing
# anonymous binds / unauthenticated operations makes it dead config at best
# and a silently broken root-base lookup at worst, so reject the combination
# instead of picking a winner.
if [ -n "$LDAP_ANONYMOUS_READ_BASE" ]; then
  if [ "$LDAP_DISALLOW_ANON_BIND" = "true" ] || [ "$LDAP_DISALLOW_ANON_BIND" = "1" ]; then
    die "LDAP_DISALLOW_ANON_BIND=true contradicts LDAP_ANONYMOUS_READ_BASE (anonymous read needs anonymous binds) — unset one of them"
  fi
  if [ "$LDAP_REQUIRE_AUTHC" = "true" ] || [ "$LDAP_REQUIRE_AUTHC" = "1" ]; then
    die "LDAP_REQUIRE_AUTHC=true contradicts LDAP_ANONYMOUS_READ_BASE (anonymous read needs unauthenticated operations) — unset one of them"
  fi
fi

# slapd sizes its connection table from RLIMIT_NOFILE at startup: it allocates
# one Connection struct per possible file descriptor, up front, and touches
# them. Measured on this build: 680 bytes per fd, exactly linear. Container
# runtimes hand out a soft nofile of 1048576 by default, so slapd reserves
#   1048576 x 680 = ~680 MiB of anonymous memory
# before serving a single request, on a directory holding two entries. That is
# what makes an otherwise idle slapd sit at ~700 MiB RSS, and it is why a 512Mi
# container limit OOMKills. It has nothing to do with the database size or the
# mdb memory map — dropping olcDbMaxSize from 10 GiB to 2 GiB changed RSS by
# under 1 MiB.
#
# Lowering a soft limit never requires privileges, so do it here, before exec.
# 4096 concurrent connections is far past what this image is shipped for, and
# costs ~2.7 MiB instead of ~680 MiB.
LDAP_MAX_OPEN_FILES="${LDAP_MAX_OPEN_FILES:-4096}"
case "$LDAP_MAX_OPEN_FILES" in
  ''|*[!0-9]*) die "LDAP_MAX_OPEN_FILES must be a number (got: ${LDAP_MAX_OPEN_FILES})" ;;
esac
# POSIX only standardizes `ulimit -f`, so shellcheck flags -n (SC3045) in an
# sh script. Suppressed deliberately: this image's /bin/sh is Debian's dash,
# which does implement -n, and the runtime shell is fixed by the Dockerfile —
# this script is not portable-shell-in-general, it is this-image's shell.
# -S/-H are avoided (also non-POSIX, and unnecessary: bare -n sets both).
# Only ever lowering means this cannot fail for lack of privilege; a failure
# means someone asked for a value above the hard limit, worth saying out loud.
# shellcheck disable=SC3045
if ulimit -n "$LDAP_MAX_OPEN_FILES" 2>/dev/null; then
  log "open-file limit set to ${LDAP_MAX_OPEN_FILES} (slapd reserves ~680 bytes of connection table per fd)"
else
  # shellcheck disable=SC3045
  ldap_nofile_now=$(ulimit -n)
  log "WARNING: could not set the open-file limit to ${LDAP_MAX_OPEN_FILES} (above the hard limit?); slapd will size its connection table from ${ldap_nofile_now} descriptors"
fi

# olcDbMaxSize — the size of the memory map mdb reserves for the database.
# Sized to the volume rather than to wishful thinking: the map can never
# usefully exceed the filesystem backing it. (It is NOT the reason an idle
# slapd shows ~700 MiB RSS — that is the connection table, see
# LDAP_MAX_OPEN_FILES above. Measured: changing this from 10 GiB to 2 GiB
# moved RSS by under 1 MiB.) Applied at bootstrap only (it lives in cn=config); changing it
# afterwards means editing cn=config by hand.
LDAP_DB_MAX_SIZE="${LDAP_DB_MAX_SIZE:-1073741824}"
case "$LDAP_DB_MAX_SIZE" in
  ''|*[!0-9]*) die "LDAP_DB_MAX_SIZE must be a byte count in digits (got: ${LDAP_DB_MAX_SIZE})" ;;
esac

# Health probes poll LDAPI_SOCK; keep setup operations on a separate socket
# so probes do not answer until the final slapd serves all listeners.
SETUP_LDAPI_SOCK="${RUN_DIR}/ldapi-setup"
SETUP_LDAPI_URL="ldapi://$(printf '%s' "$SETUP_LDAPI_SOCK" | sed 's|/|%2F|g')"

LDAPI_SOCK="${RUN_DIR}/ldapi"
LDAPI_URL="ldapi://$(printf '%s' "$LDAPI_SOCK" | sed 's|/|%2F|g')"
LISTEN_URLS="ldap:/// ${LDAPI_URL}"

if [ "$LDAP_TLS_ENABLED" = "true" ] || [ "$LDAP_TLS_ENABLED" = "1" ]; then
  : "${LDAP_TLS_CERT_FILE:?LDAP_TLS_ENABLED=true requires LDAP_TLS_CERT_FILE}"
  : "${LDAP_TLS_KEY_FILE:?LDAP_TLS_ENABLED=true requires LDAP_TLS_KEY_FILE}"
  [ -r "$LDAP_TLS_CERT_FILE" ] || die "LDAP_TLS_CERT_FILE not readable: ${LDAP_TLS_CERT_FILE}"
  [ -r "$LDAP_TLS_KEY_FILE" ] || die "LDAP_TLS_KEY_FILE not readable: ${LDAP_TLS_KEY_FILE}"
  if [ -n "${LDAP_TLS_CA_FILE:-}" ]; then
    [ -r "$LDAP_TLS_CA_FILE" ] || die "LDAP_TLS_CA_FILE not readable: ${LDAP_TLS_CA_FILE}"
  fi
  LISTEN_URLS="${LISTEN_URLS} ldaps:///"
fi

if [ "$LDAP_TLS_MUTUAL_AUTH" = "true" ] || [ "$LDAP_TLS_MUTUAL_AUTH" = "1" ]; then
  if [ "$LDAP_TLS_ENABLED" != "true" ] && [ "$LDAP_TLS_ENABLED" != "1" ]; then
    die "LDAP_TLS_MUTUAL_AUTH=true requires LDAP_TLS_ENABLED=true"
  fi
  # LDAP_TLS_CA_FILE under mutual auth must be a CA dedicated to this
  # directory's client certificates, never a shared/general-purpose one.
  # Verified live: any certificate this CA signs — even one whose subject
  # LDAP_TLS_AUTHZ_REGEXP was never meant to match — still binds via SASL
  # EXTERNAL (OpenLDAP falls back to the raw certificate-subject identity
  # rather than rejecting an unresolved one), and that bind still satisfies
  # this image's `by users` ACLs, which grant broad DIT read access to any
  # authenticated identity. See docs/client-compatibility.md's SASL section
  # and image/README.md for the full verification — there is no
  # authzRegexp-only way to scope this down.
  [ -n "${LDAP_TLS_CA_FILE:-}" ] || die "LDAP_TLS_MUTUAL_AUTH=true requires LDAP_TLS_CA_FILE so client certificates can be verified"

  # Preserve explicit empty values so the contract can reject them rather
  # than silently replacing an operator's typo with the example defaults.
  # OpenLDAP normalizes a certificate subject used for SASL EXTERNAL to a
  # lower-case DN; this example maps a certificate CN to uid=<CN> below this
  # directory's base DN. Operators should override both values for the
  # subject shape and DIT layout used by their CA.
  LDAP_TLS_AUTHZ_REGEXP="${LDAP_TLS_AUTHZ_REGEXP-^cn=([^,]+)$}"
  LDAP_TLS_AUTHZ_DN="${LDAP_TLS_AUTHZ_DN-uid=\$1,${LDAP_ROOT_DN}}"
  [ -n "$LDAP_TLS_AUTHZ_REGEXP" ] || die "LDAP_TLS_MUTUAL_AUTH=true requires non-empty LDAP_TLS_AUTHZ_REGEXP"
  [ -n "$LDAP_TLS_AUTHZ_DN" ] || die "LDAP_TLS_MUTUAL_AUTH=true requires non-empty LDAP_TLS_AUTHZ_DN"
fi

# Replication (N-way multi-provider). Disabled by default — when disabled,
# nothing below this block is ever consulted, and behavior is byte-for-byte
# identical to the non-replicated image.
LDAP_REPLICATION_ENABLED="${LDAP_REPLICATION_ENABLED:-false}"
if [ "$LDAP_REPLICATION_ENABLED" = "true" ] || [ "$LDAP_REPLICATION_ENABLED" = "1" ]; then
  : "${LDAP_REPLICATION_PEERS:?LDAP_REPLICATION_ENABLED requires LDAP_REPLICATION_PEERS (comma-separated LDAP URLs, including self)}"

  # Multi-provider's conflict resolution (entryCSN timestamp, last-write-
  # wins) is otherwise completely silent — the losing write just stops
  # existing, with nothing in cn=accesslog or the auditlog overlay to show
  # it ever happened. The `Sync` log subsystem is the one place slapd says
  # anything at all: `do_syncrep2: rid=N CSN too old, ignoring <csn>
  # (<dn>)` names the exact entry and the exact CSN it discarded. Turned on
  # unconditionally here rather than gated by another env var — a
  # replicated deployment is precisely the one place this line can ever
  # fire, so there's no "off" case worth a knob for, the way there is for
  # LDAP_AUDIT_ENABLED/LDAP_ACCESSLOG_ENABLED (which cost real disk on
  # every deployment, replicated or not). `-d` only accepts one keyword per
  # occurrence or a comma-joined list — space-separated silently fails
  # ("unrecognized log level") — so this appends onto whatever
  # LDAP_LOG_LEVEL already resolved to, unless "sync" is already in it.
  case ",${LDAP_LOG_LEVEL}," in
    *,sync,*) : ;;
    *) LDAP_LOG_LEVEL="${LDAP_LOG_LEVEL},sync" ;;
  esac

  if [ -n "${LDAP_SERVER_ID:-}" ]; then
    case "$LDAP_SERVER_ID" in
      ''|*[!0-9]*) die "LDAP_SERVER_ID must be numeric (got: ${LDAP_SERVER_ID})" ;;
    esac
  else
    # StatefulSet pods can't be given per-pod env, so the only per-node
    # signal available is the ordinal suffix of the hostname (e.g. ols-0).
    # A non-numeric suffix must be a hard failure: silently falling back to
    # a fixed ID would give every replica the same olcServerID and corrupt
    # replication instead of just refusing to start.
    ldap_hostname=$(uname -n)
    ldap_hostname_ordinal="${ldap_hostname##*-}"
    case "$ldap_hostname_ordinal" in
      ''|*[!0-9]*) die "cannot auto-derive LDAP_SERVER_ID: hostname '${ldap_hostname}' does not end in a numeric ordinal (e.g. 'ols-0'); set LDAP_SERVER_ID explicitly" ;;
    esac
    LDAP_SERVER_ID=$((ldap_hostname_ordinal + 1))
  fi
  if [ "$LDAP_SERVER_ID" -lt 1 ] || [ "$LDAP_SERVER_ID" -gt 4095 ]; then
    die "LDAP_SERVER_ID must be 1..4095 (got: ${LDAP_SERVER_ID})"
  fi

  # LDAP_SERVER_ID doubles as this node's 1-based position in
  # LDAP_REPLICATION_PEERS (used below to exclude self from olcSyncrepl —
  # see D7 in the replication design doc). If it's out of range, this node
  # would either replicate to itself or match no peer at all; refuse to
  # start instead of silently doing either.
  ldap_peer_total=0
  OLDIFS=$IFS
  IFS=','
  for ldap_peer_scan in $LDAP_REPLICATION_PEERS; do
    ldap_peer_scan=$(printf '%s' "$ldap_peer_scan" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
    [ -n "$ldap_peer_scan" ] && ldap_peer_total=$((ldap_peer_total + 1))
    # olcSecurity ssf=128 (LDAP_REQUIRE_TLS) refuses plaintext TCP on every
    # node, so a plain ldap:// peer URL means syncrepl and the first-boot peer
    # check are refused by the very peers they target.
    if flag_on "$LDAP_REQUIRE_TLS"; then
      case "$ldap_peer_scan" in
        ''|ldaps://*) ;;
        *) die "LDAP_REQUIRE_TLS=true requires every LDAP_REPLICATION_PEERS entry to use ldaps:// (got: ${ldap_peer_scan}) — peers refuse plaintext connections" ;;
      esac
    fi
  done
  IFS=$OLDIFS
  # dynlist and nestgroup *-values rewrite entries as they are returned; a
  # syncrepl consumer search goes through the same path, so computed values
  # would be replicated as if they were stored. Not verified safe -> refuse.
  if flag_on "$LDAP_DYNLIST_ENABLED"; then
    die "LDAP_DYNLIST_ENABLED=true is not supported with LDAP_REPLICATION_ENABLED (dynamic values would enter the syncrepl stream)"
  fi
  if flag_on "$LDAP_NESTGROUP_ENABLED"; then
    case " $LDAP_NESTGROUP_FLAGS " in
      *" member-values "*|*" memberof-values "*) die "LDAP_NESTGROUP_FLAGS with member-values/memberof-values is not supported with LDAP_REPLICATION_ENABLED (expanded values would enter the syncrepl stream); use member-filter/memberof-filter" ;;
    esac
  fi
  [ "$ldap_peer_total" -gt 0 ] || die "LDAP_REPLICATION_PEERS resolved to zero entries"
  [ "$LDAP_SERVER_ID" -le "$ldap_peer_total" ] || die "LDAP_SERVER_ID (${LDAP_SERVER_ID}) exceeds the number of entries in LDAP_REPLICATION_PEERS (${ldap_peer_total}) — a node's serverID must be its 1-based position in the peer list"

  # D3: bind identity for replication is rootDN, not a dedicated account —
  # the baseline ACL denies userPassword to everyone but self/anonymous-auth,
  # so a non-root bind DN would silently never receive password changes.
  LDAP_REPLICATION_BIND_DN="${LDAP_REPLICATION_BIND_DN:-$LDAP_ADMIN_DN}"

  if [ -n "${LDAP_REPLICATION_PASSWORD_FILE:-}" ]; then
    [ -r "$LDAP_REPLICATION_PASSWORD_FILE" ] || die "LDAP_REPLICATION_PASSWORD_FILE is set but not readable: ${LDAP_REPLICATION_PASSWORD_FILE}"
    LDAP_REPLICATION_PASSWORD=$(cat "$LDAP_REPLICATION_PASSWORD_FILE")
  fi
  LDAP_REPLICATION_PASSWORD="${LDAP_REPLICATION_PASSWORD:-$LDAP_ADMIN_PASSWORD}"
  [ -n "$LDAP_REPLICATION_PASSWORD" ] || die "LDAP_REPLICATION_PASSWORD resolved empty"
  case "$LDAP_REPLICATION_PASSWORD" in
    *"$nl"*) die "the replication password must not contain a newline" ;;
  esac

  # "5 10 30 +" = ten attempts 5s apart, then every 30s forever. A flat
  # "60 +" leaves a node that came up before its peers waiting a full minute
  # before it retries even once, which shows up as a cold-started cluster
  # taking over a minute to converge in one direction. Peers are normally
  # reachable within seconds of each other, so retry fast first, then back off.
  LDAP_REPLICATION_RETRY="${LDAP_REPLICATION_RETRY:-5 10 30 +}"
  LDAP_REPLICATION_INTERVAL="${LDAP_REPLICATION_INTERVAL:-00:00:00:10}"
fi

mkdir -p "$RUN_DIR"

# ---------------------------------------------------------------------------
# 2. Shared helper: a temporary background slapd bound only to the local
#    ldapi:// socket. Used both by first-launch seeding (below) and by
#    replication reconciliation (section 4) so the start/wait/stop dance for
#    a throwaway slapd instance is implemented exactly once.
# ---------------------------------------------------------------------------
TEMP_SLAPD_PID=""

start_temp_slapd() {
  slapd -F "$CONFIG_DIR" -h "$SETUP_LDAPI_URL" -d "$LDAP_LOG_LEVEL" &
  TEMP_SLAPD_PID=$!

  i=0
  # SASL EXTERNAL, not an anonymous simple bind: a previous boot's
  # LDAP_DISALLOW_ANON_BIND / LDAP_REQUIRE_AUTHC persists in cn=config and
  # would otherwise make this probe fail forever.
  until ldapwhoami -Y EXTERNAL -H "$SETUP_LDAPI_URL" >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -ge 30 ]; then
      die "temporary slapd did not become ready within 30s"
    fi
    kill -0 "$TEMP_SLAPD_PID" 2>/dev/null || die "temporary slapd exited during startup"
    sleep 1
  done
}

stop_temp_slapd() {
  if [ -n "$TEMP_SLAPD_PID" ]; then
    kill -TERM "$TEMP_SLAPD_PID" 2>/dev/null || true
    wait "$TEMP_SLAPD_PID" 2>/dev/null || true
    TEMP_SLAPD_PID=""
  fi
  rm -f "$SETUP_LDAPI_SOCK"
}

# ---------------------------------------------------------------------------
# 3. First-launch bootstrap + seed application. TLS settings are only baked
#    in at bootstrap time (they live in cn=config); changing TLS on an
#    already-bootstrapped volume requires editing cn=config manually
#    (documented in README).
#
#    Seed LDIFs are applied here too (first launch only), via a temporary
#    background slapd that is stopped again before the final `exec slapd`
#    below — so slapd still ends up PID 1 for the life of the container.
# ---------------------------------------------------------------------------
if [ ! -f "$MARKER" ]; then
  log "no bootstrap marker at ${MARKER} — bootstrapping a new directory"

  if [ -n "$(ls -A "$CONFIG_DIR" 2>/dev/null)" ]; then
    die "${CONFIG_DIR} is non-empty but unmarked — refusing to bootstrap over unknown state"
  fi

  # A bootstrap that dies halfway leaves CONFIG_DIR non-empty and unmarked, so
  # the guard above then refuses on every restart: the volume is wedged, and the
  # error that actually caused it scrolls out of the container log long before
  # anyone looks — all that is left is the refusal. Roll the partial state back
  # instead, so the next boot retries a real bootstrap and reports the real
  # failure. This only ever runs on a path where this process found CONFIG_DIR
  # empty, so it cannot delete a directory it did not create itself.
  rollback_bootstrap() {
    # Seeding (below) runs a temporary slapd against CONFIG_DIR/MDB_DIR
    # while this trap is armed, so it must be stopped before those files
    # are touched — otherwise rollback races a still-running slapd holding
    # them open. Unconditional and harmless when no temp slapd was started
    # (stop_temp_slapd no-ops on an empty TEMP_SLAPD_PID).
    stop_temp_slapd
    if [ -f "$MARKER" ]; then
      return 0
    fi
    log "bootstrap did not complete — discarding partial state so the next boot can retry"
    find "$CONFIG_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true
    rm -rf "$MDB_DIR" "$ACCESSLOG_DIR"
  }
  trap 'rollback_bootstrap' EXIT
  # dash does not run an EXIT trap when the shell is killed by a signal, so the
  # password temp dirs below (work, seed_work) would survive a TERM/INT/HUP.
  # Turning the signal into an `exit` makes the EXIT trap run on that path too.
  # These stay armed (the EXIT handler is only swapped, never these) until the
  # bootstrap ends with `trap - EXIT HUP INT TERM`.
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM

  # The mdb files live in a subdirectory that THIS process creates, never
  # directly on the volume's mount point. That is what makes `chmod 700`
  # reliable: a mount point belongs to root (with the pod's fsGroup as its
  # group), so a non-root uid cannot chmod it — and it may well arrive
  # world-writable, which no amount of fsGroup will fix. Observed on k3s with
  # the local-path provisioner: the mount point is mode 2777, because
  # local-path creates its host directory 0777 and the kubelet's fsGroup
  # handling only ADDS group bits and setgid, it never clears "other".
  # Chmod-ing the mount point therefore either fails (EPERM, crash-loop) or
  # is not ours to fix. A subdirectory we create ourselves is owned by us,
  # so 700 always applies, on every provisioner, without root anywhere.
  mkdir -p "$MDB_DIR"
  chmod 700 "$MDB_DIR"

  # `slappasswd` is a standalone binary, not slapd — it never reads
  # cn=config, so it has no idea {ARGON2} exists unless told. Always pass
  # module-load, even when LDAP_PASSWORD_HASH is something else like
  # {SSHA}: the module simply goes unused in that case, so branching on
  # the scheme here would only add a code path for no behavioral gain.
  # Verified working: `slappasswd -o module-path=/usr/lib/openldap -o
  # module-load=argon2 -h "{ARGON2}" -s ...` produces
  # {ARGON2}$argon2id$v=19$m=7168,t=5,p=1$...
  #
  # #220: -T reads the password from a file, never argv, so it is not visible in
  # /proc/*/cmdline. The file lives in the 0700 work dir (removed by the trap
  # on every exit path) and is written with printf (a builtin in dash, so the
  # password is on no process's command line while writing it either).
  work=$(mktemp -d)
  trap 'rm -rf "$work"; rollback_bootstrap' EXIT
  admin_pw_file="${work}/admin-pw"
  (umask 077; printf '%s' "$LDAP_ADMIN_PASSWORD" > "$admin_pw_file") || die "cannot write the temporary admin password file"
  ADMIN_PW_HASH=$(slappasswd -o module-path=/usr/lib/openldap -o module-load=argon2 -h "$LDAP_PASSWORD_HASH" -T "$admin_pw_file")
  rm -f "$admin_pw_file"

  cn_config="${work}/01-cn-config.ldif"
  cp "${BOOTSTRAP_DIR}/01-cn-config.ldif" "$cn_config"

  # NOTE ON THE `^...$` ANCHORS BELOW — they are load-bearing, not tidiness.
  # Both marker strings also appear inside 01-cn-config.ldif's own header
  # comment block (the "Tokens replaced by entrypoint.sh" list). An unanchored
  # /#__MARKER__/ therefore matches that documentation line too, and `r`
  # injects the replacement into the header — immediately before `dn:
  # cn=config`, with no blank line between them. LDIF separates entries by
  # blank lines, not by comments, so the injected entry merges into the first
  # real one and slapadd dies with:
  #   str2entry: entry -1 has multiple DNs "olcOverlay=unique,..." and
  #   "cn=config"
  # Observed for real on the unique overlay. The TLS marker had the same latent
  # bug the whole time and only escaped notice because the TLS path has never
  # been exercised end-to-end. Anchoring to a full line fixes both.
  if [ "$LDAP_TLS_ENABLED" = "true" ] || [ "$LDAP_TLS_ENABLED" = "1" ]; then
    tls_attrs="${work}/tls-attrs.txt"
    {
      printf 'olcTLSCertificateFile: %s\n' "$LDAP_TLS_CERT_FILE"
      printf 'olcTLSCertificateKeyFile: %s\n' "$LDAP_TLS_KEY_FILE"
      [ -n "${LDAP_TLS_CA_FILE:-}" ] && printf 'olcTLSCACertificateFile: %s\n' "$LDAP_TLS_CA_FILE"
      if [ "$LDAP_TLS_MUTUAL_AUTH" = "true" ] || [ "$LDAP_TLS_MUTUAL_AUTH" = "1" ]; then
        # `try`, never `demand`: request and verify an offered client cert,
        # while allowing certificate-less TLS clients to continue to SIMPLE
        # bind exactly as they did before mTLS was enabled.
        printf 'olcTLSVerifyClient: try\n'
        printf 'olcAuthzRegexp: {0}%s %s\n' "$LDAP_TLS_AUTHZ_REGEXP" "$LDAP_TLS_AUTHZ_DN"
      fi
      # 3.3 is OpenLDAP's own major.minor encoding for TLS 1.2 (3.1/3.2/3.4
      # are 1.0/1.1/1.3) — not a version of this image or of OpenLDAP
      # itself. Fixed, not an env var: this is a floor nobody deploying in
      # 2026 wants lower, and the library default it replaces is whatever
      # the linked OpenSSL build happens to ship rather than a policy this
      # project actually chose and can point to in cn=config.
      printf 'olcTLSProtocolMin: 3.3\n'
      # Cipher suite baseline for TLS <=1.2 connections, split out from the
      # protocol floor above (see docs/client-compatibility.md) because it
      # needed its own OpenSSL cipher-list-syntax + client-compatibility
      # review. This is the Mozilla "Intermediate" profile's TLS 1.2 list
      # (ssl-config.mozilla.org, verified current as of this project's own
      # 2026 policy review) — AEAD ciphers with ECDHE forward secrecy only,
      # no CBC/SHA-1, no static RSA key exchange, no 3DES/RC4/export/NULL.
      # Fixed, not an env var, same rationale as the protocol floor: this is
      # this project's chosen policy, not whatever OpenSSL's own default
      # cipher list happens to allow.
      #
      # This directive maps to OpenSSL's SSL_CTX_set_cipher_list(), which
      # only governs TLS 1.2 and below — it has no effect on TLS 1.3, whose
      # fixed AEAD ciphersuite list (TLS_AES_128_GCM_SHA256 and friends) is
      # negotiated separately and is not something OpenLDAP exposes a
      # directive for. A TLS 1.3 client is unaffected either way.
      printf 'olcTLSCipherSuite: ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305\n'
    } > "$tls_attrs"
    sed -i "/^#__TLS_ATTRS__$/{r ${tls_attrs}
d}" "$cn_config"
  else
    sed -i '/^#__TLS_ATTRS__$/d' "$cn_config"
  fi

  # anonymous-read ACL: whole-block conditional, same r/d technique as
  # #__TLS_ATTRS__ above but replacing the marker with one or more whole
  # olcAccess values rather than attribute lines within an existing entry.
  # Default (empty LDAP_ANONYMOUS_READ_BASE) renders the same two rules this
  # image has always shipped — anonymous read of entry/uid/objectClass
  # DIT-wide — so an unset env var is a strict no-op.
  #
  # When LDAP_ANONYMOUS_READ_BASE is set, anonymous read of entry/uid/
  # objectClass is scoped to that subtree only (rule {1}), but anonymous
  # still needs `search` (not `read`) on `entry` everywhere else (rule {2})
  # so slapd can still walk through the root and intermediate OUs to reach
  # the base — `search` lets slapd use an entry as a stepping stone without
  # ever disclosing or returning it. `uid`/`objectClass` get no anonymous
  # access at all outside the base (rule {3}, `by users` only), so a filter
  # like `(objectClass=*)` evaluates undefined against those entries for an
  # anonymous bind and never matches them. Order matters — rule {1} must
  # come before rule {2} or anonymous would match {2} first on `entry` with
  # only `search`, never reaching the `read` grant under the base.
  anon_read_access="${work}/anon-read-access.ldif"
  if [ -n "$LDAP_ANONYMOUS_READ_BASE" ]; then
    {
      printf 'olcAccess: {1}to dn.subtree="%s" attrs=entry,uid,objectClass\n' "$LDAP_ANONYMOUS_READ_BASE"
      printf '  by anonymous read\n'
      printf '  by users read\n'
      printf 'olcAccess: {2}to attrs=entry\n'
      printf '  by anonymous search\n'
      printf '  by users read\n'
      printf 'olcAccess: {3}to attrs=uid,objectClass\n'
      printf '  by users read\n'
      printf 'olcAccess: {4}to *\n'
      printf '  by self write\n'
      printf '  by users read\n'
      printf '  by anonymous none\n'
    } > "$anon_read_access"
    log "narrowing anonymous read to ${LDAP_ANONYMOUS_READ_BASE}"
  else
    {
      printf 'olcAccess: {1}to attrs=entry,uid,objectClass\n'
      printf '  by anonymous read\n'
      printf '  by users read\n'
      printf 'olcAccess: {2}to *\n'
      printf '  by self write\n'
      printf '  by users read\n'
      printf '  by anonymous none\n'
    } > "$anon_read_access"
  fi
  sed -i "/^#__ANON_READ_ACCESS__$/{r ${anon_read_access}
d}" "$cn_config"

  # unique overlay: whole-entry conditional, same r/d technique as
  # #__TLS_ATTRS__ above but replacing the marker with an entire olcOverlay
  # entry (or nothing) rather than a handful of attribute lines within an
  # existing entry — see the comment on #__UNIQUE_OVERLAY__ in
  # 01-cn-config.ldif for why an empty attribute list must delete the
  # entry outright instead of emitting one with zero olcUniqueURI values.
  unique_overlay="${work}/unique-overlay.ldif"
  unique_uri_count=0
  {
    printf 'dn: olcOverlay=unique,olcDatabase={1}mdb,cn=config\n'
    printf 'objectClass: olcOverlayConfig\n'
    printf 'objectClass: olcUniqueConfig\n'
    printf 'olcOverlay: unique\n'
    OLDIFS=$IFS
    IFS=','
    for uniq_attr in $LDAP_UNIQUE_ATTRIBUTES; do
      uniq_attr=$(printf '%s' "$uniq_attr" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
      [ -n "$uniq_attr" ] || continue
      unique_uri_count=$((unique_uri_count + 1))
      # One URI per attribute, not one URI listing several: olcUniqueURI is
      # multi-valued and each value is its OWN uniqueness domain, so combining
      # attributes in a single URI would mean "the combination is unique"
      # instead of "each one is unique on its own" — a materially different
      # (and weaker) guarantee. Filter scoped to inetOrgPerson: the admin
      # entry is organizationalRole and has no uid, and an unscoped filter
      # would pull the admin/base entries into the check for no benefit.
      printf 'olcUniqueURI: ldap:///?%s?sub?(objectClass=inetOrgPerson)\n' "$uniq_attr"
    done
    IFS=$OLDIFS
  } > "$unique_overlay"

  if [ "$unique_uri_count" -gt 0 ]; then
    log "enabling unique overlay for: ${LDAP_UNIQUE_ATTRIBUTES}"
    sed -i "/^#__UNIQUE_OVERLAY__$/{r ${unique_overlay}
d}" "$cn_config"
  else
    log "LDAP_UNIQUE_ATTRIBUTES is empty — unique overlay not created"
    sed -i '/^#__UNIQUE_OVERLAY__$/d' "$cn_config"
  fi

  # auditlog overlay: writes an LDIF record for every write, naming the bound
  # identity, the source address and the connection. Same r/d technique again.
  #
  # olcAuditlogFile is /dev/stdout deliberately. The overlay can only write to
  # a file, and every on-disk destination here is wrong: the data PVC is
  # ReadWriteOnce so nothing else can read the file while slapd holds it, an
  # emptyDir dies with the pod, and either way the log grows until it fills the
  # volume and takes the directory down with it. Sending it to stdout hands
  # retention, rotation and shipping to whatever already collects container
  # logs — which is where those problems are actually solved.
  if [ "$LDAP_AUDIT_ENABLED" = "true" ] || [ "$LDAP_AUDIT_ENABLED" = "1" ]; then
    auditlog_overlay="${work}/auditlog-overlay.ldif"
    {
      printf 'dn: olcOverlay=auditlog,olcDatabase={1}mdb,cn=config\n'
      printf 'objectClass: olcOverlayConfig\n'
      printf 'objectClass: olcAuditlogConfig\n'
      printf 'olcOverlay: auditlog\n'
      printf 'olcAuditlogFile: %s\n' "$LDAP_AUDIT_FILE"
    } > "$auditlog_overlay"
    log "enabling auditlog overlay (destination: ${LDAP_AUDIT_FILE})"
    sed -i "/^#__AUDITLOG_OVERLAY__$/{r ${auditlog_overlay}
d}" "$cn_config"
  else
    sed -i '/^#__AUDITLOG_OVERLAY__$/d' "$cn_config"
  fi

  # accesslog overlay: a second mdb database, its own suffix and files, plus
  # the overlay entry on the main database that writes into it. auditlog
  # above is write-only by design; olcAccessLogOps: reads is what makes this
  # the counterpart that covers what auditlog cannot see, rather than a
  # second copy of what it already does. Same r/d technique, two markers
  # rendered (or both deleted) together since one is meaningless without the
  # other.
  #
  # olcRootDN/olcRootPW here follow the same pattern the monitor database
  # above already uses: its own bind identity, reusing the directory admin's
  # password hash rather than minting a second secret to manage. slapd
  # requires olcRootDN to sit under the database's own olcSuffix before it
  # will accept an olcRootPW at all — cn=admin,cn=accesslog under
  # cn=accesslog satisfies that the same way cn=monitoring,cn=Monitor does
  # for cn=Monitor.
  if [ "$LDAP_ACCESSLOG_ENABLED" = "true" ] || [ "$LDAP_ACCESSLOG_ENABLED" = "1" ]; then
    # Own subdirectory, not the data volume's mount point — same reasoning
    # as MDB_DIR above: only a directory this process creates itself can be
    # reliably chmod 700'd regardless of what the provisioner handed us.
    mkdir -p "$ACCESSLOG_DIR"
    chmod 700 "$ACCESSLOG_DIR"

    accesslog_db="${work}/accesslog-db.ldif"
    {
      printf 'dn: olcDatabase={2}mdb,cn=config\n'
      printf 'objectClass: olcDatabaseConfig\n'
      printf 'objectClass: olcMdbConfig\n'
      printf 'olcDatabase: mdb\n'
      printf 'olcSuffix: cn=accesslog\n'
      printf 'olcRootDN: cn=admin,cn=accesslog\n'
      printf 'olcRootPW: %s\n' "$ADMIN_PW_HASH"
      printf 'olcDbDirectory: %s\n' "$ACCESSLOG_DIR"
      # Indices slapo-accesslog(5) itself recommends: reqStart/reqEnd bound
      # the purge task's own age-based sweep, the rest are what a consumer
      # actually filters an export on.
      printf 'olcDbIndex: default eq\n'
      printf 'olcDbIndex: entryCSN,objectClass,reqEnd,reqResult,reqStart eq\n'
      # A database with no olcAccess of its own falls through to slapd's
      # global default, "to * by * read" — anonymous included. The monitor
      # database above already knows this and locks itself down the same
      # way; this one needs the identical treatment; every search's actor,
      # target and filter is exactly what an audit trail should not hand to
      # anyone who can reach the LDAP port.
      printf 'olcAccess: {0}to * by dn.exact="cn=admin,cn=accesslog" read by * none\n'
      # Attach sssvlv overlay to cn=accesslog so server-side sorting (RFC 2891)
      # and bounded pagination are supported without loading the whole log.
      printf '\ndn: olcOverlay=sssvlv,olcDatabase={2}mdb,cn=config\n'
      printf 'objectClass: olcOverlayConfig\n'
      printf 'objectClass: olcSssVlvConfig\n'
      printf 'olcOverlay: sssvlv\n'
    } > "$accesslog_db"
    sed -i "/^#__ACCESSLOG_DB__$/{r ${accesslog_db}
d}" "$cn_config"

    accesslog_overlay="${work}/accesslog-overlay.ldif"
    {
      # Attached to olcDatabase={-1}frontend,cn=config as a global overlay so
      # that internal searches initiated by other database overlays (like
      # slapo-unique on {1}mdb) do not trigger accesslog and collide on reqStart
      # RDN (MDB_KEYEXIST) during writes.
      printf 'dn: olcOverlay=accesslog,olcDatabase={-1}frontend,cn=config\n'
      printf 'objectClass: olcOverlayConfig\n'
      printf 'objectClass: olcAccessLogConfig\n'
      printf 'olcOverlay: accesslog\n'
      printf 'olcAccessLogDB: cn=accesslog\n'
      # olcAccessLogOps defaults to "reads bind" (preserving the baseline
      # accesslog contract without duplicating auditlog writes). When
      # configured with "writes reads bind" (e.g. for the UI console operator
      # action history), writes (add, modify, delete, modrdn) are also captured.
      printf 'olcAccessLogOps: %s\n' "$LDAP_ACCESSLOG_OPS"
      # FALSE (log every request, not only successful ones): with TRUE, a
      # rejected search or a failed bind — the two events most worth
      # auditing — would never reach cn=accesslog at all. reqResult is
      # already indexed above for exactly this: distinguishing success
      # from failure downstream, not filtering failures out upstream.
      printf 'olcAccessLogSuccess: FALSE\n'
      # <age>+<hh>:<mm>:<ss> <cycle>+<hh>:<mm>:<ss> — confirmed against
      # slapo-accesslog's own log_age_parse(), not guessed: a bare "N" before
      # the '+' is N days. Cycle is fixed at one hour; only the age is
      # operator-configurable, because how often the sweep runs is an
      # implementation detail and how long records survive is the actual
      # retention decision.
      printf 'olcAccessLogPurge: %s+00:00:00 0+01:00:00\n' "$LDAP_ACCESSLOG_PURGE_DAYS"
    } > "$accesslog_overlay"
    log "enabling accesslog overlay (${LDAP_ACCESSLOG_OPS}, purge after ${LDAP_ACCESSLOG_PURGE_DAYS}d)"
    sed -i "/^#__ACCESSLOG_OVERLAY__$/{r ${accesslog_overlay}
d}" "$cn_config"
  else
    sed -i -e '/^#__ACCESSLOG_DB__$/d' -e '/^#__ACCESSLOG_OVERLAY__$/d' "$cn_config"
  fi

  # olcPPolicyDefault: single-line conditional, same anchored r/d technique
  # as the blocks above. Must track LDAP_PASSWORD_POLICY_ENABLED exactly —
  # the DN it points to (rendered from the raw LDAP_ROOT_DN shell var, same
  # as the unique overlay's filters above, ahead of the generic token sed
  # below) only exists if 03-base-structure.ldif's own password-policy
  # block is ALSO enabled; see the matching #__PASSWORD_POLICY__ handling
  # further down for the entry itself.
  if [ "$LDAP_PASSWORD_POLICY_ENABLED" = "true" ] || [ "$LDAP_PASSWORD_POLICY_ENABLED" = "1" ]; then
    ppolicy_default="${work}/ppolicy-default.ldif"
    printf 'olcPPolicyDefault: cn=default,ou=policies,%s\n' "$LDAP_ROOT_DN" > "$ppolicy_default"
    log "enabling password policy (cn=default,ou=policies,${LDAP_ROOT_DN})"
    sed -i "/^#__PPOLICY_DEFAULT__$/{r ${ppolicy_default}
d}" "$cn_config"
  else
    log "LDAP_PASSWORD_POLICY_ENABLED is false — no olcPPolicyDefault, ppolicy overlay only hashes"
    sed -i '/^#__PPOLICY_DEFAULT__$/d' "$cn_config"
  fi

  sed -i \
    -e "s|__LDAP_ROOT_DN__|${LDAP_ROOT_DN}|g" \
    -e "s|__LDAP_ADMIN_DN__|${LDAP_ADMIN_DN}|g" \
    -e "s|__LDAP_ADMIN_PW_HASH__|${ADMIN_PW_HASH}|g" \
    -e "s|__LDAP_DATA_DIR__|${MDB_DIR}|g" \
    -e "s|__LDAP_DB_MAX_SIZE__|${LDAP_DB_MAX_SIZE}|g" \
    -e "s|__LDAP_RUN_DIR__|${RUN_DIR}|g" \
    -e "s|__LDAP_PASSWORD_HASH__|${LDAP_PASSWORD_HASH}|g" \
    -e "s|__LDAP_SIZE_LIMIT__|${LDAP_SIZE_LIMIT}|g" \
    -e "s|__LDAP_TIME_LIMIT__|${LDAP_TIME_LIMIT}|g" \
    "$cn_config"

  cn_config_admin="${work}/02-cn-config-admin.ldif"
  sed -e "s|__LDAP_ADMIN_PW_HASH__|${ADMIN_PW_HASH}|g" \
    "${BOOTSTRAP_DIR}/02-cn-config-admin.ldif" > "$cn_config_admin"

  base_structure="${work}/03-base-structure.ldif"
  cp "${BOOTSTRAP_DIR}/03-base-structure.ldif" "$base_structure"

  # Password policy entries: whole-entry-pair conditional, same anchored
  # r/d technique as #__UNIQUE_OVERLAY__ above. pwdPolicy is AUXILIARY
  # (per slapo-ppolicy(5) / the ppolicy internal schema), so it rides on a
  # structural class — `device` (from core.schema, already loaded) is used
  # rather than invented, since it needs nothing but the `cn` this entry
  # already has. objectClass/attribute names below are not guessed: see
  #   docker run --rm --entrypoint sh <image> -c \
  #     "grep -aoE 'pwdPolicy|pwdSafeModify|pwdCheckQuality|pwdAttribute|
  #      pwdMinLength|pwdInHistory|pwdLockout|pwdMaxFailure|
  #      pwdLockoutDuration|pwdMaxAge' /usr/lib/openldap/ppolicy.so | sort -u"
  # which confirms every one of them exists verbatim in this build.
  if [ "$LDAP_PASSWORD_POLICY_ENABLED" = "true" ] || [ "$LDAP_PASSWORD_POLICY_ENABLED" = "1" ]; then
    policy_entries="${work}/password-policy.ldif"
    {
      printf 'dn: ou=policies,%s\n' "$LDAP_ROOT_DN"
      printf 'objectClass: organizationalUnit\n'
      printf 'ou: policies\n'
      printf '\n'
      printf 'dn: cn=default,ou=policies,%s\n' "$LDAP_ROOT_DN"
      printf 'objectClass: top\n'
      printf 'objectClass: device\n'
      printf 'objectClass: pwdPolicy\n'
      printf 'cn: default\n'
      printf 'pwdAttribute: userPassword\n'
      # pwdCheckQuality must be >=1 for pwdMinLength to be enforced at all —
      # 1 (not 2) so a missing/unreachable password-quality module never
      # blocks writes outright; length is still checked either way.
      printf 'pwdCheckQuality: 1\n'
      printf 'pwdMinLength: %s\n' "$LDAP_PASSWORD_MIN_LENGTH"
      printf 'pwdInHistory: 5\n'
      printf 'pwdLockout: TRUE\n'
      printf 'pwdMaxFailure: %s\n' "$LDAP_PASSWORD_MAX_FAILURE"
      printf 'pwdLockoutDuration: %s\n' "$LDAP_PASSWORD_LOCKOUT_DURATION"
      printf 'pwdFailureCountInterval: %s\n' "$LDAP_PASSWORD_FAILURE_INTERVAL"
      # 0 = no forced expiry. Forced periodic rotation is the thing NIST
      # 800-63B specifically recommends AGAINST — it measurably pushes
      # users toward weaker, more predictable passwords (password1,
      # password2, ...) instead of stronger ones. pwdMaxFailure/lockout
      # above is the actual defense against credential stuffing/guessing;
      # rotation-on-a-timer is not.
      printf 'pwdMaxAge: 0\n'
      # Requires the CURRENT password to be supplied for a self-service
      # change. Without this, ldappasswd/any modify to userPassword
      # succeeds with no proof of the old value — see README, "Password
      # policy", for the exact 53/"unwilling to verify old password" vs.
      # silent-success behavior this fixes.
      printf 'pwdSafeModify: TRUE\n'
    } > "$policy_entries"
    log "creating password policy (cn=default,ou=policies,${LDAP_ROOT_DN})"
    sed -i "/^#__PASSWORD_POLICY__$/{r ${policy_entries}
d}" "$base_structure"
  else
    log "LDAP_PASSWORD_POLICY_ENABLED is false — no policy entries created"
    sed -i '/^#__PASSWORD_POLICY__$/d' "$base_structure"
  fi

  sed -i \
    -e "s|__LDAP_ROOT_DN__|${LDAP_ROOT_DN}|g" \
    -e "s|__LDAP_ROOT_DC__|${LDAP_ROOT_DC}|g" \
    -e "s|__LDAP_ORG_NAME__|${LDAP_ORG_NAME}|g" \
    -e "s|__LDAP_ADMIN_DN__|${LDAP_ADMIN_DN}|g" \
    -e "s|__LDAP_ADMIN_RDN_VALUE__|${LDAP_ADMIN_RDN_VALUE}|g" \
    -e "s|__LDAP_ADMIN_PW_HASH__|${ADMIN_PW_HASH}|g" \
    "$base_structure"

  log "loading cn=config (slapadd -n 0)"
  slapadd -n 0 -F "$CONFIG_DIR" -l "$cn_config"

  # olcDatabase={0}config,cn=config is created implicitly by slapd itself —
  # slapadd (add-only) can't touch it, so grant its dedicated admin identity
  # (cn=admin,cn=config) via an offline MODIFY instead.
  log "granting cn=config admin identity (slapmodify -n 0)"
  slapmodify -n 0 -F "$CONFIG_DIR" -l "$cn_config_admin"

  # D5: exactly one node may mint the base DIT, or each would create its own
  # entryUUID for the same DN and replication would conflict forever.
  #
  # Two rules, both needed:
  #
  #   a) Only serverID 1 is ever allowed to create it. A peer probe alone is
  #      NOT sufficient: when a whole cluster is created at once, every node
  #      probes while every other node is still bootstrapping, every probe
  #      comes back empty, and every node creates its own base entry. This
  #      was observed — a 3-node cold start left node 1 on one entryUUID and
  #      nodes 2/3 on another. Ordinal-based election has no such race
  #      because it needs no communication at all.
  #   b) Even serverID 1 defers if some peer already holds the suffix. That
  #      covers losing node 1's volume while the others still hold data:
  #      re-minting the base entry there would collide with the surviving
  #      copy, so it pulls instead.
  #
  # Nodes other than serverID 1 simply start with an empty database and let
  # syncrepl's initial refresh populate it — the normal consumer path.
  LOAD_BASE_DIT=1
  if [ "$LDAP_REPLICATION_ENABLED" = "true" ] || [ "$LDAP_REPLICATION_ENABLED" = "1" ]; then
    if [ "$LDAP_SERVER_ID" -ne 1 ]; then
      log "replication enabled and serverID is ${LDAP_SERVER_ID} (not 1) — not creating the base DIT; syncrepl will populate it (D5a)"
      LOAD_BASE_DIT=0
    else
      log "replication enabled and serverID is 1 — checking peers for an existing base DIT before creating one (D5b)"
      peer_pw_file="${work}/peer-pw"
      (umask 077; printf '%s' "$LDAP_REPLICATION_PASSWORD" > "$peer_pw_file")
      OLDIFS=$IFS
      IFS=','
      for peer in $LDAP_REPLICATION_PEERS; do
        peer=$(printf '%s' "$peer" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
        [ -n "$peer" ] || continue
        # Authenticated with the replication identity (the one syncrepl itself
        # uses): an anonymous probe is refused by peers running
        # LDAP_DISALLOW_ANON_BIND / LDAP_REQUIRE_AUTHC, which reads as "no base
        # DIT" and would mint a second, conflicting one. Any failure — refused,
        # unreachable, wrong credentials — still counts as "no base DIT found",
        # exactly as before (#203/#204 semantics unchanged).
        if ldapsearch -x -H "$peer" -D "$LDAP_REPLICATION_BIND_DN" -y "$peer_pw_file" -b "$LDAP_ROOT_DN" -s base -o nettimeout=3 -l 5 '(objectClass=*)' 1.1 >/dev/null 2>&1; then
          log "peer already has the base DIT: ${peer} — skipping local slapadd -n 1"
          LOAD_BASE_DIT=0
          break
        fi
      done
      IFS=$OLDIFS
      rm -f "$peer_pw_file"
    fi
  fi

  if [ "$LOAD_BASE_DIT" -eq 1 ]; then
    log "loading base DN + admin entry (slapadd -n 1)"
    slapadd -n 1 -F "$CONFIG_DIR" -l "$base_structure"
  fi

  rm -rf "$work"
  trap 'rollback_bootstrap' EXIT

  # Seeding runs here, before the marker is written, while rollback_bootstrap
  # is still armed: a failing seed (set -eu kills ldapadd on a non-zero exit)
  # now discards the whole partial bootstrap instead of leaving a
  # marked-complete volume with a half-applied seed, so the next boot retries
  # the real bootstrap and reports the real error again instead of silently
  # coming up "healthy" with a partial seed (issue #203).
  #
  # Only the node that actually created the base DIT (LOAD_BASE_DIT=1) has a
  # local base entry to seed under. On any other replica the base DN doesn't
  # exist locally yet — it arrives later via syncrepl — so ldapadd there
  # fails with noSuchObject; skip seeding entirely and let replication supply
  # the data instead.
  if [ "$LOAD_BASE_DIT" -eq 1 ] && [ -d "$LDAP_SEED_DIR" ] && [ -n "$(ls -A "$LDAP_SEED_DIR"/*.ldif 2>/dev/null)" ]; then
    log "seeding: starting temporary slapd to apply ${LDAP_SEED_DIR}/*.ldif"
    start_temp_slapd

    # #220: -y (file), not -w (argv). Private 0700 dir, removed on every exit path.
    seed_work=$(mktemp -d)
    trap 'rm -rf "$seed_work"; rollback_bootstrap' EXIT
    seed_pw_file="${seed_work}/admin-pw"
    (umask 077; printf '%s' "$LDAP_ADMIN_PASSWORD" > "$seed_pw_file") || die "cannot write the temporary admin password file"

    for f in "$LDAP_SEED_DIR"/*.ldif; do
      [ -e "$f" ] || continue
      log "applying seed file: ${f}"
      ldapadd -x -H "$SETUP_LDAPI_URL" -D "$LDAP_ADMIN_DN" -y "$seed_pw_file" -f "$f"
    done
    rm -rf "$seed_work"
    trap 'rollback_bootstrap' EXIT

    log "seeding complete — stopping temporary slapd"
    stop_temp_slapd
  elif [ -d "$LDAP_SEED_DIR" ] && [ -n "$(ls -A "$LDAP_SEED_DIR"/*.ldif 2>/dev/null)" ]; then
    log "seed files present in ${LDAP_SEED_DIR} but this replica receives the base DIT via replication — skipping seeding"
  else
    log "seed dir ${LDAP_SEED_DIR} is empty or absent — nothing to seed"
  fi

  date -u +%FT%TZ > "$MARKER"
  trap - EXIT HUP INT TERM
  log "bootstrap complete"
else
  log "bootstrap marker present — skipping bootstrap, using existing directory"
fi

# ---------------------------------------------------------------------------
# 3b. Hardening reconciliation. Runs on every boot (bootstrap or not) as an
#     OFFLINE slapmodify on cn=config — no temporary slapd needed — so a
#     changed env var or an upgraded image takes effect on an existing volume.
#     Ownership rule: Group A limits (and every opt-in that is switched ON)
#     are env-owned and overwritten each start. When an opt-in is switched
#     OFF, its attribute is removed only if its current value is exactly what
#     this script writes (hd_clear); any other value was set by an operator
#     via ldapmodify and is left alone, with a log line.
# ---------------------------------------------------------------------------
hardening_ldif=$(mktemp)
hd_dump=$(mktemp)
hd_db=$(mktemp)
slapcat -n 0 -F "$CONFIG_DIR" -l "$hd_dump"

# hd_clear <entry dn> <attr> <value we write>: emit a delete for <attr> only
# when it is present with exactly that single value.
hd_clear() {
  _hd_cur=$(sed -n "/^dn: $1\$/,/^\$/p" "$hd_dump" | grep "^$2: " || true)
  if [ -z "$_hd_cur" ]; then
    return 0
  elif [ "$_hd_cur" = "$2: $3" ]; then
    printf 'delete: %s\n-\n' "$2"
  else
    log "leaving operator-set $2 on $1 untouched (${_hd_cur})"
  fi
}
{
  printf 'dn: cn=config\nchangetype: modify\n'
  printf 'replace: olcIdleTimeout\nolcIdleTimeout: %s\n-\n' "$LDAP_IDLE_TIMEOUT"
  printf 'replace: olcWriteTimeout\nolcWriteTimeout: %s\n-\n' "$LDAP_WRITE_TIMEOUT"
  printf 'replace: olcConnMaxPending\nolcConnMaxPending: %s\n-\n' "$LDAP_CONN_MAX_PENDING"
  printf 'replace: olcConnMaxPendingAuth\nolcConnMaxPendingAuth: %s\n-\n' "$LDAP_CONN_MAX_PENDING_AUTH"
  printf 'replace: olcSockbufMaxIncoming\nolcSockbufMaxIncoming: %s\n-\n' "$LDAP_SOCKBUF_MAX_INCOMING"
  printf 'replace: olcSockbufMaxIncomingAuth\nolcSockbufMaxIncomingAuth: %s\n-\n' "$LDAP_SOCKBUF_MAX_INCOMING_AUTH"
  printf 'replace: olcMaxFilterDepth\nolcMaxFilterDepth: %s\n-\n' "$LDAP_MAX_FILTER_DEPTH"
  if { [ "$LDAP_TLS_ENABLED" = "true" ] || [ "$LDAP_TLS_ENABLED" = "1" ]; } && [ -n "$LDAP_TLS_EC_NAME" ]; then
    # ECDHE curve only: no DH parameter file, since the cipher suite baseline
    # is ECDHE-only and a DH file would add nothing but a weak-param foot-gun.
    printf 'replace: olcTLSECName\nolcTLSECName: %s\n-\n' "$LDAP_TLS_EC_NAME"
  else
    # env-owned like Group A: the curve is only ever written from
    # LDAP_TLS_EC_NAME, and a stale one silently narrows key exchange.
    printf 'replace: olcTLSECName\n-\n'
  fi
  if [ "$LDAP_REQUIRE_TLS" = "true" ] || [ "$LDAP_REQUIRE_TLS" = "1" ]; then
    # ssf=128 alone, not "ssf=128 tls=128": `tls=` counts only the TLS layer,
    # which a unix socket never has, so it refuses ldapi:// even with
    # olcLocalSSF raised (verified live: err=13 on the HEALTHCHECK). ssf=
    # still rejects plaintext TCP (ssf 0) and accepts TLS >=128 bits.
    # ldapi:// is rated at olcLocalSSF (default 71), below ssf=128, so the
    # HEALTHCHECK, this script's own ldapi calls and the backup scripts would
    # be refused; raising it to 128 declares that local socket trusted.
    printf 'replace: olcSecurity\nolcSecurity: ssf=128\n-\n'
    printf 'replace: olcLocalSSF\nolcLocalSSF: 128\n-\n'
  else
    hd_clear cn=config olcSecurity 'ssf=128'
    hd_clear cn=config olcLocalSSF 128
  fi
  if [ "$LDAP_DISALLOW_ANON_BIND" = "true" ] || [ "$LDAP_DISALLOW_ANON_BIND" = "1" ]; then
    printf 'replace: olcDisallows\nolcDisallows: bind_anon\n-\n'
  else
    hd_clear cn=config olcDisallows bind_anon
  fi
  if [ "$LDAP_REQUIRE_AUTHC" = "true" ] || [ "$LDAP_REQUIRE_AUTHC" = "1" ]; then
    printf 'replace: olcRequires\nolcRequires: authc\n-\n'
  else
    hd_clear cn=config olcRequires authc
  fi
  # lastbind: pwdLastSuccess is written on the entry a bind succeeded on, and
  # under multi-provider replication that write replicates like any other
  # modify (see the Change Package for the entryCSN caveat). The precision
  # bounds it to at most one write per user per interval.
  # Off: remove the pair only when olcLastBind is the TRUE this script writes.
  if [ "$LDAP_LASTBIND_ENABLED" = "true" ] || [ "$LDAP_LASTBIND_ENABLED" = "1" ]; then
    printf 'replace: olcLastBind\nolcLastBind: TRUE\n-\n' > "$hd_db"
    printf 'replace: olcLastBindPrecision\nolcLastBindPrecision: %s\n-\n' "$LDAP_LASTBIND_PRECISION" >> "$hd_db"
  elif sed -n '/^dn: olcDatabase={1}mdb,cn=config$/,/^$/p' "$hd_dump" | grep -qx 'olcLastBind: TRUE'; then
    printf 'delete: olcLastBind\n-\n' > "$hd_db"
    sed -n '/^dn: olcDatabase={1}mdb,cn=config$/,/^$/p' "$hd_dump" | grep -q '^olcLastBindPrecision: ' && printf 'delete: olcLastBindPrecision\n-\n' >> "$hd_db"
  elif sed -n '/^dn: olcDatabase={1}mdb,cn=config$/,/^$/p' "$hd_dump" | grep -q '^olcLastBind'; then
    log "leaving operator-set olcLastBind on the main database untouched"
  fi
  if [ -s "$hd_db" ]; then
    printf '\ndn: olcDatabase={1}mdb,cn=config\nchangetype: modify\n'
    cat "$hd_db"
  fi
} > "$hardening_ldif"
log "reconciling hardening settings (slapmodify -n 0)"
slapmodify -n 0 -F "$CONFIG_DIR" -l "$hardening_ldif"
rm -f "$hardening_ldif" "$hd_dump" "$hd_db"

# ---------------------------------------------------------------------------
# 3b2. Paged-total rule (LDAP_PAGED_TOTAL_LIMIT). Stateless: the desired state
#      is derived from the variable and the olcLimits values actually present,
#      so there is nothing (no marker, no record) that can drift or survive a
#      crash, and every start converges. slapd applies only the FIRST olcLimits
#      rule that matches a DN and allows one rule per selector, so the rule is
#      appended behind the operator's DN/group rules and `users` is reserved
#      for it while the feature is enabled. Unset = hands off (nothing is read).
#      FAIL CLOSED in both directions: a set/off request that cannot be applied,
#      verified or rolled back aborts startup instead of serving an unproven
#      policy; the previous config file is restored atomically first.
# ---------------------------------------------------------------------------
# DEFAULT-DENY classification of olcLimits values (one awk program, O(n)).
# For each stored rule exactly one of three outcomes:
#   other     the first token, after quote removal and case folding, is clearly
#             NOT the selector `users`: the rule is none of our business and is
#             left alone;
#   reserved  selector `users` with ONLY a size.prtotal limit whose value is
#             parsed with certainty: the rule this setting manages;
#   abort     anything else whose first token is `users`, or that the parser is
#             not certain about: startup aborts in set/off mode before any
#             change. There is no "another shape, ignore" fall-through.
# What the parser handles, exactly (probed against the image's slapd 2.6.15):
#   tokens    split on any isspace() character: space, tab, VT, FF, CR, NL;
#   quotes    a double quote toggles a quoted segment anywhere inside a token
#             (`"users"`, `size.prtotal="unlimited"`, `us"ers"`); quotes are
#             removed and white space inside them belongs to the token, so a
#             quoted DN with spaces and commas (or a 64 KiB dn.regex) is one token;
#   empty     an empty argument (`""`) after the selector is ignored, like
#             limits.c does; an empty token BEFORE the selector is `abort`;
#   case      selector, keys and keywords compare case-insensitively;
#   value     surrounding white space is trimmed; unlimited, none, -1 (and -01,
#             any zero padding) = unlimited; disabled; hard; a decimal integer
#             with optional sign and zero padding, -0 = 0, anything below -1 is
#             `abort`; more than 10 digits is `abort`;
#   abort     also: an unterminated quote, a backslash before a double quote,
#             a backslash in a `users` rule or in a first token that becomes
#             `users` without it, a rule without tokens, a `users` rule with
#             any other limit or argument, a value that cannot be base64
#             decoded, a value without a {N} index, an unreadable or empty dump.
# Single quotes are ordinary characters (slapd rejects them around a selector
# or value and they appear inside DNs).
# shellcheck disable=SC2016 # the awk program is deliberately single-quoted
PT_AWK='
function isws(c) { return (c == " " || c == "\t" || c == "\013" || c == "\014" || c == "\015" || c == "\n") }
function flush(   t) {
  t = cur substr(buf, segstart, i - segstart)
  ntok++; tokv[ntok] = t; tbs[ntok] = cbs
  cur = ""; have = 0; cbs = 0
}
{ buf = (NR == 1) ? $0 : buf "\n" $0 }
END {
  n = length(buf); q = 0; have = 0; cur = ""; ntok = 0; cbs = 0; segstart = 1
  for (i = 1; i <= n; i++) {
    c = substr(buf, i, 1)
    if (c == "\"") {
      cur = cur substr(buf, segstart, i - segstart); segstart = i + 1
      q = !q; have = 1
    } else if (c == "\\") {
      if (substr(buf, i + 1, 1) == "\"") { print "abort"; exit }
      cbs = 1; have = 1
    } else if (!q && isws(c)) {
      if (have) { flush(); }
      segstart = i + 1
    } else {
      have = 1
    }
  }
  if (q) { print "abort"; exit }
  i = n + 1
  if (have) flush()
  first = 0
  for (k = 1; k <= ntok; k++) if (tokv[k] != "") { first = k; break }
  if (first != 1) { print "abort"; exit }
  sel = tolower(tokv[1])
  if (tbs[1]) { t = sel; gsub(/\\/, "", t); if (t == "users") { print "abort"; exit } }
  if (sel != "users") { print "other"; exit }
  m = 0
  for (k = 1; k <= ntok; k++) if (tokv[k] != "") { m++; idx[m] = k; if (tbs[k]) { print "abort"; exit } }
  if (m != 2) { print "abort"; exit }
  tok = tokv[idx[2]]
  eq = index(tok, "=")
  if (eq == 0) { print "abort"; exit }
  if (tolower(substr(tok, 1, eq - 1)) != "size.prtotal") { print "abort"; exit }
  v = substr(tok, eq + 1)
  while (length(v) > 0 && isws(substr(v, 1, 1))) v = substr(v, 2)
  while (length(v) > 0 && isws(substr(v, length(v), 1))) v = substr(v, 1, length(v) - 1)
  lv = tolower(v)
  if (lv == "unlimited" || lv == "none") { print "reserved unlimited"; exit }
  if (lv == "disabled") { print "reserved disabled"; exit }
  if (lv == "hard") { print "reserved hard"; exit }
  sign = ""
  d = lv
  if (substr(d, 1, 1) == "-") { sign = "-"; d = substr(d, 2) } else if (substr(d, 1, 1) == "+") { d = substr(d, 2) }
  if (d !~ /^[0-9]+$/) { print "abort"; exit }
  while (length(d) > 1 && substr(d, 1, 1) == "0") d = substr(d, 2)
  if (length(d) > 10) { print "abort"; exit }
  num = d + 0
  if (sign == "-") {
    if (num == 1) { print "reserved unlimited"; exit }
    if (num == 0) { print "reserved 0"; exit }
    print "abort"; exit
  }
  print "reserved " num
}
'

# paged_total_rules <dump> <out>: writes "<index> <class> <value> <b64>" for
# EVERY olcLimits value of the main database to <out>, in the order slapd holds
# them (first match wins, so order is the policy). class is other|reserved|abort
# (see above); b64 is the base64 of the stored "{N}spec" (the exact delete value;
# `-` for other rules), so no raw rule text, which may hold newlines, ever sits in
# the list. Every step is a separate command whose status is checked (POSIX sh
# has no pipefail); an unreadable dump, a missing database entry, an empty block
# or a decode error is a FAILURE (return 1), never an empty or partial list.
# slapcat writes a value as `olcLimits:: <base64>` when it is not plain ASCII
# text (a Korean DN, a tab, a leading space).
paged_total_rules() {
  pt_blk=$(mktemp) || return 1
  pt_unf=$(mktemp) || return 1
  if ! sed -n '/^dn: olcDatabase={1}mdb,cn=config$/,/^$/p' "$1" > "$pt_blk" || [ ! -s "$pt_blk" ]; then
    rm -f "$pt_blk" "$pt_unf"
    return 1
  fi
  if ! sed -e ':a' -e '$!N' -e 's/\n //' -e 'ta' -e 'P' -e 'D' "$pt_blk" > "$pt_unf"; then
    rm -f "$pt_blk" "$pt_unf"
    return 1
  fi
  : > "$2" || return 1
  pt_rc=0
  while IFS= read -r pt_line; do
    case "$pt_line" in
      "olcLimits: "*) pt_val=${pt_line#olcLimits: } ;;
      "olcLimits:: "*)
        if ! pt_val=$(printf '%s' "${pt_line#olcLimits:: }" | base64 -d 2>/dev/null) || [ -z "$pt_val" ]; then
          pt_rc=1 # undecodable: could be the very rule looked for
          break
        fi
        # dash drops NUL bytes in $(...) while slapd reads the value as a C
        # string cut at the first NUL: a value holding one is judged on other
        # bytes than slapd applies, so it is unparseable.
        pt_n_all=$(printf '%s' "${pt_line#olcLimits:: }" | base64 -d 2>/dev/null | wc -c)
        pt_n_nonul=$(printf '%s' "${pt_line#olcLimits:: }" | base64 -d 2>/dev/null | tr -d '\000' | wc -c)
        if [ "$pt_n_all" -ne "$pt_n_nonul" ]; then
          pt_rc=1
          break
        fi
        ;;
      *) continue ;;
    esac
    case "$pt_val" in
      "{"[0-9]*"}"*)
        pt_i=${pt_val#"{"}
        pt_i=${pt_i%%"}"*}
        pt_spec=${pt_val#*"}"}
        if ! pt_cls=$(printf '%s' "$pt_spec" | awk "$PT_AWK") || [ -z "$pt_cls" ]; then pt_rc=1; break; fi
        pt_b64='-'
        case "$pt_cls" in
          reserved*)
            if ! pt_b64=$(printf '%s' "$pt_val" | base64 | tr -d '\n'); then pt_rc=1; break; fi
            ;;
        esac
        pt_class=${pt_cls%% *}
        pt_pv='-'
        case "$pt_cls" in
          *" "*) pt_pv=${pt_cls#* } ;;
        esac
        if ! printf '%s %s %s %s\n' "$pt_i" "$pt_class" "$pt_pv" "$pt_b64" >> "$2"; then pt_rc=1; break; fi
        ;;
      *)
        pt_rc=1 # an olcLimits value without a {N} index cannot be ordered
        break
        ;;
    esac
  done < "$pt_unf"
  rm -f "$pt_blk" "$pt_unf"
  return "$pt_rc"
}
paged_total_fail() { die "paged-total reconcile failed; refusing to start"; }
paged_total_unsure() { die "an olcLimits rule for the selector 'users' is not the shape this setting manages, or could not be classified with certainty; refusing to start (LDAP_PAGED_TOTAL_LIMIT=${LDAP_PAGED_TOTAL_LIMIT})"; }
if [ -n "$LDAP_PAGED_TOTAL_LIMIT" ]; then
  pt_t0=$(date +%s)
  pt_db_file="${CONFIG_DIR}/cn=config/olcDatabase={1}mdb.ldif"
  pt_dump=$(mktemp)
  pt_list=$(mktemp)
  pt_ops=$(mktemp)
  # Fail closed BEFORE changing anything: an unreadable or empty dump aborts.
  slapcat -n 0 -F "$CONFIG_DIR" -o ldif-wrap=no -l "$pt_dump" || paged_total_fail
  paged_total_rules "$pt_dump" "$pt_list" || paged_total_fail
  pt_res_idx=''
  pt_res_val=''
  pt_res_b64=''
  pt_n_res=0
  pt_last_idx=''
  while IFS=' ' read -r pt_idx pt_class pt_pv pt_b64; do
    pt_last_idx="{${pt_idx}}"
    case "$pt_class" in
      other) ;;
      reserved)
        pt_n_res=$((pt_n_res + 1))
        pt_res_idx="{${pt_idx}}"
        pt_res_val=$pt_pv
        pt_res_b64=$pt_b64
        ;;
      *) paged_total_unsure ;;
    esac
  done < "$pt_list"
  if [ "$pt_n_res" -gt 1 ]; then
    die "more than one olcLimits rule for the selector 'users' is present; refusing to start (LDAP_PAGED_TOTAL_LIMIT=${LDAP_PAGED_TOTAL_LIMIT})"
  fi
  if [ "$LDAP_PAGED_TOTAL_LIMIT" = off ]; then
    if [ "$pt_n_res" -eq 1 ]; then
      printf 'delete: olcLimits\nolcLimits:: %s\n-\n' "$pt_res_b64" > "$pt_ops"
      log "LDAP_PAGED_TOTAL_LIMIT=off: removing the rule 'users size.prtotal=${pt_res_val}'"
    fi
  else
    pt_want="users size.prtotal=${LDAP_PAGED_TOTAL_LIMIT}"
    if [ "$pt_n_res" -eq 0 ]; then
      printf 'add: olcLimits\nolcLimits: %s\n-\n' "$pt_want" > "$pt_ops"
    elif [ "$pt_res_val" = "$LDAP_PAGED_TOTAL_LIMIT" ] && [ "$pt_res_idx" = "$pt_last_idx" ]; then
      : # converged by VALUE (not text): the one owned rule, and it is the LAST value (first match wins)
    else
      # another value, or the right value in the wrong place (an operator rule
      # behind it would never be reached): delete and re-append
      printf 'delete: olcLimits\nolcLimits:: %s\n-\nadd: olcLimits\nolcLimits: %s\n-\n' "$pt_res_b64" "$pt_want" > "$pt_ops"
    fi
  fi
  if [ -s "$pt_ops" ]; then
    pt_backup=$(mktemp)
    pt_ldif=$(mktemp)
    { printf 'dn: olcDatabase={1}mdb,cn=config\nchangetype: modify\n'; cat "$pt_ops"; } > "$pt_ldif"
    # A verified backup (non-empty, identical) or nothing is touched at all.
    if ! cp -p "$pt_db_file" "$pt_backup" 2>/dev/null || [ ! -s "$pt_backup" ] || ! cmp -s "$pt_db_file" "$pt_backup"; then
      paged_total_fail
    fi
    pt_ok=''
    if slapmodify -n 0 -F "$CONFIG_DIR" -l "$pt_ldif" \
      && slapcat -n 0 -F "$CONFIG_DIR" -o ldif-wrap=no -l "$pt_dump" \
      && paged_total_rules "$pt_dump" "$pt_list"; then
      # verify what is stored now (semantically), not what was asked for
      pt_n=0
      pt_now_idx=''
      pt_now_val=''
      pt_bad=''
      pt_last_now=''
      while IFS=' ' read -r pt_idx pt_class pt_pv pt_b64; do
        pt_last_now="{${pt_idx}}"
        case "$pt_class" in
          other) ;;
          reserved) pt_n=$((pt_n + 1)); pt_now_idx="{${pt_idx}}"; pt_now_val=$pt_pv ;;
          *) pt_bad=1 ;;
        esac
      done < "$pt_list"
      if [ -n "$pt_bad" ]; then
        : # a stored value that cannot be classified with certainty is never "verified"
      elif [ "$LDAP_PAGED_TOTAL_LIMIT" = off ]; then
        # no reserved-shape rule may remain, whatever its spelling
        if [ "$pt_n" -eq 0 ]; then pt_ok=1; fi
      elif [ "$pt_n" -eq 1 ] && [ "$pt_now_val" = "$LDAP_PAGED_TOTAL_LIMIT" ] && [ "$pt_now_idx" = "$pt_last_now" ]; then
        pt_ok=1
      fi
    fi
    if [ -z "$pt_ok" ]; then
      # put the previous file back (only if it changed), via a copy in the same
      # directory and an atomic rename, and verify it
      if ! cmp -s "$pt_db_file" "$pt_backup"; then
        pt_tmp="${pt_db_file}.restore.$$"
        if cp -p "$pt_backup" "$pt_tmp" 2>/dev/null && cmp -s "$pt_tmp" "$pt_backup" \
          && mv -f "$pt_tmp" "$pt_db_file" 2>/dev/null && cmp -s "$pt_db_file" "$pt_backup"; then
          :
        else
          rm -f "$pt_tmp" 2>/dev/null || :
          die "paged-total reconcile failed and the previous configuration could not be restored; refusing to start"
        fi
      fi
      paged_total_fail
    fi
    rm -f "$pt_backup" "$pt_ldif"
  fi
  rm -f "$pt_dump" "$pt_list" "$pt_ops"
  log "paged-total reconcile took $(($(date +%s) - pt_t0))s"
fi

# ---------------------------------------------------------------------------
# 3c. Optional modules (D6..D9). Same offline mechanism as 3b, but overlays
#     are entries, not attributes, so each one is add / modify / delete
#     depending on what cn=config currently holds. Existing overlays are
#     modified in place (never deleted and re-added) to keep their {N} order
#     stable across boots.
# ---------------------------------------------------------------------------
cfg_dump=$(mktemp)
slapcat -n 0 -F "$CONFIG_DIR" -l "$cfg_dump"
MAIN_DB_DN="olcDatabase={1}mdb,cn=config"

# Prints the current DN of an overlay on the main database, or nothing.
overlay_dn() {
  sed -n "s/^dn: \\(olcOverlay={[0-9]*}$1,olcDatabase={1}mdb,cn=config\\)\$/\\1/p" "$cfg_dump" | head -n 1
}

# reconcile_overlay <name> <on|off> <extra objectClass or ''> <attr-lines-file>
# attr-lines-file holds `attr: value` lines that make up the overlay's config.
reconcile_overlay() {
  _ro_name=$1; _ro_on=$2; _ro_oc=$3; _ro_attrs=$4
  _ro_dn=$(overlay_dn "$_ro_name")
  if [ "$_ro_on" = "on" ]; then
    if [ -z "$_ro_dn" ]; then
      log "enabling ${_ro_name} overlay"
      printf 'dn: olcOverlay=%s,%s\nchangetype: add\nobjectClass: olcOverlayConfig\n' "$_ro_name" "$MAIN_DB_DN"
      [ -z "$_ro_oc" ] || printf 'objectClass: %s\n' "$_ro_oc"
      printf 'olcOverlay: %s\n' "$_ro_name"
      cat "$_ro_attrs"
      printf '\n'
    elif [ -s "$_ro_attrs" ]; then
      printf 'dn: %s\nchangetype: modify\n' "$_ro_dn"
      # attribute names never contain whitespace, so word-splitting is safe
      # shellcheck disable=SC2013
      for _ro_attr in $(sed 's/:.*//' "$_ro_attrs" | sort -u); do
        printf 'replace: %s\n' "$_ro_attr"
        grep "^${_ro_attr}: " "$_ro_attrs"
        printf -- '-\n'
      done
      printf '\n'
    fi
  elif [ -n "$_ro_dn" ]; then
    log "removing ${_ro_name} overlay (disabled)"
    printf 'dn: %s\nchangetype: delete\n\n' "$_ro_dn"
  fi
}

attrs_tmp=$(mktemp)
modules_ldif=$(mktemp)
overlays_ldif=$(mktemp)

# Module loads first, in their own slapmodify run, so the overlay entries in
# the second run find their objectClasses. Only nestgroup is new to the
# module list; the others are already in the bootstrap template but a volume
# from an older image may predate them.
{
  for _mod in constraint deref dynlist sssvlv otp nestgroup; do
    case "$_mod" in
      constraint) _mod_on=$LDAP_CONSTRAINT_ENABLED ;;
      deref) _mod_on=$LDAP_DEREF_ENABLED ;;
      dynlist) _mod_on=$LDAP_DYNLIST_ENABLED ;;
      sssvlv) _mod_on=$LDAP_SSSVLV_MAIN_ENABLED ;;
      otp) _mod_on=$LDAP_OTP_ENABLED ;;
      nestgroup) _mod_on=$LDAP_NESTGROUP_ENABLED ;;
    esac
    if flag_on "$_mod_on" && ! grep -q "^olcModuleLoad: {[0-9]*}${_mod}\\.la\$" "$cfg_dump"; then
      printf 'dn: cn=module{0},cn=config\nchangetype: modify\nadd: olcModuleLoad\nolcModuleLoad: %s.la\n\n' "$_mod"
    fi
  done
} > "$modules_ldif"
if [ -s "$modules_ldif" ]; then
  log "loading missing overlay modules (slapmodify -n 0)"
  slapmodify -n 0 -F "$CONFIG_DIR" -l "$modules_ldif"
fi

# dynlist needs groupOfURLs/memberURL, which live in dyngroup.schema — not in
# the core/cosine/inetorgperson/nis set the bootstrap loads. Loaded only when
# enabled and left in place if the flag is later turned off: removing a schema
# out from under entries that may use it is not something a reconcile should do.
if flag_on "$LDAP_DYNLIST_ENABLED" && ! grep -qi '^dn: cn={[0-9]*}dyngroup,cn=schema,cn=config$' "$cfg_dump"; then
  log "loading dyngroup schema (groupOfURLs, memberURL) for dynlist"
  slapadd -n 0 -F "$CONFIG_DIR" -l /etc/openldap/schema/dyngroup.ldif
fi

# Re-dump so the overlay pass sees the module/schema changes above.
slapcat -n 0 -F "$CONFIG_DIR" -l "$cfg_dump"

{
  # deref: no configuration; presence of the overlay is the feature.
  : > "$attrs_tmp"
  if flag_on "$LDAP_DEREF_ENABLED"; then reconcile_overlay deref on '' "$attrs_tmp"; else reconcile_overlay deref off '' "$attrs_tmp"; fi

  # constraint: mail only. One attribute, one regex; see LDAP_CONSTRAINT_MAIL_REGEX.
  printf 'olcConstraintAttribute: mail regex %s\n' "$LDAP_CONSTRAINT_MAIL_REGEX" > "$attrs_tmp"
  if flag_on "$LDAP_CONSTRAINT_ENABLED"; then reconcile_overlay constraint on olcConstraintConfig "$attrs_tmp"; else reconcile_overlay constraint off '' "$attrs_tmp"; fi

  printf 'olcNestGroupBase: %s\n' "$LDAP_NESTGROUP_BASE" > "$attrs_tmp"
  for _ng_flag in $LDAP_NESTGROUP_FLAGS; do printf 'olcNestGroupFlags: %s\n' "$_ng_flag" >> "$attrs_tmp"; done
  if flag_on "$LDAP_NESTGROUP_ENABLED"; then reconcile_overlay nestgroup on olcNestGroupConfig "$attrs_tmp"; else reconcile_overlay nestgroup off '' "$attrs_tmp"; fi

  printf 'olcDynListAttrSet: %s\n' "$LDAP_DYNLIST_ATTRSET" > "$attrs_tmp"
  if flag_on "$LDAP_DYNLIST_ENABLED"; then reconcile_overlay dynlist on olcDynListConfig "$attrs_tmp"; else reconcile_overlay dynlist off '' "$attrs_tmp"; fi

  printf 'olcSssVlvMax: %s\nolcSssVlvMaxKeys: %s\nolcSssVlvMaxPerConn: %s\n' \
    "$LDAP_SSSVLV_MAX" "$LDAP_SSSVLV_MAX_KEYS" "$LDAP_SSSVLV_MAX_PER_CONN" > "$attrs_tmp"
  if flag_on "$LDAP_SSSVLV_MAIN_ENABLED"; then reconcile_overlay sssvlv on olcSssVlvConfig "$attrs_tmp"; else reconcile_overlay sssvlv off '' "$attrs_tmp"; fi

  # otp: no olc* attributes; the oath* schema is compiled into the module.
  : > "$attrs_tmp"
  if flag_on "$LDAP_OTP_ENABLED"; then reconcile_overlay otp on '' "$attrs_tmp"; else reconcile_overlay otp off '' "$attrs_tmp"; fi

  # ppm hooks into the existing ppolicy overlay via its check-module path.
  _pp_dn=$(overlay_dn ppolicy)
  if [ -n "$_pp_dn" ]; then
    _pp_cur=$(sed -n "/^dn: ${_pp_dn}\$/,/^\$/p" "$cfg_dump" | grep '^olcPPolicyCheckModule: ' || true)
    if flag_on "$LDAP_PPM_ENABLED"; then
      printf 'dn: %s\nchangetype: modify\nreplace: olcPPolicyCheckModule\nolcPPolicyCheckModule: /usr/lib/openldap/ppm.so\n\n' "$_pp_dn"
    elif [ "$_pp_cur" = 'olcPPolicyCheckModule: /usr/lib/openldap/ppm.so' ]; then
      printf 'dn: %s\nchangetype: modify\ndelete: olcPPolicyCheckModule\n\n' "$_pp_dn"
    elif [ -n "$_pp_cur" ]; then
      log "leaving operator-set olcPPolicyCheckModule untouched (${_pp_cur})"
    fi
  fi
} > "$overlays_ldif"
if [ -s "$overlays_ldif" ]; then
  log "reconciling optional overlays (slapmodify -n 0)"
  slapmodify -n 0 -F "$CONFIG_DIR" -l "$overlays_ldif"
fi
rm -f "$cfg_dump" "$attrs_tmp" "$modules_ldif" "$overlays_ldif"

# ppm's arguments and the switch that makes ppolicy consult it live on the
# default policy entry (directory data, not cn=config). Written when the
# wiring is missing (fresh bootstrap or a volume from an older image); after
# that the operator's ldapmodify tuning wins, and the arguments are re-applied
# only when LDAP_PPM_MIN_CLASSES is explicitly set in the environment. Removal
# when LDAP_PPM_ENABLED=false always applies. These are offline writes without
# -S/-w: slapmodify stamps them with sid 000 and does not update contextCSN,
# so they are NOT replicated and each node applies its own. A replica that has
# not yet received the entry skips this; run it again after the entry arrives.
if flag_on "$LDAP_PASSWORD_POLICY_ENABLED"; then
  policy_dn="cn=default,ou=policies,${LDAP_ROOT_DN}"
  policy_dump=$(mktemp)
  slapcat -n 1 -F "$CONFIG_DIR" -s "$policy_dn" -a '(objectClass=pwdPolicy)' -l "$policy_dump" 2>/dev/null || true
  if [ -s "$policy_dump" ]; then
    policy_ldif=$(mktemp)
    policy_want_arg="minQuality ${LDAP_PPM_MIN_CLASSES}"
    if flag_on "$LDAP_PPM_ENABLED"; then
      if ! grep -qi '^objectClass: pwdPolicyChecker$' "$policy_dump" \
        || ! grep -q '^pwdUseCheckModule: TRUE$' "$policy_dump" \
        || ! grep -q '^pwdCheckModuleArg:' "$policy_dump" \
        || { [ -n "$_ppm_min_classes_explicit" ] && ! grep -qxF "pwdCheckModuleArg: ${policy_want_arg}" "$policy_dump"; }; then
        {
          printf 'dn: %s\nchangetype: modify\n' "$policy_dn"
          grep -qi '^objectClass: pwdPolicyChecker$' "$policy_dump" || printf 'add: objectClass\nobjectClass: pwdPolicyChecker\n-\n'
          printf 'replace: pwdUseCheckModule\npwdUseCheckModule: TRUE\n-\n'
          printf 'replace: pwdCheckModuleArg\npwdCheckModuleArg: %s\n-\n' "$policy_want_arg"
        } > "$policy_ldif"
      fi
    elif grep -q '^pwdUseCheckModule: TRUE$' "$policy_dump"; then
      printf 'dn: %s\nchangetype: modify\nreplace: pwdUseCheckModule\n-\nreplace: pwdCheckModuleArg\n-\n' "$policy_dn" > "$policy_ldif"
    fi
    if [ -s "$policy_ldif" ]; then
      log "reconciling ppm settings on ${policy_dn} (slapmodify -n 1)"
      slapmodify -n 1 -F "$CONFIG_DIR" -l "$policy_ldif"
    fi
    rm -f "$policy_ldif"
  fi
  rm -f "$policy_dump"
fi

# ---------------------------------------------------------------------------
# 4. Replication reconciliation. Runs on every boot, bootstrap or not, so a
#    peer list change (e.g. scaling replicas) converges on next restart —
#    disabled by default, in which case this section is a no-op.
# ---------------------------------------------------------------------------
if [ "$LDAP_REPLICATION_ENABLED" = "true" ] || [ "$LDAP_REPLICATION_ENABLED" = "1" ]; then
  log "reconciling replication config (olcServerID=${LDAP_SERVER_ID})"

  rc_old_umask=$(umask)
  umask 077
  rc_work=$(mktemp -d)
  # Same reason as the bootstrap traps: the dir can hold replication credentials
  # and dash skips an EXIT trap on a fatal signal, so signals exit explicitly.
  trap 'rm -rf "$rc_work"' EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM

  # Issue #206: cn=config is edited OFFLINE (slapmodify/slapadd/slapcat), never
  # through a temporary slapd. Once olcSyncrepl exists, a running slapd starts
  # its consumer immediately, and stopping it a moment later can interrupt the
  # very first refresh of a wiped node after the base entry landed but before
  # any contextCSN was stored. The real slapd's syncprov then sees a non-empty
  # DB without a contextCSN and mints a fresh one for its OWN serverID
  # ("syncprov_db_open: generated a new ctxcsn"), newer than every entry the
  # peer holds for that sid. Those entries are then "not new enough" locally
  # and absent from this node's present list, so the peer deletes them (and
  # the wiped node never receives them). A wiped multi-provider node must reach
  # the real slapd with a completely empty database.

  server_id_ldif="${rc_work}/server-id.ldif"
  {
    printf 'dn: cn=config\n'
    printf 'changetype: modify\n'
    printf 'replace: olcServerID\n'
    printf 'olcServerID: %s\n' "$LDAP_SERVER_ID"
  } > "$server_id_ldif"
  log "applying olcServerID"
  slapmodify -n 0 -F "$CONFIG_DIR" -l "$server_id_ldif"

  # Detect an existing syncprov overlay by SEARCHING FOR ITS objectClass, not
  # by reading a fixed DN. slapd stores overlays with an ordering prefix in
  # the RDN — the entry created below lands at
  # olcOverlay={3}syncprov,olcDatabase={1}mdb,cn=config (after the three
  # overlays from the bootstrap LDIF), not at the unprefixed DN it was added
  # under. A base-DN probe therefore reports "not present" on every restart,
  # the add is retried, slapd rejects it with
  #   err=80 text=overlay_config(): overlay "syncprov" already in list
  # and `set -e` kills the entrypoint — every replicated node dies on its
  # SECOND start. Observed as "Exited (80)". The one-level objectClass search
  # is prefix-agnostic.
  syncprov_dn="olcOverlay=syncprov,olcDatabase={1}mdb,cn=config"
  syncprov_found=$(slapcat -n 0 -F "$CONFIG_DIR" -a '(objectClass=olcSyncProvConfig)' 2>/dev/null \
    | grep -c '^dn:' || true)
  if [ "${syncprov_found:-0}" -gt 0 ]; then
    log "syncprov overlay already present — leaving as-is"
  else
    syncprov_ldif="${rc_work}/syncprov.ldif"
    {
      printf 'dn: %s\n' "$syncprov_dn"
      printf 'objectClass: olcOverlayConfig\n'
      # The overlay's ATTRIBUTES are named olcSp* (olcSpCheckpoint,
      # olcSpSessionlog, ...) but its objectClass is olcSyncProvConfig.
      # Guessing "olcSpConfig" from the attribute prefix makes slapd reject
      # the add with "Invalid syntax (21) — objectClass: value #1 invalid per
      # syntax", which then leaves the node with no syncprov overlay and no
      # replication. Verified against this build:
      #   grep -a 'olcSyncProvConfig' /usr/lib/openldap/syncprov.so
      printf 'objectClass: olcSyncProvConfig\n'
      printf 'olcOverlay: syncprov\n'
      printf 'olcSpCheckpoint: 100 10\n'
      printf 'olcSpSessionlog: 100\n'
    } > "$syncprov_ldif"
    log "adding syncprov overlay"
    slapadd -n 0 -F "$CONFIG_DIR" -l "$syncprov_ldif"
  fi

  # olcSyncrepl is replaced wholesale (not incrementally) so the set also
  # converges when the peer list shrinks, not just when it grows.
  #
  # rid is tied to each peer's 1-based position in LDAP_REPLICATION_PEERS,
  # stable across every node's config. That position is also how a node
  # recognizes itself (LDAP_SERVER_ID is 1-based over the same list, by
  # construction when auto-derived from the StatefulSet ordinal) — self is
  # deliberately omitted from the rendered set rather than kept and relied
  # on slapd to ignore it, since that ignore-self behavior isn't verified
  # against this build.
  # ORDER MATTERS: olcSyncrepl must be applied BEFORE olcMultiProvider.
  # slapd only accepts olcMultiProvider on a database that is already a
  # "shadow" (i.e. already has at least one olcSyncrepl value); setting it
  # first fails the whole modify with:
  #   err=80 text=<olcMultiProvider> database is not a shadow
  # They are therefore two separate LDIF records rather than one modify with
  # a '-' separator, so the ordering is explicit and can't be reshuffled by
  # accident.
  peer_pos=0
  emitted_count=0
  repl_ldif="${rc_work}/syncrepl.ldif"
  {
    printf 'dn: olcDatabase={1}mdb,cn=config\n'
    printf 'changetype: modify\n'
    printf 'replace: olcSyncrepl\n'
    OLDIFS=$IFS
    IFS=','
    for peer in $LDAP_REPLICATION_PEERS; do
      peer=$(printf '%s' "$peer" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
      [ -n "$peer" ] || continue
      peer_pos=$((peer_pos + 1))
      if [ "$peer_pos" -eq "$LDAP_SERVER_ID" ]; then
        continue
      fi
      rid=$(printf '%03d' "$peer_pos")
      emitted_count=$((emitted_count + 1))
      printf 'olcSyncrepl: rid=%s provider=%s bindmethod=simple binddn="%s" credentials="%s" searchbase="%s" type=refreshAndPersist retry="%s" interval=%s\n' \
        "$rid" "$peer" "$LDAP_REPLICATION_BIND_DN" "$LDAP_REPLICATION_PASSWORD" "$LDAP_ROOT_DN" "$LDAP_REPLICATION_RETRY" "$LDAP_REPLICATION_INTERVAL"
    done
    IFS=$OLDIFS

    # A lone node (every peer filtered out as self) has no syncrepl values, so
    # it is not a shadow and olcMultiProvider would be rejected. Leaving it
    # unset is correct there: with nothing to replicate from, a plain
    # standalone database is exactly what it is.
    if [ "$emitted_count" -gt 0 ]; then
      printf '\n'
      printf 'dn: olcDatabase={1}mdb,cn=config\n'
      printf 'changetype: modify\n'
      printf 'replace: olcMultiProvider\n'
      printf 'olcMultiProvider: TRUE\n'
    fi
  } > "$repl_ldif"
  log "applying olcMultiProvider + olcSyncrepl (${emitted_count} peer(s), self excluded)"
  slapmodify -n 0 -F "$CONFIG_DIR" -l "$repl_ldif"

  rm -rf "$rc_work"
  trap - EXIT HUP INT TERM
  umask "$rc_old_umask"
  log "replication reconciliation complete"
fi

# ---------------------------------------------------------------------------
# 5. Hand off to slapd as PID 1. `-d` (any level) keeps slapd in the
#    foreground instead of daemonizing, which is what makes this exec safe.
# ---------------------------------------------------------------------------
log "starting slapd (pid 1) on: ${LISTEN_URLS}"
# #229: the container runtime exports these, so exec would hand them to slapd and
# keep them readable in /proc/1/environ for the container's lifetime. Both are
# last used above (temp seed bind, peer probe, olcSyncrepl credentials); every
# probe/healthcheck uses ldapi EXTERNAL or its own env. The *_FILE variables
# hold only a path and stay. Must run immediately before the exec.
unset LDAP_ADMIN_PASSWORD LDAP_REPLICATION_PASSWORD
exec slapd -F "$CONFIG_DIR" -h "$LISTEN_URLS" -d "$LDAP_LOG_LEVEL"
