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

if [ -n "${LDAP_ADMIN_PASSWORD_FILE:-}" ]; then
  [ -r "$LDAP_ADMIN_PASSWORD_FILE" ] || die "LDAP_ADMIN_PASSWORD_FILE is set but not readable: ${LDAP_ADMIN_PASSWORD_FILE}"
  LDAP_ADMIN_PASSWORD=$(cat "$LDAP_ADMIN_PASSWORD_FILE")
fi
: "${LDAP_ADMIN_PASSWORD:?LDAP_ADMIN_PASSWORD (or LDAP_ADMIN_PASSWORD_FILE) is required — this image ships no default admin password}"
[ -n "$LDAP_ADMIN_PASSWORD" ] || die "LDAP_ADMIN_PASSWORD is empty"

LDAP_LOG_LEVEL="${LDAP_LOG_LEVEL:-stats}"
LDAP_TLS_ENABLED="${LDAP_TLS_ENABLED:-false}"
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

# Replication (N-way multi-provider). Disabled by default — when disabled,
# nothing below this block is ever consulted, and behavior is byte-for-byte
# identical to the non-replicated image.
LDAP_REPLICATION_ENABLED="${LDAP_REPLICATION_ENABLED:-false}"
if [ "$LDAP_REPLICATION_ENABLED" = "true" ] || [ "$LDAP_REPLICATION_ENABLED" = "1" ]; then
  : "${LDAP_REPLICATION_PEERS:?LDAP_REPLICATION_ENABLED requires LDAP_REPLICATION_PEERS (comma-separated LDAP URLs, including self)}"

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
  done
  IFS=$OLDIFS
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
  slapd -F "$CONFIG_DIR" -h "$LDAPI_URL" -d "$LDAP_LOG_LEVEL" &
  TEMP_SLAPD_PID=$!

  i=0
  until ldapwhoami -x -H "$LDAPI_URL" >/dev/null 2>&1; do
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
NEEDS_BOOTSTRAP=0
if [ ! -f "$MARKER" ]; then
  NEEDS_BOOTSTRAP=1
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
    if [ -f "$MARKER" ]; then
      return 0
    fi
    log "bootstrap did not complete — discarding partial state so the next boot can retry"
    find "$CONFIG_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true
    rm -rf "$MDB_DIR"
  }
  trap 'rollback_bootstrap' EXIT

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
  ADMIN_PW_HASH=$(slappasswd -o module-path=/usr/lib/openldap -o module-load=argon2 -h "$LDAP_PASSWORD_HASH" -s "$LDAP_ADMIN_PASSWORD")

  work=$(mktemp -d)
  trap 'rm -rf "$work"; rollback_bootstrap' EXIT

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
    } > "$tls_attrs"
    sed -i "/^#__TLS_ATTRS__$/{r ${tls_attrs}
d}" "$cn_config"
  else
    sed -i '/^#__TLS_ATTRS__$/d' "$cn_config"
  fi

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
      OLDIFS=$IFS
      IFS=','
      for peer in $LDAP_REPLICATION_PEERS; do
        peer=$(printf '%s' "$peer" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
        [ -n "$peer" ] || continue
        if ldapsearch -x -H "$peer" -b "$LDAP_ROOT_DN" -s base -o nettimeout=3 -l 5 '(objectClass=*)' 1.1 >/dev/null 2>&1; then
          log "peer already has the base DIT: ${peer} — skipping local slapadd -n 1"
          LOAD_BASE_DIT=0
          break
        fi
      done
      IFS=$OLDIFS
    fi
  fi

  if [ "$LOAD_BASE_DIT" -eq 1 ]; then
    log "loading base DN + admin entry (slapadd -n 1)"
    slapadd -n 1 -F "$CONFIG_DIR" -l "$base_structure"
  fi

  rm -rf "$work"
  trap 'rollback_bootstrap' EXIT

  date -u +%FT%TZ > "$MARKER"
  trap - EXIT
  log "bootstrap complete"
else
  log "bootstrap marker present — skipping bootstrap, using existing directory"
fi

if [ "$NEEDS_BOOTSTRAP" -eq 1 ] && [ -d "$LDAP_SEED_DIR" ] && [ -n "$(ls -A "$LDAP_SEED_DIR"/*.ldif 2>/dev/null)" ]; then
  log "seeding: starting temporary slapd to apply ${LDAP_SEED_DIR}/*.ldif"
  start_temp_slapd

  for f in "$LDAP_SEED_DIR"/*.ldif; do
    [ -e "$f" ] || continue
    log "applying seed file: ${f}"
    ldapadd -x -H "$LDAPI_URL" -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" -f "$f"
  done

  log "seeding complete — stopping temporary slapd"
  stop_temp_slapd
elif [ "$NEEDS_BOOTSTRAP" -eq 1 ]; then
  log "seed dir ${LDAP_SEED_DIR} is empty or absent — nothing to seed"
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
  trap 'rm -rf "$rc_work"; stop_temp_slapd' EXIT

  # cn=admin,cn=config's password, written to a file so it never appears as
  # a `-w` command-line argument (visible to any local user via `ps`).
  admin_pw_file="${rc_work}/admin-pw"
  printf '%s' "$LDAP_ADMIN_PASSWORD" > "$admin_pw_file"

  start_temp_slapd

  server_id_ldif="${rc_work}/server-id.ldif"
  {
    printf 'dn: cn=config\n'
    printf 'changetype: modify\n'
    printf 'replace: olcServerID\n'
    printf 'olcServerID: %s\n' "$LDAP_SERVER_ID"
  } > "$server_id_ldif"
  log "applying olcServerID"
  ldapmodify -x -H "$LDAPI_URL" -D "cn=admin,cn=config" -y "$admin_pw_file" -f "$server_id_ldif"

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
  syncprov_found=$(ldapsearch -LLL -x -H "$LDAPI_URL" -D "cn=admin,cn=config" -y "$admin_pw_file" \
    -b "olcDatabase={1}mdb,cn=config" -s one -o nettimeout=3 '(objectClass=olcSyncProvConfig)' dn 2>/dev/null \
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
    ldapadd -x -H "$LDAPI_URL" -D "cn=admin,cn=config" -y "$admin_pw_file" -f "$syncprov_ldif"
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
  ldapmodify -x -H "$LDAPI_URL" -D "cn=admin,cn=config" -y "$admin_pw_file" -f "$repl_ldif"

  rm -rf "$rc_work"
  stop_temp_slapd
  trap - EXIT
  umask "$rc_old_umask"
  log "replication reconciliation complete"
fi

# ---------------------------------------------------------------------------
# 5. Hand off to slapd as PID 1. `-d` (any level) keeps slapd in the
#    foreground instead of daemonizing, which is what makes this exec safe.
# ---------------------------------------------------------------------------
log "starting slapd (pid 1) on: ${LISTEN_URLS}"
exec slapd -F "$CONFIG_DIR" -h "$LISTEN_URLS" -d "$LDAP_LOG_LEVEL"
