#!/bin/sh
# entrypoint.sh — bootstrap (first launch only) then exec slapd as PID 1.
#
# Layout (see image/README.md for the full env var contract):
#   CONFIG_DIR = /etc/openldap/slapd.d   (cn=config, dynamic config backend) — VOLUME
#   DATA_DIR   = /var/lib/openldap/data  (mdb database files)               — VOLUME
#   RUN_DIR    = /var/lib/openldap/run   (pidfile, argsfile, ldapi socket)
#   BOOTSTRAP  = /usr/local/share/openldap-suite/bootstrap (baked-in templates, read-only)
#   SEED_DIR   = $LDAP_SEED_DIR, default /opt/ldifs (operator extension point)
#
# First-launch detection: CONFIG_DIR/.bootstrapped marker file.
set -eu

CONFIG_DIR="/etc/openldap/slapd.d"
DATA_DIR="/var/lib/openldap/data"
RUN_DIR="/var/lib/openldap/run"
BOOTSTRAP_DIR="/usr/local/share/openldap-suite/bootstrap"
MARKER="${CONFIG_DIR}/.bootstrapped"

log() { printf '[entrypoint] %s\n' "$*" >&2; }
die() { printf '[entrypoint] ERROR: %s\n' "$*" >&2; exit 1; }

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

mkdir -p "$RUN_DIR"

# ---------------------------------------------------------------------------
# 2. First-launch bootstrap + seed application. TLS settings are only baked
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

  mkdir -p "$DATA_DIR"
  chmod 700 "$DATA_DIR"

  ADMIN_PW_HASH=$(slappasswd -s "$LDAP_ADMIN_PASSWORD" -h '{SSHA}')

  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT

  cn_config="${work}/01-cn-config.ldif"
  cp "${BOOTSTRAP_DIR}/01-cn-config.ldif" "$cn_config"

  if [ "$LDAP_TLS_ENABLED" = "true" ] || [ "$LDAP_TLS_ENABLED" = "1" ]; then
    tls_attrs="${work}/tls-attrs.txt"
    {
      printf 'olcTLSCertificateFile: %s\n' "$LDAP_TLS_CERT_FILE"
      printf 'olcTLSCertificateKeyFile: %s\n' "$LDAP_TLS_KEY_FILE"
      [ -n "${LDAP_TLS_CA_FILE:-}" ] && printf 'olcTLSCACertificateFile: %s\n' "$LDAP_TLS_CA_FILE"
    } > "$tls_attrs"
    sed -i "/#__TLS_ATTRS__/{r ${tls_attrs}
d}" "$cn_config"
  else
    sed -i '/#__TLS_ATTRS__/d' "$cn_config"
  fi

  sed -i \
    -e "s|__LDAP_ROOT_DN__|${LDAP_ROOT_DN}|g" \
    -e "s|__LDAP_ADMIN_DN__|${LDAP_ADMIN_DN}|g" \
    -e "s|__LDAP_ADMIN_PW_HASH__|${ADMIN_PW_HASH}|g" \
    -e "s|__LDAP_DATA_DIR__|${DATA_DIR}|g" \
    -e "s|__LDAP_RUN_DIR__|${RUN_DIR}|g" \
    "$cn_config"

  cn_config_admin="${work}/02-cn-config-admin.ldif"
  sed -e "s|__LDAP_ADMIN_PW_HASH__|${ADMIN_PW_HASH}|g" \
    "${BOOTSTRAP_DIR}/02-cn-config-admin.ldif" > "$cn_config_admin"

  base_structure="${work}/03-base-structure.ldif"
  sed \
    -e "s|__LDAP_ROOT_DN__|${LDAP_ROOT_DN}|g" \
    -e "s|__LDAP_ROOT_DC__|${LDAP_ROOT_DC}|g" \
    -e "s|__LDAP_ORG_NAME__|${LDAP_ORG_NAME}|g" \
    -e "s|__LDAP_ADMIN_DN__|${LDAP_ADMIN_DN}|g" \
    -e "s|__LDAP_ADMIN_RDN_VALUE__|${LDAP_ADMIN_RDN_VALUE}|g" \
    -e "s|__LDAP_ADMIN_PW_HASH__|${ADMIN_PW_HASH}|g" \
    "${BOOTSTRAP_DIR}/03-base-structure.ldif" > "$base_structure"

  log "loading cn=config (slapadd -n 0)"
  slapadd -n 0 -F "$CONFIG_DIR" -l "$cn_config"

  # olcDatabase={0}config,cn=config is created implicitly by slapd itself —
  # slapadd (add-only) can't touch it, so grant its dedicated admin identity
  # (cn=admin,cn=config) via an offline MODIFY instead.
  log "granting cn=config admin identity (slapmodify -n 0)"
  slapmodify -n 0 -F "$CONFIG_DIR" -l "$cn_config_admin"

  log "loading base DN + admin entry (slapadd -n 1)"
  slapadd -n 1 -F "$CONFIG_DIR" -l "$base_structure"

  rm -rf "$work"
  trap - EXIT

  date -u +%FT%TZ > "$MARKER"
  log "bootstrap complete"
else
  log "bootstrap marker present — skipping bootstrap, using existing directory"
fi

if [ "$NEEDS_BOOTSTRAP" -eq 1 ] && [ -d "$LDAP_SEED_DIR" ] && [ -n "$(ls -A "$LDAP_SEED_DIR"/*.ldif 2>/dev/null)" ]; then
  log "seeding: starting temporary slapd to apply ${LDAP_SEED_DIR}/*.ldif"
  slapd -F "$CONFIG_DIR" -h "$LDAPI_URL" -d "$LDAP_LOG_LEVEL" &
  SEED_PID=$!

  i=0
  until ldapwhoami -x -H "$LDAPI_URL" >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -ge 30 ]; then
      die "slapd did not become ready within 30s during seeding"
    fi
    kill -0 "$SEED_PID" 2>/dev/null || die "slapd exited during seed startup"
    sleep 1
  done

  for f in "$LDAP_SEED_DIR"/*.ldif; do
    [ -e "$f" ] || continue
    log "applying seed file: ${f}"
    ldapadd -x -H "$LDAPI_URL" -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" -f "$f"
  done

  log "seeding complete — stopping temporary slapd"
  kill -TERM "$SEED_PID"
  wait "$SEED_PID" 2>/dev/null || true
elif [ "$NEEDS_BOOTSTRAP" -eq 1 ]; then
  log "seed dir ${LDAP_SEED_DIR} is empty or absent — nothing to seed"
fi

# ---------------------------------------------------------------------------
# 3. Hand off to slapd as PID 1. `-d` (any level) keeps slapd in the
#    foreground instead of daemonizing, which is what makes this exec safe.
# ---------------------------------------------------------------------------
log "starting slapd (pid 1) on: ${LISTEN_URLS}"
exec slapd -F "$CONFIG_DIR" -h "$LISTEN_URLS" -d "$LDAP_LOG_LEVEL"
