#!/usr/bin/env bash
# scripts/migration-dryrun.sh — external LDIF schema/data validation and reconciliation report.
#
# Runs schema-only validation via slapadd in dry-run mode (slapadd -u, no database
# write kept) inside a throwaway container of the ldapium image against cn=config with the
# same schema and overlays loaded by the entrypoint. Produces a deterministic JSON
# reconciliation report analyzing objectClasses, unknown attributes, uniqueness overlay
# collisions, structural objectClass requirements, and base DN boundaries.
#
# The container is created (not `docker run`) so the input LDIF and the bootstrap
# script can be streamed in with `docker cp` instead of a bind mount: on macOS/Colima,
# bind-mounting a file for a non-root container user to read fails silently across the
# VM boundary (see AGENTS.md, "Local Docker/LDAP verification"), and bind-mounting a
# host path into the container is a broader exposure than necessary for LDIF that may
# carry sensitive attribute values. The container runs as the image's non-root `ldap`
# user (uid 999), matching production.
#
# Usage:
#   scripts/migration-dryrun.sh <external.ldif> [--base-dn DN] [--image ldapium:e2e]
#                                [--unique-attributes uid,mail] [-o report.json]
#
# Exit codes:
#   0: Clean (no schema or data findings)
#   1: Findings detected (unsupported attributes, schema violations, duplicates)
#   2: Error (invalid arguments, docker/bootstrap failure, unparseable input)
set -euo pipefail

prog="$(basename "$0")"

usage() {
  cat <<HELP_EOF
Usage: $prog <external.ldif> [--base-dn DN] [--image ldapium:e2e] [--unique-attributes LIST] [-o report.json]

Validates an external LDIF export against ldapium's OpenLDAP schema and overlays
in dry-run mode using a throwaway container (no daemon state, no DB writes kept).
The LDIF is copied into the container with 'docker cp' (never bind-mounted), and
the container runs as the non-root 'ldap' user.

Options:
  --base-dn DN              Expected directory base DN (default: dc=example,dc=org)
  --image IMAGE             Docker image to use for validation (default: ldapium:e2e)
  --unique-attributes LIST  Comma-separated attributes the unique overlay enforces
                             (default: \${LDAP_UNIQUE_ATTRIBUTES:-uid,mail}; empty
                             string disables uniqueness checking, matching
                             image/entrypoint.sh's own LDAP_UNIQUE_ATTRIBUTES contract)
  -o, --output FILE         Write JSON reconciliation report to FILE (default: stdout)
  -h, --help                Show this help message
HELP_EOF
}

ldif_file=""
base_dn="dc=example,dc=org"
image="ldapium:e2e"
output_file=""
unique_attributes="${LDAP_UNIQUE_ATTRIBUTES:-uid,mail}"

while [ $# -gt 0 ]; do
  case "$1" in
    --base-dn)
      base_dn="${2:?--base-dn requires a DN value}"
      shift 2;;
    --image)
      image="${2:?--image requires an image tag}"
      shift 2;;
    --unique-attributes)
      # ${2?...} (not :?) so an explicit empty string ("disable the overlay
      # check") is accepted rather than rejected as unset.
      unique_attributes="${2?--unique-attributes requires a value}"
      shift 2;;
    -o|--output)
      output_file="${2:?-o/--output requires a file path}"
      shift 2;;
    -h|--help)
      usage
      exit 0;;
    -*)
      echo "ERROR: unknown option: $1" >&2
      usage >&2
      exit 2;;
    *)
      if [ -z "$ldif_file" ]; then
        ldif_file="$1"
        shift
      else
        echo "ERROR: unexpected positional argument: $1" >&2
        usage >&2
        exit 2
      fi;;
  esac
done

if [ -z "$ldif_file" ]; then
  echo "ERROR: input LDIF file is required" >&2
  usage >&2
  exit 2
fi

if [ ! -f "$ldif_file" ]; then
  echo "ERROR: LDIF file not found: $ldif_file" >&2
  exit 2
fi

command -v docker >/dev/null 2>&1 || {
  echo "ERROR: docker command not found" >&2
  exit 2
}

docker info >/dev/null 2>&1 || {
  echo "ERROR: docker daemon is not running or accessible" >&2
  exit 2
}

if ! docker image inspect "$image" >/dev/null 2>&1; then
  echo "ERROR: Docker image '${image}' not found locally" >&2
  exit 2
fi

command -v python3 >/dev/null 2>&1 || {
  echo "ERROR: python3 is required for report generation" >&2
  exit 2
}

here="$(cd "$(dirname "$0")" && pwd)"
lib_dir="${here}/lib"
report_script="${lib_dir}/migration-report.py"

if [ ! -f "$report_script" ]; then
  echo "ERROR: migration report helper not found: $report_script" >&2
  exit 2
fi

abs_ldif="$(cd "$(dirname "$ldif_file")" && pwd)/$(basename "$ldif_file")"

work_dir="$(mktemp -d)"
container_id=""
# shellcheck disable=SC2317,SC2329
cleanup() {
  if [ -n "$container_id" ]; then
    docker rm -f "$container_id" >/dev/null 2>&1 || true
  fi
  rm -rf "$work_dir"
}
trap cleanup EXIT

slapadd_log="${work_dir}/slapadd.log"
schema_dump="${work_dir}/schema-dump.ldif"

# Copy the input LDIF into the work dir under our own, known-safe permissions
# rather than trusting the source file's mode (it may be tighter, e.g. 600,
# if it carries plaintext secrets) before shipping it into the container.
ldif_copy="${work_dir}/target.ldif"
cp "$abs_ldif" "$ldif_copy"
chmod 644 "$ldif_copy"

# Build the unique-overlay LDIF fragment for whichever attributes are
# configured, mirroring image/entrypoint.sh's own per-attribute olcUniqueURI
# templating exactly (one URI per attribute — each is its own uniqueness
# domain — scoped to the same (objectClass=inetOrgPerson) filter). An empty
# $unique_attributes drops the overlay entirely, just as entrypoint.sh does
# when LDAP_UNIQUE_ATTRIBUTES is empty.
unique_ldif="${work_dir}/unique-overlay.ldif"
: > "$unique_ldif"
uri_count=0
IFS=',' read -ra _uniq_attrs <<< "${unique_attributes}"
for _ua in "${_uniq_attrs[@]}"; do
  _ua="$(printf '%s' "$_ua" | tr -d '[:space:]')"
  [ -z "$_ua" ] && continue
  if [ "$uri_count" -eq 0 ]; then
    {
      printf 'dn: olcOverlay=unique,olcDatabase={1}mdb,cn=config\n'
      printf 'objectClass: olcOverlayConfig\n'
      printf 'objectClass: olcUniqueConfig\n'
      printf 'olcOverlay: unique\n'
    } >> "$unique_ldif"
  fi
  printf 'olcUniqueURI: ldap:///?%s?sub?(objectClass=inetOrgPerson)\n' "$_ua" >> "$unique_ldif"
  uri_count=$((uri_count + 1))
done

# Bootstrap script executed inside the container. BASE_DN is passed as argv,
# never interpolated into the script text, so it can't reinterpret shell
# metacharacters. `set -eu` up front means any failure through the schema
# bootstrap (slapadd -n 0) aborts the script with a non-zero exit and its
# stderr captured to /tmp/bootstrap.err; the final `set +e` deliberately
# stops that guarantee at the point where the *data* dry-run (slapadd -u -c,
# continue-on-error) runs, because that command's exit status reflects
# findings in the target LDIF, not bootstrap health, and must never be
# conflated with "the dry-run could not execute."
bootstrap_script="${work_dir}/bootstrap.sh"
cat > "$bootstrap_script" <<'BOOTSTRAP_EOF'
#!/bin/sh
set -eu
BASE_DN="$1"
CONFIG_DIR="/tmp/slapd.d"
MDB_DIR="/tmp/mdb"
work="/tmp/bootstrap"
mkdir -p "$CONFIG_DIR" "$MDB_DIR" "$work"

cn_config="${work}/01-cn-config.ldif"
cp /usr/local/share/ldapium/bootstrap/01-cn-config.ldif "$cn_config"

if [ -s /tmp/unique-overlay.ldif ]; then
  sed -i "/^#__UNIQUE_OVERLAY__\$/{r /tmp/unique-overlay.ldif
d}" "$cn_config"
else
  sed -i '/^#__UNIQUE_OVERLAY__$/d' "$cn_config"
fi
sed -i '/^#__TLS_ATTRS__$/d' "$cn_config"
sed -i '/^#__ANON_READ_ACCESS__$/d' "$cn_config"
sed -i '/^#__AUDITLOG_OVERLAY__$/d' "$cn_config"
sed -i '/^#__ACCESSLOG_DB__$/d' "$cn_config"
sed -i '/^#__ACCESSLOG_OVERLAY__$/d' "$cn_config"
sed -i '/^#__PPOLICY_DEFAULT__$/d' "$cn_config"

ADMIN_PW_HASH='{ARGON2}dummy'
sed -i \
  -e "s|__LDAP_ROOT_DN__|${BASE_DN}|g" \
  -e "s|__LDAP_ADMIN_DN__|cn=admin,${BASE_DN}|g" \
  -e "s|__LDAP_ADMIN_PW_HASH__|${ADMIN_PW_HASH}|g" \
  -e "s|__LDAP_DATA_DIR__|${MDB_DIR}|g" \
  -e "s|__LDAP_DB_MAX_SIZE__|1073741824|g" \
  -e "s|__LDAP_RUN_DIR__|${work}|g" \
  -e "s|__LDAP_PASSWORD_HASH__|{ARGON2}|g" \
  -e "s|__LDAP_SIZE_LIMIT__|10000|g" \
  -e "s|__LDAP_TIME_LIMIT__|3600|g" \
  "$cn_config"

if ! slapadd -n 0 -F "$CONFIG_DIR" -l "$cn_config" >/tmp/bootstrap.err 2>&1; then
  echo "FATAL: schema bootstrap (slapadd -n 0) failed:" >&2
  cat /tmp/bootstrap.err >&2
  exit 90
fi

# Dump the schema actually loaded, for the report's unknown-class/attribute
# checks to run against the real image schema. Best-effort: if this fails,
# migration-report.py falls back to its static schema list.
slapcat -n 0 -F "$CONFIG_DIR" -b cn=schema,cn=config -l /tmp/schema-dump.ldif >/tmp/schema-dump.err 2>&1 || true

set +e
slapadd -u -c -F "$CONFIG_DIR" -b "$BASE_DN" -l /tmp/target.ldif
exit 0
BOOTSTRAP_EOF
chmod 644 "$bootstrap_script"

set +e
container_id="$(docker create --user 999:999 "$image" /bin/sh /tmp/bootstrap.sh "$base_dn" 2>"${work_dir}/create.err")"
create_exit=$?
set -e
if [ "$create_exit" -ne 0 ] || [ -z "$container_id" ]; then
  echo "ERROR: docker create failed (exit ${create_exit}) for image '${image}':" >&2
  cat "${work_dir}/create.err" >&2
  exit 2
fi

copy_into() {
  # $1 = host path, $2 = destination path inside the container.
  if ! docker cp "$1" "${container_id}:$2" >/dev/null 2>"${work_dir}/cp.err"; then
    echo "ERROR: docker cp failed copying $1 into the container:" >&2
    cat "${work_dir}/cp.err" >&2
    exit 2
  fi
}

copy_into "$bootstrap_script" /tmp/bootstrap.sh
copy_into "$ldif_copy" /tmp/target.ldif
if [ -s "$unique_ldif" ]; then
  copy_into "$unique_ldif" /tmp/unique-overlay.ldif
fi

set +e
docker start -a "$container_id" > "$slapadd_log" 2>&1
docker_exit=$?
set -e

if [ "$docker_exit" -ne 0 ]; then
  echo "ERROR: schema bootstrap / container execution failed (exit ${docker_exit}):" >&2
  cat "$slapadd_log" >&2
  exit 2
fi

docker cp "${container_id}:/tmp/schema-dump.ldif" "$schema_dump" >/dev/null 2>&1 || true

report_cmd=(python3 "$report_script" "$abs_ldif" --base-dn "$base_dn" --slapadd-log "$slapadd_log")
report_cmd+=(--unique-attributes "$unique_attributes" --unique-filter "objectClass=inetOrgPerson")
if [ -s "$schema_dump" ]; then
  report_cmd+=(--schema-ldif "$schema_dump")
fi
if [ -n "$output_file" ]; then
  report_cmd+=(-o "$output_file")
fi

set +e
"${report_cmd[@]}"
report_exit=$?
set -e

exit "$report_exit"
