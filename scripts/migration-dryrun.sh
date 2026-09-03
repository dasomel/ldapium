#!/usr/bin/env bash
# scripts/migration-dryrun.sh — external LDIF schema/data validation and reconciliation report.
#
# Runs schema-only validation via slapadd in dry-run mode (slapadd -u, no database
# write) inside a throwaway container of the ldapium image against cn=config with the
# same schema and overlays loaded by the entrypoint. Produces a deterministic JSON
# reconciliation report analyzing objectClasses, unknown attributes, uniqueness overlay
# collisions (uid, mail), structural objectClass requirements, and base DN boundaries.
#
# Usage:
#   scripts/migration-dryrun.sh <external.ldif> [--base-dn DN] [--image ldapium:e2e] [-o report.json]
#
# Exit codes:
#   0: Clean (no schema or data findings)
#   1: Findings detected (unsupported attributes, schema violations, duplicates)
#   2: Error (invalid arguments, docker failure, unparseable input)
set -euo pipefail

prog="$(basename "$0")"

usage() {
  cat <<HELP_EOF
Usage: $prog <external.ldif> [--base-dn DN] [--image ldapium:e2e] [-o report.json]

Validates an external LDIF export against ldapium's OpenLDAP schema and overlays
in dry-run mode using a throwaway container (no daemon state, no DB writes).

Options:
  --base-dn DN        Expected directory base DN (default: dc=example,dc=org)
  --image IMAGE       Docker image to use for validation (default: ldapium:e2e)
  -o, --output FILE   Write JSON reconciliation report to FILE (default: stdout)
  -h, --help          Show this help message
HELP_EOF
}

ldif_file=""
base_dn="dc=example,dc=org"
image="ldapium:e2e"
output_file=""

while [ $# -gt 0 ]; do
  case "$1" in
    --base-dn)
      base_dn="${2:?--base-dn requires a DN value}"
      shift 2;;
    --image)
      image="${2:?--image requires an image tag}"
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
# shellcheck disable=SC2317,SC2329
cleanup() { rm -rf "$work_dir"; }
trap cleanup EXIT

slapadd_log="${work_dir}/slapadd.log"

set +e
docker run --rm -i --user 0:0 \
  -v "${abs_ldif}:/tmp/target.ldif:ro" \
  "$image" /bin/sh -s "$base_dn" <<'CONTAINER_EOF' > "$slapadd_log" 2>&1
set -eu
BASE_DN="$1"
CONFIG_DIR="/tmp/slapd.d"
MDB_DIR="/tmp/mdb"
work="/tmp/bootstrap"
mkdir -p "$CONFIG_DIR" "$MDB_DIR" "$work"

cn_config="${work}/01-cn-config.ldif"
cp /usr/local/share/ldapium/bootstrap/01-cn-config.ldif "$cn_config"

cat <<EOF > "${work}/unique.ldif"
dn: olcOverlay=unique,olcDatabase={1}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcUniqueConfig
olcOverlay: unique
olcUniqueURI: ldap:///?uid?sub?(objectClass=inetOrgPerson)
olcUniqueURI: ldap:///?mail?sub?(objectClass=inetOrgPerson)
EOF

sed -i "/^#__UNIQUE_OVERLAY__$/{r ${work}/unique.ldif
d}" "$cn_config"
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

slapadd -n 0 -F "$CONFIG_DIR" -l "$cn_config" >/dev/null 2>&1

slapadd -u -c -F "$CONFIG_DIR" -b "$BASE_DN" -l /tmp/target.ldif
CONTAINER_EOF
set -e

report_cmd=(python3 "$report_script" "$abs_ldif" --base-dn "$base_dn" --slapadd-log "$slapadd_log")
if [ -n "$output_file" ]; then
  report_cmd+=(-o "$output_file")
fi

set +e
"${report_cmd[@]}"
report_exit=$?
set -e

exit "$report_exit"
