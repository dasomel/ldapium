#!/usr/bin/env bash
# Back up an ldapium directory (data tree + cn=config) over the network.
set -euo pipefail
prog=$(basename "$0")
usage() { cat <<EOF
Usage: $prog -b ROOT_DN [options]

Back up an OpenLDAP directory (data tree + cn=config) via ldapsearch, gzip the
result, create a SHA-256 manifest, and write timestamped files to an output
 directory.
EOF
}
root_dn="${LDAP_ROOT_DN:-}"
ldap_url="${LDAP_URL:-ldap://localhost:389}"
admin_dn="${LDAP_ADMIN_DN:-}"
config_admin_dn="cn=admin,cn=config"
password_file=""
password_env="LDAP_ADMIN_PASSWORD"
output_dir="./ldap-backups"
retention_days=7
do_config=1
do_record=1
while [ $# -gt 0 ]; do
  case "$1" in
    -b|--root-dn) root_dn="${2:?-b needs a DN}"; shift 2;;
    -H|--url) ldap_url="${2:?-H needs a URL}"; shift 2;;
    -D|--admin-dn) admin_dn="${2:?-D needs a DN}"; shift 2;;
    --config-admin-dn) config_admin_dn="${2:?--config-admin-dn needs a DN}"; shift 2;;
    --password-file) password_file="${2:?--password-file needs a path}"; shift 2;;
    --password-env) password_env="${2:?--password-env needs a variable name}"; shift 2;;
    -o|--output-dir) output_dir="${2:?-o needs a directory}"; shift 2;;
    -r|--retention-days) retention_days="${2:?-r needs a number}"; shift 2;;
    --no-config) do_config=0; shift;;
    --no-record) do_record=0; shift;;
    -h|--help) usage; exit 0;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2;;
  esac
done
log() { printf '[backup] %s\n' "$*" >&2; }
[ -n "$root_dn" ] || { echo "root DN required" >&2; exit 2; }
case "$root_dn" in dc=*) ;; *) echo "root DN must start with dc=" >&2; exit 2;; esac
admin_dn="${admin_dn:-cn=admin,${root_dn}}"
case "$retention_days" in ''|*[!0-9]*) echo "retention-days must be numeric" >&2; exit 2;; esac
for bin in ldapsearch ldapadd ldapmodify gzip find mv grep date sha256sum mktemp; do
  command -v "$bin" >/dev/null 2>&1 || { echo "required command not found: $bin" >&2; exit 1; }
done
cleanup_pwfile=0
if [ -n "$password_file" ]; then
  [ -r "$password_file" ] || { echo "password file not readable: $password_file" >&2; exit 1; }
  pwfile="$password_file"
else
  password="${!password_env:-}"
  [ -n "$password" ] || { echo "no admin password available" >&2; exit 1; }
  umask 077
  pwfile=$(mktemp)
  printf '%s' "$password" > "$pwfile"
  cleanup_pwfile=1
fi
mkdir -p "$output_dir"
work_dir=$(mktemp -d)
cleanup() { rm -rf "$work_dir"; [ "$cleanup_pwfile" = 1 ] && rm -f "$pwfile"; }
trap cleanup EXIT
ts=$(date -u +%Y%m%dT%H%M%SZ)
dump_entry_count=0
dump() {
  ldapsearch -x -H "$ldap_url" -D "$1" -y "$pwfile" -b "$2" -o ldif-wrap=no '(objectClass=*)' '*' '+' > "${work_dir}/${3}.ldif"
  dump_entry_count=$(grep -c '^dn:' "${work_dir}/${3}.ldif" || true)
  gzip -c "${work_dir}/${3}.ldif" > "${output_dir}/.tmp-${3}-${ts}.ldif.gz"
  mv "${output_dir}/.tmp-${3}-${ts}.ldif.gz" "${output_dir}/${3}-${ts}.ldif.gz"
  rm -f "${work_dir}/${3}.ldif"
  log "wrote ${3}-${ts}.ldif.gz (${dump_entry_count} entries)"
}
log "dumping data (${root_dn}) from ${ldap_url}"
dump "$admin_dn" "$root_dn" data
data_file="data-${ts}.ldif.gz"
data_entries="$dump_entry_count"
config_file=""
if [ "$do_config" = 1 ]; then
  log "dumping cn=config from ${ldap_url}"
  dump "$config_admin_dn" cn=config config
  config_file="config-${ts}.ldif.gz"
fi
manifest_file="manifest-${ts}.sha256"
manifest_tmp="${output_dir}/.tmp-${manifest_file}"
(
  cd "$output_dir"
  sha256sum "$data_file"
  [ -z "$config_file" ] || sha256sum "$config_file"
) > "$manifest_tmp"
mv "$manifest_tmp" "${output_dir}/${manifest_file}"
log "wrote ${manifest_file}"
(
  cd "$output_dir"
  sha256sum -c "$manifest_file"
)
log "backup integrity verified"
find "$output_dir" -maxdepth 1 -name '*.ldif.gz' -mtime "+${retention_days}" -print -delete
find "$output_dir" -maxdepth 1 -name 'manifest-*.sha256' -mtime "+${retention_days}" -print -delete
record_backup_status() {
  local d_entries="$1" d_file="$2" c_file="$3"; local ops_dn="ou=operations,${root_dn}"; local backup_dn="cn=backup,${ops_dn}"; local now record_ldif
  now=$(date -u +%Y-%m-%dT%H:%M:%SZ); record_ldif="${work_dir}/backup-record.ldif"
  if ! ldapsearch -x -H "$ldap_url" -D "$admin_dn" -y "$pwfile" -b "$ops_dn" -s base -o nettimeout=5 '(objectClass=*)' 1.1 >/dev/null 2>&1; then
    printf 'dn: %s\nobjectClass: organizationalUnit\nou: operations\n' "$ops_dn" | ldapadd -x -H "$ldap_url" -D "$admin_dn" -y "$pwfile" || return 1
  fi
  if ldapsearch -x -H "$ldap_url" -D "$admin_dn" -y "$pwfile" -b "$backup_dn" -s base -o nettimeout=5 '(objectClass=*)' 1.1 >/dev/null 2>&1; then
    { printf 'dn: %s\nchangetype: modify\nreplace: description\n' "$backup_dn"; printf 'description: lastSuccessAt=%s\n' "$now"; printf 'description: dataEntries=%s\n' "$d_entries"; printf 'description: dataFile=%s\n' "$d_file"; printf 'description: configFile=%s\n' "${c_file:-none}"; printf 'description: manifestFile=%s\n' "$manifest_file"; } > "$record_ldif"
    ldapmodify -x -H "$ldap_url" -D "$admin_dn" -y "$pwfile" -f "$record_ldif" || return 1
  else
    { printf 'dn: %s\nobjectClass: applicationProcess\ncn: backup\n' "$backup_dn"; printf 'description: lastSuccessAt=%s\n' "$now"; printf 'description: dataEntries=%s\n' "$d_entries"; printf 'description: dataFile=%s\n' "$d_file"; printf 'description: configFile=%s\n' "${c_file:-none}"; printf 'description: manifestFile=%s\n' "$manifest_file"; } > "$record_ldif"
    ldapadd -x -H "$ldap_url" -D "$admin_dn" -y "$pwfile" -f "$record_ldif" || return 1
  fi
  rm -f "$record_ldif"
}
if [ "$do_record" = 1 ]; then
  set +e; record_backup_status "$data_entries" "$data_file" "$config_file"; record_rc=$?; set -e
  [ "$record_rc" -eq 0 ] || log "WARNING: could not record backup status (exit $record_rc) — backup itself succeeded"
fi
log "backup complete: ${data_file}${config_file:+, ${config_file}}, ${manifest_file}"
