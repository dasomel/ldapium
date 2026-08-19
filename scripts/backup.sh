#!/usr/bin/env bash
# Back up an ldapium directory (data tree + cn=config) over the
# network with ldapsearch — for standalone (docker run / docker compose)
# deployments that have no CronJob to do this for them.
#
# Same mechanism as charts/ldapium's Kubernetes backup CronJob, on purpose:
# ldapsearch, not slapcat. slapcat would work fine with direct container
# access (docker exec) and needs no password at all — see the note in
# --help — but using it here would mean two dump mechanisms and, sooner or
# later, two restore procedures that quietly drift apart. One mechanism
# means charts/ldapium/README.md's Restore section (slapadd, '+' 연산
# attributes 보존) applies unmodified to backups made by either this script
# or the CronJob.
#
# KEEP IN SYNC: charts/ldapium/templates/backup-cronjob.yaml implements the
# same dump/gzip/mv/prune/record sequence for Kubernetes. The logic is
# deliberately duplicated rather than shared (sharing would mean a
# ConfigMap-mounted script and more chart complexity for one script) — if
# you change the dump, the record-entry format, or the retention logic here,
# change it there too, and vice versa.
set -euo pipefail

prog=$(basename "$0")

usage() {
  cat <<EOF
Usage: $prog -b ROOT_DN [options]

Back up an OpenLDAP directory (data tree + cn=config) via ldapsearch, gzip
the result, and write timestamped files to an output directory. Optionally
record the backup's status into the directory itself (ou=operations,
same as charts/ldapium's CronJob — see charts/ldapium/README.md's
"Status recorded in the directory" section for the entry format).

Required:
  -b, --root-dn DN          Root DN, e.g. dc=example,dc=org.
                             (env: LDAP_ROOT_DN)

Connection:
  -H, --url URL              LDAP URL. Default: ldap://localhost:389
                              (env: LDAP_URL)
  -D, --admin-dn DN          Admin bind DN. Default: cn=admin,ROOT_DN
                              (env: LDAP_ADMIN_DN)
      --config-admin-dn DN   Bind DN for the cn=config dump.
                              Default: cn=admin,cn=config

Password (pick one; --password-file wins if both are set):
      --password-file FILE   Read the admin password from FILE.
      --password-env VAR     Read the admin password from environment
                              variable VAR. Default: LDAP_ADMIN_PASSWORD
                              When used, the password is written to a
                              umask-077 temp file for the lifetime of this
                              script and removed on exit — it is never
                              passed as -w, never visible via \`ps\`.

Output:
  -o, --output-dir DIR       Where backups are written. Default: ./ldap-backups
  -r, --retention-days N     Delete backup files older than N days, after a
                              successful run. Default: 7

Other:
      --no-config            Skip the cn=config dump; back up the data tree only.
      --no-record            Skip recording backup status under ou=operations.
  -h, --help                 This text.

Example:
  export LDAP_ADMIN_PASSWORD=...
  $prog -b dc=example,dc=org -o ./backups

Alternative for direct container access: if you can 'docker exec' into the
server container, 'slapcat' reads the database directly and needs no
password at all — see image/README.md's "Operational tools" section:
  docker exec ldap slapcat -F /etc/openldap/slapd.d -n 1
It is not used by this script (see the file header for why).
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
    -b|--root-dn)        root_dn="${2:?-b needs a DN}"; shift 2 ;;
    -H|--url)             ldap_url="${2:?-H needs a URL}"; shift 2 ;;
    -D|--admin-dn)        admin_dn="${2:?-D needs a DN}"; shift 2 ;;
    --config-admin-dn)    config_admin_dn="${2:?--config-admin-dn needs a DN}"; shift 2 ;;
    --password-file)      password_file="${2:?--password-file needs a path}"; shift 2 ;;
    --password-env)       password_env="${2:?--password-env needs a variable name}"; shift 2 ;;
    -o|--output-dir)      output_dir="${2:?-o needs a directory}"; shift 2 ;;
    -r|--retention-days)  retention_days="${2:?-r needs a number}"; shift 2 ;;
    --no-config)          do_config=0; shift ;;
    --no-record)          do_record=0; shift ;;
    -h|--help)             usage; exit 0 ;;
    *) printf 'unknown argument: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

log() { printf '[backup] %s\n' "$*" >&2; }

# --- validation --------------------------------------------------------
[ -n "$root_dn" ] || { echo "root DN required: -b/--root-dn, or set LDAP_ROOT_DN" >&2; usage >&2; exit 2; }
case "$root_dn" in
  dc=*) ;;
  *) echo "root DN must start with 'dc=' (got: ${root_dn})" >&2; exit 2 ;;
esac
admin_dn="${admin_dn:-cn=admin,${root_dn}}"
case "$admin_dn" in
  cn=*) ;;
  *) echo "admin DN must use 'cn=' as its RDN attribute (got: ${admin_dn})" >&2; exit 2 ;;
esac
case "$retention_days" in
  ''|*[!0-9]*) echo "--retention-days must be a non-negative integer (got: ${retention_days})" >&2; exit 2 ;;
esac

for bin in ldapsearch ldapadd ldapmodify gzip find mv grep date; do
  command -v "$bin" >/dev/null 2>&1 || { echo "required command not found on PATH: ${bin}" >&2; exit 1; }
done

# --- password resolution ------------------------------------------------
# -w is never used (visible in `ps` to any local user) — -y (a file) always
# is. --password-file is used as-is; an env-var password is written to a
# private temp file for the run and removed on exit.
cleanup_pwfile=0
if [ -n "$password_file" ]; then
  [ -r "$password_file" ] || { echo "password file not readable: ${password_file}" >&2; exit 1; }
  pwfile="$password_file"
else
  password="${!password_env:-}"
  if [ -z "$password" ]; then
    echo "no admin password available: pass --password-file, or export ${password_env} (or point --password-env at a different variable)" >&2
    exit 1
  fi
  umask 077
  pwfile=$(mktemp)
  printf '%s' "$password" > "$pwfile"
  cleanup_pwfile=1
fi

mkdir -p "$output_dir"
work_dir=$(mktemp -d)

cleanup() {
  rm -rf "$work_dir"
  [ "$cleanup_pwfile" = 1 ] && rm -f "$pwfile"
  return 0
}
trap cleanup EXIT

# --- dump ----------------------------------------------------------------
ts=$(date -u +%Y%m%dT%H%M%SZ)
dump_entry_count=0

# $1 = bind DN, $2 = search base, $3 = output basename.
# Dumped to work_dir first and gzipped to a dotfile in output_dir before the
# final mv, so a failed or partial run never leaves a corrupt/truncated
# *.ldif.gz behind under its real name (mv within the same directory is
# atomic). '*' '+' requests both user attributes and operational ones
# (entryUUID, entryCSN, creatorsName, ...) — without '+' a slapadd restore
# would mint fresh identity/CSN state for every entry instead of restoring
# it. Also sets dump_entry_count, read by the caller right after the data
# dump — '|| true' because `grep -c` exits 1 on zero matches, which set -e
# would otherwise treat as this whole assignment failing.
dump() {
  ldapsearch -x -H "$ldap_url" -D "$1" -y "$pwfile" \
    -b "$2" -o ldif-wrap=no '(objectClass=*)' '*' '+' \
    > "${work_dir}/${3}.ldif"
  dump_entry_count=$(grep -c '^dn:' "${work_dir}/${3}.ldif" || true)
  gzip -c "${work_dir}/${3}.ldif" > "${output_dir}/.tmp-${3}-${ts}.ldif.gz"
  mv "${output_dir}/.tmp-${3}-${ts}.ldif.gz" "${output_dir}/${3}-${ts}.ldif.gz"
  rm -f "${work_dir}/${3}.ldif"
  log "wrote ${3}-${ts}.ldif.gz (${dump_entry_count} entries)"
}

log "dumping data (${root_dn}) from ${ldap_url}"
dump "$admin_dn" "$root_dn" "data"
data_file="data-${ts}.ldif.gz"
data_entries="$dump_entry_count"

config_file=""
if [ "$do_config" = 1 ]; then
  log "dumping cn=config from ${ldap_url}"
  dump "$config_admin_dn" "cn=config" "config"
  config_file="config-${ts}.ldif.gz"
else
  log "skipping cn=config dump (--no-config)"
fi

log "pruning backups older than ${retention_days} day(s) in ${output_dir}"
find "$output_dir" -maxdepth 1 -name '*.ldif.gz' -mtime "+${retention_days}" -print -delete

# --- record backup status in the directory -------------------------------
# Same entry (ou=operations / cn=backup, applicationProcess, multi-valued
# `description: key=value`) that charts/ldapium's CronJob writes — see
# that chart's README for the full format/rationale, which applies here
# unchanged. Best-effort and last: it runs only after the dump(s) and prune
# above already succeeded, and a failure to record must never fail this
# script — the backup having succeeded is what matters.
#
# Existence is checked by search before deciding ldapadd-vs-ldapmodify
# (rather than trying ldapadd first and inspecting its exit code), so
# "Already exists" (68) is never hit in the first place, and re-running this
# script is always safe.
record_backup_status() {
  local d_entries="$1" d_file="$2" c_file="$3"
  local ops_dn="ou=operations,${root_dn}"
  local backup_dn="cn=backup,${ops_dn}"
  local now record_ldif
  now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  record_ldif="${work_dir}/backup-record.ldif"

  if ! ldapsearch -x -H "$ldap_url" -D "$admin_dn" -y "$pwfile" \
      -b "$ops_dn" -s base -o nettimeout=5 '(objectClass=*)' 1.1 >/dev/null 2>&1; then
    log "creating ${ops_dn}"
    printf 'dn: %s\nobjectClass: organizationalUnit\nou: operations\n' "$ops_dn" \
      | ldapadd -x -H "$ldap_url" -D "$admin_dn" -y "$pwfile" || return 1
  fi

  if ldapsearch -x -H "$ldap_url" -D "$admin_dn" -y "$pwfile" \
      -b "$backup_dn" -s base -o nettimeout=5 '(objectClass=*)' 1.1 >/dev/null 2>&1; then
    {
      printf 'dn: %s\n' "$backup_dn"
      printf 'changetype: modify\n'
      printf 'replace: description\n'
      printf 'description: lastSuccessAt=%s\n' "$now"
      printf 'description: dataEntries=%s\n' "$d_entries"
      printf 'description: dataFile=%s\n' "$d_file"
      printf 'description: configFile=%s\n' "${c_file:-none}"
    } > "$record_ldif"
    ldapmodify -x -H "$ldap_url" -D "$admin_dn" -y "$pwfile" -f "$record_ldif" || return 1
  else
    {
      printf 'dn: %s\n' "$backup_dn"
      printf 'objectClass: applicationProcess\n'
      printf 'cn: backup\n'
      printf 'description: lastSuccessAt=%s\n' "$now"
      printf 'description: dataEntries=%s\n' "$d_entries"
      printf 'description: dataFile=%s\n' "$d_file"
      printf 'description: configFile=%s\n' "${c_file:-none}"
    } > "$record_ldif"
    ldapadd -x -H "$ldap_url" -D "$admin_dn" -y "$pwfile" -f "$record_ldif" || return 1
  fi
  rm -f "$record_ldif"
}

if [ "$do_record" = 1 ]; then
  set +e
  record_backup_status "$data_entries" "$data_file" "$config_file"
  record_rc=$?
  set -e
  if [ "$record_rc" -ne 0 ]; then
    log "WARNING: could not record backup status to the directory (exit ${record_rc}) — backup itself still succeeded"
  fi
else
  log "skipping directory status record (--no-record)"
fi

log "backup complete: ${data_file}${config_file:+, ${config_file}}"
