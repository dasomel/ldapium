#!/usr/bin/env bash
# Restore an ldapium backup into an OFFLINE, empty data/config directory.
# The caller must stop slapd and explicitly acknowledge that the target is
# offline. Existing target contents are rejected unless --force-empty is used.
set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 --backup-dir DIR [--manifest FILE] --target-config DIR --target-data DIR --confirm-offline [--force-empty]

Restores data + cn=config from a verified ldapium backup. This script never
contacts LDAP and never starts slapd. The target must be offline.
EOF
}

backup_dir=""
manifest=""
target_config=""
target_data=""
confirm_offline=0
force_empty=0

while [ $# -gt 0 ]; do
  case "$1" in
    --backup-dir) backup_dir="${2:?--backup-dir needs a directory}"; shift 2;;
    --manifest) manifest="${2:?--manifest needs a file}"; shift 2;;
    --target-config) target_config="${2:?--target-config needs a directory}"; shift 2;;
    --target-data) target_data="${2:?--target-data needs a directory}"; shift 2;;
    --confirm-offline) confirm_offline=1; shift;;
    --force-empty) force_empty=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2;;
  esac
done

[ "$confirm_offline" = 1 ] || { echo "refusing restore: --confirm-offline is required" >&2; exit 2; }
if [ -z "$backup_dir" ] || [ ! -d "$backup_dir" ]; then
  echo "backup directory is required" >&2
  exit 2
fi
if [ -z "$target_config" ] || [ -z "$target_data" ]; then
  echo "target config/data directories are required" >&2
  exit 2
fi
command -v slapadd >/dev/null 2>&1 || { echo "slapadd is required" >&2; exit 1; }
command -v gzip >/dev/null 2>&1 || { echo "gzip is required" >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required" >&2; exit 1; }

if [ -z "$manifest" ]; then
  manifest=$(find "$backup_dir" -maxdepth 1 -type f -name 'manifest-*.sha256' -printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2- || true)
fi
if [ -z "$manifest" ] || [ ! -f "$manifest" ]; then
  echo "backup manifest not found" >&2
  exit 1
fi

"$(dirname "$0")/verify-backup.sh" "$manifest"

mapfile -t files < <(awk '{print $2}' "$manifest")
data_file=""
config_file=""
for f in "${files[@]}"; do
  case "$(basename "$f")" in
    data-*.ldif.gz) data_file="$backup_dir/$(basename "$f")";;
    config-*.ldif.gz) config_file="$backup_dir/$(basename "$f")";;
  esac
done
[ -f "$data_file" ] || { echo "data backup missing from manifest: $data_file" >&2; exit 1; }
[ -f "$config_file" ] || { echo "config backup missing from manifest: $config_file" >&2; exit 1; }

mkdir -p "$target_config" "$target_data"
if [ "$force_empty" != 1 ]; then
  if [ -n "$(find "$target_config" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ] || [ -n "$(find "$target_data" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
    echo "refusing restore: target config/data is not empty (use --force-empty only after confirming offline state)" >&2
    exit 1
  fi
fi

work_dir=$(mktemp -d)
cleanup() { rm -rf "$work_dir"; }
trap cleanup EXIT

# backup.sh dumps with `ldapsearch ... '*' '+'`, which returns operational
# attributes slapd generates rather than stores. slapadd takes them at face value
# and aborts on the inconsistency that follows:
#   slapadd: attr.c:243: attr_dup2: Assertion `j == i' failed.
# Reproduced on the very first entry, cn=config, with entryDN and
# subschemaSubentry — both have to go, removing either alone still aborts. The
# rest of the operational set (entryUUID, entryCSN, the creator and modifier
# stamps) is genuinely stored state and is kept, so a restored directory keeps
# its original timestamps and replication CSNs.
#
# On cn=schema,cn=config the built-in schema definitions go too: slapd assembles
# that entry from its compiled-in schema before it reads a line of the dump, so
# reloading the dumped copy adds a second set of the same definitions. User
# schema lives in the cn={N}name,cn=schema,cn=config children and is untouched.
sanitize_dump() {
  awk '
    {
      line = $0
      if (line == "") { dn = ""; drop = 0; print; next }
      if (substr(line, 1, 1) == " ") { if (!drop) print; next }
      drop = 0
      if (substr(line, 1, 1) == "#") { drop = 1; next }
      if (substr(line, 1, 4) == "dn: ") { dn = tolower(substr(line, 5)); print; next }
      # ldapsearch closes with `search:`/`result:` lines that belong to no entry;
      # slapadd reads them as an entry and stops on "entry -1 has no dn".
      if (dn == "") { drop = 1; next }
      low = tolower(line)
      if (low ~ /^(entrydn|subschemasubentry|hassubordinates|numsubordinates)[;:]/) {
        drop = 1
      } else if (dn == "cn=schema,cn=config" && low ~ /^(olcattributetypes|olcobjectclasses|olcldapsyntaxes|olcobjectidentifier|olcmatchingrules|olcmatchingruleuse|olcditcontentrules)[;:]/) {
        drop = 1
      }
      if (!drop) print
    }
  '
}

gzip -dc "$config_file" | sanitize_dump > "$work_dir/config.ldif"
gzip -dc "$data_file" | sanitize_dump > "$work_dir/data.ldif"

rm -rf "${target_config:?}"/* "${target_config:?}"/.[!.]* "${target_config:?}"/..?* 2>/dev/null || true
rm -rf "${target_data:?}"/* "${target_data:?}"/.[!.]* "${target_data:?}"/..?* 2>/dev/null || true

# slapadd writes the database wherever the restored cn=config says, not where
# --target-data points, and it refuses to start if that path does not exist.
# Create it, and refuse the restore outright if it falls outside the target
# rather than quietly scattering the mdb files somewhere the caller never named.
db_dir=$(awk '$1 == "olcDbDirectory:" { print $2; exit }' "$work_dir/config.ldif")
if [ -z "$db_dir" ]; then
  echo "config dump has no olcDbDirectory" >&2
  exit 1
fi
case "$db_dir" in
  "$target_data"/*) ;;
  *)
    echo "refusing restore: the backup's database directory is ${db_dir}, which is not under --target-data ${target_data}" >&2
    echo "mount the restore volume at ${db_dir%/*} and pass that as --target-data" >&2
    exit 1
    ;;
esac
mkdir -p "$db_dir"

slapadd -n 0 -F "$target_config" -l "$work_dir/config.ldif"
slapadd -n 1 -F "$target_config" -l "$work_dir/data.ldif"

# A restored cn=config is authoritative and the ldapium entrypoint must not
# attempt a fresh bootstrap over it. The marker is local operational metadata,
# not directory state, so it is safe to recreate after both slapadd operations.
printf '%s\n' "$(date -u +%FT%TZ)" > "$target_config/.bootstrapped"

# The runtime image uses uid/gid 999; restore tooling may run as root solely to
# repair ownership after slapadd created files as the current user.
if [ "$(id -u)" = 0 ]; then
  chown -R 999:999 "$target_config" "$target_data"
fi

printf 'restore completed successfully: data=%s config=%s\n' "$data_file" "$config_file"
