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

command -v realpath >/dev/null 2>&1 || { echo "GNU realpath is required" >&2; exit 1; }
backup_dir=$(realpath -- "$backup_dir")
manifest=$(realpath -- "$manifest")
[ "$(dirname "$manifest")" = "$backup_dir" ] || { echo "refusing restore: manifest must belong to backup-dir" >&2; exit 1; }
while read -r _ filename; do
  case "$filename" in ''|*[!a-zA-Z0-9._-]*) echo "refusing restore: manifest must name direct files only" >&2; exit 1;; esac
  [ -f "$backup_dir/$filename" ] && [ ! -L "$backup_dir/$filename" ] || { echo "refusing restore: manifest source must be a regular non-symlink file" >&2; exit 1; }
done < "$manifest"
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

command -v realpath >/dev/null 2>&1 || { echo "GNU realpath is required" >&2; exit 1; }
target_config="${target_config%/}"
target_data="${target_data%/}"
for target in "$target_config" "$target_data"; do
  [ -n "$target" ] && [ "$target" != "/" ] && [ "$target" = "$(realpath -m -- "$target")" ] || {
    echo "refusing restore: targets must be canonical absolute non-root paths without symlink parents" >&2; exit 1;
  }
done
case "$target_config/" in "$target_data/"*) echo "refusing nested restore targets" >&2; exit 1;; esac
case "$target_data/" in "$target_config/"*) echo "refusing nested restore targets" >&2; exit 1;; esac
mkdir -p "$target_config" "$target_data"
if [ "$force_empty" != 1 ]; then
  if [ -n "$(find "$target_config" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ] || [ -n "$(find "$target_data" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
    echo "refusing restore: target config/data is not empty (use --force-empty only after confirming offline state)" >&2
    exit 1
  fi
fi

work_dir=$(mktemp -d)
# D44 follow-up: the generated-credentials stash below lives in $work_dir, so
# the trap must put it back before deleting the workdir. Otherwise a failure or
# SIGINT/SIGTERM between "stash" and "put back" would destroy the only copy.
# Declared early so the trap is valid for the whole script; the real values are
# set where the stash is made.
preserved_dir="$work_dir/preserved"
preserved_paths=()
wiped=0
restore_preserved() {
  local d origin dest base k
  [ -d "$preserved_dir" ] || return 0
  for d in "$preserved_dir"/*/; do
    [ -e "${d}credentials" ] || continue
    origin=$(cat "${d}origin")
    case "$(basename "$origin")" in
      # Earlier asides keep their name; so does anything restored before the
      # target was wiped (its config is still the one that password belongs to).
      .credentials.pre-restore.*) dest="$origin";;
      *) if [ "$wiped" = 0 ]; then dest="$origin"; else dest="$(dirname "$origin")/.credentials.pre-restore.${stamp}"; fi;;
    esac
    base="$dest"; k=1
    while [ -e "$dest" ] || [ -L "$dest" ]; do k=$((k + 1)); dest="${base}.${k}"; done
    mkdir -p "$(dirname "$dest")"
    if (umask 077; mv -- "${d}credentials" "$dest"); then
      chmod -R go-rwx "$dest"
      preserved_paths+=("$dest")
    else
      echo "WARNING: could not put generated credentials back; they remain in ${d}credentials" >&2
    fi
  done
}
cleanup() {
  restore_preserved || true
  # Keep the workdir (0700) if a stash could not be restored rather than delete the only copy.
  if compgen -G "$preserved_dir/*/credentials" >/dev/null; then
    echo "WARNING: generated credentials preserved under $preserved_dir" >&2
  else
    rm -rf "$work_dir"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# D34: copy every listed compressed file into a private workspace, then verify
# that exact snapshot. Concurrent changes cannot substitute a different LDIF
# between verification and decompression/destructive target preparation.
for f in "${files[@]}"; do cp -- "$backup_dir/$f" "$work_dir/$f"; done
cp -- "$manifest" "$work_dir/$(basename "$manifest")"
"$(dirname "$0")/verify-backup.sh" "$work_dir/$(basename "$manifest")"
data_file="$work_dir/$(basename "$data_file")"
config_file="$work_dir/$(basename "$config_file")"

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
      # D35: non-ASCII DNs are base64 LDIF values. Preserve the record; built-in
      # schema DNs are ASCII, so encoded DNs need no schema-specific stripping.
      if (substr(line, 1, 5) == "dn:: ") { dn = "encoded-dn"; print; next }
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

# Validate every MDB directory before modifying either offline target. Auxiliary
# accesslog databases also need their directories before cn=config is loaded.
# Generated ldapium exports use single-line absolute paths. Fail closed for
# encoded/folded/option-bearing path values instead of silently skipping them.
awk '
  {
    if (directory && substr($0,1,1)==" ") exit 1
    directory=0
    if (tolower($0) ~ /^olcdbdirectory/) {
      if (tolower($1)!="olcdbdirectory:" || NF!=2 || $2 !~ /^\/[A-Za-z0-9_./-]+$/) exit 1
      directory=1
    }
  }
' "$work_dir/config.ldif" || { echo "refusing restore: unsupported database path encoding/format" >&2; exit 1; }
mapfile -t db_dirs < <(awk 'tolower($1) == "olcdbdirectory:" { print $2 }' "$work_dir/config.ldif")
[ "${#db_dirs[@]}" -gt 0 ] || { echo "config has no database directory" >&2; exit 1; }
for db_dir in "${db_dirs[@]}"; do
  case "$db_dir" in
    "$target_data"/*) ;;
    *) echo "refusing restore: database directory outside target-data" >&2; exit 1;;
  esac
  case "/${db_dir}/" in */../*|*/./*) echo "refusing restore: non-canonical database directory" >&2; exit 1;; esac
  if [ -L "$db_dir" ]; then echo "refusing restore: symlink database directory" >&2; exit 1; fi
  # Existing parent symlinks could redirect slapadd outside the named target.
  parent="$db_dir"
  while [ "$parent" != "$target_data" ] && [ "$parent" != "/" ]; do
    [ ! -L "$parent" ] || { echo "refusing restore: symlink database parent" >&2; exit 1; }
    parent=$(dirname "$parent")
  done
 done
mapfile -t data_suffixes < <(awk 'tolower($1) == "olcsuffix:" && tolower($2) ~ /^dc=/ { print substr($0, index($0, $2)) }' "$work_dir/config.ldif")
[ "${#data_suffixes[@]}" = 1 ] || { echo "restore requires exactly one ldapium dc= data suffix" >&2; exit 1; }

# D3: a generated admin password (DATA_DIR/.credentials) belongs to the TARGET's
# old cn=config, which is about to be replaced by the SOURCE's (rootpw hash
# included). Deleting it silently leaves the operator with no trace of the old
# password; keeping it in place would not help either (it no longer matches).
# So stash it through the wipe and put it back under a clearly named, private
# path. Backups deliberately exclude .credentials and still do.
mkdir "$preserved_dir"; chmod 700 "$preserved_dir"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
n=0
# Every .credentials* entry: the live one and any earlier .credentials.pre-restore.<ts>
# aside, so a second restore cannot delete the first one's aside. -prune keeps
# find out of a matched directory.
mapfile -t cred_paths < <(find "$target_data" -maxdepth 2 \( -name .credentials -o -name '.credentials.pre-restore.*' \) -not -type l \( -type d -o -type f \) -prune -print 2>/dev/null || true)
for cred in "${cred_paths[@]}"; do
  [ -n "$cred" ] || continue
  n=$((n + 1))
  mkdir -m 700 "$preserved_dir/$n"
  printf '%s\n' "$cred" > "$preserved_dir/$n/origin"
  mv -- "$cred" "$preserved_dir/$n/credentials"
done

rm -rf "${target_config:?}"/* "${target_config:?}"/.[!.]* "${target_config:?}"/..?* 2>/dev/null || true
rm -rf "${target_data:?}"/* "${target_data:?}"/.[!.]* "${target_data:?}"/..?* 2>/dev/null || true
wiped=1
for db_dir in "${db_dirs[@]}"; do mkdir -p "$db_dir"; done

restore_preserved

slapadd -n 0 -F "$target_config" -l "$work_dir/config.ldif"
# D33: monitor/accesslog changes numeric database order. Select the actual data
# suffix so enabling monitoring cannot redirect a restore into the wrong DB.
slapadd -b "${data_suffixes[0]}" -F "$target_config" -l "$work_dir/data.ldif"

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

# Goes to stderr; never prints any secret value.
{
  echo
  echo "WARNING: the restored directory uses the SOURCE directory's admin password,"
  echo "not this target's. Supply it when starting the container, via"
  echo "LDAP_ADMIN_PASSWORD_FILE (or LDAP_ADMIN_PASSWORD), or place the source's"
  echo ".credentials/ldap-admin-password under DATA_DIR/.credentials (dir 0700, file"
  echo "0600, owned by the LDAP user). Without it the entrypoint refuses to start."
  for kept in "${preserved_paths[@]}"; do
    echo "The target's previous generated credentials were kept (0700) at: $kept"
    echo "They do NOT match the restored directory; delete them once no longer needed."
  done
} >&2
