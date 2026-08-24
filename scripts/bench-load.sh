#!/usr/bin/env bash
# Time an OFFLINE slapadd load of a synthetic LDIF against a real,
# product-bootstrapped cn=config — not a hand-rolled test config, so the
# numbers this produces describe the actual product rather than a stand-in
# for it.
#
# Why offline slapadd rather than the seed mechanism (LDAP_SEED_DIR): that
# path applies LDIFs one at a time over the wire via ldapadd, after slapd is
# already serving — the right tool for a handful of bootstrap entries, and
# dramatically slower than offline slapadd for bulk data. This measures the
# thing #41 actually asked about.
#
# Sequencing, all against the same two named Docker volumes so every phase
# sees the real cn=config the product itself produced:
#   1. bootstrap  — a normal container run, LDAP_DB_MAX_SIZE sized for the
#                    target scale, stopped once ready (data/config persist
#                    on the named volumes)
#   2. load       — a throwaway container running `slapadd -n 1` directly,
#                    no slapd holding the database — timed
#   3. verify     — a second throwaway container counting what actually
#                    landed
#
#   ./scripts/bench-load.sh --image ldapium:bench --count 100000
#   ./scripts/bench-load.sh --image ldapium:bench --count 10000000 --db-max-size-gb 8
set -euo pipefail

image=""
count=0
base="dc=example,dc=org"
db_max_size_gb=1
out_json=""

usage() {
  cat <<'EOF'
Usage: bench-load.sh --image IMAGE --count N [--base DN] [--db-max-size-gb N] [--json FILE]

  --image             ldapium image to benchmark (build it first — this
                       script does not build one)
  --count             number of synthetic entries to generate and load
  --base              base DN (default dc=example,dc=org)
  --db-max-size-gb    olcDbMaxSize, in GiB (default 1) — must comfortably
                       exceed the loaded data's on-disk size or slapadd
                       fails partway through with the map full, not with a
                       useful benchmark number
  --json              write the evidence record to this file too (always
                       printed to stdout regardless)
  -h, --help          this text
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --image) image="${2:?--image needs a value}"; shift 2 ;;
    --count) count="${2:?--count needs a value}"; shift 2 ;;
    --base) base="${2:?--base needs a value}"; shift 2 ;;
    --db-max-size-gb) db_max_size_gb="${2:?--db-max-size-gb needs a value}"; shift 2 ;;
    --json) out_json="${2:?--json needs a path}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown argument: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

[ -n "$image" ] || { echo "--image is required" >&2; exit 2; }
[ "$count" -gt 0 ] 2>/dev/null || { echo "--count must be a positive integer" >&2; exit 2; }

command -v docker >/dev/null 2>&1 || { echo "docker not found on PATH" >&2; exit 1; }
# BSD date on macOS before Sequoia (15, 2024) doesn't support %N and emits it
# literally, silently turning every sub-second timing below into 0 rather
# than failing loudly.
[ "$(date +%N)" != "N" ] || { echo "date +%N unsupported — need macOS 15+ or GNU coreutils date" >&2; exit 1; }

# Named after the entry count, not the PID: these two volumes are this
# script's actual deliverable, meant to outlive it — bench-search.sh runs
# against them afterward. Only the throwaway containers and the generated
# LDIF get cleaned up here; the volumes are printed at the end instead of
# deleted, and it is the operator's `docker volume rm` when done with them.
run_id="ldapium-bench-${count}"
vol_config="${run_id}-config"
vol_data="${run_id}-data"
ldif_file=$(mktemp "${TMPDIR:-/tmp}/${run_id}-XXXXXX.ldif")
cleanup() {
  docker rm -f "${run_id}-bootstrap" "${run_id}-loader" "${run_id}-verify" >/dev/null 2>&1 || true
  rm -f "$ldif_file"
}
trap cleanup EXIT

if docker volume inspect "$vol_config" >/dev/null 2>&1 || docker volume inspect "$vol_data" >/dev/null 2>&1; then
  echo "volumes ${vol_config}/${vol_data} already exist — remove them first (docker volume rm) if you want a clean load, or they will be reused as-is" >&2
fi

echo "generating ${count} entries..." >&2
gen_start=$(date +%s.%N)
python3 "$(dirname "$0")/bench-generate-ldif.py" --count "$count" --base "$base" > "$ldif_file"
gen_end=$(date +%s.%N)
ldif_bytes=$(wc -c < "$ldif_file" | tr -d ' ')
echo "generated $(du -h "$ldif_file" | cut -f1) in $(awk -v a="$gen_start" -v b="$gen_end" 'BEGIN{printf "%.2f", b-a}')s" >&2

db_max_size_bytes=$((db_max_size_gb * 1073741824))

echo "bootstrapping a fresh release (olcDbMaxSize=${db_max_size_gb}GiB)..." >&2
docker run -d --name "${run_id}-bootstrap" \
  -v "${vol_config}:/etc/openldap/slapd.d" \
  -v "${vol_data}:/var/lib/openldap/data" \
  -e LDAP_ADMIN_PASSWORD=bench-not-a-real-secret \
  -e LDAP_ROOT_DN="$base" \
  -e LDAP_DB_MAX_SIZE="$db_max_size_bytes" \
  "$image" >/dev/null

for _ in $(seq 1 60); do
  docker exec "${run_id}-bootstrap" ldapwhoami -x -D "cn=admin,${base}" -w bench-not-a-real-secret >/dev/null 2>&1 && break
  sleep 1
done
docker exec "${run_id}-bootstrap" ldapwhoami -x -D "cn=admin,${base}" -w bench-not-a-real-secret >/dev/null 2>&1 \
  || { echo "bootstrap never became ready" >&2; docker logs "${run_id}-bootstrap" >&2; exit 1; }
docker stop "${run_id}-bootstrap" >/dev/null

echo "loading ${count} entries with offline slapadd..." >&2
# docker cp rather than a bind mount for the LDIF: a bind mount needs the
# docker daemon and this shell to share a filesystem, which is not a given
# — Docker Desktop / Colima on macOS, and rootless Docker setups generally,
# often do not share the host's temp directory by default. docker cp works
# over the same API a bind mount would otherwise need host-side sharing
# for, so this runs the same way regardless of the operator's setup.
#
# --user root: docker cp into a container that has not been started yet
# does not reliably preserve the source file's own permission bits (found
# by testing, not assumed — the copied file came back unreadable by the
# image's own uid 999). Root bypasses that entirely rather than fighting
# docker cp's ownership behavior, and is still safe here: this is a
# throwaway container against scratch volumes, not the product's own
# runtime, which stays non-root everywhere else in this chart.
#
# This depends on the bootstrap step above having already run first: it
# creates the actual mdb/data.mdb and mdb/lock.mdb files as uid 999 (the
# image's normal user), so slapadd-as-root here only ever writes into
# already-uid-999-owned files rather than creating new root-owned ones —
# root doesn't rewrite a file's ownership just by writing to it. Verified
# by testing: bench-search.sh's later non-root slapd, and this script's own
# non-root slapcat verify step below, both need those files to stay
# uid-999-owned, and they do. Loading straight into fresh, bootstrap-less
# volumes would leave slapadd creating the files itself — as root — and
# break both of those.
docker create --name "${run_id}-loader" \
  --user root \
  --entrypoint slapadd \
  -v "${vol_config}:/etc/openldap/slapd.d" \
  -v "${vol_data}:/var/lib/openldap/data" \
  "$image" -n 1 -F /etc/openldap/slapd.d -l /tmp/bench.ldif >/dev/null
docker cp "$ldif_file" "${run_id}-loader:/tmp/bench.ldif"
load_start=$(date +%s.%N)
docker start -a "${run_id}-loader"
load_end=$(date +%s.%N)
docker rm "${run_id}-loader" >/dev/null
load_seconds=$(awk -v a="$load_start" -v b="$load_end" 'BEGIN{printf "%.3f", b-a}')

echo "verifying entry count..." >&2
loaded_count=$(docker run --rm --name "${run_id}-verify" \
  --entrypoint slapcat \
  -v "${vol_config}:/etc/openldap/slapd.d" \
  -v "${vol_data}:/var/lib/openldap/data" \
  "$image" -n 1 -F /etc/openldap/slapd.d 2>/dev/null | grep -c '^uid: bench')

echo "loaded: ${loaded_count}, requested: ${count}, seconds: ${load_seconds}" >&2

status="ok"
[ "$loaded_count" = "$count" ] || status="count-mismatch"

record=$(cat <<JSON
{"benchmark":"load","image":"${image}","entryCount":${count},"loadedCount":${loaded_count},"loadSeconds":${load_seconds},"entriesPerSecond":$(awk -v c="$count" -v s="$load_seconds" 'BEGIN{printf "%.2f", c/s}'),"ldifBytes":${ldif_bytes},"dbMaxSizeBytes":${db_max_size_bytes},"configVolume":"${vol_config}","dataVolume":"${vol_data}","status":"${status}"}
JSON
)
echo "$record"
[ -z "$out_json" ] || echo "$record" > "$out_json"

echo >&2
if [ "$status" = "ok" ]; then
  echo "for the search benchmark:" >&2
  echo "  ./scripts/bench-search.sh --image ${image} --config-volume ${vol_config} --data-volume ${vol_data} --entry-count ${count}" >&2
  echo "when done with both:" >&2
  echo "  docker volume rm ${vol_config} ${vol_data}" >&2
else
  echo "loaded count doesn't match requested count — the volumes likely already held entries before this run started (see the reuse warning above). Delete them and re-run for a clean load before trusting a search benchmark against them:" >&2
  echo "  docker volume rm ${vol_config} ${vol_data}" >&2
fi

[ "$status" = "ok" ]
