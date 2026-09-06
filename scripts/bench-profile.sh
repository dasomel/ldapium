#!/usr/bin/env bash
# End-to-end large-scale benchmark profile: generate -> offline bulk-load ->
# search -> single-connection write-latency -> one JSON+Markdown report.
#
# This wraps bench-generate-ldif.py, bench-load.sh's own bootstrap/load/verify
# sequence (parametrized instead of copy-pasted: it forwards to bench-load.sh
# under the hood, see run_load below) and bench-search.sh, and adds three
# things #124 asked for that neither script has on its own:
#
#   1. a single "--entries N --out DIR" entry point that produces one
#      self-contained result (JSON + Markdown) instead of three commands and
#      three separate stdout blobs the operator has to stitch together by hand;
#   2. progress sampling and a wall-clock time-box for the load phase, so a
#      run that cannot finish in the allotted time is stopped and reported as
#      an honest partial result (entries loaded, elapsed, on-disk size) instead
#      of left to run unbounded or killed with nothing recorded;
#   3. environment capture (CPU/mem/disk, image digest, OpenLDAP version) in
#      the same record, because a load-rate number without the hardware it was
#      measured on is not reproducible evidence.
#
#   ./scripts/bench-profile.sh --entries 1000000 --out docs/../scripts/bench-results
#   ./scripts/bench-profile.sh --entries 10000000 --out /tmp/bench --timeout-seconds 9000 \
#       --db-max-size-gb 24 --label "colima aarch64 VM, 3 vCPU/6 GiB cap"
#
# Same offline-slapadd-over-a-real-bootstrapped-cn=config design as
# bench-load.sh (see its own header for why offline, not LDAP_SEED_DIR) plus
# `-q`: slapadd's quick/no-verify mode, which skips per-entry schema
# re-verification it would otherwise redo on data this script itself just
# generated to be schema-valid. It is the fastest supported bulk-load path —
# see docs/scale-benchmarks.md's "The profile runner" section for the
# tradeoff (skips the same-file duplicate-DN safety net a hand-authored LDIF
# would want) and why it is fine for this generator's guaranteed-unique output.
set -euo pipefail

image=""
entries=0
base="dc=example,dc=org"
out_dir=""
db_max_size_gb=0
timeout_seconds=0
search_concurrency=0
search_queries_per_worker=0
write_count=200
label=""
skip_search=0
skip_write=0
keep_volumes=0

# True iff $1 is a non-negative base-10 integer with no sign, decimal point,
# or leading garbage — used to validate numeric flags at parse time instead
# of letting a bad value (e.g. "--timeout-seconds abc") reach an arithmetic
# `[ -gt ]`/`[ -ge ]` test deep inside the load loop, where bash would raise
# an "integer expression expected" error mid-run instead of a clean, early
# exit 2 with a usage message.
is_uint() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

usage() {
  cat <<'EOF'
Usage: bench-profile.sh --entries N --out DIR [options]

  --entries              N synthetic entries to generate and load (required)
  --out                  directory to write bench-profile-<N>-<ts>.json/.md (required)
  --image                ldapium image to benchmark (default: ldapium:e2e)
  --base                 base DN (default dc=example,dc=org)
  --db-max-size-gb       olcDbMaxSize, GiB. Default: derived from --entries
                         at ~9400 bytes/entry (empirically grounded, NOT the
                         raw LDIF size, which badly undersizes this chart's
                         10-index footprint — see the comment above where
                         this is computed for the live-verified failures
                         that set this constant), rounded up to whole GiB,
                         minimum 1. This is a default of last resort that
                         over-sizes at scale (see the comment above) — pass
                         this explicitly, sized from a measured run at a
                         nearby scale, for anything beyond a quick smoke
                         test. See docs/scale-benchmarks.md before trusting
                         a number produced against an undersized map.
  --timeout-seconds      wall-clock cap on the LOAD phase only. 0 (default)
                         means unbounded. On expiry the loader is killed and
                         the last progress sample is recorded as a partial
                         result — search/write phases are skipped.
  --search-concurrency   forwarded to bench-search.sh (default: scales with
                         --entries, see code; 20 at 1M+)
  --search-queries-per-worker  forwarded to bench-search.sh (default 100)
  --write-count          online single-connection write-latency samples
                         after load+search (default 200; 0 disables)
  --label                free-text environment label recorded in the report
                         (e.g. "Colima aarch64 VM, 3 vCPU/6 GiB cap")
  --skip-search          skip the search phase
  --skip-write           skip the write-latency phase
  --keep-volumes         do not delete the config/data volumes at the end
                         (default: delete them — this runner is meant to be
                         a self-contained one-shot, unlike bench-load.sh
                         which leaves volumes for a separate bench-search.sh)
  -h, --help             this text
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --image) image="${2:?}"; shift 2 ;;
    --entries)
      is_uint "${2:-}" && [ "${2:-0}" -gt 0 ] || {
        printf -- '--entries must be a positive integer (got: %s)\n\n' "${2:-}" >&2
        usage >&2; exit 2
      }
      entries="${2:?}"; shift 2 ;;
    --base) base="${2:?}"; shift 2 ;;
    --out) out_dir="${2:?}"; shift 2 ;;
    --db-max-size-gb) db_max_size_gb="${2:?}"; shift 2 ;;
    --timeout-seconds)
      is_uint "${2:-}" || {
        printf -- '--timeout-seconds must be a non-negative integer (got: %s)\n\n' "${2:-}" >&2
        usage >&2; exit 2
      }
      timeout_seconds="${2:?}"; shift 2 ;;
    --search-concurrency) search_concurrency="${2:?}"; shift 2 ;;
    --search-queries-per-worker) search_queries_per_worker="${2:?}"; shift 2 ;;
    --write-count) write_count="${2:?}"; shift 2 ;;
    --label) label="${2:?}"; shift 2 ;;
    --skip-search) skip_search=1; shift ;;
    --skip-write) skip_write=1; shift ;;
    --keep-volumes) keep_volumes=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown argument: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

image="${image:-ldapium:e2e}"
[ "$entries" -gt 0 ] 2>/dev/null || { echo "--entries is required" >&2; usage >&2; exit 2; }
[ -n "$out_dir" ] || { echo "--out is required" >&2; usage >&2; exit 2; }

command -v docker >/dev/null 2>&1 || { echo "docker not found on PATH" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 not found on PATH" >&2; exit 1; }
[ "$(date +%N)" != "N" ] || { echo "date +%N unsupported — need macOS 15+ or GNU coreutils date" >&2; exit 1; }

script_dir="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$out_dir"

# NOT ~217 bytes/entry (docs/scale-benchmarks.md's raw-LDIF ratio) — the
# in-map size the mdb backend actually needs is dominated by this chart's 10
# default indices (image/ldifs/01-cn-config.ldif: objectClass, entryUUID,
# entryCSN, uid, cn, mail, memberOf, member, sn, givenName), not by entry
# payload size. Live-verified the hard way, twice:
#   - a first version of this formula used the raw-LDIF ratio and a 1M load
#     died at 705,499/1,000,000 entries with the map full — 1073741824 bytes
#     / 705499 entries = ~1522 bytes/entry was already the FLOOR at the point
#     it ran out, not a safe estimate.
#   - a second version used 1800 bytes/entry x2.2 headroom (~3960 bytes/
#     entry, 4GiB at 1M) on the mistaken assumption that this reproduced
#     docs/scale-benchmarks.md's separately-measured 4GiB-for-1M figure — it
#     does not: that figure is from bench-load.sh's non-`-q` path, a
#     different code path with different map growth behavior, not evidence
#     this formula's own output is sufficient under `-q`. Re-verified 2026-
#     09-06 on this exact repo state: 4GiB (this formula's own then-output
#     for --entries 1000000, no override) died at 931,499/1,000,000 with the
#     map full — 4294967296 / 931499 = ~4611 bytes/entry was the FLOOR this
#     time, already above the formula's 3960 bytes/entry effective rate.
# This uses 4700 bytes/entry (above the ~4611 floor just observed) x2.0
# safety headroom (~9400 bytes/entry effective, 9GiB at 1M) — comfortably
# above both floors above and above the 8GiB that was separately confirmed
# sufficient for the committed 1M result
# (scripts/bench-results/bench-profile-1000000-*.json). This is a default of
# last resort, not a sizing recommendation: per-entry map overhead is not
# constant across scale (the committed 10M result completed successfully
# with an explicit --db-max-size-gb of only ~2.1KB/entry — this formula
# would compute a much larger, untested value at that N; that a smaller
# explicit size worked once is not proof it is the minimum, only that this
# formula's own output at large N is unverified and likely wasteful) —
# always pass --db-max-size-gb
# explicitly, sized from a measured run at a nearby scale, for anything
# beyond a quick smoke test. See docs/scale-benchmarks.md's profile-runner
# section.
#
# That headroom is real, immediately-consumed disk under `-q`, not slack
# sitting unused until needed: `-q` allocates the FULL configured
# olcDbMaxSize on disk at load start rather than growing the file lazily
# (confirmed: 500 tiny entries into a 256MiB map produced an exact 256MiB
# data.mdb under `-q`, vs. a 1.4MB file for the identical load without
# `-q`) — size --db-max-size-gb explicitly rather than trusting this
# default when disk is tight (e.g. a shared VM), see
# docs/scale-benchmarks.md's profile-runner section.
if [ "$db_max_size_gb" -le 0 ] 2>/dev/null; then
  db_max_size_gb=$(awk -v n="$entries" 'BEGIN{gb=(n*4700*2.0)/1073741824; v=int(gb)+1; if (v<1) v=1; print v}')
fi

if [ "$search_concurrency" -le 0 ] 2>/dev/null; then
  search_concurrency=$([ "$entries" -ge 1000000 ] && echo 20 || echo 10)
fi
if [ "$search_queries_per_worker" -le 0 ] 2>/dev/null; then
  search_queries_per_worker=100
fi

run_id="ldapium-benchprofile-${entries}"
vol_config="${run_id}-config"
vol_data="${run_id}-data"
ldif_file=$(mktemp "${TMPDIR:-/tmp}/${run_id}-XXXXXX.ldif")
ts="$(date -u +%Y%m%dT%H%M%SZ)"
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/${run_id}-work-XXXXXX")

cleanup() {
  docker rm -f "${run_id}-bootstrap" "${run_id}-loader" "${run_id}-verify" "${run_id}-server" \
    "${run_id}-du-apparent" "${run_id}-du-allocated" >/dev/null 2>&1 || true
  rm -f "$ldif_file"
  rm -rf "$work_dir"
  if [ "$keep_volumes" -eq 0 ]; then
    docker volume rm "$vol_config" "$vol_data" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }

if docker volume inspect "$vol_config" >/dev/null 2>&1 || docker volume inspect "$vol_data" >/dev/null 2>&1; then
  log "volumes ${vol_config}/${vol_data} already exist — deleting for a clean run"
  docker rm -f "${run_id}-bootstrap" "${run_id}-loader" >/dev/null 2>&1 || true
  docker volume rm "$vol_config" "$vol_data" >/dev/null 2>&1 || true
fi

### 0. Environment -----------------------------------------------------------
image_digest=$(docker image inspect "$image" --format '{{.Id}}' 2>/dev/null || echo "unknown")
host_uname=$(uname -a)
host_cpus=$(docker info --format '{{.NCPU}}' 2>/dev/null || echo "unknown")
host_mem_bytes=$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo "unknown")
openldap_version=$(docker run --rm --entrypoint slapd "$image" -VV 2>&1 | head -1 || echo "unknown")
disk_free_kb=$(df -Pk "${TMPDIR:-/tmp}" | awk 'NR==2{print $4}')
log "environment: image=${image} digest=${image_digest} cpus=${host_cpus} mem=${host_mem_bytes} openldap=[${openldap_version}] tmp-disk-free-kb=${disk_free_kb}"

### 1. Generate ---------------------------------------------------------------
# Streams entries one at a time to disk (bench-generate-ldif.py writes each
# entry as it is built, never holds the full set in a list) — RAM stays flat
# regardless of --entries; only disk grows, and this script's own --out
# directory and TMPDIR are checked for headroom by the operator, not assumed.
log "generating ${entries} entries..."
gen_start=$(date +%s.%N)
python3 "${script_dir}/bench-generate-ldif.py" --count "$entries" --base "$base" > "$ldif_file"
gen_end=$(date +%s.%N)
ldif_bytes=$(wc -c < "$ldif_file" | tr -d ' ')
gen_seconds=$(awk -v a="$gen_start" -v b="$gen_end" 'BEGIN{printf "%.3f", b-a}')
log "generated $(du -h "$ldif_file" | cut -f1) in ${gen_seconds}s"

db_max_size_bytes=$((db_max_size_gb * 1073741824))

### 2. Bootstrap ----------------------------------------------------------------
log "bootstrapping a fresh release (olcDbMaxSize=${db_max_size_gb}GiB, cap 3 cpu/6g)..."
docker run -d --name "${run_id}-bootstrap" \
  --cpus 3 --memory 6g \
  -v "${vol_config}:/etc/openldap/slapd.d" \
  -v "${vol_data}:/var/lib/openldap/data" \
  -e LDAP_ADMIN_PASSWORD=bench-not-a-real-secret \
  -e LDAP_ROOT_DN="$base" \
  -e LDAP_DB_MAX_SIZE="$db_max_size_bytes" \
  "$image" >/dev/null

ready=0
for _ in $(seq 1 60); do
  if docker exec "${run_id}-bootstrap" ldapwhoami -x -D "cn=admin,${base}" -w bench-not-a-real-secret >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 1
done
[ "$ready" -eq 1 ] || { log "bootstrap never became ready"; docker logs "${run_id}-bootstrap" >&2; exit 1; }
docker stop "${run_id}-bootstrap" >/dev/null

### 3. Load (offline slapadd -q, with progress sampling + time-box) -----------
# See scripts/bench-load.sh for why --user root + docker cp (not a bind
# mount) here, and why this depends on the bootstrap step above having
# already created the mdb files as uid 999.
log "loading ${entries} entries with offline 'slapadd -q'..."
docker create --name "${run_id}-loader" \
  --user root --cpus 3 --memory 6g \
  --entrypoint slapadd \
  -v "${vol_config}:/etc/openldap/slapd.d" \
  -v "${vol_data}:/var/lib/openldap/data" \
  "$image" -q -n 1 -F /etc/openldap/slapd.d -l /tmp/bench.ldif >/dev/null
docker cp "$ldif_file" "${run_id}-loader:/tmp/bench.ldif"

progress_log="${work_dir}/load-progress.tsv"
: > "$progress_log"
# A separate throwaway container against the same data volume, run read-only
# via slapcat while the loader container is mid-transaction. Safe because
# LMDB readers never block on (or are blocked by) a writer — confirmed live
# for this exact scenario, see docs/scale-benchmarks.md's "1M / 10M / 30M+
# load profile" section. NOT free, though: the cost of one slapcat scan
# grows with however much of the database already exists, so sampling it on
# a fixed interval for the whole duration of a long run means later samples
# cost more than earlier ones, and the cumulative cost compounds across a
# many-sample run. Live-verified doing exactly this to a 10M attempt: the
# reported load rate collapsed from ~30,000 entries/s in the first 30s to
# ~1,700 entries/s by 131s with no other explanation — self-inflicted
# monitoring overhead, not the product slowing down. Fixed by making this
# genuinely O(1) instead of O(current size): past PROGRESS_COUNT_MAX_ENTRIES
# this reports only wall-clock elapsed + loader RSS (both cheap, no database
# scan) and leaves the exact count to the one unavoidable slapcat count this
# script already runs once, after the load phase ends either way.
progress_count_max_entries=2000000
sample_progress() {
  if [ "$entries" -gt "$progress_count_max_entries" ]; then
    echo "n/a (skipped above ${progress_count_max_entries} entries — see comment above)"
    return
  fi
  docker run --rm --entrypoint slapcat \
    -v "${vol_config}:/etc/openldap/slapd.d" \
    -v "${vol_data}:/var/lib/openldap/data" \
    "$image" -n 1 -F /etc/openldap/slapd.d 2>/dev/null | grep -c '^uid: bench' || true
}
sample_rss() {
  docker stats --no-stream --format '{{.MemUsage}}' "${run_id}-loader" 2>/dev/null | awk -F' / ' '{print $1}' || true
}

load_start=$(date +%s.%N)
docker start "${run_id}-loader" >/dev/null

# Sample every 30s for >=100K entries (keeps overhead well under 1% of a
# multi-minute run), every 5s below that (calibration runs are short enough
# that 30s would produce one or two samples total).
sample_interval=5
[ "$entries" -ge 100000 ] && sample_interval=30

elapsed=0
status="running"
while docker inspect -f '{{.State.Running}}' "${run_id}-loader" 2>/dev/null | grep -q true; do
  sleep "$sample_interval"
  elapsed=$(awk -v a="$load_start" -v b="$(date +%s.%N)" 'BEGIN{printf "%.0f", b-a}')
  cnt=$(sample_progress)
  rss=$(sample_rss)
  printf '%s\t%s\t%s\n' "$elapsed" "$cnt" "$rss" >> "$progress_log"
  log "  load progress: ${elapsed}s elapsed, ~${cnt} entries visible, loader mem ${rss}"
  if [ "$timeout_seconds" -gt 0 ] && [ "$elapsed" -ge "$timeout_seconds" ]; then
    log "timeout (${timeout_seconds}s) reached — killing loader, recording partial result"
    docker kill "${run_id}-loader" >/dev/null 2>&1 || true
    status="timed-out"
    break
  fi
done
load_end=$(date +%s.%N)
load_seconds=$(awk -v a="$load_start" -v b="$load_end" 'BEGIN{printf "%.3f", b-a}')

if [ "$status" = "running" ]; then
  exit_code=$(docker inspect -f '{{.State.ExitCode}}' "${run_id}-loader" 2>/dev/null || echo 1)
  status=$([ "$exit_code" = "0" ] && echo "ok" || echo "failed")
fi
# Captured before removal regardless of outcome: on a non-"ok" status this is
# the only record of *why* (e.g. slapadd's own "mdb_put failed: MDB_MAP_FULL"
# when --db-max-size-gb was undersized for --entries), since `docker start`
# above runs detached, not `-a`, so nothing else ever sees this container's
# stdout/stderr.
loader_log_tail=$(docker logs "${run_id}-loader" 2>&1 | tail -20 || true)
docker rm -f "${run_id}-loader" >/dev/null 2>&1 || true
if [ "$status" != "ok" ]; then
  log "loader exited non-zero — last output:"
  printf '%s\n' "$loader_log_tail" >&2
fi

log "verifying loaded entry count (final slapcat count)..."
loaded_count=$(docker run --rm --entrypoint slapcat \
  -v "${vol_config}:/etc/openldap/slapd.d" \
  -v "${vol_data}:/var/lib/openldap/data" \
  "$image" -n 1 -F /etc/openldap/slapd.d 2>/dev/null | grep -c '^uid: bench' || true)
[ -n "$loaded_count" ] || loaded_count=0

if [ "$status" = "ok" ] && [ "$loaded_count" != "$entries" ]; then
  status="count-mismatch"
fi

log "on-disk DB size..."
# Two different numbers, both recorded, because they answer different
# questions and can legitimately diverge:
#   - dbApparentBytes ('du -sb', apparent size): under 'slapadd -q' this
#     equals dbMaxSizeBytes almost exactly, not real data volume — see the
#     eager-allocation note above db_max_size_gb's default. This is what a
#     filesystem call like stat()/`ls -l` reports.
#   - dbAllocatedBytes (plain 'du', real device blocks, sparse-file-aware):
#     what actually occupies disk. These two DIVERGE SHARPLY at real scale on
#     this runner's Colima aarch64 VM — live-verified 2026-09-06 at 1M
#     entries: dbApparentBytes 9,663,684,672 (~9.0GiB, ≈dbMaxSizeBytes) vs.
#     dbAllocatedBytes 1,529,278,464 (~1.4GiB) — apparent is 6.3x the real
#     allocated size. (An earlier, smaller synthetic test — 500 tiny entries
#     into a 256MiB map — had shown the two equal and is why an earlier
#     version of this comment claimed no sparseness; that test was too small
#     to be representative and that claim was wrong. Trust the 1M number
#     above, not the 500-entry one.) dbAllocatedBytes is the number that
#     matters for capacity planning; dbApparentBytes only tells you the
#     configured map size took effect, not what disk it actually consumed.
#     ldifBytes remains the closer proxy for actual *data* volume (excluding
#     index/LMDB overhead) than either.
# Distinct --name per call (not a shared "${run_id}-du"): two docker run
# invocations back to back with the same --rm'd container name race a
# lagging removal — if the first container's removal hasn't completed by
# the time the second starts, docker refuses the name collision and this
# `du` call fails. Falling back to a bare `0` on that failure would silently
# report "zero bytes" instead of "measurement failed", indistinguishable
# from a real (if implausible) empty database — so a failure here is logged
# and recorded as -1 (never a real byte count) instead.
measure_du_bytes() {
  local container_name="$1" du_flags="$2" out rc=0
  out=$(docker run --rm --name "$container_name" \
    -v "${vol_data}:/var/lib/openldap/data" \
    --entrypoint sh "$image" -c "du ${du_flags} /var/lib/openldap/data | cut -f1") || rc=$?
  if [ "$rc" -ne 0 ] || [ -z "$out" ]; then
    log "WARNING: 'du ${du_flags}' via ${container_name} failed (exit ${rc}, output: '${out}') — recording -1, not 0"
    echo -1
    return
  fi
  echo "$out"
}
db_apparent_bytes=$(measure_du_bytes "${run_id}-du-apparent" "-sb")
db_allocated_bytes=$(measure_du_bytes "${run_id}-du-allocated" "-s --block-size=1")

log "load phase done: status=${status} loaded=${loaded_count}/${entries} seconds=${load_seconds} db-apparent-bytes=${db_apparent_bytes} db-allocated-bytes=${db_allocated_bytes}"

### 4. Search (skipped on a non-ok load, per --skip-search, or on timeout) ---
search_json="{}"
if [ "$status" = "ok" ] && [ "$skip_search" -eq 0 ]; then
  log "running search phase (concurrency=${search_concurrency} x ${search_queries_per_worker})..."
  search_json_file="${work_dir}/search.json"
  "${script_dir}/bench-search.sh" --image "$image" \
    --config-volume "$vol_config" --data-volume "$vol_data" \
    --entry-count "$entries" --base "$base" \
    --concurrency "$search_concurrency" --queries-per-worker "$search_queries_per_worker" \
    --json "$search_json_file" >&2 || log "search phase reported failures — see above"
  [ -f "$search_json_file" ] && search_json=$(cat "$search_json_file")
else
  log "skipping search phase (status=${status}, --skip-search=${skip_search})"
fi

### 5. Write latency (single connection, online, against the loaded server) --
write_json="{}"
if [ "$status" = "ok" ] && [ "$skip_write" -eq 0 ] && [ "$write_count" -gt 0 ]; then
  log "running write-latency phase (${write_count} sequential online ldapadd, single connection)..."
  docker run -d --name "${run_id}-server" --cpus 3 --memory 6g \
    -v "${vol_config}:/etc/openldap/slapd.d" \
    -v "${vol_data}:/var/lib/openldap/data" \
    -e LDAP_ADMIN_PASSWORD=bench-not-a-real-secret \
    -e LDAP_ROOT_DN="$base" \
    "$image" >/dev/null
  ready=0
  for _ in $(seq 1 60); do
    docker exec "${run_id}-server" ldapwhoami -x -D "cn=admin,${base}" -w bench-not-a-real-secret >/dev/null 2>&1 && { ready=1; break; }
    sleep 1
  done
  if [ "$ready" -eq 1 ]; then
    write_lat="${work_dir}/write-latency.tsv"
    : > "$write_lat"
    for i in $(seq 1 "$write_count"); do
      uid="writebench$(printf '%09d' "$i")"
      entry_ldif="dn: uid=${uid},ou=people,${base}
objectClass: inetOrgPerson
uid: ${uid}
cn: Write Bench ${i}
sn: WriteBench${i}
"
      t0=$(date +%s.%N)
      rc=0
      printf '%s' "$entry_ldif" | docker exec -i "${run_id}-server" \
        ldapadd -x -D "cn=admin,${base}" -w bench-not-a-real-secret >/dev/null 2>&1 || rc=$?
      t1=$(date +%s.%N)
      ms=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.3f", (b-a)*1000}')
      printf '%s\t%s\n' "$ms" "$rc" >> "$write_lat"
    done
    sort -n "$write_lat" | awk -F'\t' '{print $1}' > "${write_lat}.sorted"
    wfailed=$(awk -F'\t' '$2 != 0' "$write_lat" | wc -l | tr -d ' ')
    wpercentile() {
      p="$1"; n=$(wc -l < "${write_lat}.sorted" | tr -d ' ')
      idx=$(awk -v n="$n" -v p="$p" 'BEGIN{x=(p/100)*n; i=int(x); if (x>i) i++; if (i<1) i=1; if (i>n) i=n; print i}')
      sed -n "${idx}p" "${write_lat}.sorted"
    }
    wp50=$(wpercentile 50); wp95=$(wpercentile 95); wp99=$(wpercentile 99)
    write_json=$(cat <<JSON
{"benchmark":"write-latency","mode":"single-connection-sequential-online-ldapadd","count":${write_count},"failed":${wfailed},"latencyMsP50":${wp50},"latencyMsP95":${wp95},"latencyMsP99":${wp99}}
JSON
)
    log "write-latency: ${write_count} adds, ${wfailed} failed, p50=${wp50}ms p95=${wp95}ms p99=${wp99}ms"
  else
    log "server never became ready for write-latency phase — skipping"
  fi
  docker rm -f "${run_id}-server" >/dev/null 2>&1 || true
else
  log "skipping write-latency phase (status=${status}, --skip-write=${skip_write}, --write-count=${write_count})"
fi

### 6. Report -------------------------------------------------------------------
# Reads one field out of a small JSON blob on stdin, "n/a" if absent —
# kept as a plain function (not inline python -c with an f-string) because
# nested double-quotes inside a single-quoted -c argument do not survive
# bash's single-quote escaping, which is why this exists instead of that.
jfield() {
  python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    print(d.get(sys.argv[1], "n/a"))
except Exception:
    print("n/a")
' "$1"
}

out_base="${out_dir}/bench-profile-${entries}-${ts}"
json_file="${out_base}.json"
md_file="${out_base}.md"

progress_json="[]"
if [ -s "$progress_log" ]; then
  # entriesVisible is a quoted string, not a bare number: above
  # progress_count_max_entries it holds a "n/a (skipped ...)" note instead of
  # a count (see sample_progress), which would otherwise break this as JSON.
  progress_json=$(awk -F'\t' '{printf "%s{\"elapsedSeconds\":%s,\"entriesVisible\":\"%s\",\"loaderMem\":\"%s\"}", (NR>1?",":""), $1, $2, $3} END{print ""}' "$progress_log")
  progress_json="[${progress_json}]"
fi

label_json=$(printf '%s' "$label" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')
cat > "$json_file" <<JSON
{
  "benchmark": "profile",
  "label": ${label_json},
  "timestampUtc": "${ts}",
  "environment": {
    "uname": $(printf '%s' "$host_uname" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().strip()))'),
    "dockerCpus": "${host_cpus}",
    "dockerMemBytes": "${host_mem_bytes}",
    "openldapVersion": $(printf '%s' "$openldap_version" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().strip()))'),
    "imageDigest": "${image_digest}",
    "tmpDiskFreeKb": ${disk_free_kb}
  },
  "requestedEntries": ${entries},
  "loadedCount": ${loaded_count},
  "status": "${status}",
  "loaderLogTail": $(printf '%s' "$loader_log_tail" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'),
  "generation": {"seconds": ${gen_seconds}, "ldifBytes": ${ldif_bytes}},
  "load": {
    "seconds": ${load_seconds},
    "entriesPerSecond": $(awk -v c="$loaded_count" -v s="$load_seconds" 'BEGIN{printf "%.2f", (s>0)?c/s:0}'),
    "dbMaxSizeBytes": ${db_max_size_bytes},
    "dbApparentBytes": ${db_apparent_bytes},
    "dbAllocatedBytes": ${db_allocated_bytes},
    "timeoutSeconds": ${timeout_seconds},
    "progressSamples": ${progress_json}
  },
  "search": ${search_json},
  "writeLatency": ${write_json}
}
JSON

python3 -m json.tool "$json_file" > "${json_file}.pretty" && mv "${json_file}.pretty" "$json_file"

{
  echo "# Benchmark profile: ${entries} entries"
  echo
  echo "- Label: ${label:-none}"
  echo "- Timestamp (UTC): ${ts}"
  echo "- Image: ${image} (${image_digest})"
  echo "- OpenLDAP: ${openldap_version}"
  echo "- Docker CPUs / mem visible to daemon: ${host_cpus} / ${host_mem_bytes}"
  echo "- Status: **${status}**"
  echo
  echo "| Metric | Value |"
  echo "|---|---|"
  echo "| Requested entries | ${entries} |"
  echo "| Loaded entries | ${loaded_count} |"
  echo "| Load time | ${load_seconds}s |"
  echo "| Load rate | $(awk -v c="$loaded_count" -v s="$load_seconds" 'BEGIN{printf "%.2f", (s>0)?c/s:0}') entries/s |"
  echo "| DB apparent size (== configured map size under \`-q\`; \`du -sb\`, see script header) | ${db_apparent_bytes} bytes |"
  echo "| DB allocated size (actual disk blocks, sparse-aware; \`du\` without \`-b\`) | ${db_allocated_bytes} bytes |"
  echo "| olcDbMaxSize used | ${db_max_size_bytes} bytes |"
  echo "| LDIF size | ${ldif_bytes} bytes |"
  if [ "$search_json" != "{}" ]; then
    echo "| Search QPS | $(printf '%s' "$search_json" | jfield queriesPerSecond) |"
    echo "| Search p50/p95/p99 | $(printf '%s' "$search_json" | jfield latencyMsP50)ms / $(printf '%s' "$search_json" | jfield latencyMsP95)ms / $(printf '%s' "$search_json" | jfield latencyMsP99)ms |"
  fi
  if [ "$write_json" != "{}" ]; then
    echo "| Write p50/p95/p99 (single conn, online) | $(printf '%s' "$write_json" | jfield latencyMsP50)ms / $(printf '%s' "$write_json" | jfield latencyMsP95)ms / $(printf '%s' "$write_json" | jfield latencyMsP99)ms |"
  fi
  echo
  echo "Full machine-readable record: \`$(basename "$json_file")\`"
} > "$md_file"

log "report written: ${json_file} / ${md_file}"
cat "$json_file"

[ "$status" = "ok" ]
