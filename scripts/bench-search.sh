#!/usr/bin/env bash
# Measure search throughput and latency distribution against a release
# already loaded by bench-load.sh — same two named volumes, so the search
# benchmark runs against the exact data and cn=config (including the
# indices below) the load benchmark produced, not a fresh empty database.
#
# Indices matter more here than the load benchmark's own timing: #41's own
# scoping note says a number measured without the right index in place is
# noise, not a benchmark. The uid index this chart ships by default
# (charts/ldapium/values.yaml -> image/ldifs/01-cn-config.ldif) covers the
# equality lookups this script runs; it does not add or change any index
# itself; it uses the deployment's index configuration.
#
#   ./scripts/bench-search.sh --image ldapium:bench \
#       --config-volume ldapium-bench-1234-config --data-volume ldapium-bench-1234-data \
#       --entry-count 100000 --concurrency 20 --queries-per-worker 200
set -euo pipefail

image=""
vol_config=""
vol_data=""
base="dc=example,dc=org"
entry_count=0
concurrency=10
queries_per_worker=100
out_json=""

usage() {
  cat <<'EOF'
Usage: bench-search.sh --image IMAGE --config-volume V --data-volume V --entry-count N
                        [--concurrency N] [--queries-per-worker N] [--base DN] [--json FILE]

  --image                ldapium image (same one bench-load.sh loaded)
  --config-volume        the Docker volume bench-load.sh left the config in
  --data-volume           the Docker volume bench-load.sh left the data in
  --entry-count          how many bench entries exist, to pick valid uids
  --concurrency          parallel workers (default 10)
  --queries-per-worker   sequential lookups per worker (default 100) —
                          total queries = concurrency * queries-per-worker
  --base                 base DN (default dc=example,dc=org)
  --json                 write the evidence record to this file too
  -h, --help             this text
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --image) image="${2:?}"; shift 2 ;;
    --config-volume) vol_config="${2:?}"; shift 2 ;;
    --data-volume) vol_data="${2:?}"; shift 2 ;;
    --entry-count) entry_count="${2:?}"; shift 2 ;;
    --concurrency) concurrency="${2:?}"; shift 2 ;;
    --queries-per-worker) queries_per_worker="${2:?}"; shift 2 ;;
    --base) base="${2:?}"; shift 2 ;;
    --json) out_json="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown argument: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

for req in image vol_config vol_data; do
  [ -n "${!req}" ] || { echo "--${req//_/-} is required" >&2; usage >&2; exit 2; }
done
[ "$entry_count" -gt 0 ] 2>/dev/null || { echo "--entry-count must be a positive integer" >&2; exit 2; }

run_id="ldapium-bench-search-$$"
results_dir=$(mktemp -d "${TMPDIR:-/tmp}/${run_id}-XXXXXX")
cleanup() {
  docker rm -f "${run_id}-server" >/dev/null 2>&1 || true
  rm -rf "$results_dir"
}
trap cleanup EXIT

echo "starting server against the loaded volumes..." >&2
docker run -d --name "${run_id}-server" \
  -v "${vol_config}:/etc/openldap/slapd.d" \
  -v "${vol_data}:/var/lib/openldap/data" \
  -e LDAP_ADMIN_PASSWORD=bench-not-a-real-secret \
  -e LDAP_ROOT_DN="$base" \
  "$image" >/dev/null

for _ in $(seq 1 60); do
  docker exec "${run_id}-server" ldapwhoami -x -D "cn=admin,${base}" -w bench-not-a-real-secret >/dev/null 2>&1 && break
  sleep 1
done
docker exec "${run_id}-server" ldapwhoami -x -D "cn=admin,${base}" -w bench-not-a-real-secret >/dev/null 2>&1 \
  || { echo "server never became ready" >&2; docker logs "${run_id}-server" >&2; exit 1; }

echo "running ${concurrency} workers x ${queries_per_worker} queries each..." >&2
worker() {
  wid="$1"
  out="${results_dir}/${wid}.tsv"
  : > "$out"
  for i in $(seq 1 "$queries_per_worker"); do
    n=$(( (RANDOM * RANDOM + i + wid) % entry_count ))
    uid=$(printf 'bench%09d' "$n")
    t0=$(date +%s.%N)
    docker exec "${run_id}-server" \
      ldapsearch -x -D "cn=admin,${base}" -w bench-not-a-real-secret \
        -b "ou=people,${base}" -LLL "(uid=${uid})" >/dev/null 2>&1
    rc=$?
    t1=$(date +%s.%N)
    ms=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.3f", (b-a)*1000}')
    printf '%s\t%s\n' "$ms" "$rc" >> "$out"
  done
}

overall_start=$(date +%s.%N)
pids=()
for w in $(seq 1 "$concurrency"); do
  worker "$w" &
  pids+=($!)
done
for pid in "${pids[@]}"; do
  wait "$pid"
done
overall_end=$(date +%s.%N)
wall_seconds=$(awk -v a="$overall_start" -v b="$overall_end" 'BEGIN{printf "%.3f", b-a}')

cat "${results_dir}"/*.tsv > "${results_dir}/all.tsv"
total=$(wc -l < "${results_dir}/all.tsv" | tr -d ' ')
failed=$(awk -F'\t' '$2 != 0' "${results_dir}/all.tsv" | wc -l | tr -d ' ')

# Percentiles over the latency column, sorted ascending — nearest-rank
# method (simple, and exact enough for a benchmark, not a load-testing
# product's own SLA reporting).
sorted="${results_dir}/sorted.txt"
awk -F'\t' '{print $1}' "${results_dir}/all.tsv" | sort -n > "$sorted"
percentile() {
  p="$1"
  n=$(wc -l < "$sorted" | tr -d ' ')
  idx=$(awk -v n="$n" -v p="$p" 'BEGIN{i=int((p/100)*n); if (i<1) i=1; if (i>n) i=n; print i}')
  sed -n "${idx}p" "$sorted"
}
p50=$(percentile 50)
p95=$(percentile 95)
p99=$(percentile 99)
qps=$(awk -v n="$total" -v s="$wall_seconds" 'BEGIN{printf "%.2f", n/s}')

echo "total=${total} failed=${failed} qps=${qps} p50=${p50}ms p95=${p95}ms p99=${p99}ms" >&2

record=$(cat <<JSON
{"benchmark":"search","image":"${image}","entryCount":${entry_count},"concurrency":${concurrency},"totalQueries":${total},"failedQueries":${failed},"wallSeconds":${wall_seconds},"queriesPerSecond":${qps},"latencyMsP50":${p50},"latencyMsP95":${p95},"latencyMsP99":${p99}}
JSON
)
echo "$record"
[ -z "$out_json" ] || echo "$record" > "$out_json"

[ "$failed" -eq 0 ]
