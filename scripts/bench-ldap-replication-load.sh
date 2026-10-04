#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
properties_file="${JMETER_PROPERTIES:-${repo_root}/.local/ldap-replication-load.properties}"
threads="${LDAP_LOAD_THREADS:-10}"
loops="${LDAP_LOAD_LOOPS:-1000}"
jmeter_bin="${JMETER_BIN:-jmeter}"

usage() {
  cat <<'EOF'
Usage: scripts/bench-ldap-replication-load.sh [--properties FILE] [--threads N] [--loops N]

Runs the read-only three-node Apache JMeter LDAP profile. All three nodes are
loaded concurrently; each virtual user binds once, searches on a persistent
LDAP session, then unbinds. Reports are written below .local/ldap-load-results/.

  --properties FILE  protected JMeter properties file (default:
                    .local/ldap-replication-load.properties)
  --threads N        concurrent users per provider (default: 10)
  --loops N          searches per user on each provider (default: 1000)
  JMETER_BIN         JMeter executable (default: jmeter)
EOF
}

is_positive_integer() { [[ "$1" =~ ^[1-9][0-9]*$ ]]; }

while (($#)); do
  case "$1" in
    --properties) properties_file="${2:?}"; shift 2 ;;
    --threads) threads="${2:?}"; shift 2 ;;
    --loops) loops="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown argument: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

is_positive_integer "$threads" || { echo "--threads must be a positive integer" >&2; exit 2; }
is_positive_integer "$loops" || { echo "--loops must be a positive integer" >&2; exit 2; }
[[ -f "$properties_file" ]] || { printf 'JMeter properties file not found: %s\n' "$properties_file" >&2; exit 1; }
command -v "$jmeter_bin" >/dev/null 2>&1 || { echo "JMeter not found; install Apache JMeter and set JMETER_BIN if needed" >&2; exit 1; }

python3 - "$properties_file" <<'PY'
import os
import stat
import sys

path = sys.argv[1]
mode = stat.S_IMODE(os.stat(path).st_mode)
if mode & 0o077:
    print(f"refusing properties file with group/other permissions {mode:04o}: {path}; run chmod 600", file=sys.stderr)
    raise SystemExit(1)
required = {"load.bind_dn", "load.bind_password", "load.base_dn", "load.search_base", "load.search_filter"}
found = set()
for raw in open(path, encoding="utf-8"):
    line = raw.strip()
    if line and not line.startswith(("#", "!")) and "=" in line:
        found.add(line.split("=", 1)[0].strip())
missing = sorted(required - found)
if missing:
    print("missing required JMeter properties: " + ", ".join(missing), file=sys.stderr)
    raise SystemExit(1)
PY

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
result_dir="${repo_root}/.local/ldap-load-results/${timestamp}"
mkdir -p "$result_dir"

echo "Starting three-node read load: ${threads} users/node × ${loops} searches/user/node"
"$jmeter_bin" -n \
  -t "${repo_root}/tests/load/ldap-replication-read.jmx" \
  -q "$properties_file" \
  -Jload.threads="$threads" \
  -Jload.loops="$loops" \
  -Jjmeter.save.saveservice.output_format=csv \
  -Jjmeter.save.saveservice.print_field_names=true \
  -j "${result_dir}/jmeter.log" \
  -l "${result_dir}/results.jtl" \
  -e -o "${result_dir}/html"
[[ -s "${result_dir}/results.jtl" ]] || { echo "JMeter produced no sample file; inspect ${result_dir}/jmeter.log" >&2; exit 1; }
python3 - "${result_dir}/results.jtl" "$threads" "$loops" <<'PY'
import csv
import math
import sys
from collections import defaultdict

path, threads, loops = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
totals = defaultdict(lambda: [0, 0])
searches = defaultdict(list)
with open(path, newline="", encoding="utf-8") as stream:
    for row in csv.DictReader(stream):
        label = row.get("label", "")
        if " search" in label or label.endswith(" bind") or label.endswith(" unbind"):
            totals[label][0] += 1
            totals[label][1] += row.get("success", "false").lower() != "true"
        if label.endswith(" search"):
            searches[label].append(row)

failed = False
for node in range(1, 4):
    for operation in ("bind", "search", "unbind"):
        label = f"P{node} {operation}"
        count, errors = totals[label]
        expected = threads * loops if operation == "search" else threads
        print(f"{label}: {count}/{expected} samples, errors={errors}")
        if count != expected or errors:
            failed = True
    samples = searches[f"P{node} search"]
    elapsed = sorted(int(row["elapsed"]) for row in samples)
    sizes = sorted(int(row["bytes"]) for row in samples)

    def percentile(values, fraction):
        return values[max(0, math.ceil(fraction * len(values)) - 1)]

    print(
        f"P{node} search latency ms: min={elapsed[0]} "
        f"p50={percentile(elapsed, 0.50)} p95={percentile(elapsed, 0.95)} "
        f"p99={percentile(elapsed, 0.99)} max={elapsed[-1]}; "
        f"response bytes p50={percentile(sizes, 0.50)} "
        f"p95={percentile(sizes, 0.95)}"
    )
if failed:
    raise SystemExit("LDAP load result did not meet expected per-node sample counts with zero errors")
PY
echo "JMeter results: ${result_dir}/results.jtl"
echo "HTML report: ${result_dir}/html/index.html"
