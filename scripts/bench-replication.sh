#!/usr/bin/env bash
# Measure write throughput and multi-provider replication convergence on a
# real replicated release — installs the chart itself (replicaCount=3) on
# whatever Kubernetes context is current, so this measures the actual
# syncrepl topology (charts/ldapium/README.md, "HA / replication"), not a
# stand-in for it.
#
# contextCSN comparison across all three providers is the same check
# .github/workflows/replication-chaos-e2e.yml already uses to prove
# convergence after a partition — reused here rather than reinvented, so a
# "converged" verdict means the same thing in both places.
#
#   ./scripts/bench-replication.sh --image ldapium:bench --namespace bench --count 500
set -euo pipefail

image=""
ns="ldapium-bench-repl"
count=1000
base="dc=example,dc=org"
timeout_seconds=300
out_json=""
keep=0

usage() {
  cat <<'EOF'
Usage: bench-replication.sh --image IMAGE [--namespace NS] [--count N]
                             [--timeout-seconds N] [--json FILE] [--keep]

  --image             ldapium image to benchmark
  --namespace         Kubernetes namespace to install into (default
                       ldapium-bench-repl) — created if it does not exist
  --count             number of write bursts against provider 0 (default 1000)
  --timeout-seconds   how long to wait for convergence before failing
                       (default 300)
  --json              write the evidence record to this file too
  --keep              leave the Helm release and namespace installed
                       afterward instead of uninstalling
  -h, --help          this text

Requires a working kubectl context with a Helm 3 client and enough
cluster capacity for a 3-replica StatefulSet. kind works; so does any
real cluster.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --image) image="${2:?}"; shift 2 ;;
    --namespace) ns="${2:?}"; shift 2 ;;
    --count) count="${2:?}"; shift 2 ;;
    --timeout-seconds) timeout_seconds="${2:?}"; shift 2 ;;
    --json) out_json="${2:?}"; shift 2 ;;
    --keep) keep=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown argument: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

[ -n "$image" ] || { echo "--image is required" >&2; exit 2; }
command -v kubectl >/dev/null 2>&1 || { echo "kubectl not found on PATH" >&2; exit 1; }
command -v helm >/dev/null 2>&1 || { echo "helm not found on PATH" >&2; exit 1; }
# BSD date on macOS before Sequoia (15, 2024) doesn't support %N and emits it
# literally, silently turning every sub-second timing below into 0 rather
# than failing loudly.
[ "$(date +%N)" != "N" ] || { echo "date +%N unsupported — need macOS 15+ or GNU coreutils date" >&2; exit 1; }

release="bench"
password="bench-not-a-real-secret-$$"

ldif_file=""
cleanup() {
  rm -f "$ldif_file"
  [ "$keep" -eq 1 ] && return 0
  helm uninstall "$release" -n "$ns" --timeout 60s >/dev/null 2>&1 || true
  kubectl delete namespace "$ns" --ignore-not-found --timeout=60s >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Split only on a colon in the last path segment, not the first colon
# anywhere: a registry with a port (registry.example.com:5000/ldapium:bench)
# has a colon that is not the tag separator, and %%:*/##*: (first-colon)
# would misparse it as repository="registry.example.com".
image_repo="$image"
image_tag="latest"
if [[ "${image##*/}" == *:* ]]; then
  image_tag="${image##*:}"
  image_repo="${image%:*}"
fi

echo "installing a 3-replica release in namespace ${ns}..." >&2
# helm --set splits on unescaped commas between key=value pairs, so a
# multi-RDN DN like dc=example,dc=org would otherwise be silently truncated
# to dc=example (verified: --set ldap.rootDN=dc=example,dc=org renders
# LDAP_ROOT_DN=dc=example, and slapd then refuses to boot because the
# admin/base entries in the bootstrap LDIFs still say dc=example,dc=org).
helm upgrade --install "$release" "$(dirname "$0")/../charts/ldapium" \
  --namespace "$ns" --create-namespace \
  --set image.repository="$image_repo" --set image.tag="$image_tag" \
  --set image.pullPolicy=Never \
  --set ui.enabled=false \
  --set auth.adminPassword="$password" \
  --set ldap.rootDN="${base//,/\\,}" \
  --set replicaCount=3 \
  --set replication.enabled=true \
  --wait --timeout 5m >/dev/null

fullname="${release}-ldapium"

echo "generating and writing ${count} entries against ${fullname}-0..." >&2
ldif_file=$(mktemp "${TMPDIR:-/tmp}/ldapium-bench-repl-XXXXXX.ldif")
python3 "$(dirname "$0")/bench-generate-ldif.py" --count "$count" --base "$base" > "$ldif_file"

write_start=$(date +%s.%N)
kubectl -n "$ns" exec -i "${fullname}-0" -c openldap -- \
  ldapadd -x -D "cn=admin,${base}" -w "$password" < "$ldif_file" >/dev/null
write_end=$(date +%s.%N)
write_seconds=$(awk -v a="$write_start" -v b="$write_end" 'BEGIN{printf "%.3f", b-a}')

echo "write burst took ${write_seconds}s — polling convergence across all 3 providers..." >&2
converge_start=$(date +%s)
converged=0
while [ $(( $(date +%s) - converge_start )) -lt "$timeout_seconds" ]; do
  ok=1
  ref=""
  for ordinal in 0 1 2; do
    csn=$(kubectl -n "$ns" exec "${fullname}-${ordinal}" -c openldap -- \
      ldapsearch -x -LLL -H "ldapi://%2Fvar%2Flib%2Fopenldap%2Frun%2Fldapi" \
        -D "cn=admin,cn=config" -w "$password" \
        -b "$base" -s base contextCSN 2>/dev/null | grep '^contextCSN:' | sort)
    if [ "$ordinal" = 0 ]; then
      ref="$csn"
    elif [ "$csn" != "$ref" ]; then
      ok=0
    fi
  done
  if [ "$ok" = 1 ] && [ -n "$ref" ]; then
    converged=1
    break
  fi
  sleep 2
done
converge_seconds=$(( $(date +%s) - converge_start ))

if [ "$converged" = 1 ]; then
  echo "PASS: all 3 providers converged on the same contextCSN set in ${converge_seconds}s" >&2
else
  echo "FAIL: providers had not converged after ${timeout_seconds}s" >&2
fi

record=$(cat <<JSON
{"benchmark":"replication","image":"${image}","entryCount":${count},"writeSeconds":${write_seconds},"entriesPerSecond":$(awk -v c="$count" -v s="$write_seconds" 'BEGIN{printf "%.2f", c/s}'),"convergenceSeconds":${converge_seconds},"converged":$([ "$converged" = 1 ] && echo true || echo false)}
JSON
)
echo "$record"
[ -z "$out_json" ] || echo "$record" > "$out_json"

[ "$converged" = 1 ]
