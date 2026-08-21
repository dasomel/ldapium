#!/usr/bin/env bash
set -euo pipefail

# Verify an air-gap bundle and load it into a cluster, without reaching the
# network for anything.
#
# Usage:
#   scripts/offline-install.sh --bundle DIR --release NAME --namespace NS [options]
#
# Options:
#   --kind-cluster NAME   also load the image archives into that kind cluster
#   --set KEY=VALUE       passed through to helm (repeatable)
#   --upgrade             helm upgrade an existing release instead of installing
#   --verify-only         verify the bundle and stop
#
# The verification is the point, not a formality: a bundle that has lost a file
# since it was assembled, or whose contents no longer match SHA256SUMS, is
# rejected here rather than half-installed and discovered later.

usage() {
  sed -n '4,18p' "$0" >&2
  exit 2
}

bundle=""
release=""
namespace=""
kind_cluster=""
verify_only=0
upgrade=0
helm_sets=()

while [ $# -gt 0 ]; do
  case "$1" in
    --bundle) bundle="${2:?--bundle needs a directory}"; shift 2;;
    --release) release="${2:?--release needs a name}"; shift 2;;
    --namespace) namespace="${2:?--namespace needs a name}"; shift 2;;
    --kind-cluster) kind_cluster="${2:?--kind-cluster needs a name}"; shift 2;;
    --set) helm_sets+=("--set" "${2:?--set needs KEY=VALUE}"); shift 2;;
    --upgrade) upgrade=1; shift;;
    --verify-only) verify_only=1; shift;;
    -h|--help) usage;;
    *) echo "unknown argument: $1" >&2; usage;;
  esac
done

if [ -z "$bundle" ] || [ ! -d "$bundle" ]; then
  echo "bundle directory is required" >&2
  exit 2
fi
bundle=$(cd "$bundle" && pwd)

command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 1; }

manifest="$bundle/metadata/bundle-manifest.json"
[ -f "$bundle/SHA256SUMS" ] || { echo "bundle is missing SHA256SUMS: $bundle" >&2; exit 1; }
[ -f "$manifest" ] || { echo "bundle is missing metadata/bundle-manifest.json" >&2; exit 1; }

echo "[offline-install] verifying checksums"
(
  cd "$bundle"
  # `sha256sum -c` on an empty or thinned list succeeds: it reports zero
  # mismatches because it was given nothing to check. Emptying SHA256SUMS, or
  # deleting the one line covering a file you just swapped, would otherwise be
  # a clean way past this. So the list has to account for every file in the
  # bundle before any of it is checked.
  listed=$(grep -cE '^[0-9a-fA-F]{64} ' SHA256SUMS || true)
  if [ "$listed" -eq 0 ]; then
    echo "SHA256SUMS lists no files" >&2
    exit 1
  fi
  present=$(find . -type f ! -name SHA256SUMS | wc -l | tr -d ' ')
  if [ "$listed" -ne "$present" ]; then
    echo "SHA256SUMS covers ${listed} file(s) but the bundle holds ${present}" >&2
    awk '{ print $2 }' SHA256SUMS | sort > /tmp/.offline-listed.$$
    find . -type f ! -name SHA256SUMS | sort > /tmp/.offline-present.$$
    diff /tmp/.offline-listed.$$ /tmp/.offline-present.$$ >&2 || true
    rm -f /tmp/.offline-listed.$$ /tmp/.offline-present.$$
    exit 1
  fi
  sha256sum -c SHA256SUMS
)

echo "[offline-install] verifying the bundle is complete"
chart=$(find "$bundle/chart" -maxdepth 1 -name '*.tgz' -type f | head -1)
[ -n "$chart" ] || { echo "bundle contains no packaged chart" >&2; exit 1; }
images=$(find "$bundle/images" -maxdepth 1 -name '*.tar.gz' -type f | sort)
[ -n "$images" ] || { echo "bundle contains no image archives" >&2; exit 1; }
for key in '.release' '.images.ldapium' '.images["ldapium-ui"]' '.chart.version'; do
  jq -e "$key" "$manifest" >/dev/null || { echo "bundle manifest is missing $key" >&2; exit 1; }
done
find "$bundle/sbom" -maxdepth 1 -name '*.spdx.json' -type f | grep -q . \
  || { echo "bundle contains no SBOM" >&2; exit 1; }

version=$(jq -r '.release' "$manifest")
source=$(jq -r '.source // "release"' "$manifest")
echo "[offline-install] bundle ok: release=${version} source=${source}"
echo "[offline-install]   chart:  $(basename "$chart")"
while IFS= read -r archive; do
  echo "[offline-install]   image:  $(basename "$archive")"
done <<EOF
$images
EOF

[ "$verify_only" -eq 0 ] || exit 0

if [ -z "$release" ] || [ -z "$namespace" ]; then
  echo "--release and --namespace are required unless --verify-only" >&2
  exit 2
fi
command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 1; }
command -v helm >/dev/null 2>&1 || { echo "helm is required" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

while IFS= read -r archive; do
  plain="${work}/$(basename "${archive%.gz}")"
  gzip -dc "$archive" > "$plain"
  echo "[offline-install] loading $(basename "$archive") into the local daemon"
  docker load -i "$plain"
  if [ -n "$kind_cluster" ]; then
    command -v kind >/dev/null 2>&1 || { echo "kind is required for --kind-cluster" >&2; exit 1; }
    echo "[offline-install] loading $(basename "$archive") into kind/${kind_cluster}"
    kind load image-archive "$plain" --name "$kind_cluster"
  fi
  rm -f "$plain"
done <<EOF
$images
EOF

# imagePullPolicy=Never is not a preference here. It is what turns "we did not
# happen to need the network" into "the network was never an option": if an
# archive failed to load, the pod fails rather than silently pulling.
action=install
[ "$upgrade" -eq 0 ] || action=upgrade
echo "[offline-install] helm ${action} ${release} from $(basename "$chart")"
helm "$action" "$release" "$chart" \
  --namespace "$namespace" \
  --create-namespace \
  --set image.pullPolicy=Never \
  --set ui.image.pullPolicy=Never \
  "${helm_sets[@]+"${helm_sets[@]}"}" \
  --timeout 10m

echo "[offline-install] done"
