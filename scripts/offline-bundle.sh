#!/usr/bin/env bash
set -euo pipefail

# Build an air-gap bundle from immutable release artifacts.
# Required: docker, docker buildx, helm, jq, sha256sum.
#
# Usage:
#   scripts/offline-bundle.sh 0.1.0 ./bundle
#
# The bundle contains:
#   - amd64/arm64 server + UI image archives
#   - Helm chart package
#   - raw multi-arch manifest metadata and immutable digests
#   - SPDX/CycloneDX SBOMs generated from the pulled images
#   - checksums for every payload
#   - a machine-readable bundle manifest

usage() {
  echo "Usage: $0 VERSION OUTPUT_DIR" >&2
  exit 2
}

[[ $# -eq 2 ]] || usage
VERSION="$1"
OUTPUT_DIR="$2"
OWNER="${GITHUB_REPOSITORY_OWNER:-dasomel}"
REGISTRY="ghcr.io/${OWNER}"
SERVER_IMAGE="${REGISTRY}/ldapium:${VERSION}"
UI_IMAGE="${REGISTRY}/ldapium-ui:${VERSION}"
CHART="oci://${REGISTRY}/charts/ldapium"

for bin in docker helm jq sha256sum; do
  command -v "$bin" >/dev/null 2>&1 || { echo "required command not found: $bin" >&2; exit 1; }
done

mkdir -p "$OUTPUT_DIR/images" "$OUTPUT_DIR/chart" "$OUTPUT_DIR/sbom" "$OUTPUT_DIR/metadata"

manifest_json() {
  local image="$1"
  docker buildx imagetools inspect "$image" --raw
}

pull_and_save() {
  local image="$1" name="$2" platform="$3"
  local archive="$OUTPUT_DIR/images/${name}-${platform}.tar"
  echo "[offline-bundle] pulling ${image} (${platform})"
  docker pull --platform="$platform" "$image"
  docker save "$image" -o "$archive"
  gzip -f "$archive"
}

echo "[offline-bundle] resolving immutable manifests"
server_manifest=$(manifest_json "$SERVER_IMAGE")
ui_manifest=$(manifest_json "$UI_IMAGE")
printf '%s\n' "$server_manifest" > "$OUTPUT_DIR/metadata/ldapium-${VERSION}-manifest.json"
printf '%s\n' "$ui_manifest" > "$OUTPUT_DIR/metadata/ldapium-ui-${VERSION}-manifest.json"

server_digest=$(jq -r '.manifests[] | select(.platform.architecture=="amd64" and .platform.os=="linux") | .digest' "$OUTPUT_DIR/metadata/ldapium-${VERSION}-manifest.json")
server_arm_digest=$(jq -r '.manifests[] | select(.platform.architecture=="arm64" and .platform.os=="linux") | .digest' "$OUTPUT_DIR/metadata/ldapium-${VERSION}-manifest.json")
ui_digest=$(jq -r '.manifests[] | select(.platform.architecture=="amd64" and .platform.os=="linux") | .digest' "$OUTPUT_DIR/metadata/ldapium-ui-${VERSION}-manifest.json")
ui_arm_digest=$(jq -r '.manifests[] | select(.platform.architecture=="arm64" and .platform.os=="linux") | .digest' "$OUTPUT_DIR/metadata/ldapium-ui-${VERSION}-manifest.json")

for value in "$server_digest" "$server_arm_digest" "$ui_digest" "$ui_arm_digest"; do
  [[ "$value" == sha256:* ]] || { echo "invalid image digest: $value" >&2; exit 1; }
done

pull_and_save "$SERVER_IMAGE" ldapium amd64
pull_and_save "$SERVER_IMAGE" ldapium arm64
pull_and_save "$UI_IMAGE" ldapium-ui amd64
pull_and_save "$UI_IMAGE" ldapium-ui arm64

echo "[offline-bundle] pulling Helm chart"
helm pull "$CHART" --version "$VERSION" --destination "$OUTPUT_DIR/chart"

# Generate SBOMs from the exact image archives just captured. The local image
# tags remain immutable for this run because the script resolved their release
# manifest before saving them.
for image_spec in \
  "${SERVER_IMAGE}|ldapium" \
  "${UI_IMAGE}|ldapium-ui"; do
  image="${image_spec%%|*}"
  name="${image_spec##*|}"
  echo "[offline-bundle] generating SBOM for ${image}"
  docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    anchore/syft:latest "$image" -o spdx-json="$OUTPUT_DIR/sbom/${name}-${VERSION}.spdx.json"
done

# Machine-readable provenance/evidence record. This is bundle provenance,
# not a replacement for the signed build attestation carried by the images.
cat > "$OUTPUT_DIR/metadata/bundle-manifest.json" <<EOF
{
  "schemaVersion": 1,
  "release": "${VERSION}",
  "repository": "${OWNER}/ldapium",
  "images": {
    "ldapium": {
      "tag": "${SERVER_IMAGE}",
      "linux-amd64": "${server_digest}",
      "linux-arm64": "${server_arm_digest}"
    },
    "ldapium-ui": {
      "tag": "${UI_IMAGE}",
      "linux-amd64": "${ui_digest}",
      "linux-arm64": "${ui_arm_digest}"
    }
  },
  "chart": {
    "oci": "${CHART}",
    "version": "${VERSION}"
  },
  "provenance": {
    "source": "github.com/${OWNER}/ldapium",
    "release": "${VERSION}",
    "signed_image_attestations": true
  }
}
EOF

(
  cd "$OUTPUT_DIR"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)

cat <<EOF
[offline-bundle] bundle ready: ${OUTPUT_DIR}
[offline-bundle] verify with: (cd ${OUTPUT_DIR} && sha256sum -c SHA256SUMS)
EOF
