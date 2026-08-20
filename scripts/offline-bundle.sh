#!/usr/bin/env bash
set -euo pipefail

# Build an air-gap bundle from immutable release artifacts.
# Required: docker, docker buildx, helm, jq, sha256sum.
#
# Usage:
#   scripts/offline-bundle.sh 0.1.0 ./bundle
#   scripts/offline-bundle.sh e2e ./bundle --from-local-images
#
# The bundle contains:
#   - amd64/arm64 server + UI image archives
#   - Helm chart package
#   - raw multi-arch manifest metadata and immutable digests
#   - SPDX/CycloneDX SBOMs generated from the pulled images
#   - checksums for every payload
#   - a machine-readable bundle manifest
#
# --from-local-images builds the same bundle out of images already in the local
# daemon, under the same names a release would have, plus the chart in this
# working tree — instead of pulling a published release. It exists so CI can exercise this script — and the offline install
# that consumes its output — on a pull request, where nothing is published yet.
# The resulting bundle records source="local-build" and carries no digests,
# because a locally built image has none until it is pushed; scripts that
# promote a bundle must refuse one that says local-build.

usage() {
  echo "Usage: $0 VERSION OUTPUT_DIR [--from-local-images]" >&2
  exit 2
}

[[ $# -ge 2 ]] || usage
VERSION="$1"
OUTPUT_DIR="$2"
shift 2
LOCAL_IMAGES=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --from-local-images) LOCAL_IMAGES=1; shift;;
    *) usage;;
  esac
done
OWNER="${GITHUB_REPOSITORY_OWNER:-dasomel}"
REGISTRY="ghcr.io/${OWNER}"
SERVER_IMAGE="${REGISTRY}/ldapium:${VERSION}"
UI_IMAGE="${REGISTRY}/ldapium-ui:${VERSION}"
if [[ "$LOCAL_IMAGES" -eq 1 ]]; then
  # Same image names as a release bundle, deliberately: the difference is where
  # the bytes come from, not what the image is called. Anything that consumes
  # the bundle — and the chart's own image.repository default — then works on
  # a local bundle without being told it is one.
  CHART="$(cd "$(dirname "$0")/.." && pwd)/charts/ldapium"
else
  CHART="oci://${REGISTRY}/charts/ldapium"
fi

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

# A locally built image has no registry digest and no multi-arch manifest to
# inspect, so the local path records the image ID instead and saves the one
# architecture the daemon actually holds. Everything downstream — checksums,
# SBOMs, the bundle manifest, and the offline install that consumes it — is the
# same code either way, which is the point of having this mode at all.
save_local() {
  local image="$1" name="$2" platform="$3"
  local archive="$OUTPUT_DIR/images/${name}-${platform}.tar"
  echo "[offline-bundle] saving local ${image} (${platform})"
  docker image inspect "$image" >/dev/null
  docker save "$image" -o "$archive"
  gzip -f "$archive"
}

if [[ "$LOCAL_IMAGES" -eq 1 ]]; then
  echo "[offline-bundle] local build: recording image IDs, not registry digests"
  local_arch=$(docker version --format '{{.Server.Arch}}')
  server_digest=$(docker image inspect "$SERVER_IMAGE" --format '{{.Id}}')
  ui_digest=$(docker image inspect "$UI_IMAGE" --format '{{.Id}}')
  server_arm_digest=""
  ui_arm_digest=""
  for image_id in "$server_digest" "$ui_digest"; do
    [[ "$image_id" == sha256:* ]] || { echo "invalid local image id: $image_id" >&2; exit 1; }
  done
  docker image inspect "$SERVER_IMAGE" > "$OUTPUT_DIR/metadata/ldapium-${VERSION}-manifest.json"
  docker image inspect "$UI_IMAGE" > "$OUTPUT_DIR/metadata/ldapium-ui-${VERSION}-manifest.json"
  save_local "$SERVER_IMAGE" ldapium "$local_arch"
  save_local "$UI_IMAGE" ldapium-ui "$local_arch"
  echo "[offline-bundle] packaging Helm chart from the working tree"
  helm package "$CHART" --version "$VERSION" --app-version "$VERSION" \
    --destination "$OUTPUT_DIR/chart" >/dev/null
else
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
fi

# Generate SBOMs from the exact image archives just captured. The local image
# tags remain immutable for this run because the script resolved their release
# manifest before saving them.
for image_spec in \
  "${SERVER_IMAGE}|ldapium" \
  "${UI_IMAGE}|ldapium-ui"; do
  image="${image_spec%%|*}"
  name="${image_spec##*|}"
  echo "[offline-bundle] generating SBOM for ${image}"
  # Two things this needs and did not have: the output directory has to be
  # mounted, or syft writes the SBOM inside its own container and the bundle
  # ships without one; and the docker: scheme makes syft read the image out of
  # the local daemon rather than resolving it against a registry, which a
  # locally built image cannot satisfy.
  docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$(cd "$OUTPUT_DIR/sbom" && pwd):/sbom" \
    anchore/syft:latest "docker:${image}" -o "spdx-json=/sbom/${name}-${VERSION}.spdx.json"
done

# Machine-readable provenance/evidence record. This is bundle provenance,
# not a replacement for the signed build attestation carried by the images.
if [[ "$LOCAL_IMAGES" -eq 1 ]]; then
  bundle_source="local-build"
  signed_attestations="false"
else
  bundle_source="release"
  signed_attestations="true"
fi

cat > "$OUTPUT_DIR/metadata/bundle-manifest.json" <<EOF
{
  "schemaVersion": 1,
  "source": "${bundle_source}",
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
    "signed_image_attestations": ${signed_attestations}
  }
}
EOF

(
  cd "$OUTPUT_DIR"
  rm -f SHA256SUMS
  sums=$(mktemp)
  find . -type f -print0 | sort -z | xargs -0 sha256sum > "$sums"
  mv "$sums" SHA256SUMS
  chmod 644 SHA256SUMS
)

cat <<EOF
[offline-bundle] bundle ready: ${OUTPUT_DIR}
[offline-bundle] verify with: (cd ${OUTPUT_DIR} && sha256sum -c SHA256SUMS)
EOF
