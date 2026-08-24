#!/usr/bin/env bash
# Bundle the Go module cache for ui/backend's go.sum into a portable tarball,
# so the build *toolchain* itself is reproducible on a disconnected machine —
# a distinct problem from scripts/offline-bundle.sh, which ships the built
# product (images, chart, SBOMs) for an air-gapped install, not the module
# cache a from-source build of this repo needs.
#
#   ./scripts/bundle-go-modules.sh -o go-modules.tar.gz
#
# On the disconnected machine:
#   tar xzf go-modules.tar.gz -C /some/cache/dir
#   cd ui/backend
#   GOPROXY=off GOFLAGS=-mod=readonly GOMODCACHE=/some/cache/dir go mod verify
#   GOPROXY=off GOFLAGS=-mod=readonly GOMODCACHE=/some/cache/dir go build ./...
set -euo pipefail

module_dir="ui/backend"
out="go-modules.tar.gz"

usage() {
  cat <<'EOF'
Usage: bundle-go-modules.sh [-o FILE] [--dir DIR]

  -o, --output   Output tarball path (default: go-modules.tar.gz)
  --dir          Go module directory (default: ui/backend)
  -h, --help     This text.

Downloads exactly what go.sum records (GOFLAGS=-mod=readonly, so a missing
or drifted requirement fails loudly instead of silently updating go.sum),
verifies it, and tars the resulting module cache. The tarball plus
GOPROXY=off is what a disconnected build/verify needs — see the header
comment in this script for the exact commands.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    -o|--output) out="${2:?--output needs a path}"; shift 2 ;;
    --dir) module_dir="${2:?--dir needs a path}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown argument: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

command -v go >/dev/null 2>&1 || { echo "go not found on PATH" >&2; exit 1; }
[ -f "${module_dir}/go.sum" ] || { echo "no go.sum in ${module_dir}" >&2; exit 1; }

scratch_cache=$(mktemp -d "${TMPDIR:-/tmp}/go-modules-bundle-XXXXXX")
cleanup() {
  # go mod download marks module cache contents (and the downloaded
  # toolchain, if go.mod needs one newer than what's installed) read-only —
  # a plain rm -rf fails per-file on that and, as an EXIT trap, would
  # overwrite this script's real exit status with the cleanup failure's.
  chmod -R u+w "$scratch_cache" 2>/dev/null || true
  rm -rf "$scratch_cache" 2>/dev/null || true
}
trap cleanup EXIT

echo "downloading modules for ${module_dir}/go.sum into a scratch cache..." >&2
(
  cd "$module_dir"
  # With no package arguments, on a go.mod at 1.17+ (this one is), `go mod
  # download` fetches every module needed to build and test the packages in
  # the main module (`go help mod download`) — the same set go.sum records.
  # The one thing that would NOT be covered is a `tool` directive (Go
  # 1.24+), which needs `go mod download tool` separately; this module has
  # none today (no tools.go pattern either), but a future one would need
  # this script updated to match, since it would keep bundling successfully
  # while silently leaving that gap.
  #
  # Deliberately not a `go build ./...` dry-run here: this module's web/
  # package go:embeds the built frontend SPA (web/embed.go), which does not
  # exist until `npm run build` has run in ui/frontend — unrelated to
  # whether the Go module set is complete, and would fail this script on a
  # perfectly good bundle whenever the frontend hasn't been built yet
  # (confirmed by testing: removing web/dist and re-running `go build ./...`
  # fails with "pattern all:dist: no matching files found", nothing to do
  # with modules).
  GOFLAGS=-mod=readonly GOMODCACHE="$scratch_cache" go mod download
  echo "verifying against go.sum before bundling..." >&2
  GOFLAGS=-mod=readonly GOMODCACHE="$scratch_cache" go mod verify
)

echo "bundling into ${out}..." >&2
tar czf "$out" -C "$scratch_cache" .

echo >&2
echo "PASS: $(du -h "$out" | cut -f1) bundled at ${out}." >&2
echo "Offline use (no network required once extracted):" >&2
echo "  tar xzf ${out} -C /some/cache/dir" >&2
echo "  cd ${module_dir} && GOPROXY=off GOFLAGS=-mod=readonly GOMODCACHE=/some/cache/dir go mod verify" >&2
