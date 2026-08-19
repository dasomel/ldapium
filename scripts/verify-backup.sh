#!/usr/bin/env bash
# Verify an ldapium backup manifest before restore.
# Fails closed when the manifest is missing, a listed file is missing, or any
# SHA-256 checksum does not match.
set -euo pipefail

usage() {
  echo "Usage: $0 MANIFEST.sha256"
}

manifest="${1:-}"
if [ -z "$manifest" ] || [ "$manifest" = "-h" ] || [ "$manifest" = "--help" ]; then
  usage
  [ "$manifest" = "-h" ] || [ "$manifest" = "--help" ] || exit 2
  exit 0
fi

[ -f "$manifest" ] || { echo "manifest not found: $manifest" >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required" >&2; exit 1; }

base_dir=$(cd "$(dirname "$manifest")" && pwd)
manifest_name=$(basename "$manifest")
file_count=$(grep -cE '^[0-9a-fA-F]{64}  .+$' "$manifest" || true)
[ "$file_count" -gt 0 ] || { echo "manifest contains no SHA-256 entries: $manifest_name" >&2; exit 1; }

# sha256sum -c resolves relative paths from the current directory, so verify
# from the manifest's directory rather than the caller's working directory.
(
  cd "$base_dir"
  sha256sum -c "$manifest_name"
)

echo "backup integrity verified: $manifest_name ($file_count file(s))"
