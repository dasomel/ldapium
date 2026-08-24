#!/usr/bin/env bash
# Deterministically roll go.mod/go.sum back to a known-good git ref when a
# dependency turns out to be compromised — docs/dependency-policy.md ("When a
# dependency turns out to be compromised") already describes these exact
# steps in prose; this makes them runnable and testable instead of something
# copy-pasted by hand under pressure, when a typo is most likely.
#
#   ./scripts/rollback-dependency.sh --to v1.2.3
#   ./scripts/rollback-dependency.sh --to abc1234def
set -euo pipefail

to_ref=""
module_dir="ui/backend"
purge_shared_cache=0

usage() {
  cat <<'EOF'
Usage: rollback-dependency.sh --to REF [--dir DIR] [--purge-shared-cache]

  --to     Git ref (tag, branch, or commit) whose go.mod/go.sum are known
           good — typically the commit before the compromised dependency's
           go.sum entry was introduced.
  --dir    Go module directory (default: ui/backend — the only Go module
           this repo has).
  --purge-shared-cache   Also run `go clean -modcache`, wiping this
           machine's entire shared module cache — every Go project's cached
           modules, not just this one's. Off by default: re-verification
           below already proves the restored go.sum downloads and verifies
           clean without needing to touch the shared cache at all. Use this
           only if you specifically need the compromised module gone from
           disk everywhere on this machine, not just out of this repo.
  -h, --help  This text.

Checks out go.mod and go.sum from REF into a backup pair first
(go.mod.pre-rollback / go.sum.pre-rollback, so a failed verification below
does not strand you with unknown files and no way back), then re-downloads
and re-verifies the restored go.sum against a scratch module cache — proving
it is internally consistent without needing to touch your real GOMODCACHE.
Leaves the restored files as an uncommitted change in the working tree for
review; this script does not commit or push, and does not delete the backup
pair on success (remove them yourself once you've reviewed the diff).
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --to) to_ref="${2:?--to needs a git ref}"; shift 2 ;;
    --dir) module_dir="${2:?--dir needs a path}"; shift 2 ;;
    --purge-shared-cache) purge_shared_cache=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown argument: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

[ -n "$to_ref" ] || { echo "--to is required" >&2; usage >&2; exit 2; }
command -v git >/dev/null 2>&1 || { echo "git not found on PATH" >&2; exit 1; }
command -v go >/dev/null 2>&1 || { echo "go not found on PATH" >&2; exit 1; }

git rev-parse --is-inside-work-tree >/dev/null 2>&1 \
  || { echo "not inside a git repository" >&2; exit 1; }
git rev-parse --verify "${to_ref}^{commit}" >/dev/null 2>&1 \
  || { echo "unknown git ref: ${to_ref}" >&2; exit 1; }
[ -d "$module_dir" ] || { echo "no such directory: ${module_dir}" >&2; exit 1; }
git cat-file -e "${to_ref}:${module_dir}/go.mod" 2>/dev/null \
  || { echo "${to_ref} has no ${module_dir}/go.mod — that ref predates this module, or --dir is wrong" >&2; exit 1; }

repo_root=$(git rev-parse --show-toplevel)
mod_file="${repo_root}/${module_dir}/go.mod"
sum_file="${repo_root}/${module_dir}/go.sum"

echo "backing up the current go.mod/go.sum before touching them..." >&2
cp "$mod_file" "${mod_file}.pre-rollback"
cp "$sum_file" "${sum_file}.pre-rollback"

echo "restoring ${module_dir}/go.mod and go.sum from ${to_ref}..." >&2
git -C "$repo_root" checkout "$to_ref" -- "${module_dir}/go.mod" "${module_dir}/go.sum"

if [ "$purge_shared_cache" -eq 1 ]; then
  echo "--purge-shared-cache set: clearing this machine's ENTIRE Go module cache..." >&2
  go clean -modcache
fi

# A scratch cache, not $GOMODCACHE: proving the restored go.sum verifies
# clean does not require — and must not risk — destroying every other Go
# project's cached modules on this machine to do it.
scratch_cache=$(mktemp -d "${TMPDIR:-/tmp}/rollback-dependency-XXXXXX")
cleanup() {
  chmod -R u+w "$scratch_cache" 2>/dev/null || true
  rm -rf "$scratch_cache" 2>/dev/null || true
}
trap cleanup EXIT

echo "re-downloading and verifying against the restored go.sum..." >&2
(
  cd "${repo_root}/${module_dir}"
  GOFLAGS=-mod=readonly GOMODCACHE="$scratch_cache" go mod download
  GOFLAGS=-mod=readonly GOMODCACHE="$scratch_cache" go mod verify
)

echo >&2
echo "PASS: ${module_dir}/go.mod and go.sum restored from ${to_ref} and verified clean." >&2
echo "Pre-rollback files kept at ${mod_file}.pre-rollback / ${sum_file}.pre-rollback — remove them once you've reviewed the diff below." >&2
echo "Review the diff, then commit and open a PR yourself — nothing here does either:" >&2
git -C "$repo_root" status --short -- "${module_dir}/go.mod" "${module_dir}/go.sum" >&2
