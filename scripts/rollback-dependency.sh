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

usage() {
  cat <<'EOF'
Usage: rollback-dependency.sh --to REF [--dir DIR]

  --to     Git ref (tag, branch, or commit) whose go.mod/go.sum are known
           good — typically the commit before the compromised dependency's
           go.sum entry was introduced.
  --dir    Go module directory (default: ui/backend — the only Go module
           this repo has).
  -h, --help  This text.

Checks out go.mod and go.sum from REF, clears the local module cache so a
already-poisoned entry cannot survive in it, and re-downloads + re-verifies
against the restored go.sum. Leaves the restored files as an uncommitted
change in the working tree for review — this script does not commit or push;
that decision belongs to whoever is doing the rollback, with the PASS output
below as their evidence it actually verified clean.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --to) to_ref="${2:?--to needs a git ref}"; shift 2 ;;
    --dir) module_dir="${2:?--dir needs a path}"; shift 2 ;;
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

repo_root=$(git rev-parse --show-toplevel)

echo "restoring ${module_dir}/go.mod and go.sum from ${to_ref}..." >&2
git -C "$repo_root" checkout "$to_ref" -- "${module_dir}/go.mod" "${module_dir}/go.sum"

echo "clearing the local module cache so nothing compromised survives in it..." >&2
go clean -modcache

echo "re-downloading and verifying against the restored go.sum..." >&2
(
  cd "${repo_root}/${module_dir}"
  GOFLAGS=-mod=readonly go mod download
  GOFLAGS=-mod=readonly go mod verify
)

echo >&2
echo "PASS: ${module_dir}/go.mod and go.sum restored from ${to_ref} and verified clean." >&2
echo "Review the diff below, then commit and open a PR yourself — nothing here does either:" >&2
git -C "$repo_root" status --short -- "${module_dir}/go.mod" "${module_dir}/go.sum" >&2
