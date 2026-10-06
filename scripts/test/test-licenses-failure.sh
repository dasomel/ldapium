#!/usr/bin/env bash
# scripts/licenses.sh must say why when the go-licenses step fails, and must not
# leave its temporary install directory behind. The install is forced to fail by
# pointing Go at an empty module cache with the proxy off.
#
# Run: ./scripts/test/test-licenses-failure.sh
set -euo pipefail

cd "$(dirname "$0")/../.."

if command -v go-licenses >/dev/null 2>&1; then
	echo "SKIP: go-licenses is on PATH, so licenses.sh never installs it"
	exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/tmp" "$work/modcache"

fail=0
ok() { printf 'PASS: %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }

rc=0
out=$(TMPDIR="$work/tmp" GOPROXY=off GOMODCACHE="$work/modcache" GOFLAGS=-modcacherw ./scripts/licenses.sh --check 2>&1) || rc=$?

if [ "$rc" -ne 0 ]; then ok "a failing go-licenses install fails the script (exit $rc)"; else bad "the script succeeded although the install cannot work"; fi
if printf '%s' "$out" | grep -q 'could not install go-licenses'; then ok "the install failure is explained"; else bad "no install failure message: $out"; fi
if printf '%s' "$out" | grep -q 'go-licenses csv failed'; then ok "the csv step reports its failure and shows the tool's stderr"; else bad "no csv failure message: $out"; fi
if [ -z "$(ls -A "$work/tmp")" ]; then ok "no temporary directory or file is left behind"; else bad "left behind: $(ls -A "$work/tmp")"; fi

exit "$fail"
