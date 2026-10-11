#!/usr/bin/env bash
# ARTIFACT check for the drill-only build tag (machine-write-scope T-022): builds the default server and the
# tagged server, then inspects the binaries themselves, not the sources. The default binary must show no drill
# build setting and no drill marker; the tagged binary must show both, so the check cannot pass vacuously.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
tag=machinewritedrill
marker='DRILL BUILD'
work=$(mktemp -d)
made_dist=0
# shellcheck disable=SC2317,SC2329 # invoked via the EXIT trap below (code differs by shellcheck version)
cleanup() {
  if [ "$made_dist" = 1 ]; then
    rm -f "$root/ui/backend/web/dist/index.html"
    rmdir "$root/ui/backend/web/dist" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT
cd "$root/ui/backend"
# go:embed needs a dist directory; a CI job that built the frontend already has one.
if [ ! -d web/dist ] || [ -z "$(ls -A web/dist 2>/dev/null)" ]; then
  mkdir -p web/dist && echo placeholder > web/dist/index.html && made_dist=1
fi
go build -o "$work/default-server" ./cmd/server
go build -tags "$tag" -o "$work/drill-server" ./cmd/server

fail=0
if go version -m "$work/default-server" | grep -E 'build[[:space:]]+-tags' | grep -q "$tag"; then
  echo "FAIL: the default server records the drill build tag"; fail=1
else
  echo "PASS: default server: no $tag in its build settings"
fi
if grep -aq "$marker" "$work/default-server"; then
  echo "FAIL: the default server contains the '$marker' marker"; fail=1
else
  echo "PASS: default server: no '$marker' marker"
fi
if go version -m "$work/drill-server" | grep -E 'build[[:space:]]+-tags' | grep -q "$tag"; then
  echo "PASS: tagged server records the tag (the check is not vacuous)"
else
  echo "FAIL: the tagged server does not record the tag"; fail=1
fi
if grep -aq "$marker" "$work/drill-server"; then
  echo "PASS: tagged server contains the '$marker' marker"
else
  echo "FAIL: the tagged server lacks the '$marker' marker"; fail=1
fi
exit "$fail"
