#!/usr/bin/env bash
# Render-time assertions for ui.basePath (docs/changes/ui-base-path, D1/D8):
# UI_BASE_PATH only when set (normalized), probes under the prefix, NOTES shows
# the path, and an invalid value or a mismatched ingress path fails the render.
#
# Run: ./scripts/test/test-chart-ui-base-path.sh   (needs helm)
# has/fails are reached indirectly (check DESC has ...), which shellcheck cannot follow.
# shellcheck disable=SC2317,SC2329
set -euo pipefail

cd "$(dirname "$0")/../.."

fail=0
ok() { printf 'PASS: %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }

has() { printf '%s\n' "$1" | grep -qF -- "$2"; }
check() {
	local desc=$1
	shift
	if "$@"; then ok "$desc"; else bad "$desc"; fi
}
# fails: the render must exit non-zero and mention the given text.
fails() {
	local want=$1
	shift
	local out
	if out=$("$@" 2>&1); then return 1; fi
	has "$out" "$want"
}

# Throwaway render-only values, never credentials.
base=(--set auth.adminPassword=ci-render-only-not-a-secret --set ui.enabled=true
	--set ui.session.secret=ci-render-only-session-secret-not-a-secret-0123)
render() { helm template t charts/ldapium "${base[@]}" --show-only templates/ui-deployment.yaml "$@"; }
ingress() {
	helm template t charts/ldapium "${base[@]}" --show-only templates/ui-ingress.yaml \
		--set ui.ingress.enabled=true --set 'ui.ingress.hosts[0].host=ldap.example' \
		--set 'ui.ingress.hosts[0].paths[0].pathType=Prefix' "$@"
}

default=$(render)
check "default render has no UI_BASE_PATH" test "$(printf '%s\n' "$default" | grep -c UI_BASE_PATH)" = 0
check "default probes stay at /api/auth/config" test "$(printf '%s\n' "$default" | grep -c 'path: /api/auth/config')" = 2

for raw in '/ldapium' 'ldapium' '/ldapium/'; do
	out=$(render --set "ui.basePath=$raw")
	check "basePath=$raw sets UI_BASE_PATH=/ldapium" has "$out" 'value: "/ldapium"'
	check "basePath=$raw moves both probes" test "$(printf '%s\n' "$out" | grep -c 'path: /ldapium/api/auth/config')" = 2
done

nested=$(render --set ui.basePath=/a/b)
check "nested prefix is kept" has "$nested" 'value: "/a/b"'

root=$(render --set ui.basePath=/)
check "basePath=/ is the root (no env)" test "$(printf '%s\n' "$root" | grep -c UI_BASE_PATH)" = 0

for bad_value in '/a//b' '/a/../b' '/a b' '/a?x' '/%2e' '/.'; do
	check "invalid basePath '$bad_value' fails the render" fails 'ui.basePath must be' render --set "ui.basePath=$bad_value"
done

# NOTES.txt is only printed by install/upgrade; render a copy of the chart in
# which it is an ordinary template (same trick as test-chart-idempotency-render.sh).
copy=$(mktemp -d "${TMPDIR:-/tmp}/base-path-notes.XXXXXX")
trap 'rm -rf "$copy"' EXIT
cp -R charts/ldapium "$copy/ldapium"
{
	printf 'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: notes-check\ndata:\n  notes: |\n'
	sed 's/^/    /' "$copy/ldapium/templates/NOTES.txt"
} >"$copy/ldapium/templates/notes-check.yaml"
rm "$copy/ldapium/templates/NOTES.txt"
notes() { helm template t "$copy/ldapium" "${base[@]}" --show-only templates/notes-check.yaml "$@"; }

check "NOTES shows the path" has "$(notes --set ui.basePath=/ldapium)" 'http://localhost:8080/ldapium/'
check "NOTES shows the SSO redirect path" has "$(notes --set ui.basePath=/ldapium)" '/ldapium/api/sso/callback'
check "NOTES at the root is unchanged" has "$(notes)" 'then open http://localhost:8080/'

good=$(ingress --set ui.basePath=/ldapium --set 'ui.ingress.hosts[0].paths[0].path=/ldapium')
check "ingress path under the prefix renders" has "$good" 'path: /ldapium'
check "ingress path outside the prefix fails the render" fails 'must start with ui.basePath' \
	ingress --set ui.basePath=/ldapium --set 'ui.ingress.hosts[0].paths[0].path=/'
rootok=$(ingress --set 'ui.ingress.hosts[0].paths[0].path=/')
check "root ingress without a prefix is unchanged" has "$rootok" 'path: /'

exit "$fail"
