#!/usr/bin/env bash
# Render-time assertions for the UI CORS value of the Helm chart
# (docs/changes/api-error-envelope, D218-12): no CORS_ALLOWED_ORIGINS unless
# ui.cors.allowedOrigins is set, and the list reaches the container verbatim.
#
# Run: ./scripts/test/test-chart-ui-cors.sh   (needs helm)
# has is reached indirectly (check DESC has ...), which shellcheck cannot follow.
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

# Throwaway render-only values, never credentials.
base=(--set auth.adminPassword=ci-render-only-not-a-secret --set ui.enabled=true
	--set ui.session.secret=ci-render-only-session-secret-not-a-secret-0123)
render() { helm template t charts/ldapium "${base[@]}" --show-only templates/ui-deployment.yaml "$@"; }

default=$(render)
check "default render has no CORS_ALLOWED_ORIGINS" test "$(printf '%s\n' "$default" | grep -c CORS_ALLOWED_ORIGINS)" = 0

one=$(render --set 'ui.cors.allowedOrigins[0]=https://app.example')
check "one origin is set verbatim" has "$one" 'value: "https://app.example"'
check "one origin sets CORS_ALLOWED_ORIGINS" has "$one" 'name: CORS_ALLOWED_ORIGINS'

two=$(render --set 'ui.cors.allowedOrigins[0]=https://a.example' --set 'ui.cors.allowedOrigins[1]=https://b.example:8443')
check "two origins are comma-joined in order" has "$two" 'value: "https://a.example,https://b.example:8443"'

empty=$(render --set-json 'ui.cors.allowedOrigins=[]')
check "an explicitly empty list sets nothing" test "$(printf '%s\n' "$empty" | grep -c CORS_ALLOWED_ORIGINS)" = 0

exit "$fail"
