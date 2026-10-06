#!/usr/bin/env bash
# Render-time assertions for the UI /metrics wiring of the Helm chart
# (docs/changes/api-error-envelope, D218-10, AC-018): off by default, the metrics
# port never on the public UI Service, reachable only by the configured peers,
# monitors off unless asked for, slapd's own resources untouched.
#
# Run: ./scripts/test/test-chart-ui-metrics.sh   (needs helm)
# The has/lacks/fails_with helpers are reached indirectly (check DESC has ...),
# which shellcheck cannot follow.
# shellcheck disable=SC2317,SC2329
set -euo pipefail

cd "$(dirname "$0")/../.."

fail=0
ok() { printf 'PASS: %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }

# has TEXT PATTERN: TEXT contains a line matching the (fixed) PATTERN.
has() { printf '%s\n' "$1" | grep -qF -- "$2"; }
# check DESCRIPTION CMD...: PASS when CMD succeeds, FAIL otherwise.
check() {
	local desc=$1
	shift
	if "$@"; then ok "$desc"; else bad "$desc"; fi
}
# lacks TEXT PATTERN: the negation of has.
lacks() { ! has "$1" "$2"; }
# fails_with MESSAGE ARGS...: helm template fails and its error contains MESSAGE.
fails_with() {
	local msg=$1 err
	shift
	if err=$(render "$@" 2>&1 >/dev/null); then return 1; fi
	[ -z "$msg" ] || has "$err" "$msg"
}

# Throwaway render-only values, never credentials.
base=(--set auth.adminPassword=ci-render-only-not-a-secret --set ui.enabled=true
	--set ui.session.secret=ci-render-only-session-secret-not-a-secret-0123)
peer=(--set 'ui.metrics.networkPolicy.from[0].namespaceSelector.matchLabels.kubernetes\.io/metadata\.name=monitoring')

render() { helm template t charts/ldapium "${base[@]}" "$@"; }

# 1. Default: nothing about UI metrics is rendered.
default=$(render)
for pattern in ui-metrics 9331 METRICS_ADDR 'kind: PodMonitor' 'kind: ServiceMonitor' 'kind: NetworkPolicy'; do
	check "default render has no '$pattern'" lacks "$default" "$pattern"
done

# 2. Enabled with a scrape peer.
on=(--set ui.metrics.enabled=true "${peer[@]}")
enabled=$(render "${on[@]}")
dep=$(render "${on[@]}" --show-only templates/ui-deployment.yaml)
pub=$(render "${on[@]}" --show-only templates/ui-service.yaml)
svc=$(render "${on[@]}" --show-only templates/ui-metrics-service.yaml)
pol=$(render "${on[@]}" --show-only templates/ui-networkpolicy.yaml)

check "Deployment sets METRICS_ADDR" has "$dep" 'name: METRICS_ADDR'
check "Deployment METRICS_ADDR is :9331" has "$dep" 'value: ":9331"'
check "Deployment names the container port ui-metrics" has "$dep" 'name: ui-metrics'
check "Deployment exposes containerPort 9331" has "$dep" 'containerPort: 9331'

check "public UI Service (ui-service.yaml) has no metrics port" lacks "$pub" '9331'
check "public UI Service has no metrics name" lacks "$pub" 'metrics'
check "public UI Service still exposes 8080" has "$pub" 'port: 8080'

check "separate t-ldapium-ui-metrics Service exists" has "$svc" 'name: t-ldapium-ui-metrics'
check "metrics Service carries port 9331" has "$svc" 'port: 9331'
check "metrics Service is component ui-metrics" has "$svc" 'app.kubernetes.io/component: ui-metrics'
check "metrics Service does not expose the HTTP port" lacks "$svc" 'port: 8080'

# NetworkPolicy: two ingress rules; 8080 with no `from`, 9331 only from the peer.
rules=$(printf '%s\n' "$pol" | awk '/^  ingress:/{f=1;next} f')
http_rule=$(printf '%s\n' "$rules" | awk '/^    -( |$)/{n++} n==1')
metrics_rule=$(printf '%s\n' "$rules" | awk '/^    -( |$)/{n++} n==2')
check "NetworkPolicy HTTP rule opens 8080" has "$http_rule" 'port: 8080'
check "NetworkPolicy HTTP rule keeps every source (no from)" lacks "$http_rule" 'from:'
check "NetworkPolicy metrics rule opens 9331" has "$metrics_rule" 'port: 9331'
check "NetworkPolicy metrics rule is limited to the configured peer" has "$metrics_rule" 'kubernetes.io/metadata.name: monitoring'
check "NetworkPolicy metrics rule does not open 8080" lacks "$metrics_rule" 'port: 8080'
check "NetworkPolicy opens exactly two ports" test "$(printf '%s\n' "$pol" | grep -c 'port: ')" = 2

check "ServiceMonitor stays off unless enabled" lacks "$enabled" 'kind: ServiceMonitor'
check "PodMonitor stays off unless enabled" lacks "$enabled" 'kind: PodMonitor'

# 3. An empty peer list fails (an empty `from` would mean "every source").
check "metrics enabled with no peers fails with the explanation" fails_with 'ui.metrics.networkPolicy.from is empty' --set ui.metrics.enabled=true

# 4. Monitors, when asked for, target only the metrics Service / UI pods.
sm=$(render "${on[@]}" --set ui.metrics.serviceMonitor.enabled=true --show-only templates/ui-servicemonitor.yaml)
pm=$(render "${on[@]}" --set ui.metrics.podMonitor.enabled=true --show-only templates/ui-podmonitor.yaml)
check "ServiceMonitor renders" has "$sm" 'kind: ServiceMonitor'
check "ServiceMonitor selects component ui-metrics" has "$sm" 'app.kubernetes.io/component: ui-metrics'
check "ServiceMonitor scrapes port ui-metrics" has "$sm" 'port: ui-metrics'
check "ServiceMonitor does not use slapd's port name 'metrics'" lacks "$sm" 'port: metrics'
check "PodMonitor renders" has "$pm" 'kind: PodMonitor'
check "PodMonitor targets the ui-metrics container port" has "$pm" 'port: ui-metrics'
check "serviceMonitor without ui.metrics.enabled fails" fails_with 'requires ui.metrics.enabled' --set ui.metrics.serviceMonitor.enabled=true
check "podMonitor without ui.metrics.enabled fails" fails_with 'requires ui.metrics.enabled' --set ui.metrics.podMonitor.enabled=true
check "ui.metrics.port 8080 (the container's HTTP listener) fails" fails_with 'must not be 8080' "${on[@]}" --set ui.metrics.port=8080
# Ports are validated and compared numerically, not as written.
for bad_port in 0 65536 -1 99999; do
	check "ui.metrics.port $bad_port fails (must be 1-65535)" fails_with '1-65535' "${on[@]}" --set "ui.metrics.port=$bad_port"
done
check "ui.metrics.port 08080 is the same port as 8080 and fails" fails_with 'must not be 8080' "${on[@]}" --set-string ui.metrics.port=08080
check "ui.metrics.port abc fails" fails_with '1-65535' "${on[@]}" --set-string ui.metrics.port=abc
check "ui.metrics.port 09331 renders as 9331" has "$(render "${on[@]}" --set-string ui.metrics.port=09331 --show-only templates/ui-deployment.yaml)" 'value: ":9331"'
# The Service port is not the container listener: 80 -> 8080 is a normal setup and must not hide the collision.
check "ui.metrics.port 8080 fails even when ui.service.port is 80" fails_with 'must not be 8080' "${on[@]}" --set ui.service.port=80 --set ui.metrics.port=8080
check "a metrics port equal to the Service port is fine when it is not 8080" render "${on[@]}" --set ui.service.port=9331 >/dev/null

# 5. slapd's own resources are identical with and without UI metrics, and its
#    ServiceMonitor selector (component server) cannot match the metrics Service.
slapd=(--set metrics.enabled=true --set metrics.serviceMonitor.enabled=true --set networkPolicy.enabled=true)
for t in statefulset service networkpolicy servicemonitor metrics-service; do
	a=$(render "${slapd[@]}" --show-only "templates/$t.yaml")
	b=$(render "${slapd[@]}" "${on[@]}" --show-only "templates/$t.yaml")
	check "slapd $t.yaml unchanged by ui.metrics" test "$a" = "$b"
done
slapd_sm=$(render "${slapd[@]}" --show-only templates/servicemonitor.yaml)
check "slapd ServiceMonitor selector pins component=server (disjoint from ui-metrics)" has "$slapd_sm" 'app.kubernetes.io/component: server'

check "helm lint with metrics enabled" helm lint charts/ldapium "${base[@]}" "${on[@]}"

exit "$fail"
