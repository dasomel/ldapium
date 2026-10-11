#!/usr/bin/env bash
# #375 / T-017 chart assertions: real Helm renders and a real promtool run, no cluster mutation.
#   - default render has no trace of the feature, and is byte-identical to the chart at the ref given
#     as $1 when one is given (the commit before this feature proves it; skipped otherwise, because an
#     unrelated chart change on the base branch would make the comparison fail for the wrong reason)
#   - enabled render: CronJob arguments, no password in env/args, NetworkPolicy rule, PrometheusRule
#   - refusals: wrong identity, missing image
#   - the ConfigMap scripts are byte-identical to scripts/lib
#   - promtool unit test of the alert rule
set -euo pipefail
cd "$(dirname "$0")/../.."
chart=charts/ldapium
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
common=(--set auth.adminPassword=chart-test-password --set replicaCount=3)
dedicated=(--set replication.identity=dedicated --set replication.existingSecret=replication-secret --set tls.enabled=true --set tls.existingSecret=server-tls --set tls.caFile=/etc/openldap/tls/ca.crt)
check=(--set replication.check.enabled=true --set replication.check.image.repository=registry.example/ldapium-check --set-string replication.check.image.tag=1.0)
extras=(--set networkPolicy.enabled=true --set metrics.enabled=true --set metrics.prometheusRule.enabled=true)
render() { helm template rc "$chart" --namespace directory "${common[@]}" "$@"; }
refuse() { if render "$@" >/dev/null 2>&1; then echo 'FAIL unsafe combination rendered' >&2; exit 1; fi; echo 'PASS unsafe combination refused'; }
has() { [[ "$1" == *"$2"* ]] || { echo "FAIL missing: $2" >&2; exit 1; }; }
lacks() { [[ "$1" != *"$2"* ]] || { echo "FAIL unexpected: $2" >&2; exit 1; }; }

for profile in "" "${extras[*]}"; do
  # shellcheck disable=SC2086
  lacks "$(render $profile)" 'replication-check'
done
echo 'PASS defaults render nothing of the check'

# Default render unchanged: the previous chart is rendered from git with the same values.
ref="${1:-}"
if [ -n "$ref" ]; then
  git rev-parse --verify -q "$ref^{commit}" >/dev/null || { echo "FAIL unknown ref $ref" >&2; exit 1; }
  mkdir "$work/base"
  git archive "$ref" charts | tar -x -C "$work/base"
  for profile in "" "${extras[*]}" "${dedicated[*]} ${extras[*]}"; do
    # shellcheck disable=SC2086
    new=$(render $profile)
    # shellcheck disable=SC2086
    old=$(helm template rc "$work/base/$chart" --namespace directory "${common[@]}" $profile)
    [ "$new" = "$old" ] || { echo "FAIL default render differs from $ref (profile: ${profile:-defaults})" >&2; exit 1; }
  done
  echo "PASS default renders are byte-identical to $ref"
else
  echo "SKIP default-render comparison with a previous chart: pass a ref as the first argument"
fi

on=$(render "${dedicated[@]}" "${check[@]}" "${extras[@]}")
has "$on" 'name: rc-ldapium-replication-check'
has "$on" 'kind: CronJob'
has "$on" 'schedule: "*/30 * * * *"'
has "$on" 'image: "registry.example/ldapium-check:1.0"'
has "$on" 'ldaps://rc-ldapium-0.rc-ldapium-headless.directory.svc.cluster.local:636'
has "$on" 'ldaps://rc-ldapium-2.rc-ldapium-headless.directory.svc.cluster.local:636'
has "$on" '- --require-converged'
has "$on" '- --dedicated'
has "$on" 'secretName: server-tls'
has "$on" 'name: replication-secret'
has "$on" 'app.kubernetes.io/component: replication-check'
has "$on" 'alert: LDAPiumReplicationCheckFailed'
lacks "$on" '- --canary'
lacks "$on" 'chart-test-password'
cron=$(render "${dedicated[@]}" "${check[@]}" --show-only templates/replication-check-cronjob.yaml)
lacks "$cron" 'tls.key'
has "$cron" 'path: ca.crt'
# The NetworkPolicy admits the check pod on 636 only.
policy=$(render "${dedicated[@]}" "${check[@]}" "${extras[@]}" --show-only templates/networkpolicy.yaml)
has "$policy" 'app.kubernetes.io/component: replication-check'
canary=$(render "${dedicated[@]}" "${check[@]}" --set replication.check.canary=true --set replication.check.requireConverged=false --show-only templates/replication-check-cronjob.yaml)
has "$canary" '- --canary'
lacks "$canary" '- --require-converged'
echo 'PASS enabled render'

refuse "${check[@]}"
refuse "${dedicated[@]}" --set replication.check.enabled=true
refuse "${dedicated[@]}" "${check[@]}" --set-string replication.check.image.tag=
refuse "${check[@]}" --set replication.identity=prepare
refuse "${dedicated[@]}" "${check[@]}" --set replication.check.schedule=
refuse "${dedicated[@]}" "${check[@]}" --set replication.check.failedJobsHistoryLimit=0

# The scripts shipped in the ConfigMap are the ones the operator runs.
for name in replication_identity_check.py replication_identity_config.py replication_uri.py; do
  cmp "scripts/lib/$name" "$chart/files/replication-check/$name" || { echo "FAIL chart copy of $name drifted from scripts/lib" >&2; exit 1; }
done
configmap=$(render "${dedicated[@]}" "${check[@]}" --show-only templates/replication-check-configmap.yaml)
has "$configmap" 'replication_identity_check.py: |'
echo 'PASS scripts in the ConfigMap match scripts/lib'

# Alert rule: rendered from the chart, then promtool.
# The thresholds the other alerts need come from the observability example profile.
render "${dedicated[@]}" "${check[@]}" --values "$chart/examples/metrics-values.yaml" --show-only templates/prometheusrule.yaml |
  sed -n '/^spec:/,$p' | tail -n +2 | sed 's/^  //' > "$work/replication_check_rules.yaml"
grep -q '^groups:' "$work/replication_check_rules.yaml"
cp tests/prometheus/replication_check_test.yaml "$work/"
if command -v promtool >/dev/null 2>&1; then
  (cd "$work" && promtool check rules replication_check_rules.yaml && promtool test rules replication_check_test.yaml)
else
  docker run --rm --entrypoint /bin/promtool -v "$work:/tests" -w /tests prom/prometheus:v3.7.3 test rules replication_check_test.yaml
fi
echo 'ALL PASS: replication check chart (render, refusals, script copies, promtool)'
