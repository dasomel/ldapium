#!/usr/bin/env bash
set -euo pipefail

# Render the chart's PrometheusRule into a plain Prometheus rules file, the
# shape `promtool test rules` expects.
#
# Usage:
#   scripts/render-alert-rules.sh [VALUES_FILE] [OUTPUT_FILE]
#
# Defaults to the observability profile in charts/ldapium/examples and
# tests/prometheus/rules.yaml, which is what tests/prometheus/alerts_test.yaml
# references. The rules the tests run against are therefore the rules the chart
# actually ships, not a copy that can drift away from them.

repo_root=$(cd "$(dirname "$0")/.." && pwd)
values="${1:-${repo_root}/charts/ldapium/examples/metrics-values.yaml}"
output="${2:-${repo_root}/tests/prometheus/rules.yaml}"

command -v helm >/dev/null 2>&1 || { echo "helm is required" >&2; exit 1; }

mkdir -p "$(dirname "$output")"

# `promtool` wants the rule groups at the top level; a PrometheusRule nests
# them under spec:. Everything from `spec:` onward, minus that line, minus one
# level of indentation.
helm template alerts "${repo_root}/charts/ldapium" \
  --namespace directory \
  --set auth.adminPassword=render-only \
  --values "$values" \
  --show-only templates/prometheusrule.yaml \
  | sed -n '/^spec:/,$p' \
  | tail -n +2 \
  | sed 's/^  //' \
  > "$output"

grep -q '^groups:' "$output" || {
  echo "rendered file does not look like a rules file: $output" >&2
  exit 1
}
echo "wrote $output"
