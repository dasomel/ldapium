#!/usr/bin/env bash
# Render assertions for ui.idempotency.enabled (#216, D216-9a, AC-020).
#
# The in-memory Idempotency-Key store only guarantees anything while exactly
# one UI process exists, so the chart turns UI_IDEMPOTENCY_ENABLED on only for
# one replica with a Recreate rollout, and otherwise renders it false.
set -euo pipefail

cd "$(dirname "$0")/../.."

command -v helm >/dev/null 2>&1 || {
	echo "helm is required; install Helm" >&2
	exit 2
}

ADMIN_DN='cn=admin\,dc=example\,dc=org'
SECRET="idempotency-render-session-secret-not-a-secret-0123"
fail=0

render() {
	helm template idem charts/ldapium \
		--set-string "ldap.adminDN=$ADMIN_DN" \
		--set-string "auth.adminPassword=render-only" \
		--set ui.enabled=true --set-string "ui.session.secret=$SECRET" "$@"
}

# env_value NAME: the value rendered for the UI container env var NAME.
env_value() {
	awk -v n="$1" '$0 ~ "- name: "n"$" {getline; gsub(/.*value: /, ""); gsub(/"/, ""); print; exit}'
}

recreate_count() { grep -c '^    type: Recreate$' || true; }

check() {
	local label=$1 want=$2 got=$3
	if [ "$want" != "$got" ]; then
		printf 'FAIL: %s: want %q, got %q\n' "$label" "$want" "$got" >&2
		fail=1
	else
		printf 'ok: %s = %s\n' "$label" "$got"
	fi
}

backup_args=(
	--set ui.backups.enabled=true --set ui.backups.runtimeConfirmed=true
	--set-string ui.backups.existingClaim=bk --set-string ui.backups.existingSecret=bk-op
	--set 'ui.backups.adminDNs={cn=a}'
)
profile_args=(--set ui.applicationProfiles.enabled=true --set-string ui.applicationProfiles.existingClaim=pf --set 'ui.applicationProfiles.adminDNs={cn=a}')

out=$(render)
check "default: env" false "$(env_value UI_IDEMPOTENCY_ENABLED <<<"$out")"
check "default: no Recreate" 0 "$(recreate_count <<<"$out")"
check "default: no key file" "" "$(env_value UI_IDEMPOTENCY_KEY_FILE <<<"$out")"

out=$(render --set ui.idempotency.enabled=true)
check "enabled, 1 replica: env" true "$(env_value UI_IDEMPOTENCY_ENABLED <<<"$out")"
check "enabled, 1 replica: Recreate" 1 "$(recreate_count <<<"$out")"
check "enabled without backups: no key file" "" "$(env_value UI_IDEMPOTENCY_KEY_FILE <<<"$out")"

out=$(render --set ui.idempotency.enabled=true --set ui.replicaCount=2)
check "enabled, 2 replicas: env stays off" false "$(env_value UI_IDEMPOTENCY_ENABLED <<<"$out")"
# NOTES.txt is only printed by install/upgrade (needs a cluster in Helm 3) and
# `helm template --show-only` cannot select it. Render a copy of the chart in
# which it is an ordinary template, with the same helm template call under
# Helm 3 and 4.
copy=$(mktemp -d "${TMPDIR:-/tmp}/idem-notes.XXXXXX")
trap 'rm -rf "$copy"' EXIT
cp -R charts/ldapium "$copy/ldapium"
# Wrapped as a block scalar of a ConfigMap so the output is valid YAML.
{
	printf 'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: notes-check\ndata:\n  notes: |\n'
	sed 's/^/    /' "$copy/ldapium/templates/NOTES.txt"
} >"$copy/ldapium/templates/notes-check.yaml"
rm "$copy/ldapium/templates/NOTES.txt"

notes() {
	helm template idem "$copy/ldapium" --show-only templates/notes-check.yaml \
		--set-string "ldap.adminDN=$ADMIN_DN" --set-string auth.adminPassword=x \
		--set ui.enabled=true --set-string "ui.session.secret=$SECRET" "$@"
}

notes_out=$(notes --set ui.idempotency.enabled=true --set ui.replicaCount=2)
if grep -q 'Idempotency-Key stays OFF' <<<"$notes_out"; then
	echo "ok: 2 replicas: NOTES.txt warns"
else
	echo "FAIL: 2 replicas: NOTES.txt must warn that idempotency is off" >&2
	fail=1
fi
notes_out=$(notes --set ui.idempotency.enabled=true)
if grep -q 'Idempotency-Key stays OFF' <<<"$notes_out"; then
	echo "FAIL: 1 replica: NOTES.txt must not warn" >&2
	fail=1
else
	echo "ok: 1 replica: no warning"
fi

out=$(render --set ui.idempotency.enabled=true "${profile_args[@]}" "${backup_args[@]}")
check "with profiles and backups: Recreate once" 1 "$(recreate_count <<<"$out")"
check "with backups: key file in the backup PVC" "/var/lib/ldapium-backups/.idempotency/key" "$(env_value UI_IDEMPOTENCY_KEY_FILE <<<"$out")"
check "with backups: env" true "$(env_value UI_IDEMPOTENCY_ENABLED <<<"$out")"

# Backups alone (switch off) still get the persisted key for backup start.
out=$(render "${backup_args[@]}")
check "backups only: env off" false "$(env_value UI_IDEMPOTENCY_ENABLED <<<"$out")"
check "backups only: key file" "/var/lib/ldapium-backups/.idempotency/key" "$(env_value UI_IDEMPOTENCY_KEY_FILE <<<"$out")"
check "backups only: Recreate once" 1 "$(recreate_count <<<"$out")"

[ "$fail" -eq 0 ] && echo "PASS: chart idempotency render"
exit "$fail"
