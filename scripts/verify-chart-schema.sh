#!/usr/bin/env bash
# Render the chart's supported configuration paths and validate the manifests
# against the Kubernetes OpenAPI schema. `helm lint` checks templates, but it
# cannot tell us whether a template renders a field with the wrong type or in
# the wrong object.
#
# The profiles below cover each conditional chart path. The admin DN is set
# with --set-string because Helm otherwise treats its escaped commas as a
# value-list separator; the password is a disposable render-only fixture.
set -euo pipefail

cd "$(dirname "$0")/.."

KUBERNETES_VERSION="1.32.0"
ADMIN_DN='cn=admin\,dc=example\,dc=org'
ADMIN_PASSWORD="schema-validation-not-a-secret"

need() {
	command -v "$1" >/dev/null 2>&1 || {
		echo "$1 is required; $2" >&2
		exit 2
	}
}

need helm "install Helm"
need kubeconform "install kubeconform"

validate() {
	local profile=$1
	shift

	helm template "$profile" charts/ldapium \
		--set-string "ldap.adminDN=$ADMIN_DN" \
		--set-string "auth.adminPassword=$ADMIN_PASSWORD" \
		"$@" |
		kubeconform \
			-strict \
			-summary \
			-kubernetes-version "$KUBERNETES_VERSION"

	printf 'PASS: %s\n' "$profile"
}

validate defaults
validate replicated --set replicaCount=3
validate tls --set tls.enabled=true --set-string tls.existingSecret=schema-validation-tls
validate ui --set ui.enabled=true
