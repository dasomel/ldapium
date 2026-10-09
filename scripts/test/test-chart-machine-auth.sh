#!/usr/bin/env bash
# Render-time assertions for ui.machineAuth.* (change package
# docs/changes/machine-principal-auth, T-016, #214): off by default and
# rendering nothing, required values enforced when on, the machine LDAP bind
# password only ever a Secret reference, MACHINE_LDAP_ROOT_DNS derived from
# ldap.adminDN with ";" (a DN contains commas), no insecure-http switch.
#
# Run: ./scripts/test/test-chart-machine-auth.sh   (needs helm; CI pins 3.17.3,
# which is why this uses `helm template`, never `helm install --dry-run=client`)
# has is reached indirectly (check DESC has ...), which shellcheck cannot follow.
# shellcheck disable=SC2317,SC2329
set -euo pipefail

cd "$(dirname "$0")/../.."

fail=0
# HELM=/path/to/helm runs the script against a specific Helm (CI pins 3.17.3).
helm() { command "${HELM:-helm}" "$@"; }
ok() { printf 'PASS: %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }

has() { printf '%s\n' "$1" | grep -qF -- "$2"; }
lacks() { ! has "$1" "$2"; }
check() {
	local desc=$1
	shift
	if "$@"; then ok "$desc"; else bad "$desc"; fi
}
# refuses DESC -- helm args...: the render must fail and say MSG.
refuses() {
	local desc=$1 want=$2
	shift 2
	local out
	# Schema errors name the property as a dotted path in Helm 3 (ui.machineAuth.
	# rateLimit.rps) and as a slash path in Helm 4 ('/ui/machineAuth/rateLimit/rps'),
	# with different wording for the reason. Only the property path is asserted, in
	# dotted form: '/' in the output is normalised to '.' before matching.
	if out=$(render "$@" 2>&1); then
		bad "$desc (rendered, expected a failure)"
	elif out=$(printf '%s' "$out" | tr '/' '.'); has "$out" "$want"; then
		ok "$desc"
	else
		bad "$desc (failed without \"$want\": $(printf '%s' "$out" | tail -n 3))"
	fi
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Throwaway render-only values, never credentials.
base=(--set auth.adminPassword=ci-render-only-not-a-secret --set ui.enabled=true
	--set ui.session.secret=ci-render-only-session-secret-not-a-secret-0123)
render() { helm template t charts/ldapium "${base[@]}" --show-only templates/ui-deployment.yaml "$@"; }

cat >"$tmp/on.yaml" <<'EOF'
ui:
  trustedProxies: none
  machineAuth:
    enabled: true
    issuerURL: https://sso.example.com/realms/example
    audience: ldapium-api
    allowedClients:
      - id: svc-reporting
        scopes: [directory.users.read, directory.groups.read]
      - id: svc-monitor
        scopes: [server.monitor.read]
    ldapBindDN: uid=machine,ou=system,dc=example,dc=org
    existingSecret: machine-ldap
EOF
on=(-f "$tmp/on.yaml")

# --- disabled: nothing rendered -------------------------------------------------
default=$(render)
check "default render has no MACHINE_ variable" lacks "$default" 'MACHINE_'
check "default render does not touch terminationGracePeriodSeconds" lacks "$default" 'terminationGracePeriodSeconds'
off=$(render --set ui.machineAuth.enabled=false --set-string ui.machineAuth.audience=x)
check "enabled=false renders nothing even with values set" lacks "$off" 'MACHINE_'

# --- enabled: the env contract --------------------------------------------------
r=$(render "${on[@]}")
check "MACHINE_AUTH_ENABLED is true" has "$r" 'name: MACHINE_AUTH_ENABLED'
check "issuer reaches the container" has "$r" 'value: "https://sso.example.com/realms/example"'
check "audience reaches the container" has "$r" 'value: "ldapium-api"'
check "allowed clients are clientId=scope,scope joined with ;" has "$r" 'value: "svc-reporting=directory.users.read,directory.groups.read;svc-monitor=server.monitor.read"'
check "bind DN is a plain value" has "$r" 'value: "uid=machine,ou=system,dc=example,dc=org"'
check "bind password is a secretKeyRef (name)" has "$r" 'name: "machine-ldap"'
check "bind password is a secretKeyRef (default key)" has "$r" 'key: "machine-ldap-bind-password"'
check "no insecure-http variable exists in the chart output" lacks "$r" 'MACHINE_OIDC_INSECURE_HTTP'
check "default root DNs: cn=admin,<rootDN> as ONE entry (the comma is not a separator)" has "$r" 'name: MACHINE_LDAP_ROOT_DNS
              value: "cn=admin,dc=example,dc=org"'
check "limits default to the package values" has "$r" 'name: MACHINE_AUTH_FAILURE_LIMIT
              value: "10"'
check "request timeout is rendered in seconds" has "$r" 'value: "10s"'
check "grace period covers the request timeout (30 s floor)" has "$r" 'terminationGracePeriodSeconds: 30'

check "revocation off emits no environment" lacks "$r" 'MACHINE_REVOCATION_'
rrev=$(render "${on[@]}" --set ui.machineAuth.revocation.enabled=true)
check "revocation on reaches backend" has "$rrev" 'name: MACHINE_REVOCATION_ENABLED'
check "revocation base derives root DN" has "$rrev" 'value: "ou=revocations,ou=system,dc=example,dc=org"'
refuses "revocation freshness gap" 'revocation.maxStaleSeconds' "${on[@]}" --set ui.machineAuth.revocation.enabled=true --set ui.machineAuth.revocation.refreshSeconds=20
refuses "revocation entries cap" 'revocation.maxEntries' "${on[@]}" --set ui.machineAuth.revocation.maxEntries=2501
refuses "revocation refresh range" 'revocation.refreshSeconds' "${on[@]}" --set ui.machineAuth.revocation.refreshSeconds=0
refuses "revocation sentinel age range" 'revocation.sentinelMaxAgeSeconds' "${on[@]}" --set ui.machineAuth.revocation.sentinelMaxAgeSeconds=29

# the whole chart: no secret value is created or printed
whole=$(helm template t charts/ldapium "${base[@]}" "${on[@]}")
without=$(helm template t charts/ldapium "${base[@]}")
check "enabling machine auth adds no Secret object" test "$(printf '%s\n' "$whole" | grep -c '^kind: Secret$')" = "$(printf '%s\n' "$without" | grep -c '^kind: Secret$')"
check "the bind password appears only as one secretKeyRef, never as a value" test "$(printf '%s\n' "$whole" | grep -A4 'name: MACHINE_LDAP_BIND_PASSWORD' | grep -c 'secretKeyRef')" = 1
check "MACHINE_LDAP_BIND_PASSWORD has no inline value" lacks "$(printf '%s\n' "$whole" | grep -A1 'name: MACHINE_LDAP_BIND_PASSWORD')" 'value:'

# --- root DN derivation ----------------------------------------------------------
cat >"$tmp/dn.yaml" <<'EOF'
ldap:
  adminDN: cn=root,ou=system,dc=example,dc=org
ui:
  machineAuth:
    extraRootDNs:
      - cn=second,dc=example,dc=org
      - 'cn=semi\3Bcolon,dc=example,dc=org'
EOF
dn=$(render "${on[@]}" -f "$tmp/dn.yaml")
check "custom ldap.adminDN with commas plus extras is ;-joined, commas untouched" has "$dn" 'value: "cn=root,ou=system,dc=example,dc=org;cn=second,dc=example,dc=org;cn=semi\\3Bcolon,dc=example,dc=org"'
rd=$(render "${on[@]}" --set-string 'ldap.rootDN=dc=corp\,dc=example')
check "default adminDN follows ldap.rootDN" has "$rd" 'value: "cn=admin,dc=corp,dc=example"'

# --- grace period follows the timeout ---------------------------------------------
g=$(render "${on[@]}" --set ui.machineAuth.requestTimeoutSeconds=60)
check "a 60 s timeout renders MACHINE_REQUEST_TIMEOUT 60s" has "$g" 'value: "60s"'
check "and a 75 s grace period (10 s auth phase + 5 s margin)" has "$g" 'terminationGracePeriodSeconds: 75'

# --- SSO issuer inheritance ---------------------------------------------------------
cat >"$tmp/sso.yaml" <<'EOF'
ui:
  machineAuth:
    issuerURL: ""
  sso:
    enabled: true
    issuerURL: https://sso.example.com/realms/example
    clientID: ldapium-sso
    existingSecret: sso-secret
    callbackOrigins: [https://ldapium.example.com]
  ldapServiceAccount:
    existingSecret: ldap-sa
EOF
sso=$(render "${on[@]}" -f "$tmp/sso.yaml")
check "empty issuerURL with SSO on sets no MACHINE_OIDC_ISSUER_URL (inherits SSO_ISSUER_URL)" lacks "$sso" 'MACHINE_OIDC_ISSUER_URL'

# --- refusals ----------------------------------------------------------------------------
refuses "missing audience fails" "ui.machineAuth.audience" "${on[@]}" --set-string ui.machineAuth.audience=
refuses "missing allowedClients fails" "ui.machineAuth.allowedClients" "${on[@]}" --set-json 'ui.machineAuth.allowedClients=[]'
refuses "missing bind DN fails" "ui.machineAuth.ldapBindDN" "${on[@]}" --set-string ui.machineAuth.ldapBindDN=
refuses "missing bind password Secret fails" "ui.machineAuth.existingSecret" "${on[@]}" --set-string ui.machineAuth.existingSecret=
refuses "missing Secret key fails" "ui.machineAuth.existingSecretKey" "${on[@]}" --set-string ui.machineAuth.existingSecretKey=
refuses "missing issuer without SSO fails" "ui.machineAuth.issuerURL" "${on[@]}" --set-string ui.machineAuth.issuerURL=
refuses "all missing values are listed in one message" "audience, ui.machineAuth.allowedClients, ui.machineAuth.ldapBindDN" \
	"${on[@]}" --set-string ui.machineAuth.audience= --set-json 'ui.machineAuth.allowedClients=[]' --set-string ui.machineAuth.ldapBindDN=
refuses "an http issuer fails" "https" "${on[@]}" --set-string ui.machineAuth.issuerURL=http://sso.example.com/realms/example
refuses "trustedProxies=private (the default) fails" "ui.trustedProxies" "${on[@]}" --set-string ui.trustedProxies=private
refuses "an empty trustedProxies fails" "ui.trustedProxies" "${on[@]}" --set-string ui.trustedProxies=
refuses "a client without scopes fails" "allowedClients.0.scopes" "${on[@]}" --set-json 'ui.machineAuth.allowedClients=[{"id":"svc","scopes":[]}]'
refuses "an unknown scope fails the schema" "allowedClients.0.scopes.0" "${on[@]}" --set-json 'ui.machineAuth.allowedClients=[{"id":"svc","scopes":["directory.users.write"]}]'
refuses "a client id with a separator fails" "allowedClients.0.id" "${on[@]}" --set-json 'ui.machineAuth.allowedClients=[{"id":"a;b","scopes":["audit.read"]}]'
refuses "the account audience fails" "machineAuth.audience" "${on[@]}" --set-string ui.machineAuth.audience=account
refuses "an insecure http switch is not a value (unknown key)" "insecureHTTP" "${on[@]}" --set ui.machineAuth.insecureHTTP=true
refuses "a limit of zero fails the schema" "rateLimit.rps" "${on[@]}" --set ui.machineAuth.rateLimit.rps=0
refuses "a timeout over 300 s fails the schema" "machineAuth.requestTimeoutSeconds" "${on[@]}" --set ui.machineAuth.requestTimeoutSeconds=301

exit "$fail"
