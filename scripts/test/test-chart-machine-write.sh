#!/usr/bin/env bash
# Render-time assertions for ui.machineAuth.write.* (change package
# docs/changes/machine-write-scope, T-024, #285): off by default and rendering
# nothing, every gate refusing with its own message, bind passwords only ever
# Secret references, the credential (W_cred) compartment rendered only when
# cred.enabled (T-026: identity, cn=config reader, canaries; never next to
# auditlog or accesslog extended/all), no HPA.
#
# BASE_REF (default origin/main) names the ref whose chart the off-render must be
# byte-identical to; when the ref is not available (shallow clone) that one
# comparison is reported as SKIP, everything else still runs.
#
# Run: ./scripts/test/test-chart-machine-write.sh   (needs helm; CI pins 3.17.3)
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
# refuses DESC WANT helm args...: the render must fail and say WANT ('/' in the
# output is normalised to '.' so Helm 3 and Helm 4 schema paths compare equal).
refuses() {
	local desc=$1 want=$2
	shift 2
	local out
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
full() { helm template t charts/ldapium "${base[@]}" "$@"; }
renders() { render "$@" >/dev/null 2>&1; }

cat >"$tmp/read.yaml" <<'YAML'
ui:
  trustedProxies: none
  machineAuth:
    enabled: true
    issuerURL: https://sso.example.com/realms/example
    audience: ldapium-api
    allowedClients:
      - id: svc-provisioning
        scopes: [directory.users.read, directory.groups.read]
      - id: svc-monitor
        scopes: [server.monitor.read]
    ldapBindDN: uid=machine,ou=system,dc=example,dc=org
    existingSecret: machine-ldap
YAML
cat >"$tmp/write.yaml" <<'YAML'
ui:
  idempotency:
    enabled: true
  machineAuth:
    write:
      enabled: true
      data:
        bindDN: uid=w-data,ou=system,dc=example,dc=org
        existingSecret: machine-ldap-write
      subtrees:
        - client: svc-provisioning
          dns: ['ou=people,dc=example,dc=org', 'ou=staff,dc=example,dc=org']
      groups:
        - client: svc-provisioning
          dns: ['cn=team,ou=groups,dc=example,dc=org']
      privilegedGroups:
        - cn=admins,ou=groups,dc=example,dc=org
YAML
read=(-f "$tmp/read.yaml")
wr=("${read[@]}" -f "$tmp/write.yaml")
cat >"$tmp/lock.yaml" <<'YAML'
ui:
  machineAuth:
    write:
      lock:
        enabled: true
        bindDN: uid=w-lock,ou=system,dc=example,dc=org
        existingSecret: machine-ldap-write-lock
YAML
lock=(-f "$tmp/lock.yaml")
cat >"$tmp/cred.yaml" <<'YAML'
ui:
  machineAuth:
    write:
      cred:
        enabled: true
        bindDN: uid=w-cred,ou=system,dc=example,dc=org
        existingSecret: machine-ldap-write-cred
        subtrees:
          - client: svc-provisioning
            dns: ['ou=people,dc=example,dc=org']
        pendingPolicyDN: cn=credential-pending,ou=policies,dc=example,dc=org
        aclReader:
          dn: uid=cred-reader,ou=system,dc=example,dc=org
          existingSecret: machine-ldap-cred-reader
        canaries:
          - withPassword: uid=canary-pw,ou=people,dc=example,dc=org
            unmarked: uid=canary-unmarked,ou=people,dc=example,dc=org
            pending: uid=canary-pending,ou=people,dc=example,dc=org
YAML
cred=(-f "$tmp/cred.yaml")

# --- off: nothing rendered, identical to the base ref -------------------------------
check "default render has no MACHINE_WRITE variable" lacks "$(full)" 'MACHINE_WRITE_'
check "machineAuth-on render has no MACHINE_WRITE variable" lacks "$(full "${read[@]}")" 'MACHINE_WRITE_'
offset=$(full "${wr[@]}" --set ui.machineAuth.write.enabled=false)
check "write.enabled=false renders no MACHINE_WRITE variable even with write values set" lacks "$offset" 'MACHINE_WRITE_'

baseref=${BASE_REF:-origin/main}
if git rev-parse --verify --quiet "$baseref^{commit}" >/dev/null; then
	mkdir "$tmp/basechart"
	git archive "$baseref" charts/ldapium | tar -x -C "$tmp/basechart"
	# A release bump changes the chart label and default image tag in every render;
	# compare the templates, not the version, by giving the base the current version.
	cur_version=$(awk '/^version:/ { print $2; exit }' charts/ldapium/Chart.yaml)
	sed "s/^version:.*/version: $cur_version/" "$tmp/basechart/charts/ldapium/Chart.yaml" >"$tmp/Chart.yaml.new"
	mv "$tmp/Chart.yaml.new" "$tmp/basechart/charts/ldapium/Chart.yaml"
	helm template t "$tmp/basechart/charts/ldapium" "${base[@]}" >"$tmp/base-default.out"
	full >"$tmp/cur-default.out"
	check "off render is byte-identical to $baseref (default)" cmp -s "$tmp/base-default.out" "$tmp/cur-default.out"
	helm template t "$tmp/basechart/charts/ldapium" "${base[@]}" "${read[@]}" >"$tmp/base-ma.out"
	full "${read[@]}" >"$tmp/cur-ma.out"
	check "off render is byte-identical to $baseref (machineAuth.enabled)" cmp -s "$tmp/base-ma.out" "$tmp/cur-ma.out"
else
	printf 'SKIP: byte-identity against %s (ref not available)\n' "$baseref"
fi

# --- on: the env contract -------------------------------------------------------------
r=$(render "${wr[@]}")
check "MACHINE_WRITE_ENABLED is true" has "$r" 'name: MACHINE_WRITE_ENABLED
              value: "true"'
check "data bind DN is a plain value" has "$r" 'name: MACHINE_WRITE_DATA_BIND_DN
              value: "uid=w-data,ou=system,dc=example,dc=org"'
check "data bind password is a secretKeyRef (name)" has "$r" 'name: "machine-ldap-write"'
check "data bind password is a secretKeyRef (default key)" has "$r" 'key: "machine-ldap-write-data-password"'
check "subtrees are client=dn|dn" has "$r" 'value: "svc-provisioning=ou=people,dc=example,dc=org|ou=staff,dc=example,dc=org"'
check "groups are client=dn" has "$r" 'value: "svc-provisioning=cn=team,ou=groups,dc=example,dc=org"'
check "privileged groups are rendered" has "$r" 'name: MACHINE_WRITE_PRIVILEGED_GROUPS
              value: "cn=admins,ou=groups,dc=example,dc=org"'
check "write limits default to the application defaults" has "$r" 'name: MACHINE_WRITE_GLOBAL_SLOTS
              value: "2"'
check "group seed absent by default" lacks "$r" 'MACHINE_WRITE_GROUP_SEED_DN'
rs=$(render "${wr[@]}" --set 'ui.machineAuth.write.groupSeedDN=uid=group-seed\,ou=system\,dc=example\,dc=org')
check "group seed renders as a plain value when set" has "$rs" 'name: MACHINE_WRITE_GROUP_SEED_DN
              value: "uid=group-seed,ou=system,dc=example,dc=org"'
check "lock identity absent by default" lacks "$r" 'MACHINE_WRITE_LOCK'
check "no credential identity variable while cred is off" lacks "$r" 'MACHINE_WRITE_CRED'
check "Recreate strategy with idempotency" has "$r" 'type: Recreate'
check "replicas is 1" has "$r" 'replicas: 1'
check "grace period covers the request timeout (30 s floor)" has "$r" 'terminationGracePeriodSeconds: 30'
rg=$(render "${wr[@]}" --set ui.machineAuth.requestTimeoutSeconds=60)
check "grace period follows a longer request timeout (60+15)" has "$rg" 'terminationGracePeriodSeconds: 75'
rl=$(render "${wr[@]}" "${lock[@]}")
check "lock identity renders when enabled" has "$rl" 'name: MACHINE_WRITE_LOCK_BIND_DN'
check "lock password is a secretKeyRef" test "$(printf '%s\n' "$rl" | grep -A4 'name: MACHINE_WRITE_LOCK_BIND_PASSWORD' | grep -c 'secretKeyRef')" = 1
# --- v2c (#379 T-026): the W_cred compartment -------------------------------------
rc=$(render "${wr[@]}" "${lock[@]}" "${cred[@]}" --set audit.accessLog.enabled=true --set 'audit.accessLog.ops=writes reads bind')
check "cred flag renders" has "$rc" 'name: MACHINE_WRITE_CRED_ENABLED
              value: "true"'
check "cred bind DN is a plain value" has "$rc" 'name: MACHINE_WRITE_CRED_BIND_DN
              value: "uid=w-cred,ou=system,dc=example,dc=org"'
check "cred bind password is a secretKeyRef (name, default key)" test "$(printf '%s\n' "$rc" | grep -A4 'name: MACHINE_WRITE_CRED_BIND_PASSWORD' | grep -c -e 'secretKeyRef' -e 'name: "machine-ldap-write-cred"' -e 'key: "machine-ldap-write-cred-password"')" = 3
check "reader password is a secretKeyRef (name, default key)" test "$(printf '%s\n' "$rc" | grep -A4 'name: MACHINE_WRITE_CRED_ACL_READER_PASSWORD' | grep -c -e 'secretKeyRef' -e 'name: "machine-ldap-cred-reader"' -e 'key: "machine-ldap-cred-acl-reader-password"')" = 3
check "cred subtrees are client=dn" has "$rc" 'name: MACHINE_WRITE_CRED_SUBTREES
              value: "svc-provisioning=ou=people,dc=example,dc=org"'
check "pending policy DN is rendered" has "$rc" 'name: MACHINE_WRITE_CRED_PENDING_POLICY_DN
              value: "cn=credential-pending,ou=policies,dc=example,dc=org"'
check "canaries are with-password|unmarked|pending" has "$rc" 'name: MACHINE_WRITE_CRED_CANARIES
              value: "uid=canary-pw,ou=people,dc=example,dc=org|uid=canary-unmarked,ou=people,dc=example,dc=org|uid=canary-pending,ou=people,dc=example,dc=org"'
check "cred defaults: min length 12, 1 rps, 24h TTL" has "$rc" 'name: MACHINE_WRITE_CRED_MIN_LENGTH
              value: "12"
            - name: MACHINE_WRITE_CRED_RATE_LIMIT_RPS
              value: "1"
            - name: MACHINE_WRITE_CRED_PENDING_TTL
              value: "24h"'
check "policy allowlist absent by default" lacks "$rc" 'MACHINE_WRITE_CRED_POLICY_DNS'
rp=$(render "${wr[@]}" "${cred[@]}" --set-json 'ui.machineAuth.write.cred.policyDNs=["cn=a,ou=policies,dc=example,dc=org","cn=b,ou=policies,dc=example,dc=org"]')
check "policy allowlist renders ;-joined when set" has "$rp" 'name: MACHINE_WRITE_CRED_POLICY_DNS
              value: "cn=a,ou=policies,dc=example,dc=org;cn=b,ou=policies,dc=example,dc=org"'
check "no cred or reader password has an inline value" test "$(printf '%s\n' "$rc" | grep -A1 -E 'name: MACHINE_WRITE_CRED_(BIND|ACL_READER)_PASSWORD' | grep -c 'value:')" = 0
check "cred.enabled=false renders no MACHINE_WRITE_CRED variable even with cred values set" lacks "$(render "${wr[@]}" "${cred[@]}" --set ui.machineAuth.write.cred.enabled=false)" 'MACHINE_WRITE_CRED'

whole=$(full "${wr[@]}" "${lock[@]}")
without=$(full "${read[@]}")
check "enabling write adds no Secret object" test "$(printf '%s\n' "$whole" | grep -c '^kind: Secret$')" = "$(printf '%s\n' "$without" | grep -c '^kind: Secret$')"
check "enabling write adds no HorizontalPodAutoscaler" lacks "$whole" 'kind: HorizontalPodAutoscaler'
wholec=$(full "${wr[@]}" "${lock[@]}" "${cred[@]}")
check "enabling cred adds no Secret object" test "$(printf '%s\n' "$wholec" | grep -c '^kind: Secret$')" = "$(printf '%s\n' "$without" | grep -c '^kind: Secret$')"
check "no write bind password has an inline value" test "$(printf '%s\n' "$whole" | grep -A1 -E 'name: MACHINE_WRITE_(DATA|LOCK)_BIND_PASSWORD' | grep -c 'value:')" = 0

# --- gates: each refusal has its own message ---------------------------------------
refuses "write without machine auth" 'ui.machineAuth.write.enabled=true requires ui.machineAuth.enabled=true' \
	-f "$tmp/write.yaml"
refuses "write with two UI replicas" 'requires ui.replicaCount=1' "${wr[@]}" --set ui.replicaCount=2
refuses "write with zero UI replicas" 'requires ui.replicaCount=1' "${wr[@]}" --set ui.replicaCount=0
refuses "write without idempotency" 'requires ui.idempotency.enabled=true' "${wr[@]}" --set ui.idempotency.enabled=false
refuses "write without subtrees" 'requires: ui.machineAuth.write.subtrees' "${wr[@]}" --set-json 'ui.machineAuth.write.subtrees=[]'
refuses "write without groups" 'requires: ui.machineAuth.write.groups' "${wr[@]}" --set-json 'ui.machineAuth.write.groups=[]'
refuses "write without privileged groups" 'requires: ui.machineAuth.write.privilegedGroups' "${wr[@]}" --set-json 'ui.machineAuth.write.privilegedGroups=[]'
refuses "write without data identity" 'ui.machineAuth.write.data.bindDN' "${wr[@]}" --set ui.machineAuth.write.data.bindDN=
refuses "write without data Secret" 'ui.machineAuth.write.data.existingSecret' "${wr[@]}" --set ui.machineAuth.write.data.existingSecret=
refuses "lock enabled without lock identity" 'write.lock.enabled=true requires' "${wr[@]}" --set ui.machineAuth.write.lock.enabled=true
refuses "data DN equals read DN" 'write.data.bindDN must differ from ui.machineAuth.ldapBindDN' "${wr[@]}" \
	--set 'ui.machineAuth.write.data.bindDN=UID=machine\, ou=system\,dc=example\,dc=org'
refuses "data DN is the administrator" 'write.data.bindDN must not be the LDAP administrator DN' "${wr[@]}" \
	--set 'ui.machineAuth.write.data.bindDN=cn=admin\,dc=example\,dc=org'
refuses "lock DN equals data DN" 'write.lock.bindDN must differ from ui.machineAuth.write.data.bindDN' "${wr[@]}" "${lock[@]}" \
	--set 'ui.machineAuth.write.lock.bindDN=uid=w-data\,ou=system\,dc=example\,dc=org'
refuses "lock DN equals read DN" 'write.lock.bindDN must differ from ui.machineAuth.ldapBindDN' "${wr[@]}" "${lock[@]}" \
	--set 'ui.machineAuth.write.lock.bindDN=uid=machine\,ou=system\,dc=example\,dc=org'
refuses "lock DN is the administrator" 'write.lock.bindDN must not be the LDAP administrator DN' "${wr[@]}" "${lock[@]}" \
	--set 'ui.machineAuth.write.lock.bindDN=cn=admin\,dc=example\,dc=org'
refuses "data reuses the read Secret key" 'write.data must not reuse the read identity' "${wr[@]}" \
	--set ui.machineAuth.write.data.existingSecret=machine-ldap \
	--set ui.machineAuth.write.data.existingSecretKey=machine-ldap-bind-password
refuses "lock reuses the data Secret key" 'write.lock must not reuse the data identity' "${wr[@]}" "${lock[@]}" \
	--set ui.machineAuth.write.lock.existingSecret=machine-ldap-write \
	--set ui.machineAuth.write.lock.existingSecretKey=machine-ldap-write-data-password
refuses "subtrees name an unknown client" 'write.subtrees client "ghost" is not in ui.machineAuth.allowedClients' "${wr[@]}" \
	--set-json 'ui.machineAuth.write.subtrees=[{"client":"ghost","dns":["ou=people,dc=example,dc=org"]}]'
refuses "groups name a client without subtrees" 'write.groups client "svc-monitor" has no ui.machineAuth.write.subtrees entry' "${wr[@]}" \
	--set-json 'ui.machineAuth.write.groups=[{"client":"svc-monitor","dns":["cn=g,ou=groups,dc=example,dc=org"]}]'

# --- schema: types, ranges, unknown keys --------------------------------------------
refuses "inline cred password is not a key" 'ui.machineAuth.write.cred' "${wr[@]}" "${cred[@]}" --set ui.machineAuth.write.cred.bindPassword=x
refuses "inline reader password is not a key" 'ui.machineAuth.write.cred.aclReader' "${wr[@]}" "${cred[@]}" --set ui.machineAuth.write.cred.aclReader.password=x
refuses "cred min length below the floor" 'ui.machineAuth.write.cred.minLength' "${wr[@]}" "${cred[@]}" --set ui.machineAuth.write.cred.minLength=8
refuses "cred rate above 10" 'ui.machineAuth.write.cred.rateLimitRPS' "${wr[@]}" "${cred[@]}" --set ui.machineAuth.write.cred.rateLimitRPS=11
refuses "cred canary set needs three DNs" 'pending' "${wr[@]}" "${cred[@]}" \
	--set-json 'ui.machineAuth.write.cred.canaries=[{"withPassword":"uid=a,ou=people,dc=example,dc=org","unmarked":"uid=b,ou=people,dc=example,dc=org"}]'
refuses "cred.enabled must be boolean" 'ui.machineAuth.write.cred.enabled' "${wr[@]}" --set-string ui.machineAuth.write.cred.enabled=yes
# --- v2c (#379 T-028, D379-14, F-7): never next to auditlog or a crashing accesslog ops list
refuses "cred next to audit.enabled (auditlog writes password hashes)" 'cannot be combined with audit.enabled=true' "${wr[@]}" \
	--set ui.machineAuth.write.cred.enabled=true --set audit.enabled=true
refuses "cred next to audit.enabled, even with write off" 'cannot be combined with audit.enabled=true' "${read[@]}" \
	--set ui.machineAuth.write.cred.enabled=true --set audit.enabled=true
refuses "cred next to accessLog ops extended (F-7)" 'audit.accessLog.ops containing extended or all' "${wr[@]}" \
	--set ui.machineAuth.write.cred.enabled=true --set audit.accessLog.enabled=true --set 'audit.accessLog.ops=writes reads bind extended'
refuses "cred next to accessLog ops all (F-7)" 'audit.accessLog.ops containing extended or all' "${wr[@]}" \
	--set ui.machineAuth.write.cred.enabled=true --set audit.accessLog.enabled=true --set audit.accessLog.ops=all
refuses "cred next to accessLog ops EXTENDED, any case (F-7)" 'audit.accessLog.ops containing extended or all' "${wr[@]}" \
	--set ui.machineAuth.write.cred.enabled=true --set audit.accessLog.enabled=true --set 'audit.accessLog.ops=writes EXTENDED'
refuses "cred next to accessLog ops All after a tab (F-7)" 'audit.accessLog.ops containing extended or all' "${wr[@]}" \
	--set ui.machineAuth.write.cred.enabled=true --set audit.accessLog.enabled=true --set-string "audit.accessLog.ops=writes$(printf '\t')All"
refuses "cred without write.enabled" 'write.cred.enabled=true requires ui.machineAuth.write.enabled=true' "${read[@]}" "${cred[@]}"
refuses "cred without its values (all named)" 'requires: ui.machineAuth.write.cred.bindDN, ui.machineAuth.write.cred.existingSecret, ui.machineAuth.write.cred.subtrees, ui.machineAuth.write.cred.pendingPolicyDN, ui.machineAuth.write.cred.canaries, ui.machineAuth.write.cred.aclReader.dn, ui.machineAuth.write.cred.aclReader.existingSecret' \
	"${wr[@]}" --set ui.machineAuth.write.cred.enabled=true
refuses "cred DN equals data DN" 'write.cred.bindDN must differ' "${wr[@]}" "${cred[@]}" --set 'ui.machineAuth.write.cred.bindDN=UID=w-data\, ou=system\,dc=example\,dc=org'
refuses "cred DN equals lock DN" 'write.cred.bindDN must differ' "${wr[@]}" "${lock[@]}" "${cred[@]}" --set 'ui.machineAuth.write.cred.bindDN=uid=w-lock\,ou=system\,dc=example\,dc=org'
refuses "cred DN equals read DN" 'write.cred.bindDN must differ' "${wr[@]}" "${cred[@]}" --set 'ui.machineAuth.write.cred.bindDN=uid=machine\,ou=system\,dc=example\,dc=org'
refuses "cred DN is the administrator" 'write.cred.bindDN must differ' "${wr[@]}" "${cred[@]}" --set 'ui.machineAuth.write.cred.bindDN=cn=admin\,dc=example\,dc=org'
refuses "reader DN equals cred DN" 'write.cred.aclReader.dn must differ' "${wr[@]}" "${cred[@]}" --set 'ui.machineAuth.write.cred.aclReader.dn=uid=w-cred\,ou=system\,dc=example\,dc=org'
refuses "reader DN equals data DN" 'write.cred.aclReader.dn must differ' "${wr[@]}" "${cred[@]}" --set 'ui.machineAuth.write.cred.aclReader.dn=uid=w-data\,ou=system\,dc=example\,dc=org'
refuses "cred reuses the data Secret key" 'write.cred must not reuse' "${wr[@]}" "${cred[@]}" \
	--set ui.machineAuth.write.cred.existingSecret=machine-ldap-write --set ui.machineAuth.write.cred.existingSecretKey=machine-ldap-write-data-password
refuses "cred reuses the read Secret key" 'write.cred must not reuse' "${wr[@]}" "${cred[@]}" \
	--set ui.machineAuth.write.cred.existingSecret=machine-ldap --set ui.machineAuth.write.cred.existingSecretKey=machine-ldap-bind-password
refuses "data reuses the LDAP administrator Secret key" 'write.data must not reuse the LDAP administrator' "${wr[@]}" \
	--set auth.existingSecret=ldap-admin --set ui.machineAuth.write.data.existingSecret=ldap-admin --set ui.machineAuth.write.data.existingSecretKey=admin-password
refuses "lock reuses the LDAP administrator Secret key" 'write.lock must not reuse the LDAP administrator' "${wr[@]}" "${lock[@]}" \
	--set auth.existingSecret=ldap-admin --set ui.machineAuth.write.lock.existingSecret=ldap-admin --set ui.machineAuth.write.lock.existingSecretKey=admin-password
refuses "cred reuses the LDAP administrator Secret key" 'or of the LDAP administrator' "${wr[@]}" "${cred[@]}" \
	--set auth.existingSecret=ldap-admin --set ui.machineAuth.write.cred.existingSecret=ldap-admin --set ui.machineAuth.write.cred.existingSecretKey=admin-password
refuses "reader reuses the LDAP administrator Secret key" 'write.cred.aclReader must not reuse' "${wr[@]}" "${cred[@]}" \
	--set auth.existingSecret=ldap-admin --set ui.machineAuth.write.cred.aclReader.existingSecret=ldap-admin --set ui.machineAuth.write.cred.aclReader.existingSecretKey=admin-password
refuses "reader reuses the cred Secret key" 'write.cred.aclReader must not reuse' "${wr[@]}" "${cred[@]}" \
	--set ui.machineAuth.write.cred.aclReader.existingSecret=machine-ldap-write-cred --set ui.machineAuth.write.cred.aclReader.existingSecretKey=machine-ldap-write-cred-password
refuses "cred subtrees name a client without write subtrees" 'write.cred.subtrees client "svc-monitor" has no ui.machineAuth.write.subtrees entry' "${wr[@]}" "${cred[@]}" \
	--set-json 'ui.machineAuth.write.cred.subtrees=[{"client":"svc-monitor","dns":["ou=people,dc=example,dc=org"]}]'
check "cred with the accepted accesslog ops renders" renders "${wr[@]}" "${cred[@]}" --set audit.accessLog.enabled=true --set 'audit.accessLog.ops=writes reads bind'
check "cred off with audit.enabled renders" renders "${wr[@]}" --set audit.enabled=true
refuses "inline bind password is not a key" 'ui.machineAuth.write.data' "${wr[@]}" --set ui.machineAuth.write.data.bindPassword=x
refuses "inline lock password is not a key" 'ui.machineAuth.write.lock' "${wr[@]}" --set ui.machineAuth.write.lock.bindPassword=x
refuses "write.enabled must be boolean" 'ui.machineAuth.write.enabled' "${wr[@]}" --set-string ui.machineAuth.write.enabled=yes
refuses "write rps range" 'ui.machineAuth.write.limits.rps' "${wr[@]}" --set ui.machineAuth.write.limits.rps=101
refuses "write burst range" 'ui.machineAuth.write.limits.burst' "${wr[@]}" --set ui.machineAuth.write.limits.burst=0
refuses "write global slots range" 'ui.machineAuth.write.limits.globalSlots' "${wr[@]}" --set ui.machineAuth.write.limits.globalSlots=65
refuses "write limits unknown key" 'ui.machineAuth.write.limits' "${wr[@]}" --set ui.machineAuth.write.limits.unknown=1
refuses "subtree entry without dns" 'dns' "${wr[@]}" --set-json 'ui.machineAuth.write.subtrees=[{"client":"svc-provisioning"}]'
refuses "subtree DN may not contain a list separator" 'ui.machineAuth.write.subtrees' "${wr[@]}" \
	--set-json 'ui.machineAuth.write.subtrees=[{"client":"svc-provisioning","dns":["ou=a|ou=b,dc=example,dc=org"]}]'

if [ "$fail" -ne 0 ]; then
	echo "chart machine-write assertions FAILED" >&2
	exit 1
fi
echo "chart machine-write assertions passed"
