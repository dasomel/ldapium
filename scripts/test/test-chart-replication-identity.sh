#!/usr/bin/env bash
# D66 chart credential combinations: real Helm renders, no cluster mutation.
set -euo pipefail
chart=charts/ldapium
common=(--set auth.adminPassword=chart-test-password --set replicaCount=3)
dedicated=(--set replication.identity=dedicated --set replication.existingSecret=replication-secret --set tls.enabled=true --set tls.existingSecret=server-tls --set tls.caFile=/etc/openldap/tls/ca.crt)
render() { helm template ridtest "$chart" "${common[@]}" "$@"; }
refuse() { if render "$@" >/dev/null 2>&1; then echo 'FAIL unsafe combination rendered' >&2; exit 1; fi; echo 'PASS unsafe combination refused'; }
admin=$(render)
[[ "$admin" != *LDAP_REPLICATION_PASSWORD* ]] || { echo 'FAIL admin uses dedicated credential'; exit 1; }
[[ "$admin" == *'value: "admin"'* ]] || exit 1
prepare=$(render --set replication.identity=prepare)
[[ "$prepare" != *LDAP_REPLICATION_PASSWORD* ]] || exit 1
identity=$(render "${dedicated[@]}")
[[ "$identity" == *LDAP_REPLICATION_PASSWORD* && "$identity" == *'name: replication-secret'* && "$identity" == *'value: "dedicated"'* ]] || exit 1
[[ "$identity" != *LDAP_REPLICATION_BIND_DN* ]] || { echo 'FAIL dedicated custom DN'; exit 1; }
refuse --set replication.identity=typo
refuse --set replication.existingSecret=replication-secret
refuse --set replication.identity=prepare --set replication.existingSecret=replication-secret
refuse "${dedicated[@]}" --set tls.enabled=false
refuse "${dedicated[@]}" --set tls.caFile=
refuse "${dedicated[@]}" --set tls.existingSecret=
refuse "${dedicated[@]}" --set replication.existingSecret=
refuse "${dedicated[@]}" --set replication.bindDN=cn=custom
refuse "${dedicated[@]}" --set replication.enabled=false
refuse "${dedicated[@]}" --set replication.existingSecretKey=
echo 'ALL PASS: mode plus Secret combinations'
