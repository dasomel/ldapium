#!/usr/bin/env bash
# Kubernetes / StatefulSet verification of the dedicated replication identity
# (docs/changes/replication-identity, #353, T-022/T-024, AC-004). The chart is installed in
# the CURRENT kube context (a throwaway kind cluster with the image loaded; replication-chaos-e2e.yml
# creates one), 3 replicas, default OrderedReady, verified TLS: admin -> prepare -> operator ensure ->
# dedicated, all through helm upgrades. Then:
#   K1 a deleted pod-0 returns Ready on its own while pods 1 and 2 keep serving (no peer wait)
#   K2 ALL pods deleted at once: OrderedReady starts pod-0 alone, it becomes Ready without peers,
#      the others follow, data and hashes are intact on every pod
#   K3 the DATA claim of pod-1 is lost while its CONFIG claim survives: the pod crash-loops (refusal,
#      nothing created, peers untouched); deleting BOTH claims recovers it from the peers
#
# Usage: scripts/test/test-replication-identity-k8s.sh [image]   (default ldapium:e2e, imagePullPolicy Never)
#   RIDK8S_TIMEOUT (seconds, default 300) bounds every wait. The namespace ridk8s-* is removed on exit.
set -euo pipefail
# Never pipe into `grep -q` (SIGPIPE + pipefail): match captured variables.

image="${1:-ldapium:e2e}"
repo="${image%:*}"
tag="${image##*:}"
here="$(cd "$(dirname "$0")/.." && pwd)"
chart="$(cd "$here/.." && pwd)/charts/ldapium"
timeout_s="${RIDK8S_TIMEOUT:-300}"
ns="ridk8s-$$"
rel=rid
full=rid-ldapium
headless=rid-ldapium-headless
pw="ridk8sAdminPw-Zq7Lm2Xv9Kd4Hs8Wt1Bn6Rc3Yf5Ug0Pe"
alicepw="ridk8sAlicePw-1"
base="dc=example,dc=org"
admin="cn=admin,${base}"
iddn="cn=replicator,${base}"
work="$(mktemp -d)"

fail=0
ok() { printf 'PASS: %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: expected '$2', got '$3'"; fi; }
# shellcheck disable=SC2317,SC2329 # invoked via the trap below
cleanup() {
  local rc=$?
  trap - EXIT
  if [ "$rc" != 0 ]; then
    kubectl -n "$ns" get pods -o wide >&2 2>&1 || true
    kubectl -n "$ns" logs "${full}-0" -c openldap --tail=15 >&2 2>&1 || true
  fi
  helm uninstall "$rel" --namespace "$ns" >/dev/null 2>&1 || true
  kubectl delete namespace "$ns" --wait=false >/dev/null 2>&1 || true
  rm -rf "$work"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

poll() { local w=0; until "$@" >/dev/null 2>&1; do sleep 2; w=$((w + 2)); [ "$w" -lt "$timeout_s" ] || return 1; done; }
lx() { local p="$1"; shift; kubectl -n "$ns" exec -c openldap "$p" -- "$@"; }
lxi() { local p="$1"; shift; kubectl -n "$ns" exec -i -c openldap "$p" -- "$@"; }
asearch() { local p="$1"; shift; lx "$p" ldapsearch -x -LLL -o ldif-wrap=no -H ldap://localhost -D "$admin" -w "$pw" "$@"; }
pod() { printf '%s-%s' "$full" "$1"; }
# shellcheck disable=SC2317,SC2329 # invoked through poll
pod_ready() { [ "$(kubectl -n "$ns" get pod "$1" -o jsonpath='{.status.containerStatuses[?(@.name=="openldap")].ready}' 2>/dev/null)" = true ]; }
# shellcheck disable=SC2317,SC2329 # invoked through poll
has_uid() { local o; o="$(asearch "$1" -b "$base" "(uid=$2)" uid)" || return 1; case "$o" in *"uid: $2"*) return 0 ;; *) return 1 ;; esac; }
uid_count() { local o; o="$(asearch "$1" -b "$base" '(objectClass=inetOrgPerson)' uid)" || { echo "?"; return; }; grep -c '^uid: ' <<<"$o" || true; }
hash_of() { local o; o="$(asearch "$1" -b "$base" "(uid=$2)" userPassword)" || return 1; sed -n 's/^userPassword:: *//p;s/^userPassword: *//p' <<<"$o" | head -n 1; }
add_user() {
  lxi "$1" ldapadd -x -H ldap://localhost -D "$admin" -w "$pw" >/dev/null <<EOF
dn: uid=$2,${base}
objectClass: inetOrgPerson
uid: $2
cn: $2
sn: $2
userPassword: ${alicepw}
EOF
}
binds() { local o; o="$(lx "$1" slapcat -n 0 -o ldif-wrap=no)" || { echo "?"; return; }; grep -c "^olcSyncrepl:.*binddn=\"$2\"" <<<"$o" || true; }
helm_set() { # extra --set args: upgrade the release in place
  helm upgrade "$rel" "$chart" --namespace "$ns" --reuse-values --wait --timeout "${timeout_s}s" "$@" >/dev/null
}
all_ready() { local i; for i in 0 1 2; do pod_ready "$(pod "$i")" || return 1; done; }

echo "== setup: chart install (admin, 3 replicas, verified TLS), then prepare -> ensure -> dedicated"
(
  cd "$work"
  printf 'subjectAltName=DNS:*.%s.%s.svc.cluster.local,DNS:localhost\n' "$headless" "$ns" > ext.cnf
  openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 2 -subj /CN=ridk8s-ca 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -keyout tls.key -out s.csr -subj /CN=localhost 2>/dev/null
  openssl x509 -req -in s.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out tls.crt -days 2 -extfile ext.cnf 2>/dev/null
)
kubectl create namespace "$ns" >/dev/null
kubectl -n "$ns" create secret generic server-tls --from-file=tls.crt="$work/tls.crt" --from-file=tls.key="$work/tls.key" --from-file=ca.crt="$work/ca.crt" >/dev/null
helm install "$rel" "$chart" --namespace "$ns" --wait --timeout "${timeout_s}s" \
  --set image.repository="$repo" --set image.tag="$tag" --set image.pullPolicy=Never \
  --set auth.adminPassword="$pw" --set replicaCount=3 --set ui.enabled=false \
  --set tls.enabled=true --set tls.existingSecret=server-tls --set tls.caFile=/etc/openldap/tls/ca.crt >/dev/null
check "OrderedReady is the StatefulSet policy" "OrderedReady" "$(kubectl -n "$ns" get sts "$full" -o jsonpath='{.spec.podManagementPolicy}')"
for u in alice bob; do add_user "$(pod 0)" "$u"; done
for i in 1 2; do poll has_uid "$(pod "$i")" bob || bad "admin: bob never reached pod-$i"; done
helm_set --set replication.identity=prepare
all_ready || bad "prepare: not every pod is Ready"
kubectl -n "$ns" exec -i -c openldap "$(pod 0)" -- sh -c 'cat > /tmp/ri.sh' < "${here}/replication-identity.sh"
printf '%s' "$pw" | lxi "$(pod 0)" sh -c 'umask 077; cat > /tmp/admin.pw'
p0fqdn="$(pod 0).${headless}.${ns}.svc.cluster.local"
ens_rc=0
lx "$(pod 0)" env LDAPTLS_CACERT=/etc/openldap/tls/ca.crt bash /tmp/ri.sh ensure --uri "ldaps://${p0fqdn}:636" --base "$base" \
  --admin-password-file /tmp/admin.pw --out /tmp/idpw >"$work/ensure.out" 2>&1 || ens_rc=$?
check "operator ensure through the pod" 0 "$ens_rc"
lx "$(pod 0)" cat /tmp/idpw > "$work/idpw"
kubectl -n "$ns" create secret generic repl --from-file=replication-password="$work/idpw" >/dev/null
for i in 1 2; do poll has_uid "$(pod "$i")" alice || bad "prepare: alice never reached pod-$i"; done
helm_set --set replication.identity=dedicated --set replication.existingSecret=repl
all_ready || bad "dedicated: not every pod is Ready"
for i in 0 1 2; do
  check "dedicated pod-$i: consumers bind as the identity only" "2:0" "$(binds "$(pod "$i")" "$iddn"):$(binds "$(pod "$i")" "$admin")"
done
add_user "$(pod 1)" carol
for i in 0 2; do poll has_uid "$(pod "$i")" carol || bad "dedicated: carol never reached pod-$i"; done
check "dedicated: the chart renders no administrator replication credential (env)" "0" \
  "$(kubectl -n "$ns" get pod "$(pod 0)" -o jsonpath='{.spec.containers[?(@.name=="openldap")].env[*].name}' | tr ' ' '\n' | grep -c -x 'LDAP_REPLICATION_BIND_DN' || true)"
want_hash="$(hash_of "$(pod 0)" alice)"

echo "== K1: pod-0 deleted: Ready again without waiting for peers"
kubectl -n "$ns" delete pod "$(pod 0)" --wait=true >/dev/null
poll pod_ready "$(pod 0)" || bad "K1: pod-0 never Ready after deletion"
check "K1: pods 1 and 2 stayed Ready" "true:true" "$(pod_ready "$(pod 1)" && echo true):$(pod_ready "$(pod 2)" && echo true)"
poll has_uid "$(pod 0)" carol || bad "K1: pod-0 lost carol"
check "K1: pod-0 has the same user count and hash as pod-1" "3:$want_hash" "$(uid_count "$(pod 0)"):$(hash_of "$(pod 0)" alice)"

echo "== K2: every pod deleted at once; OrderedReady restarts pod-0 first, alone"
old_uids="$(for i in 0 1 2; do kubectl -n "$ns" get pod "$(pod "$i")" -o jsonpath='{.metadata.uid}'; echo; done)"
kubectl -n "$ns" delete pod --all --wait=false >/dev/null
# a terminating old pod can still report Ready: only pods with a NEW uid count
# shellcheck disable=SC2317,SC2329 # invoked through poll
new_and_ready() { local i u; for i in 0 1 2; do u="$(kubectl -n "$ns" get pod "$(pod "$i")" -o jsonpath='{.metadata.uid}' 2>/dev/null)"; [ -n "$u" ] && ! grep -q -x "$u" <<<"$old_uids" && pod_ready "$(pod "$i")" || return 1; done; }
poll new_and_ready || bad "K2: the StatefulSet did not recover all pods (OrderedReady deadlock?)"
for i in 0 1 2; do poll has_uid "$(pod "$i")" carol || bad "K2: pod-$i lost carol"; done
check "K2: every pod holds all 3 users and the same hash" "3:3:3:1" \
  "$(uid_count "$(pod 0)"):$(uid_count "$(pod 1)"):$(uid_count "$(pod 2)"):$(for i in 0 1 2; do hash_of "$(pod "$i")" alice; done | sort -u | grep -c .)"
check "K2: the identity binds again on every pod (no err=49 in the pod logs)" "0:0:0" \
  "$(for i in 0 1 2; do kubectl -n "$ns" logs "$(pod "$i")" -c openldap 2>&1 | grep -c 'err=49' || true; done | tr '\n' ':' | sed 's/:$//')"

echo "== K3: pod-1 loses its DATA claim, its CONFIG claim survives"
fp="$(for i in 0 2; do asearch "$(pod "$i")" -b "$base" '(objectClass=*)' entryCSN | sort | cksum; done | cksum)"
kubectl -n "$ns" delete pvc "data-${full}-1" --wait=false >/dev/null
kubectl -n "$ns" delete pod "$(pod 1)" --wait=true >/dev/null
# shellcheck disable=SC2317,SC2329 # invoked through poll
crashing() { [ "$(kubectl -n "$ns" get pod "$(pod 1)" -o jsonpath='{.status.containerStatuses[?(@.name=="openldap")].restartCount}' 2>/dev/null || echo 0)" -ge 1 ]; }
if poll crashing; then ok "K3: pod-1 restarts (the stored database directory is gone: the image refuses the configuration)"; else bad "K3: pod-1 never crash-looped"; fi
check "K3: ... and is not Ready" "no" "$(pod_ready "$(pod 1)" && echo yes || echo no)"
check "K3: the failed starts changed nothing on the peers" "$fp" "$(for i in 0 2; do asearch "$(pod "$i")" -b "$base" '(objectClass=*)' entryCSN | sort | cksum; done | cksum)"
kubectl -n "$ns" delete pvc "config-${full}-1" "data-${full}-1" --wait=false >/dev/null 2>&1 || true
kubectl -n "$ns" delete pod "$(pod 1)" --wait=true >/dev/null
poll pod_ready "$(pod 1)" || bad "K3: pod-1 never Ready after both claims were recreated"
poll has_uid "$(pod 1)" carol || bad "K3: pod-1 never refilled carol"
check "K3: recovered from the peers: 3 users, same hash, same base entry" "3:$want_hash:1" \
  "$(uid_count "$(pod 1)"):$(hash_of "$(pod 1)" alice):$(for i in 0 1 2; do asearch "$(pod "$i")" -b "$base" -s base entryUUID | sed -n 's/^entryUUID: //p'; done | sort -u | grep -c .)"

if [ "$fail" = 0 ]; then echo 'ALL PASS: dedicated replication identity on a StatefulSet (OrderedReady recovery, data-claim loss)'; else exit 1; fi
