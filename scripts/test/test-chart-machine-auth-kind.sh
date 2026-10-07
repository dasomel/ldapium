#!/usr/bin/env bash
# Cluster proof of ui.machineAuth.* (#284, follow-up of #214, change package
# docs/changes/machine-principal-auth): installs the chart on a throwaway kind
# cluster with machine auth ON and checks, against real pods:
#   1. ACL on more than one LDAP node: cn=config olcAccess is per node and is NOT
#      replicated (applied on pod 0 only => pod 1 has no machine rule), then the
#      documented ACL on every node and the machine account's read-only behaviour on each.
#   2. A bearer call through a real ingress-nginx (200, visible in the ingress access log).
#   3. X-Forwarded-For with ui.trustedProxies = the pod CIDR: forged XFF values do not
#      reset the per-IP failure budget (a) through the default ingress, (b) through the
#      ingress with use-forwarded-headers=true once proxy-real-ip-cidr is restricted, (c) straight
#      at a pod from an untrusted peer. Negative control: use-forwarded-headers=true with the
#      default proxy-real-ip-cidr lets forged XFF evade the throttle (the documented precondition).
#   4. Helm replica replacement (docs/machine-auth-operations.md section 2): `helm upgrade`
#      without one client => old pods and old ReplicaSet gone, the SAME pre-upgrade token
#      is 401 token_invalid on every new replica, the client that stays is still 200;
#      then ui.machineAuth.enabled=false => 401 unauthenticated.
#
# The OIDC issuer is a stand-in (nginx serving a static discovery document and JWKS over
# TLS from a throwaway CA; tokens are signed here with openssl). The chart refuses an http
# issuer and has no CA value, so a post-renderer (yq) mounts the CA and sets SSL_CERT_FILE
# on the UI Deployment. The real-Keycloak proof is machine-keycloak-e2e.yml (docker, no kind).
#
# Run (needs docker, kind, kubectl, helm, yq v4 (mikefarah), openssl, curl, python3):
#   docker build -t ldapium:machine-kind image && docker build -t ldapium-ui:machine-kind ui
#   ./scripts/test/test-chart-machine-auth-kind.sh
# Overrides: IMAGE_TAG (default machine-kind), KIND_CLUSTER (default ldapium-mk-<pid>-<random>; an existing cluster of that name is refused, never deleted),
# KEEP_CLUSTER=1 keeps the cluster, INGRESS_MANIFEST. Uses its own KUBECONFIG file; the
# caller's kubeconfig and contexts are never touched. CI: .github/workflows/chart-machine-auth-kind.yml
# (Helm 4.3.0, the version this script was proven on).
# has/check helpers are reached indirectly.
# shellcheck disable=SC2317,SC2329
set -euo pipefail

cd "$(dirname "$0")/../.."

TAG=${IMAGE_TAG:-machine-kind}
CLUSTER=${KIND_CLUSTER:-ldapium-mk-$$-$RANDOM}
created=0 # set only once this run created the cluster; cleanup never deletes any other
INGRESS_MANIFEST=${INGRESS_MANIFEST:-https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.12.1/deploy/static/provider/kind/deploy.yaml}
NS=directory
REL=directory
HOST=ldapium.test
ISSUER_HOST=oidc-issuer.$NS.svc
ISSUER=https://$ISSUER_HOST/realms/kind
AUD=ldapium-api
ROOT=dc=example,dc=org
MACHINE_DN=uid=machine,ou=system,$ROOT
CFG_URI='ldapi://%2Fvar%2Flib%2Fopenldap%2Frun%2Fldapi'

fail=0
ok() { printf 'PASS: %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }
check() {
	local desc=$1
	shift
	if "$@"; then ok "$desc"; else bad "$desc"; fi
}
eq() { [ "$1" = "$2" ]; }
has() { printf '%s\n' "$1" | grep -qF -- "$2"; }
lacks() { ! has "$1" "$2"; }
# retry N CMD...: CMD must succeed within N seconds.
retry() {
	local n=$1 i
	shift
	for ((i = 0; i < n; i++)); do if "$@"; then return 0; fi; sleep 1; done
	return 1
}

tmp=$(mktemp -d)
export KUBECONFIG=$tmp/kubeconfig
pids=()
cleanup() {
	local p
	for p in ${pids[@]+"${pids[@]}"}; do kill "$p" 2>/dev/null || true; done
	if [ "$created" = 1 ] && [ "${KEEP_CLUSTER:-}" != 1 ]; then
		kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
	fi
	rm -rf "$tmp"
}
trap cleanup EXIT
trap "exit 130" INT
trap "exit 143" TERM
trap "exit 129" HUP

for t in docker kind kubectl helm yq openssl curl python3; do
	command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 2; }
done

free_port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
# pf_to TARGET NAMESPACE REMOTE_PORT: background port-forward, sets PF_PORT
pf_to() {
	local target=$1 ns=$2 remote=$3
	PF_PORT=$(free_port)
	kubectl port-forward -n "$ns" "$target" "$PF_PORT:$remote" >/dev/null 2>&1 &
	PF_PID=$!
	pids+=("$PF_PID")
	retry 30 curl -s -o /dev/null "http://127.0.0.1:$PF_PORT/" || { echo "port-forward to $target failed" >&2; return 1; }
}

# --- 1. cluster, images, ingress -------------------------------------------------------
cat >"$tmp/kind.yaml" <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    kubeadmConfigPatches:
      - |
        kind: InitConfiguration
        nodeRegistration:
          kubeletExtraArgs:
            node-labels: "ingress-ready=true"
EOF
if kind get clusters 2>/dev/null | grep -qxF -- "$CLUSTER"; then echo "kind cluster $CLUSTER already exists, refusing to touch it" >&2; exit 2; fi
created=1
kind create cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG" --config "$tmp/kind.yaml" --wait 120s
for img in "ldapium:$TAG" "ldapium-ui:$TAG"; do
	kind load docker-image "$img" --name "$CLUSTER"
done
kubectl apply -f "$INGRESS_MANIFEST" >/dev/null
kubectl wait -n ingress-nginx --for=condition=complete job/ingress-nginx-admission-patch --timeout=240s
kubectl wait -n ingress-nginx --for=condition=ready pod -l app.kubernetes.io/component=controller --timeout=240s
ok "kind cluster $CLUSTER with ingress-nginx is up"

# --- 2. stand-in OIDC issuer over TLS ---------------------------------------------------
kubectl create namespace "$NS" >/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=machine-kind-ca -days 2 -keyout "$tmp/ca.key" -out "$tmp/ca.crt" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=$ISSUER_HOST" -keyout "$tmp/tls.key" -out "$tmp/tls.csr" 2>/dev/null
printf 'subjectAltName=DNS:%s\n' "$ISSUER_HOST" >"$tmp/san.ext"
openssl x509 -req -in "$tmp/tls.csr" -CA "$tmp/ca.crt" -CAkey "$tmp/ca.key" -CAcreateserial -days 2 -extfile "$tmp/san.ext" -out "$tmp/tls.crt" 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=machine-kind-signer -days 2 -keyout "$tmp/sign.key" -out "$tmp/sign.crt" 2>/dev/null

mkdir "$tmp/issuer"
python3 - "$tmp" "$ISSUER" <<'PY'
import base64, json, subprocess, sys
tmp, issuer = sys.argv[1], sys.argv[2]
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=').decode()
mod = subprocess.run(['openssl', 'rsa', '-in', f'{tmp}/sign.key', '-noout', '-modulus'], capture_output=True, text=True,
                     check=True).stdout.strip().split('=')[1]
jwks = {'keys': [{'kty': 'RSA', 'kid': 'kind-1', 'use': 'sig', 'alg': 'RS256', 'n': b64u(bytes.fromhex(mod)), 'e': 'AQAB'}]}
disc = {'issuer': issuer, 'jwks_uri': issuer + '/protocol/openid-connect/certs',
        'authorization_endpoint': issuer + '/protocol/openid-connect/auth',
        'token_endpoint': issuer + '/protocol/openid-connect/token',
        'id_token_signing_alg_values_supported': ['RS256'], 'response_types_supported': ['code'],
        'subject_types_supported': ['public']}
json.dump(jwks, open(f'{tmp}/issuer/jwks.json', 'w'))
json.dump(disc, open(f'{tmp}/issuer/discovery.json', 'w'))
PY
cat >"$tmp/issuer/default.conf" <<'EOF'
server {
  listen 443 ssl;
  ssl_certificate /tls/tls.crt;
  ssl_certificate_key /tls/tls.key;
  default_type application/json;
  root /srv;
}
EOF
kubectl -n "$NS" create secret tls issuer-tls --cert="$tmp/tls.crt" --key="$tmp/tls.key" >/dev/null
kubectl -n "$NS" create configmap issuer-ca --from-file=ca.crt="$tmp/ca.crt" >/dev/null
kubectl -n "$NS" create configmap issuer-files --from-file="$tmp/issuer/jwks.json" --from-file="$tmp/issuer/discovery.json" \
	--from-file="$tmp/issuer/default.conf" >/dev/null
kubectl -n "$NS" apply -f - >/dev/null <<EOF
apiVersion: apps/v1
kind: Deployment
metadata: {name: oidc-issuer}
spec:
  replicas: 1
  selector: {matchLabels: {app: oidc-issuer}}
  template:
    metadata: {labels: {app: oidc-issuer}}
    spec:
      containers:
        - name: nginx
          image: nginx:alpine
          imagePullPolicy: IfNotPresent
          ports: [{containerPort: 443}]
          volumeMounts:
            - {name: tls, mountPath: /tls, readOnly: true}
            - {name: files, mountPath: /etc/nginx/conf.d/default.conf, subPath: default.conf}
            - {name: files, mountPath: /srv/realms/kind/.well-known/openid-configuration, subPath: discovery.json}
            - {name: files, mountPath: /srv/realms/kind/protocol/openid-connect/certs, subPath: jwks.json}
      volumes:
        - {name: tls, secret: {secretName: issuer-tls}}
        - {name: files, configMap: {name: issuer-files}}
---
apiVersion: v1
kind: Service
metadata: {name: oidc-issuer}
spec:
  selector: {app: oidc-issuer}
  ports: [{port: 443, targetPort: 443}]
EOF
kubectl -n "$NS" rollout status deploy/oidc-issuer --timeout=120s

# mint CLIENT [TTL]: an RS256 service-account token the stand-in issuer's key signs.
mint() {
	python3 - "$tmp" "$ISSUER" "$AUD" "$1" "${2:-1200}" <<'PY'
import base64, json, subprocess, sys, time
tmp, issuer, aud, client, ttl = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=').decode()
now = int(time.time())
claims = {'typ': 'Bearer', 'iss': issuer, 'aud': aud, 'azp': client, 'client_id': client,
          'preferred_username': 'service-account-' + client, 'sub': 'sub-' + client,
          'scope': 'directory.users.read directory.groups.read', 'iat': now, 'exp': now + ttl}
si = b64u(json.dumps({'alg': 'RS256', 'typ': 'JWT', 'kid': 'kind-1'}).encode()) + '.' + b64u(json.dumps(claims).encode())
sig = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', f'{tmp}/sign.key'], input=si.encode(), capture_output=True,
                     check=True).stdout
print(si + '.' + b64u(sig))
PY
}

# --- 3. chart install -------------------------------------------------------------------
head -c 24 /dev/urandom | base64 | tr -d '\n=' >"$tmp/admin.pw"
openssl rand -base64 33 | tr -d '\n' >"$tmp/machine.pw"
kubectl -n "$NS" create secret generic machine-ldap --from-file=machine-ldap-bind-password="$tmp/machine.pw" >/dev/null

# Mounts the stand-in CA into the UI pods and points Go at it; applied on every helm
# install/upgrade so replacement pods keep trusting the issuer.
cat >"$tmp/post-render.sh" <<'EOF'
#!/usr/bin/env bash
exec yq eval '
  (select(.kind == "Deployment") | .spec.template.spec.volumes) += [{"name": "issuer-ca", "configMap": {"name": "issuer-ca"}}] |
  (select(.kind == "Deployment") | .spec.template.spec.containers[0].volumeMounts) += [{"name": "issuer-ca", "mountPath": "/issuer-ca", "readOnly": true}] |
  (select(.kind == "Deployment") | .spec.template.spec.containers[0].env) += [{"name": "SSL_CERT_FILE", "value": "/issuer-ca/ca.crt"}]' -
EOF
chmod +x "$tmp/post-render.sh"
# Helm 3 takes the executable path; Helm 4 only accepts a postrenderer plugin name, so wrap it
# in a throwaway plugin directory (HELM_PLUGINS points at it; the user's plugins are untouched).
post_renderer=$tmp/post-render.sh
if [ "$(helm version --template '{{.Version}}' | cut -c2)" -ge 4 ]; then
	mkdir -p "$tmp/plugins/machine-ca"
	printf 'apiVersion: v1\nname: machine-ca\nversion: 0.1.0\ntype: postrenderer/v1\nruntime: subprocess\nruntimeConfig:\n  platformCommand:\n    - command: %s\n' "$tmp/post-render.sh" >"$tmp/plugins/machine-ca/plugin.yaml"
	export HELM_PLUGINS=$tmp/plugins
	post_renderer=machine-ca
fi

cat >"$tmp/values.yaml" <<EOF
image: {repository: ldapium, tag: $TAG, pullPolicy: Never}
replicaCount: 2
ui:
  enabled: true
  replicaCount: 2
  image: {repository: ldapium-ui, tag: $TAG, pullPolicy: Never}
  trustedProxies: 10.244.0.0/16
  ingress:
    enabled: true
    className: nginx
    hosts:
      - host: $HOST
        paths: [{path: /, pathType: Prefix}]
  machineAuth:
    enabled: true
    issuerURL: $ISSUER
    audience: $AUD
    allowedClients:
      - {id: svc-drill, scopes: [directory.users.read, directory.groups.read]}
      - {id: svc-other, scopes: [directory.users.read, directory.groups.read]}
    ldapBindDN: $MACHINE_DN
    existingSecret: machine-ldap
    tokenMaxTTL: 30m
    authFailureLimit: 3
    authFailureWindow: 20s
    rateLimit: {rps: 100, burst: 100}
EOF
# Generated throwaway secrets go through a 0600 values file, not helm's argv.
(umask 077; printf 'auth:\n  adminPassword: "%s"\nui:\n  session:\n    secret: "%s"\n' "$(cat "$tmp/admin.pw")" "$(head -c 32 /dev/urandom | base64 | tr -d '\n=')" >"$tmp/secrets.yaml")
helm_install() {
	helm "$1" "$REL" charts/ldapium -n "$NS" -f "$tmp/values.yaml" "${@:2}" \
		-f "$tmp/secrets.yaml" \
		--post-renderer "$post_renderer" --wait --timeout 6m
}
helm_install install
ok "chart installed with ui.machineAuth.enabled=true (2 LDAP pods, 2 UI pods)"

ldap_pods() { kubectl get pods -n "$NS" -o name | sed 's#pod/##' | grep -E -- "-ldapium-[0-9]+$" | sort; }
ui_pods() { kubectl get pods -n "$NS" -l app.kubernetes.io/component=ui --field-selector=status.phase=Running -o name | sed 's#pod/##' | sort; }
IFS=$'\n' read -r -d '' -a LDAP < <(ldap_pods) || true
check "two LDAP pods exist" eq "${#LDAP[@]}" 2
lx() { local pod=$1; shift; kubectl exec -i -n "$NS" "$pod" -- "$@"; }
put_pw() { lx "$1" sh -c "umask 077; cat > $2" <"$3"; }

# --- 4. machine account, then the ACL node by node ---------------------------------------
for p in "${LDAP[@]}"; do put_pw "$p" /tmp/.pw-admin "$tmp/admin.pw"; put_pw "$p" /tmp/.pw-machine "$tmp/machine.pw"; done
adm() { lx "$1" ldapadd -c -x -H ldap://127.0.0.1 -D "cn=admin,$ROOT" -y /tmp/.pw-admin; }
printf 'dn: ou=system,%s\nobjectClass: organizationalUnit\nou: system\n\ndn: ou=people,%s\nobjectClass: organizationalUnit\nou: people\n' "$ROOT" "$ROOT" | adm "${LDAP[0]}" >/dev/null || true
{
	printf 'dn: %s\nobjectClass: inetOrgPerson\nuid: machine\ncn: machine\nsn: machine\nuserPassword:: %s\n\n' "$MACHINE_DN" "$(base64 <"$tmp/machine.pw" | tr -d '\n')"
	printf 'dn: uid=u01,ou=people,%s\nobjectClass: inetOrgPerson\nuid: u01\ncn: u01\nsn: u01\nuserPassword: seeded-secret-1\n' "$ROOT"
} | adm "${LDAP[0]}" >/dev/null
node_has_machine() { lx "$1" ldapsearch -x -H ldap://127.0.0.1 -D "cn=admin,$ROOT" -y /tmp/.pw-admin -LLL -b "$MACHINE_DN" -s base dn 2>/dev/null | grep -q '^dn:'; }
check "the machine account replicated to LDAP pod 1" retry 90 node_has_machine "${LDAP[1]}"

main_db() { lx "$1" sh -c "ldapsearch -x -H '$CFG_URI' -D cn=admin,cn=config -y /tmp/.pw-admin -LLL -b cn=config '(olcSuffix=$ROOT)' dn" | sed -n 's/^dn: //p'; }
rules() { lx "$1" sh -c "ldapsearch -x -H '$CFG_URI' -D cn=admin,cn=config -y /tmp/.pw-admin -LLL -b '$(main_db "$1")' -s base olcAccess" | awk '/^ /{sub(/^ /,""); printf "%s",$0; next} NR>1{print ""} {printf "%s",$0} END{print ""}' | sed -n 's/^olcAccess: //p'; }
apply_acl() {
	local db
	db=$(main_db "$1")
	sed -e "s#@MACHINE_DN@#$MACHINE_DN#g" -e "s#@ALLOWED_DN@#$ROOT#g" -e "s#@MAIN_DB_DN@#$db#g" \
		scripts/test/fixtures/machine-acl/main-database.ldif |
		lx "$1" ldapmodify -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin >/dev/null
}
apply_acl "${LDAP[0]}"
r0=$(rules "${LDAP[0]}")
r1=$(rules "${LDAP[1]}")
check "ACL applied on pod 0: rules {0}-{2} name the machine DN" eq "$(printf '%s\n' "$r0" | grep -c "$MACHINE_DN")" 3
# the query on pod 1 must have worked (it lists the image's own {0} rule) before "no machine rule" means anything
check "pod 1 olcAccess was read (positive evidence: it lists its own rules)" has "$r1" '{0}to '
check "ACL is per node: pod 1 has no machine rule after pod 0 got it (cn=config is not replicated)" eq "$(printf '%s\n' "$r1" | grep -c "$MACHINE_DN" || true)" 0
apply_acl "${LDAP[1]}"
for p in "${LDAP[@]}"; do
	r=$(rules "$p")
	check "$p: olcAccess was read" has "$r" "{0}"
	check "$p: olcAccess {0}, {1}, {2} are the machine rules" eq "$(printf '%s\n' "$r" | head -n 3 | grep -c "$MACHINE_DN")" 3
	check "$p: {0} is the secret-attribute rule" has "$(printf '%s\n' "$r" | head -n 1)" '{0}to attrs=userPassword'
	out=$(lx "$p" ldapsearch -x -H ldap://127.0.0.1 -D "$MACHINE_DN" -y /tmp/.pw-machine -LLL -b "$ROOT" '(uid=u01)' uid userPassword)
	check "$p: machine reads the entry" has "$out" 'uid: u01'
	check "$p: machine never sees userPassword" lacks "$out" 'userPassword'
	adm_out=$(lx "$p" ldapsearch -x -H ldap://127.0.0.1 -D "cn=admin,$ROOT" -y /tmp/.pw-admin -LLL -b "$ROOT" '(uid=u01)' userPassword)
	check "$p: control, the attribute exists for the admin" has "$adm_out" 'userPassword'
	rc=0
	printf 'dn: uid=u01,ou=people,%s\nchangetype: modify\nreplace: description\ndescription: x\n' "$ROOT" |
		lx "$p" ldapmodify -x -H ldap://127.0.0.1 -D "$MACHINE_DN" -y /tmp/.pw-machine >/dev/null 2>&1 || rc=$?
	check "$p: machine write to another entry is refused (rc 50)" eq "$rc" 50
	rc=0
	printf 'dn: %s\nchangetype: modify\nreplace: userPassword\nuserPassword: Another-Passw0rd-xyz\n' "$MACHINE_DN" |
		lx "$p" ldapmodify -x -H ldap://127.0.0.1 -D "$MACHINE_DN" -y /tmp/.pw-machine >/dev/null 2>&1 || rc=$?
	check "$p: machine cannot change its own password (rc 50)" eq "$rc" 50
done

# --- 5. bearer call through the real ingress --------------------------------------------
pf_to svc/ingress-nginx-controller ingress-nginx 80
ING=$PF_PORT
# call PORT TOKEN [curl args]: prints "<status> <code>" ("-" when the body has no code)
call() {
	local port=$1 tok=$2 body code
	shift 2
	# the token goes through a header file (printf is a builtin), never curl's argv
	(umask 077; printf 'Authorization: Bearer %s\n' "$tok" >"$tmp/hdr")
	body=$(curl -sS -m 20 -o - -w '\n%{http_code}' -H "Host: $HOST" -H @"$tmp/hdr" "$@" "http://127.0.0.1:$port/api/users?limit=1")
	code=$(printf '%s' "$body" | sed '$d' | grep -o '"code":"[a-z_]*"' | head -n 1 | cut -d'"' -f4 || true)
	printf '%s %s\n' "$(printf '%s' "$body" | tail -n 1)" "${code:--}"
}
T_DRILL=$(mint svc-drill)
T_OTHER=$(mint svc-other)
check "allowed bearer -> 200 through the ingress" eq "$(call "$ING" "$T_DRILL")" '200 -'
check "the request is in the ingress access log" retry 20 sh -c "kubectl logs -n ingress-nginx -l app.kubernetes.io/component=controller --tail=200 | grep -q 'GET /api/users?limit=1.*200'"

# --- 6. X-Forwarded-For --------------------------------------------------------------------
# 10 forged values; limit 3 per pod, 2 pods: a working throttle ends in 429 after at most
# 6 x 401. A forged XFF that reset the budget would keep returning 401 forever.
flood() {
	local port=$1 i st
	local bad=${T_DRILL%????}AAAA
	N401=0 FIRST429=0 LAST=
	for i in $(seq 1 10); do
		st=$(call "$port" "$bad" -H "X-Forwarded-For: 203.0.113.$i")
		LAST=${st%% *}
		if [ "$LAST" = 401 ]; then N401=$((N401 + 1)); fi
		if [ "$LAST" = 429 ] && [ "$FIRST429" = 0 ]; then FIRST429=$i; fi
	done
	echo "  flood: 401 x$N401, first 429 at request $FIRST429, last status $LAST"
}
held() { [ "$N401" -le 6 ] && [ "$FIRST429" -ge 1 ] && [ "$LAST" = 429 ]; }
# ingress_cfg JSON present|absent PATTERN: patch the controller ConfigMap, then poll (60 s) until the
# rendered nginx config has (or lacks) the extended regex PATTERN, instead of sleeping a fixed time.
ingress_cfg() {
	local json=$1 mode=$2 pat=$3 i cfg
	kubectl -n ingress-nginx patch configmap ingress-nginx-controller --type merge -p "{\"data\":$json}" >/dev/null
	for ((i = 0; i < 60; i++)); do
		cfg=$(kubectl exec -n ingress-nginx deploy/ingress-nginx-controller -- nginx -T 2>/dev/null || true)
		if { [ "$mode" = present ] && printf '%s\n' "$cfg" | grep -qE -- "$pat"; } || { [ "$mode" = absent ] && ! printf '%s\n' "$cfg" | grep -qE -- "$pat"; }; then
			sleep 3 # the reload that follows the config write
			return 0
		fi
		sleep 1
	done
	echo "ingress config never became effective ($mode $pat)" >&2
	return 1
}
flood "$ING"
check "default ingress (overwrites XFF): 10 forged XFF values do not reset the budget" held
sleep 25
# Negative control = the documented precondition (docs/machine-auth-operations.md section 5.3):
# use-forwarded-headers=true with the default proxy-real-ip-cidr (0.0.0.0/0) makes nginx trust the
# client's own X-Forwarded-For, so the ingress no longer sanitizes it and every forged value is a new IP.
ingress_cfg '{"use-forwarded-headers":"true"}' present 'real_ip_header +X-Forwarded-For'
flood "$ING"
check "negative control, ingress trusting client XFF (use-forwarded-headers=true): the throttle IS evaded (10 x 401, never 429)" eq "$N401" 10
ingress_cfg '{"use-forwarded-headers":"true","proxy-real-ip-cidr":"192.0.2.0/24"}' present 'set_real_ip_from +192[.]0[.]2[.]0/24'
sleep 25
flood "$ING"
check "use-forwarded-headers=true with proxy-real-ip-cidr limited to the real upstream: budget holds again" held
ingress_cfg '{"use-forwarded-headers":"false","proxy-real-ip-cidr":null}' absent 'real_ip_header +X-Forwarded-For'
sleep 25
IFS=$'\n' read -r -d '' -a UI < <(ui_pods) || true
check "two UI pods are running" eq "${#UI[@]}" 2
CPORT=$(kubectl get pod -n "$NS" "${UI[0]}" -o jsonpath='{.spec.containers[0].ports[0].containerPort}')
pf_to "pod/${UI[0]}" "$NS" "$CPORT"
check "direct to a pod (untrusted peer 127.0.0.1): forged XFF does not reset the budget" eq "$(
	b=${T_DRILL%????}AAAA
	for i in 1 2 3 4; do call "$PF_PORT" "$b" -H "X-Forwarded-For: 198.51.100.$i"; done | tr '\n' ' '
)" '401 token_invalid 401 token_invalid 401 token_invalid 429 machine_rate_limited '
sleep 25

# --- 7. Helm replica replacement -------------------------------------------------------------
for p in "${UI[@]}"; do
	pf_to "pod/$p" "$NS" "$CPORT"
	check "before: svc-drill token -> 200 on $p" eq "$(call "$PF_PORT" "$T_DRILL")" '200 -'
done
OLD_UI=("${UI[@]}")
OLD_RS=$(kubectl get rs -n "$NS" -l app.kubernetes.io/component=ui -o jsonpath='{.items[?(@.status.replicas>0)].metadata.name}')
sleep 22 # per-pod failure budgets from the checks above drain
cat >"$tmp/revoke.yaml" <<EOF
ui:
  machineAuth:
    allowedClients:
      - {id: svc-other, scopes: [directory.users.read, directory.groups.read]}
EOF
helm_install upgrade -f "$tmp/revoke.yaml"
kubectl rollout status deploy -n "$NS" -l app.kubernetes.io/component=ui --timeout=180s
# NotFound is the only "deleted"; an unreachable API or any other error keeps the poll failing.
gone() {
	local p out
	for p in "${OLD_UI[@]}"; do
		if out=$(kubectl get pod -n "$NS" "$p" 2>&1); then return 1; fi
		has "$out" '(NotFound)' || return 1
	done
}
check "old UI pods are gone" retry 120 gone
check "old ReplicaSet is scaled to 0" eq "$(kubectl get rs -n "$NS" "$OLD_RS" -o jsonpath='{.status.replicas}')" 0
IFS=$'\n' read -r -d '' -a UI < <(ui_pods) || true
check "two new UI pods run" eq "${#UI[@]}" 2
check "terminationGracePeriodSeconds on the pods is 30" eq "$(kubectl get pod -n "$NS" "${UI[0]}" -o jsonpath='{.spec.terminationGracePeriodSeconds}')" 30
for p in "${UI[@]}"; do
	pf_to "pod/$p" "$NS" "$CPORT"
	check "after helm upgrade: the SAME svc-drill token -> 401 token_invalid on $p" eq "$(call "$PF_PORT" "$T_DRILL")" '401 token_invalid'
	check "after helm upgrade: svc-other (still allowed) -> 200 on $p" eq "$(call "$PF_PORT" "$T_OTHER")" '200 -'
done
check "through the ingress: svc-drill 401, svc-other 200" eq "$(call "$ING" "$T_DRILL"; call "$ING" "$T_OTHER")" "$(printf '401 token_invalid\n200 -')"

helm_install upgrade -f "$tmp/revoke.yaml" --set ui.machineAuth.enabled=false
kubectl rollout status deploy -n "$NS" -l app.kubernetes.io/component=ui --timeout=180s
sleep 5
check "machine auth off: bearer is ignored, 401 unauthenticated (ingress)" eq "$(call "$ING" "$T_OTHER")" '401 unauthenticated'

echo
if [ "$fail" = 0 ]; then echo "ALL PASS"; else echo "FAILURES" >&2; fi
exit "$fail"
