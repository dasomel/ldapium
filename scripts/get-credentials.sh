#!/usr/bin/env bash
# Print the admin credentials for an openldap-suite release running in
# Kubernetes.
#
# There is no such thing as a generated "initial password" in this project:
# the image refuses to start without LDAP_ADMIN_PASSWORD and the chart refuses
# to render without auth.adminPassword or auth.existingSecret. This script
# reads back whatever was supplied at install time.
#
# Discovery works off the running StatefulSet rather than off chart values, so
# it is correct whether the password lives in a chart-created Secret or in a
# pre-existing one referenced by auth.existingSecret — it follows the actual
# secretKeyRef the server container is using.
#
#   ./scripts/get-credentials.sh                     # auto-discover in current namespace
#   ./scripts/get-credentials.sh -n openldap-suite   # explicit namespace
#   ./scripts/get-credentials.sh -n ns -r ols        # explicit release/StatefulSet
#   ./scripts/get-credentials.sh --password-only     # just the password, for scripts
set -euo pipefail

ns=""
sts=""
password_only=0

usage() {
  cat <<'EOF'
Usage: get-credentials.sh [-n NAMESPACE] [-r RELEASE] [--password-only]

  -n, --namespace   Kubernetes namespace (default: current kubectl context's)
  -r, --release     Helm release name. Only needed when a namespace holds more
                    than one openldap-suite install.
      --password-only
                    Print only the password, with no trailing newline and no
                    other output. For command substitution:
                      -w "$(get-credentials.sh --password-only)"
  -h, --help        This text.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    -n|--namespace) ns="${2:?-n needs a namespace}"; shift 2 ;;
    -r|--release)   sts="${2:?-r needs a release name}"; shift 2 ;;
    --password-only) password_only=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown argument: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

command -v kubectl >/dev/null 2>&1 || { echo "kubectl not found on PATH" >&2; exit 1; }

if [ -z "$ns" ]; then
  ns=$(kubectl config view --minify --output 'jsonpath={..namespace}' 2>/dev/null || true)
  ns="${ns:-default}"
fi

# The chart labels its StatefulSet app.kubernetes.io/name=openldap. Finding it
# by label rather than by "<release>-openldap" survives nameOverride and
# fullnameOverride.
if [ -z "$sts" ]; then
  found=$(kubectl -n "$ns" get statefulset -l app.kubernetes.io/name=openldap \
            -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null || true)
  count=$(printf '%s' "$found" | grep -c . || true)
  case "$count" in
    0) echo "no openldap-suite StatefulSet found in namespace '${ns}'." >&2
       echo "Pass -n NAMESPACE, or -r RELEASE if it is labelled differently." >&2
       exit 1 ;;
    1) sts=$(printf '%s' "$found" | head -1) ;;
    *) echo "found more than one openldap-suite StatefulSet in '${ns}':" >&2
       printf '%s\n' "$found" | sed 's/^/  /' >&2
       echo "Disambiguate with -r RELEASE." >&2
       exit 1 ;;
  esac
else
  # Accept either the release name or the full StatefulSet name.
  kubectl -n "$ns" get statefulset "$sts" >/dev/null 2>&1 || sts="${sts}-openldap"
  kubectl -n "$ns" get statefulset "$sts" >/dev/null 2>&1 || {
    echo "no StatefulSet '${sts}' in namespace '${ns}'." >&2; exit 1; }
fi

# NOTE: keep every jsonpath on ONE line. A jsonpath template written across
# two lines emits that newline into the result, and the value silently comes
# back as "\nols-openldap-admin" — which then fails to match a Secret name.
get_env() { # get_env <ENV_NAME> — value of a plain (non-secretKeyRef) env var
  kubectl -n "$ns" get statefulset "$sts" -o jsonpath="{range .spec.template.spec.containers[0].env[?(@.name=='$1')]}{.value}{end}" 2>/dev/null
}

pwref='{range .spec.template.spec.containers[0].env[?(@.name=="LDAP_ADMIN_PASSWORD")]}'
secret_name=$(kubectl -n "$ns" get statefulset "$sts" -o jsonpath="${pwref}{.valueFrom.secretKeyRef.name}{end}" 2>/dev/null)
secret_key=$(kubectl -n "$ns" get statefulset "$sts" -o jsonpath="${pwref}{.valueFrom.secretKeyRef.key}{end}" 2>/dev/null)

if [ -z "$secret_name" ] || [ -z "$secret_key" ]; then
  echo "StatefulSet '${sts}' does not source LDAP_ADMIN_PASSWORD from a Secret." >&2
  echo "It may predate this chart, or set the password inline (which the chart never does)." >&2
  exit 1
fi

encoded=$(kubectl -n "$ns" get secret "$secret_name" -o jsonpath="{.data.${secret_key}}" 2>/dev/null || true)
if [ -z "$encoded" ]; then
  echo "Secret '${secret_name}' has no key '${secret_key}' in namespace '${ns}'." >&2
  exit 1
fi
password=$(printf '%s' "$encoded" | base64 -d)

if [ "$password_only" = 1 ]; then
  printf '%s' "$password"
  exit 0
fi

root_dn=$(get_env LDAP_ROOT_DN)
admin_dn=$(get_env LDAP_ADMIN_DN)
[ -n "$admin_dn" ] || admin_dn="cn=admin,${root_dn}"

# The UI Service carries name=openldap (the chart-wide name) and is
# distinguished by component=ui — not by name=openldap-ui, which is what an
# obvious guess would select and which matches nothing.
ui_svc=$(kubectl -n "$ns" get svc \
           -l app.kubernetes.io/name=openldap,app.kubernetes.io/component=ui \
           -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

cat <<EOF
Namespace:    ${ns}
StatefulSet:  ${sts}
Secret:       ${secret_name} (key: ${secret_key})

Admin bind DN:  ${admin_dn}
Admin password: ${password}

Bind directly:
  kubectl -n ${ns} port-forward svc/${sts} 3389:389
  ldapwhoami -x -H ldap://localhost:3389 -D "${admin_dn}" \\
    -w "\$(${0} -n ${ns} -r ${sts} --password-only)"
EOF

if [ -n "$ui_svc" ]; then
  cat <<EOF

Management UI:
  kubectl -n ${ns} port-forward svc/${ui_svc} 8080:8080
  then open http://localhost:8080

  Log in with the FULL DN, not "admin":
    ${admin_dn}
  The admin entry is an organizationalRole and has no uid attribute, so the
  uid-based shorthand login does not resolve it. Regular users created as
  inetOrgPerson do log in with their bare uid.
EOF
fi

cat <<'EOF'

Note: the password above was printed to your terminal. It is in your scrollback
(and, if you used command substitution in an interactive shell, possibly your
history). Use --password-only when piping into another command.
EOF
