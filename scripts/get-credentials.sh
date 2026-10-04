#!/usr/bin/env bash
# Print the admin credentials for an ldapium release running in
# Kubernetes.
#
# Random startup credentials are persisted; this operator-only command reads
# them from the running compose service or its Kubernetes Secret.
#
# Discovery works off the running StatefulSet rather than off chart values, so
# it is correct whether the password lives in a chart-created Secret or in a
# pre-existing one referenced by auth.existingSecret — it follows the actual
# secretKeyRef the server container is using.
#
#   ./scripts/get-credentials.sh --local             # read from the running compose container (.env only if not running)
#   ./scripts/get-credentials.sh                     # auto-discover in current namespace
#   ./scripts/get-credentials.sh -n ldapium   # explicit namespace
#   ./scripts/get-credentials.sh -n ns -r ols        # explicit release/StatefulSet
#   ./scripts/get-credentials.sh --password-only     # just the password, for scripts
set -euo pipefail

ns=""
explicit_ns=""
sts=""
password_only=0
local_env=0
allow_env=0
ui_service=0
credential_key="LDAP_ADMIN_PASSWORD"

usage() {
  cat <<'EOF'
Usage: get-credentials.sh [--local [--allow-env]] [-n NAMESPACE] [-r RELEASE] [--password-only]

      --ui-service  Print "<namespace>/<service>" for the deployed management
                    UI and exit. Discovery lives here rather than in the
                    Makefile so both callers agree on how the UI is found.
      --local       Read the credentials docker-compose uses, from ./.env in
                    the repo root (created by `make local-init`), instead of
                    talking to Kubernetes. The running container is read
                    first; the source used is reported on stderr. If docker
                    is unreachable or the container is unreadable this fails
                    (exit 1) unless --allow-env is given; if the service is
                    simply not running, ./.env is used with a stderr note.
      --allow-env   With --local: fall back to ./.env when the container
                    cannot be read (value may be stale).
  -n, --namespace   Kubernetes namespace (default: current kubectl context's)
  -r, --release     Helm release name. Only needed when a namespace holds more
                    than one ldapium install.
      --password-only
                    Print only the password, with no trailing newline and no
                    other output. For command substitution:
                      ldapwhoami ... -y <(get-credentials.sh --password-only)
                    (bash process substitution; never put the password on a
                    command line with -w, it is visible in ps)
      --key NAME    LDAP_ADMIN_PASSWORD (default) or SESSION_SECRET.
  -h, --help        This text.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    -n|--namespace) ns="${2:?-n needs a namespace}"; explicit_ns=1; shift 2 ;;
    -r|--release)   sts="${2:?-r needs a release name}"; shift 2 ;;
    --local) local_env=1; shift ;;
    --allow-env) allow_env=1; shift ;;
    --key) credential_key="${2:?... --key needs LDAP_ADMIN_PASSWORD or SESSION_SECRET}"; shift 2 ;;
    --ui-service) ui_service=1; shift ;;
    --password-only) password_only=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown argument: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$credential_key" in LDAP_ADMIN_PASSWORD|SESSION_SECRET) ;; *) echo "unsupported credential key" >&2;exit 2;; esac

# --local short-circuits before anything Kubernetes-related: the compose stack
# has no StatefulSet or Secret to discover, its credentials live in the .env
# that docker-compose itself reads. Keeping both modes in one command means
# "how do I get the password" has a single answer regardless of how the
# directory is running.
if [ "$local_env" = 1 ]; then
  repo="$(cd "$(dirname "$0")/.." && pwd)"
  env_file="$repo/.env"
  read_env() { [ ! -r "$env_file" ] || sed -n "s/^$1=//p" "$env_file" | tail -1; }
  password=""; root_dn=""; source_used=""
  svc=ldap; [ "$credential_key" != SESSION_SECRET ] || svc=ui
  # D4: the running container is the only authoritative source (it resolves
  # *_FILE / env / generated precedence). .env can be stale, so it is used only
  # when the service is genuinely not running (docker answered, service absent)
  # or when the operator explicitly passes --allow-env. A docker daemon that is
  # unreachable, a failing `compose ps`, or a running container that cannot be
  # read, is an error: the
  # cause is unknown and a silently stale password is worse than no password.
  err_file=$(mktemp); trap 'rm -f "$err_file"' EXIT
  docker_state=unavailable
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>"$err_file"; then
    # A failing `compose ps` (bad compose file, broken plugin) is not "service
    # not running": only a successful, empty-of-$svc answer is.
    if running_services=$(cd "$repo" && docker compose ps --status running --services 2>"$err_file"); then
      if printf '%s\n' "$running_services" | grep -qx "$svc"; then docker_state=running; else docker_state=stopped; fi
    else
      docker_state=compose_error
    fi
  fi
  case "$docker_state" in
    running)
      if [ "$credential_key" = SESSION_SECRET ]; then
        password=$(cd "$repo" && docker compose exec -T ui /server -print-session-secret 2>"$err_file") || password=""
      else
        password=$(cd "$repo" && docker compose exec -T ldap /bin/sh -c 'if [ -n "${LDAP_ADMIN_PASSWORD_FILE:-}" ]; then cat "$LDAP_ADMIN_PASSWORD_FILE"; elif [ -n "${LDAP_ADMIN_PASSWORD:-}" ]; then printf "%s" "$LDAP_ADMIN_PASSWORD"; else cat /var/lib/openldap/data/.credentials/ldap-admin-password; fi' 2>"$err_file") || password=""
        root_dn=$(cd "$repo" && docker compose exec -T ldap /bin/sh -c 'printf "%s" "$LDAP_ROOT_DN"' 2>/dev/null) || root_dn=""
      fi
      if [ -n "$password" ]; then
        source_used="running '${svc}' container"
      elif [ "$allow_env" != 1 ]; then
        echo "error: '${svc}' container is running but the credential could not be read from it (credential file missing or empty?)." >&2
        sed 's/^/  docker: /' "$err_file" >&2
        echo "Pass --allow-env to fall back to ${env_file} (may be stale)." >&2
        exit 1
      fi ;;
    stopped)
      echo "note: docker is reachable but the '${svc}' service is not running." >&2 ;;
    compose_error)
      if [ "$allow_env" != 1 ]; then
        echo "error: 'docker compose ps' failed; cannot tell whether the '${svc}' service is running." >&2
        [ ! -s "$err_file" ] || sed 's/^/  docker: /' "$err_file" >&2
        echo "Fix the compose error, or pass --allow-env to use ${env_file} (may be stale)." >&2
        exit 1
      fi ;;
    *)
      if [ "$allow_env" != 1 ]; then
        echo "error: docker is unavailable (not installed or daemon not reachable); cannot read the credential from the container." >&2
        [ ! -s "$err_file" ] || sed 's/^/  docker: /' "$err_file" >&2
        echo "Start docker/the stack, or pass --allow-env to use ${env_file} (may be stale)." >&2
        exit 1
      fi ;;
  esac
  if [ -z "$password" ]; then
    password=$(read_env "$credential_key")
    [ -z "$password" ] || source_used="${env_file} (container not read; may be stale)"
  fi
  [ -n "$root_dn" ] || root_dn=$(read_env LDAP_ROOT_DN)
  [ -n "$password" ] || { echo "error: no credential available: ${svc} not running and ${credential_key} not set in ${env_file}. Start services first." >&2;exit 1; }
  echo "source: ${source_used}" >&2
  admin_dn="cn=admin,${root_dn}"
  if [ "$credential_key" = SESSION_SECRET ]; then
    if [ "$password_only" = 1 ];then printf '%s' "$password";else printf 'SESSION_SECRET: %s\n' "$password";fi
    exit 0
  fi

  if [ "$password_only" = 1 ]; then
    printf '%s' "$password"
    exit 0
  fi

  cat <<EOF
Source:         ${source_used} (docker-compose)

Admin bind DN:  ${admin_dn}
Admin password: ${password}

Bind directly:
  ldapwhoami -x -H ldap://localhost:389 -D "${admin_dn}" \\
    -y <(${0} --local --password-only)

Management UI:  http://localhost:8080
  Log in with the FULL DN above, not "admin" — the admin entry is an
  organizationalRole and has no uid attribute for the uid filter to match.
EOF
  exit 0
fi

command -v kubectl >/dev/null 2>&1 || { echo "kubectl not found on PATH" >&2; exit 1; }

# The chart labels the UI Service with the chart-wide name plus component=ui —
# not name=openldap-ui, which is the obvious guess and matches nothing. Defined
# once so the two lookups below cannot drift apart.
UI_LABELS='app.kubernetes.io/name=ldapium,app.kubernetes.io/component=ui'

if [ -z "$ns" ]; then
  ns=$(kubectl config view --minify --output 'jsonpath={..namespace}' 2>/dev/null || true)
  ns="${ns:-default}"
fi

# --ui-service resolves only the UI Service and prints "<namespace>/<name>".
# Unlike the credential lookup below it searches cluster-wide when no
# namespace was given: its caller (make k8s-ui-forward) is a convenience for
# "forward whatever UI is running", and requiring the operator to already know
# the namespace defeats that. An ambiguous result lists the candidates instead
# of guessing.
if [ "$ui_service" = 1 ]; then
  if [ -n "$explicit_ns" ]; then
    svc=$(kubectl -n "$ns" get svc -l "$UI_LABELS" \
            -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
    [ -n "$svc" ] || { echo "no OpenLDAP UI Service found in namespace '${ns}'." >&2; exit 1; }
    printf '%s/%s\n' "$ns" "$svc"
    exit 0
  fi
  matches=$(kubectl get svc -A -l "$UI_LABELS" \
              -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{"\n"}{end}' 2>/dev/null || true)
  count=$(printf '%s\n' "$matches" | grep -c . || true)
  if [ "$count" != 1 ]; then
    echo "found ${count} OpenLDAP UI Services; pass -n NAMESPACE to select one:" >&2
    printf '%s\n' "$matches" | sed 's/^/  /' >&2
    exit 1
  fi
  printf '%s\n' "$matches"
  exit 0
fi

# The chart labels its StatefulSet app.kubernetes.io/name=ldapium. Finding it
# by label rather than by "<release>-openldap" survives nameOverride and
# fullnameOverride.
if [ -z "$sts" ]; then
  found=$(kubectl -n "$ns" get statefulset -l app.kubernetes.io/name=ldapium \
            -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null || true)
  count=$(printf '%s' "$found" | grep -c . || true)
  case "$count" in
    0) echo "no ldapium StatefulSet found in namespace '${ns}'." >&2
       echo "Pass -n NAMESPACE, or -r RELEASE if it is labelled differently." >&2
       exit 1 ;;
    1) sts=$(printf '%s' "$found" | head -1) ;;
    *) echo "found more than one ldapium StatefulSet in '${ns}':" >&2
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

if [ "$credential_key" = SESSION_SECRET ]; then
  deployment=$(kubectl -n "$ns" get deployment -l "$UI_LABELS" -o jsonpath='{.items[0].metadata.name}')
  [ -n "$deployment" ] || { echo "management UI deployment unavailable" >&2;exit 1; }
  ref='{range .spec.template.spec.containers[0].env[?(@.name=="SESSION_SECRET")]}'
  secret_name=$(kubectl -n "$ns" get deployment "$deployment" -o jsonpath="${ref}{.valueFrom.secretKeyRef.name}{end}")
  secret_key=$(kubectl -n "$ns" get deployment "$deployment" -o jsonpath="${ref}{.valueFrom.secretKeyRef.key}{end}")
  [ -n "$secret_name" ] && [ -n "$secret_key" ] || { echo "UI session Secret reference unavailable" >&2;exit 1; }
  encoded=$(kubectl -n "$ns" get secret "$secret_name" -o jsonpath="{.data.${secret_key}}")
  [ -n "$encoded" ] || { echo "UI session Secret value unavailable" >&2;exit 1; }
  password=$(printf '%s' "$encoded" | base64 -d)
  if [ "$password_only" = 1 ];then printf '%s' "$password";else printf 'SESSION_SECRET: %s\n' "$password";fi
  exit 0
fi

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

ui_svc=$(kubectl -n "$ns" get svc -l "$UI_LABELS" \
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
    -y <(${0} -n ${ns} -r ${sts} --password-only)
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
history). Use --password-only with -y <(...) (bash) rather than -w "$(...)",
which exposes the password in the process list.
EOF
