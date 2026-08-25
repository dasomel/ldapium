#!/usr/bin/env bash
# Detect whether cn=config has been modified since a known-good baseline was
# captured — bootstrap only ever writes cn=config once, at first launch (see
# image/entrypoint.sh's MARKER check), so nothing else changes it unless an
# operator hand-edits it with ldapmodify against cn=config directly. There is
# currently no other signal for that anywhere in this project.
#
#   ./scripts/detect-config-drift.sh --baseline > baseline.ldif
#   ./scripts/detect-config-drift.sh --check baseline.ldif
#
# Exit code from --check is the actual signal: 0 means no drift, 1 means
# drift was found (or the config was unreachable), suitable as a CI/cron
# gate. The diff itself goes to stdout for a human to read.
#
# Per pod, deliberately, same reasoning as export-audit-log.sh: cn=config is
# rendered independently by each pod's own entrypoint.sh at its own
# bootstrap, not synced between them (only the directory *data* replicates).
# One baseline file holds every pod's snapshot, so --check also catches a
# pod that has quietly diverged from its siblings, not only drift from the
# original baseline.
set -euo pipefail

ns=""
sts=""
mode=""
baseline_file=""

usage() {
  cat <<'EOF'
Usage: detect-config-drift.sh --baseline [-n NAMESPACE] [-r RELEASE]
       detect-config-drift.sh --check BASELINE_FILE [-n NAMESPACE] [-r RELEASE]

  --baseline        Capture cn=config from every pod and print it to stdout.
                     Redirect it somewhere durable — this script has no
                     opinion on where a baseline should live, same as
                     export-audit-log.sh has none about where its export
                     goes.
  --check FILE       Re-capture cn=config from every pod and diff it against
                     a baseline captured earlier with --baseline. Prints any
                     differences to stdout. Exit 0 if none found, 1 if drift
                     was found or a pod's config could not be read.
  -n, --namespace   Kubernetes namespace (default: current kubectl context's)
  -r, --release     Helm release name. Only needed when a namespace holds
                    more than one ldapium install.
  -h, --help        This text.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --baseline) mode="baseline"; shift ;;
    --check) mode="check"; baseline_file="${2:?--check needs a baseline file}"; shift 2 ;;
    -n|--namespace) ns="${2:?-n needs a namespace}"; shift 2 ;;
    -r|--release)   sts="${2:?-r needs a release name}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown argument: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

[ -n "$mode" ] || { echo "one of --baseline or --check is required" >&2; usage >&2; exit 2; }
if [ "$mode" = "check" ]; then
  [ -r "$baseline_file" ] || { echo "baseline file not readable: ${baseline_file}" >&2; exit 1; }
fi

command -v kubectl >/dev/null 2>&1 || { echo "kubectl not found on PATH" >&2; exit 1; }

if [ -z "$ns" ]; then
  ns=$(kubectl config view --minify --output 'jsonpath={..namespace}' 2>/dev/null || true)
  ns="${ns:-default}"
fi

# Same discovery this chart's other operator scripts use — see
# get-credentials.sh for why label rather than "<release>-openldap".
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
  kubectl -n "$ns" get statefulset "$sts" >/dev/null 2>&1 || sts="${sts}-openldap"
  kubectl -n "$ns" get statefulset "$sts" >/dev/null 2>&1 || {
    echo "no StatefulSet '${sts}' in namespace '${ns}'." >&2; exit 1; }
fi

replicas=$(kubectl -n "$ns" get statefulset "$sts" -o jsonpath='{.spec.replicas}' 2>/dev/null)
[ -n "$replicas" ] || { echo "could not read replica count from StatefulSet '${sts}'." >&2; exit 1; }

password=$("$(dirname "$0")/get-credentials.sh" -n "$ns" -r "$sts" --password-only 2>/dev/null) || {
  echo "could not read the admin password via get-credentials.sh" >&2
  exit 1
}

# Strips exactly the attributes that change on every independent bootstrap
# even when the *logical* configuration is identical — verified live against
# a running container's cn=config dump, not guessed: entryUUID/entryCSN are
# minted fresh per entry at creation time, and creatorsName/createTimestamp/
# modifiersName/modifyTimestamp record when and by whom cn=config's LDIF was
# loaded, not anything an operator configured. olcRootPW is included for a
# different reason: entrypoint.sh hashes LDAP_ADMIN_PASSWORD with a fresh
# Argon2 salt on every bootstrap (live-confirmed: two containers started
# with the byte-identical password produced two different olcRootPW
# values), so it can never be compared byte-for-byte across independent
# bootstraps regardless of whether the actual password changed. None of
# these seven are something a real config change would touch as its actual
# content, only as bootstrap bookkeeping. Left in, a redeploy onto a fresh
# volume (same Helm values, new PVC — a completely ordinary
# disaster-recovery or re-provisioning event) would report as full drift on
# every single entry despite nothing having actually changed.
strip_noise() {
  grep -Ev '^(entryUUID|entryCSN|creatorsName|createTimestamp|modifiersName|modifyTimestamp|olcRootPW): '
}

# olcSyncrepl embeds the replication bind password in cleartext
# (credentials="..." — see entrypoint.sh's olcSyncrepl rendering), so it
# must never reach the baseline file or a diff verbatim, same principle as
# this repo's userPassword denylist for HTTP responses (see CLAUDE.md).
# Masking it to a fixed placeholder means a legitimate password rotation
# won't itself register as drift on this line — acceptable here since a
# real rotation goes through Helm/the replication secret and a rolling
# restart (which regenerates the *whole* olcSyncrepl line the same as any
# other redeploy), not a hand-edit of cn=config, which is the only kind of
# change this script exists to catch.
redact_secrets() {
  sed -E 's/(credentials=")[^"]*(")/\1<redacted>\2/'
}

dump_pod_config() {
  pod="$1"
  echo "# pod: ${pod}"
  kubectl -n "$ns" exec "$pod" -c openldap -- sh -c \
    "ldapsearch -x -o ldif-wrap=no -H ldapi://%2Fvar%2Flib%2Fopenldap%2Frun%2Fldapi -D 'cn=admin,cn=config' -w '${password}' -b cn=config -s sub '(objectClass=*)' '*' '+'" \
    2>/dev/null | strip_noise | redact_secrets
}

case "$mode" in
  baseline)
    for i in $(seq 0 $((replicas - 1))); do
      dump_pod_config "${sts}-${i}"
    done
    ;;
  check)
    drift=0
    for i in $(seq 0 $((replicas - 1))); do
      pod="${sts}-${i}"
      current=$(mktemp)
      dump_pod_config "$pod" > "$current"
      if [ ! -s "$current" ]; then
        echo "::error:: could not read cn=config from ${pod} — treating as drift" >&2
        drift=1
        rm -f "$current"
        continue
      fi
      # Extract just this pod's section from the baseline (bounded by the
      # next "# pod:" marker or EOF) so a multi-pod baseline file compares
      # like-for-like rather than diffing the whole file against one pod.
      baseline_section=$(awk -v marker="# pod: ${pod}" '
        $0 == marker { found=1; next }
        found && /^# pod: / { exit }
        found { print }
      ' "$baseline_file")
      if [ -z "$baseline_section" ]; then
        echo "::error:: no baseline section found for ${pod} in ${baseline_file}" >&2
        drift=1
        rm -f "$current"
        continue
      fi
      pod_diff=$(diff <(printf '%s\n' "$baseline_section") "$current" || true)
      if [ -n "$pod_diff" ]; then
        echo "=== drift detected: ${pod} ==="
        echo "$pod_diff"
        drift=1
      fi
      rm -f "$current"
    done
    if [ "$drift" = 1 ]; then
      exit 1
    fi
    echo "no drift detected across ${replicas} pod(s)"
    ;;
esac
