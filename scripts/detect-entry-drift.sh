#!/usr/bin/env bash
# Detect whether directory entry data has drifted from a known-good baseline.
#
#   ./scripts/detect-entry-drift.sh --baseline-out baseline.ldif
#   ./scripts/detect-entry-drift.sh --check baseline.ldif
#
# Exit codes:
#   0: no drift detected
#   1: drift detected (diff printed to stdout)
#   2: error (e.g. baseline file missing, connectivity/auth failure, bad arguments)
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
canonicalizer="${here}/lib/canonicalize-ldif.py"

mode=""
baseline_file=""
input_file=""
ns=""
sts=""
base_dn=""

usage() {
  cat <<'USAGE_EOF'
Usage: detect-entry-drift.sh --baseline-out FILE [-n NAMESPACE] [-r RELEASE] [-b BASE_DN] [--input FILE]
       detect-entry-drift.sh --check BASELINE_FILE [-n NAMESPACE] [-r RELEASE] [-b BASE_DN] [--input FILE]

  --baseline-out FILE  Capture subtree entries, canonicalize, and write baseline to FILE.
  --check FILE         Re-export subtree entries, canonicalize, and diff against FILE.
                       Exit 0 if identical, 1 if drift detected, 2 on error.
  --input FILE         Read raw LDIF from FILE (or '-' for stdin) instead of querying a cluster.
  -b, --base-dn DN     Subtree base DN (default: auto-discover from root DSE or dc=example,dc=org).
  -n, --namespace NS   Kubernetes namespace (default: current kubectl context).
  -r, --release REL    Helm release or StatefulSet name.
  -h, --help           Show this help.
USAGE_EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --baseline-out)
      mode="baseline-out"
      [ $# -ge 2 ] || { echo "error: --baseline-out requires a file path" >&2; exit 2; }
      baseline_file="$2"
      shift 2
      ;;
    --check)
      mode="check"
      [ $# -ge 2 ] || { echo "error: --check requires a baseline file" >&2; exit 2; }
      baseline_file="$2"
      shift 2
      ;;
    --input)
      [ $# -ge 2 ] || { echo "error: --input requires a file path" >&2; exit 2; }
      input_file="$2"
      shift 2
      ;;
    -b|--base-dn)
      [ $# -ge 2 ] || { echo "error: -b/--base-dn requires a base DN" >&2; exit 2; }
      base_dn="$2"
      shift 2
      ;;
    -n|--namespace)
      [ $# -ge 2 ] || { echo "error: -n/--namespace requires a namespace" >&2; exit 2; }
      ns="$2"
      shift 2
      ;;
    -r|--release)
      [ $# -ge 2 ] || { echo "error: -r/--release requires a release name" >&2; exit 2; }
      sts="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [ -z "$mode" ]; then
  echo "error: one of --baseline-out or --check is required" >&2
  usage >&2
  exit 2
fi

if [ "$mode" = "check" ]; then
  if [ ! -r "$baseline_file" ]; then
    echo "error: baseline file not readable: ${baseline_file}" >&2
    exit 2
  fi
fi

if [ ! -f "$canonicalizer" ]; then
  echo "error: canonicalizer script not found: ${canonicalizer}" >&2
  exit 2
fi

dump_ldif() {
  if [ "$input_file" = "-" ]; then
    cat
  else
    if [ ! -r "$input_file" ]; then
      echo "error: input file not readable: ${input_file}" >&2
      exit 2
    fi
    cat "$input_file"
  fi
}

dump_cluster_ldif() {
  command -v kubectl >/dev/null 2>&1 || { echo "error: kubectl not found on PATH" >&2; exit 2; }

  if [ -z "$ns" ]; then
    ns=$(kubectl config view --minify --output 'jsonpath={..namespace}' 2>/dev/null || true)
    ns="${ns:-default}"
  fi

  if [ -z "$sts" ]; then
    found=$(kubectl -n "$ns" get statefulset -l app.kubernetes.io/name=ldapium \
              -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null || true)
    count=$(printf '%s' "$found" | grep -c . || true)
    case "$count" in
      0) echo "error: no ldapium StatefulSet found in namespace '${ns}'." >&2
         exit 2 ;;
      1) sts=$(printf '%s' "$found" | head -1) ;;
      *) echo "error: found more than one ldapium StatefulSet in '${ns}'. Disambiguate with -r RELEASE." >&2
         exit 2 ;;
    esac
  else
    kubectl -n "$ns" get statefulset "$sts" >/dev/null 2>&1 || sts="${sts}-openldap"
    kubectl -n "$ns" get statefulset "$sts" >/dev/null 2>&1 || {
      echo "error: no StatefulSet '${sts}' in namespace '${ns}'." >&2; exit 2; }
  fi

  pod="${sts}-0"
  password=$("${here}/get-credentials.sh" -n "$ns" -r "$sts" --password-only 2>/dev/null) || {
    echo "error: could not read admin password via get-credentials.sh" >&2
    exit 2
  }

  if [ -z "$base_dn" ]; then
    base_dn=$(kubectl -n "$ns" exec "$pod" -c openldap -- sh -c \
      'ldapsearch -x -LLL -o ldif-wrap=no -H ldapi://%2Fvar%2Flib%2Fopenldap%2Frun%2Fldapi -s base -b "" namingContexts 2>/dev/null' \
      | awk '/^namingContexts: / { print $2; exit }')
    base_dn="${base_dn:-dc=example,dc=org}"
  fi

  # base_dn and the admin password are cluster-/user-supplied values that
  # must never be interpolated into a shell command string: base_dn is
  # valid LDAP-DN syntax that can legitimately contain a single quote or a
  # space, either of which would break out of the naive '${base_dn}'
  # quoting above and change what the remote shell actually runs; the
  # password would otherwise sit in the remote process's argv, readable by
  # any other user on the node via /proc/<pid>/cmdline. base_dn is passed
  # as an environment variable to the remote shell, referenced there only
  # as "$BASE_DN" (expanded remotely, never substituted into the command
  # string by this script); the password is never put on a command line or
  # in an environment variable at all -- it is streamed over the exec'd
  # process's stdin and read with ldapsearch's "-y /dev/stdin".
  # $BASE_DN below must expand in the *remote* shell from its own
  # environment, not be substituted by this script -- hence the single
  # quotes shellcheck otherwise flags.
  # shellcheck disable=SC2016
  printf '%s' "$password" | kubectl -n "$ns" exec -i "$pod" -c openldap -- \
    env BASE_DN="$base_dn" sh -c \
    'ldapsearch -x -LLL -o ldif-wrap=no -H ldapi://%2Fvar%2Flib%2Fopenldap%2Frun%2Fldapi -D "cn=admin,$BASE_DN" -y /dev/stdin -b "$BASE_DN" -s sub "(objectClass=*)" "*" "+"' \
    2>/dev/null || {
      echo "error: ldapsearch failed on ${pod}" >&2
      exit 2
    }
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

current_canonical="${work}/current.ldif"
raw_dump="${work}/raw-dump.ldif"

# The dump is captured to a temp file first, as its own distinct step,
# rather than piped straight into the canonicalizer: dump_ldif and
# dump_cluster_ldif already print their own specific error and exit 2 on
# failure, but each is the left side of what would otherwise be a pipeline,
# and under `set -o pipefail` (set at the top of this script) that failure
# would surface through the generic `|| { canonicalization failed }`
# handler below regardless of which side actually failed -- misreporting
# an ldapsearch/kubectl failure as a canonicalization failure. Calling them
# directly (not through a pipe) also means their internal `exit 2` ends
# the whole script immediately, as intended, instead of only the subshell
# a pipeline component runs in.
if [ -n "$input_file" ]; then
  dump_ldif > "$raw_dump"
else
  dump_cluster_ldif > "$raw_dump"
fi

python3 "$canonicalizer" "$raw_dump" > "$current_canonical" || {
  echo "error: canonicalization failed" >&2
  exit 2
}

case "$mode" in
  baseline-out)
    cp "$current_canonical" "$baseline_file" || {
      echo "error: failed to write baseline file: ${baseline_file}" >&2
      exit 2
    }
    echo "wrote baseline to ${baseline_file}"
    exit 0
    ;;
  check)
    # The baseline is put through the exact same canonicalize+redact
    # pipeline as the live dump before it is ever diffed or printed --
    # unconditionally, regardless of whether it happens to already be a
    # canonical baseline from a prior --baseline-out run (canonicalization
    # is idempotent) or a raw/hand-edited LDIF that still has real
    # userPassword hashes in it. That makes it impossible for the diff (and
    # therefore stdout on drift) to ever surface a non-redacted
    # userPassword value, without needing a separate "does this look like
    # a raw baseline" heuristic that could be bypassed.
    baseline_canonical="${work}/baseline.ldif"
    python3 "$canonicalizer" "$baseline_file" > "$baseline_canonical" || {
      echo "error: failed to canonicalize baseline file: ${baseline_file}" >&2
      exit 2
    }
    if diff -u "$baseline_canonical" "$current_canonical" > "${work}/entry.diff"; then
      echo "no drift detected"
      exit 0
    else
      cat "${work}/entry.diff"
      exit 1
    fi
    ;;
esac
