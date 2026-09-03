#!/usr/bin/env bash
# Export this release's audit trail as newline-delimited JSON — one line per
# event, suitable for piping straight into a SIEM's file/stdin ingestion.
#
# Two overlays and one replication diagnostic, unified into one stream here because a
# SIEM wants one feed, not "read the auditlog doc, then separately read the
# accesslog doc":
#
#   auditlog                  writes (add/modify/modrdn/delete) — container stdout, per pod
#   accesslog                 reads (search/bind), when audit.accessLog.enabled — its own
#                             LDAP database (cn=accesslog), per pod
#   replication-conflict-raw  discarded replication CSNs — container stdout, per pod
#
# replication-conflict-raw is deliberately raw, not a conflict detector: it
# mixes genuine same-entry conflicts with harmless duplicate delivery over
# N-way relay paths. Consumers must not treat every record as confirmed data
# loss; that needs correlation with converged state or other nodes' records.
#
# "Per pod" both times, deliberately: on a replicated install each provider
# only has the events it personally handled — that is what replication
# carries, not audit records — so a complete export means every pod, and
# this script iterates the StatefulSet's own replica count rather than
# assume one.
#
# Every record is normalized into the common identity-audit envelope
# documented in docs/audit-event-schema.md (issue #24): schemaVersion,
# source, seq, time, actor, target, op, result, objectId, correlationId,
# privileged, plus the original source-specific fields (redacted/sanitized
# where noted in the schema doc) verbatim under "raw" so nothing this script
# has always emitted is lost, only moved. The actual transform lives in
# scripts/lib/audit-normalize.py — a pure stdin/stdout filter, unit-tested
# with fixtures in scripts/test/ — this script's own job is only to fetch
# and flatten the three raw sources; retrieval order is NOT relied on for
# determinism (see that file's own module docstring for why and how it
# sorts before assigning `seq`).
#
# If any input line could not be parsed, the normalizer appends a final
# "exporter"/"summary" record naming the drop count rather than silently
# reporting fewer events than actually happened — see
# docs/audit-event-schema.md.
#
#   ./scripts/export-audit-log.sh                    # auto-discover, both overlays
#   ./scripts/export-audit-log.sh -n ldapium -r prod
#   ./scripts/export-audit-log.sh --writes-only       # skip accesslog reads; keep container-log diagnostics
#   ./scripts/export-audit-log.sh --reads-only        # skip the container-log writes
#   ./scripts/export-audit-log.sh --legacy            # flat pre-#24 per-source shape, no envelope
#
# --legacy matches the pre-#24 field set exactly (no entryDn/entryUUID/
# changedAttrs/reqSession) and applies the same filter redaction as the
# default mode — the one guarantee that is not optional in either mode. It
# is not a general compatibility promise beyond that field-set match — see
# docs/audit-event-schema.md. Unlike default mode, --legacy has no
# in-stream way to report a dropped/unparseable input line without adding a
# key to that flat shape, so it instead exits non-zero when anything was
# dropped.
#
# Known limitation: cn=accesslog's bind credential (like cn=Monitor's and
# {1}mdb's own rootdn) is rendered once, at bootstrap, from the admin
# password the release started with — the same way this whole chart's
# cn=config only ever gets rendered on first launch. If the admin password
# has since been rotated by binding as the directory entry and changing it
# there (the normal LDAP way, not by editing the Secret and hoping), the
# password get-credentials.sh now returns will no longer match, and the
# accesslog half of this script fails per-pod with a clear warning rather
# than a wrong result — it does not fail the whole run.
set -euo pipefail

ns=""
sts=""
want_writes=1
want_reads=1
legacy=0
chain=0

usage() {
  cat <<'EOF'
Usage: export-audit-log.sh [-n NAMESPACE] [-r RELEASE] [--writes-only|--reads-only] [--legacy] [--chain]

Prints one normalized identity-audit event per line to stdout (see
docs/audit-event-schema.md), e.g.:
  {"schemaVersion":"1","source":"auditlog","seq":1,"time":"2026-08-23T15:54:13Z","actor":"cn=admin,dc=example,dc=org","target":"uid=alice,ou=people,dc=example,dc=org","op":"modify","result":"unknown","objectId":null,"correlationId":"auditlog:directory-ldapium-0:1787500453:uid=alice,ou=people,dc=example,dc=org:cn=admin,dc=example,dc=org","privileged":true,"raw":{"pod":"directory-ldapium-0","source":"auditlog","time":"1787500453","actor":"cn=admin,dc=example,dc=org","op":"modify","target":"dc=example,dc=org","entryDn":"uid=alice,ou=people,dc=example,dc=org","entryUUID":"","changedAttrs":["sn"]}}

If any input line failed to parse, one more line is appended:
  {"schemaVersion":"1","source":"exporter","seq":9,"time":null,"actor":"exporter","target":null,"op":"summary","result":"unknown","objectId":null,"correlationId":"exporter:summary:1:8","privileged":false,"raw":{"dropped":1,"emitted":8}}

With --legacy, prints the flat pre-#24 per-source shape instead (no
envelope, no additive keys):
  {"pod":"...","source":"auditlog","time":"...","actor":"...","op":"modify","target":"..."}
  {"pod":"...","source":"accesslog","time":"...","actor":"...","op":"search","target":"...","filter":"...","result":"0"}
  {"pod":"...","source":"accesslog","time":"...","actor":"...","op":"bind","target":"...","filter":"","result":"49"}
  {"pod":"...","source":"replication-conflict-raw","time":"20260825130859.674401Z","entry":"uid=baseline,ou=chaos,dc=example,dc=org","discardedCSN":"20260825130859.674401Z#000000#003#000000","rid":"002"}

  -n, --namespace   Kubernetes namespace (default: current kubectl context's)
  -r, --release     Helm release name. Only needed when a namespace holds more
                    than one ldapium install.
      --writes-only Export auditlog (write) events and raw replication
                    diagnostics from the same container logs. The latter
                    includes harmless relay duplicates; it is not confirmed
                    data-loss reporting.
      --reads-only  Export only accesslog (read) events — fails per pod with a
                    warning on stderr if that pod does not have
                    audit.accessLog.enabled, rather than failing the run.
      --legacy      Skip envelope normalization; print the flat pre-#24
                    per-source shape instead (see above). Exits non-zero if
                    any input line could not be parsed.
      --chain       Add cryptographic SHA-256 hash chaining (prevHash, hash)
                    across records for tamper-evidence.
  -h, --help        This text.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    -n|--namespace) ns="${2:?-n needs a namespace}"; shift 2 ;;
    -r|--release)   sts="${2:?-r needs a release name}"; shift 2 ;;
    --writes-only) want_reads=0; shift ;;
    --reads-only) want_writes=0; shift ;;
    --legacy) legacy=1; shift ;;
    --chain) chain=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown argument: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ "$legacy" = 1 ] && [ "$chain" = 1 ]; then
  echo "export-audit-log.sh: --chain cannot be used with --legacy (the legacy flat shape does not support envelope hash chaining)" >&2
  exit 2
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

# Same jsonpath-over-the-StatefulSet technique get-credentials.sh uses to
# find LDAP_ADMIN_PASSWORD's Secret ref — reused here to find the actual
# rootdn this release was configured with, so "privileged" classification
# (docs/audit-event-schema.md) compares against the real value instead of
# assuming the "cn=admin,<root dn>" default. jsonpath stays on one line —
# see get-credentials.sh's own NOTE on why a wrapped template silently
# breaks the match.
get_env() { # get_env <ENV_NAME> — value of a plain (non-secretKeyRef) env var
  kubectl -n "$ns" get statefulset "$sts" -o jsonpath="{range .spec.template.spec.containers[0].env[?(@.name=='$1')]}{.value}{end}" 2>/dev/null
}
admin_dn=$(get_env LDAP_ADMIN_DN)
if [ -z "$admin_dn" ]; then
  root_dn=$(get_env LDAP_ROOT_DN)
  [ -n "$root_dn" ] && admin_dn="cn=admin,${root_dn}"
fi
[ -n "$admin_dn" ] || echo "warning: could not determine the rootdn (LDAP_ADMIN_DN/LDAP_ROOT_DN) from StatefulSet '${sts}' — every record will be exported as privileged:false" >&2

lib_dir="$(cd "$(dirname "$0")/lib" && pwd)"

# Everything below fetches and flattens the three raw sources. Retrieval
# order here is NOT relied on for determinism — accesslog's ldapsearch in
# particular has no ordering guarantee across runs — scripts/lib/
# audit-normalize.py sorts records itself (by time, then pod, then
# correlationId, then a stable hash) before assigning `seq`, so two runs
# over the same underlying data are byte-identical regardless of what order
# this function happened to emit them in. Wrapped in a function so the pipe
# to the normalizer below is the ONLY place deciding whether this run gets
# the envelope or the flat --legacy shape; the extraction logic itself does
# not know or care which — and it always goes through the normalizer either
# way, because filter redaction (docs/audit-event-schema.md) has exactly one
# implementation and it lives there, not duplicated per output mode.
run_export() {
if [ "$want_writes" = 1 ]; then
  for i in $(seq 0 $((replicas - 1))); do
    pod="${sts}-${i}"
    # Fetch the container log once: auditlog writes and syncrep diagnostics
    # share stdout, and fetching them independently risks seeing a different
    # slice of a rotating log between the two requests.
    container_log=$(kubectl -n "$ns" logs "$pod" -c openldap --since=720h 2>/dev/null || true)
    # auditlog's own format: "# <op> <unixtime> <suffix> <bindDN> IP=... conn=..."
    # opening each record, ended by the next such line or EOF, followed by
    # the LDIF body of what changed. This awk pass now reads that body too —
    # not to capture full attribute values (still left for a SIEM's own "show
    # me the raw event" drill-down, and doing so would risk logging
    # userPassword's value) but to pull two cheap, high-value fields out of
    # it: the entry's real DN (the LDIF's own "dn:" line — the header's $4 is
    # the database suffix, not the entry, see the security-e2e.yml comment on
    # why it was never asserted as one) and which attribute NAMES changed
    # (docs/audit-event-schema.md's redaction guarantee: names only, never
    # values, which is what keeps a password out of this export without
    # needing to know every password-like attribute name in advance).
    #
    # "time" is a string in both sources but not the same string format —
    # auditlog gives a raw Unix epoch, accesslog gives LDAP GeneralizedTime
    # (20260823155413.000004Z). Both are converted to RFC3339 by
    # scripts/lib/audit-normalize.py below, not here — GeneralizedTime needs
    # no `date` binary (pure string reformatting), but epoch-to-calendar does,
    # and this script's own history already flagged GNU-vs-BSD `date` as a
    # portability risk; Python's stdlib sidesteps it entirely.
    printf '%s\n' "$container_log" | awk -v pod="$pod" -f "${lib_dir}/parse-auditlog.awk"

    # `CSN too old, ignoring` also marks ordinary relay duplicates, so leave
    # this undeduplicated evidence intact rather than guessing which records
    # lost data. --writes-only owns it because it comes from this exact log
    # fetch; a third selector would imply a certainty the stream cannot offer.
    printf '%s\n' "$container_log" \
      | grep -E 'do_syncrep2: rid=[0-9]+ CSN too old, ignoring [^ ]+ \(.*\)$' \
      | awk -v pod="$pod" -f "${lib_dir}/parse-replication-conflict.awk" || true
  done
fi

password=""
if [ "$want_reads" = 1 ] || [ "$want_writes" = 1 ]; then
  password=$("$(dirname "$0")/get-credentials.sh" -n "$ns" -r "$sts" --password-only 2>/dev/null) || {
    password=""
  }
fi
export LDAP_ADMIN_PASSWORD="${password:-}"

if [ "$want_reads" = 1 ]; then
  if [ -z "$password" ]; then
    echo "could not read the admin password via get-credentials.sh — skipping accesslog export" >&2
  else
    for i in $(seq 0 $((replicas - 1))); do
      pod="${sts}-${i}"
      # auditBind alongside auditSearch: reqResult is what tells success
      # from failure (0 = LDAP_SUCCESS) for both, and a failed bind is the
      # one event this export existed to surface but couldn't, back when
      # the overlay only logged reads and only logged successes.
      out=$(kubectl -n "$ns" exec "$pod" -c openldap -- \
        ldapsearch -x -o ldif-wrap=no -D "cn=admin,cn=accesslog" -w "$password" \
          -b cn=accesslog -LLL "(|(objectClass=auditSearch)(objectClass=auditBind))" \
          objectClass reqStart reqSession reqAuthzID reqDN reqFilter reqResult 2>/dev/null) || {
        echo "pod ${pod}: accesslog not reachable (audit.accessLog.enabled may be false) — skipping" >&2
        continue
      }
      # reqSession: slapo-accesslog's own per-connection counter, added here
      # solely to build correlationId (docs/audit-event-schema.md) — it is
      # the closest thing this overlay has to a request/session id, though
      # it resets across a slapd restart so it is not cross-restart-unique
      # on its own (the correlationId derivation pairs it with reqStart).
      printf '%s\n' "$out" | awk -v pod="$pod" -f "${lib_dir}/parse-accesslog.awk"
    done
  fi
fi
}

norm_flags=(--admin-dn "$admin_dn")
if [ "$legacy" = 1 ]; then
  norm_flags+=(--legacy)
fi
if [ "$chain" = 1 ]; then
  norm_flags+=(--chain)
fi

run_export \
  | python3 "${lib_dir}/resolve-conflict-objectid.py" --namespace "$ns" --statefulset "$sts" --replicas "$replicas" --admin-dn "$admin_dn" \
  | python3 "${lib_dir}/audit-normalize.py" "${norm_flags[@]}"

