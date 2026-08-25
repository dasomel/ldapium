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
#   ./scripts/export-audit-log.sh                    # auto-discover, both overlays
#   ./scripts/export-audit-log.sh -n ldapium -r prod
#   ./scripts/export-audit-log.sh --writes-only       # skip accesslog reads; keep container-log diagnostics
#   ./scripts/export-audit-log.sh --reads-only        # skip the container-log writes
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

usage() {
  cat <<'EOF'
Usage: export-audit-log.sh [-n NAMESPACE] [-r RELEASE] [--writes-only|--reads-only]

Prints one JSON object per line to stdout:
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
  -h, --help        This text.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    -n|--namespace) ns="${2:?-n needs a namespace}"; shift 2 ;;
    -r|--release)   sts="${2:?-r needs a release name}"; shift 2 ;;
    --writes-only) want_reads=0; shift ;;
    --reads-only) want_writes=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown argument: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

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

# JSON string escaping: backslash and double-quote, the two characters an
# LDAP DN or filter can actually contain that would otherwise break the
# object. Good enough for the ASCII this attribute set holds — reqDN/
# reqFilter/reqAuthzID are DNs and filters, not free text.
json_escape() {
  sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

if [ "$want_writes" = 1 ]; then
  for i in $(seq 0 $((replicas - 1))); do
    pod="${sts}-${i}"
    # Fetch the container log once: auditlog writes and syncrep diagnostics
    # share stdout, and fetching them independently risks seeing a different
    # slice of a rotating log between the two requests.
    container_log=$(kubectl -n "$ns" logs "$pod" -c openldap --since=720h 2>/dev/null || true)
    # auditlog's own format: "# <op> <unixtime> <suffix> <bindDN> IP=... conn=..."
    # opening each record, ended by the next such line or EOF. Only the
    # opening line is needed here — it already carries actor, time and op;
    # the LDIF body between openings is the changed attributes, which is
    # what a SIEM's own "show me the raw event" drill-down is for, not this
    # summary line.
    #
    # "time" is a string in both sources but not the same string format —
    # auditlog gives a raw Unix epoch, accesslog gives LDAP GeneralizedTime
    # (20260823155413.000004Z). Reformatting one to match the other means
    # doing date arithmetic in POSIX shell/awk, which behaves differently
    # under GNU vs BSD date; left as-is rather than risk that silently
    # producing a wrong time. A SIEM's own ingest pipeline is the place to
    # normalize this, with a real date library instead of shell.
    # `grep` exits 1 on no match — a normal outcome here (auditlog disabled,
    # or a pod with nothing written yet), not a failure. Under pipefail that
    # exit code propagates through the whole pipeline and set -e kills the
    # script before it ever reaches the accesslog half below; `|| true`
    # neutralizes it at the source rather than the caller having to guess
    # what a bare failure meant.
    { printf '%s\n' "$container_log" | grep -E '^# (add|modify|modrdn|delete) ' || true; } \
      | while IFS= read -r line; do
          op=$(printf '%s' "$line" | awk '{print $2}')
          t=$(printf '%s' "$line" | awk '{print $3}')
          target=$(printf '%s' "$line" | awk '{print $4}' | json_escape)
          actor=$(printf '%s' "$line" | awk '{print $5}' | json_escape)
          printf '{"pod":"%s","source":"auditlog","time":"%s","actor":"%s","op":"%s","target":"%s"}\n' \
            "$pod" "$t" "$actor" "$op" "$target"
        done

    # `CSN too old, ignoring` also marks ordinary relay duplicates, so leave
    # this undeduplicated evidence intact rather than guessing which records
    # lost data. --writes-only owns it because it comes from this exact log
    # fetch; a third selector would imply a certainty the stream cannot offer.
    printf '%s\n' "$container_log" \
      | grep -E 'do_syncrep2: rid=[0-9]+ CSN too old, ignoring [^ ]+ \(.*\)$' \
      | awk -v pod="$pod" '
        function esc(s) {
          gsub(/\\/,"\\\\",s)
          gsub(/"/,"\\\"",s)
          return s
        }
        {
          record=$0
          sub(/^.*do_syncrep2: rid=/, "", record)
          rid=record
          sub(/ CSN too old, ignoring .*/, "", rid)
          csn=record
          sub(/^[0-9]+ CSN too old, ignoring /, "", csn)
          entry=csn
          sub(/^.* \(/, "", entry)
          sub(/\)$/, "", entry)
          sub(/ \(.*/, "", csn)
          time=csn
          sub(/#.*/, "", time)
          printf "{\"pod\":\"%s\",\"source\":\"replication-conflict-raw\",\"time\":\"%s\",\"entry\":\"%s\",\"discardedCSN\":\"%s\",\"rid\":\"%s\"}\n", \
            esc(pod), esc(time), esc(entry), esc(csn), esc(rid)
        }
      ' || true
  done
fi

if [ "$want_reads" = 1 ]; then
  password=$("$(dirname "$0")/get-credentials.sh" -n "$ns" -r "$sts" --password-only 2>/dev/null) || {
    echo "could not read the admin password via get-credentials.sh — skipping accesslog export" >&2
    password=""
  }
  if [ -n "$password" ]; then
    for i in $(seq 0 $((replicas - 1))); do
      pod="${sts}-${i}"
      # auditBind alongside auditSearch: reqResult is what tells success
      # from failure (0 = LDAP_SUCCESS) for both, and a failed bind is the
      # one event this export existed to surface but couldn't, back when
      # the overlay only logged reads and only logged successes.
      out=$(kubectl -n "$ns" exec "$pod" -c openldap -- \
        ldapsearch -x -o ldif-wrap=no -D "cn=admin,cn=accesslog" -w "$password" \
          -b cn=accesslog -LLL "(|(objectClass=auditSearch)(objectClass=auditBind))" \
          objectClass reqStart reqAuthzID reqDN reqFilter reqResult 2>/dev/null) || {
        echo "pod ${pod}: accesslog not reachable (audit.accessLog.enabled may be false) — skipping" >&2
        continue
      }
      printf '%s\n' "$out" | awk -v pod="$pod" '
        BEGIN { t=""; actor=""; dn=""; filt=""; result=""; is_bind=0 }
        /^dn: reqStart=/ { if (t != "") print_record(); t=""; actor=""; dn=""; filt=""; result=""; is_bind=0 }
        /^objectClass: auditBind$/ { is_bind=1 }
        /^reqStart: / { t=substr($0,11) }
        /^reqAuthzID: / { actor=substr($0,13) }
        /^reqAuthzID:: / { actor=b64dec(substr($0,14)) }
        /^reqDN: / { dn=substr($0,8) }
        /^reqDN:: / { dn=b64dec(substr($0,9)) }
        /^reqFilter: / { filt=substr($0,12) }
        /^reqFilter:: / { filt=b64dec(substr($0,13)) }
        /^reqResult: / { result=substr($0,12) }
        # LDIF uses "attr:: <base64>" instead of "attr: <value>" whenever the
        # value itself would be unsafe as plain text — a leading space or
        # colon, a trailing space, or a non-UTF8 byte. A DN or filter with
        # such a character is unusual but not impossible, and an audit
        # export silently dropping a field on exactly the kind of value
        # someone might be trying to hide is the wrong failure mode.
        # Known residual limit: `cmd | getline` reads exactly one line, so a
        # decoded value containing an embedded newline of its own only
        # yields that value up to its first line — the rest is discarded
        # when the pipe is closed below. Covers the realistic case (a DN or
        # filter needing base64 for a stray byte, not for holding multiple
        # lines of content) without the complexity of a full multi-line read
        # for a shape reqDN/reqFilter are not expected to take.
        function b64dec(enc,    cmd, decoded) {
          cmd = "printf %s '\''" enc "'\'' | base64 -d 2>/dev/null"
          decoded = ""
          cmd | getline decoded
          close(cmd)
          return decoded
        }
        # Order matters: backslash first, or the backslashes this function
        # itself inserts for \n/\t below would get escaped a second time.
        # \n/\t/\r matter specifically because a base64-decoded value (the
        # one case a raw control character can actually reach this function)
        # can legitimately contain one — that is the reason LDIF encoded it
        # in the first place, and an un-escaped one here would split a
        # single JSON record across two lines of output.
        function esc(s) {
          gsub(/\\/,"\\\\",s)
          gsub(/"/,"\\\"",s)
          gsub(/\r/,"\\r",s)
          gsub(/\n/,"\\n",s)
          gsub(/\t/,"\\t",s)
          return s
        }
        # A bind record has an empty reqAuthzID (there is no authorization
        # identity until the bind itself succeeds) — reqDN, the identity the
        # client attempted to bind as, is the only "who" a bind record has,
        # so it stands in for actor here rather than being left blank.
        function print_record(    op, who) {
          op = is_bind ? "bind" : "search"
          who = is_bind ? dn : actor
          printf "{\"pod\":\"%s\",\"source\":\"accesslog\",\"time\":\"%s\",\"actor\":\"%s\",\"op\":\"%s\",\"target\":\"%s\",\"filter\":\"%s\",\"result\":\"%s\"}\n", \
            pod, esc(t), esc(who), op, esc(dn), esc(filt), esc(result)
        }
        END { if (t != "") print_record() }
      '
    done
  fi
fi
