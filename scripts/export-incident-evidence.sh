#!/usr/bin/env bash
# Export a deterministic, redacted, versioned incident-evidence bundle for an
# ldapium deployment: a self-contained snapshot an external consumer (a
# human, a runbook, an offline/local-LLM RCA tool) can read to understand
# "what does this directory look like right now" without that consumer ever
# needing write access, an LDAP bind of its own, or a network call to any AI
# service. See docs/incident-evidence.md for the schema, the redaction
# guarantee, and the read-only ChatOps/RCA contract this bundle exists to
# satisfy (issue #12) — ldapium ships no ChatOps bot, no AI service, and no
# remediation executor; this script and its output are the entire boundary.
#
# D1: connection flags/env vars mirror scripts/backup.sh (-H/-D/-b,
# --password-file/--password-env), not scripts/export-audit-log.sh's own
# kubectl+get-credentials.sh discovery — export-audit-log.sh has no direct
# host/bind-DN/password-file/TLS convention of its own to reuse (it never
# binds directly; it execs into pods and reads a password get-credentials.sh
# resolved for it). backup.sh already established the direct-connection
# convention this project uses, so that is what is reused. audit-tail.ndjson
# still comes from export-audit-log.sh itself (via kubectl, when reachable)
# or from a pre-captured --audit-log-file, rather than reimplementing its
# accesslog/auditlog parsing here.
#
# D2: JSON key ordering is stabilized with `jq -S` per the issue's own
# determinism requirement; timestamp arithmetic (contextCSN lag, GeneralizedTime
# parsing, cert-expiry days-remaining, backup age) uses python3 instead of
# shell `date` — this project's own export-audit-log.sh documents GNU-vs-BSD
# `date` arithmetic as a real hazard it deliberately avoids, and python3 is
# already an accepted dependency here (scripts/bench-load.sh,
# scripts/bench-replication.sh).
#
# D3: redaction runs twice: proactively while each section is built (only
# known-safe fields are ever copied into a section file; credentials="..."
# is stripped from any raw olcSyncrepl line before it is quoted) and once
# more as a blanket defense-in-depth pass over every file's bytes, followed
# by a whole-bundle grep assertion that fails the run if anything matching
# (?i)password|secret|credential|token still holds a live value.
#
#   ./scripts/export-incident-evidence.sh -b dc=example,dc=org \
#     --password-env LDAP_ADMIN_PASSWORD -o ./incident-evidence
#
#   # fully offline / deterministic (used by scripts/test-incident-evidence.sh):
#   ./scripts/export-incident-evidence.sh -b dc=example,dc=org --skip-health \
#     --monitor-ldif fixtures/monitor.ldif \
#     --replication-ldif fixtures/replication.ldif \
#     --audit-log-file fixtures/audit-tail.ndjson \
#     --fixed-time 2026-09-03T00:00:00Z -o /tmp/out
set -euo pipefail
prog=$(basename "$0")

usage() {
  cat <<EOF
Usage: $prog -b ROOT_DN [options]

Produce a single incident-evidence bundle (directory, or --tar for a
.tar.gz) containing manifest.json plus one file per section: health.json,
monitor.json, replication.json, config-drift.txt, backup.json,
audit-tail.ndjson, tls.json.

Connection (same conventions as scripts/backup.sh):
  -b, --root-dn DN          Directory root DN. Required.
  -H, --url URL             LDAP_URL env var default. Default: ldap://localhost:389
  -D, --admin-dn DN         LDAP_ADMIN_DN env var default. Default: cn=admin,ROOT_DN
      --config-admin-dn DN  Default: cn=admin,cn=config
      --password-file PATH  Read the admin password from this file.
      --password-env NAME   Env var holding the admin password. Default: LDAP_ADMIN_PASSWORD

Output:
  -o, --output-dir DIR      Where the bundle is written. Default: ./incident-evidence
      --tar                 Write DIR.tar.gz instead of a loose directory.
      --fixed-time RFC3339  Use this instant as "generated-at" and as "now"
                             for every age/lag calculation, instead of the
                             wall clock — for byte-identical repeat runs.

Section inputs (each has a live path and an offline/file path):
      --skip-health              Do not attempt an anonymous bind/ping.
      --monitor-ldif FILE        Parse this ldapsearch -LLL cn=Monitor dump
                                 instead of querying live.
      --replication-ldif FILE    Parse this file instead of querying live
                                 contextCSN/olcSyncrepl. Format: one or more
                                 "# provider: <name>" headed blocks, each an
                                 ldapsearch -LLL dump of contextCSN (and,
                                 optionally, an olcSyncrepl: line).
      --audit-log-file FILE      Use this NDJSON file (the format
                                 scripts/export-audit-log.sh emits) instead of
                                 invoking it live.
      --audit-lines N            Tail length for audit-tail.ndjson. Default: 200
      --k8s-namespace NS         Passed to export-audit-log.sh as -n, for a
                                 live audit fetch when --audit-log-file is not given.
      --k8s-release NAME         Passed to export-audit-log.sh as -r.
      --config-drift-baseline FILE
                                 Passed to scripts/detect-config-drift.sh --check
                                 (requires kubectl + --k8s-namespace/--k8s-release
                                 reachability). Without kubectl reachable, this is
                                 recorded as unavailable rather than attempted.
      --backup-dir DIR          A scripts/backup.sh output directory; the
                                 newest manifest-*.sha256 there is used.
      --cert-file FILE          Inspect this PEM file instead of probing a
                                 live LDAPS endpoint with openssl s_client.
      --tls-host HOST:PORT      Live TLS probe target. Default: derived from
                                 --url when it is ldaps://.

Finding thresholds (all default to this chart's own
charts/ldapium/examples/metrics-values.yaml profile):
      --replication-lag-threshold-seconds N   Default: 30
      --cert-expiry-warning-days N            Default: 30
      --backup-max-age-seconds N              Default: 93600
      --auth-failure-threshold N              Default: 5
      --auth-failure-window-seconds N         Default: 300

  -h, --help                 This text.
EOF
}

root_dn=""
ldap_url="${LDAP_URL:-ldap://localhost:389}"
admin_dn="${LDAP_ADMIN_DN:-}"
config_admin_dn="cn=admin,cn=config"
password_file=""
password_env="LDAP_ADMIN_PASSWORD"
output_dir="./incident-evidence"
make_tar=0
fixed_time=""
skip_health=0
monitor_ldif=""
replication_ldif=""
audit_log_file=""
audit_lines=200
k8s_namespace=""
k8s_release=""
config_drift_baseline=""
backup_dir=""
cert_file=""
tls_host=""
repl_lag_threshold=30
cert_warn_days=30
backup_max_age=93600
auth_fail_threshold=5
auth_fail_window=300

while [ $# -gt 0 ]; do
  case "$1" in
    -b|--root-dn) root_dn="${2:?-b needs a DN}"; shift 2 ;;
    -H|--url) ldap_url="${2:?-H needs a URL}"; shift 2 ;;
    -D|--admin-dn) admin_dn="${2:?-D needs a DN}"; shift 2 ;;
    --config-admin-dn) config_admin_dn="${2:?--config-admin-dn needs a DN}"; shift 2 ;;
    --password-file) password_file="${2:?--password-file needs a path}"; shift 2 ;;
    --password-env) password_env="${2:?--password-env needs a variable name}"; shift 2 ;;
    -o|--output-dir) output_dir="${2:?-o needs a directory}"; shift 2 ;;
    --tar) make_tar=1; shift ;;
    --fixed-time) fixed_time="${2:?--fixed-time needs an RFC3339 timestamp}"; shift 2 ;;
    --skip-health) skip_health=1; shift ;;
    --monitor-ldif) monitor_ldif="${2:?--monitor-ldif needs a path}"; shift 2 ;;
    --replication-ldif) replication_ldif="${2:?--replication-ldif needs a path}"; shift 2 ;;
    --audit-log-file) audit_log_file="${2:?--audit-log-file needs a path}"; shift 2 ;;
    --audit-lines) audit_lines="${2:?--audit-lines needs a number}"; shift 2 ;;
    --k8s-namespace) k8s_namespace="${2:?--k8s-namespace needs a value}"; shift 2 ;;
    --k8s-release) k8s_release="${2:?--k8s-release needs a value}"; shift 2 ;;
    --config-drift-baseline) config_drift_baseline="${2:?--config-drift-baseline needs a path}"; shift 2 ;;
    --backup-dir) backup_dir="${2:?--backup-dir needs a path}"; shift 2 ;;
    --cert-file) cert_file="${2:?--cert-file needs a path}"; shift 2 ;;
    --tls-host) tls_host="${2:?--tls-host needs host:port}"; shift 2 ;;
    --replication-lag-threshold-seconds) repl_lag_threshold="${2:?needs a number}"; shift 2 ;;
    --cert-expiry-warning-days) cert_warn_days="${2:?needs a number}"; shift 2 ;;
    --backup-max-age-seconds) backup_max_age="${2:?needs a number}"; shift 2 ;;
    --auth-failure-threshold) auth_fail_threshold="${2:?needs a number}"; shift 2 ;;
    --auth-failure-window-seconds) auth_fail_window="${2:?needs a number}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

log() { printf '[incident-evidence] %s\n' "$*" >&2; }

[ -n "$root_dn" ] || { echo "root DN required (-b)" >&2; exit 2; }
case "$root_dn" in dc=*) ;; *) echo "root DN must start with dc=" >&2; exit 2 ;; esac
admin_dn="${admin_dn:-cn=admin,${root_dn}}"

for bin in jq python3 sha256sum mktemp grep sed; do
  command -v "$bin" >/dev/null 2>&1 || { echo "required command not found: $bin" >&2; exit 1; }
done

# Fail fast, before any live LDAP/kubectl work, rather than silently wiping
# whatever the operator already had at -o — scripts/backup.sh's own output
# path is never destructive (it only ever creates new timestamped files),
# and this script matches that: an existing, non-empty output directory (or
# an existing archive at --tar's target path) is refused outright, never
# overwritten.
if [ "$make_tar" = 1 ]; then
  if [ -e "${output_dir}.tar.gz" ]; then
    echo "refusing to overwrite existing file: ${output_dir}.tar.gz" >&2
    exit 1
  fi
elif [ -e "$output_dir" ]; then
  [ -d "$output_dir" ] || { echo "output path exists and is not a directory: ${output_dir}" >&2; exit 1; }
  if [ -n "$(find "$output_dir" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
    echo "output directory already exists and is not empty — refusing to overwrite it: ${output_dir}" >&2
    exit 1
  fi
fi

# Password is only needed for live LDAP calls (health/monitor/replication
# sections without their offline *-ldif/--skip-health equivalents). Resolved
# up front, same as backup.sh, but never required outright: a fully offline
# run (all --*-ldif/--audit-log-file flags plus --skip-health) needs no
# credential at all.
cleanup_pwfile=0
pwfile=""
resolve_password() {
  if [ -n "$password_file" ]; then
    [ -r "$password_file" ] || { echo "password file not readable: $password_file" >&2; exit 1; }
    pwfile="$password_file"
    return 0
  fi
  local password="${!password_env:-}"
  [ -n "$password" ] || return 1
  umask 077
  pwfile=$(mktemp)
  printf '%s' "$password" > "$pwfile"
  cleanup_pwfile=1
}

work_dir=$(mktemp -d)
cleanup() {
  [ "$cleanup_pwfile" = 1 ] && rm -f "$pwfile"
  rm -rf "$work_dir"
}
trap cleanup EXIT

if [ -n "$fixed_time" ]; then
  now_iso="$fixed_time"
else
  now_iso=$(date -u +%Y-%m-%dT%H:%M:%SZ)
fi
# now_epoch drives every age/lag calculation below; python3's own ISO8601
# parser (not shell `date -d`, which is a GNU-only flag) so --fixed-time
# behaves identically on macOS and Linux.
now_epoch=$(python3 - "$now_iso" <<'PY'
import sys, datetime
s = sys.argv[1].replace("Z", "+00:00")
print(int(datetime.datetime.fromisoformat(s).timestamp()))
PY
)

bundle_name="incident-evidence-$(printf '%s' "$now_iso" | tr -d ':' )"
bundle_dir="${work_dir}/${bundle_name}"
mkdir -p "$bundle_dir"

# ---------------------------------------------------------------------------
# redact_file FILE — blanket defense-in-depth pass, applied to every file
# this script writes. Structured sections only ever contain fields this
# script deliberately chose to copy (see each section builder below), so in
# the common case this is a no-op; it exists for the raw/semi-raw sections
# (config-drift.txt, audit-tail.ndjson, any quoted olcSyncrepl line) where a
# value from the directory passes through closer to verbatim.
#
# .json/.ndjson files are redacted structurally (parse -> walk ->
# re-serialize), not with a whole-file regex: a plain-text regex applied to
# raw JSON bytes can't tell a value's content from the JSON syntax around
# it — a text-substring match like "userPassword=hunter2" embedded inside a
# quoted LDAP filter value ("filter":"(userPassword=hunter2)") has no
# reliable stopping point on undecoded JSON, and an earlier, greedier
# version of this regex ate the record's own closing quote/brace, producing
# invalid NDJSON. Walking the parsed structure means the redaction only
# ever touches a string's content; json's own serializer re-escapes it
# correctly no matter what ends up inside.
# ---------------------------------------------------------------------------
redact_file() {
  case "$1" in
    *.json|*.ndjson) redact_json_file "$1" ;;
    *) redact_text_file "$1" ;;
  esac
}

redact_text_file() {
  python3 - "$1" <<'PY'
import re, sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8", errors="replace") as f:
    text = f.read()

SENSITIVE = r'(?:user)?password\w*|secret\w*|credential\w*|token\w*'

# olcSyncrepl-style inline attr="value" or attr=value (unquoted) pairs.
text = re.sub(
    r'(?i)\b(' + SENSITIVE + r')(\s*=\s*)"([^"]*)"',
    lambda m: m.group(1) + m.group(2) + '"<redacted>"',
    text,
)
text = re.sub(
    r'(?i)\b(' + SENSITIVE + r')(\s*=\s*)(?!")([^\s")}\],]+)',
    lambda m: m.group(1) + m.group(2) + '<redacted>',
    text,
)
# LDIF-style "attr: value" / "attr:: base64value" lines.
text = re.sub(
    r'(?im)^(\s*(?:' + SENSITIVE + r')\s*:{1,2}\s*).*$',
    lambda m: m.group(1) + '<redacted>',
    text,
)
with open(path, "w", encoding="utf-8") as f:
    f.write(text)
PY
}

# redact_json_file FILE — .json is one JSON value; .ndjson is one JSON value
# per line. Each string leaf is redacted in place (an embedded "attr=value"
# fragment, e.g. inside an LDAP filter) and any object key that is itself a
# sensitive attribute name has its whole value replaced — belt-and-braces
# for a case this script's own section builders never produce today, but a
# structural guarantee is cheap here and costs nothing while unused. A line
# in a .ndjson file that fails to parse as JSON (a truncated/corrupt record
# — export-audit-log.sh's own consumers already tolerate this) falls back
# to the plain-text substitution for that single line rather than aborting
# the whole file.
redact_json_file() {
  python3 - "$1" <<'PY'
import json, re, sys

path = sys.argv[1]
is_ndjson = path.endswith(".ndjson")

SENSITIVE = r'(?:user)?password\w*|secret\w*|credential\w*|token\w*'
KEY_RE = re.compile(r'(?i)^(?:' + SENSITIVE + r')$')
VALUE_RE = re.compile(r'(?i)\b(' + SENSITIVE + r')(\s*=\s*)(?!")([^\s")}\],]+)')


def redact_string(s):
    return VALUE_RE.sub(lambda m: m.group(1) + m.group(2) + "<redacted>", s)


def walk(obj):
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if KEY_RE.match(k):
                out[k] = "<redacted>"
            else:
                out[k] = walk(v)
        return out
    if isinstance(obj, list):
        return [walk(v) for v in obj]
    if isinstance(obj, str):
        return redact_string(obj)
    return obj


with open(path, "r", encoding="utf-8", errors="replace") as f:
    text = f.read()

if is_ndjson:
    out_lines = []
    for line in text.split("\n"):
        if line == "":
            out_lines.append(line)
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            out_lines.append(VALUE_RE.sub(lambda m: m.group(1) + m.group(2) + "<redacted>", line))
            continue
        # sort_keys=False: preserve the field order the record was written
        # in (export-audit-log.sh's own schema), not an arbitrary one.
        out_lines.append(json.dumps(walk(obj), sort_keys=False))
    new_text = "\n".join(out_lines)
else:
    obj = json.loads(text)
    new_text = json.dumps(walk(obj), sort_keys=True, indent=2) + "\n"

with open(path, "w", encoding="utf-8") as f:
    f.write(new_text)
PY
}

findings_file="${work_dir}/findings.jsonl"
: > "$findings_file"
add_finding() {
  # add_finding ID SEVERITY DETAIL
  jq -n --arg id "$1" --arg severity "$2" --arg detail "$3" \
    '{id: $id, severity: $severity, detail: $detail}' >> "$findings_file"
}

sections_file="${work_dir}/sections.jsonl"
: > "$sections_file"
write_section() {
  # write_section NAME RELATIVE_FILENAME
  local name="$1" rel="$2" path="${bundle_dir}/${2}"
  redact_file "$path"
  local sha
  sha=$(sha256sum "$path" | awk '{print $1}')
  jq -n --arg name "$name" --arg file "$rel" --arg sha256 "$sha" \
    '{name: $name, file: $file, sha256: $sha256}' >> "$sections_file"
}

# ---------------------------------------------------------------------------
# health.json — anonymous bind/ping and its latency.
# ---------------------------------------------------------------------------
build_health() {
  local out="${bundle_dir}/health.json"
  if [ "$skip_health" = 1 ]; then
    jq -n '{status: "skipped", reason: "--skip-health"}' | jq -S . > "$out"
  else
    command -v ldapwhoami >/dev/null 2>&1 || {
      jq -n '{status: "skipped", reason: "ldapwhoami not found on PATH"}' | jq -S . > "$out"
      write_section health health.json
      return 0
    }
    local start_ms end_ms latency_ms status
    start_ms=$(python3 -c 'import time; print(int(time.time()*1000))')
    if ldapwhoami -x -H "$ldap_url" -o nettimeout=5 >/dev/null 2>&1; then
      status="ok"
    else
      status="failed"
    fi
    end_ms=$(python3 -c 'import time; print(int(time.time()*1000))')
    latency_ms=$((end_ms - start_ms))
    jq -n --arg status "$status" --arg url "$ldap_url" --argjson latencyMs "$latency_ms" \
      '{status: $status, url: $url, latencyMs: $latencyMs}' | jq -S . > "$out"
  fi
  write_section health health.json
}

# ---------------------------------------------------------------------------
# monitor.json — cn=Monitor counters, same attribute names/grouping as
# ui/backend/internal/ldapclient/monitor.go's MonitorStats.
# ---------------------------------------------------------------------------
build_monitor() {
  local out="${bundle_dir}/monitor.json" ldif="${work_dir}/monitor.ldif"
  if [ -n "$monitor_ldif" ]; then
    [ -r "$monitor_ldif" ] || { echo "--monitor-ldif not readable: $monitor_ldif" >&2; exit 1; }
    cp "$monitor_ldif" "$ldif"
  elif resolve_password && command -v ldapsearch >/dev/null 2>&1; then
    ldapsearch -x -H "$ldap_url" -D "$admin_dn" -y "$pwfile" -o ldif-wrap=no -LLL \
      -b cn=Monitor '(objectClass=*)' cn monitorCounter monitorOpInitiated monitorOpCompleted monitoredInfo \
      > "$ldif" 2>/dev/null || : > "$ldif"
  else
    : > "$ldif"
  fi

  if [ ! -s "$ldif" ]; then
    jq -n '{status: "unavailable", reason: "no cn=Monitor data (no --monitor-ldif and no live read succeeded)"}' \
      | jq -S . > "$out"
    write_section monitor monitor.json
    return 0
  fi

  python3 - "$ldif" > "$out" <<'PY'
import sys, json

path = sys.argv[1]
entries = []
cur = None
for raw in open(path, encoding="utf-8", errors="replace"):
    line = raw.rstrip("\n")
    if line.startswith("dn:"):
        if cur is not None:
            entries.append(cur)
        cur = {"dn": line.split(":", 1)[1].strip(), "attrs": {}}
        continue
    if cur is None or not line.strip() or line.startswith("#"):
        continue
    if ":" not in line:
        continue
    k, v = line.split(":", 1)
    cur["attrs"].setdefault(k.strip(), []).append(v.strip(": ").strip())
if cur is not None:
    entries.append(cur)

def first(attrs, name):
    vals = attrs.get(name) or []
    return vals[0] if vals else None

connections = {"current": 0, "total": 0, "maxFileDescriptors": 0}
threads = {"active": 0, "max": 0, "maxPending": 0}
operations = []

for e in entries:
    dn = e["dn"].lower()
    cn = first(e["attrs"], "cn") or ""
    if dn.endswith(",cn=connections,cn=monitor"):
        v = int(first(e["attrs"], "monitorCounter") or 0)
        if cn == "Current":
            connections["current"] = v
        elif cn == "Total":
            connections["total"] = v
        elif cn == "Max File Descriptors":
            connections["maxFileDescriptors"] = v
    elif dn.endswith(",cn=operations,cn=monitor"):
        operations.append({
            "name": cn,
            "initiated": int(first(e["attrs"], "monitorOpInitiated") or 0),
            "completed": int(first(e["attrs"], "monitorOpCompleted") or 0),
        })
    elif dn.endswith(",cn=threads,cn=monitor"):
        v = int(first(e["attrs"], "monitoredInfo") or 0)
        if cn == "Active":
            threads["active"] = v
        elif cn == "Max":
            threads["max"] = v
        elif cn == "Max Pending":
            threads["maxPending"] = v

operations.sort(key=lambda o: o["name"])
json.dump({"connections": connections, "threads": threads, "operations": operations}, sys.stdout, sort_keys=True)
PY
  jq -S . "$out" > "${out}.tmp" && mv "${out}.tmp" "$out"
  write_section monitor monitor.json
}

# ---------------------------------------------------------------------------
# replication.json — contextCSN per provider/base, and whether olcSyncrepl is
# configured (never its credentials).
# ---------------------------------------------------------------------------
build_replication() {
  local out="${bundle_dir}/replication.json" raw="${work_dir}/replication.raw"
  if [ -n "$replication_ldif" ]; then
    [ -r "$replication_ldif" ] || { echo "--replication-ldif not readable: $replication_ldif" >&2; exit 1; }
    cp "$replication_ldif" "$raw"
  elif resolve_password && command -v ldapsearch >/dev/null 2>&1; then
    {
      echo "# provider: self"
      ldapsearch -x -H "$ldap_url" -D "$admin_dn" -y "$pwfile" -o ldif-wrap=no -LLL \
        -b "$root_dn" -s base contextCSN 2>/dev/null || true
      ldapsearch -x -H "$ldap_url" -D "$config_admin_dn" -y "$pwfile" -o ldif-wrap=no -LLL \
        -b cn=config olcSyncrepl 2>/dev/null || true
    } > "$raw"
  else
    : > "$raw"
  fi

  # olcSyncrepl carries its bind password as credentials="..." (see
  # image/entrypoint.sh) — stripped here, before anything derived from this
  # file is quoted into replication.json, not left to the blanket
  # redact_file pass alone.
  sed -E 's/(credentials=")[^"]*(")/\1<redacted>\2/' "$raw" > "${raw}.redacted" 2>/dev/null || cp "$raw" "${raw}.redacted"

  if [ ! -s "$raw" ]; then
    jq -n --arg base "$root_dn" '{status: "unavailable", base: $base, reason: "no replication data (no --replication-ldif and no live read succeeded)"}' \
      | jq -S . > "$out"
    write_section replication replication.json
    return 0
  fi

  python3 - "${raw}.redacted" "$root_dn" "$now_epoch" "$repl_lag_threshold" > "${work_dir}/replication.build.json" <<'PY'
import sys, json, re

path, base, now_epoch, threshold = sys.argv[1], sys.argv[2], int(sys.argv[3]), float(sys.argv[4])

def csn_to_epoch(csn):
    # contextCSN: <GeneralizedTime>#<count>#<serverID>#<mod> — only the
    # leading timestamp is used for lag; see image/entrypoint.sh's own
    # olcMultiProvider/CSN comments for the full field meaning.
    m = re.match(r'^(\d{14})(?:\.(\d+))?Z', csn)
    if not m:
        return None
    from datetime import datetime, timezone
    ts = datetime.strptime(m.group(1), "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    frac = float("0." + m.group(2)) if m.group(2) else 0.0
    return ts.timestamp() + frac

provider = None
providers = {}
syncrepl_configured = False
syncrepl_lines = []
for raw in open(path, encoding="utf-8", errors="replace"):
    line = raw.rstrip("\n")
    m = re.match(r'^#\s*provider:\s*(.+)$', line)
    if m:
        provider = m.group(1).strip()
        providers.setdefault(provider, [])
        continue
    m = re.match(r'^contextCSN:\s*(.+)$', line)
    if m and provider is not None:
        providers[provider].append(m.group(1).strip())
        continue
    if line.startswith("olcSyncrepl:"):
        syncrepl_configured = True
        syncrepl_lines.append(line[len("olcSyncrepl:"):].strip())

provider_records = []
epochs = {}
for name, csns in providers.items():
    parsed_epochs = [csn_to_epoch(c) for c in csns]
    parsed_epochs = [e for e in parsed_epochs if e is not None]
    latest = max(parsed_epochs) if parsed_epochs else None
    if latest is not None:
        epochs[name] = latest
    provider_records.append({
        "provider": name,
        "contextCSN": sorted(csns),
        "latestTimestampEpoch": latest,
    })

provider_records.sort(key=lambda p: p["provider"])

lag_seconds = None
if len(epochs) >= 2:
    lag_seconds = max(epochs.values()) - min(epochs.values())

result = {
    "base": base,
    "providers": provider_records,
    "syncreplConfigured": syncrepl_configured,
    "maxLagSeconds": lag_seconds,
}
print(json.dumps(result, sort_keys=True))
PY
  jq -S . "${work_dir}/replication.build.json" > "$out"
  write_section replication replication.json

  local lag
  lag=$(jq -r '.maxLagSeconds // empty' "$out")
  if [ -n "$lag" ]; then
    # awk for the float comparison — bash arithmetic is integer-only and
    # lag/threshold may both carry fractional seconds.
    if awk -v l="$lag" -v t="$repl_lag_threshold" 'BEGIN{exit !(l > t)}'; then
      add_finding "replication-lag" "warning" "max contextCSN lag across providers is ${lag}s, above the ${repl_lag_threshold}s threshold"
    fi
  fi
}

# ---------------------------------------------------------------------------
# config-drift.txt
# ---------------------------------------------------------------------------
build_config_drift() {
  local out="${bundle_dir}/config-drift.txt"
  if [ -z "$config_drift_baseline" ]; then
    echo "no baseline" > "$out"
  elif ! command -v kubectl >/dev/null 2>&1; then
    echo "baseline provided (${config_drift_baseline}) but kubectl is not available in this environment — drift check skipped" > "$out"
  else
    local args=(--check "$config_drift_baseline")
    [ -n "$k8s_namespace" ] && args+=(-n "$k8s_namespace")
    [ -n "$k8s_release" ] && args+=(-r "$k8s_release")
    if "$(dirname "$0")/detect-config-drift.sh" "${args[@]}" > "$out" 2>&1; then
      :
    else
      echo "(detect-config-drift.sh exited non-zero — see output above; treat as drift/unavailable)" >> "$out"
    fi
  fi
  write_section config-drift config-drift.txt
}

# ---------------------------------------------------------------------------
# backup.json — latest backup manifest timestamp/age, from a
# scripts/backup.sh output directory.
# ---------------------------------------------------------------------------
build_backup() {
  local out="${bundle_dir}/backup.json"
  if [ -z "$backup_dir" ]; then
    jq -n '{status: "not-configured", reason: "no --backup-dir given"}' | jq -S . > "$out"
    write_section backup backup.json
    return 0
  fi
  if [ ! -d "$backup_dir" ]; then
    jq -n --arg dir "$backup_dir" '{status: "unavailable", reason: "backup dir does not exist", dir: $dir}' \
      | jq -S . > "$out"
    write_section backup backup.json
    return 0
  fi
  # manifest-<ts>.sha256, ts = %Y%m%dT%H%M%SZ (scripts/backup.sh) — sorting
  # the filename sorts by time too, since the timestamp format is
  # lexicographically ordered.
  local latest
  latest=$(find "$backup_dir" -maxdepth 1 -name 'manifest-*.sha256' 2>/dev/null | sort | tail -1)
  if [ -z "$latest" ]; then
    jq -n --arg dir "$backup_dir" '{status: "unavailable", reason: "no manifest-*.sha256 found", dir: $dir}' \
      | jq -S . > "$out"
    write_section backup backup.json
    return 0
  fi
  local base ts age status
  base=$(basename "$latest")
  ts=$(printf '%s' "$base" | sed -E 's/^manifest-(.+)\.sha256$/\1/')
  local ts_epoch
  ts_epoch=$(python3 - "$ts" <<'PY'
import sys, datetime
ts = sys.argv[1]
try:
    dt = datetime.datetime.strptime(ts, "%Y%m%dT%H%M%SZ").replace(tzinfo=datetime.timezone.utc)
    print(int(dt.timestamp()))
except ValueError:
    print("")
PY
)
  if [ -z "$ts_epoch" ]; then
    jq -n --arg dir "$backup_dir" --arg file "$base" \
      '{status: "unavailable", reason: "manifest filename timestamp did not parse", dir: $dir, file: $file}' \
      | jq -S . > "$out"
    write_section backup backup.json
    return 0
  fi
  age=$(( now_epoch - ts_epoch ))
  if [ "$age" -gt "$backup_max_age" ]; then
    status="stale"
  else
    status="ok"
  fi
  jq -n --arg dir "$backup_dir" --arg file "$base" --arg ts "$ts" \
    --argjson ageSeconds "$age" --argjson maxAgeSeconds "$backup_max_age" --arg status "$status" \
    '{status: $status, dir: $dir, latestManifest: $file, timestamp: $ts, ageSeconds: $ageSeconds, maxAgeSeconds: $maxAgeSeconds}' \
    | jq -S . > "$out"
  write_section backup backup.json
  if [ "$status" = "stale" ]; then
    add_finding "backup-stale" "warning" "latest backup (${base}) is ${age}s old, above the ${backup_max_age}s threshold"
  fi
}

# ---------------------------------------------------------------------------
# audit-tail.ndjson — last N records, from export-audit-log.sh or a
# pre-captured file; also feeds the auth-failure-burst finding.
# ---------------------------------------------------------------------------
build_audit() {
  local out="${bundle_dir}/audit-tail.ndjson" full="${work_dir}/audit-full.ndjson"
  if [ -n "$audit_log_file" ]; then
    [ -r "$audit_log_file" ] || { echo "--audit-log-file not readable: $audit_log_file" >&2; exit 1; }
    cp "$audit_log_file" "$full"
  elif command -v kubectl >/dev/null 2>&1; then
    local args=()
    [ -n "$k8s_namespace" ] && args+=(-n "$k8s_namespace")
    [ -n "$k8s_release" ] && args+=(-r "$k8s_release")
    "$(dirname "$0")/export-audit-log.sh" "${args[@]}" > "$full" 2>/dev/null || : > "$full"
  else
    : > "$full"
  fi
  tail -n "$audit_lines" "$full" > "$out" 2>/dev/null || : > "$out"
  write_section audit audit-tail.ndjson

  # auth-failure-burst: bind records (accesslog "op":"bind" or auditlog
  # "op":"bind") whose result is not LDAP_SUCCESS ("0"), clustered within
  # --auth-failure-window-seconds of the newest such record in the tail.
  # LDAP GeneralizedTime for accesslog, raw epoch for auditlog — both are
  # what export-audit-log.sh itself documents as the two time formats this
  # stream carries; each is parsed on its own terms rather than reformatted.
  python3 - "$out" "$auth_fail_window" "$auth_fail_threshold" >> "$findings_file" <<'PY'
import sys, json, re
from datetime import datetime, timezone

path, window, threshold = sys.argv[1], float(sys.argv[2]), int(sys.argv[3])

def to_epoch(rec):
    t = rec.get("time", "")
    if re.match(r'^\d{14}(\.\d+)?Z$', t):
        m = re.match(r'^(\d{14})', t)
        return datetime.strptime(m.group(1), "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc).timestamp()
    try:
        return float(t)
    except ValueError:
        return None

fails = []
for line in open(path, encoding="utf-8", errors="replace"):
    line = line.strip()
    if not line:
        continue
    try:
        rec = json.loads(line)
    except json.JSONDecodeError:
        continue
    if rec.get("op") != "bind":
        continue
    if rec.get("result") in (None, "0"):
        continue
    epoch = to_epoch(rec)
    if epoch is not None:
        fails.append(epoch)

if fails:
    fails.sort()
    newest = fails[-1]
    burst = [f for f in fails if newest - f <= window]
    if len(burst) >= threshold:
        print(json.dumps({
            "id": "auth-failure-burst",
            "severity": "warning",
            "detail": f"{len(burst)} failed bind(s) within {window}s of the most recent, at or above the {threshold}-failure threshold",
        }))
PY
}

# ---------------------------------------------------------------------------
# tls.json — server cert subject/issuer/notAfter/days-remaining.
# ---------------------------------------------------------------------------
build_tls() {
  local out="${bundle_dir}/tls.json"
  local pem="${work_dir}/tls.pem"
  local have_cert=0

  if [ -n "$cert_file" ]; then
    [ -r "$cert_file" ] || { echo "--cert-file not readable: $cert_file" >&2; exit 1; }
    cp "$cert_file" "$pem"
    have_cert=1
  elif command -v openssl >/dev/null 2>&1; then
    local host=""
    if [ -n "$tls_host" ]; then
      host="$tls_host"
    else
      case "$ldap_url" in
        ldaps://*)
          host="${ldap_url#ldaps://}"
          host="${host%%/*}"
          case "$host" in *:*) ;; *) host="${host}:636" ;; esac
          ;;
      esac
    fi
    if [ -n "$host" ]; then
      if openssl s_client -connect "$host" -servername "${host%%:*}" </dev/null 2>/dev/null \
        | openssl x509 > "$pem" 2>/dev/null && [ -s "$pem" ]; then
        have_cert=1
      fi
    fi
  fi

  if [ "$have_cert" = 0 ]; then
    jq -n '{status: "not-applicable", reason: "no --cert-file given and no live ldaps:// endpoint to probe"}' \
      | jq -S . > "$out"
    write_section tls tls.json
    return 0
  fi

  local subject issuer not_after
  subject=$(openssl x509 -in "$pem" -noout -subject 2>/dev/null | sed 's/^subject=\s*//')
  issuer=$(openssl x509 -in "$pem" -noout -issuer 2>/dev/null | sed 's/^issuer=\s*//')
  not_after=$(openssl x509 -in "$pem" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')

  local not_after_epoch days_remaining
  not_after_epoch=$(python3 - "$not_after" <<'PY'
import sys, datetime
s = sys.argv[1].strip()
try:
    dt = datetime.datetime.strptime(s, "%b %d %H:%M:%S %Y %Z")
    print(int(dt.replace(tzinfo=datetime.timezone.utc).timestamp()))
except ValueError:
    print("")
PY
)
  if [ -n "$not_after_epoch" ]; then
    days_remaining=$(( (not_after_epoch - now_epoch) / 86400 ))
  else
    days_remaining=""
  fi

  jq -n --arg subject "$subject" --arg issuer "$issuer" --arg notAfter "$not_after" \
    --argjson daysRemaining "${days_remaining:-null}" \
    '{status: "ok", subject: $subject, issuer: $issuer, notAfter: $notAfter, daysRemaining: $daysRemaining}' \
    | jq -S . > "$out"
  write_section tls tls.json

  if [ -n "$days_remaining" ] && [ "$days_remaining" -lt "$cert_warn_days" ]; then
    add_finding "tls-cert-expiry" "warning" "server certificate has ${days_remaining} day(s) remaining, below the ${cert_warn_days}-day threshold"
  fi
}

log "building bundle in ${bundle_dir}"
build_health
build_monitor
build_replication
build_config_drift
build_backup
build_audit
build_tls

# manifest.json — fixed section order regardless of build order above, so
# the file is stable even if a future section is reordered in the script.
manifest_order='["health","monitor","replication","config-drift","backup","audit","tls"]'
jq -s --argjson order "$manifest_order" '
  map({(.name): .}) | add as $bySection
  | $order | map($bySection[.])
' "$sections_file" > "${work_dir}/sections.ordered.json"

jq -s '.' "$findings_file" > "${work_dir}/findings.json"

jq -n \
  --arg schemaVersion "1" \
  --arg generatedAt "$now_iso" \
  --slurpfile sections "${work_dir}/sections.ordered.json" \
  --slurpfile findings "${work_dir}/findings.json" \
  '{
    schemaVersion: $schemaVersion,
    generatedAt: $generatedAt,
    sections: $sections[0],
    findings: $findings[0]
  }' | jq -S . > "${bundle_dir}/manifest.json"

# ---------------------------------------------------------------------------
# Final redaction assertion — grep the whole bundle for a sensitive key still
# holding a live value. Anything already replaced with "<redacted>" is
# excluded, so this only fails on something the passes above missed.
# ---------------------------------------------------------------------------
assert_no_secrets() {
  local hits
  hits=$(grep -RIn -iE '(userpassword|password|secret|credential|token)[[:space:]]*[:=]' "$1" 2>/dev/null \
    | grep -v '<redacted>' || true)
  if [ -n "$hits" ]; then
    echo "REDACTION FAILURE: sensitive value(s) survived export:" >&2
    printf '%s\n' "$hits" >&2
    exit 1
  fi
}
assert_no_secrets "$bundle_dir"
log "redaction assertion passed"

mkdir -p "$(dirname "$output_dir")" 2>/dev/null || true
if [ "$make_tar" = 1 ]; then
  # Existing-file check already ran before any work started (see above);
  # nothing to delete here.
  tar -C "$work_dir" -czf "${output_dir}.tar.gz" "$bundle_name"
  log "wrote ${output_dir}.tar.gz"
else
  # Never rm -rf a caller-supplied path: the empty-or-nonexistent check
  # above already guarantees $output_dir holds nothing of the operator's to
  # lose, so this only ever creates it or writes into an empty directory —
  # scripts/backup.sh's own output path is equally non-destructive.
  mkdir -p "$output_dir"
  cp -R "$bundle_dir"/. "$output_dir"/
  log "wrote ${output_dir}/"
fi
