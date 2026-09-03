#!/usr/bin/env bash
# Fixture-driven test suite for scripts/export-incident-evidence.sh.
#
# Plain shell with set -e, matching this repo's existing convention (no bats
# anywhere in scripts/ or charts/ldapium/files/tests/ to follow instead —
# checked before adding a new test-runner style).
#
#   ./scripts/test-incident-evidence.sh
#
# Exercises:
#   (a) determinism — the same fixtures + --fixed-time twice produce
#       byte-identical section files (sha256 compared, not just manifest.json)
#   (b) the redaction guarantee — a fixture containing olcSyncrepl
#       credentials never surfaces the raw secret anywhere in the bundle
#   (c) the findings rule set — each scenario fixture yields exactly the
#       finding(s) it is named for, and its "healthy" counterpart yields none
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="${here}/export-incident-evidence.sh"
fixtures="${here}/testdata/incident"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Certificates are generated here rather than committed under
# testdata/incident/: *.pem/*.crt/*.key are blanket-.gitignore'd repo-wide as
# a leak guardrail (see .gitignore), and e2e.yml already establishes the
# precedent of generating TLS material on the fly instead of fighting that
# guardrail with `git add -f`.
#
# `openssl req -x509 -not_before/-not_after` looked like the obvious way to
# pin an absolute expiry, but those flags do not exist on OpenSSL 3.0 (the
# version ubuntu-24.04 runners ship) — only on 3.1+ — so a CI run on that
# runner failed at cert generation under `set -e` before ever reaching the
# script under test. `-days N` is portable back to essentially every OpenSSL
# release; N is computed here as "days until the target calendar date",
# which lands each cert on the same fixed target regardless of what day this
# suite actually runs on, without needing a flag introduced after 3.0.
days_until() { # days_until YYYY-MM-DD
  python3 -c "
import datetime, sys
target = datetime.date.fromisoformat(sys.argv[1])
today = datetime.datetime.now(datetime.timezone.utc).date()
print(max((target - today).days, 1))
" "$1"
}
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "${work}/cert-key.pem" -out "${work}/cert-expiring.pem" \
  -subj "/CN=ldap.example.org" \
  -days "$(days_until 2026-09-15)" >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "${work}/cert-key2.pem" -out "${work}/cert-healthy.pem" \
  -subj "/CN=ldap.example.org" \
  -days "$(days_until 2030-01-01)" >/dev/null 2>&1

fail=0
pass=0

ok() { pass=$((pass + 1)); printf 'ok - %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'NOT OK - %s\n' "$1" >&2; }

# run NAME OUTPUT_DIR [extra export-incident-evidence.sh args...]
run() {
  local name="$1" out="$2"; shift 2
  if ! "$script" -b dc=example,dc=org --skip-health \
    --monitor-ldif "${fixtures}/monitor.ldif" \
    --fixed-time 2026-09-03T00:00:00Z \
    -o "$out" "$@" > "${out}.log" 2>&1; then
    bad "${name}: export-incident-evidence.sh exited non-zero"
    cat "${out}.log" >&2
    return 1
  fi
  return 0
}

has_finding() {
  jq -e --arg id "$2" '.findings[] | select(.id == $id)' "${1}/manifest.json" >/dev/null 2>&1
}

# --- (c) findings rule set -------------------------------------------------

run replication-lag "${work}/lag" \
  --replication-ldif "${fixtures}/replication-lag.ldif" \
  --audit-log-file "${fixtures}/audit-healthy.ndjson" \
  --backup-dir "${fixtures}/backup-fresh" \
  --cert-file "${work}/cert-healthy.pem"
if has_finding "${work}/lag" replication-lag; then ok "replication-lag fixture yields replication-lag finding"; else bad "replication-lag fixture missing replication-lag finding"; fi

run replication-healthy "${work}/repl-healthy" \
  --replication-ldif "${fixtures}/replication-healthy.ldif" \
  --audit-log-file "${fixtures}/audit-healthy.ndjson" \
  --backup-dir "${fixtures}/backup-fresh" \
  --cert-file "${work}/cert-healthy.pem"
if has_finding "${work}/repl-healthy" replication-lag; then bad "replication-healthy fixture unexpectedly has replication-lag finding"; else ok "replication-healthy fixture has no replication-lag finding"; fi

run backup-stale "${work}/backup-stale" \
  --replication-ldif "${fixtures}/replication-healthy.ldif" \
  --audit-log-file "${fixtures}/audit-healthy.ndjson" \
  --backup-dir "${fixtures}/backup-stale" \
  --cert-file "${work}/cert-healthy.pem"
if has_finding "${work}/backup-stale" backup-stale; then ok "backup-stale fixture yields backup-stale finding"; else bad "backup-stale fixture missing backup-stale finding"; fi

run backup-fresh "${work}/backup-fresh" \
  --replication-ldif "${fixtures}/replication-healthy.ldif" \
  --audit-log-file "${fixtures}/audit-healthy.ndjson" \
  --backup-dir "${fixtures}/backup-fresh" \
  --cert-file "${work}/cert-healthy.pem"
if has_finding "${work}/backup-fresh" backup-stale; then bad "backup-fresh fixture unexpectedly has backup-stale finding"; else ok "backup-fresh fixture has no backup-stale finding"; fi

run cert-expiring "${work}/cert-expiring" \
  --replication-ldif "${fixtures}/replication-healthy.ldif" \
  --audit-log-file "${fixtures}/audit-healthy.ndjson" \
  --backup-dir "${fixtures}/backup-fresh" \
  --cert-file "${work}/cert-expiring.pem"
if has_finding "${work}/cert-expiring" tls-cert-expiry; then ok "cert-expiring fixture yields tls-cert-expiry finding"; else bad "cert-expiring fixture missing tls-cert-expiry finding"; fi

run cert-healthy "${work}/cert-healthy" \
  --replication-ldif "${fixtures}/replication-healthy.ldif" \
  --audit-log-file "${fixtures}/audit-healthy.ndjson" \
  --backup-dir "${fixtures}/backup-fresh" \
  --cert-file "${work}/cert-healthy.pem"
if has_finding "${work}/cert-healthy" tls-cert-expiry; then bad "cert-healthy fixture unexpectedly has tls-cert-expiry finding"; else ok "cert-healthy fixture has no tls-cert-expiry finding"; fi

run auth-failure-burst "${work}/auth-burst" \
  --replication-ldif "${fixtures}/replication-healthy.ldif" \
  --audit-log-file "${fixtures}/audit-auth-failure-burst.ndjson" \
  --backup-dir "${fixtures}/backup-fresh" \
  --cert-file "${work}/cert-healthy.pem"
if has_finding "${work}/auth-burst" auth-failure-burst; then ok "auth-failure-burst fixture yields auth-failure-burst finding"; else bad "auth-failure-burst fixture missing auth-failure-burst finding"; fi

# audit-auth-failure-burst.ndjson's trailing "source":"exporter"/"op":"summary"
# record must not be miscounted as a 6th failed bind — the finding text
# names the exact count, so an off-by-one here would show up as "6 failed
# bind(s)" instead of "5 failed bind(s)".
burst_detail=$(jq -r '.findings[] | select(.id == "auth-failure-burst") | .detail' "${work}/auth-burst/manifest.json")
case "$burst_detail" in
  "5 failed bind"*) ok "exporter summary record excluded from the auth-failure-burst count" ;;
  *) bad "auth-failure-burst count is wrong (exporter summary record likely miscounted): ${burst_detail}" ;;
esac

run audit-healthy "${work}/audit-healthy" \
  --replication-ldif "${fixtures}/replication-healthy.ldif" \
  --audit-log-file "${fixtures}/audit-healthy.ndjson" \
  --backup-dir "${fixtures}/backup-fresh" \
  --cert-file "${work}/cert-healthy.pem"
if has_finding "${work}/audit-healthy" auth-failure-burst; then bad "audit-healthy fixture unexpectedly has auth-failure-burst finding"; else ok "audit-healthy fixture has no auth-failure-burst finding"; fi

run sensitive-filter "${work}/sensitive-filter" \
  --replication-ldif "${fixtures}/replication-healthy.ldif" \
  --audit-log-file "${fixtures}/audit-sensitive-filter.ndjson" \
  --backup-dir "${fixtures}/backup-fresh" \
  --cert-file "${work}/cert-healthy.pem"

# --- (b) redaction guarantee ------------------------------------------------
# replication-lag.ldif and replication-healthy.ldif both embed a live
# olcSyncrepl credentials value ("s3cr3t-repl-pw"); it must never surface
# anywhere in either bundle already built above.
if grep -RIl 's3cr3t-repl-pw' "${work}/lag" "${work}/repl-healthy" >/dev/null 2>&1; then
  bad "olcSyncrepl credential leaked into a bundle"
else
  ok "olcSyncrepl credential redacted from every bundle"
fi

# audit-sensitive-filter.ndjson embeds a live secret ("hunter2") inside an
# LDAP filter *value*, not as a top-level JSON key — the shape that used to
# corrupt the NDJSON structure (P1-3: a greedy text-regex redaction ate the
# record's own closing quote/brace). Every line must still be valid JSON
# after redaction, and the secret itself must be gone.
sensitive_tail="${work}/sensitive-filter/audit-tail.ndjson"
if [ ! -s "$sensitive_tail" ]; then
  bad "sensitive-filter fixture: audit-tail.ndjson missing or empty"
else
  json_ok=1
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    if ! printf '%s' "$line" | jq -e . >/dev/null 2>&1; then
      json_ok=0
      printf 'invalid NDJSON line after redaction: %s\n' "$line" >&2
    fi
  done < "$sensitive_tail"
  if [ "$json_ok" = 1 ]; then ok "every audit-tail.ndjson line still parses as JSON after redaction"; else bad "redaction produced invalid NDJSON"; fi
fi
if grep -RIl 'hunter2' "${work}/sensitive-filter" >/dev/null 2>&1; then
  bad "sensitive reqFilter value (hunter2) leaked into the bundle"
else
  ok "sensitive reqFilter value redacted from the bundle"
fi

# --- (a) determinism ---------------------------------------------------------
run determinism-a "${work}/det-a" \
  --replication-ldif "${fixtures}/replication-lag.ldif" \
  --audit-log-file "${fixtures}/audit-auth-failure-burst.ndjson" \
  --backup-dir "${fixtures}/backup-stale" \
  --cert-file "${work}/cert-expiring.pem"
run determinism-b "${work}/det-b" \
  --replication-ldif "${fixtures}/replication-lag.ldif" \
  --audit-log-file "${fixtures}/audit-auth-failure-burst.ndjson" \
  --backup-dir "${fixtures}/backup-stale" \
  --cert-file "${work}/cert-expiring.pem"

det_mismatch=0
for f in "${work}/det-a"/*; do
  name="$(basename "$f")"
  sha_a=$(sha256sum "$f" | awk '{print $1}')
  sha_b=$(sha256sum "${work}/det-b/${name}" | awk '{print $1}')
  if [ "$sha_a" != "$sha_b" ]; then
    bad "determinism: ${name} differs between two --fixed-time runs"
    det_mismatch=1
  fi
done
[ "$det_mismatch" = 0 ] && ok "two --fixed-time runs produced byte-identical section files"

echo ""
echo "${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
