# Incident evidence export

`scripts/export-incident-evidence.sh` produces a single, deterministic,
redacted, versioned snapshot of an ldapium deployment's health, replication
state, backup posture, TLS certificate, config drift, and recent audit
trail — the evidence a human, a runbook, or an offline/local-LLM RCA tool
needs to answer "what does this directory look like right now", with no
write path back into the directory and no network call to any AI service.

This document is the boundary this repository draws around issue #12's
"LDAP incident evidence and Local LLM RCA/ChatOps integration": **ldapium
ships no ChatOps bot, no AI service, and no remediation executor.** What it
ships instead is this script and the read-only contract below.

## Producing a bundle

```bash
./scripts/export-incident-evidence.sh -b dc=example,dc=org \
  --password-env LDAP_ADMIN_PASSWORD \
  -o ./incident-evidence
```

Connection flags mirror `scripts/backup.sh` (`-H`/`-D`/`-b`,
`--password-file`/`--password-env`), not `scripts/export-audit-log.sh`'s own
kubectl-mediated discovery — `export-audit-log.sh` never binds directly
itself, so it has no direct host/bind-DN/password-file/TLS convention of its
own to reuse. `backup.sh` already established that convention for this
project. `audit-tail.ndjson` still comes from `export-audit-log.sh` itself
(invoked via `kubectl`, when reachable, with `--k8s-namespace`/`--k8s-release`
passed through) or from a pre-captured `--audit-log-file`, rather than
reimplementing its accesslog/auditlog parsing here.

Pass `--tar` to get a single `.tar.gz` instead of a loose directory. Run
`./scripts/export-incident-evidence.sh -h` for the full flag list, including
per-section offline inputs (`--monitor-ldif`, `--replication-ldif`,
`--audit-log-file`, `--cert-file`, `--backup-dir`,
`--config-drift-baseline`) and the finding thresholds.

## Bundle layout and `manifest.json`

```
incident-evidence/
  manifest.json         # schemaVersion, generatedAt, sections[], findings[]
  health.json            # anonymous bind/ping result + latency
  monitor.json           # cn=Monitor counters (connections/operations/threads)
  replication.json       # contextCSN per provider, olcSyncrepl presence, max lag
  config-drift.txt       # detect-config-drift.sh output, or "no baseline"
  backup.json            # latest scripts/backup.sh manifest timestamp/age
  audit-tail.ndjson      # last N records from export-audit-log.sh
  tls.json               # server cert subject/issuer/notAfter/days-remaining
```

`manifest.json`:

```json
{
  "schemaVersion": "1",
  "generatedAt": "2026-09-03T00:00:00Z",
  "sections": [
    {"name": "health", "file": "health.json", "sha256": "..."},
    "... one entry per file above, always in this fixed order ..."
  ],
  "findings": [
    {"id": "replication-lag", "severity": "warning", "detail": "..."}
  ]
}
```

**Versioning policy**: `schemaVersion` is a plain string, bumped only on a
breaking change to a section's field names/types or to `manifest.json`'s own
shape. Adding a new optional field, a new section, or a new finding `id` is
not breaking and does not bump it. A consumer should key its parsing off
`schemaVersion`, not off which fields happen to be present.

## Determinism

Every JSON file is written with stable (sorted) key ordering, and
`manifest.json`'s `sections` array is always in the fixed order listed above
regardless of which order the script happened to build them in. `--fixed-time
<RFC3339>` fixes both `generatedAt` and the "now" every age/lag calculation is
computed against, so the same inputs (live directory state held constant, or
the same `--*-ldif`/`--audit-log-file`/`--cert-file`/`--backup-dir` fixtures)
produce byte-identical files on every run — `scripts/test-incident-evidence.sh`
proves this by running the same fixtures through the script twice and
diffing every file's sha256.

Timestamp arithmetic (contextCSN lag, LDAP `GeneralizedTime`, certificate
`notAfter`, backup-manifest age) is done in `python3`, not shell `date` —
`export-audit-log.sh`'s own comments already document GNU-vs-BSD `date`
arithmetic as a real, previously-hit hazard this project avoids on purpose.

## Redaction guarantee

`userPassword` and any attribute whose name matches
`(?i)password|secret|credential|token` are stripped everywhere in the
bundle — this is the same denylist principle `CLAUDE.md` already applies to
the UI's HTTP responses (`entryRedactedAttrs` in
`ui/backend/internal/ldapclient/tree.go`), extended to this export path.
Concretely:

- `replication.json` never quotes the raw `olcSyncrepl` line at all — it
  only reports the boolean `syncreplConfigured`, so the bind `credentials=`
  it carries (see `image/entrypoint.sh`) can't leak by construction.
- Every file that could still carry something closer to a raw value
  (`config-drift.txt`, `audit-tail.ndjson`) goes through a blanket
  redaction pass before its sha256 is computed.
- After the whole bundle is built, the script greps every file for
  `(?i)(userpassword|password|secret|credential|token)[:=]` and **fails the
  run** (non-zero exit, bundle already on disk but flagged in the script's
  own stderr) if anything survives that isn't already the literal string
  `<redacted>`. `scripts/test-incident-evidence.sh` also asserts this
  directly against a fixture that embeds a live `olcSyncrepl` credential.

## The findings rule set

A small, deterministic set of threshold checks, each independently
configurable as a flag (see `-h` for defaults, which match this chart's own
`charts/ldapium/examples/metrics-values.yaml` alerting profile where one
exists):

| Finding `id` | Fires when | Flag |
|---|---|---|
| `replication-lag` | max contextCSN timestamp distance across providers exceeds the threshold | `--replication-lag-threshold-seconds` (default 30) |
| `tls-cert-expiry` | server certificate has fewer than N days remaining | `--cert-expiry-warning-days` (default 30) |
| `backup-stale` | the latest `scripts/backup.sh` manifest is older than N seconds | `--backup-max-age-seconds` (default 93600) |
| `auth-failure-burst` | N or more failed binds (`op=bind`, non-zero `result`) land within a window of each other in the audit tail | `--auth-failure-threshold` (default 5) / `--auth-failure-window-seconds` (default 300) |

`scripts/testdata/incident/` holds one fixture pair per finding (a
"triggering" fixture and its healthy counterpart);
`scripts/test-incident-evidence.sh` asserts each yields exactly the finding
it is named for and nothing else.

## Read-only ChatOps / local-LLM RCA integration contract

This is the entire contract issue #12 asks for on ldapium's side:

1. **A consumer reads a bundle (or `audit-tail.ndjson` alone) and gets no
   write path.** Nothing in this bundle, and nothing this script does, ever
   writes to the directory, to Kubernetes, or anywhere but the output
   path/tarball the operator chose. A local LLM, a ChatOps bot, or a human
   reading this bundle can form a root-cause hypothesis; it cannot act on
   it through anything ldapium ships.
2. **Remediation is out of scope, by design, and goes through existing
   runbooks with a human in the loop.** The restore procedure
   (`charts/ldapium/README.md`, "Restoring" and "Restoring a replicated
   deployment") and the certificate rotation procedure
   (`charts/ldapium/README.md`, "Renewing a certificate") are the two
   runbooks a `replication-lag`/`backup-stale`/`tls-cert-expiry` finding
   points an operator at. ldapium provides no remediation executor — no
   script or endpoint anywhere in this repository takes a finding and acts
   on it. An operator (or whatever tool they choose to wire up downstream)
   decides, then runs the runbook by hand.
3. **Offline operation.** Producing a bundle needs no external service:
   `jq`, `python3`, `sha256sum`, `openssl`, and (only for their respective
   live sections) `ldapsearch`/`ldapwhoami`/`kubectl` — the same tool set
   this repository's other operator scripts already depend on. Reading a
   bundle afterward needs nothing at all; it is plain JSON/NDJSON/text
   files. A local LLM performing RCA against this bundle does not require
   network access either, provided it is already running offline.

## Local verification

```bash
./scripts/test-incident-evidence.sh
```

runs the fixture suite (determinism, redaction, the findings rule set) with
no Docker/kind dependency, and is wired into `ci.yml`'s `incident-evidence`
job on every PR. `e2e.yml`'s `install + helm test` job additionally runs the
script live against a real kind-deployed directory and validates
`manifest.json`'s `schemaVersion`.
