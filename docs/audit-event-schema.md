# Identity audit event schema

`scripts/export-audit-log.sh` turns three raw sources — the `auditlog`
overlay's write records, the `accesslog` overlay's read/bind records, and
`replication-conflict-raw` (discarded replication CSNs) — into one NDJSON
stream. This document describes the envelope every record carries as of the
work tracked by issue #24, how each derived field is computed, and where
that computation runs out of information and has to say so honestly rather
than guess.

This is a format document, not a design proposal: it describes what
`scripts/export-audit-log.sh` and `scripts/lib/audit-normalize.py` actually
emit today, verified against the fixtures in `scripts/test/` and against a
live export in `.github/workflows/security-e2e.yml`'s "Verify the audit
export script" step.

## Format history

This envelope **replaces** the flat per-source shape `export-audit-log.sh`
emitted before issue #24 (`{"pod":...,"source":...,"time":...,"actor":...}`,
one shape per source). That old shape is still reachable with `--legacy`,
but not as a compatibility promise — see "`--legacy` is not a compatibility
guarantee" below. Every existing consumer that read the old shape needs to
either move to the envelope or pin `--legacy` and read that section first.

## The envelope

One JSON object per line, in this field order:

```json
{
  "schemaVersion": "1",
  "source": "auditlog",
  "seq": 42,
  "time": "2026-08-23T15:54:13Z",
  "actor": "cn=admin,dc=example,dc=org",
  "target": "uid=alice,ou=people,dc=example,dc=org",
  "op": "modify",
  "result": "unknown",
  "objectId": null,
  "correlationId": "auditlog:1787500453:uid=alice,ou=people,dc=example,dc=org:cn=admin,dc=example,dc=org",
  "privileged": true,
  "raw": { "...": "source-specific fields, verbatim — see below" }
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `schemaVersion` | string | Always `"1"` for this format. Bump this document and the constant in `scripts/lib/audit-normalize.py` together if the envelope shape ever changes again. |
| `source` | string | `auditlog`, `accesslog`, or `replication-conflict-raw`. |
| `seq` | integer | 1-based, monotonic, contiguous within one export run — see "seq" below. Not stable across runs and not a cross-run event id. |
| `time` | string or null | RFC3339 UTC. `null` if the source's own time value could not be parsed (fails soft — see "Time normalization"). |
| `actor` | string | A bind DN, `"anonymous"` (accesslog record with no bind identity — see the "anonymous" note below), or `"system"` (`replication-conflict-raw` — no bind identity exists for a sync-consumer discard event). |
| `target` | string or null | A DN when the source has one. For `auditlog`, this is the entry actually modified (parsed from the LDIF body's own `dn:` line), not the database suffix the header line's own accounting names the same position with — see "auditlog's target" below. |
| `op` | string | `add`/`modify`/`modrdn`/`delete` (auditlog), `search`/`bind` (accesslog), or `replication-conflict` (the fixed value for `replication-conflict-raw`, which has no real "operation"). |
| `result` | string | `success`, `failure`, or `unknown` — see "result" below. |
| `objectId` | string or null | `entryUUID` where the source data actually contains it. `null` otherwise — see "objectId" below; this is usually `null` and that is expected, not a bug. |
| `correlationId` | string | Deterministic, derived only from fields already in the record — see "correlationId" below. |
| `privileged` | boolean | `true` when `actor` matches the release's rootdn (`LDAP_ADMIN_DN`, or `cn=admin,<LDAP_ROOT_DN>` if unset) — see "privileged" below. |
| `raw` | object | The complete, unmodified extraction record this envelope was built from — every field the pre-#24 export emitted for that source, plus a few additive ones (`entryDn`, `entryUUID`, `changedAttrs` for auditlog; `reqSession` for accesslog). Nothing is lost, only wrapped. |

### seq

Assigned by `scripts/lib/audit-normalize.py` as records arrive on its stdin,
in the exact order `scripts/export-audit-log.sh`'s `run_export` function
produces them: per pod (`0..replicas-1`), auditlog then
replication-conflict-raw, then — once every pod's writes are done — accesslog
per pod. That order is fixed and deterministic for a given set of container
logs / accesslog contents, which is what makes two runs against unchanged
underlying data byte-identical (`scripts/test/test-export-audit-log.sh`
proves this against fixtures; a live cluster's logs are of course not
unchanged between two runs of the real script).

`seq` is **not** an event id that survives across export runs — it is purely
"the Nth line of this particular invocation's output". Two separate
`export-audit-log.sh` invocations both start at `seq: 1`.

### Time normalization

The three sources give time in two different native formats, and this
export normalizes both to RFC3339 UTC in the envelope's `time` field while
leaving the original string untouched in `raw.time`:

- **auditlog** gives a raw Unix epoch (seconds). Converted with Python's
  `datetime.fromtimestamp(..., tz=timezone.utc)` — deliberately not with
  shell `date`, because `export-audit-log.sh`'s own history already
  identified GNU-vs-BSD `date` epoch conversion as a portability risk (see
  the script's changelog/comments); Python's stdlib has no such split.
- **accesslog** and **replication-conflict-raw** give LDAP GeneralizedTime
  (`20260823155413.000004Z`). This is already UTC (the trailing `Z`), so
  normalizing it is pure string reformatting
  (`YYYYMMDDHHMMSS[.ffffff]Z` → `YYYY-MM-DDTHH:MM:SS[.ffffff]Z`) — no `date`
  binary, no portability risk.

If a record's own time value fails to parse (should not happen against a
real server, but the normalizer does not trust its own input — "contractual
distrust"), `time` is `null` rather than the whole run aborting; a warning is
printed once to stderr per malformed pattern.

### auditlog's target

The auditlog overlay's one-line header
(`# modify 1787500453 dc=example,dc=org cn=admin,dc=example,dc=org`) puts
the **database suffix** in the position a naive reading calls "target" — not
the entry that was actually changed. That suffix value is still present,
unchanged, at `raw.target`. This envelope's `target` field is instead parsed
from the LDIF body's own `dn:` (or base64 `dn::`) line, which every
add/modify/modrdn/delete record has — the entry actually modified, which is
what a SIEM operator means by "target" and what correlating audit-log/
replication events by identity (issue #24, AC #5) needs.

### objectId

Populated from an `entryUUID` attribute line found in the auditlog record's
LDIF body, when present. In practice this is usually **not** present:
`entryUUID` is a server-generated operational attribute, not something a
client submits on `add`, and an ordinary `modify`/`delete` record's body
doesn't carry it either unless the entry's full attribute set happens to be
echoed (e.g. some `delete` records do include it, per slapd's own behavior
of logging the deleted entry's contents). `null` here is the honest, expected
answer for most records, not a parsing failure.

`replication-conflict-raw`'s own log line
(`do_syncrep2: rid=002 CSN too old, ignoring <CSN> (<entry DN>)`) carries
only the entry's DN, never its `entryUUID` — `objectId` is always `null` for
this source. `accesslog`'s `auditSearch`/`auditBind` records likewise carry
no `entryUUID`-equivalent attribute (`reqDN`/`reqFilter` describe what was
requested, not a resolved object identity) — `objectId` is always `null` for
this source too.

### changedAttrs and password redaction (raw.changedAttrs)

For `auditlog` `add` and `modify` records, `raw.changedAttrs` is the list of
attribute **names** the LDIF body says were set/added/deleted/replaced — for
example `["sn"]` for a single-attribute modify, or
`["objectClass","uid","cn","sn","userPassword"]` for an add. **Values are
never captured for this field, on purpose**: the extraction awk
(`scripts/lib/parse-auditlog.awk`) only ever reads an attribute's *name* off
each LDIF line, never the value after the `:`/`::`. This is what keeps a
password out of the export without needing to enumerate every
password-like attribute name in advance — the redaction is structural, not
a denylist filter applied after the fact.

`scripts/lib/audit-normalize.py` additionally has a belt-and-suspenders
check (`check_changed_attrs_are_names_only`) that warns to stderr — without
failing the run — if a `changedAttrs` entry ever looks like more than a bare
attribute name (contains a space, `::`, or is implausibly long). This is a
safety net for a future change to the extraction side, not the primary
control.

The one attribute this codebase treats as sensitive is `userPassword` —
same convention as `entryRedactedAttrs` in
`ui/backend/internal/ldapclient/tree.go` (see `AGENTS.md`'s "Attribute
exposure" section). `delete` and `modrdn` records carry no `changedAttrs` at
all — `delete` has no per-attribute change list to parse, and `modrdn`'s
body (`newrdn`/`deleteoldrdn`/`newsuperior`) is not "changed attributes" in
the entry-content sense.

Separately: the raw container log (`kubectl logs`) that `auditlog` writes to
**does** contain the actual `userPassword` value for a password change —
that is documented, intentional overlay behavior
(`.github/workflows/security-e2e.yml`'s "Show what a password change leaves
in the audit log" step proves and documents it at the LDAP/log level). This
export's own redaction guarantee is about what *this NDJSON stream* carries,
not about the underlying container log, which a SIEM operator with
`kubectl logs` access can still read directly.

### result

Only `accesslog` carries a real success/failure signal (`reqResult`, the
LDAP result code): `"success"` if `reqResult == "0"`, `"failure"` otherwise,
`"unknown"` if the field is missing. `auditlog` and `replication-conflict-raw`
carry no result code at all in what this export reads from them — reporting
anything but `"unknown"` for those two sources would be a claim the data
does not support.

### correlationId

No cross-system, cross-source correlation ID exists anywhere in this data —
these are three independently-generated log streams with no shared request
id. `correlationId` is instead a deterministic string built only from
fields already in the same record, so the same underlying event always
produces the same id and two different events essentially never collide:

- **auditlog**: `auditlog:<raw epoch time>:<target DN>:<actor>`. Two writes
  to the same entry by the same actor within the same second collide —
  auditlog's one-line-per-record format has nothing finer-grained to key on.
- **accesslog**: `accesslog:<reqSession>:<raw GeneralizedTime>`.
  `reqSession` is slapo-accesslog's own per-connection counter (added to the
  ldapsearch attribute list specifically for this); it resets across a
  slapd restart, so it is not cross-restart-unique on its own — pairing it
  with `reqStart` is what keeps the id meaningful across a restart.
- **replication-conflict-raw**: `replication-conflict-raw:<rid>:<discardedCSN>`.
  `discardedCSN` already encodes a server-assigned, effectively-unique
  timestamp+counter+server-id+mod-count; `rid` is included because two
  different consumers can each independently discard the same delivered
  CSN, which is two distinct discard events, not one.

**Limit**: there is no way to tell, from this data alone, that an auditlog
write and an accesslog read (or a replication-conflict-raw discard) are "the
same" underlying client request — `correlationId` correlates records
*within* one source's own stream, not *across* sources. Cross-source
correlation (issue #24, AC #5) is instead what `objectId`/`target` are for:
join on the entry identity, not on a shared request id that does not exist.

### privileged

`true` when `actor` case-insensitively, comma-spacing-normalized (same
technique `image/entrypoint.sh` already uses for its own
`LDAP_ADMIN_DN`/`LDAP_ROOT_DN` comparisons) equals the release's configured
rootdn (`LDAP_ADMIN_DN`, resolved from the running StatefulSet's env, or
`cn=admin,<LDAP_ROOT_DN>` if `LDAP_ADMIN_DN` was left at its default).
`"anonymous"` and `"system"` actors are always `privileged: false`.

**This chart has no admin-group concept beyond the rootdn.** Its ACLs (see
`image/entrypoint.sh`'s `#__ANON_READ_ACCESS__` block) are `by self write`,
`by users read`, `by anonymous {read,search,none}` — there is no
`by group.exact=cn=admins,...` grant anywhere. So "privileged" here means
exactly "is the rootdn", not "is a member of some admin group", because no
such group exists in this chart's authorization model to check membership
against. If a future chart version adds a real admin-group ACL grant, this
classification should be extended to check group membership too — until
then, rootdn-only is the complete and honest answer.

If the rootdn cannot be determined (StatefulSet not found, or neither
`LDAP_ADMIN_DN` nor `LDAP_ROOT_DN` readable from it),
`scripts/export-audit-log.sh` prints a warning to stderr and every record is
exported as `privileged: false` rather than guessing.

## `--legacy` is not a compatibility guarantee

`./scripts/export-audit-log.sh --legacy` skips envelope normalization and
prints the flat per-source records `scripts/lib/audit-normalize.py` would
otherwise consume — the same shape the pre-#24 script emitted, **plus** the
additive fields this work introduced at the extraction layer regardless of
`--legacy` (`entryDn`, `entryUUID`, `changedAttrs` for auditlog;
`reqSession` for accesslog). A consumer that only reads the fields it
already knew about is unaffected; a consumer that asserts on the *complete*
set of keys in a record will see new ones. `--legacy` exists for scripts
that want the simple flat shape without the envelope getting in the way, not
as a frozen historical format.

## Retention, loss, and the SIEM adapter boundary

- **This is a pull-only export**, run by hand or by whatever schedules
  `scripts/export-audit-log.sh`. There is no push exporter, no daemon, and
  no persistent queue — this issue does not add one. Nothing here changes
  that boundary.
- **No sequence numbering across runs.** `seq` is per-invocation only (see
  above). A SIEM ingesting this feed cannot use `seq` to detect a gap
  between two separate export runs; that requires the SIEM's own ingestion
  bookkeeping (e.g. tracking the highest `time` it has already ingested per
  source per pod).
- **No dead-letter queue.** If a pod is unreachable, or `accesslog` is
  disabled, or the accesslog bind credential is stale (see
  `scripts/export-audit-log.sh`'s own header comment on rotated admin
  passwords), that pod's records for that run are simply absent from the
  output — `export-audit-log.sh` warns to stderr and continues, it does not
  fail the whole run, and it does not track "I owe you these records later."
- **The exporter is a script, not a service.** It has no retry policy beyond
  what `kubectl`/`ldapsearch` themselves do, no backoff, and no persistent
  state between invocations.
- **The SIEM adapter boundary**: a consumer is expected to run this script
  (or a wrapper around it) and feed its stdout, line by line, into whatever
  NDJSON/file/stdin ingestion its SIEM offers. This project does not ship or
  plan to ship a push-based exporter, an agent, or a long-running daemon —
  "run the script, pipe the output" is the entire integration surface.
- **`replication-conflict-raw` is still not a conflict detector** (unchanged
  from before #24 — see `scripts/export-audit-log.sh`'s own header comment):
  it mixes genuine same-entry conflicts with harmless duplicate delivery
  over N-way relay paths. A SIEM correlating this source with directory
  state must not treat every record as confirmed data loss.

## Testing

`scripts/test/test-export-audit-log.sh` runs the normalizer against fixture
input in `scripts/test/fixtures/` (`auditlog-container.log`,
`replication-container.log`, `accesslog.ldif`) with no cluster involved,
and checks:

- two runs against the same fixture input produce byte-identical output
  (deterministic replay);
- output matches the checked-in golden fixture
  (`scripts/test/fixtures/expected-normalized.ndjson`);
- every record parses as JSON, carries the full envelope, and `seq` is
  contiguous starting at 1;
- no `userPassword` *value* appears anywhere in the output, while the
  attribute *name* still appears in `changedAttrs`;
- rootdn vs. non-rootdn actors are classified `privileged` correctly;
- `objectId` is populated from a fixture `entryUUID` where present.

`.github/workflows/security-e2e.yml`'s "Verify the audit export script" step
additionally runs the real script against a live cluster and asserts every
record parses with `schemaVersion`/`seq`/`correlationId` present, and that
the rootdn's and a self-service user's writes are attributed and classified
distinctly — this is the one thing the fixture test cannot prove, since it
never talks to a real `kubectl`/directory.
