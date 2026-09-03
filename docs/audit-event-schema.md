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
one shape per source) as the *default*. That old shape is still reachable
with `--legacy`, matched field-for-field — see "`--legacy` mode" below for
the one deliberate exception (filter redaction, which applies regardless of
mode). Every existing consumer that read the old shape needs to either move
to the envelope or pin `--legacy` and read that section first.

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
  "correlationId": "auditlog:directory-ldapium-0:1787500453:uid=alice,ou=people,dc=example,dc=org:cn=admin,dc=example,dc=org",
  "privileged": true,
  "raw": { "...": "source-specific fields, sanitized/redacted where noted below — see below" }
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `schemaVersion` | string | Always `"1"` for this format. Bump this document and the constant in `scripts/lib/audit-normalize.py` together if the envelope shape ever changes again. |
| `source` | string | `auditlog`, `accesslog`, `replication-conflict-raw`, or `exporter` (the run's own integrity summary — see "Malformed input handling" below). |
| `seq` | integer | 1-based, contiguous within one export run — see "seq" below. Not stable across runs and not a cross-run event id. |
| `time` | string or null | RFC3339 UTC. `null` if the source's own time value could not be parsed, or is not applicable (the `exporter` summary record) — see "Time normalization". |
| `actor` | string | A bind DN, `"anonymous"` (accesslog record with no bind identity — see the "anonymous" note below), `"system"` (`replication-conflict-raw` — no bind identity exists for a sync-consumer discard event), or `"exporter"` (the summary record — see below). |
| `target` | string or null | A DN when the source has one. For `auditlog`, this is the entry actually modified (parsed from the LDIF body's own `dn:` line), not the database suffix the header line's own accounting names the same position with — see "auditlog's target" below. |
| `op` | string | `add`/`modify`/`modrdn`/`delete` (auditlog), `search`/`bind` (accesslog), `replication-conflict` (the fixed value for `replication-conflict-raw`, which has no real "operation"), or `summary` (the `exporter` record). |
| `result` | string | `success`, `failure`, or `unknown` — see "result" below. |
| `objectId` | string or null | `entryUUID` where the source data actually contains it. `null` otherwise — see "objectId" below; this is usually `null` and that is expected, not a bug. |
| `correlationId` | string | Deterministic, derived only from fields already in the record — see "correlationId" below. |
| `privileged` | boolean | `true` when `actor` matches the release's rootdn (`LDAP_ADMIN_DN`, or `cn=admin,<LDAP_ROOT_DN>` if unset) — see "privileged" below. |
| `raw` | object | The extraction record this envelope was built from — every field the pre-#24 export emitted for that source, plus a few additive ones (`entryDn`, `entryUUID`, `changedAttrs` for auditlog; `reqSession` for accesslog) — with `filter` (accesslog) and `changedAttrs` (auditlog) sanitized in place, see "Filter redaction" and "changedAttrs" below. Nothing is silently lost; two fields are deliberately cleaned. |
| `prevHash` | string (optional) | Present when `--chain` is passed. SHA-256 hash of previous record in chain, or sha256 of export manifest line for the genesis record. |
| `hash` | string (optional) | Present when `--chain` is passed. SHA-256 hash of the canonical JSON of this record (without the `hash` field itself). |

### seq

**Determinism holds for a given set of underlying data, regardless of the
order it happened to be retrieved in** — not because retrieval order is
guaranteed stable (it is not: accesslog's `ldapsearch` in particular has no
`ORDER BY` equivalent, and a live cluster gives no ordering promise across
two separate runs either). Before assigning `seq`,
`scripts/lib/audit-normalize.py` sorts every record it read from stdin by:

1. `time` (nulls last — see "Time normalization");
2. `pod` (`raw.pod`);
3. `correlationId`;
4. a SHA-256 hash of the sanitized `raw` object, as a final tiebreaker for
   two records that are otherwise identical.

`seq` is then assigned 1-based over that sorted order. This is what makes
two runs over the same underlying data byte-identical even if
`export-audit-log.sh`'s own fetch order differed between them —
`scripts/test/test-export-audit-log.sh` proves this by reversing the raw
extraction stream's line order and asserting the normalized output is
unchanged.

`seq` is **not** an event id that survives across export runs — it is purely
"the Nth line of this particular invocation's sorted output". Two separate
`export-audit-log.sh` invocations both start at `seq: 1`.

### Malformed input handling

A line on `audit-normalize.py`'s stdin that fails to parse as JSON (should
not happen against this project's own extraction, but the normalizer does
not trust its own input — "contractual distrust") is counted and dropped,
**never silently**:

- **Default (envelope) mode** appends one final record, as the last `seq`,
  naming the drop and emit counts:
  ```json
  {"schemaVersion":"1","source":"exporter","seq":9,"time":null,"actor":"exporter","target":null,"op":"summary","result":"unknown","objectId":null,"correlationId":"exporter:summary:1:8","privileged":false,"raw":{"dropped":1,"emitted":8}}
  ```
  The process still exits `0` — this record is what makes the loss visible
  to a consumer reading only the NDJSON stream itself (a file, a SIEM's
  ingest), which is treated as more reliable than trusting every caller to
  check an exit code. `time` is deliberately `null` (this record describes
  the run's own integrity, not a directory event with a timestamp), which
  keeps the record itself reproducible across replay: `correlationId` is
  built only from the dropped/emitted counts, not a wall-clock value.
- **`--legacy` mode** has no field in the flat shape to carry this
  information without adding a key (which would violate the "no additive
  keys" guarantee below), so it instead **exits non-zero** when anything was
  dropped, with a message to stderr. It emits every record it could parse
  either way; the non-zero exit is the only signal.

One behavior per mode, chosen so neither can report success while quietly
under-counting events. See `scripts/test/test-export-audit-log.sh`'s
corrupted-input checks.

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
  binary, no portability risk. The digits are also checked for calendar
  validity (via a `datetime(...)` construction) before being reformatted —
  a regex only confirms digit *shape*; month `13` or February `30` has the
  right shape and the wrong meaning, and reformatting it anyway would hand a
  SIEM an equally-impossible RFC3339 string instead of catching the problem
  here.

If a record's own time value fails to parse OR fails calendar validation
(should not happen against a real server, but the normalizer does not trust
its own input — "contractual distrust"), `time` is `null` rather than the
whole run aborting; a warning naming the bad value is printed once to
stderr per distinct value.

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
only the entry's DN, not `entryUUID`. As of issue #126, at export time
`scripts/export-audit-log.sh` passes raw records through
`scripts/lib/resolve-conflict-objectid.py`, which resolves each distinct entry DN
to its `entryUUID` via a base-scoped `ldapsearch` (cached once per distinct DN
across all pods). When the entry exists in the directory, `objectId` (and
`raw.entryUUID`) is populated; if the entry was deleted or cannot be resolved,
`objectId` remains `null`. For offline tests and CI, `LDAP_STUB_OBJECTID_MAP`
provides a deterministic stub mapping. (Note: `.github/workflows/security-e2e.yml`
deploys a single-node replica where syncrepl replication does not run, so conflict
records are not generated in that workflow; conflict `objectId` resolution is
verified fixture-only via `scripts/test/test-export-audit-log.sh`).

`accesslog`'s `auditSearch`/`auditBind` records carry no `entryUUID`-equivalent
attribute (`reqDN`/`reqFilter` describe what was requested, not a resolved
object identity) — `objectId` is always `null` for this source.

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

**This is enforced twice, independently, not just checked once:**

1. `scripts/lib/parse-auditlog.awk` is the primary control — its
   `add_changed()` truncates anything at the first whitespace and validates
   what remains against a strict attribute-name shape
   (`^[A-Za-z][A-Za-z0-9-]*(;[A-Za-z0-9-]+)*$`) before accepting it, so even
   a malformed or adversarial single-line record like
   `replace: userPassword hunter2` cannot smuggle the trailing text through
   — the value is stripped, `userPassword` (the name) is kept. Something
   that still doesn't look like a bare name after truncation (e.g. a name
   starting with a digit) is dropped entirely, not merely truncated, with a
   warning to stderr.
2. `scripts/lib/audit-normalize.py`'s `sanitize_changed_attrs()` re-applies
   the identical check to whatever it received, and *rewrites* `raw.changedAttrs`
   to the cleaned list — an enforcement layer, not a warning-only
   belt-and-suspenders note, so a future bug in the awk layer alone cannot
   leak a value through this field.

The one attribute this codebase names explicitly elsewhere is `userPassword`
— same convention as `entryRedactedAttrs` in
`ui/backend/internal/ldapclient/tree.go` (see `AGENTS.md`'s "Attribute
exposure" section) — but the enforcement above is name-*shape*-based, not a
denylist: it accepts any syntactically valid bare attribute name and rejects
everything else, which is what keeps a value from ever qualifying as a
"name" in the first place. `delete` and `modrdn` records carry no
`changedAttrs` at all — `delete` has no per-attribute change list to parse,
and `modrdn`'s body (`newrdn`/`deleteoldrdn`/`newsuperior`) is not "changed
attributes" in the entry-content sense.

Separately: the raw container log (`kubectl logs`) that `auditlog` writes to
**does** contain the actual `userPassword` value for a password change —
that is documented, intentional overlay behavior
(`.github/workflows/security-e2e.yml`'s "Show what a password change leaves
in the audit log" step proves and documents it at the LDAP/log level). This
export's own redaction guarantee is about what *this NDJSON stream* carries,
not about the underlying container log, which a SIEM operator with
`kubectl logs` access can still read directly.

### Filter redaction (raw.filter)

`accesslog`'s `reqFilter` is an LDAP search filter, and a filter can itself
carry a secret as a literal assertion value — `(userPassword=hunter2)`,
`(authToken=abc123XYZ)` — which the pre-#24 export, and this export until
this was found in review, passed straight through into `raw.filter`
unredacted. `scripts/lib/audit-normalize.py`'s `redact_filter()` is now the
single, sole implementation (used by both output modes — see "`--legacy`"
below) that scans a filter for `(attr<op>value)` assertions and replaces
`value` with the literal string `<redacted>` whenever `attr` matches
`password|secret|credential|token|pwd` case-insensitively — a substring
match against a shape, not a fixed attribute allowlist, since a deployment's
schema can name a sensitive attribute anything. The attribute name and
operator are preserved; a benign filter (`(uid=alice)`) is left untouched.
Compound filters (`(&(uid=alice)(userPassword=hunter2))`) are handled —
each parenthesized assertion is considered independently.

**Known limits**: LDAP filter escaping (`\28`/`\29` for a literal paren
*inside* a value) and extensible-match filters (`attr:dn:=value`) are out of
scope — the same boundary this export already draws around filter parsing
elsewhere. A sensitive value hidden behind escaped parens would not be
matched by the redaction regex; this is a known gap, not a silent one.

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
produces the same id and two different events essentially never collide.

**The pod is always the second segment**, for every source: two different
pods can legitimately produce the same rid/CSN pair, or the same
actor+target+timestamp-second write — multi-provider replication routinely
does exactly the latter, with the same logical write landing in more than
one provider's own `auditlog` — and without the pod those look like the
same event.

- **auditlog**: `auditlog:<pod>:<raw epoch time>:<target DN>:<actor>`. Two
  writes to the same entry by the same actor, on the same pod, within the
  same second, collide — auditlog's one-line-per-record format has nothing
  finer-grained to key on.
- **accesslog**: `accesslog:<pod>:<reqSession>:<raw GeneralizedTime>`.
  `reqSession` is slapo-accesslog's own per-connection counter (added to the
  ldapsearch attribute list specifically for this); it resets across a
  slapd restart, so it is not cross-restart-unique on its own — pairing it
  with `reqStart` is what keeps the id meaningful across a restart.
- **replication-conflict-raw**: `replication-conflict-raw:<pod>:<rid>:<discardedCSN>`.
  `discardedCSN` already encodes a server-assigned, effectively-unique
  timestamp+counter+server-id+mod-count; `rid` and `pod` are included
  because two different consumers — on two different pods — can each
  independently discard the same delivered CSN, which is two distinct
  discard events, not one.

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

## `--legacy` mode

`./scripts/export-audit-log.sh --legacy` skips envelope normalization.
`scripts/lib/audit-normalize.py --legacy` receives the exact same extended
extraction records the default mode does (including `entryDn`, `entryUUID`,
`changedAttrs`, `reqSession`), but **projects each one down to exactly the
field set the pre-#24 script emitted for that source** —
`{"pod","source","time","actor","op","target"}` for auditlog,
`{"pod","source","time","actor","op","target","filter","result"}` for
accesslog, `{"pod","source","time","entry","discardedCSN","rid"}` for
replication-conflict-raw — with no additive keys. This is verified, not
merely claimed: `scripts/test/test-export-audit-log.sh` diffs `--legacy`'s
output against a golden fixture
(`scripts/test/fixtures/expected-legacy.ndjson`) captured by running the
actual pre-#24 extraction logic (`git show origin/main:scripts/export-audit-log.sh`)
against the same fixtures, and asserts it is byte-for-byte identical.

**The one guarantee that is not optional, even in `--legacy`: filter
redaction.** `redact_filter()` (see "Filter redaction" above) is applied to
`filter` in both modes — there is exactly one implementation, and
`export-audit-log.sh` pipes through it unconditionally regardless of which
mode was requested. A fixture with a sensitive filter value therefore
produces output that differs from a literal pre-#24 replay for that one
field; the byte-identity claim above holds for the *shape* (no additive
keys) and for fixtures with no sensitive filter content, not for the value
of an attribute this project has decided must never leak. `--legacy` is a
shape-compatibility mode, not a "disable the security fix" switch.

Malformed input is handled differently between the two modes too — see
"Malformed input handling" above: default mode appends a summary record and
exits 0, `--legacy` exits non-zero instead (it has nowhere to put a summary
record in the flat shape without adding a key).

`--legacy` exists for scripts that want the simple flat shape without the
envelope getting in the way. It is not a frozen historical format beyond the
guarantees stated here.

## Retention, loss, and the SIEM adapter boundary

Issue #126 delivers the "tested" half of the SIEM adapter boundary via `scripts/ship-audit-log.sh`
while preserving the distinction between pull extraction and push ingestion:

- **The extraction exporter (`scripts/export-audit-log.sh`) remains pull-based**:
  It runs on-demand or on a cron schedule, pulling from container logs and `cn=accesslog`.
- **The push shipper (`scripts/ship-audit-log.sh`)**:
  Takes the normalized NDJSON stream (piped from `scripts/export-audit-log.sh` or read from a file)
  and ships it to a generic HTTPS endpoint:
  - **Delivery semantics (at-least-once)**: The shipper guarantees at-least-once delivery.
    If network connectivity drops after the sink receives a batch but before acknowledgment reaches
    the shipper, or if the shipper retries a transient error or replays from dead-letter, batches may
    be delivered again. There is no client-side "zero duplicate" guarantee.
  - **Idempotency keys**: Each POST batch includes an `X-Ldapium-Batch-Id` header (the SHA-256 digest
    of the batch's canonical NDJSON), plus per-record `hash` fields when `--chain` was used during export.
    The downstream sink/adapter is expected to deduplicate on this batch idempotency key.
  - **Cursor (NOT seq)**: Maintains a cursor state file (`--cursor-file`, default `.audit-ship-cursor.json`)
    tracking the last delivered `(time, hashes)` per `(source, pod)`. `seq` is strictly invocation-scoped
    (assigned 1..N after sorting within a single run) and resets to 1 on every export run; treating `seq`
    as a persistent cursor causes complete data loss on subsequent runs. Keying per `(source, pod)` ensures
    that an event from a pod whose log fetch failed in one export (`|| true` in `export-audit-log.sh`) and
    appears later with an older time is not shadowed by another pod's newer events. A record is considered already
    delivered only if its timestamp is strictly older than its pod's cursor timestamp, or equal to the cursor
    timestamp and its canonical record hash is in the set of hashes recorded at that timestamp.
    *Limitation*: within a single pod, records are assumed to be fetched in time order; a pod whose fetch
    fails is simply not advanced.
  - **Transport security**: HTTPS only by default (`--sink-url https://...`). Plaintext `http://`
    is rejected unless `--allow-insecure-http` is explicitly passed (strictly for CI/local test fixtures).
    Redirects are strictly forbidden via a custom redirect handler to prevent credential leakage.
    TLS certificate verification is never disabled. Optional Bearer authentication is strictly read
    from a file (`--token-file`, never as a CLI argument).
  - **Process locking & fatal persistence failure**: The shipper acquires an exclusive `flock` on
    the state directory for the run (failing fast if locked), plus a second exclusive `flock` on
    `<dead-letter-file>.lock` for every dead-letter read/append/rewrite operation (failing fast if held).
    Cursor persistence failure after an acknowledged batch is fatal: the shipper exits non-zero
    immediately and halts.
  - **Streaming & input validation**: The shipper streams NDJSON line-by-line and dead-letter records
    batch-by-batch without buffering entire logs in memory. Arguments are validated (`batch_size >= 1`,
    `max_retries >= 0`, `initial_backoff >= 0`, `max_backoff >= 0`).
  - **Bounded exponential backoff retry**: Network errors, timeouts, HTTP 5xx responses, and HTTP 429
    trigger retries with bounded exponential backoff (`--max-retries`, `--initial-backoff`, `--max-backoff`).
  - **Dead-letter queue & replay**: Undeliverable batches upon retry exhaustion are written to a
    dead-letter NDJSON file (`--dead-letter-file`, default `.audit-dead-letter.ndjson`) with failure
    details. On subsequent invocations, the shipper replays dead-letter records first before
    processing new events, preserving chronological delivery order.
- **What is NOT covered (out of scope)**:
  - No vendor-specific adapters (Splunk HEC, Datadog Logs API, Elastic Beats, Microsoft Sentinel, etc.).
  - No persistent background daemon or resident message queue process (standard CLI script invocation model).
- **`replication-conflict-raw` is still not a conflict detector** (unchanged from before #24):
  it mixes genuine same-entry conflicts with harmless duplicate delivery over N-way relay paths.
  While distinct DNs are resolved to `objectId` (entryUUID) at export time by querying provider pods
  in ordinal order (`pod-0`, `pod-1`, ...) and caching by exact DN string (case preserved to avoid
  collisions across case-exact schemas), consumers must correlate with directory state rather than
  treating every discard record as data loss.

## Tamper-evident chain option (`--chain`)

`scripts/export-audit-log.sh --chain` and `scripts/lib/audit-normalize.py --chain` add cryptographic
SHA-256 hash chaining to each envelope record for tamper-evidence (issue #126):

- **Fields added**:
  - `prevHash`: For the genesis (first) record in the export, `prevHash = sha256(export manifest line)`.
    For subsequent records, `prevHash` equals the `hash` of the immediately preceding record.
  - `hash`: SHA-256 digest of the canonical JSON representation (keys sorted, compact separators)
    of the record excluding the `hash` field itself.
- **Verification (`scripts/verify-audit-chain.py`)**:
  `python3 scripts/verify-audit-chain.py <file.ndjson> [--expected-head <hash>]`
  Verifies every record in sequence. Fails and exits non-zero if:
  - Any record has missing or malformed hash fields.
  - The genesis `prevHash` does not match the expected manifest line.
  - A record's payload was modified (content hash mismatch).
  - An interior record was deleted or reordered (`prevHash` mismatch).
  - The final record's hash does not match `--expected-head` (when provided).
- **Evidence integrity limits**:
  Tamper evidence guarantees that any alteration, reordering, or interior deletion of exported records
  after the fact is detectable. However, **without `--expected-head`, tail truncation (deleting the most
  recent records from the end of the log) is undetectable from the log file alone**, because the remaining
  prefix forms a cryptographically valid chain starting from genesis. Detecting tail truncation strictly
  requires storing the chain head hash out-of-band (e.g. in a signed backup manifest or external SIEM)
  and asserting it with `--expected-head`. Furthermore, **this is still NOT immutable storage**:
  raw container logs and local database rows prior to export can still be truncated or altered by
  a container-level root adversary before export. Non-repudiation requires immediate off-cluster transmission.

## Audit coverage matrix

In accordance with product boundary D1 (`docs/product-boundary.md`), ldapium provides directory-level
identity and operation auditing. The table below delineates current audit coverage and explicit gaps:

| Category | Event Type | Covered? | Source | Notes / Gaps |
| --- | --- | :---: | --- | --- |
| **Security / Auth** | Successful binds | Yes | `accesslog` | `auditBind` records `reqAuthzID`, client IP, GeneralizedTime. |
| **Security / Auth** | Failed binds | Yes | `accesslog` | Captured with `reqResult: 49` (Invalid credentials) and target DN. |
| **Security / Auth** | `cn=config` binds | Partial | Container log | Local domain socket (`ldapi://`) administrative operations bypass accesslog. |
| **Security / Auth** | Read ACL denials | No | None | OpenLDAP does not log denied attribute read attempts within searches. |
| **Security / Auth** | Write ACL denials | No | None | `auditlog` only logs completed writes; rejected writes (result 50) are dropped. |
| **Operations** | User / group adds | Yes | `auditlog` | Full entry DN, actor DN, changed attribute names recorded. |
| **Operations** | Modifications | Yes | `auditlog` | `raw.changedAttrs` sanitized to attribute names (passwords redacted). |
| **Operations** | Deletions | Yes | `auditlog` | Target DN and actor DN recorded. |
| **HA / DR** | Replication conflicts | Yes | `replication-conflict-raw` | CSN discard diagnostic; entry DN resolved to `objectId` (entryUUID) at export time. |
| **HA / DR** | Syncrepl relay dups | Yes | `replication-conflict-raw` | Emitted alongside conflicts; harmless relay duplicates not filtered out. |
| **HA / DR** | Backup creation | Partial | Backup manifest / Pod log | Logged to Kubernetes CronJob logs and LDAP `applicationProcess`; not in audit stream. |
| **HA / DR** | Directory restore | Partial | Restore job log | Executed via offline `slapadd` or `restore.sh`; not captured in online audit stream. |
| **Lifecycle** | Federation events | Out of Scope | None | Product boundary D1 excludes federation engines and IdP broker suites. |
| **Lifecycle** | Machine identity vault | Out of Scope | None | Product boundary D1 excludes PAM/secret vaults and dynamic token injectors. |

## Testing

`scripts/test/test-export-audit-log.sh` runs the normalizer against fixture
input in `scripts/test/fixtures/` with no cluster involved, and checks:

- two runs against the same fixture input produce byte-identical output
  (deterministic replay), including after **reversing the raw extraction
  stream's line order** — proving `seq` is assigned from a sort, not from
  arrival order (`auditlog-container.log`, `replication-container.log`,
  `accesslog.ldif`);
- output matches the checked-in golden fixture
  (`scripts/test/fixtures/expected-normalized.ndjson`);
- every record parses as JSON, carries the full envelope, and `seq` is
  contiguous starting at 1;
- no `userPassword` *value* appears anywhere in the output, while the
  attribute *name* still appears in `changedAttrs`;
- rootdn vs. non-rootdn actors are classified `privileged` correctly;
- `objectId` is populated from a fixture `entryUUID` where present;
- `correlationId` includes the pod;
- `--legacy` output is byte-identical to a golden fixture captured from the
  pre-#24 script's own logic (`expected-legacy.ndjson`), and carries no
  envelope fields;
- a filter with `userPassword`/`authToken`-like assertions
  (`accesslog-sensitive-filter.ldif`) has those values redacted — not a
  benign filter alongside them — in both default and `--legacy` output,
  matching dedicated golden fixtures
  (`expected-sensitive-filter-normalized.ndjson`,
  `expected-sensitive-filter-legacy.ndjson`);
- a malformed `changedAttrs`-producing line
  (`auditlog-malformed.log` — a value smuggled onto the same line as the
  attribute name, and a garbage attribute name) is sanitized to match
  `expected-malformed-normalized.ndjson`, with a stderr warning and no
  leaked value or invalid name in the output;
- a corrupted, unparseable input line (`raw-with-corrupted-line.ndjson`)
  produces the `exporter`/`summary` record with correct counts in default
  mode (exit 0), and a non-zero exit in `--legacy` mode;
- an impossible calendar date (`accesslog-invalid-time.ldif`, month 13)
  normalizes to `time: null` with a stderr warning instead of a bogus
  RFC3339 string.

`.github/workflows/security-e2e.yml`'s "Verify the audit export script" step
additionally runs the real script against a live cluster and asserts every
record parses with `schemaVersion`/`seq`/`correlationId` present, and that
the rootdn's and a self-service user's writes are attributed and classified
distinctly — this is the one thing the fixture test cannot prove, since it
never talks to a real `kubectl`/directory.
