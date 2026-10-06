# Close-out audit, 2026-10: #215, #216, #217, #218

Audited on `origin/main` at `02d09fc` (after PRs #233-#246). Docs only: no code was changed. The tick
marks in each package's `TASKS.md` were updated from this audit; each changed line carries a
`**(CLOSE-OUT: ...)**` note. Maintainers decide issue state and file the successor issues below
(AGENTS.md "Issue tracker convention": a partially met umbrella issue is never closed; remaining scope
becomes focused successors).

## Method and what was actually run

- Read every REQ/AC/task in `CHANGE.md` and `TASKS.md` of the four packages, grepped the code on main,
  read the `EVIDENCE*.md` files, and read the merged PR bodies via `gh`.
- `cd ui/backend && go vet ./... && go test ./... -race -count=1`: every package `ok`.
- `make check` (npm lint + build, gofmt, go vet, go test, go build, helm lint, `check-versions.sh`,
  `check-modules.sh`, shellcheck, incident-evidence tests, licence gate, govulncheck): exit 0.
- NOT run (needs Docker/images): every live script (`test-api-edge-codes-local.py`,
  `test-api-idempotency-local.py`, `test-api-cursor-pagination-local.py`, `test-backup-jobs-live.py`),
  `npm run e2e`, `helm template` assertion scripts beyond what `make check` runs. Live claims below rest on
  the committed `EVIDENCE*.md` and the PR/CI record and are marked UNVERIFIED where this audit could not
  re-observe them.
- PR-body consistency (`Related to #N (not closing yet)`): checked for #233-#246 (list at the end). Consistent.

Status vocabulary: DONE = demonstrably on main with cited evidence; PARTIAL; NOT DONE; UNVERIFIED = claimed
but needs a live container to observe.

---

## #218 error envelope, `/metrics`, CORS (`api-error-envelope`)

PRs: #234 (A envelope), #240 (B origin gate), #242 (C metrics), #246 (D CORS).

| REQ | Status | Evidence |
|---|---|---|
| 001 one envelope on every `/api` error | DONE | `httpapi/errors.go:215-300` (`apiErr`, `buildEnvelope`), `api_docs.go:79` (`apiErrorHandler`); `TestEnvelopeContract_EveryRouteUnauthenticated401`, `_EveryRouteWrongMethod405`, `_UnknownPaths404`, `_EveryRouteAuthenticated` (incl. nil-pointer panic -> 500), `_GatesAndStatuses` in `api_error_contract_test.go` |
| 002 `error`+`message` kept, UI unchanged | DONE | `error ?? message` in `frontend/src/lib/{api,app-profiles,backups}.ts`; `ApiErrorBody` in `types.ts:194`; `e2e/error-envelope.spec.ts` (login 429, users, password policy, profile, backup; groups screen not covered) |
| 003 append-only code table | DONE | `TestEnvelope_CodeTableMatchesGoldenList` (`errors_envelope_test.go:30`) |
| 004 `requestId` == `X-Request-Id` | DONE | `api_error_contract_test.go:70` asserted on every contract case |
| 005 `retryable` / `Retry-After` | DONE | `TestEnvelope_RetryableRules`, `_RetryAfterOnlyForRetryable429And503`, `TestEnvelopeContract_LoginRateLimited429` |
| 006 5xx fixed text | DONE | `TestEnvelope_FivexxBodiesNeverCarryHandlerOrCauseText`, `api_error_contract_producers_test.go` |
| 007 single OpenAPI `Error` | DONE | `api_contract_errors_test.go:12` (`TestOpenAPIErrorResponsesUseTheSingleErrorSchema`, old components absent) |
| 008 `/metrics` off by default, separate listener, public 404 envelope, chart protection | DONE (live UNVERIFIED) | `cmd/server/metrics.go`, `metrics_test.go` (off without address, serves only `/metrics`); `TestPublicPortMetricsIsEnvelope404`; `config/metrics_addr_test.go`; chart `ui-metrics-service.yaml`, `ui-networkpolicy.yaml`, `scripts/test/test-chart-ui-metrics.sh` wired in `ci.yml:241`; live scrape step in `test-api-edge-codes-local.py` and `metrics-e2e.yml` not re-run |
| 009 bounded labels, no secrets | DONE | `metrics/metrics_test.go` `TestCardinalityIsBounded`, `TestLabelValuesAreNormalised`; `httpapi/metrics_test.go` `TestMetricsCardinalityThroughTheRouter`, `TestMetricsCarryNoSecrets` |
| 010 dependency gates | DONE | `prometheus/client_golang` in `ui/backend/go.mod` and `THIRD-PARTY-LICENSES.md`; licence gate, govulncheck and `check-modules.sh` pass in `make check` |
| 011 CORS off by default, exact allowlist, `Vary` | DONE | `cors.go`; `TestCORS_OffByDefault`, `_ActualRequests`, `_Preflight`, `_KeepsExistingVary`; startup rejection in `internal/config` tests |
| 012 CORS does not weaken writes | DONE | `TestCORS_DoesNotWeakenWriteProtection`, `TestCORS_ListedOriginCannotWrite` |
| 013 additive rollout, docs synced | PARTIAL | Flags default off; `docs/api.md` (CORS section line 283, codes, Origin gate), `llms.txt`, `charts/ldapium/README.md`, `ui/README.md` env rows exist. Gaps: `llms.txt:12` and the `openapi.json` info text still say flatly "no CORS headers" (CORS is opt-in now); `CHANGELOG.md [Unreleased]` has the envelope entry but nothing for the Origin gate, `METRICS_ADDR`/`ui.metrics.*`, `CORS_ALLOWED_ORIGINS`/`ui.cors.*`; no operator guide (scrape target, NetworkPolicy caveat) |
| 014 conventions for #214-#217 | PARTIAL | Rules are in `CHANGE.md` and `docs/api.md:94-167` (reserved names); #215/#216/#217 packages reference the table. Not done: T-004/T-053 link-up (#214 package, `IMPLEMENTATION-STATUS.md`) |
| 015 write Origin gate | DONE | `origin_gate.go`; `TestOriginGate_EveryWriteRoute`, `_LoginAndLogout`, `_Probe`, `TestSameOrigin`; `e2e/origin-gate.spec.ts` |
| 016 4xx message policy, no DN | DONE (live UNVERIFIED) | `TestRespondErr_WithholdsLDAPDiagnostics`, `TestPublicDomainMessage_*`, `TestValidateMessagesDoNotEchoValues`, DN leak sentinel `api_error_contract_test.go:33`. The live change-password failure screen was not observed |

Unmet acceptance criteria: AC-002 PARTIAL (no groups-screen e2e), AC-014 PARTIAL (REQ-013 gaps),
AC-015 NOT DONE (downstream link-up), AC-017 live part UNVERIFIED. AC-001, 003-013, 016, 018 met.

What remains: T-001..T-005 (baselines, spikes, Owner/ADR draft/security review were never recorded),
T-015 groups e2e, T-017 live check and the UI `code`-branch decision, T-035 release note, T-041 live run,
T-042, T-050..T-053 (ops guide, ADR, release/migration/rollback notes, downstream sync).
T-035 was ticked on main but its release-note clause is not satisfied, so this audit un-ticked it.

**Recommendation: KEEP OPEN.** The issue's three asks (one shape, `/metrics`, CORS decision) are
implemented, but AC-014/015/017 and the durable-truth tasks are open. Successors:

1. **docs: finish #218 documentation, release notes and downstream sync** (REQ-013, REQ-014; AC-014, AC-015; T-050..T-053)
   - Add `CHANGELOG.md [Unreleased]` entries for the same-origin write gate (breaking for non-browser clients that send `Origin`), `METRICS_ADDR` / `ui.metrics.*`, `CORS_ALLOWED_ORIGINS` / `ui.cors.*`.
   - Fix the unconditional "no CORS headers" wording in `openapi.json` info and `llms.txt:12` (update the drift tests together).
   - Operator guide: scrape target, NetworkPolicy peers, public-port `/metrics` 404.
   - Link #214-#217 packages to the code table, update `docs/IMPLEMENTATION-STATUS.md`, write the ADR for D218-1..14 or record "not needed".
   - Rollback/compat note for the `message` deprecated alias.
2. **test(ui): envelope e2e for groups and a live change-password failure check** (REQ-002, REQ-016; AC-002, AC-017; T-015, T-017, T-041)
   - Add the groups-screen case to `ui/frontend/e2e/error-envelope.spec.ts`.
   - Run a real change-password failure against `ldapium:e2e` and record the screen text and UX cost; decide whether `ChangePasswordPage.tsx` branches on `code`.
   - Re-run `test-api-edge-codes-local.py` (including the `/metrics` scrape) and record the image tags in a new `EVIDENCE.md`.
   - Record the T-001..T-004 baselines that are still feasible, or mark them waived with a reason.

---

## #216 conditional writes and idempotency (`api-conditional-writes`)

PRs: #235 (part A), #241 (part B).

| REQ | Status | Evidence |
|---|---|---|
| 001 headerless requests unchanged | DONE | `conditional_writes_test.go`, `api_conditional_contract_test.go`; live in `EVIDENCE.md` "Part A implementation" (edge-codes script) |
| 002 `etag` / `ETag` | DONE | `conditional.go`; list items and `GET /api/entry`; cursor items carry the same value (`docs/api.md:89`) |
| 003 conditional writes, 412 `revision_conflict`, 400 on malformed | DONE | `conditional_writes_test.go`; live "stale 412 with no write, concurrent writers 1x204+1x412 x15" |
| 004 atomic, fail-closed | DONE | `ldapclient/assertion.go` (critical control OID 1.3.6.1.1.12), `assertion_test.go` incl. `FuzzRevisionControls`; slapd 122 and code 12 in `EVIDENCE.md` (a) |
| 005 PATCH, PUT warning | DONE | `patch_handlers.go`, `patch_handlers_test.go`; PUT warning in `docs/api.md` and OpenAPI |
| 006 create compensation | DONE (caveat) | `ldapclient/create_compensation.go`, `create_failure_test.go`, `create_states_test.go`; `rolled_back` live. Not verified: `partial_failure` from a genuinely refused compensation, go-ldap mismatching-identity delete (`EVIDENCE.md` "Not verified") |
| 007 idempotency protocol | DONE | `internal/idempotency/*_test.go`, `idempotency_test.go`, `idempotency_review*_test.go`; live Part B run (25 PASS lines) |
| 008 no secrets stored | DONE | live "password with a key: replay body is {}", "UI log does not contain a key/password"; `TestBackupStartKeyRecordHoldsNoKeyNoDNAndIsNotServed` |
| 009 storage rules, outcome unknown | DONE (caveat) | `idempotency_review_test.go` with real go-ldap error shape over `net.Pipe`; a real socket drop mid-write was NOT run live (`EVIDENCE.md` Part B "Not verified") |
| 010 adoptable by #217 | DONE | `backup_idempotency_test.go` (same key same job, other kind 422, scope, rotation/lost key 409, restart) |
| 011 envelope and code table | DONE | codes in `errors.go:86-93`, `docs/api.md:148-155` |
| 012 docs/contract | DONE | `TestOpenAPIDocumentsIdempotencyKey`, `docs/api.md` ETag/Idempotency-Key sections, `llms.txt:33-36` |
| 013 frontend | NOT DONE | `grep -rn "If-Match\|Idempotency-Key\|idempotencyEnabled" ui/frontend/src` has no UI sender; no `etag` in the UI types |
| 014 live verification | PARTIAL | `EVIDENCE.md`: spike (a)-(d), Part A and Part B live runs, 2-node replication run. Missing: socket-drop retry, Playwright UI, ppolicy lastbind + If-Match, SSO mode |
| 015 limits disclosed | DONE | `docs/api.md:251` (memory records lost on restart), CHANGELOG (node-local condition, memberOf/refint), `charts/ldapium/README.md:320` |
| 016 activation switch | DONE | `UI_IDEMPOTENCY_ENABLED`, `idempotencyEnabled` in server-settings, `test-chart-idempotency-render.sh` wired in `ci.yml:414` |
| 017 persisted fingerprint key | DONE | `internal/idempotency/keyring_test.go`; live "key file is 0600 in a 0700 directory" |

Unmet acceptance criteria: AC-018 (UI) NOT DONE; AC-019 PARTIAL (limits evidence exists, listed live
cases missing). All other ACs have the evidence above (live parts UNVERIFIED here, recorded in `EVIDENCE.md`).

What remains: T-018 (frontend), T-001/T-004 (never recorded), T-021 residuals (no
`test-api-conditional-writes-local.py`; coverage was folded into the edge-codes and idempotency scripts),
T-020 frontend part, T-023, T-030 operator guide, T-031 ADR, T-033 (D217-9 still stale).

**Recommendation: KEEP OPEN.** The three criteria in the issue body are met at the API level, but
the package's REQ-013/AC-018 (UI) is open and several live cases were never run. Successors:

1. **ui: send If-Match and Idempotency-Key from the Users and Groups screens** (REQ-013, AC-018; T-018)
   - `lib/api.ts` header argument; edit/delete send `If-Match` when the item has `etag`.
   - Reuse one `Idempotency-Key` per attempt only when `server-settings.idempotencyEnabled` is true.
   - 412 shows a re-read notice (en/ko i18n); 422 `idempotency_unsupported` retries once without a key.
   - Bulk member saves send no `If-Match`. Types: `etag?`, `idempotencyEnabled?`.
   - Playwright cases for stale edit and replay; old server/new UI keeps working.
2. **test: close the remaining live-verification gaps for conditional writes and idempotency** (REQ-009, REQ-014; AC-019; T-020, T-021)
   - Kill the socket mid-write and retry with the same key against a real slapd.
   - go-ldap Delete with a mismatching `(entryUUID, entryCSN)` assertion answers 122; `partial_failure` from a genuinely refused compensation.
   - `ppolicy` lastbind + `If-Match`, SSO mode.
   - Put these into one committed live script and record image tags in `EVIDENCE.md`.
3. **docs: ADR and operator guide for conditional writes, update stale #217 text** (REQ-015; T-023, T-030, T-031, T-033)
   - ADR for D216-1, 2, 5, 6-9.
   - Operator note on expected 412 frequency (bookkeeping writes bump `entryCSN`) and the single-replica requirement.
   - Update `backup-job-ids/CHANGE.md` D217-9/Q2, which still say idempotency keys are out of scope although #241 shipped them for backup start.

---

## #215 cursor pagination (`api-cursor-pagination`)

PRs: #237 (image `LDAP_PAGED_TOTAL_LIMIT`), #243 (NUL fix), #244 (API).

| REQ | Status | Evidence |
|---|---|---|
| 001 no-parameter response unchanged | DONE | `TestListUsersLegacyBodyIsByteForByteUnchanged`, `TestListGroupsLegacyBodyIsByteForByteUnchanged` (`list_page_handlers_test.go:94,116`); live "legacy GET ... 5000 entries, truncated=true (unchanged)" in `EVIDENCE-api.md` |
| 002 keyset order, `limit` | DONE | `ldapclient/page.go`, `page_test.go`, `page_scan_test.go`; `TestKeysetResponseShapeAndCursorFlow` |
| 003 stateless opaque cursor, misuse rejected | DONE | `cursor.go`; `TestCursorRejectsEveryOneByteTamper`, `_RejectsMisuse`, `TestCursorBindingDoesNotExposeTheSessionID`; live re-login rejection |
| 004 lossless 10k+ walk | DONE (live UNVERIFIED here) | `EVIDENCE-api.md` section 3 (12000) and 6 (50000), admin and non-root with `LDAP_PAGED_TOTAL_LIMIT=unlimited`; `api-cursor-e2e.yml` |
| 005 documented concurrent-change semantics | DONE | `docs/api.md:83-89`; live `TestLiveChangesBetweenPhases` (a)-(f) |
| 006 `q` only, `sort` validated | DONE | `TestKeysetParameterValidation`, `page_test.go` filter escaping |
| 007 no `userPassword` | DONE | live over-privileged bind check in `EVIDENCE-api.md` section 3; denylist unchanged |
| 008 bounded latency/occupancy | DONE | `search_chunk.go`, `TestKeysetClientGoneIsNotAnError500`; live cancelled-chunk and parallel-probe results (`EVIDENCE-api.md` (e)-(g), section 8: 503 `scan_timeout` at 30.0 s) |
| 009 400 + envelope | DONE | `TestKeysetErrorMapping`, `TestKeysetErrorsAreEnvelopesAndNeverLeakDiagnostics` |
| 010 OpenAPI/docs/llms | DONE | `api_contract_test.go` drift tests pass; `docs/api.md:61-96`, `llms.txt:43-44` |
| 011 ACL-hidden entries, session binding | DONE | live case (e) hidden by ACL; `cursorBinding` tests |
| 012 performance budget | DONE | `EVIDENCE-api.md` section 6: p95 0.39-0.46 s at 50k, 12k full walk 4.8-4.9 s vs D215-9 budget |
| 013 explicit size-limit error | DONE | live "default config non-root: 422 `size_limit_exceeded`"; `TestKeysetErrorMapping` |
| 014 opt-in image/chart setting | DONE | `image/entrypoint.sh` `LDAP_PAGED_TOTAL_LIMIT` (#237, hardened #243); `EVIDENCE.md` section 1(b) 12 PASS lines; chart `ldap.limits.pagedTotal` |
| 015 monotonic emission across the two phases | DONE | `page_scan_test.go` assemble tests; live `betweenPhases` seam test |

AC-001..009, 011..013 are met with the evidence above. AC-010 (UI cursor mode) is explicitly conditional
and out of this package (D215-11); it is NOT DONE because the follow-up issue does not exist yet.

What remains: T-003 (no recorded downstream review), T-014 (`scripts/bench-generate-ldif.py` is
unchanged since #233; the live script has its own edge-entry generator, but the bench extension and its
`bench-load.sh` reuse were not done), T-032 (no cursor/image/chart lines in `CHANGELOG.md`, no scope
comment on the issue), T-033, Completion-review boxes for ownership and tracking.

**Recommendation: CLOSE once the UI successor exists.** Every acceptance criterion of the issue body (10000+
walk without loss/duplicates, scoped sort/filter and documented semantics, backward compatible response,
OpenAPI updated) is met with evidence, and the only unmet package AC is the conditional UI one, which
must be tracked, not hidden. File the two successors first, then close:

1. **ui: use cursor pagination in the Users and Groups lists** (AC-010; D215-11)
   - Replace client-side paging with `limit`/`cursor`/`q` and `hasMore`/`nextCursor`.
   - Previous/next: keep a client-side cursor stack; cursors are bound to the session and `q`.
   - Handle empty page with `hasMore: true`, 400 `cursor_invalid` (restart), 422 `size_limit_exceeded` (narrow `q` hint), 503 `scan_timeout`.
   - Narrow-viewport layout, en/ko strings, Playwright cases for boundaries and error recovery.
   - Leave the groups-pagination package's client-side behaviour intact until this lands.
2. **docs/tooling: #215 leftovers (release notes, bench generator, downstream sync)** (T-003, T-014, T-032, T-033)
   - `CHANGELOG.md [Unreleased]`: API (cursor mode, new codes), image (`LDAP_PAGED_TOTAL_LIMIT`), chart (`ldap.limits.pagedTotal`), rollback note.
   - Extend `scripts/bench-generate-ldif.py` with groups and the edge entries, or point the task at the live script's generator and drop the task.
   - Record the #214 cursor-binding and #218 code-table review; update `IMPLEMENTATION-STATUS.md`.

---

## #217 backup job IDs (`backup-job-ids`)

PR: #236 (single implementation PR, "Related to #217 (not closing yet)").

| REQ | Status | Evidence |
|---|---|---|
| 001 202 + `Location` + `job_id` | DONE | `TestBackupJobStartReturnsIDAndCompletes` (`backup_jobs_handlers_test.go:135`), `TestBackupJobBoundaries`; live "202 + Location" (`EVIDENCE.md`) |
| 002 unique persistent record | DONE | `backup/jobs.go`, `jobs_store.go`, `jobs_store_test.go` |
| 003 states, timestamps, codes, no secrets | DONE | `jobs_test.go`, `jobs_trust_test.go`; secret sentinel test |
| 004 atomic 0600 file, pruning | DONE | `jobs_store_test.go`; live "`.results/<job_id>.json` mode 600" |
| 005 list/get | DONE | `GET /api/v1/backups/jobs`, `/jobs/{id}`; `TestBackupJobBoundaries` |
| 006 cancel | DONE (SIGKILL path unit only) | `TestBackupCancelOverHTTP`, `manager_jobs_test.go`; live cancel -> `cancelled`, `staging_cleanup=done` |
| 007 deadline | DONE (unit only) | `TestJobDeadlineKillsTheProcessGroup`; `config` timeout tests; no live run (`EVIDENCE.md` "Not verified") |
| 008 restart recovery incl. orphan worker | DONE | `jobs_reconcile.go`, `jobs_reconcile_test.go`; live backend-SIGKILL -> `running`+`orphan_suspected` -> settled `succeeded` |
| 009 single active job, 409 names it | DONE | `TestBackupBusyNamesTheActiveJob`; live 409 `backup_busy` with `active_job_id` |
| 010 per-destination results, manifest | DONE (remote destinations UNVERIFIED) | `scripts/test/test_backup_worker.py` (12 tests); remote S3/FTP/SFTP not run live |
| 011 log lines | DONE | live "backup log lines carry no DN"; `manager_jobs_test.go` |
| 012 envelope and codes | DONE | `errors.go:81-83`; codes in `docs/api.md:143-146` |
| 013 OpenAPI/docs/compat | DONE | drift tests pass; `docs/api.md`, `llms.txt:46`, `ui/README.md`; `states[kind]` unchanged |
| 014 UI | DONE | `BackupsPage.tsx`, `e2e/backup-jobs.spec.ts`; live Playwright 4 passed (`EVIDENCE.md`, not re-run here) |
| 015 no secrets/DN anywhere | DONE | sentinel test (T-020); `TestBackupStartKeyRecordHoldsNoKeyNoDNAndIsNotServed` |
| 016 persistence order/failure | DONE | `TestBackupPersistenceFailureIs503AndStartsNothing`; injected-writer tables in `jobs_store_test.go` |
| 017 worker lock, `worker_busy` rescheduling | DONE | `jobs_reconcile_test.go`; worker exit 75 test in `test_backup_worker.py` |

All 15 ACs are met with the evidence above (live parts UNVERIFIED here; recorded in `EVIDENCE.md`: 23 live
checks PASS). Caveats stated by the package itself: remote destinations, SIGKILL-after-grace and deadline
are unit-tested only.

What remains: T-001..T-005 (baselines/spikes/acceptance never recorded; the orphan scenario was instead
exercised live in `test-backup-jobs-live.py`), T-031 (`CHANGE.md` D217-9 and Q2 still say keys are out of
scope although #241 added them to backup start), T-032 (no backup entry in `CHANGELOG.md`: new endpoints,
`cancelled` status, 409 body fields, 422 -> 503 persistence split, `actor` -> `actor_fp` log change,
`<root>/.results/`, image rebuild), T-033.

**Recommendation: CLOSE.** The issue asks for job ID, status query, cancel/recovery, deadline and audit
correlation; each is implemented and evidenced. No unmet acceptance criterion. The leftovers are docs and
recording tasks; file one small docs issue so they are tracked, then close:

1. **docs: #217 release notes and package sync** (T-031, T-032, T-033; T-001..T-005 either recorded or waived)
   - `CHANGELOG.md [Unreleased]` entry with the compatibility changes listed above and the rollback note (old versions ignore `backup-jobs.json`).
   - Update `backup-job-ids/CHANGE.md` D217-9/Q2 to reflect #241 (keyed backup start, key file, key_id).
   - Run the remote-destination, SIGKILL-after-grace and deadline paths live once, or record them as accepted unit-only.
   - Fill in `docs/IMPLEMENTATION-STATUS.md`.

---

## PR-body consistency check

All implementation PRs say "Related to #N (not closing...)": #233 (#215-#218, "not closing"), #234 (#218,
"closes with the last slice"), #235 (#216, "part B ... closes the issue"), #236 (#217), #237 and #243
(#215), #240, #242, #246 (#218), #241 (#216, "not closing yet"), #244 (#215). None used a closing keyword,
and all four issues are still OPEN (`gh issue list`). Two statements were overtaken by events and are
not errors: #235 predicted that part B would close #216, and #234 that the last #218 slice would close
#218; this audit finds open scope in both, so keeping them open is correct. #245 touches no tracked issue.

## Tick summary

| Package | Ticked in this audit | Un-ticked | Notes added |
|---|---|---|---|
| api-error-envelope | 8 (T-010..T-014, T-016, T-040, T-043) | 1 (T-035) | 14 |
| api-conditional-writes | 8 (T-002, T-003, T-010..T-013, T-016, T-032) | 0 | 9 |
| api-cursor-pagination | 0 (already ticked on main and re-verified) | 0 | 5 |
| backup-job-ids | 0 (already ticked on main and re-verified) | 0 | 9 |
