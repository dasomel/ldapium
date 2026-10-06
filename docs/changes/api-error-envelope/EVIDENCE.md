# Evidence: HTTP API error envelope, `/metrics`, CORS (#218, #249)

Environment: macOS, docker context `colima`, Go 1.27.1, Node v26.10.0, Playwright 1.63 (chromium), Python 3.
Image tags: the edge-codes run used `ldapium:lane-249` / `ldapium-ui:lane-249`; the change-password re-run (below) used fresh builds `ldapium:lane-249b` (`docker build -t ldapium:lane-249b -f image/Dockerfile ./image`) and `ldapium-ui:lane-249b` (`docker build -t ldapium-ui:lane-249b ui`).
Date: 2026-10-06.
Docker objects were prefixed `ldapium-edge-249-` and `ldapium-cp-249b-`, and cleaned up after execution.

## T-001..T-004 Baselines and Downstream Review

- **T-001 (Source-of-truth recount):**
  - Error producer count in non-test `ui/backend/internal/httpapi`: 98 `echo.NewHTTPError`, 30 `respondErr`, 31 `apiErr` (total 159 call sites across router, gates, and domain handlers).
  - Error assertion call sites across `*_test.go`, `scripts/test`, and `ui/frontend/e2e` verified and compatible with `{error, message, code, requestId, retryable}`.
- **T-002 (Pre-change baseline):**
  - Pre-PR baseline waived as historical: PR #234 already merged on `main`. Current baseline verified: `go vet ./...` clean; `go test ./... -race -count=1` passes across all 13 backend packages; `npm run lint` and `npm run build` pass in `ui/frontend`.
- **T-003 (Spike conclusions):**
  - ① Recover panic and router 404 `X-Request-Id`: Confirmed by `TestEnvelopeContract_EveryRouteAuthenticated` (panic recovered to 500 with `X-Request-Id` == `requestId`) and `TestEnvelopeContract_UnknownPaths404`.
  - ② Echo `OPTIONS` + CORS: Confirmed in PR #240 / `cors_test.go`: registered routes return 204 with `Allow`; CORS preflight is intercepted before `RouteNotFound` and answered with 204 + `Access-Control-*` + `Vary: Origin`.
  - ③ Session auth test fixture: Confirmed in `contract_fixture_test.go` via in-memory session store (`session.NewStore`) and signed session cookies without live slapd.
- **T-004 (Downstream review):**
  - Verified against main (`6c118ac`): All error codes introduced by #215, #216, and #217 (`cursor_invalid`, `size_limit_exceeded`, `scan_limit_exceeded`, `scan_timeout`, 5 idempotency codes, `partial_failure`, `backup_busy`, `job_not_found`, `job_not_cancellable`, `persistence_unavailable`) are present in `codeTable` and the 35-entry golden list with no name collisions.

## Groups Screen E2E Test (T-015, AC-002)

Added `group list failure shows the validation text` to `ui/frontend/e2e/error-envelope.spec.ts` mirroring the existing user list failure case.
Ran Playwright test suite against dev server (`E2E_BASE_URL=http://localhost:15249`; mocked routes, no backend):
```
Running 6 tests using 1 worker
  ✓ login shows the 429 text and ignores the new keys (930ms)
  ✓ user list failure shows the validation text (694ms)
  ✓ group list failure shows the validation text (708ms)
  ✓ password-policy refusal is shown as the server sent it (807ms)
  ✓ application profile screen reads error first, message as a fallback (1.1s)
  ✓ backup screen shows the 409 text (691ms)
  6 passed (6.3s)
```

## Live Change-Password Check & Decision (T-017, AC-017)

Re-run 2026-10-06 against `ldapium:lane-249b` and `ldapium-ui:lane-249b` with Chromium driving `ChangePasswordPage.tsx`:
`LDAPIUM_IMAGE=ldapium:lane-249b LDAPIUM_UI_IMAGE=ldapium-ui:lane-249b LDAPIUM_CP_PREFIX=ldapium-cp-249b- python3 scripts/test/test-change-password-live.py`.
The script now asserts every outcome below (status, `code`, screen text, and `LDAP Result Code 53` in the UI log for the 500's requestId; a missing log line fails the run). All `ok:` checks passed. requestIds below are from the earlier lane-249 run; the 249b run produced the same statuses, codes and texts with new requestIds (e.g. `hlxLepQJGyjuTTHVlYqEeUCYrOTlMvJS` for scenario 1):

1. **Scenario 1 — Wrong current password:**
   - Input: Current = `Wrong-Current-Pass-999!`, New = `Valid-New-Pass-456!`, Confirm = `Valid-New-Pass-456!`.
   - HTTP Status: `500 Internal Server Error`.
   - API Body: `{"error":"internal error","message":"internal error","code":"internal","requestId":"zjbQirFuuVjeLEEbEsbFiKhcvrWtARyo","retryable":false}`.
   - Screen Text: `"internal error"`.
   - UI Backend Log: `internal error ["zjbQirFuuVjeLEEbEsbFiKhcvrWtARyo"] "POST" /api/users/password: "ldap set password: LDAP Result Code 53 \"Unwilling To Perform\": unwilling to verify old password"`.
2. **Scenario 2 — Weak new password (PPM strength failure):**
   - Input: Current = `Current-Pass-123!`, New = `aaaaaaaaaaaaaaaa`, Confirm = `aaaaaaaaaaaaaaaa`.
   - HTTP Status: `400 Bad Request`.
   - API Body: `{"error":"invalid input: Password does not pass required number of strength checks (1 of 3)","message":"invalid input: Password does not pass required number of strength checks (1 of 3)","code":"invalid_request","requestId":"RUXVMiRmJolxDSwQXsPwLFwdViBIuhdc","retryable":false}`.
   - Screen Text: `"invalid input: Password does not pass required number of strength checks (1 of 3)"`.
3. **Scenario 3 — Unchanged password:**
   - Input: Current = `Current-Pass-123!`, New = `Current-Pass-123!`, Confirm = `Current-Pass-123!`.
   - HTTP Status: `400 Bad Request`.
   - API Body: `{"error":"invalid input: Password is not being changed from existing value","message":"invalid input: Password is not being changed from existing value","code":"invalid_request","requestId":"ftDFHmYwAxqxkYljFrzqEZqBYmEzlcuh","retryable":false}`.
   - Screen Text: `"invalid input: Password is not being changed from existing value"`.

### Decision on branching on `code` in `ChangePasswordPage.tsx`
- **Decision: NO.**
- **Rationale:**
  1. OpenLDAP slapd returns LDAP Result Code 53 (`Unwilling To Perform`) when verifying the current password under `pwdSafeModify`. In `ui/backend/internal/ldapclient/errors.go`, Result Code 53 is not mapped to a domain sentinel, and `respondErr` maps unmapped errors to HTTP 500 (`code: internal`).
  2. Per D218-8, 5xx bodies are strictly redacted to static `"internal error"` to prevent internal diagnostic and credential leakage.
  3. The task requires that the backend error contract is NOT changed.
  4. If `ChangePasswordPage.tsx` were to branch on `code === 'internal'`, any genuine 500 error (LDAP server crash, network failure, unhandled panic) would be misreported to the user as an incorrect current password input (`changePassword.ambiguousCurrentPassword`).
  5. Branching on `code === 'invalid_request'` would override the curated, safe ppm/ppolicy diagnostic text allowlisted by `error_diagnostics.go`.
  6. Therefore, branching on `code` in `ChangePasswordPage.tsx` is unsafe.
- **UX Cost:**
  Users who submit an incorrect current password receive `"internal error"` instead of the ambiguous-current-password explanation. Operators must use the `requestId` in the UI logs to correlate with `LDAP Result Code 53: unwilling to verify old password`.

## Live API Edge-Codes Script Execution (T-041, AC-007..AC-009, AC-018)

Executed `scripts/test/test-api-edge-codes-local.py` against `ldapium:lane-249` and `ldapium-ui:lane-249`:
```
LDAPIUM_IMAGE=ldapium:lane-249 LDAPIUM_UI_IMAGE=ldapium-ui:lane-249 LDAPIUM_EDGE_PREFIX=ldapium-edge-249- python3 scripts/test/test-api-edge-codes-local.py
```
Output:
```
ok: admin password absent from every /proc/*/environ and /proc/*/cmdline (names=0 hits=0 seen=2)
ok: conditional writes (ETag/If-Match on every protected route, stale 412 with no write, concurrent writers 1x204+1x412 x15, PATCH merge, create rollback, identity-bound delete 122)
ok: CORS read-only for https://console.example (Vary: Origin on every response, preflight GET/HEAD/OPTIONS only, listed origins cannot write: user create and logout are 403, session survives)
ok: /metrics on the metrics port only (18 routes in the label set); public /metrics is the 404 envelope; bind/search/write, API error codes, sessions counted; no secrets or paths in labels
PASS: unlock idempotent (204/404), lock->bind fails->unlock->bind works, group member 204/409/404, error envelope on 400/401/403/404/405/409/412/422/428/500 (error==message, requestId==X-Request-Id, no DN), password-policy text without DN, meta allowlist, no userPassword in /api/entry, conditional writes (If-Match/ETag/PATCH/create rollback)
```
Status: PASS (exit 0).

## Frontend Playwright specs run for T-041

Scope actually run: only the specs that use mocked routes and need no backend or credentials, against `npx vite --port 15260 --strictPort` (`E2E_BASE_URL=http://localhost:15260`; vite binds IPv6 localhost, so `127.0.0.1` does not connect):
`npx playwright test api-docs conditional-writes.spec error-envelope` -> `24 passed (16.7s)`.
NOT run: `applications`, `backups`, `backup-jobs`, `conditional-writes-live`, `grafana-permissions`, `groups-pagination`, `health`, `keycloak-apps`, `origin-gate`, `ui-review`. They require `E2E_ADMIN_DN`/`E2E_ADMIN_PASSWORD` and a live stack (`applications.spec.ts` and `backups.spec.ts` throw at load without them, observed), Grafana or Keycloak; CI runs them (`ui-e2e.yml`, `ui-fixture-e2e.yml`).
