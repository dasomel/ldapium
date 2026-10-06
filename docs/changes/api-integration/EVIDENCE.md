# Evidence: External system / AI HTTP API readiness (api-integration)

Live and contract evidence for items prioritized in [PLAN.md](PLAN.md).

## P1: Conditional writes and idempotency (Issue #216, Issue #251)

Acceptance criteria:
- Lost HTTP response and retries do not create duplicate or silently destructive effects.
- Stale revision rejects writes (HTTP 412 `revision_conflict`).
- Atomic fail-closed RFC 4528 assertion controls (LDAP result 122).
- Explicit partial completion/compensation for user Add + password update (HTTP 500 `partial_failure` with `state: partial`, `dn`).

Detailed test runs, image tags, and outputs are documented in [docs/changes/api-conditional-writes/EVIDENCE.md](../api-conditional-writes/EVIDENCE.md) (Part A, Part B, and Part C).

Automated regression coverage:
- `scripts/test/test-api-conditional-writes-local.py`: live test covering mid-write socket drop replay, wire-level LDAP result 122 mapping, refused compensation 500 partial failure, and ppolicy lastbind in SSO mode.
- `ui/backend/internal/ldapclient/assertion_live_test.go`: wire-level assertion delete test against a real slapd.
- `.github/workflows/api-credentials-e2e.yml`: CI workflow executing `test-api-conditional-writes-local.py` against disposable Docker containers.
