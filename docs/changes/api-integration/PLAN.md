# External system / AI HTTP API readiness review

2026-10-03 review requested; implementation of a new public service API is not
part of this request. Current source (not a published release) supports UI/session
and constrained scripted automation. REVIEW.md contains static evidence and limits.

## Current integration boundary

LDAP mode: authenticate via POST /api/login, retain its signed cookie, call protected
HTTP endpoints using the bound principal's LDAP ACL, log out. SSO mode uses browser
OIDC authorization and does not accept external bearer tokens or client_credentials.
Application profiles and backups have session/admin allowlists and revision gates;
core LDAP CRUD has no general API scope, idempotency or conditional-write contract.
Unknown /api routes are JSON 404s, not UI assets. UI pagination is client-side;
user/group HTTP lists cannot retrieve entries beyond the 5000-entry cap.

## Prioritized next design work

P0 — Define the supported machine principal and per-operation/subtree permissions.
Reuse verified Keycloak issuer/audience policy with a dedicated service client; do
not give AI the root LDAP password or SESSION_SECRET. Enforce server-side scopes
and map execution to least-privileged LDAP identities. Read-only default. Preserve
UI authorization/CSRF boundaries; browser and machine flows need separate contracts.

P1 — Versioned OpenAPI for supported DTOs, capability discovery, common errors
(code/message/request_id/retryable), explicit PUT/PATCH semantics and examples.
Contract tests and generated client evidence. Document enabled/disabled features,
not local-only overlays as released capabilities. Keep old paths compatible.

P1 — Server cursor paging, bounded filters/order and complete list traversal.
Acceptance: 10000+ entries traversed without loss/duplication in a stable snapshot;
concurrent change semantics explicitly documented. Scope prevents data enumeration
outside the service principal's subtree. LDAP/password/config secrets remain redacted.

P1 — Conditional writes and idempotency; explicit partial completion/compensation
for user Add + password update. Acceptance: lost HTTP response and retries do not
create duplicate or silently destructive effects; stale revision rejects writes.

P2 — Durable job IDs/status/cancellation/recovery for applicable asynchronous jobs,
request/LDAP deadlines, retry hints, quotas and audit correlations. A backup run is
not the same as a universal jobs API. Add AI function/MCP adapters only after the
HTTP contract; tool schemas follow authorized API operations. Read/plan/write
separation for privileged operations, no arbitrary DN/command proxy tools.

Existing strengths: live LDAP ACL authorization, password denylist, private secrets,
SSO validation, audit request IDs, ETags for profile/backup changes. They do not
establish blanket platform-wide service authentication or applied native-app rights.
SCIM/IGA/policy engine/AI executor remain separate product-scope decisions.
