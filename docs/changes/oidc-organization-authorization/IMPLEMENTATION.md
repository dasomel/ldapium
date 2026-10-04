# Application OIDC permission integration — implementation evidence

Date: 2026-10-01. User authorized implementation and continued completion.
D15/D16 in APP-AUTHORITY-AND-CAPABILITIES.md are the current baseline; earlier
organization/PDP/DB proposals are alternative future work, not implemented scope.

## Delivered

- Arbitrary app registration, persistent profile CRUD, revision conflicts, claim
  mappings, validation, and browser UI. No hardcoded mandatory OSS catalog.
- Explicit profile-admin DN authorization, same-origin JSON writes, strict bounded
  inputs, private atomic single-process metadata storage. Feature disabled by default.
- Real Keycloak catalog read-through and delegated client-role CRUD, composites,
  configured group-role mapping; issuer/client/group boundaries, cycles and
  cross-client privilege checks; observed fingerprint conflicts and intent/result audit.
- Generic OIDC integration contract, capability API, claim mapping preview,
  Grafana and ArgoCD configuration exports. Artifacts contain no credentials.
- Configuration observation explicitly distinguishes catalog verification from
  token delivery and actual native app authorization. Profile deletion only
  removes metadata; it never deletes upstream roles or application permissions.
- Helm opt-in PVC/Secret wiring, one-replica guard and Recreate strategy, operating
  instructions and rollback boundaries. No shared deployment or commit/push.

## Decisions and operating limits

D17–D19: optional file storage, explicit DN gate, same-origin browser writes.
D20: shared-realm writes denied; service account must be confined to an isolated
realm and allowlisted clients/groups. The flag is an operator assertion, not a
proof of upstream least privilege. D21: synchronous bounded upstream operations
with reread and audit replace the initial asynchronous outbox proposal for this
single-authority integration. Keycloak has no atomic external CAS: concurrent
Console changes can race after comparison; ambiguous failures require reload.
D22: Helm prevents multiple metadata writers using one replica and Recreate.

Composite roles explicitly aggregate child roles. Organizational hierarchy does
not imply group-role inheritance or global app administration. Unsupported
organization scopes are rejected. Existing tokens retain claims until renewal;
app sessions require native revocation policy. No bearer/PDP API, native ACL
provisioning, generic remote adapter execution, HA database, realm/client creation,
LDAP federation provisioning or organization policy engine is delivered.

## Observed checks

- `cd ui/backend && go test -race ./... && go vet ./...`: all packages passed.
- `cd ui/frontend && npm run lint && npm run build`: zero lint errors; existing
  React warnings outside this feature; TypeScript/Vite production build passed.
- `python3 scripts/test/test-app-profiles-local.py`: disposable real LDAP login,
  Chromium profile save/reload, unsupported mapping rejection and backend restart.
- `python3 scripts/test/test-app-keycloak-local.py`: Keycloak 26.7.4 isolated realm,
  actual service-account role/composite/group writes, fresh JWT inherited roles,
  revocation on fresh token, cycle/stale/client-boundary rejection; browser creates
  and deletes a delegated role (`1 passed (3.0s)`).
- Same script applies exported configuration to real Grafana, version 13.1.0:
  OIDC user becomes Editor, admin access denied, unmapped login rejected
  (`1 passed (2.1s)`). Local Grafana `latest` tag is not a pinned production contract.
- `helm lint charts/ldapium --set auth.existingSecret=ldap-secret`: passed.
  Enabled profile/Keycloak template rendered; multi-replica, missing PVC and blank
  administrator fixtures rejected after the blank-list-item regression was fixed.
- `git diff --check`: passed.

Preserved failures: initial TS type-only import and accessible-select lookup;
wrong working directory checks; test fixture omitted numeric zero If-Match;
chart accepted a list containing an empty admin DN. Each was fixed and the
relevant check rerun. No skipped or placeholder feature branches added.

ArgoCD export has unit/structure verification, not a live ArgoCD deployment.
Independent review and finding re-review completed on 2026-10-02; see
[follow-up evidence](../ui-review/FOLLOW-UP.md). Existing unrelated working-tree
changes are preserved; no production credentials or external app mutations.
