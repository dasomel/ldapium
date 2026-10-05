# OSS integration guidance and UI change

2026-10-02. Accepted user request: research OSS permission integration and apply
an improved UI to both local ports while preserving existing local features.

## Plan and acceptance

- Keep Keycloak as role authority and each application as native enforcement.
- Add optional integration_type metadata (legacy profiles remain generic), reusable
  OSS guides, setup selection, structured mapping rows and separate setup/Keycloak/
  export views. Examples must not become a fixed list of supported applications.
- Distinguish tested exporter, configuration exporter and manual integration guide.
  Do not imply a Harbor project or Kubernetes namespace grant is applied by a
  generic profile. Persist guide selection and expose the guide IDs in capabilities.
- Preserve existing APIs, credentials, upstream roles and other worktree files.
- Verify schema compatibility, browser template/save/reload/export journeys,
  production build, local 8080/5173 and restored test-data page.

## Research (official sources)

| Application | How authorization follows SSO | Current product support |
| --- | --- | --- |
| Grafana | claim expression → organization role; strict mapping can reject unmapped users | Export; prior live Editor/deny evidence |
| Argo CD | groups → global RBAC or AppProject role; default policy applies to all authenticated users | App-wide admin/readonly export only |
| Harbor | groups claim registers identities; admin group is system-wide; project memberships separately set roles | Manual guide, generic contract |
| Gitea | OAuth source supports group claim admin/restricted users and organization/team mapping; repository permissions belong to teams | Manual guide, generic contract |
| Kubernetes | JWT/OIDC authenticates identity/groups; RoleBinding scopes grants to namespaces, ClusterRoleBinding grants cluster-wide | Manual guide, generic contract |
| OpenBao | OIDC/JWT role constraints and token policies, groups claim creates identity group aliases; policies authorize paths | Manual guide, generic contract |
| OAuth2 Proxy | allowed groups restrict gateway entry; application data/actions still require app authorization | Gateway guide, generic contract |
| Other apps | declare claim/token source and actual native or gateway enforcement | Generic contract |

Sources accessed 2026-10-02:
- https://grafana.com/docs/grafana/latest/setup-grafana/configure-access/configure-authentication/generic-oauth/
- https://argo-cd.readthedocs.io/en/stable/operator-manual/rbac/
- https://goharbor.io/docs/2.14.0/administration/configure-authentication/oidc-auth/
- https://docs.gitea.com/administration/authentication/
- https://kubernetes.io/docs/reference/access-authn-authz/authentication/
- https://kubernetes.io/docs/reference/access-authn-authz/rbac/
- https://openbao.org/docs/auth/jwt/
- https://oauth2-proxy.github.io/oauth2-proxy/configuration/overview/

Guide selection supplies defaults only and cannot prove claim delivery, revoke
existing tokens or enforce native resource scopes. Owner must verify their deployed
version, positive/negative permissions and session/token revocation separately.

## Implementation and observed evidence

- Optional guide type persists without changing existing profile role authority.
  Legacy missing guide defaults to generic. Unknown guide IDs are rejected with
  generic available for arbitrary applications. Downgrade of strict older stores
  requires a compatible backup/metadata migration (documented in UI README).
- Eight selectable starting points, bilingual native scope/privilege guidance,
  exact claim-value mapping rows, application role choices, separate Keycloak and
  delivery stages. Unsaved profile changes disable downstream stages.
- Exports are prepared visibly before explicit download. Preview separates mapped
  roles from unmapped values. App access remains unverified; no fabricated status.
- `go test -race ./... && go vet ./...` (ui/backend): passed.
- `npm run lint && npm run build` (ui/frontend): zero errors; pre-existing React
  warnings and production chunk-size warning remain. No new dependency.
- `python3 scripts/test/test-app-profiles-local.py`: two Chromium journeys passed
  (2.8s), plus actual LDAP login and full profile equality after backend restart.
  Covers generic save/reload, gateway rejection, Harbor privilege guide, Grafana
  guide persistence, role preview, supported export and dirty downstream guard.
- `python3 scripts/test/test-app-keycloak-local.py`: Keycloak role CRUD browser
  journey passed (1.9s), live composite/group/fresh-token revocation and negative
  boundaries passed; real Grafana 13.1.0 Editor/unmapped denial passed (1.9s).
- Local integrated build retains test-data/Keycloak/replication source from the
  previous local worktree; original worktree and other session's commits untouched.
  Both 8080 and 5173 verify Korean guide, mapping save/export/metadata deletion,
  unsaved-change guard and real test-data dataset API. Screenshots inspected.
- `git diff --check`: passed. No commit, push, native app deployment or test-data
  generation/deletion performed. Native permissions were changed only in disposable
  test containers, not existing local applications.

Failures retained: accessible enforcement label missing its exact name, unmapped
value lacked a separate text element, restart harness expected one profile instead
of two, first immediate deployment check raced server readiness, and two shell
commands used the wrong working directory. Fixed and rerun; no skipped assertions.

Only Grafana has live native authorization evidence; other new guides were
researched and UI-tested, not deployed to real Harbor/Gitea/Kubernetes/OpenBao.
Independent review has not been performed.

D24: Vite's string proxy configuration rewrote Host while retaining Origin,
causing a real 5173 profile PUT to fail the backend same-origin check (403).
Explicit `changeOrigin:false` preserves both browser headers; backend CSRF and
Origin enforcement remain unchanged. Actual Korean Chromium save/export/delete
journeys passed on both ports after this fix; temporary profiles were removed
and the original two persisted profiles remain. Vite primary reference:
https://v8.vite.dev/config/server-options#server-proxy

## User-defined integration methods — 2026-10-02

User requested adding methods instead of a fixed OSS selection. Plan: reusable
admin-managed method metadata, UI add/edit, HTTP list/conditional save and
single-process atomic persistence beside profiles. Acceptance: add a custom
method, choose its card, preserve claim/token defaults and roles after restart,
reuse across apps, reject stale updates and unsafe documentation URLs. Existing
native exporters and Keycloak authority remain unchanged. Custom methods export
generic contracts; custom scripts/native APIs are not executed. No deletion in
this slice, preventing dangling references from existing app profiles.


Custom-method implementation evidence (2026-10-02): template store/API and editor
implemented; native exporters remain capability-bound. `python3
scripts/test/test-app-profiles-local.py` passed all 3 browser tests (4.0s), then
compared profiles and custom method revision 2 after backend restart. HTTP tests
cover denied non-admin/cross-origin requests, missing/stale revisions, unsafe
URLs and unregistered methods. `go test -race ./...` and `go vet ./...` passed.
