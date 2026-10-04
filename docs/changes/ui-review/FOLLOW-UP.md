# UI/SSO follow-up — 2026-10-02

Goal: close independent implementation review and automate supported native
configuration preparation without broadening the backend credential/proxy boundary.
Files: appprofile store/export and regression tests; offline integration tool;
local Keycloak/Grafana verification; operating documentation. Keep other worktrees,
LDAP semantics, existing deployment credentials and shared app instances untouched.
Verify: independent read-only review/re-review, Go race/vet, browser persistence,
real exported+merged Grafana OIDC allow/deny journey and private file preservation.

Independent reviewer found two P2 defects:
1. Export rejected nested/full Keycloak group paths accepted by the UI.
2. Profile delete/recreate reset the revision, accepting a stale tab's mutation.

Fixes: bounded slash-compatible group values while retaining quote/comma/control/
wildcard rejection; persistent deleted records retain each ID's revision generation.
Deleted entries never appear in list/get and callers cannot set `deleted=true`.
Recreation uses If-Match zero but continues the saved revision sequence. Regression
covers restart between deletion/recreation and stale PUT/DELETE. Deleted IDs count
against the 1000-entry/4MiB catalog ceiling; offline backup must retain tombstones.
Rollback to strict old readers requires a compatible backup because of `deleted`.

Native preparation: `scripts/integration/merge-app-oidc.py` consumes the exported
API artifact envelope and existing Grafana INI or Argo CD ConfigMap JSON. Default
mode validates and reports managed field names only; --output creates a new 0600
file exclusively, leaving the original unchanged. No remote calls or server-side
credentials. Grafana secrets/unmanaged settings remain, but INI comments/format
are normalized. Argo CD policy.csv/other composed policies stay unchanged; the
owned policy.ldapium.<profile-id>.csv is replaced and conflicting default/scopes are rejected.
Each profile owns a distinct composed key, preserving other profiles on the target.
Merged Argo CD RBAC preserves existing grants, so unmatched login denial must be
checked against the whole app policy and cannot be inferred from this export.

Actual native deployment remains dependent on the user's target address and
Docker/Helm/GitOps ownership. This tool is not an automatic remote ACL executor.
User asked to finish remaining work; target clarification requested while review,
fixes and local/disposable verification proceed independently.

Official references:
- https://argo-cd.readthedocs.io/en/stable/operator-manual/rbac/#policy-csv-composition
- https://grafana.com/docs/grafana/latest/setup-grafana/configure-grafana/


Observed verification:
- `go test -race ./... && go vet ./...`: all packages passed after both P2 fixes.
- `python3 scripts/test/test-app-profiles-local.py`: 3 browser tests passed (4.4s),
  real LDAP authentication and profile/custom-method backend-restart equality.
- `python3 -m unittest discover -s scripts/test -p test_merge_app_oidc.py`: 3 passed;
  secrets/other policies preserved, two profile keys coexist, conflicting defaults
  rejected, output private and source/existing output never overwritten.
- `python3 scripts/test/test-app-keycloak-local.py`: Keycloak browser 1 passed
  (1.9s); exported artifact passed through merge CLI to real Grafana 13.1.0;
  `/developers` Editor and unmapped-user rejection browser 1 passed (2.0s).
- Local integrated frontend build/backend rebuild passed; 8080 restarted, both
  existing profiles and live read-only Keycloak catalogs observed after LDAP login.
- Reviewers' static verification and locally run tests are separate evidence.
  Initial review and re-review findings are preserved in REVIEW-INITIAL.md and
  REVIEW-RECHECK.md. No production/native permission mutation performed.

Final independent re-review: PASS. Cross-profile policy preservation and conflicting
default rejection confirmed; 2 targeted tests passed in the review lane. Reviewer
read-only sandbox could not run CLI tempfile tests; all 3 were run locally and passed.
Final artifact: REVIEW-FINAL.md. Remote target address/deployment method is the
remaining blocker for actual native deployment; configuration preparation is delivered.
