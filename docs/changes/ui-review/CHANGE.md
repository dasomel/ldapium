# Administrative UI review and improvement

2026-10-02. User requested research-informed review and improvements throughout
UI, retaining other sessions' implemented work and local deployment continuity.

Goal: clear navigation, accessible controls, responsive layouts, explicit
LDAP/Keycloak/native-app authority, truthful status and safer action presentation.
Scope: shared shell/components, directory pages and app SSO integration; inspect
existing local settings/Keycloak/replication/test-data pages as well. Preserve
backend LDAP operation semantics, auth rules and destructive confirmation gates.
No native OSS app rollout or data mutation is needed for the visual audit.

Acceptance:
- Inventory every local menu route through actual authenticated browsing.
- Current route indicated correctly; compact navigation usable at narrow width.
- Form inputs/action controls have names, keyboard focus remains visible, dialogs
  fit short screens and scroll, empty/error/loading states give a next action.
- Role/grant vs login/admission and observed/configured/verified state stay distinct.
- User-created integration methods work without a fixed OSS list.
- Build/lint, meaningful browser keyboard/responsive journeys and existing SSO
  regression pass; 8080/5173 both updated with existing local features retained.

Sources (official, accessed 2026-10-02):
- https://www.keycloak.org/docs/26.8.0/server_admin/ (current docs; runtime pilot remains 26.7.4)
- https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/
- https://www.patternfly.org/components/table/html/
- https://www.patternfly.org/components/empty-state/
- https://www.w3.org/WAI/ARIA/apg/patterns/tabs/
- https://www.w3.org/WAI/ARIA/apg/patterns/dialog-modal/

Approach: inventory/render first; implement proportionate fixes to shared shell,
forms and permission views; separate verification pass. Main repository and other
worktree have divergent features. Integrate locally under .local/ui-integrated;
never overwrite another worktree or silently replace its pages with older copies.


Implemented and verified (2026-10-02):
- Shared ConsoleFrame: selected route, desktop sidebar/mobile drawer, skip link,
  full-width narrow-screen content. Retained local test-data/Keycloak/replication
  navigation through an integration snapshot; other worktree remains untouched.
- Responsive directory tree, wrapping user/group filters, named audit filters and
  explicit current-page filtering. Health refresh clears stale results on failure.
- Named loading/error states; bounded scrollable dialogs and invoking-control focus
  restoration; SSO keyboard tabs, explicit save gates and visible delete actions.
- Keycloak role/composite inheritance explanation, empty-role guidance and separate
  configured/observed/native-app-verification states. Reusable custom method editor.
- Light accent button contrast improved from 3.46:1 to 4.97:1; selected accent text
  4.65:1. Dark equivalents 8.20:1/5.76:1; danger text 5.02:1 light/5.75:1 dark.
  These are sampled theme pairs, not a full WCAG conformance certification.
  Reference: https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html

Evidence:
- Authenticated Chromium audit: 11 routes x 1440/768/390px = 33 views; zero document
  or main overflow, unnamed form inputs or page errors after changes. At 390px,
  main width improved from 166px to 390px. Local screenshots/metrics:
  `.local/audit-after-*.png`, `.local/ui-audit-before.json`, `.local/ui-audit-after.json`.
- `npm run lint && npm run build`: exit 0; existing React lint and >500kB bundle
  warnings remain. Local integrated frontend build also passed.
- `go test -race ./... && go vet ./...`: exit 0.
- `python3 scripts/test/test-app-profiles-local.py`: 3 passed (4.0s), real LDAP
  authentication and profile/method persistence after backend restart.
- `python3 scripts/test/test-app-keycloak-local.py`: Keycloak browser test 1 passed
  (1.9s), Grafana browser test 1 passed (1.9s), actual inherited JWT roles, fresh-token
  revocation and Grafana 13.1.0 Editor/unmapped-user denial checks passed.
- `npx playwright test e2e/ui-review.spec.ts` against 5173: 2 passed (2.6s);
  against rebuilt 8080: 2 passed (2.2s). No directory writes in these audit journeys.
- Rebuilt embedded local 8080 and preserved Vite 5173. LDAP login and read-only
  observation of the two existing Keycloak clients passed after restart.

Limits: no automated native provisioning beyond existing exports; no production
permission mutation; organization-wide resource inheritance policy remains a
separate design. Other worktree changes are retained locally, not merged/committed
into this branch. Independent security review T-065 completed in the follow-up, with findings fixed
and re-reviewed; see FOLLOW-UP.md. No commits or pushes performed.
