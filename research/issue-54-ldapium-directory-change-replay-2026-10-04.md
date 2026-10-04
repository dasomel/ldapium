# Issue 54 replay: ldapium-directory-change (2026-10-04)

Fresh-session replay of `.agents/skills/ldapium-directory-change/SKILL.md` (skillVersion `"1"`)
in a clean worktree of origin/main. Runtime: claude-sonnet-5-5 (Claude Code subagent). Started from
`AGENTS.md` / `CLAUDE.md` (`@AGENTS.md`) only.

## Plan

1. Activate from the description, read the skill, follow its workflow on one live-LDAP change/analysis (scratch-only).
2. Edge case: break the `userPassword` response denylist, show the repo's own tests fail, revert, show they pass.
3. Run `make check`, confirm `git status` shows only the two deliverables, then validate with the audit script.

## Step 1: Activation

`.agents/skills/` contains exactly one skill, `ldapium-directory-change`. Its description reads
"Implement or verify LDAPium directory/API/auth/replication changes ... Use for OpenLDAP entrypoint,
ACL/accesslog, replication, LDAP-wire, auth, backup/restore, upgrade, or LDAP-backed UI/API changes."
(`AGENTS.md` also points to it explicitly.)

Representative task chosen from the description: "Verify that the OpenLDAP entrypoint's accesslog
overlay records failed binds." Result: the description matches (entrypoint, ACL/accesslog, auth), so
the skill activates. Caveat: with a single skill in the directory there is no competing candidate, so
this is a weak discrimination test.

## Step 2: Happy path

Skill workflow followed: step 1 read `AGENTS.md` (accesslog bullets); step 3 applied "Local Docker/LDAP
verification" (image tag `ldapium:e2e`, `docker exec -i` / no file bind-mounts needed); step 6 live
evidence. Source of truth: `image/entrypoint.sh` lines ~731-751 (`olcAccessLogOps` default `reads bind`,
`olcAccessLogSuccess: FALSE`).

Commands and observations:

- `docker info` rc=0 (Colima context, Docker 29.8.1). Docker is usable.
- `docker build -q -t ldapium:e2e -f image/Dockerfile ./image` printed an image id in 0.8s (layer cache hit; build succeeded).
- First container, default env: `ldapsearch -b cn=accesslog` returned `No such object (32)`.
  Cause: `LDAP_ACCESSLOG_ENABLED` defaults to `false` (entrypoint.sh:177), so no accesslog DB existed. Not a defect.
- Second container with `-e LDAP_ACCESSLOG_ENABLED=true`: log line
  `[entrypoint] enabling accesslog overlay (reads bind, purge after 30d)`.
- A wrong-password bind: `ldapsearch -x ... -D cn=admin,dc=example,dc=org -w WRONG` exit code 49.
- Querying as the admin DN `cn=admin,dc=example,dc=org` still returned `No such object (32)`:
  the accesslog DB is readable only by `cn=admin,cn=accesslog` (matches the comment in
  `security-e2e.yml`). Skill-relevant trap: querying with the wrong identity looks like "not logged".
- Query as `-D cn=admin,cn=accesslog` with filter `(&(objectClass=auditBind)(reqResult=49))`, exit 0, output:

  ```
  dn: reqStart=20261004043845.000006Z,cn=accesslog
  reqDN: cn=admin,dc=example,dc=org
  reqResult: 49
  reqMethod: SIMPLE
  ```

  (more entries followed; one per failed attempt, including my repeated probes.)

Directory state was checked, not just the command exit: the failed bind (result 49) is present in
`cn=accesslog`, which is what `olcAccessLogSuccess: FALSE` plus `bind` in the ops list promises.
The test container `ldapium-replay54` was removed afterwards (`docker rm -f`). No source changes were made in this step.

## Step 3: Edge case (boundary: `userPassword` must never reach an HTTP response)

Hazard from `AGENTS.md` "Attribute exposure" and SKILL workflow step 4: the app-side denylist
`entryRedactedAttrs` in `ui/backend/internal/ldapclient/tree.go`.

Prerequisite: frontend built (`web/dist` is embedded by the Go module): `npm ci` in `ui/frontend`,
`npm run lint` rc=0 (warnings only), `npm run build` rc=0.

- Baseline: `go test -count=1 ./internal/ldapclient/` rc=0 (`ok ... 0.287s` on first run).
- Mutation: `sed` changed `"userpassword": true,` to `"userpassword": false,` in `tree.go`.
- `go test -count=1 ./internal/ldapclient/` rc=1 with:
  - `--- FAIL: TestEntryToDomainEntry_RedactsUserPassword` (`tree_test.go:69: Attributes contains userPassword, want it redacted`)
  - `--- FAIL: TestEntryToDomainEntry_RedactionIsCaseInsensitive` (the `USERPASSWORD` hash value appears in the attribute map)
  - `--- FAIL: TestEntryToDomainEntry_RedactsUserPasswordWithAttributeOptions` (`userPassword;binary` leaks)
  - `FAIL github.com/dasomel/ldapium/ui/backend/internal/ldapclient`
- Revert: restored `tree.go` from a byte copy; `git diff --stat` empty.
- After revert: `go test -count=1 ./internal/ldapclient/` rc=0 (`ok ... 0.134s`).

Edge case caught by the repository's own deterministic test: status pass.

## Step 4: Repository verification entrypoint

`make check` (what CI runs, per `AGENTS.md`): exit code 0. It includes ui lint/build, gofmt, `go vet`,
`go test ./...`, `go build ./...`, `helm lint`, version/module checks, shellcheck, incident-evidence and
audit-log/migration/drift fixture scripts, license check, make/CI parity and `govulncheck` ("No
vulnerabilities found. Your code is affected by 0 vulnerabilities.").

## Reverts and final tree

`git status --short` after all steps showed no changes (node_modules and `web/dist` are gitignored);
only the two deliverables of this task are added on top of that.

## NOT verified

- Only the accesslog-failed-bind behaviour was exercised live. Replication, LDAP-wire `Bind/Ping/Search`
  from the Go client, backup/restore, upgrade, keycloak federation and browser/UI E2E workflows
  (`e2e.yml`, `ui-e2e.yml`, `replication-chaos-e2e.yml`, `upgrade-e2e.yml`, ...) were not run;
  they are CI workflows needing their own images/harness.
- The `olcAccessLogSuccess: TRUE` mutation (a second possible hazard) was not tried; only
  `security-e2e.yml` (live) appears to cover it, and `make check` does not.
- `make check` has no live-LDAP step, so it supplies pure-helper/unit and static evidence only.
- Activation was tested with a single skill present, so no competing-skill selection was exercised.
