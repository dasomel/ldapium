# Issue #140: directory-change skill replay

Replay date: 2026-09-16 (Asia/Seoul)
Revision: `c1ba5b3a8c6463c7f7ce7450cf6a32d53a4f84a7`

## Scope and activation

The fresh-session prompt was an LDAPium directory/auth/E2E verification task, so
`.agents/skills/ldapium-directory-change/SKILL.md` activated. The replay read
`AGENTS.md`, the skill, the relevant README guidance, and the E2E workflows before
selecting evidence paths.

## Evidence separation

- Pure/helper evidence: `(cd ui/backend && go test ./...)` passed, including
  `TestEntryToDomainEntry_RedactsUserPassword`, case-insensitive redaction, and
  attribute-option redaction.
- Live LDAP evidence: a freshly built `ldapium:e2e` image was booted; an admin bind
  succeeded; `docker exec -i ... ldapadd` added a synthetic `uid=issue140-*` entry;
  a follow-up `ldapsearch` returned the same UID. Image ID:
  `sha256:060afd937a1cd1c98fe35e5b8003bde565664352f3f8f1f1705148f4406b`.
- Existing live/fixture paths passed: `test-migration-dryrun.sh`,
  `test-export-audit-log.sh`, and `test-detect-entry-drift.sh`.
- Application-side password protection is covered by the helper tests and the
  security/UI E2E workflows; LDAP ACLs are not treated as the HTTP redaction layer.

The first `make check` run correctly failed because the dependency bump had left
`THIRD-PARTY-LICENSES.md` stale (`lucide-react` and `react-router` versions). Running
`./scripts/licenses.sh` regenerated only that inventory; the second `make check`
run passed, with the repository's existing frontend lint warnings only.

## Required stdin edge case

With a disposable `ldapium:e2e` container running `sh -c 'sleep 5'`:

```text
printf 'sentinel\n' | docker exec <container> sh -c 'wc -c'    # 0, exit 0
printf 'sentinel\n' | docker exec -i <container> sh -c 'wc -c'  # 9, exit 0
```

The first command demonstrates the false-green stdin loss; the second is the
required form used by the workflows. The Colima bind-mount trap was not needed
for acceptance and was not reproduced.

## CI status and limits

For `c1ba5b3`, CI, CodeQL, Security, SSSD, Metrics, Backup/Restore, UI, Keycloak,
Replication Chaos, and Upgrade E2E were green. At report time, the E2E (kind) and
Build and publish images runs were still in progress. No local kind workflow was
re-run; the local live LDAP path and the repository's focused regression suites
were run directly.

The fresh-session replay was recorded by an ephemeral `codex exec` run and by this
report. No credentials, hashes, or private directory data are included.
