# Backup verification evidence — 2026-10-02

Local/disposable evidence; no production destination was configured.

| Command / environment | Observed result |
| --- | --- |
| `go test -race ./...` and `go vet ./...` in `ui/backend` | All packages passed; vet exit 0 |
| `go test -race ./internal/backup` after partial-success state change | `ok .../internal/backup 1.735s` |
| `npm run build` root frontend | 2003 modules, successful build; bundle warning |
| `npm run build` integrated frontend | 2013 modules, successful build; bundle warning |
| Playwright `e2e/backups.spec.ts`, real LDAP admin, 8080 | 1 passed (7.5s) |
| Same test, 5173 | 1 passed (6.7s) |
| `python3 scripts/test/test_backup_worker.py` | Ran 4 tests, OK |
| `python3 scripts/test/test-backup-transports-local.py --container` | Non-root shipped runtime and host clients: S3/FTP/SFTP bytes/checksums, independent namespaces, retention, transfer failure and host-key rejection passed |
| `python3 scripts/test/test-backup-restore-local.py --operator ...` | 937/937 entries restored, bound LDAP query succeeded, base entryUUID preserved |
| `python3 scripts/test/test-restore-boundaries-local.py` | Encoded MDB path, symlink target, unrelated manifest rejected before target clearing |
| `docker build --target backup-runtime -t ldapium-ui:backup-e2e -f ui/Dockerfile ui` | Successful image build |
| `helm lint charts/ldapium` | 1 chart linted, 0 failed |
| Helm configured render + invalid-config checks | Valid backup mounts/env rendered; replica>1, missing Secret, unconfirmed runtime, blank admin rejected |
| Actual 1-minute scheduler on rebuilt 8080 | Scheduled log job succeeded; next run after completion; original disabled policies restored |
| Final targeted independent static review | PASS |
| `git diff --check` | Exit 0 |

Failures preserved as findings: legacy numeric MDB restore selection broke after
monitor/accesslog; restore now selects suffix and prepares every validated MDB
path. A parent Docker volume was shadowed by the image's nested VOLUME; disposable
fixture now mounts the actual data path. Full-count verification then exposed
six Base64 DN records dropped by the legacy sanitizer; D35 preserved them and
937/937 passed. Independent static reviews found deletion ownership, transient
remote-read ambiguity, encoded paths and verified-source/import mismatches;
fixes were retested. Review passes are static evidence, not live proof.

Local runtime additionally contains earlier session features through the existing
`.local` integration helper; root sources contain the durable backup implementation.
Private fixtures/configuration/credentials remain local, outside these records.
Host verification installed rclone 1.75.1. Homebrew cleanup removed an older
OpenJDK 25 installation; OpenJDK 25 was restored (25.0.4.1). Shipped runtime's
rclone client was separately exercised, so host version is not sole evidence.

Limits: no live FTPS fixture, no production remote account test, logical online
exports are not cross-database transactional, and UI metadata restore is manual.

## Capacity and UI-managed connection extension — 2026-10-03

- `go test -race ./...` and `go vet ./...`: passed after initial extension;
  targeted backup/httpapi suites rerun after safety/API tests, passed (1.658s/1.380s).
- Public GET/save replies omit passwords/access keys/secret keys; real browser
  and API boundary tests prove the projection. Blank edits retain credentials,
  restart persistence works, selected connection deletion is rejected, private
  file mode is 0600. Unknown fields/revision/admin/same-origin gates remain enforced.
- `python3 scripts/test/test_backup_worker.py`: 5 passed including operator remote
  collision and dotted S3 bucket regressions. Capacity helper counts owned completed
  files only and ignores symlinks/foreign manifests.
- Real S3/FTP/SFTP fixtures passed with UI-managed worker credentials and known_hosts,
  both host and rebuilt non-root Docker runtime clients. Test connections removed
  afterward; production destinations unchanged.
- Frontend + integrated builds and lint passed (existing warnings). Docker backup
  runtime rebuilt. No LDAP/export/restore behavior changes in this extension.
- Playwright: 8080 2 passed (8.5s); 5173 2 passed (8.7s). Includes local capacity,
  each remote transport form, save/blank-credential edit/reload/delete, response
  redaction, policy/manual job regression and 390px viewport without overflow.
- Initial browser test failed because select label included option text; explicit
  accessible names fixed Transport/SSH keys controls, same test passed.
- Independent static review found remote-name collision and dotted bucket rejection;
  fixes and targeted rereview PASS are in REVIEW.md.

Managed credentials are private-file plaintext, not app-encrypted. UI save is not
connectivity verification. No production remote was configured, and live FTPS fixture
remains outside observed evidence. Local capacity does not imply remote storage use.
