# Scheduled multi-target backups with separate data/log policies

Class D. User authorized implementation 2026-10-02. Scope accepted from request:
local/disposable implementation and verification; no shared production storage changes.
Goal: independent data/log enabled state, interval scheduling, keep-days/keep-count,
manual execution and verified local + S3/FTP/FTPS/SSH-SFTP delivery through registered
operator destinations. UI/API cannot upload scripts, choose source paths or read saved secrets.
The 2026-10-03 extension accepts write-only managed credentials.

D29: opt-in single-process controller + fixed Python worker and rclone transports.
Cost: separate backup-capable runtime includes tools; existing distroless default stays.
Escape hatch: disable feature, retain archives and existing Helm CronJob unchanged.
D30: local verified archive retained even if remote transfer fails; prune each destination
only after its new verified copy completes, preventing unbounded local accumulation.
Source LDAP online exports are logical backups, not a cross-database transactional
snapshot. Existing offline restore and manifest contract preserved for data+config.
D31: data/config and allowlisted log-file snapshots in separate namespaces. Policies
control backup copies only, never rotate/delete live logs. Remote/local retention uses only owned complete run manifests in separate instance
and kind namespaces. Remote deletion occurs only after that destination completes. FTP plaintext requires operator opt-in; SFTP host verification required.

Acceptance: admin/same-origin/revision gates; policy persistence and restart scheduling;
manual job state reflects failure; no concurrent jobs; local SHA256 verification;
S3/FTP/SFTP bytes roundtrip evidence; failed transport retains local backup; log and data
retention independent; real LDAP restore test; UI rendered, no secret exposure.
Changes: new backup package/worker, HTTP handlers, opt-in env, UI page/navigation,
backup-capable Docker target, docs/test evidence. Existing LDAP auth/CRUD and original
CronJob remain unchanged. Broad shared deployment requires operator configuration.

## Implementation and observed verification (2026-10-02)

Implemented the acceptance scope, including revision-checked UI policies and
separate partial local verification state. Interval scheduling is completion-relative,
not wall-clock cron. Operator configuration owns credentials and destination registration.

- `go test -race ./...` and `go vet ./...`: passed backend suite.
- Frontend and integrated local frontend `npm run build`: passed; existing bundle-size warning.
- Playwright backups on 5173 and 8080: passed real login, policy persistence,
  manual log job and narrow viewport. See EVIDENCE.md for final rerun.
- `python3 scripts/test/test_backup_worker.py`: four tests passed.
- `python3 scripts/test/test-backup-transports-local.py --container`: real loopback
  S3/FTP/SFTP checksum roundtrips and retention passed using host and shipped
  non-root runtime clients; SSH host-key mismatch denied and failed transfer
  retained verified local data. FTPS TLS config implemented; no live FTPS fixture.
- Actual one-minute scheduler: observed successful log job and independent data policy.
- Actual UI data/config export then offline Docker restore: 937/937 entries and
  original base entryUUID preserved. Regression found six Base64 DN records
  dropped by legacy sanitizer; D35 preserves encoded records.
- Restore boundary fixture: encoded MDB path, symlink target and unrelated
  manifest rejected before target clearing.
- Helm lint/render passed; multiwriter, missing Secret, unconfirmed runtime and
  blank backup admin configurations rejected.

D32: remote pending markers and checksum verification distinguish incomplete
uploads from complete copies; transient reads cannot authorize deletion.
D33: restore selects the data suffix instead of numeric MDB order.
D34: verified private compressed-file snapshot closes verification/import race.
D35: preserve Base64 DN records so non-ASCII directory names survive restoration.

Remaining limits: logical exports are not transactional across data/config/metadata;
external production accounts were not configured; encryption/quota are storage-owner
responsibilities; one writer/replica required; backup-copy retention does not rotate
live logs. Existing CronJob and offline recovery remain operator controlled.

## UI destination management and capacity extension — 2026-10-03

User requested visible capacity and remote configuration. Acceptance: display local
completed-copy bytes/count and newest-copy bytes per data/log policy; administrator
can add/edit/remove managed S3/FTP/FTPS/SFTP connections, then select them for a
policy; credentials are write-only API inputs and never returned/logged. Blank
credential edits retain saved values only while the destination (host/port/user/known hosts/plaintext flag; S3 endpoint/region/bucket/access key) is unchanged; otherwise the save is rejected (422) so a stored secret cannot be redirected. Single revision, atomic private persistence,
busy-job protection, explicit FTP plaintext acknowledgement and pinned SSH host keys
remain enforced. Existing operator destinations are read-only and remain usable.
Sources/LDAP identities/raw paths and restore behavior are outside this extension.
Verification: Go race/API/helper tests, actual managed transport fixtures, UI save/edit,
credential redaction and narrow viewport, rebuild/redeploy both local ports.
D37: server stores managed credentials with policies in a private 0600 volume file;
worker receives them via pipe and creates a private transient rclone configuration.
Cost: volume requires operator encryption/access control; escape hatch: keep using
operator-mounted destination configuration and remove unselected managed entries.

Extension acceptance verified; results and failed-test/fix evidence in EVIDENCE.md.
D38: generated remote names never override operator rclone sections; only selected
managed connections are materialized. Cost: ephemeral names; stable remote namespace
remains prefix/instance/kind/run. Existing connections retain destinations unchanged.
