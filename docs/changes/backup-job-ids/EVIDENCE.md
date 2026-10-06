# Evidence: backup job IDs (#217)

Environment: macOS, docker context `colima`, Go 1.27.1, Python 3, Playwright 1.63 (chromium). Image
`ldapium:e2e` (LDAP) and `ldapium-ui` built from this branch as `backup-runtime` (`l4-ui:backup`).
Docker objects were prefixed `l4-` and removed afterwards.

## Unit / static

- `gofmt -l .` empty; `go vet ./...` clean; `go test ./... -race -count=1` ok for every package;
  `go test ./internal/backup -race -count=20` ok (88s).
- `python3 scripts/test/test_backup_worker.py`: 12 tests OK (the 5 existing + job id, result file,
  per-destination failure classes, SIGTERM cleanup, lock contention exit 75, `--job-id` validation).
- `cd ui/frontend && npm run build` ok; `npm run lint` reports only pre-existing warnings.
- `helm lint charts/ldapium` ok; `scripts/verify-chart-schema.sh` ok; rendered chart carries
  `BACKUP_JOB_TIMEOUT_DATA/LOGS`.

## Non-vacuity (each change made, test run, change reverted)

| Change | Result |
|---|---|
| deadline ignored (`WithDeadline` -> `WithCancel`) | `TestJobDeadlineKillsTheProcessGroup` fails: job still running |
| cancel sends SIGKILL first instead of SIGTERM | `TestCancelTerminatesGracefullyAndRunsWorkerCleanup` and `...EscalatesToSIGKILL...` fail |
| startup ignores the worker lock (orphan -> abandoned) | live script fails at "after restart the job is running + orphan_suspected" |

## Live (`scripts/test/test-backup-jobs-live.py`, real LDAP + UI image + real worker)

All 23 checks PASS, including: 202 + `Location`; artifact files equal on-disk `complete.json`
(which carries `job_id`); `.results/<job_id>.json` mode 600; 409 `backup_busy` with
`active_job_id`; cancel -> `cancelled`, `staging_cleanup=done`, no worker process, no `.pending-*`;
backend-only SIGKILL -> worker survives, job `running`+`orphan_suspected`, start is 409 naming the
orphan, cancel is 409 `job_not_cancellable`, then settled `succeeded` from the result file
(`result_source=file`), new start accepted; backup log lines carry no DN.

`scripts/test/test-backup-ui-local.py` (Playwright `backups.spec.ts` + `backup-jobs.spec.ts`
against the same image): 4 passed.

## Live remotes and termination paths (`scripts/test/test-backup-jobs-remotes-live.py`, #255)

Date: 2026-10-06. Environment: macOS (arm64), docker context `colima`.
Images:
- LDAP: `ldapium:lane-255`
- UI: `ldapium-ui:lane-255` (built with target `backup-runtime`)
- MinIO (S3): `alpine/minio:latest-release` (digest `sha256:cf23643a6cf9ce159c57643ceb88279e431262282428c9e0bf3a7ef1a97e84b4`)
- FTP: `delfer/alpine-ftp-server:latest` (digest `sha256:60bb774d8408d9d4d5c74d05d1c086a34ce192c6c1a142ffac268cac0dbc6fac`)
- SFTP: `atmoz/sftp:alpine` (digest `sha256:6d41b9200f8115ce925bbd295376cb3c6b72634a267f41946e5aee4efe482186`)

Command: `python3 scripts/test/test-backup-jobs-remotes-live.py`

Observed results:
1. **Remote destinations (S3, FTP, SFTP)**:
   - S3 (MinIO): job `POST /api/v1/backups/jobs/logs` returned 202; job settled `status=succeeded`, `local.verified=true`, destination `s3-dest` status `succeeded`; result file `.results/<job_id>.json` landed with mode 0600; MinIO object storage verified with `complete.json`.
   - FTP: job returned 202; settled `status=succeeded`, `local.verified=true`, destination `ftp-dest` status `succeeded`; result file landed mode 0600; FTP server storage verified with `complete.json`.
   - SFTP: job returned 202; settled `status=succeeded`, `local.verified=true`, destination `sftp-dest` status `succeeded`; result file landed mode 0600; SFTP server storage verified with `complete.json`.
   - Combined: job specifying all 4 destinations (`local`, `s3-dest`, `ftp-dest`, `sftp-dest`) succeeded across all 4 destinations simultaneously.
2. **SIGKILL-after-grace path**:
   - Job started with worker configured to ignore `SIGTERM`.
   - `POST .../jobs/{id}/cancel` issued; 202 accepted with `cancel_requested_at`.
   - Controller waited out the 10-second grace period (`defaultKillGrace = 10s`, elapsed 10.1s) before sending `SIGKILL`.
   - Job settled `status=cancelled`, `staging_cleanup=pending` (honestly reflects that SIGKILL prevented worker `finally` cleanup).
   - Worker process confirmed terminated by SIGKILL.
   - Leftover staging directory removed; subsequent query dynamically computed and reported `staging_cleanup=done`.
3. **Deadline path (`BACKUP_JOB_TIMEOUT_LOGS=1m`)**:
   - Job started with `BACKUP_JOB_TIMEOUT_LOGS=1m`; record carries `deadline_at` = `started_at + 1m`.
   - Worker ran past 60s; context deadline expired at 60.3s; SIGTERM sent to process group.
   - Job settled `status=failed`, `error.code=deadline_exceeded`, `error.message="backup job deadline exceeded"`, `staging_cleanup=done`.
   - Worker process confirmed terminated; `GET /api/v1/backups` reflects `states.logs.status="failed"`.
   - Follow-up job started and succeeded normally.

## Not verified

All scopes of #217 / #255 are verified live. Idempotency-Key (#216 part B) was verified live in `test-api-idempotency-local.py` (#241).
