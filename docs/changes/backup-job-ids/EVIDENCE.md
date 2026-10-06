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

Date: 2026-10-06 (re-run after Codex review fixes). Environment: macOS (arm64), docker context `colima`.
Images:
- LDAP: `ldapium:lane-255b` (`sha256:bb0a7241acf889eb2fa9172188c1472b7e16286784db47d0669cb4fafbd7337e`, built from `image/Dockerfile` of this branch)
- UI: `ldapium-ui:lane-255b` (`sha256:7fbd40fcb6572bef5df9ca8ed5898ad4cdc0548d9aa3d12ad7b7e70a3ea8c870`, target `backup-runtime`)
- MinIO (S3): `alpine/minio@sha256:cf23643a6cf9ce159c57643ceb88279e431262282428c9e0bf3a7ef1a97e84b4` (script default, verified with `docker image inspect`)
- FTP: `delfer/alpine-ftp-server@sha256:60bb774d8408d9d4d5c74d05d1c086a34ce192c6c1a142ffac268cac0dbc6fac` (script default, verified with `docker image inspect`)
- SFTP: `atmoz/sftp@sha256:6d41b9200f8115ce925bbd295376cb3c6b72634a267f41946e5aee4efe482186` (script default, verified with `docker image inspect`)

Command: `LDAPIUM_IMAGE=ldapium:lane-255b LDAPIUM_UI_IMAGE=ldapium-ui:lane-255b LDAPIUM_TEST_PREFIX=lane255b- python3 scripts/test/test-backup-jobs-remotes-live.py` -> exit 0, `ALL LIVE CHECKS PASSED` (48 PASS lines). Remote artifact checks assert the exit status of `test -s` and a non-zero size; the script first proves them non-vacuous (negative self-test: the same check fails for a missing path on each remote and for a missing container). Remote passwords travel via 0600 env/volume files and stdin, never argv; failure text is masked. MinIO stores each object as a directory, so the S3 check asserts `complete.json/xl.meta`.

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
   - Before the script removes it, the leftover `.pending-*` directory is asserted to exist and the job to report `staging_cleanup=pending`; after removal the read-time computation reports `done` (a view computation, not worker cleanup).
3. **Deadline path (`BACKUP_JOB_TIMEOUT_LOGS=1m`)**:
   - The worker is a wrapper stand-in that creates `logs/.pending-deadline-test` and removes it in its own SIGTERM handler; the script asserts the directory exists while running and is gone after. This proves the controller's deadline/SIGTERM/`done` bookkeeping, not the real worker's cleanup.
   - Job started with `BACKUP_JOB_TIMEOUT_LOGS=1m`; record carries `deadline_at` = `started_at + 1m`.
   - Worker ran past 60s; context deadline expired at 60.3s; SIGTERM sent to process group.
   - Job settled `status=failed`, `error.code=deadline_exceeded`, `error.message="backup job deadline exceeded"`, `staging_cleanup=done`.
   - Worker process confirmed terminated; `GET /api/v1/backups` reflects `states.logs.status="failed"`.
   - Follow-up job started and succeeded normally.

## Not verified

Accepted as unit-only (no live proof): remote failure injection (per-destination failure outcomes against a real remote); the real `backup_worker.py` cleaning its staging directory on a deadline SIGTERM (the live deadline run uses a stand-in worker); remote destinations beyond the success path. Idempotency-Key (#216 part B) was verified live in `test-api-idempotency-local.py` (#241).

Round-2 re-run (UI/LDAP/remote containers now removed with `docker rm -fv`, because the UI image declares `VOLUME /var/lib/ldapium/secrets`): same command with `LDAPIUM_TEST_PREFIX=lane255d-` -> exit 0, `ALL LIVE CHECKS PASSED`, `grep -c '^PASS:'` = 48, 0 FAIL. `docker volume ls -q` before/after diff empty; no `lane255*` containers left.
