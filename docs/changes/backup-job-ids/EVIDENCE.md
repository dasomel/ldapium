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

## Not verified

Remote (S3/FTP/SFTP) destinations live; the SIGKILL-after-grace path live (unit test only);
deadline live (unit test only); Idempotency-Key (#216 part B, not implemented).
