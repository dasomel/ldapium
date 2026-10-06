package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	jobA = "job-20261006T150000Z-111111111111"
	jobB = "job-20261006T150100Z-222222222222"
	runA = "20261006T150000Z-0123456789ab"
	runB = "20261006T150100Z-ba9876543210"
)

// env is a throwaway controller directory. Managers are built with newManager
// so the lock probe, clock and worker launcher are in place before startup
// reconciliation runs, and a "restart" is simply another manager on the same env.
type env struct {
	dir, root, operator, policy, jobs string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	e := &env{dir: dir, root: filepath.Join(dir, "backup-root"), operator: filepath.Join(dir, "operator.json"), policy: filepath.Join(dir, "policy.json"), jobs: filepath.Join(dir, "backup-jobs.json")}
	op := fmt.Sprintf(`{"root":%q,"instance_id":"inst-1","destinations":[{"id":"local","name":"Local","type":"local"}],"log_paths":["/registered/log"]}`, e.root)
	if err := os.WriteFile(e.operator, []byte(op), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(e.root, 0700); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) manager(t *testing.T, configure func(*Manager)) *Manager {
	t.Helper()
	m, err := newManager(e.policy, e.operator, "/fixed/worker.py", "/fixed/python3", configure)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func (e *env) seed(t *testing.T, jobs ...*Job) {
	t.Helper()
	if err := write(e.jobs, jobFile{Version: 1, Jobs: jobs}); err != nil {
		t.Fatal(err)
	}
}

// seedPolicy stores a policy file with the data schedule enabled.
func (e *env) seedPolicy(t *testing.T, nextRun time.Time) {
	t.Helper()
	p := defaultPolicies()
	p.Data.Enabled = true
	if err := write(e.policy, disk{Policies: p, States: map[string]State{"data": {NextRun: nextRun}}}); err != nil {
		t.Fatal(err)
	}
}

func (e *env) writeResult(t *testing.T, jobID, body string) {
	t.Helper()
	dir := filepath.Join(e.root, ".results")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, jobID+".json"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}

// writeRun creates <root>/<kind>/<dirName>/ with the files and a complete.json
// holding manifest (not validated: tests craft hostile manifests on purpose).
func (e *env) writeRun(t *testing.T, kind, dirName string, manifest map[string]any, files map[string]string) string {
	t.Helper()
	dir := filepath.Join(e.root, kind, dirName)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(dir, "complete.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func sum(body string) string {
	s := sha256.Sum256([]byte(body))
	return hex.EncodeToString(s[:])
}

func goodManifest(runID, jobID string, sums map[string]string) map[string]any {
	return map[string]any{"owner": "ldapium-backup-v1", "kind": "data", "run_id": runID, "job_id": jobID, "instance_id": "inst-1", "sha256": sums}
}

func okResult(jobID, runID string) string {
	return fmt.Sprintf(`{"run_id":%q,"kind":"data","verified":true,"local_verified":true,"job_id":%q,"destinations":[{"id":"local","status":"succeeded"}]}`, runID, jobID)
}

func runningJob(id, kind string, created time.Time) *Job {
	return &Job{JobID: id, Kind: kind, Trigger: JobTriggerManual, Status: JobStatusRunning, RequestedBy: JobRequester{Type: JobRequesterUser}, CreatedAt: created, StartedAt: created}
}

func (e *env) readJobs(t *testing.T) []*Job {
	t.Helper()
	jobs, err := loadJobFile(e.jobs)
	if err != nil {
		t.Fatal(err)
	}
	return jobs
}

func (e *env) readDisk(t *testing.T) disk {
	t.Helper()
	b, err := os.ReadFile(e.policy)
	if err != nil {
		t.Fatal(err)
	}
	var d disk
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// fakeWorker is the launcher seam: it counts launches without any process.
type fakeWorker struct {
	calls atomic.Int32
	run   func(ctx context.Context, kind string) ([]byte, error)
}

func (f *fakeWorker) fn(ctx context.Context, kind string, _ []byte) ([]byte, error) {
	f.calls.Add(1)
	if f.run == nil {
		return []byte(fmt.Sprintf(`{"run_id":%q,"verified":true,"local_verified":true}`, runA)), nil
	}
	return f.run(ctx, kind)
}

func free(m *Manager) { m.lockProbe = func() (bool, error) { return false, nil } }

func failJobWrites(path string, failing func() bool, msg string) func(string, any) error {
	return func(p string, data any) error {
		if p == path && failing() {
			return errors.New(msg)
		}
		return write(p, data)
	}
}

func TestOrphanLifecycleAcrossHeldToFreeTransition(t *testing.T) {
	e := newEnv(t)
	now := time.Date(2026, 10, 6, 15, 10, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	e.seedPolicy(t, past)
	e.seed(t, runningJob(jobA, "data", now.Add(-10*time.Minute)))
	e.writeResult(t, jobA, okResult(jobA, runA))

	var held atomic.Bool
	held.Store(true)
	fw := &fakeWorker{}
	var delays []time.Duration
	// ONE manager for the whole held -> free transition; the clock, lock probe
	// and wait are injected, so nothing sleeps.
	m := e.manager(t, func(m *Manager) {
		m.lockProbe = func() (bool, error) { return held.Load(), nil }
		m.clock = func() time.Time { return now }
		m.runWorker = fw.fn
		m.after = func(d time.Duration) <-chan time.Time {
			delays = append(delays, d)
			if len(delays) == 5 {
				held.Store(false) // the orphan worker exits while we wait
			}
			c := make(chan time.Time, 1)
			c <- now
			return c
		}
	})

	// Held: still running, orphan_suspected, everything that starts work is blocked.
	job, err := m.GetJob(jobA)
	if err != nil || job.Status != JobStatusRunning || !job.OrphanSuspected || job.OrphanReason != OrphanReasonLockHeld {
		t.Fatalf("held orphan must stay running+orphan_suspected: %+v err=%v", job, err)
	}
	if !m.View().Running {
		t.Fatal("running must be true while the orphan holds the lock")
	}
	if err := m.Run(context.Background(), "data"); err != ErrBusy {
		t.Fatalf("Run while orphaned = %v; want ErrBusy", err)
	}
	var busy *BusyError
	if _, err := m.StartJob(context.Background(), RunRequest{Kind: "data"}); !errors.As(err, &busy) || busy.ActiveJobID != jobA {
		t.Fatalf("StartJob must report the orphan as the active job: %v", err)
	}
	if _, err := m.Save(m.View().Policies, 0); !errors.Is(err, ErrBusy) {
		t.Fatalf("policy save while orphaned = %v; want ErrBusy", err)
	}
	m.tick(context.Background(), now)
	if fw.calls.Load() != 0 || !m.View().States["data"].NextRun.Equal(past) {
		t.Fatalf("catch-up must be deferred: launches=%d next_run=%v", fw.calls.Load(), m.View().States["data"].NextRun)
	}
	if got := e.readJobs(t); len(got) != 1 || got[0].Status != JobStatusRunning || !got[0].OrphanSuspected {
		t.Fatalf("orphan state must be on disk: %+v", got)
	}

	// Poll with backoff until the lock is free, then settle from the result file.
	m.orphanLoop(context.Background())
	want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 30 * time.Second, 30 * time.Second}
	if fmt.Sprint(delays) != fmt.Sprint(want) {
		t.Fatalf("backoff = %v; want %v", delays, want)
	}
	job, _ = m.GetJob(jobA)
	if job.Status != JobStatusSucceeded || job.OrphanSuspected || job.OrphanReason != "" || job.Artifact == nil || job.Artifact.RunID != runA {
		t.Fatalf("not settled from the result file: %+v", job)
	}
	if id, kind, running := m.ActiveJobInfo(); running || id != "" || kind != "" || m.View().Running {
		t.Fatalf("running/active job must be cleared: %q %q %v", id, kind, running)
	}
	st := m.View().States["data"]
	if st.Status != "succeeded" || st.RunID != runA || !st.NextRun.Equal(now) {
		t.Fatalf("state after settle (catch-up due now): %+v", st)
	}
	if got := e.readJobs(t); got[0].Status != JobStatusSucceeded || e.readDisk(t).States["data"].Status != "succeeded" {
		t.Fatalf("settlement must be persisted: %+v", got)
	}

	// Free: policy saves work again and the deferred catch-up is released.
	if _, err := m.Save(m.View().Policies, 0); err != nil {
		t.Fatalf("policy save after orphan exit: %v", err)
	}
	m.tick(context.Background(), now)
	waitIdle(t, m)
	if fw.calls.Load() != 1 {
		t.Fatalf("catch-up launches = %d; want 1", fw.calls.Load())
	}
}

func TestOrphanLoopStopsOnShutdown(t *testing.T) {
	e := newEnv(t)
	e.seed(t, runningJob(jobA, "data", time.Now().UTC()))
	m := e.manager(t, func(m *Manager) {
		m.lockProbe = func() (bool, error) { return true, nil }
		m.after = func(time.Duration) <-chan time.Time { return nil } // never fires
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.orphanLoop(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(workerWait):
		t.Fatal("orphan loop did not stop when the process context ended")
	}
	if job, _ := m.GetJob(jobA); job.Status != JobStatusRunning {
		t.Fatalf("shutdown must not settle the orphan: %+v", job)
	}
}

func TestNextOrphanDelay(t *testing.T) {
	var d time.Duration
	var got []time.Duration
	for i := 0; i < 7; i++ {
		d = nextOrphanDelay(d)
		got = append(got, d)
	}
	want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 30 * time.Second, 30 * time.Second, 30 * time.Second, 30 * time.Second}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("backoff = %v; want %v", got, want)
	}
}

func TestLockProbeErrorNeverAbandonsALiveWorker(t *testing.T) {
	e := newEnv(t)
	now := time.Date(2026, 10, 6, 15, 10, 0, 0, time.UTC)
	e.seed(t, runningJob(jobA, "data", now.Add(-time.Minute)))
	var probeFails atomic.Bool
	probeFails.Store(true)
	m := e.manager(t, func(m *Manager) {
		m.lockProbe = func() (bool, error) {
			if probeFails.Load() {
				return false, errors.New("EIO")
			}
			return false, nil
		}
	})

	job, _ := m.GetJob(jobA)
	if job.Status != JobStatusRunning || !job.OrphanSuspected || job.OrphanReason != OrphanReasonProbeError {
		t.Fatalf("a probe error must keep the job running as orphan_suspected/lock_probe_error: %+v", job)
	}
	if !m.View().Running || m.Run(context.Background(), "data") != ErrBusy {
		t.Fatal("a probe error must block new runs")
	}
	if delay, again := m.orphanStep(now); !again || delay == 0 {
		t.Fatalf("a probe error must keep polling with backoff: %v %v", delay, again)
	}
	if job, _ = m.GetJob(jobA); job.Status != JobStatusRunning {
		t.Fatalf("still-failing probe must not settle: %+v", job)
	}
	probeFails.Store(false)
	if _, again := m.orphanStep(now); again {
		t.Fatal("a readable free lock with no evidence must settle")
	}
	if job, _ = m.GetJob(jobA); job.Status != JobStatusAbandoned || job.Error.Code != ErrCodeAbandoned {
		t.Fatalf("free lock and no evidence = abandoned: %+v", job)
	}
}

func TestStartJobReturnsTheJobItCreated(t *testing.T) {
	e := newEnv(t)
	fw := &fakeWorker{} // finishes immediately: the old re-lookup returned (nil, nil)
	m := e.manager(t, func(m *Manager) { free(m); m.runWorker = fw.fn })
	for i := 0; i < 20; i++ {
		job, err := m.StartJob(context.Background(), RunRequest{Kind: "data", ActorFingerprint: "0123456789abcdef", RequestID: "req-1"})
		if err != nil || job == nil {
			t.Fatalf("StartJob #%d = %v, %v", i, job, err)
		}
		if job.Status != JobStatusRunning || job.Kind != "data" || job.Trigger != JobTriggerManual || job.RequestedBy.Fingerprint != "0123456789abcdef" || job.RequestID != "req-1" {
			t.Fatalf("returned record is not the created one: %+v", job)
		}
		waitIdle(t, m)
		if got, _ := m.GetJob(job.JobID); got == nil || got.Status != JobStatusSucceeded {
			t.Fatalf("job %s did not complete: %+v", job.JobID, got)
		}
	}
	if _, err := m.StartJob(context.Background(), RunRequest{Kind: "bogus"}); err == nil {
		t.Fatal("invalid kind must fail")
	}
}

func TestConcurrentStartJobBusyCarriesTheWinner(t *testing.T) {
	e := newEnv(t)
	release := make(chan struct{})
	fw := &fakeWorker{run: func(ctx context.Context, _ string) ([]byte, error) {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return []byte(fmt.Sprintf(`{"run_id":%q,"verified":true,"local_verified":true}`, runA)), nil
	}}
	m := e.manager(t, func(m *Manager) { free(m); m.runWorker = fw.fn })

	const n = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	var winners []*Job
	var busyIDs []string
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			job, err := m.StartJob(context.Background(), RunRequest{Kind: "data"})
			mu.Lock()
			defer mu.Unlock()
			var busy *BusyError
			switch {
			case err == nil:
				winners = append(winners, job)
			case errors.As(err, &busy) && errors.Is(err, ErrBusy):
				busyIDs = append(busyIDs, busy.ActiveJobID)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	close(release)
	waitIdle(t, m)
	if len(winners) != 1 || len(busyIDs) != n-1 {
		t.Fatalf("winners=%d busy=%d", len(winners), len(busyIDs))
	}
	for _, id := range busyIDs {
		if id != winners[0].JobID {
			t.Fatalf("busy error names %q; the active job is %q", id, winners[0].JobID)
		}
	}
	if fw.calls.Load() != 1 {
		t.Fatalf("launches = %d; want 1", fw.calls.Load())
	}
}

func TestStartWriteFailureNeverLaunchesTheWorker(t *testing.T) {
	e := newEnv(t)
	var failing atomic.Bool
	failing.Store(true)
	fw := &fakeWorker{}
	m := e.manager(t, func(m *Manager) {
		free(m)
		m.runWorker = fw.fn
		m.writer = failJobWrites(e.jobs, failing.Load, "disk full")
	})

	_, err := m.StartJob(context.Background(), RunRequest{Kind: "data"})
	var pe *PersistenceUnavailableError
	if !errors.As(err, &pe) || !errors.Is(err, ErrPersistenceUnavailable) {
		t.Fatalf("err = %v; want PersistenceUnavailableError", err)
	}
	if m.View().Running || len(m.Jobs("", "", 10)) != 0 || m.View().States["data"].Status == "running" {
		t.Fatalf("memory changed despite the failed start write: %+v", m.View())
	}
	if _, statErr := os.Stat(e.jobs); !os.IsNotExist(statErr) {
		t.Fatal("a job file must not exist after a failed start write")
	}

	// A worker that was (wrongly) launched asynchronously would still be counted
	// once the next, healthy job has run to completion.
	failing.Store(false)
	if _, err := m.StartJob(context.Background(), RunRequest{Kind: "data"}); err != nil {
		t.Fatal(err)
	}
	waitIdle(t, m)
	if fw.calls.Load() != 1 {
		t.Fatalf("worker launches = %d; want exactly 1 (the healthy start)", fw.calls.Load())
	}
}

func TestCancelWriteFailureSendsNoSignal(t *testing.T) {
	e := newEnv(t)
	var failing atomic.Bool
	started := make(chan context.Context, 1)
	fw := &fakeWorker{run: func(ctx context.Context, _ string) ([]byte, error) {
		started <- ctx
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	m := e.manager(t, func(m *Manager) {
		free(m)
		m.runWorker = fw.fn
		m.writer = failJobWrites(e.jobs, failing.Load, "disk failure")
	})
	job, err := m.StartJob(context.Background(), RunRequest{Kind: "data"})
	if err != nil {
		t.Fatal(err)
	}
	workerCtx := <-started

	failing.Store(true)
	if _, err := m.CancelJob(job.JobID); !errors.Is(err, ErrPersistenceUnavailable) {
		t.Fatalf("err = %v; want ErrPersistenceUnavailable", err)
	}
	if workerCtx.Err() != nil || !m.View().Running {
		t.Fatal("a cancel signal was sent although the request could not be recorded")
	}
	if got, _ := m.GetJob(job.JobID); !got.CancelRequestedAt.IsZero() {
		t.Fatal("cancel_requested_at must be reverted")
	}

	failing.Store(false)
	if _, err := m.CancelJob(job.JobID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-workerCtx.Done():
	case <-time.After(workerWait):
		t.Fatal("recorded cancel never signalled the worker")
	}
	waitIdle(t, m)
	if got, _ := m.GetJob(job.JobID); got.Status != JobStatusCancelled {
		t.Fatalf("status = %q; want cancelled", got.Status)
	}
	if st := m.View().States["data"].Status; st != "cancelled" {
		t.Fatalf("state = %q; want cancelled", st)
	}
}

func TestCompletionWriteFailureMarksDirtyAndTickRetries(t *testing.T) {
	e := newEnv(t)
	var failing atomic.Bool
	m := e.manager(t, func(m *Manager) {
		free(m)
		m.runWorker = (&fakeWorker{}).fn
		m.writer = failJobWrites(e.jobs, failing.Load, "fail completion persist")
	})
	if _, err := m.StartJob(context.Background(), RunRequest{Kind: "data"}); err != nil {
		t.Fatal(err)
	}
	failing.Store(true)
	waitIdle(t, m)

	jobs := m.Jobs("data", "", 10)
	if len(jobs) != 1 || jobs[0].Status != JobStatusSucceeded {
		t.Fatalf("job in memory should be succeeded: %+v", jobs)
	}
	m.mu.Lock()
	dirty := m.jobDirty
	m.mu.Unlock()
	if !dirty {
		t.Fatal("expected jobDirty after the completion write failed")
	}
	failing.Store(false)
	m.tick(context.Background(), time.Now().UTC())
	m.mu.Lock()
	dirty = m.jobDirty
	m.mu.Unlock()
	if dirty {
		t.Fatal("tick must flush the dirty job file")
	}
	if got := e.readJobs(t); len(got) != 1 || got[0].Status != JobStatusSucceeded {
		t.Fatalf("flushed file = %+v", got)
	}
}

func TestStateRestoredFromJobFileAfterStateWriteFailure(t *testing.T) {
	for _, tc := range []struct {
		name       string
		run        func(ctx context.Context, kind string) ([]byte, error)
		wantStatus string
		wantOK     bool
	}{
		{"succeeded", nil, "succeeded", true},
		{"failed", func(context.Context, string) ([]byte, error) { return nil, errors.New("exit 1") }, "failed", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.seedPolicy(t, time.Time{})
			// First process: the job write succeeds, the State write fails (D217-17
			// step 2) or the process dies between them.
			m1 := e.manager(t, func(m *Manager) {
				free(m)
				m.runWorker = (&fakeWorker{run: tc.run}).fn
				m.writer = failJobWrites(e.policy, func() bool { return true }, "disk full")
			})
			if _, err := m1.StartJob(context.Background(), RunRequest{Kind: "data"}); err != nil {
				t.Fatal(err)
			}
			waitIdle(t, m1)
			if st := e.readDisk(t).States["data"]; st.Status != "" {
				t.Fatalf("precondition: State must be stale on disk, got %+v", st)
			}
			jobs := e.readJobs(t)
			if len(jobs) != 1 || jobs[0].Status != tc.wantStatus {
				t.Fatalf("precondition: job file = %+v", jobs)
			}
			j := jobs[0]

			// Restart: State is re-derived from the job file.
			m2 := e.manager(t, free)
			st := m2.View().States["data"]
			if st.Status != tc.wantStatus || !st.LastAttempt.Equal(j.StartedAt) {
				t.Fatalf("State not restored: %+v from %+v", st, j)
			}
			wantNext := j.FinishedAt.Add(1440 * time.Minute)
			if !st.NextRun.Equal(wantNext) {
				t.Fatalf("NextRun = %v; want %v", st.NextRun, wantNext)
			}
			if tc.wantOK && (!st.LastSuccess.Equal(j.FinishedAt) || st.RunID != runA || !st.LocalVerified) {
				t.Fatalf("success fields not restored: %+v", st)
			}
			if !tc.wantOK && !st.LastSuccess.IsZero() {
				t.Fatalf("a failed job must not set LastSuccess: %+v", st)
			}
			if got := e.readDisk(t).States["data"]; got.Status != tc.wantStatus {
				t.Fatalf("restored State must be persisted: %+v", got)
			}
		})
	}
}

func TestStartupPruningIsPersistedAndResultFilesGoLast(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	mkJobs := func() []*Job {
		var jobs []*Job
		for i := 0; i < 233; i++ {
			age := time.Duration(233-i) * time.Hour // newest last, all < 90 days...
			if i < 3 {
				age = 100*24*time.Hour + time.Duration(i)*time.Hour // ...except 3 older than 90 days
			}
			fin := now.Add(-age)
			jobs = append(jobs, &Job{JobID: fmt.Sprintf("job-20260901T%06dZ-%012x", i, i), Kind: "data", Trigger: JobTriggerManual, Status: JobStatusFailed,
				RequestedBy: JobRequester{Type: JobRequesterUser}, CreatedAt: fin.Add(-time.Minute), StartedAt: fin.Add(-time.Minute), FinishedAt: fin})
		}
		return jobs
	}
	resultExists := func(e *env, j *Job) bool {
		_, err := os.Stat(filepath.Join(e.root, ".results", j.JobID+".json"))
		return err == nil
	}

	t.Run("healthy: pruned file is written at startup without any later run", func(t *testing.T) {
		e := newEnv(t)
		jobs := mkJobs()
		e.seed(t, jobs...)
		for _, j := range jobs {
			e.writeResult(t, j.JobID, "{}")
		}
		e.manager(t, func(m *Manager) { free(m); m.clock = func() time.Time { return now } })
		onDisk := e.readJobs(t)
		if len(onDisk) != MaxJobHistory {
			t.Fatalf("jobs on disk = %d; want %d", len(onDisk), MaxJobHistory)
		}
		kept := map[string]bool{}
		for _, j := range onDisk {
			kept[j.JobID] = true
		}
		for _, j := range jobs {
			if kept[j.JobID] != resultExists(e, j) {
				t.Fatalf("job %s kept=%v but result file exists=%v", j.JobID, kept[j.JobID], resultExists(e, j))
			}
		}
	})

	t.Run("failed write keeps result files and the next tick finishes the job", func(t *testing.T) {
		e := newEnv(t)
		jobs := mkJobs()
		e.seed(t, jobs...)
		for _, j := range jobs {
			e.writeResult(t, j.JobID, "{}")
		}
		var failing atomic.Bool
		failing.Store(true)
		m := e.manager(t, func(m *Manager) {
			free(m)
			m.clock = func() time.Time { return now }
			m.writer = failJobWrites(e.jobs, failing.Load, "disk full")
		})
		if len(e.readJobs(t)) != len(jobs) {
			t.Fatal("precondition: the failed write must leave the old file")
		}
		for _, j := range jobs {
			if !resultExists(e, j) {
				t.Fatalf("result file of %s was deleted before the pruned job file was durable", j.JobID)
			}
		}
		failing.Store(false)
		m.tick(context.Background(), now)
		if got := e.readJobs(t); len(got) != MaxJobHistory {
			t.Fatalf("jobs on disk after tick = %d; want %d", len(got), MaxJobHistory)
		}
		if resultExists(e, jobs[0]) || !resultExists(e, jobs[len(jobs)-1]) {
			t.Fatal("result files must follow the durable prune")
		}
	})
}
