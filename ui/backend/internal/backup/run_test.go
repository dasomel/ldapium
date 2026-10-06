package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Real-process tests for T-013: deadline, cancel and the SIGTERM -> SIGKILL ladder.

func waitFile(t *testing.T, path string) string {
	t.Helper()
	deadline := time.Now().Add(workerWait)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
			return string(b)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s never appeared", path)
	return ""
}

func assertDead(t *testing.T, pidText string) {
	t.Helper()
	pid, _ := strconv.Atoi(strings.TrimSpace(pidText))
	// A killed process may briefly be a zombie until init reaps it; it must not run.
	out, err := exec.Command("ps", "-o", "stat=", "-p", strconv.Itoa(pid)).Output()
	if err == nil && !strings.HasPrefix(strings.TrimSpace(string(out)), "Z") {
		t.Fatalf("process %d remains active: %s", pid, out)
	}
}

func quote(p string) string { return strconv.Quote(p) }

func TestJobDeadlineKillsTheProcessGroup(t *testing.T) {
	m := testManager(t)
	dir := filepath.Dir(m.path)
	childPID := filepath.Join(dir, "child.pid")
	script := "import subprocess,time\np=subprocess.Popen(['sleep','60'])\nopen(" + quote(childPID) + ",'w').write(str(p.pid))\ntime.sleep(60)\n"
	if err := os.WriteFile(m.worker, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	m.SetJobTimeouts(600*time.Millisecond, 600*time.Millisecond)
	m.SetKillGrace(5 * time.Second)

	job, err := m.StartJob(context.Background(), RunRequest{Kind: "data"})
	if err != nil {
		t.Fatal(err)
	}
	if job.DeadlineAt.IsZero() || job.DeadlineAt.Sub(job.StartedAt) != 600*time.Millisecond {
		t.Fatalf("deadline_at must be set from the per-kind timeout: %+v", job)
	}
	child := waitFile(t, childPID)
	waitIdle(t, m)
	got, _ := m.GetJob(job.JobID)
	if got.Status != JobStatusFailed || got.Error == nil || got.Error.Code != ErrCodeDeadlineExceeded || got.StagingCleanup != StagingCleanupDone {
		t.Fatalf("deadline must fail the job as deadline_exceeded: %+v", got)
	}
	assertDead(t, child)
	if st := m.View().States["data"]; st.Status != "failed" {
		t.Fatalf("state = %+v", st)
	}
}

func TestCancelTerminatesGracefullyAndRunsWorkerCleanup(t *testing.T) {
	m := testManager(t)
	dir := filepath.Dir(m.path)
	started, cleaned := filepath.Join(dir, "started.pid"), filepath.Join(dir, "cleanup.done")
	script := "import os,signal,sys,time\nopen(" + quote(started) + ",'w').write(str(os.getpid()))\n" +
		"def term(*a):\n  open(" + quote(cleaned) + ",'w').write('x')\n  sys.exit(0)\nsignal.signal(signal.SIGTERM, term)\ntime.sleep(60)\n"
	if err := os.WriteFile(m.worker, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	m.SetKillGrace(10 * time.Second)

	job, err := m.StartJob(context.Background(), RunRequest{Kind: "data"})
	if err != nil {
		t.Fatal(err)
	}
	pid := waitFile(t, started)
	if _, err := m.CancelJob(job.JobID); err != nil {
		t.Fatal(err)
	}
	waitIdle(t, m)
	got, _ := m.GetJob(job.JobID)
	if got.Status != JobStatusCancelled || got.StagingCleanup != StagingCleanupDone || got.CancelRequestedAt.IsZero() {
		t.Fatalf("cancel must end cancelled with cleanup done: %+v", got)
	}
	if _, err := os.Stat(cleaned); err != nil {
		t.Fatal("SIGTERM must reach the worker so its cleanup runs (a SIGKILL-first cancel skips it)")
	}
	assertDead(t, pid)
	if st := m.View().States["data"].Status; st != "cancelled" {
		t.Fatalf("state = %q", st)
	}
	// Repeating the cancel is idempotent; any other terminal job is not cancellable.
	if again, err := m.CancelJob(job.JobID); err != nil || again.Status != JobStatusCancelled {
		t.Fatalf("second cancel = %+v %v", again, err)
	}
}

func TestCancelEscalatesToSIGKILLAndReportsPendingStaging(t *testing.T) {
	m := testManager(t)
	dir := filepath.Dir(m.path)
	started, childPID := filepath.Join(dir, "started.pid"), filepath.Join(dir, "child.pid")
	script := "import os,signal,subprocess,time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\n" +
		"p=subprocess.Popen(['sleep','60'],preexec_fn=lambda: signal.signal(signal.SIGTERM, signal.SIG_IGN))\n" +
		"open(" + quote(childPID) + ",'w').write(str(p.pid))\nopen(" + quote(started) + ",'w').write(str(os.getpid()))\ntime.sleep(60)\n"
	if err := os.WriteFile(m.worker, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	m.SetKillGrace(400 * time.Millisecond)
	// A leftover staging directory makes staging_cleanup stay "pending".
	m.root = filepath.Join(dir, "root")
	if err := os.MkdirAll(filepath.Join(m.root, "data", ".pending-leftover"), 0700); err != nil {
		t.Fatal(err)
	}

	job, err := m.StartJob(context.Background(), RunRequest{Kind: "data"})
	if err != nil {
		t.Fatal(err)
	}
	pid, child := waitFile(t, started), waitFile(t, childPID)
	begin := time.Now()
	if _, err := m.CancelJob(job.JobID); err != nil {
		t.Fatal(err)
	}
	waitIdle(t, m)
	if time.Since(begin) < 400*time.Millisecond {
		t.Fatal("SIGKILL must wait out the grace period")
	}
	got, _ := m.GetJob(job.JobID)
	if got.Status != JobStatusCancelled || got.StagingCleanup != StagingCleanupPending {
		t.Fatalf("a SIGKILLed worker leaves staging pending: %+v", got)
	}
	assertDead(t, pid)
	assertDead(t, child)

	// Once no .pending-* is left the same record reads as done (computed, not stored).
	if err := os.RemoveAll(filepath.Join(m.root, "data", ".pending-leftover")); err != nil {
		t.Fatal(err)
	}
	if got, _ = m.GetJob(job.JobID); got.StagingCleanup != StagingCleanupDone {
		t.Fatalf("pending must read as done once cleaned: %+v", got)
	}
	m.mu.Lock()
	stored := m.jobs[0].StagingCleanup
	m.mu.Unlock()
	if stored != StagingCleanupPending {
		t.Fatalf("the stored value must stay pending, got %q", stored)
	}
}

func TestWorkerBusyExitRetriesSoonNotAfterAFullInterval(t *testing.T) {
	m := testManager(t)
	if err := os.WriteFile(m.worker, []byte("import sys\nsys.exit(75)\n"), 0600); err != nil {
		t.Fatal(err)
	}
	job, err := m.StartJob(context.Background(), RunRequest{Kind: "data"})
	if err != nil {
		t.Fatal(err)
	}
	waitIdle(t, m)
	got, _ := m.GetJob(job.JobID)
	if got.Status != JobStatusFailed || got.Error.Code != ErrCodeWorkerBusy {
		t.Fatalf("exit 75 = failed/worker_busy: %+v", got)
	}
	st := m.View().States["data"]
	if d := st.NextRun.Sub(got.FinishedAt); d != 60*time.Second {
		t.Fatalf("next_run must be 60s after worker_busy, got %v", d)
	}
}

func TestWorkerResultFileIsUsedWhenStdoutIsLost(t *testing.T) {
	// A worker stopped by SIGTERM cannot print; its result file still records a
	// finalized local copy, which a cancelled job must keep (D217-6 point 2).
	e := newEnv(t)
	m := e.manager(t, func(m *Manager) {
		free(m)
		m.runWorker = func(ctx context.Context, kind, jobID string, _ []byte) ([]byte, error) {
			e.writeResult(t, jobID, strings.Replace(okResult(jobID, runA), `"verified":true`, `"verified":false`, 1))
			e.writeRun(t, kind, runA, goodManifest(runA, jobID, map[string]string{"data.ldif.gz": sum("d")}), map[string]string{"data.ldif.gz": "d"})
			<-ctx.Done()
			return nil, ctx.Err()
		}
	})
	job, err := m.StartJob(context.Background(), RunRequest{Kind: "data"})
	if err != nil {
		t.Fatal(err)
	}
	for m.ActiveJob() == nil || func() bool { _, e := os.Stat(filepath.Join(e.root, "data", runA)); return e != nil }() {
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := m.CancelJob(job.JobID); err != nil {
		t.Fatal(err)
	}
	waitIdle(t, m)
	got, _ := m.GetJob(job.JobID)
	if got.Status != JobStatusCancelled || got.Local == nil || !got.Local.Verified || got.Artifact == nil || got.Artifact.RunID != runA || len(got.Artifact.Files) != 1 {
		t.Fatalf("cancelled job must keep the finalized local copy: %+v", got)
	}
}

// realWorkerManager runs the real backup_worker.py (local destination only) so
// the Go/Python result contract is exercised end to end.
func realWorkerManager(t *testing.T) (*Manager, *env, string) {
	t.Helper()
	python := pythonForTest(t)
	_, thisFile, _, _ := runtime.Caller(0)
	worker := filepath.Join(filepath.Dir(thisFile), "..", "..", "backup-tools", "backup_worker.py")
	e := newEnv(t)
	source := filepath.Join(e.dir, "audit.log")
	if err := os.WriteFile(source, []byte("audit event"), 0600); err != nil {
		t.Fatal(err)
	}
	op := fmt.Sprintf(`{"root":%q,"instance_id":"inst-1","destinations":[{"id":"local","name":"Local","type":"local"}],"log_paths":[%q]}`, e.root, source)
	if err := os.WriteFile(e.operator, []byte(op), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := newManager(e.policy, e.operator, worker, python, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m, e, source
}

func TestRealWorkerJobSucceedsWithManifestMatchingArtifact(t *testing.T) {
	m, e, _ := realWorkerManager(t)
	job, err := m.StartJob(context.Background(), RunRequest{Kind: "logs"})
	if err != nil {
		t.Fatal(err)
	}
	waitIdle(t, m)
	got, _ := m.GetJob(job.JobID)
	if got.Status != JobStatusSucceeded || got.Local == nil || !got.Local.Verified || got.Artifact == nil || len(got.Destinations) != 1 || got.Destinations[0].Status != DestStatusSucceeded {
		t.Fatalf("real worker job = %+v", got)
	}
	// The recorded files are exactly the worker's complete.json entries.
	raw, err := os.ReadFile(filepath.Join(e.root, "logs", got.Artifact.RunID, "complete.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest ownedManifest
	if err := json.Unmarshal(raw, &manifest); err != nil || manifest.JobID != job.JobID {
		t.Fatalf("manifest job_id = %q (%v); want %s", manifest.JobID, err, job.JobID)
	}
	if len(got.Artifact.Files) != len(manifest.SHA256) || len(got.Artifact.Files) == 0 {
		t.Fatalf("files = %+v, manifest = %v", got.Artifact.Files, manifest.SHA256)
	}
	for _, f := range got.Artifact.Files {
		if manifest.SHA256[f.Name] != f.SHA256 || f.Bytes == 0 {
			t.Fatalf("file %+v does not match the manifest", f)
		}
	}
	// The worker's result file is what validateWorkerResult accepts (orphan path).
	if res, status := m.readWorkerResult(got); status != resultOK || !res.Verified {
		t.Fatalf("worker result file rejected: %v %+v", status, res)
	}
}

func TestRealWorkerLockRaceBecomesWorkerBusy(t *testing.T) {
	m, e, _ := realWorkerManager(t)
	m.SetLockProbe(func() (bool, error) { return false, nil }) // the race: free at probe time, held at start
	lock, err := os.OpenFile(filepath.Join(e.root, ".worker.lock"), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	job, err := m.StartJob(context.Background(), RunRequest{Kind: "logs"})
	if err != nil {
		t.Fatal(err)
	}
	waitIdle(t, m)
	got, _ := m.GetJob(job.JobID)
	if got.Status != JobStatusFailed || got.Error == nil || got.Error.Code != ErrCodeWorkerBusy {
		t.Fatalf("real worker exit 75 = %+v", got)
	}
}
