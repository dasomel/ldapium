package backup

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Regression tests for the Codex review of the job core (M1-M5, H1).

func TestStoredErrorTextIsNeverTrustedAndNeverReturned(t *testing.T) {
	e := newEnv(t)
	raw := "password=sentinel-secret cn=admin /outside/path"
	if err := os.WriteFile(e.jobs, validJobJSON(t, func(j *Job) { j.Error.Message = raw }), 0600); err != nil {
		t.Fatal(err)
	}
	m := e.manager(t, free)
	got := m.Jobs("", "", 10)[0]
	if got.Error.Message != ErrorMessage(got.Error.Code) {
		t.Fatalf("stored text reached a returned job: %q", got.Error.Message)
	}
	// Even a record built in memory with foreign text serializes with the catalog text.
	b, err := (Job{JobID: jobA, Error: &JobError{Code: ErrCodeWorkerFailed, Message: raw}}).MarshalJSON()
	if err != nil || strings.Contains(string(b), "sentinel-secret") {
		t.Fatalf("serialization must derive the message from the code: %s %v", b, err)
	}
}

func TestSymlinkedKindDirectoryIsNotAnOwnedRoot(t *testing.T) {
	for _, kind := range []string{"data", "logs"} {
		t.Run(kind, func(t *testing.T) {
			e := newEnv(t)
			outside := t.TempDir()
			if err := os.Symlink(outside, filepath.Join(e.root, kind)); err != nil {
				t.Fatal(err)
			}
			man := goodManifest(runA, jobA, map[string]string{"data.ldif.gz": sum("outside")})
			man["kind"] = kind
			e.writeRun(t, kind, runA, man, map[string]string{"data.ldif.gz": "outside"})
			if got := findMatchingManifest(e.root, kind, jobA, "inst-1"); got != nil {
				t.Fatalf("accepted an artifact through a symlinked %s directory: %+v", kind, got)
			}
			m := e.manager(t, free)
			if st := m.storage(); st[kind].Copies != 0 {
				t.Fatalf("capacity counted outside files through the symlink: %+v", st[kind])
			}
		})
	}
}

func TestStateRestoreTakesEachFieldFromTheLatestJobThatHasIt(t *testing.T) {
	e := newEnv(t)
	now := time.Now().UTC()
	a := runningJob(jobA, "data", now.Add(-2*time.Minute))
	a.Status, a.FinishedAt, a.Local, a.Artifact = JobStatusSucceeded, now.Add(-time.Minute), &JobLocal{Verified: true}, &JobArtifact{RunID: runA}
	b := runningJob(jobB, "data", now)
	b.Status, b.FinishedAt = JobStatusFailed, now.Add(time.Second)
	e.seed(t, a, b)
	st := e.manager(t, free).View().States["data"]
	if st.Status != "failed" || st.RunID != runA || !st.LastLocalSuccess.Equal(a.FinishedAt) || !st.LastSuccess.Equal(a.FinishedAt) || st.LocalVerified {
		t.Fatalf("restore from success->failure lost the earlier success: %+v", st)
	}
}

func TestKilledAfterLocalCommitKeepsTheCommittedArtifact(t *testing.T) {
	e := newEnv(t)
	ready := make(chan struct{})
	m := e.manager(t, func(m *Manager) {
		free(m)
		m.runWorker = func(ctx context.Context, kind, id string, _ []byte) ([]byte, error) {
			// Local copy committed, then stuck in a remote transfer: no result file, no stdout.
			e.writeRun(t, kind, runA, goodManifest(runA, id, map[string]string{"data.ldif.gz": sum("d")}), map[string]string{"data.ldif.gz": "d"})
			close(ready)
			<-ctx.Done()
			return nil, errWorkerKilled
		}
	})
	job, err := m.StartJob(context.Background(), RunRequest{Kind: "data"})
	if err != nil {
		t.Fatal(err)
	}
	<-ready
	if _, err := m.CancelJob(job.JobID); err != nil {
		t.Fatal(err)
	}
	waitIdle(t, m)
	got, _ := m.GetJob(job.JobID)
	if got.Local == nil || !got.Local.Verified || got.Artifact == nil || got.Artifact.RunID != runA || len(got.Artifact.Files) != 1 {
		t.Fatalf("the committed local copy was lost from the cancelled job: %+v", got)
	}
	if st := m.View().States["data"]; st.RunID != runA || !st.LocalVerified {
		t.Fatalf("state lost the committed copy: %+v", st)
	}
}

func TestNaturalExitReapsTheRestOfTheProcessGroup(t *testing.T) {
	dir := t.TempDir()
	pidfile, script := filepath.Join(dir, "pid"), filepath.Join(dir, "worker.py")
	code := "import subprocess\np=subprocess.Popen(['sleep','60'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\nopen(" + quote(pidfile) + ",'w').write(str(p.pid))\n"
	if err := os.WriteFile(script, []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	m := &Manager{python: pythonForTest(t), worker: script, operator: "/unused"}
	if _, err := m.execWorker(context.Background(), "logs", jobA, nil); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(pidfile)
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	defer func() { _ = syscall.Kill(pid, syscall.SIGKILL) }()
	if err := syscall.Kill(pid, 0); err == nil {
		t.Fatalf("worker returned but its child %d is still running", pid)
	}
}

func TestNoSignalIsSentToAReapedProcessGroup(t *testing.T) {
	var sent atomic.Int32
	g := &procGroup{pgid: 4242, send: func(pgid int, sig syscall.Signal) error { sent.Add(1); return nil }}
	if !g.signal(syscall.SIGTERM) || sent.Load() != 1 {
		t.Fatal("a live group must be signalled")
	}
	g.markExited()
	if g.signal(syscall.SIGTERM) || g.signal(syscall.SIGKILL) || sent.Load() != 1 {
		t.Fatalf("signals must never be sent once the leader is reaped (the pid may be reused): %d", sent.Load())
	}
}

// Cancel racing a natural exit: whichever wins, no group signal may follow the reap
// except the explicit sweep of leftover members, and the injected sender sees every one.
func TestCancelRacingNaturalExitNeverSignalsAfterReap(t *testing.T) {
	python := pythonForTest(t)
	script := filepath.Join(t.TempDir(), "worker.py")
	if err := os.WriteFile(script, []byte("pass\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		var afterExit atomic.Int32
		var exited atomic.Bool
		m := &Manager{python: python, worker: script, operator: "/unused", killGrace: time.Second}
		m.signalGroup = func(pgid int, sig syscall.Signal) error {
			if sig != 0 && exited.Load() {
				afterExit.Add(1)
			}
			return syscall.Kill(-pgid, sig)
		}
		ctx, cancel := context.WithCancel(context.Background())
		go func() { time.Sleep(time.Duration(i) * 3 * time.Millisecond); cancel() }()
		_, _ = m.execWorker(ctx, "logs", jobA, nil)
		exited.Store(true)
		cancel()
		if afterExit.Load() != 0 {
			t.Fatalf("iteration %d: a signal was sent after execWorker returned", i)
		}
	}
}
