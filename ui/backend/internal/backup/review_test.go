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

// The file is written by hand, not serialized by Job, so the foreign text really
// is on disk and only the load side can neutralise it.
const hostileErrorJobFile = `{"version":1,"jobs":[{"job_id":"job-20261006T150000Z-111111111111","kind":"data","trigger":"manual","status":"failed",
"requested_by":{"type":"user"},"policy_revision":0,"created_at":"2026-10-06T10:00:00Z",
"error":{"code":"worker_failed","message":"password=sentinel-secret cn=admin /outside/path"}}]}`

func TestStoredErrorTextIsNeverTrustedAndNeverReturned(t *testing.T) {
	e := newEnv(t)
	if err := os.WriteFile(e.jobs, []byte(hostileErrorJobFile), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadJobFile(e.jobs)
	if err != nil || len(loaded) != 1 || loaded[0].Error.Message != ErrorMessage(ErrCodeWorkerFailed) {
		t.Fatalf("loadJobFile must replace stored text by the catalog text: %+v %v", loaded, err)
	}
	if err := os.WriteFile(e.jobs, []byte(hostileErrorJobFile), 0600); err != nil {
		t.Fatal(err)
	}
	got := e.manager(t, free).Jobs("", "", 10)[0]
	if got.Error.Message != ErrorMessage(got.Error.Code) {
		t.Fatalf("stored text reached a returned job: %q", got.Error.Message)
	}
	// Serialization is a second line of defence for records built in memory.
	b, err := (Job{JobID: jobA, Error: &JobError{Code: ErrCodeWorkerFailed, Message: "password=sentinel-secret"}}).MarshalJSON()
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

// signalLog is an injected group signaller that records the calls and whether the
// leader had already been reaped. A sweep of leftover members legitimately signals
// after the reap, but always starts with a signal-0 probe; a SIGTERM/SIGKILL that
// is not preceded by that probe after the reap is a cancel path signalling a pid
// that may have been reused.
type signalLog struct {
	leader     func() int // worker pid, 0 until known
	reaped     func(pid int) bool
	sweeping   atomic.Bool
	violations atomic.Int32
	calls      atomic.Int32
}

func (l *signalLog) send(pgid int, sig syscall.Signal) error {
	l.calls.Add(1)
	if pid := l.leader(); pid != 0 && l.reaped(pid) {
		if sig == 0 {
			l.sweeping.Store(true)
		} else if !l.sweeping.Load() {
			l.violations.Add(1)
		}
	}
	return syscall.Kill(-pgid, sig)
}

func leaderGone(pid int) bool { return syscall.Kill(pid, 0) == syscall.ESRCH }

func pidFrom(file string) func() int {
	return func() int {
		b, err := os.ReadFile(file)
		pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil {
			return 0
		}
		return pid
	}
}

// Cancel arrives in the window right after the kernel reaped the worker (the
// reaper is held there by the afterReap seam): the signal must not be sent.
func TestCancelRightAfterTheReapSendsNoSignal(t *testing.T) {
	dir := t.TempDir()
	pidfile, script := filepath.Join(dir, "pid"), filepath.Join(dir, "worker.py")
	if err := os.WriteFile(script, []byte("import os\nopen("+quote(pidfile)+",'w').write(str(os.getpid()))\n"), 0600); err != nil {
		t.Fatal(err)
	}
	log := &signalLog{leader: pidFrom(pidfile), reaped: leaderGone}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := &Manager{python: pythonForTest(t), worker: script, operator: "/unused", killGrace: time.Second, signalGroup: log.send}
	m.afterReap = func() { cancel(); time.Sleep(100 * time.Millisecond) } // ctx is done before execWorker sees the exit
	if _, err := m.execWorker(ctx, "logs", jobA, nil); err != nil {
		t.Fatal(err)
	}
	if log.violations.Load() != 0 {
		t.Fatalf("%d signal(s) were sent to the group after its leader was reaped", log.violations.Load())
	}
}

// The worker exits while a grandchild keeps the inherited stdout open: the reap
// must be noticed at once (Wait must not wait for that pipe), so a cancel that
// follows the reap cannot signal the group as if the leader were alive.
func TestWorkerExitWithOpenInheritedPipeIsNoticedAtTheReap(t *testing.T) {
	dir := t.TempDir()
	pidfile, script := filepath.Join(dir, "pid"), filepath.Join(dir, "worker.py")
	code := "import os,subprocess\nopen(" + quote(pidfile) + ",'w').write(str(os.getpid()))\nsubprocess.Popen(['sleep','60'])\n"
	if err := os.WriteFile(script, []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	log := &signalLog{leader: pidFrom(pidfile), reaped: leaderGone}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := &Manager{python: pythonForTest(t), worker: script, operator: "/unused", killGrace: time.Second, signalGroup: log.send}
	go func() {
		for {
			if pid := log.leader(); pid != 0 && leaderGone(pid) {
				cancel()
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	if _, err := m.execWorker(ctx, "logs", jobA, nil); err != nil {
		t.Fatal(err)
	}
	if log.violations.Load() != 0 {
		t.Fatalf("%d signal(s) were sent to the group after its leader was reaped", log.violations.Load())
	}
}

// Ids and kinds that reach a path from HTTP input: "../", an absolute path and a
// NUL byte must never be joined into one (CodeQL go/path-injection, and for real).
func TestHostileIDsAndKindsNeverReachAPath(t *testing.T) {
	e := newEnv(t)
	outside := t.TempDir()
	secret := filepath.Join(outside, "victim.json")
	if err := os.WriteFile(secret, []byte(okResult(jobA, runA)), 0600); err != nil {
		t.Fatal(err)
	}
	rel, _ := filepath.Rel(filepath.Join(e.root, ".results"), strings.TrimSuffix(secret, ".json"))
	hostile := []string{"../x", "../../etc/passwd", "/etc/passwd", "job-20261006T150000Z-111111111111\x00../../x", rel, "..", "a/b", "", "\x00"}

	m := e.manager(t, free)
	for _, id := range hostile {
		if _, err := m.GetJob(id); err == nil {
			t.Fatalf("GetJob(%q) must fail", id)
		}
		if _, err := m.CancelJob(id); err == nil {
			t.Fatalf("CancelJob(%q) must fail", id)
		}
		if got := findMatchingManifest(e.root, "data", id, "inst-1"); got != nil {
			t.Fatalf("findMatchingManifest accepted job id %q", id)
		}
		// A job record with a hostile id (hand-built, as a corrupt file could not load it).
		if res, status := m.readWorkerResult(&Job{JobID: id, Kind: "data"}); res != nil || status == resultOK {
			t.Fatalf("readWorkerResult accepted job id %q", id)
		}
		if _, _, ok := readOwnedManifest(e.root, "data", id, "inst-1"); ok {
			t.Fatalf("readOwnedManifest accepted run dir %q", id)
		}
	}
	for _, kind := range append(hostile, "DATA", "data/../logs") {
		if got := findMatchingManifest(e.root, kind, jobA, "inst-1"); got != nil {
			t.Fatalf("findMatchingManifest accepted kind %q", kind)
		}
		if _, _, ok := readOwnedManifest(e.root, kind, runA, "inst-1"); ok {
			t.Fatalf("readOwnedManifest accepted kind %q", kind)
		}
		if _, err := m.StartJob(context.Background(), RunRequest{Kind: kind}); err == nil {
			t.Fatalf("StartJob accepted kind %q", kind)
		}
	}
	// Result-file removal must stay inside .results even for a hostile id.
	removeResultFiles(filepath.Join(e.root, ".results"), hostile)
	if _, err := os.Stat(secret); err != nil {
		t.Fatalf("a file outside .results was removed: %v", err)
	}
	// An absolute or NUL path never opens a file, even through the low-level reader.
	for _, p := range []string{secret, "/etc/passwd", filepath.Join(e.root, "x\x00"), filepath.Join(e.root, "..", "victim.json")} {
		if _, err := readRegularFile(e.root, p, 1<<10); err == nil {
			t.Fatalf("readRegularFile opened %q outside the root", p)
		}
	}
}
