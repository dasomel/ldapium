package backup

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// workerWait bounds how long a test waits for a worker subprocess. Generous on
// purpose (D1): a cold interpreter start under parallel-package load took >5s
// once (#225); the poll returns as soon as the job is idle, so it costs nothing
// when healthy.
const workerWait = 30 * time.Second

// pythonForTest resolves python3 from PATH instead of hardcoding
// /usr/bin/python3 (the macOS xcode-select shim) and warms it once so the
// first-launch cost is paid before any timed wait starts.
func pythonForTest(t *testing.T) string {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found in PATH; backup worker tests need it")
	}
	if python, err = filepath.Abs(python); err != nil {
		t.Skip("cannot resolve python3 path: ", err)
	}
	if out, err := exec.Command(python, "-c", "pass").CombinedOutput(); err != nil {
		t.Skipf("python3 at %s cannot run: %v: %s", python, err, out)
	}
	return python
}

// waitIdle polls until no job is running. On timeout it fails with the elapsed
// time and the full View so a future flake is diagnosable.
func waitIdle(t *testing.T, m *Manager) {
	t.Helper()
	start := time.Now()
	for m.View().Running {
		if time.Since(start) > workerWait {
			t.Fatalf("job still running after %s: %+v", time.Since(start).Round(time.Millisecond), m.View())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func testManager(t *testing.T) *Manager {
	t.Helper()
	python := pythonForTest(t)
	dir := t.TempDir()
	operator := filepath.Join(dir, "operator.json")
	if err := os.WriteFile(operator, []byte(`{"destinations":[{"id":"local","name":"Local","type":"local"}],"log_paths":["/registered/log"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	worker := filepath.Join(dir, "worker.py")
	if err := os.WriteFile(worker, []byte("import time,json\ntime.sleep(.1)\nprint(json.dumps({'run_id':'test-run','verified':True}))\n"), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := New(filepath.Join(dir, "policy.json"), operator, worker, python)
	if err != nil {
		t.Fatal(err)
	}
	// Registered after TempDir, so it runs first: no worker may outlive the test
	// and write into (or recreate) a removed directory.
	t.Cleanup(func() {
		start := time.Now()
		for m.View().Running {
			if time.Since(start) > workerWait {
				t.Errorf("worker still running at cleanup after %s", workerWait)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	return m
}
func TestPolicyRestartIsolationAndConflicts(t *testing.T) {
	m := testManager(t)
	p := m.View().Policies
	p.Data.Enabled = true
	p.Logs.KeepDays = 3
	p.Logs.IntervalMinutes = 5
	saved, err := m.Save(p, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Save(p, 0); err != ErrConflict {
		t.Fatal(err)
	}
	restarted, err := New(m.path, m.operator, m.worker, m.python)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.View().Policies.Logs.KeepDays != 3 || saved.Data.KeepDays != 30 || restarted.View().States["data"].NextRun.IsZero() {
		t.Fatal("policy/state not preserved")
	}
	nextBefore := m.View().States["data"].NextRun
	saved.Logs.KeepDays = 4
	saved, err = m.Save(saved, saved.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if !m.View().States["data"].NextRun.Equal(nextBefore) {
		t.Fatal("log policy moved data schedule")
	}
	p = saved
	p.Data.Destinations = []string{"unknown"}
	if _, err = m.Save(p, saved.Revision); err == nil {
		t.Fatal("unknown destination")
	}
}
func TestJobsSerializeAndSchedulerRecoversDueState(t *testing.T) {
	m := testManager(t)
	p := m.View().Policies
	p.Data.Enabled = true
	if _, err := m.Save(p, 0); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	state := m.states["data"]
	state.NextRun = time.Now().Add(-time.Minute)
	m.states["data"] = state
	m.mu.Unlock()
	m.tick(context.Background(), time.Now())
	if err := m.Run(context.Background(), "logs"); err != ErrBusy {
		t.Fatal(err)
	}
	waitIdle(t, m)
	v := m.View()
	if v.States["data"].Status != "succeeded" || v.States["logs"].Status != "" {
		t.Fatalf("unexpected state: %+v", v)
	}
	b, err := os.ReadFile(m.path)
	if err != nil {
		t.Fatal(err)
	}
	var stored disk
	if err = json.Unmarshal(b, &stored); err != nil || stored.States["data"].RunID != "test-run" {
		t.Fatal(err)
	}
}

func TestCancellationTerminatesWorkerAndChild(t *testing.T) {
	m := testManager(t)
	childPID := filepath.Join(filepath.Dir(m.path), "child.pid")
	script := "import subprocess,time\np=subprocess.Popen(['sleep','60'])\nopen(" + strconv.Quote(childPID) + ",'w').write(str(p.pid))\ntime.sleep(60)\n"
	if err := os.WriteFile(m.worker, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.Run(ctx, "data"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(workerWait)
	var child int
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(childPID); err == nil {
			child, _ = strconv.Atoi(string(b))
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if child == 0 {
		t.Fatal("child not started")
	}
	cancel()
	waitIdle(t, m)
	if m.View().States["data"].Status != "failed" {
		t.Fatal("canceled worker did not stop")
	}
	// A killed child may briefly be a zombie until init reaps it; it must not run.
	output, err := exec.Command("ps", "-o", "stat=", "-p", strconv.Itoa(child)).Output()
	if err == nil && !strings.HasPrefix(strings.TrimSpace(string(output)), "Z") {
		t.Fatalf("child remains active: %s", output)
	}
}

func TestRemoteFailureRecordsVerifiedLocalCopy(t *testing.T) {
	m := testManager(t)
	script := "import json,sys\nprint(json.dumps({'run_id':'local-only','verified':False,'local_verified':True}))\nsys.exit(1)\n"
	if err := os.WriteFile(m.worker, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.Run(context.Background(), "data"); err != nil {
		t.Fatal(err)
	}
	waitIdle(t, m)
	state := m.View().States["data"]
	if state.Status != "failed" || !state.LocalVerified || state.RunID != "local-only" || state.LastLocalSuccess.IsZero() || !state.LastSuccess.IsZero() {
		t.Fatal(state)
	}
}
