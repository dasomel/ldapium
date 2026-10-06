package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// Defaults for the run limits (D217-6, D217-10).
const (
	DefaultJobTimeout = 2 * time.Hour
	defaultKillGrace  = 10 * time.Second
	workerBusyExit    = 75
)

// errWorkerKilled marks a worker that ignored SIGTERM for the whole grace
// period and had to be SIGKILLed, so its staging directory may be left behind.
var errWorkerKilled = errors.New("worker killed after grace period")

// limitedBuffer keeps at most max bytes of worker stdout; the rest is dropped.
type limitedBuffer struct {
	buf bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.max - l.buf.Len(); room > 0 {
		l.buf.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

// SetJobTimeouts sets the per-kind maximum run time (config enforces the
// 1m..24h bounds; tests use shorter values directly).
func (m *Manager) SetJobTimeouts(data, logs time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.jobTimeouts = map[string]time.Duration{"data": data, "logs": logs}
}

func (m *Manager) timeoutFor(kind string) time.Duration {
	if d := m.jobTimeouts[kind]; d > 0 {
		return d
	}
	return DefaultJobTimeout
}

// procGroup guards signalling of the worker's process group. Once cmd.Wait has
// reaped the leader its pid (= pgid) can be reused, so ctx-driven signals are
// only sent while the leader is provably unreaped: the waiter marks the group
// exited, under the same mutex signal() takes, immediately after Wait returns.
type procGroup struct {
	mu     sync.Mutex
	pgid   int
	exited bool
	send   func(pgid int, sig syscall.Signal) error
}

func (g *procGroup) markExited() {
	g.mu.Lock()
	g.exited = true
	g.mu.Unlock()
}

// signal reports whether the signal was sent; it never is after the reap.
func (g *procGroup) signal(sig syscall.Signal) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.exited {
		return false
	}
	_ = g.send(g.pgid, sig)
	return true
}

// sweep ends members the worker left behind after it exited (a child that
// outlives its parent). A surviving member keeps the pgid allocated, so it is
// probed first (signal 0): an empty group is left alone. Members get SIGTERM,
// then SIGKILL after the grace period.
func (g *procGroup) sweep(grace time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.send(g.pgid, 0) != nil {
		return
	}
	_ = g.send(g.pgid, syscall.SIGTERM)
	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		if g.send(g.pgid, 0) != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = g.send(g.pgid, syscall.SIGKILL)
}

// execWorker runs the worker in its own process group. When ctx ends (cancel,
// deadline, shutdown) the group gets SIGTERM, then SIGKILL after the grace
// period (D217-6); the worker's SIGTERM handler removes its staging directory.
// When the worker exits, any process it left in the group is swept before the
// job settles. It is the default Manager.runWorker.
func (m *Manager) execWorker(ctx context.Context, kind, jobID string, stdin []byte) ([]byte, error) {
	cmd := exec.Command(m.python, m.worker, "--config", m.operator, "--kind", kind, "--job-id", jobID)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdin = bytes.NewReader(stdin)
	out := &limitedBuffer{max: maxResultBytes}
	cmd.Stdout = out
	// A grandchild that outlives the worker must not hold Wait open forever.
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	send := m.signalGroup
	if send == nil {
		send = func(pgid int, sig syscall.Signal) error { return syscall.Kill(-pgid, sig) }
	}
	g := &procGroup{pgid: cmd.Process.Pid, send: send}
	grace := m.killGrace
	if grace <= 0 {
		grace = defaultKillGrace
	}
	done := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		g.markExited()
		done <- err
	}()
	select {
	case err := <-done:
		g.sweep(grace)
		return out.buf.Bytes(), err
	case <-ctx.Done():
	}
	g.signal(syscall.SIGTERM)
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case err := <-done:
		g.sweep(grace)
		return out.buf.Bytes(), err
	case <-timer.C:
		g.signal(syscall.SIGKILL)
		err := <-done
		g.sweep(grace)
		return out.buf.Bytes(), fmt.Errorf("%w: %v", errWorkerKilled, err)
	}
}

func (m *Manager) execute(ctx context.Context, kind string, p Policy, connections []Connection, jobID string, deadline time.Time) {
	runCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	b, _ := json.Marshal(struct {
		Policy
		Connections []Connection `json:"connections"`
	}{p, connections})
	out, err := m.runWorker(runCtx, kind, jobID, b)
	runErr := runCtx.Err()

	m.mu.Lock()
	defer m.mu.Unlock()
	m.running = false
	m.cancelFunc = nil
	finishedAt := m.now()

	var job *Job
	for _, j := range m.jobs {
		if j.JobID == jobID {
			job = j
			break
		}
	}
	if job == nil {
		return
	}

	// Worker evidence: validated stdout first, else the validated result file
	// (a worker stopped by SIGTERM writes it on its way out).
	var wr WorkerResult
	var result *WorkerResult
	if json.Unmarshal(out, &wr) == nil && validateWorkerResult(&wr, job) == nil {
		result = &wr
	} else if fromFile, status := m.readWorkerResult(job); status == resultOK {
		result = fromFile
	}

	var exitErr *exec.ExitError
	succeeded := err == nil && result != nil && result.Verified
	cancelled := !job.CancelRequestedAt.IsZero() && !succeeded
	deadlineHit := !cancelled && !succeeded && errors.Is(runErr, context.DeadlineExceeded)
	code := ""
	switch {
	case succeeded, cancelled:
	case deadlineHit:
		code = ErrCodeDeadlineExceeded
	case errors.As(err, &exitErr) && exitErr.ExitCode() == workerBusyExit:
		code = ErrCodeWorkerBusy
	case err == nil:
		code = ErrCodeUnverifiedResult
	default:
		code = ErrCodeWorkerFailed
	}

	job.FinishedAt = finishedAt
	switch {
	case succeeded:
		job.Status = JobStatusSucceeded
	case cancelled:
		job.Status = JobStatusCancelled
	default:
		job.Status = JobStatusFailed
	}
	if code != "" {
		job.Error = &JobError{Code: code, Message: ErrorMessage(code)}
	}
	if cancelled || deadlineHit {
		job.StagingCleanup = StagingCleanupDone
		if errors.Is(err, errWorkerKilled) {
			job.StagingCleanup = StagingCleanupPending
		}
	}
	if result != nil {
		if result.LocalVerified {
			job.Local = &JobLocal{Verified: true}
		}
		for _, d := range result.Destinations {
			job.Destinations = append(job.Destinations, JobDestination{ID: d.ID, Status: d.Status, ErrorCode: d.ErrorCode})
		}
		if result.RunID != "" {
			job.Artifact = &JobArtifact{RunID: result.RunID}
			if man := findMatchingManifest(m.root, kind, jobID, m.instanceID); man != nil && man.RunID == result.RunID {
				job.Artifact.Files = convertManifestFiles(man.Files)
			}
		}
	}

	if result == nil {
		// No stdout and no result file (SIGKILLed mid-transfer): a manifest that
		// carries this job's ID in an owned run directory proves the local copy was
		// committed (verified before the rename), so record exactly that.
		if man := findMatchingManifest(m.root, kind, jobID, m.instanceID); man != nil {
			job.Local = &JobLocal{Verified: true}
			job.Artifact = &JobArtifact{RunID: man.RunID, Files: convertManifestFiles(man.Files)}
		}
	}

	state := foldJobIntoState(m.states[kind], job)
	state.NextRun = finishedAt.Add(time.Duration(p.IntervalMinutes) * time.Minute)
	if code == ErrCodeWorkerBusy {
		state.NextRun = ScheduleAfterWorkerBusy(consecutiveWorkerBusy(m.jobs, kind)-1, p.IntervalMinutes, finishedAt)
	}
	m.states[kind] = state
	if m.activeJobID == jobID {
		m.activeJobID = ""
		m.activeJobKind = ""
	}

	// D217-17: job record first, then State; result files of pruned jobs go only
	// after the pruned job file is durably written.
	m.pruneLocked(finishedAt)
	m.persistJobsLocked()
	m.persistStateLocked()
	log.Printf("backup_completed job_id=%s kind=%s status=%s error_code=%s policy_revision=%d", jobID, kind, job.Status, code, job.PolicyRevision)
}

// consecutiveWorkerBusy counts the trailing run of worker_busy failures of kind.
func consecutiveWorkerBusy(jobs []*Job, kind string) int {
	n := 0
	for i := len(jobs) - 1; i >= 0; i-- {
		j := jobs[i]
		if j.Kind != kind || j.Status == JobStatusRunning {
			continue
		}
		if j.Status != JobStatusFailed || j.Error == nil || j.Error.Code != ErrCodeWorkerBusy {
			break
		}
		n++
	}
	return n
}
