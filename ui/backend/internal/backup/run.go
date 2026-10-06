package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"syscall"
	"time"
)

// execWorker runs the worker in its own process group; ctx cancellation kills
// the whole group. It is the default Manager.runWorker.
func (m *Manager) execWorker(ctx context.Context, kind string, stdin []byte) ([]byte, error) {
	cmd := exec.CommandContext(ctx, m.python, m.worker, "--config", m.operator, "--kind", kind)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.Stdin = bytes.NewReader(stdin)
	return cmd.Output()
}

func (m *Manager) execute(ctx context.Context, kind string, p Policy, connections []Connection, jobID string) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()
	b, _ := json.Marshal(struct {
		Policy
		Connections []Connection `json:"connections"`
	}{p, connections})
	out, err := m.runWorker(ctx, kind, b)
	var result struct {
		RunID         string `json:"run_id"`
		Verified      bool   `json:"verified"`
		LocalVerified bool   `json:"local_verified"`
	}
	decodeErr := json.Unmarshal(out, &result)
	if err == nil {
		err = decodeErr
		if err == nil && (!result.Verified || result.RunID == "") {
			err = fmt.Errorf("unverified worker result")
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.running = false
	m.cancelFunc = nil
	state := m.states[kind]
	state.Status = "failed"
	if decodeErr == nil && result.LocalVerified && result.RunID != "" {
		state.LocalVerified = true
		state.LastLocalSuccess = time.Now().UTC()
		state.RunID = result.RunID
	}
	state.NextRun = time.Now().UTC().Add(time.Duration(p.IntervalMinutes) * time.Minute)
	if err == nil {
		state.Status = "succeeded"
		state.LastSuccess = time.Now().UTC()
		state.RunID = result.RunID
	}

	finishedAt := time.Now().UTC()
	var currentJob *Job
	for _, j := range m.jobs {
		if j.JobID == jobID {
			currentJob = j
			break
		}
	}
	// The job file is validated on load, so only a well-formed run ID may enter it.
	jobRunID := ""
	if decodeErr == nil && runName.MatchString(result.RunID) {
		jobRunID = result.RunID
	}
	if currentJob != nil {
		currentJob.FinishedAt = finishedAt
		if !currentJob.CancelRequestedAt.IsZero() {
			currentJob.Status = JobStatusCancelled
			state.Status = "cancelled"
			if decodeErr == nil && result.LocalVerified {
				currentJob.Local = &JobLocal{Verified: true}
			}
			if jobRunID != "" {
				currentJob.Artifact = &JobArtifact{RunID: jobRunID}
			}
		} else if err == nil {
			currentJob.Status = JobStatusSucceeded
			currentJob.Local = &JobLocal{Verified: result.LocalVerified}
			if jobRunID != "" {
				currentJob.Artifact = &JobArtifact{RunID: jobRunID}
			}
			currentJob.Error = nil
		} else {
			currentJob.Status = JobStatusFailed
			currentJob.Error = &JobError{
				Code:    ErrCodeWorkerFailed,
				Message: ErrorMessage(ErrCodeWorkerFailed),
			}
			if decodeErr == nil && result.LocalVerified {
				currentJob.Local = &JobLocal{Verified: true}
			}
			if jobRunID != "" {
				currentJob.Artifact = &JobArtifact{RunID: jobRunID}
			}
		}
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
	log.Printf("backup_completed job_id=%s kind=%s status=%s policy_revision=%d", jobID, kind, state.Status, state.PolicyRevision)
}
