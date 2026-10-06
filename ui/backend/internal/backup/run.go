package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

func (m *Manager) Run(ctx context.Context, kind string, req ...RunRequest) error {
	if kind != "data" && kind != "logs" {
		return fmt.Errorf("backup kind must be data or logs")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		if len(req) > 0 {
			return &BusyError{ActiveJobID: m.activeJobID, ActiveKind: m.activeJobKind}
		}
		return ErrBusy
	}
	if m.lockProbe != nil {
		if held, err := m.lockProbe(); err == nil && held {
			if len(req) > 0 {
				return &BusyError{ActiveJobID: m.activeJobID, ActiveKind: m.activeJobKind}
			}
			return ErrBusy
		}
	}
	if kind == "logs" && !m.logsAvailable {
		return fmt.Errorf("log sources not registered")
	}

	var r RunRequest
	if len(req) > 0 {
		r = req[0]
	}
	if r.Kind == "" {
		r.Kind = kind
	}
	if r.Trigger == "" {
		r.Trigger = JobTriggerManual
	}
	if r.RequesterType == "" {
		if r.Trigger == JobTriggerSchedule {
			r.RequesterType = JobRequesterScheduler
		} else {
			r.RequesterType = JobRequesterUser
		}
	}

	jobID, err := m.idGen.Generate()
	if err != nil {
		return fmt.Errorf("generating job id: %w", err)
	}

	now := time.Now().UTC()
	p := clonePolicy(m.policies.Data)
	if kind == "logs" {
		p = clonePolicy(m.policies.Logs)
	}

	job := &Job{
		JobID:   jobID,
		Kind:    kind,
		Trigger: r.Trigger,
		Status:  JobStatusRunning,
		RequestedBy: JobRequester{
			Type:        r.RequesterType,
			Fingerprint: r.ActorFingerprint,
		},
		RequestID:      r.RequestID,
		PolicyRevision: m.policies.Revision,
		CreatedAt:      now,
		StartedAt:      now,
		StagingCleanup: StagingCleanupNotApplicable,
	}

	// Step ① of D217-17: Persist running job to backup-jobs.json before starting worker.
	nextJobs := append(append([]*Job{}, m.jobs...), job)
	if err := m.writer(m.jobsPath, jobFile{Version: 1, Jobs: nextJobs}); err != nil {
		return &PersistenceUnavailableError{Err: err}
	}

	m.jobs = nextJobs
	m.jobDirty = false
	m.running = true
	m.activeJobID = jobID
	m.activeJobKind = kind

	state := m.states[kind]
	state.Status = "running"
	state.LocalVerified = false
	state.LastAttempt = now
	state.PolicyRevision = m.policies.Revision
	state.NextRun = now.Add(time.Duration(p.IntervalMinutes) * time.Minute)
	m.states[kind] = state

	runCtx := ctx
	if m.runtimeContext != nil {
		runCtx = m.runtimeContext
	}
	cancelCtx, cancel := context.WithCancel(runCtx)
	m.cancelFunc = cancel
	go m.execute(cancelCtx, kind, p, append([]Connection{}, m.connections...), jobID)
	return nil
}

func (m *Manager) execute(ctx context.Context, kind string, p Policy, connections []Connection, jobID string) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()
	b, _ := json.Marshal(struct {
		Policy
		Connections []Connection `json:"connections"`
	}{p, connections})
	cmd := exec.CommandContext(ctx, m.python, m.worker, "--config", m.operator, "--kind", kind)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.Stdin = bytes.NewReader(b)
	out, err := cmd.Output()
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
	m.states[kind] = state

	finishedAt := time.Now().UTC()
	var currentJob *Job
	for _, j := range m.jobs {
		if j.JobID == jobID {
			currentJob = j
			break
		}
	}
	if currentJob != nil {
		currentJob.FinishedAt = finishedAt
		if !currentJob.CancelRequestedAt.IsZero() {
			currentJob.Status = JobStatusCancelled
			state.Status = "cancelled"
			if decodeErr == nil && result.LocalVerified {
				currentJob.Local = &JobLocal{Verified: true}
			}
			if decodeErr == nil && result.RunID != "" {
				currentJob.Artifact = &JobArtifact{RunID: result.RunID}
			}
		} else if err == nil {
			currentJob.Status = JobStatusSucceeded
			currentJob.Local = &JobLocal{Verified: result.LocalVerified}
			currentJob.Artifact = &JobArtifact{RunID: result.RunID}
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
			if decodeErr == nil && result.RunID != "" {
				currentJob.Artifact = &JobArtifact{RunID: result.RunID}
			}
		}
	}
	if m.activeJobID == jobID {
		m.activeJobID = ""
		m.activeJobKind = ""
	}

	if pruned, _, pErr := pruneJobs(m.jobs, finishedAt, filepath.Join(m.root, ".results")); pErr == nil {
		m.jobs = pruned
	}

	if jobPersistErr := m.writer(m.jobsPath, jobFile{Version: 1, Jobs: m.jobs}); jobPersistErr != nil {
		m.jobDirty = true
	}

	if persistErr := m.writer(m.path, disk{m.policies, m.states, m.connections}); persistErr != nil {
		log.Printf("backup_state_persist_failed kind=%s", kind)
	}
	log.Printf("backup_completed kind=%s status=%s policy_revision=%d", kind, state.Status, state.PolicyRevision)
}
