package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"time"
)

// Orphan polling backoff per D217-16: 5s doubling up to 30s.
const (
	orphanPollMin = 5 * time.Second
	orphanPollMax = 30 * time.Second
)

// nextOrphanDelay is the backoff schedule: 5s, 10s, 20s, 30s, 30s, ...
func nextOrphanDelay(prev time.Duration) time.Duration {
	if prev < orphanPollMin {
		return orphanPollMin
	}
	if next := prev * 2; next < orphanPollMax {
		return next
	}
	return orphanPollMax
}

func (m *Manager) now() time.Time {
	if m.clock != nil {
		return m.clock()
	}
	return time.Now().UTC()
}

func startedOf(j *Job) time.Time {
	if !j.StartedAt.IsZero() {
		return j.StartedAt
	}
	return j.CreatedAt
}

func (m *Manager) policyFor(kind string) Policy {
	if kind == "logs" {
		return m.policies.Logs
	}
	return m.policies.Data
}

func stateStatusFor(jobStatus string) string {
	if jobStatus == JobStatusAbandoned {
		return "interrupted"
	}
	return jobStatus
}

// foldJobIntoState applies a terminal job record to the per-kind State. The job
// file is the authority (D217-3/17); State is a derived view of it.
func foldJobIntoState(st State, j *Job) State {
	st.LastAttempt = startedOf(j)
	st.PolicyRevision = j.PolicyRevision
	st.Status = stateStatusFor(j.Status)
	st.LocalVerified = j.Local != nil && j.Local.Verified
	if st.LocalVerified {
		st.LastLocalSuccess = j.FinishedAt
	}
	if j.Artifact != nil && j.Artifact.RunID != "" {
		st.RunID = j.Artifact.RunID
	}
	if j.Status == JobStatusSucceeded && j.FinishedAt.After(st.LastSuccess) {
		st.LastSuccess = j.FinishedAt
	}
	return st
}

// restoreStatesLocked re-derives State from terminal job records when the job
// write succeeded but the State write failed or never ran (the process died in
// between). A job is newer than State exactly when it started after the
// State's recorded last attempt, because a completed State write stores the
// job's own start time there.
func (m *Manager) restoreStatesLocked() {
	for _, kind := range []string{"data", "logs"} {
		var latest, latestOK *Job
		for _, j := range m.jobs {
			if j.Kind != kind || j.Status == JobStatusRunning {
				continue
			}
			latest = j
			if j.Status == JobStatusSucceeded {
				latestOK = j
			}
		}
		if latest == nil {
			continue
		}
		st := m.states[kind]
		if startedOf(latest).After(st.LastAttempt) {
			st = foldJobIntoState(st, latest)
			if p := m.policyFor(kind); p.Enabled && !latest.FinishedAt.IsZero() {
				st.NextRun = latest.FinishedAt.Add(time.Duration(p.IntervalMinutes) * time.Minute)
				if latest.Error != nil && latest.Error.Code == ErrCodeWorkerBusy {
					st.NextRun = latest.FinishedAt.Add(60 * time.Second)
				}
			}
		}
		if latestOK != nil && latestOK.FinishedAt.After(st.LastSuccess) {
			st.LastSuccess = latestOK.FinishedAt
		}
		m.states[kind] = st
	}
}

// startupLocked converges persisted jobs and State at process start: restore
// State from the job file, reconcile jobs left running, apply retention, and
// persist only what changed (job file first, then State: D217-17).
func (m *Manager) startupLocked(now time.Time) {
	before := map[string]State{}
	for k, v := range m.states {
		before[k] = v
	}
	jobsBefore := len(m.jobs)
	m.restoreStatesLocked()

	latestRunning := -1
	for i, j := range m.jobs {
		if j.Status == JobStatusRunning {
			latestRunning = i
		}
	}
	jobsChanged := false
	for i, j := range m.jobs {
		if j.Status != JobStatusRunning {
			continue
		}
		jobsChanged = true
		// Only the newest running record can own the worker lock: single-flight.
		m.reconcileJobLocked(j, now, i == latestRunning)
	}
	if latestRunning < 0 && !m.running {
		for kind, state := range m.states {
			if state.Status == "running" {
				state.Status = "interrupted"
				m.states[kind] = state
			}
		}
	}

	m.pruneLocked(now)
	if jobsChanged || len(m.jobs) != jobsBefore || m.jobDirty {
		m.persistJobsLocked()
	}
	if !reflect.DeepEqual(before, m.states) {
		m.persistStateLocked()
	}
}

func (m *Manager) pruneLocked(now time.Time) {
	if pruned, ids := pruneJobs(m.jobs, now); len(ids) > 0 {
		m.jobs = pruned
		m.pendingResultDeletes = append(m.pendingResultDeletes, ids...)
		m.jobDirty = true
	}
}

// commitJobsLocked writes next as the whole job file and adopts it only if the
// write succeeded. Result files of pruned jobs are removed only after that.
func (m *Manager) commitJobsLocked(next []*Job) error {
	if err := m.writer(m.jobsPath, jobFile{Version: 1, Jobs: next}); err != nil {
		return err
	}
	m.jobs = next
	m.jobDirty = false
	removeResultFiles(filepath.Join(m.root, ".results"), m.pendingResultDeletes)
	m.pendingResultDeletes = nil
	return nil
}

// persistJobsLocked writes the in-memory job list; a failure leaves it dirty
// for the next tick or write (D217-17).
func (m *Manager) persistJobsLocked() bool {
	if err := m.commitJobsLocked(m.jobs); err != nil {
		m.jobDirty = true
		return false
	}
	return true
}

func (m *Manager) persistStateLocked() {
	if err := m.writer(m.path, disk{m.policies, m.states, m.connections}); err != nil {
		log.Print("backup_state_persist_failed")
	}
}

type resultStatus int

const (
	resultAbsent resultStatus = iota
	resultOK
	resultInvalid
)

// readWorkerResult loads <root>/.results/<job_id>.json for j. Anything that is
// present but not a bounded, regular, schema-valid result for this very job is
// resultInvalid, never settled as a worker outcome.
func (m *Manager) readWorkerResult(j *Job) (*WorkerResult, resultStatus) {
	if m.root == "" || !IsValidJobID(j.JobID) {
		return nil, resultAbsent
	}
	dir := filepath.Join(m.root, ".results")
	info, err := os.Lstat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, resultAbsent
		}
		return nil, resultInvalid
	}
	if !info.IsDir() {
		return nil, resultInvalid
	}
	b, err := readRegularFile(filepath.Join(dir, j.JobID+".json"), maxResultBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, resultAbsent
		}
		return nil, resultInvalid
	}
	var wr WorkerResult
	if json.Unmarshal(b, &wr) != nil {
		return nil, resultInvalid
	}
	if err := validateWorkerResult(&wr, j); err != nil {
		return nil, resultInvalid
	}
	return &wr, resultOK
}

// reconcileJobLocked settles or keeps one running record from disk evidence
// (D217-7/16). A held or unprobeable worker lock keeps it running as
// orphan_suspected, with m.running set so new runs and policy saves stay blocked
// and catch-up is deferred; any settlement clears running and the active job
// before catch-up is scheduled.
func (m *Manager) reconcileJobLocked(j *Job, now time.Time, mayOwnLock bool) ReconcileDecision {
	var ev ReconcileEvidence
	if mayOwnLock && m.lockProbe != nil {
		held, err := m.lockProbe()
		ev.LockHeld = err == nil && held
		ev.ProbeError = err != nil
	}
	if !ev.LockHeld && !ev.ProbeError {
		var rs resultStatus
		ev.Result, rs = m.readWorkerResult(j)
		ev.ResultInvalid = rs == resultInvalid
		ev.Manifest = findMatchingManifest(m.root, j.Kind, j.JobID, m.instanceID)
	}

	reconciled, decision := ReconcileEvidenceWithTime(j, ev, now)
	*j = *reconciled

	if decision == DecisionOrphanSuspected {
		m.running = true
		m.activeJobID = j.JobID
		m.activeJobKind = j.Kind
		st := m.states[j.Kind]
		st.Status = "running"
		m.states[j.Kind] = st
		if !j.DeadlineAt.IsZero() && now.After(j.DeadlineAt) {
			log.Printf("backup_orphan_past_deadline job_id=%s kind=%s", j.JobID, j.Kind)
		}
		log.Printf("backup_orphan_suspected job_id=%s kind=%s reason=%s", j.JobID, j.Kind, j.OrphanReason)
		return decision
	}

	if m.activeJobID == j.JobID {
		m.running = false
		m.activeJobID = ""
		m.activeJobKind = ""
	}
	st := foldJobIntoState(m.states[j.Kind], j)
	if p := m.policyFor(j.Kind); p.Enabled {
		st.NextRun = ScheduleAfterRecovery(m.jobs, j.Kind, p.IntervalMinutes, now)
	}
	m.states[j.Kind] = st
	log.Printf("backup_abandoned_or_settled job_id=%s kind=%s status=%s decision=%s", j.JobID, j.Kind, j.Status, decision)
	return decision
}

// orphanStep re-probes the active orphan once. It returns the delay before the
// next poll and whether polling must continue.
func (m *Manager) orphanStep(now time.Time) (time.Duration, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j := m.activeOrphanLocked()
	if j == nil {
		return 0, false
	}
	prevReason := j.OrphanReason
	if m.reconcileJobLocked(j, now, true) == DecisionOrphanSuspected {
		if j.OrphanReason != prevReason {
			m.persistJobsLocked()
		}
		m.orphanDelay = nextOrphanDelay(m.orphanDelay)
		return m.orphanDelay, true
	}
	m.orphanDelay = 0
	m.pruneLocked(now)
	m.persistJobsLocked()
	m.persistStateLocked()
	return 0, false
}

func (m *Manager) activeOrphanLocked() *Job {
	if !m.running || m.activeJobID == "" {
		return nil
	}
	for _, j := range m.jobs {
		if j.JobID == m.activeJobID && j.Status == JobStatusRunning && j.OrphanSuspected {
			return j
		}
	}
	return nil
}

// orphanLoop polls an orphan worker's lock with backoff until it is settled or
// ctx (process shutdown) ends. It returns immediately when there is no orphan.
func (m *Manager) orphanLoop(ctx context.Context) {
	m.mu.Lock()
	ok := m.activeOrphanLocked() != nil
	if ok {
		m.orphanDelay = nextOrphanDelay(0)
	}
	delay := m.orphanDelay
	m.mu.Unlock()
	for ok {
		select {
		case <-ctx.Done():
			return
		case <-m.after(delay):
		}
		delay, ok = m.orphanStep(m.now())
	}
}

func (m *Manager) tick(ctx context.Context, now time.Time) {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	if m.jobDirty {
		m.persistJobsLocked()
	}
	due := ""
	for _, kind := range []string{"data", "logs"} {
		state := m.states[kind]
		if p := m.policyFor(kind); p.Enabled && (state.NextRun.IsZero() || !now.Before(state.NextRun)) {
			due = kind
			break
		}
	}
	m.mu.Unlock()
	if due != "" {
		_, _ = m.StartJob(ctx, RunRequest{Kind: due, Trigger: JobTriggerSchedule, RequesterType: JobRequesterScheduler})
	}
}

// findMatchingManifest returns the owned complete.json that carries jobID. It
// never reads outside an owned run directory (readOwnedManifest) and keeps only
// flat file names backed by regular files inside it (artifactFiles).
func findMatchingManifest(root, kind, jobID, instanceID string) *ArtifactManifest {
	if root == "" || !IsValidJobID(jobID) {
		return nil
	}
	base := filepath.Join(root, kind)
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		raw, dir, ok := readOwnedManifest(base, entry.Name(), kind, instanceID)
		if !ok || raw.JobID != jobID {
			continue
		}
		return &ArtifactManifest{
			Owner:      raw.Owner,
			InstanceID: raw.InstanceID,
			Kind:       raw.Kind,
			RunID:      raw.RunID,
			JobID:      raw.JobID,
			Files:      artifactFiles(dir, raw.SHA256),
		}
	}
	return nil
}

// Jobs returns a list of jobs matching filters, ordered newest first.
func (m *Manager) Jobs(kind, status string, limit int) []*Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	var filtered []*Job
	for i := len(m.jobs) - 1; i >= 0; i-- {
		j := m.jobs[i]
		if kind != "" && j.Kind != kind {
			continue
		}
		if status != "" && j.Status != status {
			continue
		}
		filtered = append(filtered, cloneJob(j))
		if len(filtered) >= limit {
			break
		}
	}
	return filtered
}

// GetJob returns a single job by ID.
func (m *Manager) GetJob(id string) (*Job, error) {
	if !IsValidJobID(id) {
		return nil, &JobNotFoundError{JobID: id}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, j := range m.jobs {
		if j.JobID == id {
			return cloneJob(j), nil
		}
	}
	return nil, &JobNotFoundError{JobID: id}
}

// ActiveJob returns the currently executing job, or nil.
func (m *Manager) ActiveJob() *Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.running || m.activeJobID == "" {
		return nil
	}
	for _, j := range m.jobs {
		if j.JobID == m.activeJobID {
			return cloneJob(j)
		}
	}
	return nil
}

// ActiveJobInfo returns correlation info for the currently running job.
func (m *Manager) ActiveJobInfo() (jobID string, kind string, running bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.activeJobID, m.activeJobKind, m.running
}

// Run starts a manual backup. It keeps the pre-#217 contract: ErrBusy itself
// (not the typed BusyError) when a job is active. Callers that need the job or
// the active job's ID use StartJob.
func (m *Manager) Run(ctx context.Context, kind string) error {
	_, err := m.StartJob(ctx, RunRequest{Kind: kind})
	var busy *BusyError
	if errors.As(err, &busy) {
		return ErrBusy
	}
	return err
}

// StartJob creates the job record and starts its worker in one critical
// section and returns that exact record (a copy). Errors are typed:
// *BusyError (carries the active job ID), *PersistenceUnavailableError.
func (m *Manager) StartJob(ctx context.Context, req RunRequest) (*Job, error) {
	if req.Kind != "data" && req.Kind != "logs" {
		return nil, fmt.Errorf("backup kind must be data or logs")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		return nil, &BusyError{ActiveJobID: m.activeJobID, ActiveKind: m.activeJobKind}
	}
	if m.lockProbe != nil {
		held, err := m.lockProbe()
		if err != nil {
			// The worker's own flock stays authoritative (a raced start exits 75
			// and becomes worker_busy), so an unprobeable lock does not block
			// starting; it is surfaced in the log only.
			log.Print("backup_start_lock_probe_error")
		} else if held {
			return nil, &BusyError{ActiveJobID: m.activeJobID, ActiveKind: m.activeJobKind}
		}
	}
	if req.Kind == "logs" && !m.logsAvailable {
		return nil, fmt.Errorf("log sources not registered")
	}
	kind := req.Kind
	if req.Trigger != JobTriggerSchedule {
		req.Trigger = JobTriggerManual
	}
	if req.Trigger == JobTriggerSchedule {
		req.RequesterType = JobRequesterScheduler
	} else {
		req.RequesterType = JobRequesterUser
	}
	// Requester identity is a one-way fingerprint and the request ID a plain
	// token; anything else (a DN, a path) is dropped rather than persisted.
	if !jobFingerprintRe.MatchString(req.ActorFingerprint) || req.RequesterType == JobRequesterScheduler {
		req.ActorFingerprint = ""
	}
	if !jobRequestIDRe.MatchString(req.RequestID) {
		req.RequestID = ""
	}

	jobID, err := m.idGen.Generate()
	if err != nil {
		return nil, fmt.Errorf("generating job id: %w", err)
	}

	now := m.now()
	p := clonePolicy(m.policyFor(kind))
	job := &Job{
		JobID:          jobID,
		Kind:           kind,
		Trigger:        req.Trigger,
		Status:         JobStatusRunning,
		RequestedBy:    JobRequester{Type: req.RequesterType, Fingerprint: req.ActorFingerprint},
		RequestID:      req.RequestID,
		PolicyRevision: m.policies.Revision,
		CreatedAt:      now,
		StartedAt:      now,
		StagingCleanup: StagingCleanupNotApplicable,
	}

	// Step 1 of D217-17: persist the running record before the worker starts.
	if err := m.commitJobsLocked(append(append([]*Job{}, m.jobs...), job)); err != nil {
		return nil, &PersistenceUnavailableError{Err: err}
	}
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
	return cloneJob(job), nil
}

// CancelJob requests cancellation of a running backup job per D217-5 and D217-17.
func (m *Manager) CancelJob(id string) (*Job, error) {
	if !IsValidJobID(id) {
		return nil, &JobNotFoundError{JobID: id}
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	var target *Job
	for _, j := range m.jobs {
		if j.JobID == id {
			target = j
			break
		}
	}
	if target == nil {
		return nil, &JobNotFoundError{JobID: id}
	}
	if target.Status == JobStatusCancelled {
		return cloneJob(target), nil
	}
	if target.Status != JobStatusRunning {
		return nil, &JobNotCancellableError{JobID: id, Status: target.Status}
	}

	prevCancel := target.CancelRequestedAt
	target.CancelRequestedAt = m.now()
	if err := m.writer(m.jobsPath, jobFile{Version: 1, Jobs: m.jobs}); err != nil {
		target.CancelRequestedAt = prevCancel
		return nil, &PersistenceUnavailableError{Err: err}
	}

	if m.cancelFunc != nil {
		m.cancelFunc()
	}
	return cloneJob(target), nil
}

// SetWriter overrides the atomic persistence writer (for failure testing).
func (m *Manager) SetWriter(w func(string, any) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if w == nil {
		m.writer = write
	} else {
		m.writer = w
	}
}

// SetLockProbe overrides the worker lock probe (for startup/contention testing).
func (m *Manager) SetLockProbe(probe LockProbe) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lockProbe = probe
}

// SetIDGenerator overrides the job ID generator (for collision testing).
func (m *Manager) SetIDGenerator(gen *JobIDGenerator) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.idGen = gen
}
