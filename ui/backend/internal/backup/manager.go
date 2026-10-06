package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var ErrConflict = errors.New("backup policy revision conflict")
var ErrBusy = errors.New("backup already running")

type disk struct {
	Policies    Policies         `json:"policies"`
	States      map[string]State `json:"states"`
	Connections []Connection     `json:"connections,omitempty"`
}

type Manager struct {
	connections                    []Connection
	root, instanceID               string
	runtimeContext                 context.Context
	mu                             sync.Mutex
	path, operator, worker, python string
	policies                       Policies
	destinations                   []Destination
	logsAvailable                  bool
	states                         map[string]State
	running                        bool
	started                        bool

	writer        func(path string, data any) error
	lockProbe     LockProbe
	jobsPath      string
	jobs          []*Job
	jobDirty      bool
	activeJobID   string
	activeJobKind string
	idGen         *JobIDGenerator
	cancelFunc    context.CancelFunc
}

func New(path, operator, worker, python string) (*Manager, error) {
	for _, p := range []string{path, operator, worker, python} {
		if !filepath.IsAbs(p) {
			return nil, fmt.Errorf("backup paths must be absolute")
		}
	}
	b, err := os.ReadFile(operator)
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Root         string        `json:"root"`
		InstanceID   string        `json:"instance_id"`
		Destinations []Destination `json:"destinations"`
		LogPaths     []string      `json:"log_paths"`
	}
	if err = json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	local := false
	for _, d := range cfg.Destinations {
		if !safeID.MatchString(d.ID) || seen[d.ID] || d.Name == "" {
			return nil, fmt.Errorf("invalid backup destination")
		}
		seen[d.ID] = true
		switch d.Type {
		case "local":
			if d.ID != "local" {
				return nil, fmt.Errorf("local destination id must be local")
			}
			local = true
		case "s3", "ftp", "ftps", "sftp":
		default:
			return nil, fmt.Errorf("unsupported destination")
		}
	}
	if !local {
		return nil, fmt.Errorf("local destination required")
	}
	m := &Manager{
		root:          cfg.Root,
		instanceID:    cfg.InstanceID,
		path:          path,
		operator:      operator,
		worker:        worker,
		python:        python,
		policies:      defaultPolicies(),
		destinations:  cfg.Destinations,
		logsAvailable: len(cfg.LogPaths) > 0,
		states:        map[string]State{},
		writer:        write,
		jobsPath:      filepath.Join(filepath.Dir(path), "backup-jobs.json"),
		jobs:          []*Job{},
	}
	m.lockProbe = DefaultLockProbe(cfg.Root)
	m.idGen = NewJobIDGenerator(nil, nil, func(id string) bool {
		for _, j := range m.jobs {
			if j.JobID == id {
				return true
			}
		}
		return false
	})
	if b, err = os.ReadFile(path); err == nil {
		var saved disk
		if err = json.Unmarshal(b, &saved); err != nil {
			return nil, err
		}

		m.policies = saved.Policies
		m.states = saved.States
		m.connections = saved.Connections
		for _, c := range m.connections {
			if seen[c.ID] {
				return nil, fmt.Errorf("duplicate backup connection")
			}
			seen[c.ID] = true
			if err := validateConnection(c); err != nil {
				return nil, err
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err = validate(m.policies.Data, m.allDestinations()); err != nil {
		return nil, err
	}
	if err = validate(m.policies.Logs, m.allDestinations()); err != nil {
		return nil, err
	}
	if m.states == nil {
		m.states = map[string]State{}
	}

	// Load durable jobs store per D217-3.
	if loadedJobs, jErr := loadJobFile(m.jobsPath); jErr == nil {
		m.jobs = loadedJobs
	} else {
		return nil, jErr
	}

	// Reconcile any in-flight running jobs per D217-16 / D217-7.
	m.reconcileStartupLocked(time.Now().UTC())

	// Apply retention bounds per D217-14.
	if pruned, _, pErr := pruneJobs(m.jobs, time.Now().UTC(), filepath.Join(m.root, ".results")); pErr == nil {
		m.jobs = pruned
	}

	return m, nil
}
func clonePolicy(p Policy) Policy { p.Destinations = append([]string{}, p.Destinations...); return p }
func (m *Manager) View() View {
	m.mu.Lock()
	defer m.mu.Unlock()
	states := map[string]State{}
	for k, v := range m.states {
		states[k] = v
	}
	p := m.policies
	p.Data = clonePolicy(p.Data)
	p.Logs = clonePolicy(p.Logs)
	return View{Policies: p, Destinations: m.allDestinations(), States: states, Running: m.running, LogsAvailable: m.logsAvailable, Storage: m.storage(), Connections: publicConnections(m.connections)}
}
func write(path string, data any) error {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".backup-policy-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
func (m *Manager) Save(p Policies, expected uint64) (Policies, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := validate(p.Data, m.allDestinations()); err != nil {
		return p, err
	}
	if err := validate(p.Logs, m.allDestinations()); err != nil {
		return p, err
	}
	if p.Logs.Enabled && !m.logsAvailable {
		return p, fmt.Errorf("operator must register log sources first")
	}
	if m.policies.Revision != expected {
		return p, ErrConflict
	}
	if m.running {
		return p, ErrBusy
	}
	p.Data = clonePolicy(p.Data)
	p.Logs = clonePolicy(p.Logs)
	p.Revision = expected + 1
	next := map[string]State{}
	for k, v := range m.states {
		next[k] = v
	}
	for kind, policy := range map[string]Policy{"data": p.Data, "logs": p.Logs} {
		state := next[kind]
		old := m.policies.Data
		if kind == "logs" {
			old = m.policies.Logs
		}
		if !policy.Enabled {
			state.NextRun = time.Time{}
		} else if !old.Enabled || old.IntervalMinutes != policy.IntervalMinutes || state.NextRun.IsZero() {
			state.NextRun = time.Now().UTC().Add(time.Duration(policy.IntervalMinutes) * time.Minute)
		}
		next[kind] = state
	}
	if err := m.writer(m.path, disk{p, next, m.connections}); err != nil {
		return p, err
	}
	m.policies = p
	m.states = next
	return p, nil
}
func (m *Manager) Start(ctx context.Context) {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return
	}
	m.started = true
	m.runtimeContext = ctx
	m.mu.Unlock()
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				m.tick(ctx, now)
			}
		}
	}()
}
func (m *Manager) tick(ctx context.Context, now time.Time) {
	v := m.View()
	if v.Running {
		return
	}
	m.mu.Lock()
	if m.jobDirty {
		if err := m.writer(m.jobsPath, jobFile{Version: 1, Jobs: m.jobs}); err == nil {
			m.jobDirty = false
		}
	}
	m.mu.Unlock()

	for _, kind := range []string{"data", "logs"} {
		p := v.Policies.Data
		if kind == "logs" {
			p = v.Policies.Logs
		}
		state := v.States[kind]
		if p.Enabled && (state.NextRun.IsZero() || !now.Before(state.NextRun)) {
			_ = m.Run(ctx, kind, RunRequest{Trigger: JobTriggerSchedule, RequesterType: JobRequesterScheduler})
			return
		}
	}
}

func (m *Manager) reconcileStartupLocked(now time.Time) {
	hasRunningJob := false
	for _, j := range m.jobs {
		if j.Status != JobStatusRunning {
			continue
		}
		hasRunningJob = true
		lockHeld := false
		if m.lockProbe != nil {
			held, probeErr := m.lockProbe()
			if probeErr != nil {
				log.Printf("worker lock probe error on startup: %v", probeErr)
			} else {
				lockHeld = held
			}
		}

		var resultFile *WorkerResult
		resultPath := filepath.Join(m.root, ".results", j.JobID+".json")
		if rb, rerr := os.ReadFile(resultPath); rerr == nil {
			var wr WorkerResult
			if uerr := json.Unmarshal(rb, &wr); uerr == nil {
				resultFile = &wr
			}
		}

		manifest := findMatchingManifest(m.root, j.Kind, j.JobID, m.instanceID)

		reconciled, decision := ReconcileWithTime(j, lockHeld, resultFile, manifest, now)
		*j = *reconciled

		if decision == DecisionOrphanSuspected {
			m.running = true
			m.activeJobID = j.JobID
			m.activeJobKind = j.Kind
			state := m.states[j.Kind]
			state.Status = "running"
			m.states[j.Kind] = state
		} else {
			state := m.states[j.Kind]
			switch j.Status {
			case JobStatusSucceeded:
				state.Status = "succeeded"
				state.LastSuccess = j.FinishedAt
				if j.Local != nil && j.Local.Verified {
					state.LocalVerified = true
					state.LastLocalSuccess = j.FinishedAt
				}
				if j.Artifact != nil && j.Artifact.RunID != "" {
					state.RunID = j.Artifact.RunID
				}
			case JobStatusFailed:
				state.Status = "failed"
				if j.Local != nil && j.Local.Verified {
					state.LocalVerified = true
					state.LastLocalSuccess = j.FinishedAt
				}
				if j.Artifact != nil && j.Artifact.RunID != "" {
					state.RunID = j.Artifact.RunID
				}
			case JobStatusAbandoned:
				state.Status = "interrupted"
				if j.Local != nil && j.Local.Verified {
					state.LocalVerified = true
					state.LastLocalSuccess = j.FinishedAt
				}
				if j.Artifact != nil && j.Artifact.RunID != "" {
					state.RunID = j.Artifact.RunID
				}
			}
			p := m.policies.Data
			if j.Kind == "logs" {
				p = m.policies.Logs
			}
			if p.Enabled {
				state.NextRun = ScheduleAfterRecovery(m.jobs, j.Kind, p.IntervalMinutes, now)
			}
			m.states[j.Kind] = state
		}
	}

	if !hasRunningJob {
		for kind, state := range m.states {
			if state.Status == "running" {
				state.Status = "interrupted"
				m.states[kind] = state
			}
		}
	}

	if err := m.writer(m.jobsPath, jobFile{Version: 1, Jobs: m.jobs}); err != nil {
		m.jobDirty = true
	}
	if err := m.writer(m.path, disk{m.policies, m.states, m.connections}); err != nil {
		log.Printf("startup state persist failed: %v", err)
	}
}

// ReconcileStartup re-evaluates in-flight jobs against locks and disk artifacts.
func (m *Manager) ReconcileStartup(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if loaded, err := loadJobFile(m.jobsPath); err == nil && len(loaded) > 0 {
		m.jobs = loaded
	}
	m.reconcileStartupLocked(now)
}

func findMatchingManifest(root, kind, jobID, instanceID string) *ArtifactManifest {
	base := filepath.Join(root, kind)
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		if !entry.IsDir() || !runName.MatchString(entry.Name()) {
			continue
		}
		completePath := filepath.Join(base, entry.Name(), "complete.json")
		b, err := os.ReadFile(completePath)
		if err != nil {
			continue
		}
		var raw struct {
			Owner      string            `json:"owner"`
			InstanceID string            `json:"instance_id"`
			Kind       string            `json:"kind"`
			RunID      string            `json:"run_id"`
			JobID      string            `json:"job_id,omitempty"`
			SHA256     map[string]string `json:"sha256,omitempty"`
		}
		if json.Unmarshal(b, &raw) != nil {
			continue
		}
		if raw.Owner != "ldapium-backup-v1" || raw.Kind != kind || (instanceID != "" && raw.InstanceID != instanceID) {
			continue
		}
		if jobID != "" && raw.JobID != jobID {
			continue
		}
		manifest := &ArtifactManifest{
			Owner:      raw.Owner,
			InstanceID: raw.InstanceID,
			Kind:       raw.Kind,
			RunID:      raw.RunID,
			JobID:      raw.JobID,
		}
		for name, sum := range raw.SHA256 {
			filePath := filepath.Join(base, entry.Name(), name)
			var size int64
			if fi, err := os.Stat(filePath); err == nil {
				size = fi.Size()
			}
			manifest.Files = append(manifest.Files, ArtifactManifestFile{
				Name:   name,
				Bytes:  size,
				SHA256: sum,
			})
		}
		return manifest
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

// StartJob creates and starts a new backup job.
func (m *Manager) StartJob(ctx context.Context, req RunRequest) (*Job, error) {
	if err := m.Run(ctx, req.Kind, req); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, j := range m.jobs {
		if j.JobID == m.activeJobID {
			return cloneJob(j), nil
		}
	}
	return nil, nil
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
	target.CancelRequestedAt = time.Now().UTC()
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
