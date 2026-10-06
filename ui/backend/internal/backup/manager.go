package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
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

	// Seams (D217-17): production defaults, replaced only by tests.
	writer    func(path string, data any) error
	lockProbe LockProbe
	clock     func() time.Time
	after     func(time.Duration) <-chan time.Time
	runWorker func(ctx context.Context, kind, jobID string, stdin []byte) ([]byte, error)

	jobsPath      string
	jobs          []*Job
	jobDirty      bool
	activeJobID   string
	activeJobKind string
	idGen         *JobIDGenerator
	cancelFunc    context.CancelFunc

	// orphanDelay is the current poll backoff while an orphan worker holds the
	// lock; pendingResultDeletes are pruned jobs whose result files may only be
	// removed once the pruned job file is durably written.
	jobTimeouts map[string]time.Duration
	killGrace   time.Duration
	// signalGroup sends a signal to a worker process group (default kill(-pgid)); tests inject a counter.
	signalGroup func(pgid int, sig syscall.Signal) error

	orphanDelay          time.Duration
	pendingResultDeletes []string
}

func New(path, operator, worker, python string) (*Manager, error) {
	return newManager(path, operator, worker, python, nil)
}

// newManager is New with a hook that runs before startup reconciliation, so
// tests can inject the lock probe, clock and worker launcher it depends on.
func newManager(path, operator, worker, python string, configure func(*Manager)) (*Manager, error) {
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
		after:         time.After,
	}
	m.runWorker = m.execWorker
	m.lockProbe = DefaultLockProbe(cfg.Root)
	m.idGen = NewJobIDGenerator(nil, nil, func(id string) bool {
		for _, j := range m.jobs {
			if j.JobID == id {
				return true
			}
		}
		return false
	})
	if configure != nil {
		configure(m)
	}
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

	// Load durable jobs store per D217-3, then converge states, orphans and
	// retention on it (D217-7/14/16).
	loadedJobs, err := loadJobFile(m.jobsPath)
	if err != nil {
		return nil, err
	}
	m.jobs = loadedJobs
	m.startupLocked(m.now())
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
	go m.orphanLoop(ctx)
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
