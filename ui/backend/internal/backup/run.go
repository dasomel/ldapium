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

func (m *Manager) Run(ctx context.Context, kind string) error {
	if kind != "data" && kind != "logs" {
		return fmt.Errorf("backup kind must be data or logs")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		return ErrBusy
	}
	if kind == "logs" && !m.logsAvailable {
		return fmt.Errorf("log sources not registered")
	}
	p := clonePolicy(m.policies.Data)
	if kind == "logs" {
		p = clonePolicy(m.policies.Logs)
	}
	state := m.states[kind]
	state.Status = "running"
	state.LocalVerified = false
	state.LastAttempt = time.Now().UTC()
	state.PolicyRevision = m.policies.Revision
	state.NextRun = state.LastAttempt.Add(time.Duration(p.IntervalMinutes) * time.Minute)
	previous := m.states[kind]
	m.states[kind] = state
	if err := write(m.path, disk{m.policies, m.states, m.connections}); err != nil {
		m.states[kind] = previous
		return err
	}
	m.running = true
	if m.runtimeContext != nil {
		ctx = m.runtimeContext
	}
	go m.execute(ctx, kind, p, append([]Connection{}, m.connections...))
	return nil
}
func (m *Manager) execute(ctx context.Context, kind string, p Policy, connections []Connection) {
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
	if persistErr := write(m.path, disk{m.policies, m.states, m.connections}); persistErr != nil {
		log.Printf("backup_state_persist_failed kind=%s", kind)
	}
	log.Printf("backup_completed kind=%s status=%s policy_revision=%d", kind, state.Status, state.PolicyRevision)
}
