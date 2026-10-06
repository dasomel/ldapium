package backup

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestReconcileTable(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

	manifest := &ArtifactManifest{
		Owner:      "ldapium-backup-v1",
		InstanceID: "inst-1",
		Kind:       "data",
		RunID:      "run-manifest-1",
		Files: []ArtifactManifestFile{
			{Name: "data.ldif.gz", Bytes: 2048, SHA256: "sha256-test"},
		},
	}

	resultSuccess := &WorkerResult{
		RunID:         "run-result-1",
		Kind:          "data",
		Verified:      true,
		LocalVerified: true,
		JobID:         "job-1",
		Destinations: []WorkerDestinationResult{
			{ID: "local", Status: DestStatusSucceeded},
			{ID: "s3", Status: DestStatusSucceeded},
		},
	}

	resultFailed := &WorkerResult{
		RunID:         "run-result-2",
		Kind:          "data",
		Verified:      false,
		LocalVerified: true,
		JobID:         "job-2",
		Destinations: []WorkerDestinationResult{
			{ID: "local", Status: DestStatusSucceeded},
			{ID: "s3", Status: DestStatusFailed, ErrorCode: DestErrCodeTransferFailed},
		},
	}

	tests := []struct {
		name             string
		record           *Job
		lockHeld         bool
		resultFile       *WorkerResult
		manifest         *ArtifactManifest
		expectedDecision ReconcileDecision
		expectedStatus   string
		expectOrphan     bool
		expectError      bool
		expectedErrCode  string
		expectedLocalVer bool
		expectedRunID    string
	}{
		{
			name:             "nil record returns unchanged",
			record:           nil,
			lockHeld:         false,
			expectedDecision: DecisionUnchanged,
		},
		{
			name: "terminal record (succeeded) remains untouched",
			record: &Job{
				JobID:      "job-term",
				Kind:       "data",
				Status:     JobStatusSucceeded,
				FinishedAt: now.Add(-time.Hour),
			},
			lockHeld:         true,
			resultFile:       resultSuccess,
			expectedDecision: DecisionUnchanged,
			expectedStatus:   JobStatusSucceeded,
		},
		{
			name: "terminal record (cancelled) remains untouched",
			record: &Job{
				JobID:      "job-term-2",
				Kind:       "data",
				Status:     JobStatusCancelled,
				FinishedAt: now.Add(-time.Hour),
			},
			lockHeld:         false,
			expectedDecision: DecisionUnchanged,
			expectedStatus:   JobStatusCancelled,
		},
		{
			name: "Row 1: running + lock held -> stays running with orphan_suspected",
			record: &Job{
				JobID:     "job-orphan-live",
				Kind:      "data",
				Status:    JobStatusRunning,
				CreatedAt: now.Add(-10 * time.Minute),
			},
			lockHeld:         true,
			resultFile:       nil,
			manifest:         nil,
			expectedDecision: DecisionOrphanSuspected,
			expectedStatus:   JobStatusRunning,
			expectOrphan:     true,
		},
		{
			name: "Row 2: running + lock free + result file verified=true -> succeeded",
			record: &Job{
				JobID:     "job-res-ok",
				Kind:      "data",
				Status:    JobStatusRunning,
				CreatedAt: now.Add(-10 * time.Minute),
			},
			lockHeld:         false,
			resultFile:       resultSuccess,
			manifest:         manifest,
			expectedDecision: DecisionSettledResult,
			expectedStatus:   JobStatusSucceeded,
			expectOrphan:     false,
			expectError:      false,
			expectedLocalVer: true,
			expectedRunID:    "run-result-1",
		},
		{
			name: "Row 3: running + lock free + result file verified=false -> failed",
			record: &Job{
				JobID:     "job-res-fail",
				Kind:      "data",
				Status:    JobStatusRunning,
				CreatedAt: now.Add(-10 * time.Minute),
			},
			lockHeld:         false,
			resultFile:       resultFailed,
			manifest:         nil,
			expectedDecision: DecisionSettledResult,
			expectedStatus:   JobStatusFailed,
			expectOrphan:     false,
			expectError:      true,
			expectedErrCode:  ErrCodeWorkerFailed,
			expectedLocalVer: true,
			expectedRunID:    "run-result-2",
		},
		{
			name: "Row 4: running + lock free + no result file + manifest present -> abandoned with artifact",
			record: &Job{
				JobID:     "job-mani-only",
				Kind:      "data",
				Status:    JobStatusRunning,
				CreatedAt: now.Add(-10 * time.Minute),
				Destinations: []JobDestination{
					{ID: "local", Status: DestStatusSucceeded},
				},
			},
			lockHeld:         false,
			resultFile:       nil,
			manifest:         manifest,
			expectedDecision: DecisionSettledManifest,
			expectedStatus:   JobStatusAbandoned,
			expectOrphan:     false,
			expectError:      true,
			expectedErrCode:  ErrCodeAbandoned,
			expectedLocalVer: true,
			expectedRunID:    "run-manifest-1",
		},
		{
			name: "Row 5: running + lock free + no result file + no manifest -> abandoned without artifact",
			record: &Job{
				JobID:     "job-none-ab",
				Kind:      "data",
				Status:    JobStatusRunning,
				CreatedAt: now.Add(-10 * time.Minute),
				Destinations: []JobDestination{
					{ID: "local", Status: DestStatusSucceeded},
				},
			},
			lockHeld:         false,
			resultFile:       nil,
			manifest:         nil,
			expectedDecision: DecisionSettledNone,
			expectedStatus:   JobStatusAbandoned,
			expectOrphan:     false,
			expectError:      true,
			expectedErrCode:  ErrCodeAbandoned,
			expectedLocalVer: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reconciled, decision := ReconcileWithTime(tt.record, tt.lockHeld, tt.resultFile, tt.manifest, now)
			if decision != tt.expectedDecision {
				t.Fatalf("decision = %v; want %v", decision, tt.expectedDecision)
			}
			if tt.record == nil {
				if reconciled != nil {
					t.Fatalf("expected nil reconciled job, got %+v", reconciled)
				}
				return
			}

			if reconciled.Status != tt.expectedStatus {
				t.Errorf("status = %q; want %q", reconciled.Status, tt.expectedStatus)
			}
			if reconciled.OrphanSuspected != tt.expectOrphan {
				t.Errorf("orphan_suspected = %v; want %v", reconciled.OrphanSuspected, tt.expectOrphan)
			}
			if tt.expectError {
				if reconciled.Error == nil {
					t.Fatal("expected error object, got nil")
				}
				if reconciled.Error.Code != tt.expectedErrCode {
					t.Errorf("error code = %q; want %q", reconciled.Error.Code, tt.expectedErrCode)
				}
				if reconciled.Error.Message != ErrorMessage(tt.expectedErrCode) {
					t.Errorf("error message mismatch: got %q, want %q", reconciled.Error.Message, ErrorMessage(tt.expectedErrCode))
				}
			} else if tt.expectedStatus == JobStatusSucceeded {
				if reconciled.Error != nil {
					t.Errorf("expected nil error on success, got %+v", reconciled.Error)
				}
			}
			if tt.expectedLocalVer {
				if reconciled.Local == nil || !reconciled.Local.Verified {
					t.Errorf("expected local.verified = true, got %+v", reconciled.Local)
				}
			}
			if tt.expectedRunID != "" {
				if reconciled.Artifact == nil || reconciled.Artifact.RunID != tt.expectedRunID {
					t.Errorf("expected runID = %q, got %+v", tt.expectedRunID, reconciled.Artifact)
				}
			}
		})
	}
}

func TestShouldCatchUpAndScheduleAfterRecovery(t *testing.T) {
	now := time.Date(2026, 10, 6, 14, 0, 0, 0, time.UTC)
	const intervalMinutes = 60

	t.Run("suppresses catch-up when last 3 jobs of kind were abandoned (crash-loop guard)", func(t *testing.T) {
		jobs := []*Job{
			{JobID: "1", Kind: "data", Status: JobStatusSucceeded},
			{JobID: "2", Kind: "data", Status: JobStatusAbandoned},
			{JobID: "3", Kind: "data", Status: JobStatusAbandoned},
			{JobID: "4", Kind: "data", Status: JobStatusAbandoned},
		}

		if ShouldCatchUp(jobs, "data") {
			t.Error("ShouldCatchUp should be false for 3 consecutive abandoned jobs")
		}

		next := ScheduleAfterRecovery(jobs, "data", intervalMinutes, now)
		expected := now.Add(time.Duration(intervalMinutes) * time.Minute)
		if !next.Equal(expected) {
			t.Errorf("next_run = %v; want %v (postponed by interval)", next, expected)
		}
	})

	t.Run("allows catch-up when at least one recent job succeeded or failed", func(t *testing.T) {
		jobs := []*Job{
			{JobID: "1", Kind: "data", Status: JobStatusAbandoned},
			{JobID: "2", Kind: "data", Status: JobStatusSucceeded},
			{JobID: "3", Kind: "data", Status: JobStatusAbandoned},
			{JobID: "4", Kind: "data", Status: JobStatusAbandoned},
		}

		if !ShouldCatchUp(jobs, "data") {
			t.Error("ShouldCatchUp should be true when not all 3 are abandoned")
		}

		next := ScheduleAfterRecovery(jobs, "data", intervalMinutes, now)
		if !next.Equal(now) {
			t.Errorf("next_run = %v; want %v (immediate catch-up)", next, now)
		}
	})

	t.Run("allows catch-up when fewer than 3 terminal jobs exist", func(t *testing.T) {
		jobs := []*Job{
			{JobID: "1", Kind: "data", Status: JobStatusAbandoned},
			{JobID: "2", Kind: "data", Status: JobStatusAbandoned},
		}

		if !ShouldCatchUp(jobs, "data") {
			t.Error("ShouldCatchUp should be true with only 2 jobs")
		}
		next := ScheduleAfterRecovery(jobs, "data", intervalMinutes, now)
		if !next.Equal(now) {
			t.Errorf("next_run = %v; want %v", next, now)
		}
	})

	t.Run("filters by kind properly", func(t *testing.T) {
		jobs := []*Job{
			{JobID: "1", Kind: "logs", Status: JobStatusAbandoned},
			{JobID: "2", Kind: "logs", Status: JobStatusAbandoned},
			{JobID: "3", Kind: "logs", Status: JobStatusAbandoned},
			{JobID: "4", Kind: "data", Status: JobStatusSucceeded},
		}

		// logs is in crash-loop guard
		if ShouldCatchUp(jobs, "logs") {
			t.Error("logs ShouldCatchUp should be false")
		}
		// data is healthy
		if !ShouldCatchUp(jobs, "data") {
			t.Error("data ShouldCatchUp should be true")
		}
	})
}

func TestScheduleAfterWorkerBusy(t *testing.T) {
	now := time.Date(2026, 10, 6, 14, 0, 0, 0, time.UTC)
	const intervalMinutes = 120

	// Attempts 0 through 9: retry after 60 seconds
	for i := 0; i < 10; i++ {
		next := ScheduleAfterWorkerBusy(i, intervalMinutes, now)
		expected := now.Add(60 * time.Second)
		if !next.Equal(expected) {
			t.Errorf("consecutiveBusy %d: next = %v; want %v (60s)", i, next, expected)
		}
	}

	// Attempts 10+: back off to policy interval
	for _, attempts := range []int{10, 15, 20} {
		next := ScheduleAfterWorkerBusy(attempts, intervalMinutes, now)
		expected := now.Add(time.Duration(intervalMinutes) * time.Minute)
		if !next.Equal(expected) {
			t.Errorf("consecutiveBusy %d: next = %v; want %v (interval)", attempts, next, expected)
		}
	}
}

func TestDefaultLockProbe(t *testing.T) {
	dir := t.TempDir()
	probe := DefaultLockProbe(dir)

	// Case 1: Lock not held
	held, err := probe()
	if err != nil {
		t.Fatalf("probe error: %v", err)
	}
	if held {
		t.Fatal("expected held = false on unlocked file")
	}

	// Case 2: Hold lock externally with flock
	lockFile := filepath.Join(dir, ".worker.lock")
	f, err := os.OpenFile(lockFile, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("failed to acquire test flock: %v", err)
	}

	held, err = probe()
	if err != nil {
		t.Fatalf("probe error: %v", err)
	}
	if !held {
		t.Fatal("expected held = true when flock is held")
	}

	// Case 3: Release lock
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatalf("failed to unlock test flock: %v", err)
	}

	held, err = probe()
	if err != nil {
		t.Fatalf("probe error: %v", err)
	}
	if held {
		t.Fatal("expected held = false after release")
	}
}

func TestStartupReconciliationLifecycle(t *testing.T) {
	t.Run("orphan worker holding lock keeps running state with orphan_suspected", func(t *testing.T) {
		m := testManager(t)
		defer func() {
			m.mu.Lock()
			m.running = false
			m.mu.Unlock()
		}()
		now := time.Now().UTC()

		// Simulate pre-existing running job in backup-jobs.json
		runningJob := &Job{
			JobID:     "job-20261006T150000Z-111111111111",
			Kind:      "data",
			Status:    JobStatusRunning,
			CreatedAt: now.Add(-5 * time.Minute),
		}
		if err := write(m.jobsPath, jobFile{Version: 1, Jobs: []*Job{runningJob}}); err != nil {
			t.Fatal(err)
		}

		// Inject lockProbe returning held=true (simulating alive orphan worker)
		m.SetLockProbe(func() (bool, error) { return true, nil })

		m.ReconcileStartup(now)

		job, err := m.GetJob(runningJob.JobID)
		if err != nil {
			t.Fatal(err)
		}
		if job.Status != JobStatusRunning {
			t.Errorf("status = %q; want running", job.Status)
		}
		if !job.OrphanSuspected {
			t.Error("expected orphan_suspected = true")
		}

		jobID, kind, isRunning := m.ActiveJobInfo()
		if !isRunning || jobID != runningJob.JobID || kind != "data" {
			t.Errorf("unexpected active job info: running=%v, id=%s, kind=%s", isRunning, jobID, kind)
		}
	})

	t.Run("orphan worker finished and left result file settles outcome", func(t *testing.T) {
		m := testManager(t)
		now := time.Now().UTC()

		jobID := "job-20261006T150000Z-222222222222"
		runningJob := &Job{
			JobID:     jobID,
			Kind:      "data",
			Status:    JobStatusRunning,
			CreatedAt: now.Add(-5 * time.Minute),
		}
		if err := write(m.jobsPath, jobFile{Version: 1, Jobs: []*Job{runningJob}}); err != nil {
			t.Fatal(err)
		}

		m.root = filepath.Join(filepath.Dir(m.path), "backup-root")
		// Write worker result file in <root>/.results/<jobID>.json
		resultsDir := filepath.Join(m.root, ".results")
		_ = os.MkdirAll(resultsDir, 0700)
		resData, _ := json.Marshal(WorkerResult{
			RunID:         "20261006T150000Z-000000000001",
			Kind:          "data",
			Verified:      true,
			LocalVerified: true,
			JobID:         jobID,
		})
		_ = os.WriteFile(filepath.Join(resultsDir, jobID+".json"), resData, 0600)

		// Lock probe returns lock free
		m.SetLockProbe(func() (bool, error) { return false, nil })

		m.ReconcileStartup(now)

		job, err := m.GetJob(jobID)
		if err != nil {
			t.Fatal(err)
		}
		if job.Status != JobStatusSucceeded {
			t.Errorf("status = %q; want succeeded", job.Status)
		}
		if job.OrphanSuspected {
			t.Error("expected orphan_suspected = false")
		}
		if job.Artifact == nil || job.Artifact.RunID != "20261006T150000Z-000000000001" {
			t.Errorf("unexpected artifact: %+v", job.Artifact)
		}

		// Memory running flag must be cleared
		_, _, isRunning := m.ActiveJobInfo()
		if isRunning {
			t.Error("expected isRunning = false after settlement")
		}
	})

	t.Run("lock probe error does not panic or crash controller", func(t *testing.T) {
		m := testManager(t)
		now := time.Now().UTC()

		runningJob := &Job{
			JobID:     "job-20261006T150000Z-333333333333",
			Kind:      "data",
			Status:    JobStatusRunning,
			CreatedAt: now.Add(-5 * time.Minute),
		}
		if err := write(m.jobsPath, jobFile{Version: 1, Jobs: []*Job{runningJob}}); err != nil {
			t.Fatal(err)
		}

		// Inject failing probe
		m.SetLockProbe(func() (bool, error) { return false, errors.New("io error on probe") })

		// Must not panic
		m.ReconcileStartup(now)

		job, err := m.GetJob(runningJob.JobID)
		if err != nil {
			t.Fatal(err)
		}
		// Since probe error means lock not verified held, and no result/manifest, it settles as abandoned
		if job.Status != JobStatusAbandoned {
			t.Errorf("status = %q; want abandoned", job.Status)
		}
	})
}
