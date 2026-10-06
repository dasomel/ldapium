package backup

import (
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
			manifest:         &ArtifactManifest{RunID: "run-result-1", Files: manifest.Files},
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
