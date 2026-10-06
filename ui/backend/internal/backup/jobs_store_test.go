package backup

import (
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestJobStoreRoundTripAndFileModes(t *testing.T) {
	dir := t.TempDir()
	storeDir := filepath.Join(dir, "nested", "backups")
	path := filepath.Join(storeDir, "backup-jobs.json")

	now := time.Date(2026, 10, 6, 10, 0, 0, 0, time.UTC)
	testJob := &Job{
		JobID:          "job-20261006T100000Z-abcdef012345",
		Kind:           "data",
		Trigger:        JobTriggerManual,
		Status:         JobStatusSucceeded,
		RequestedBy:    JobRequester{Type: JobRequesterUser, Fingerprint: "0123456789abcdef"},
		RequestID:      "req-1",
		PolicyRevision: 2,
		CreatedAt:      now,
		StartedAt:      now,
		FinishedAt:     now.Add(5 * time.Minute),
		StagingCleanup: StagingCleanupDone,
		Local:          &JobLocal{Verified: true},
		Destinations: []JobDestination{
			{ID: "local", Status: DestStatusSucceeded},
		},
		Artifact: &JobArtifact{
			RunID: "20261006T100000Z-0123456789ab",
			Files: []JobArtifactFile{
				{Name: "data.ldif.gz", Bytes: 1024, SHA256: strings.Repeat("ab", 32)},
			},
		},
	}

	// Write via standard write() helper
	if err := write(path, jobFile{Version: 1, Jobs: []*Job{testJob}}); err != nil {
		t.Fatalf("write() error = %v", err)
	}

	// Check file mode (0600)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("os.Stat(path) error = %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("file mode = %o; want 0600", fi.Mode().Perm())
	}

	// Check directory mode (0700)
	dirFi, err := os.Stat(storeDir)
	if err != nil {
		t.Fatalf("os.Stat(storeDir) error = %v", err)
	}
	if dirFi.Mode().Perm() != 0700 {
		t.Errorf("dir mode = %o; want 0700", dirFi.Mode().Perm())
	}

	// Load back
	loaded, err := loadJobFile(path)
	if err != nil {
		t.Fatalf("loadJobFile error = %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("loaded jobs count = %d; want 1", len(loaded))
	}
	got := loaded[0]
	if got.JobID != testJob.JobID || got.Status != testJob.Status || got.Kind != testJob.Kind {
		t.Errorf("loaded job mismatch: %+v", got)
	}
	if got.Artifact == nil || got.Artifact.RunID != "20261006T100000Z-0123456789ab" || len(got.Artifact.Files) != 1 {
		t.Errorf("artifact not round-tripped properly: %+v", got.Artifact)
	}
}

func TestCorruptJobFileHandling(t *testing.T) {
	t.Run("invalid json triggers quarantine and starts empty", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "backup-jobs.json")
		if err := os.WriteFile(path, []byte("{not valid json..."), 0600); err != nil {
			t.Fatal(err)
		}

		jobs, err := loadJobFile(path)
		if err != nil {
			t.Fatalf("loadJobFile should not fail startup on corrupt file: %v", err)
		}
		if len(jobs) != 0 {
			t.Fatalf("expected empty jobs slice, got %d", len(jobs))
		}

		// Original corrupt file should have been moved
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("original corrupt file %s still exists", path)
		}

		// Quarantined file should exist matching .corrupt-*
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		foundQuarantine := false
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".corrupt-") {
				foundQuarantine = true
				content, _ := os.ReadFile(filepath.Join(dir, e.Name()))
				if string(content) != "{not valid json..." {
					t.Errorf("quarantine file content corrupted: %s", string(content))
				}
				break
			}
		}
		if !foundQuarantine {
			t.Error("quarantine file .corrupt-* not found")
		}
	})

	t.Run("unsupported version triggers quarantine", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "backup-jobs.json")
		if err := os.WriteFile(path, []byte(`{"version":99,"jobs":[]}`), 0600); err != nil {
			t.Fatal(err)
		}

		jobs, err := loadJobFile(path)
		if err != nil {
			t.Fatalf("loadJobFile should not fail on unsupported version: %v", err)
		}
		if len(jobs) != 0 {
			t.Fatalf("expected empty jobs, got %d", len(jobs))
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("original file still exists after quarantine")
		}
	})

	t.Run("non-existent file starts empty", func(t *testing.T) {
		dir := t.TempDir()
		jobs, err := loadJobFile(filepath.Join(dir, "non-existent.json"))
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if len(jobs) != 0 {
			t.Fatalf("expected empty jobs, got %d", len(jobs))
		}
	})
}

func TestPruneJobs(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	resultsDir := filepath.Join(t.TempDir(), ".results")
	if err := os.MkdirAll(resultsDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Result files are removed by job ID path, so labels map to valid IDs.
	idOf := func(label string) string {
		h := fnv.New64a()
		_, _ = h.Write([]byte(label))
		return fmt.Sprintf("job-20261006T120000Z-%012x", h.Sum64()&0xffffffffffff)
	}
	createJob := func(label, kind, status string, finishedAge time.Duration) *Job {
		id := idOf(label)
		finished := now.Add(-finishedAge)
		j := &Job{
			JobID:      id,
			Kind:       kind,
			Status:     status,
			CreatedAt:  finished.Add(-5 * time.Minute),
			FinishedAt: finished,
		}
		if status == JobStatusRunning {
			j.FinishedAt = time.Time{}
		}
		// Write dummy result file
		_ = os.WriteFile(filepath.Join(resultsDir, id+".json"), []byte("{}"), 0600)
		return j
	}

	t.Run("preserves running and most recent succeeded per kind across 90 days", func(t *testing.T) {
		jobs := []*Job{
			createJob("running-old", "data", JobStatusRunning, 100*24*time.Hour),
			createJob("succeeded-old-data", "data", JobStatusSucceeded, 100*24*time.Hour),
			createJob("succeeded-older-data", "data", JobStatusSucceeded, 120*24*time.Hour),
			createJob("succeeded-old-logs", "logs", JobStatusSucceeded, 95*24*time.Hour),
			createJob("failed-old", "data", JobStatusFailed, 91*24*time.Hour),
			createJob("failed-recent", "data", JobStatusFailed, 10*24*time.Hour),
		}

		retained, prunedIDs := pruneJobs(jobs, now)
		// pruneJobs only decides; the caller removes result files after the
		// pruned job file is durably written.
		for _, id := range prunedIDs {
			if _, err := os.Stat(filepath.Join(resultsDir, id+".json")); err != nil {
				t.Fatalf("pruneJobs must not touch result files itself: %v", err)
			}
		}
		removeResultFiles(resultsDir, prunedIDs)

		retainedMap := make(map[string]bool)
		for _, j := range retained {
			retainedMap[j.JobID] = true
		}

		// Must keep running job even if old
		if !retainedMap[idOf("running-old")] {
			t.Error("running-old was pruned")
		}
		// Must keep most recent succeeded per kind even if > 90 days
		if !retainedMap[idOf("succeeded-old-data")] {
			t.Error("succeeded-old-data (most recent succeeded for data) was pruned")
		}
		if !retainedMap[idOf("succeeded-old-logs")] {
			t.Error("succeeded-old-logs (most recent succeeded for logs) was pruned")
		}
		// Must keep recent failed job
		if !retainedMap[idOf("failed-recent")] {
			t.Error("failed-recent was pruned")
		}

		// Older succeeded data job and old failed job must be pruned
		if retainedMap[idOf("succeeded-older-data")] {
			t.Error("succeeded-older-data should have been pruned")
		}
		if retainedMap[idOf("failed-old")] {
			t.Error("failed-old should have been pruned")
		}

		// Result files for pruned jobs must be deleted
		for _, id := range prunedIDs {
			if _, err := os.Stat(filepath.Join(resultsDir, id+".json")); !os.IsNotExist(err) {
				t.Errorf("result file for pruned job %s was not deleted", id)
			}
		}
		// Result files for retained jobs must be kept
		for _, j := range retained {
			if _, err := os.Stat(filepath.Join(resultsDir, j.JobID+".json")); os.IsNotExist(err) {
				t.Errorf("result file for retained job %s was deleted", j.JobID)
			}
		}
	})

	t.Run("enforces 200 record history limit oldest first", func(t *testing.T) {
		var jobs []*Job
		// Create 210 jobs with varying ages (< 90 days)
		for i := 0; i < 210; i++ {
			id := fmt.Sprintf("job-%03d", i)
			jobs = append(jobs, createJob(id, "data", JobStatusFailed, time.Duration(210-i)*time.Hour))
		}

		retained, prunedIDs := pruneJobs(jobs, now)

		if len(retained) != MaxJobHistory {
			t.Fatalf("retained count = %d; want %d", len(retained), MaxJobHistory)
		}
		if len(prunedIDs) != 10 {
			t.Fatalf("prunedIDs count = %d; want 10", len(prunedIDs))
		}

		// Oldest 10 (job-000 to job-009) should have been pruned
		for i := 0; i < 10; i++ {
			expectedPruned := idOf(fmt.Sprintf("job-%03d", i))
			found := false
			for _, pid := range prunedIDs {
				if pid == expectedPruned {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected %s to be pruned", expectedPruned)
			}
		}
	})
}
