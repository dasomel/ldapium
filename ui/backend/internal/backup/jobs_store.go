package backup

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Retention bounds per D217-14: maximum 200 records or 90 days.
const (
	MaxJobHistory = 200
	MaxJobAge     = 90 * 24 * time.Hour
)

type jobFile struct {
	Version int    `json:"version"`
	Jobs    []*Job `json:"jobs"`
}

// pruneJobs enforces the retention rules of D217-14:
// 1. Never prune any job currently in "running" status.
// 2. Keep the most recent "succeeded" job for each kind regardless of age or count limit.
// 3. Remove non-protected terminal jobs older than MaxJobAge (90 days).
// 4. If remaining jobs exceed MaxJobHistory (200), remove the oldest non-protected terminal jobs.
// 5. Clean up associated worker result files (<resultsDir>/<job_id>.json) for pruned jobs.
// Invariant: Pruning NEVER modifies or removes backup archives under <root>/<kind>.
func pruneJobs(jobs []*Job, now time.Time, resultsDir string) ([]*Job, []string, error) {
	if len(jobs) == 0 {
		return jobs, nil, nil
	}

	// Identify protected jobs: running jobs and most recent succeeded per kind.
	protected := make(map[string]bool)
	latestSucceeded := make(map[string]*Job)

	for _, j := range jobs {
		if j.Status == JobStatusRunning {
			protected[j.JobID] = true
			continue
		}
		if j.Status == JobStatusSucceeded {
			existing := latestSucceeded[j.Kind]
			if existing == nil || j.FinishedAt.After(existing.FinishedAt) || (j.FinishedAt.Equal(existing.FinishedAt) && j.CreatedAt.After(existing.CreatedAt)) {
				latestSucceeded[j.Kind] = j
			}
		}
	}

	for _, j := range latestSucceeded {
		protected[j.JobID] = true
	}

	// Filter by age (90 days) for non-protected jobs.
	var retained []*Job
	var prunedIDs []string

	for _, j := range jobs {
		if protected[j.JobID] {
			retained = append(retained, j)
			continue
		}
		refTime := j.FinishedAt
		if refTime.IsZero() {
			refTime = j.CreatedAt
		}
		if !refTime.IsZero() && now.Sub(refTime) > MaxJobAge {
			prunedIDs = append(prunedIDs, j.JobID)
		} else {
			retained = append(retained, j)
		}
	}

	// Filter by count (200 items) for non-protected jobs, removing oldest first.
	if len(retained) > MaxJobHistory {
		type sortable struct {
			job     *Job
			refTime time.Time
		}
		var nonProtected []sortable
		var protectedJobs []*Job

		for _, j := range retained {
			if protected[j.JobID] {
				protectedJobs = append(protectedJobs, j)
			} else {
				refTime := j.FinishedAt
				if refTime.IsZero() {
					refTime = j.CreatedAt
				}
				nonProtected = append(nonProtected, sortable{job: j, refTime: refTime})
			}
		}

		// Sort non-protected jobs oldest first
		sort.Slice(nonProtected, func(i, j int) bool {
			return nonProtected[i].refTime.Before(nonProtected[j].refTime)
		})

		excess := len(retained) - MaxJobHistory
		var keptNonProtected []*Job
		for i, item := range nonProtected {
			if i < excess {
				prunedIDs = append(prunedIDs, item.job.JobID)
			} else {
				keptNonProtected = append(keptNonProtected, item.job)
			}
		}

		// Combine kept jobs preserving original chronological ordering
		keptSet := make(map[string]bool)
		for _, j := range protectedJobs {
			keptSet[j.JobID] = true
		}
		for _, j := range keptNonProtected {
			keptSet[j.JobID] = true
		}

		var finalRetained []*Job
		for _, j := range jobs {
			if keptSet[j.JobID] {
				finalRetained = append(finalRetained, j)
			}
		}
		retained = finalRetained
	}

	// Prune accompanying .results/<job_id>.json files if resultsDir is specified
	if resultsDir != "" {
		for _, id := range prunedIDs {
			resultFile := filepath.Join(resultsDir, id+".json")
			if err := os.Remove(resultFile); err != nil && !os.IsNotExist(err) {
				log.Printf("warning: failed to delete pruned job result file %s: %v", resultFile, err)
			}
		}
	}

	return retained, prunedIDs, nil
}

// quarantineCorruptFile renames an unparseable job file to .corrupt-<timestamp>
// so controller startup is never blocked by diagnostic history corruption.
func quarantineCorruptFile(path string) (string, error) {
	ts := time.Now().UTC().Format("20060102T150405Z")
	target := filepath.Join(filepath.Dir(path), fmt.Sprintf(".corrupt-%s", ts))
	if err := os.Rename(path, target); err != nil {
		return "", fmt.Errorf("quarantining corrupt job file %s to %s: %w", path, target, err)
	}
	return target, nil
}

// loadJobFile reads backup-jobs.json. If the file is corrupt, it is quarantined
// and an empty job slice is returned without blocking controller startup.
func loadJobFile(path string) ([]*Job, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []*Job{}, nil
		}
		return nil, err
	}

	var file jobFile
	if err := json.Unmarshal(b, &file); err != nil {
		quarantined, qErr := quarantineCorruptFile(path)
		if qErr != nil {
			log.Printf("error quarantining corrupt job file: %v", qErr)
		} else {
			log.Printf("backup-jobs.json was corrupt, quarantined to %s: %v", quarantined, err)
		}
		return []*Job{}, nil
	}

	if file.Version > 1 {
		quarantined, qErr := quarantineCorruptFile(path)
		if qErr != nil {
			log.Printf("error quarantining unsupported job file: %v", qErr)
		} else {
			log.Printf("backup-jobs.json has unsupported version %d, quarantined to %s", file.Version, quarantined)
		}
		return []*Job{}, nil
	}

	if file.Jobs == nil {
		file.Jobs = []*Job{}
	}
	return file.Jobs, nil
}
