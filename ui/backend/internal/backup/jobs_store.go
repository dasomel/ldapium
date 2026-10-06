package backup

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
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
// It only decides; the caller deletes the pruned records' result files with
// removeResultFiles AFTER the pruned job file is durably written, so a failed
// write can never leave a record whose evidence is already gone.
// Invariant: Pruning NEVER modifies or removes backup archives under <root>/<kind>.
func pruneJobs(jobs []*Job, now time.Time) ([]*Job, []string) {
	if len(jobs) == 0 {
		return jobs, nil
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

	return retained, prunedIDs
}

// removeResultFiles deletes <resultsDir>/<job_id>.json for already-pruned jobs.
// IDs are re-validated because they become path components.
func removeResultFiles(resultsDir string, ids []string) {
	if resultsDir == "" {
		return
	}
	for _, id := range ids {
		if !IsValidJobID(id) {
			continue
		}
		file := filepath.Join(filepath.Clean(resultsDir), id+".json")
		if !strings.HasPrefix(file, filepath.Clean(resultsDir)+string(filepath.Separator)) {
			continue
		}
		if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
			log.Printf("backup_result_file_remove_failed job_id=%s", id)
		}
	}
}

// quarantineCorruptFile renames an unusable job file to .corrupt-<timestamp>
// so controller startup is never blocked by diagnostic history corruption.
func quarantineCorruptFile(path string) (string, error) {
	ts := time.Now().UTC().Format("20060102T150405Z")
	target := filepath.Join(filepath.Dir(path), fmt.Sprintf(".corrupt-%s", ts))
	if err := os.Rename(path, target); err != nil {
		return "", err
	}
	return target, nil
}

// quarantine moves the file aside and logs a fixed reason (never file content
// or filesystem error text, which can carry paths).
func quarantine(path, reason string) {
	if target, err := quarantineCorruptFile(path); err != nil {
		log.Printf("backup_jobs_quarantine_failed reason=%s", reason)
	} else {
		log.Printf("backup_jobs_quarantined reason=%s file=%s", reason, filepath.Base(target))
	}
}

const (
	maxJobRecords = 10000
	maxJobDests   = 32
	maxTextLen    = 256
)

var (
	jobFingerprintRe = regexp.MustCompile(`^[a-f0-9]{1,64}$`)
	jobRequestIDRe   = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	jobKeyIDRe       = regexp.MustCompile(`^[a-f0-9]{8}$`)
)

// validJobIdempotency: lowercase SHA-256 / HMAC hex digests and an 8-hex key_id.
// Anything else is a corrupt or tampered file.
func validJobIdempotency(i *JobIdempotency) bool {
	return sha256HexRe.MatchString(i.KeyHash) && sha256HexRe.MatchString(i.Fingerprint) && jobKeyIDRe.MatchString(i.KeyID)
}

func inSet(v string, set ...string) bool {
	for _, s := range set {
		if v == s {
			return true
		}
	}
	return false
}

func validDestStatus(v string) bool {
	return inSet(v, DestStatusSucceeded, DestStatusFailed, DestStatusSkipped, DestStatusUnknown)
}

func validDestErrCode(v string) bool {
	return v == "" || inSet(v, DestErrCodeTransferFailed, DestErrCodeVerifyFailed, DestErrCodeConfigInvalid, DestErrCodePrevDestinationFailed)
}

// validateJob checks one persisted record. The job file is a trust boundary: a
// well-formed JSON file can still carry nulls, path-shaped IDs or huge strings,
// and the ID is later used to build result-file paths.
func validateJob(j *Job) error {
	if j == nil {
		return errors.New("null record")
	}
	switch {
	case !IsValidJobID(j.JobID):
		return errors.New("invalid job id")
	case !inSet(j.Kind, "data", "logs"):
		return errors.New("invalid kind")
	case !inSet(j.Trigger, JobTriggerManual, JobTriggerSchedule):
		return errors.New("invalid trigger")
	case !inSet(j.Status, JobStatusRunning, JobStatusSucceeded, JobStatusFailed, JobStatusCancelled, JobStatusAbandoned):
		return errors.New("invalid status")
	case !inSet(j.RequestedBy.Type, JobRequesterUser, JobRequesterScheduler):
		return errors.New("invalid requester type")
	case j.RequestedBy.Fingerprint != "" && !jobFingerprintRe.MatchString(j.RequestedBy.Fingerprint):
		return errors.New("invalid requester fingerprint")
	case j.RequestID != "" && !jobRequestIDRe.MatchString(j.RequestID):
		return errors.New("invalid request id")
	case j.StagingCleanup != "" && !inSet(j.StagingCleanup, StagingCleanupDone, StagingCleanupPending, StagingCleanupNotApplicable):
		return errors.New("invalid staging cleanup")
	case j.OrphanReason != "" && !inSet(j.OrphanReason, OrphanReasonLockHeld, OrphanReasonProbeError):
		return errors.New("invalid orphan reason")
	case len(j.Destinations) > maxJobDests:
		return errors.New("too many destinations")
	case j.Idempotency != nil && !validJobIdempotency(j.Idempotency):
		return errors.New("invalid idempotency record")
	}
	if j.Error != nil {
		if _, ok := errorCatalog[j.Error.Code]; !ok || len(j.Error.Message) > maxTextLen {
			return errors.New("invalid error")
		}
	}
	for _, d := range j.Destinations {
		if !safeID.MatchString(d.ID) || !validDestStatus(d.Status) || !validDestErrCode(d.ErrorCode) {
			return errors.New("invalid destination")
		}
	}
	if a := j.Artifact; a != nil {
		if (a.RunID != "" && !runName.MatchString(a.RunID)) || len(a.Files) > maxArtifactFiles {
			return errors.New("invalid artifact")
		}
		for _, f := range a.Files {
			if !artifactNameRe.MatchString(f.Name) || f.Bytes < 0 || !sha256HexRe.MatchString(f.SHA256) {
				return errors.New("invalid artifact file")
			}
		}
	}
	return nil
}

func validateJobs(jobs []*Job) error {
	if len(jobs) > maxJobRecords {
		return errors.New("too many records")
	}
	seen := make(map[string]bool, len(jobs))
	for _, j := range jobs {
		if err := validateJob(j); err != nil {
			return err
		}
		if seen[j.JobID] {
			return errors.New("duplicate job id")
		}
		seen[j.JobID] = true
	}
	return nil
}

// loadJobFile reads backup-jobs.json. Per the change package's corruption
// policy (diagnostic history, not policy), an unreadable, oversized, unparseable,
// wrong-version or invalid-record file is quarantined and startup continues with
// an empty history; only a plain I/O failure is returned.
func loadJobFile(path string) ([]*Job, error) {
	b, err := readRegularFile(filepath.Dir(path), path, maxJobFileBytes)
	switch {
	case os.IsNotExist(err):
		return []*Job{}, nil
	case errors.Is(err, errNotRegular), errors.Is(err, errTooLarge):
		quarantine(path, "unusable_file")
		return []*Job{}, nil
	case err != nil:
		return nil, errors.New("reading backup job file")
	}

	var file jobFile
	if err := json.Unmarshal(b, &file); err != nil {
		quarantine(path, "invalid_json")
		return []*Job{}, nil
	}
	if file.Version != 1 {
		quarantine(path, "unsupported_version")
		return []*Job{}, nil
	}
	if err := validateJobs(file.Jobs); err != nil {
		quarantine(path, "invalid_record")
		return []*Job{}, nil
	}
	if file.Jobs == nil {
		file.Jobs = []*Job{}
	}
	// Stored error text is never trusted: it is re-derived from the code catalog.
	for _, j := range file.Jobs {
		if j.Error != nil {
			j.Error.Message = ErrorMessage(j.Error.Code)
		}
	}
	return file.Jobs, nil
}
