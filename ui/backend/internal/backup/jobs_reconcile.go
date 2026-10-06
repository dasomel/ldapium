package backup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// WorkerDestinationResult models destination outcomes reported by the worker.
type WorkerDestinationResult struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	ErrorCode string `json:"error_code,omitempty"`
}

// WorkerResult is the content written to <root>/.results/<job_id>.json upon worker exit.
type WorkerResult struct {
	RunID         string                    `json:"run_id"`
	Kind          string                    `json:"kind"`
	Verified      bool                      `json:"verified"`
	LocalVerified bool                      `json:"local_verified"`
	JobID         string                    `json:"job_id"`
	Destinations  []WorkerDestinationResult `json:"destinations,omitempty"`
}

// ArtifactManifestFile details a verified archive component.
type ArtifactManifestFile struct {
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// ArtifactManifest models complete.json left in <root>/<kind>/<run_id>.
type ArtifactManifest struct {
	Owner      string                 `json:"owner"`
	InstanceID string                 `json:"instance_id"`
	Kind       string                 `json:"kind"`
	RunID      string                 `json:"run_id"`
	JobID      string                 `json:"job_id,omitempty"`
	Files      []ArtifactManifestFile `json:"files,omitempty"`
}

// ReconcileDecision describes the outcome of startup job reconciliation.
type ReconcileDecision string

const (
	DecisionUnchanged       ReconcileDecision = "unchanged"
	DecisionOrphanSuspected ReconcileDecision = "orphan_suspected"
	DecisionSettledResult   ReconcileDecision = "settled_result"
	DecisionSettledManifest ReconcileDecision = "settled_manifest"
	DecisionSettledNone     ReconcileDecision = "settled_none"
	DecisionSettledInvalid  ReconcileDecision = "settled_invalid"
)

func cloneJob(j *Job) *Job {
	if j == nil {
		return nil
	}
	cp := *j
	if j.Error != nil {
		errCp := *j.Error
		cp.Error = &errCp
	}
	if j.Local != nil {
		locCp := *j.Local
		cp.Local = &locCp
	}
	if j.Artifact != nil {
		artCp := *j.Artifact
		artCp.Files = append([]JobArtifactFile{}, j.Artifact.Files...)
		cp.Artifact = &artCp
	}
	if j.Destinations != nil {
		cp.Destinations = append([]JobDestination{}, j.Destinations...)
	}
	return &cp
}

func convertManifestFiles(in []ArtifactManifestFile) []JobArtifactFile {
	if len(in) == 0 {
		return nil
	}
	out := make([]JobArtifactFile, len(in))
	for i, f := range in {
		out[i] = JobArtifactFile{
			Name:   f.Name,
			Bytes:  f.Bytes,
			SHA256: f.SHA256,
		}
	}
	return out
}

// ReconcileEvidence is everything reconcile may base a decision on.
type ReconcileEvidence struct {
	// LockHeld: the worker lock is held (a live worker, possibly an orphan).
	LockHeld bool
	// ProbeError: the lock could not be probed. Treated like LockHeld, because an
	// unknown lock state must never abandon a live worker.
	ProbeError bool
	// Result is a worker result file that passed validateWorkerResult.
	Result *WorkerResult
	// ResultInvalid: a result file exists but failed validation (wrong job,
	// symlink, oversized, malformed...). It is unverifiable and never settles
	// the job as succeeded or failed.
	ResultInvalid bool
	Manifest      *ArtifactManifest
}

// Reconcile evaluates a running job record against the current lock state,
// worker result file, and archive manifest as a pure function.
func Reconcile(record *Job, lockHeld bool, resultFile *WorkerResult, manifest *ArtifactManifest) (*Job, ReconcileDecision) {
	return ReconcileWithTime(record, lockHeld, resultFile, manifest, time.Now().UTC())
}

// ReconcileWithTime evaluates reconciliation with an explicit current time.
func ReconcileWithTime(record *Job, lockHeld bool, resultFile *WorkerResult, manifest *ArtifactManifest, now time.Time) (*Job, ReconcileDecision) {
	return ReconcileEvidenceWithTime(record, ReconcileEvidence{LockHeld: lockHeld, Result: resultFile, Manifest: manifest}, now)
}

// ReconcileEvidenceWithTime is the pure reconcile state machine (D217-7/16).
func ReconcileEvidenceWithTime(record *Job, ev ReconcileEvidence, now time.Time) (*Job, ReconcileDecision) {
	if record == nil {
		return nil, DecisionUnchanged
	}
	if record.Status != JobStatusRunning {
		return cloneJob(record), DecisionUnchanged
	}

	j := cloneJob(record)

	// Row 1: Worker lock is held (or could not be probed) - an active orphan.
	// Invariant: Do NOT settle as abandoned; retain running state with orphan_suspected.
	if ev.LockHeld || ev.ProbeError {
		j.OrphanSuspected = true
		j.OrphanReason = OrphanReasonLockHeld
		if ev.ProbeError && !ev.LockHeld {
			j.OrphanReason = OrphanReasonProbeError
		}
		return j, DecisionOrphanSuspected
	}

	j.OrphanSuspected = false
	j.OrphanReason = ""
	if j.FinishedAt.IsZero() {
		j.FinishedAt = now
	}

	// A result whose run disagrees with the manifest that carries this job's ID
	// cannot be trusted either.
	resultFile, invalid := ev.Result, ev.ResultInvalid
	if resultFile != nil && ev.Manifest != nil && resultFile.RunID != "" && resultFile.RunID != ev.Manifest.RunID {
		resultFile, invalid = nil, true
	}

	// Row 2 & 3: Worker finished and left a validated result file.
	if resultFile != nil {
		j.Local = &JobLocal{Verified: resultFile.LocalVerified}
		if resultFile.RunID != "" {
			j.Artifact = &JobArtifact{RunID: resultFile.RunID}
			if ev.Manifest != nil && len(ev.Manifest.Files) > 0 {
				j.Artifact.Files = convertManifestFiles(ev.Manifest.Files)
			}
		}
		if len(resultFile.Destinations) > 0 {
			var dests []JobDestination
			for _, d := range resultFile.Destinations {
				dests = append(dests, JobDestination{
					ID:        d.ID,
					Status:    d.Status,
					ErrorCode: d.ErrorCode,
				})
			}
			j.Destinations = dests
		}

		if resultFile.Verified {
			j.Status = JobStatusSucceeded
			j.Error = nil
		} else {
			j.Status = JobStatusFailed
			j.Error = &JobError{
				Code:    ErrCodeWorkerFailed,
				Message: ErrorMessage(ErrCodeWorkerFailed),
			}
		}
		return j, DecisionSettledResult
	}

	code, decision := ErrCodeAbandoned, DecisionSettledNone
	if invalid {
		code, decision = ErrCodeResultInvalid, DecisionSettledInvalid
	}

	// Row 4 (and the invalid-result variant): no usable result, but an owned
	// complete.json carries this job's ID.
	if ev.Manifest != nil {
		j.Status = JobStatusAbandoned
		j.Error = &JobError{Code: code, Message: ErrorMessage(code)}
		j.Local = &JobLocal{Verified: true}
		j.Artifact = &JobArtifact{
			RunID: ev.Manifest.RunID,
			Files: convertManifestFiles(ev.Manifest.Files),
		}
		for i := range j.Destinations {
			j.Destinations[i].Status = DestStatusUnknown
		}
		if !invalid {
			decision = DecisionSettledManifest
		}
		return j, decision
	}

	// Row 5: Lock is free, no usable result file, no manifest: process was killed abruptly.
	j.Status = JobStatusAbandoned
	j.Error = &JobError{Code: code, Message: ErrorMessage(code)}
	for i := range j.Destinations {
		j.Destinations[i].Status = DestStatusUnknown
	}
	return j, decision
}

// validateWorkerResult is the schema gate for <root>/.results/<job_id>.json.
// The file is evidence left by a process the controller did not supervise, so
// it must belong to this job and carry only enumerated, bounded values. Unknown
// keys are ignored because they are never copied into the job record.
func validateWorkerResult(wr *WorkerResult, j *Job) error {
	switch {
	case wr.JobID != j.JobID:
		return errors.New("job_id mismatch")
	case wr.Kind != j.Kind:
		return errors.New("kind mismatch")
	case wr.RunID != "" && !runName.MatchString(wr.RunID):
		return errors.New("invalid run_id")
	case (wr.Verified || wr.LocalVerified) && wr.RunID == "":
		return errors.New("verified result without run_id")
	case wr.Verified && !wr.LocalVerified:
		return errors.New("verified without local_verified")
	case len(wr.Destinations) > maxJobDests:
		return errors.New("too many destinations")
	}
	seen := map[string]bool{}
	for _, d := range wr.Destinations {
		if !safeID.MatchString(d.ID) || seen[d.ID] {
			return errors.New("invalid destination id")
		}
		seen[d.ID] = true
		if !validDestStatus(d.Status) || !validDestErrCode(d.ErrorCode) {
			return errors.New("invalid destination status")
		}
		if wr.Verified && d.Status != DestStatusSucceeded {
			return errors.New("verified result with unsuccessful destination")
		}
	}
	return nil
}

// ShouldCatchUp implements the crash-loop guard of D217-8:
// If the most recent 3 jobs of this kind were all abandoned, immediate catch-up
// is suppressed to prevent restart storms from hammering LDAP.
func ShouldCatchUp(jobs []*Job, kind string) bool {
	var recentFinished []*Job
	for i := len(jobs) - 1; i >= 0; i-- {
		j := jobs[i]
		if j.Kind == kind && j.Status != JobStatusRunning {
			recentFinished = append(recentFinished, j)
			if len(recentFinished) == 3 {
				break
			}
		}
	}

	if len(recentFinished) == 3 {
		allAbandoned := true
		for _, j := range recentFinished {
			if j.Status != JobStatusAbandoned {
				allAbandoned = false
				break
			}
		}
		if allAbandoned {
			return false
		}
	}
	return true
}

// ScheduleAfterRecovery determines next_run after startup reconciliation:
// If catch-up is allowed, next_run is set to recoveryTime so the scheduler
// runs on the first tick. If crash-loop guard triggers, next_run is postponed
// by a full policy interval.
func ScheduleAfterRecovery(jobs []*Job, kind string, intervalMinutes int, recoveryTime time.Time) time.Time {
	if ShouldCatchUp(jobs, kind) {
		return recoveryTime
	}
	return recoveryTime.Add(time.Duration(intervalMinutes) * time.Minute)
}

// ScheduleAfterWorkerBusy implements D217-8 / AC-015:
// Lock contention retry should NOT postpone the schedule by a full interval.
// Retries occur after 60s for up to 10 consecutive attempts before backing off
// to the policy interval.
func ScheduleAfterWorkerBusy(consecutiveBusy int, intervalMinutes int, now time.Time) time.Time {
	if consecutiveBusy < 10 {
		return now.Add(60 * time.Second)
	}
	return now.Add(time.Duration(intervalMinutes) * time.Minute)
}

// LockProbe is the signature for probing worker lock ownership.
type LockProbe func() (held bool, err error)

// DefaultLockProbe creates a real non-blocking flock probe on <root>/.worker.lock,
// matching ui/backend/backup-tools/backup_worker.py:160.
func DefaultLockProbe(root string) LockProbe {
	lockPath := filepath.Join(root, ".worker.lock")
	return func() (bool, error) {
		if err := os.MkdirAll(root, 0700); err != nil {
			return false, err
		}
		f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0600)
		if err != nil {
			return false, err
		}
		defer f.Close()

		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			return false, nil
		}
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return true, nil
		}
		return false, fmt.Errorf("flock probe on %s: %w", lockPath, err)
	}
}
