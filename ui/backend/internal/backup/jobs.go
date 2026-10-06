package backup

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"
)

// Job status enum per D217-2. Queued is deliberately omitted:ldapium enforces
// a single active backup job and returns 409 when busy rather than queuing.
const (
	JobStatusRunning   = "running"
	JobStatusSucceeded = "succeeded"
	JobStatusFailed    = "failed"
	JobStatusCancelled = "cancelled"
	JobStatusAbandoned = "abandoned"
)

// Job trigger enum per D217-2.
const (
	JobTriggerManual   = "manual"
	JobTriggerSchedule = "schedule"
)

// Requester types per D217-2.
const (
	JobRequesterUser      = "user"
	JobRequesterScheduler = "scheduler"
)

// Staging cleanup states per D217-6.
const (
	StagingCleanupDone          = "done"
	StagingCleanupPending       = "pending"
	StagingCleanupNotApplicable = "not_applicable"
)

// Why a running job is held as orphan_suspected (D217-16): the worker lock is
// held, or it could not be probed (a probe error must never abandon a live worker).
const (
	OrphanReasonLockHeld   = "worker_lock_held"
	OrphanReasonProbeError = "lock_probe_error"
)

// Destination status enum per D217-11.
const (
	DestStatusSucceeded = "succeeded"
	DestStatusFailed    = "failed"
	DestStatusSkipped   = "skipped"
	DestStatusUnknown   = "unknown"
)

// Error codes introduced in #217 and closed catalog per D217-2 / D217-11 / #218.
const (
	ErrCodeBackupBusy             = "backup_busy"
	ErrCodeJobNotFound            = "job_not_found"
	ErrCodeJobNotCancellable      = "job_not_cancellable"
	ErrCodePersistenceUnavailable = "persistence_unavailable"

	ErrCodeDeadlineExceeded = "deadline_exceeded"
	ErrCodeAbandoned        = "abandoned"
	ErrCodeWorkerFailed     = "worker_failed"
	ErrCodeWorkerBusy       = "worker_busy"
	ErrCodeUnverifiedResult = "unverified_result"
	ErrCodeResultInvalid    = "result_invalid"

	DestErrCodeTransferFailed        = "transfer_failed"
	DestErrCodeVerifyFailed          = "verify_failed"
	DestErrCodeConfigInvalid         = "config_invalid"
	DestErrCodePrevDestinationFailed = "previous_destination_failed"
)

// errorCatalog maps stable snake_case codes to fixed non-sensitive English
// messages. Invariant: messages must NEVER interpolate paths, command output,
// or credentials.
var errorCatalog = map[string]string{
	ErrCodeBackupBusy:                "backup already running",
	ErrCodeJobNotFound:               "backup job not found",
	ErrCodeJobNotCancellable:         "backup job is not cancellable",
	ErrCodePersistenceUnavailable:    "backup state could not be saved; retry",
	ErrCodeDeadlineExceeded:          "backup job deadline exceeded",
	ErrCodeAbandoned:                 "controller restarted while the job was running",
	ErrCodeWorkerFailed:              "backup worker process failed",
	ErrCodeWorkerBusy:                "backup worker busy",
	ErrCodeUnverifiedResult:          "unverified worker result",
	ErrCodeResultInvalid:             "worker result could not be validated",
	DestErrCodeTransferFailed:        "remote transfer command failed",
	DestErrCodeVerifyFailed:          "checksum verification failed",
	DestErrCodeConfigInvalid:         "destination configuration rejected",
	DestErrCodePrevDestinationFailed: "skipped due to previous destination failure",
}

// ErrorMessage returns the fixed, non-sensitive message for a given error code.
func ErrorMessage(code string) string {
	if msg, ok := errorCatalog[code]; ok {
		return msg
	}
	return "internal error"
}

// Typed errors for callers and error-envelope mapping.
var (
	ErrPersistenceUnavailable = errors.New(errorCatalog[ErrCodePersistenceUnavailable])
	ErrJobNotFound            = errors.New(errorCatalog[ErrCodeJobNotFound])
	ErrJobNotCancellable      = errors.New(errorCatalog[ErrCodeJobNotCancellable])
)

// BusyError provides active job correlation on 409 while preserving errors.Is
// compatibility with ErrBusy.
type BusyError struct {
	ActiveJobID string
	ActiveKind  string
}

func (e *BusyError) Error() string {
	return ErrorMessage(ErrCodeBackupBusy)
}

func (e *BusyError) Is(target error) bool {
	return target == ErrBusy
}

// PersistenceUnavailableError signals that a state transition write failed.
type PersistenceUnavailableError struct {
	Err error
}

func (e *PersistenceUnavailableError) Error() string {
	return ErrorMessage(ErrCodePersistenceUnavailable)
}

func (e *PersistenceUnavailableError) Unwrap() error {
	return e.Err
}

func (e *PersistenceUnavailableError) Is(target error) bool {
	return target == ErrPersistenceUnavailable
}

// JobNotFoundError is returned when a requested job ID is unknown or malformed.
type JobNotFoundError struct {
	JobID string
}

func (e *JobNotFoundError) Error() string {
	return ErrorMessage(ErrCodeJobNotFound)
}

func (e *JobNotFoundError) Is(target error) bool {
	return target == ErrJobNotFound
}

// JobNotCancellableError is returned when attempting to cancel a terminal job.
type JobNotCancellableError struct {
	JobID  string
	Status string
}

func (e *JobNotCancellableError) Error() string {
	return ErrorMessage(ErrCodeJobNotCancellable)
}

func (e *JobNotCancellableError) Is(target error) bool {
	return target == ErrJobNotCancellable
}

// JobRequester records the initiating actor identity as a one-way fingerprint
// (D217-12) or as scheduler. Raw DNs must never be stored here.
type JobRequester struct {
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// JobError carries a stable error code and fixed message from the catalog.
type JobError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// JobLocal records whether the on-disk local copy was verified.
type JobLocal struct {
	Verified bool `json:"verified"`
}

// JobDestination records outcome per configured destination.
type JobDestination struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	ErrorCode string `json:"error_code,omitempty"`
}

// JobArtifactFile references a single verified file in complete.json.
type JobArtifactFile struct {
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// JobArtifact references verified backup files and the worker run ID.
type JobArtifact struct {
	RunID string            `json:"run_id"`
	Files []JobArtifactFile `json:"files,omitempty"`
}

// Job is the durable record of a single backup run per D217-2.
type Job struct {
	JobID             string           `json:"job_id"`
	Kind              string           `json:"kind"`
	Trigger           string           `json:"trigger"`
	Status            string           `json:"status"`
	RequestedBy       JobRequester     `json:"requested_by"`
	RequestID         string           `json:"request_id,omitempty"`
	PolicyRevision    uint64           `json:"policy_revision"`
	CreatedAt         time.Time        `json:"created_at"`
	StartedAt         time.Time        `json:"started_at,omitempty"`
	FinishedAt        time.Time        `json:"finished_at,omitempty"`
	DeadlineAt        time.Time        `json:"deadline_at,omitempty"`
	CancelRequestedAt time.Time        `json:"cancel_requested_at,omitempty"`
	OrphanSuspected   bool             `json:"orphan_suspected,omitempty"`
	OrphanReason      string           `json:"orphan_reason,omitempty"`
	StagingCleanup    string           `json:"staging_cleanup,omitempty"`
	Error             *JobError        `json:"error,omitempty"`
	Local             *JobLocal        `json:"local,omitempty"`
	Destinations      []JobDestination `json:"destinations,omitempty"`
	Artifact          *JobArtifact     `json:"artifact,omitempty"`
}

// MarshalJSON omits unset times (omitempty does not apply to time.Time), for
// both the API and the job file.
func (j Job) MarshalJSON() ([]byte, error) {
	type plain Job
	opt := func(t time.Time) *time.Time {
		if t.IsZero() {
			return nil
		}
		return &t
	}
	if j.Error != nil {
		// Whatever text the record carries, only the catalog text is serialized.
		j.Error = &JobError{Code: j.Error.Code, Message: ErrorMessage(j.Error.Code)}
	}
	return json.Marshal(struct {
		plain
		StartedAt         *time.Time `json:"started_at,omitempty"`
		FinishedAt        *time.Time `json:"finished_at,omitempty"`
		DeadlineAt        *time.Time `json:"deadline_at,omitempty"`
		CancelRequestedAt *time.Time `json:"cancel_requested_at,omitempty"`
	}{plain(j), opt(j.StartedAt), opt(j.FinishedAt), opt(j.DeadlineAt), opt(j.CancelRequestedAt)})
}

// ValidTransition enforces the state machine per D217-2. Initial creation may
// only enter running. Terminal states are append-only sink states.
func ValidTransition(from, to string) bool {
	switch from {
	case "":
		return to == JobStatusRunning
	case JobStatusRunning:
		switch to {
		case JobStatusRunning, JobStatusSucceeded, JobStatusFailed, JobStatusCancelled, JobStatusAbandoned:
			return true
		default:
			return false
		}
	default:
		return false
	}
}

// CanTransitionTo reports whether this job may move to target status.
func (j *Job) CanTransitionTo(target string) bool {
	return ValidTransition(j.Status, target)
}

// JobIDRegex enforces D217-1: job-<UTC YYYYMMDDTHHMMSSZ>-<12 hex>.
var JobIDRegex = regexp.MustCompile(`^job-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}$`)

// IsValidJobID checks if an identifier strictly adheres to the job ID regex.
func IsValidJobID(id string) bool {
	return JobIDRegex.MatchString(id)
}

// JobIDGenerator creates unique job identifiers with injectable clock, random
// source, and collision checking.
type JobIDGenerator struct {
	clock  func() time.Time
	rand   io.Reader
	exists func(id string) bool
}

// NewJobIDGenerator initializes a generator. If clock or rand are nil, real
// UTC time and crypto/rand.Reader are used.
func NewJobIDGenerator(clock func() time.Time, r io.Reader, exists func(id string) bool) *JobIDGenerator {
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	if r == nil {
		r = rand.Reader
	}
	return &JobIDGenerator{
		clock:  clock,
		rand:   r,
		exists: exists,
	}
}

// Generate produces a new job ID. If a collision is detected with existing IDs,
// it retries up to 10 times before failing.
func (g *JobIDGenerator) Generate() (string, error) {
	const maxRetries = 10
	var buf [6]byte
	for i := 0; i < maxRetries; i++ {
		if _, err := io.ReadFull(g.rand, buf[:]); err != nil {
			return "", fmt.Errorf("reading random bytes for job ID: %w", err)
		}
		id := fmt.Sprintf("job-%s-%s", g.clock().UTC().Format("20060102T150405Z"), hex.EncodeToString(buf[:]))
		if g.exists == nil || !g.exists(id) {
			return id, nil
		}
	}
	return "", fmt.Errorf("job ID collision retry limit exceeded")
}

// RunRequest carries caller metadata into Manager.StartJob per D217-12 / REQ-001.
type RunRequest struct {
	Kind             string
	Trigger          string
	RequesterType    string
	ActorFingerprint string
	RequestID        string
}
