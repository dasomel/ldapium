package backup

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestJobTransitions(t *testing.T) {
	tests := []struct {
		name     string
		from     string
		to       string
		expected bool
	}{
		// Initial transitions
		{name: "init to running", from: "", to: JobStatusRunning, expected: true},
		{name: "init to succeeded", from: "", to: JobStatusSucceeded, expected: false},
		{name: "init to failed", from: "", to: JobStatusFailed, expected: false},
		{name: "init to cancelled", from: "", to: JobStatusCancelled, expected: false},
		{name: "init to abandoned", from: "", to: JobStatusAbandoned, expected: false},
		{name: "init to queued (rejected: no queue)", from: "", to: "queued", expected: false},

		// From running
		{name: "running to running (heartbeat/update)", from: JobStatusRunning, to: JobStatusRunning, expected: true},
		{name: "running to succeeded", from: JobStatusRunning, to: JobStatusSucceeded, expected: true},
		{name: "running to failed", from: JobStatusRunning, to: JobStatusFailed, expected: true},
		{name: "running to cancelled", from: JobStatusRunning, to: JobStatusCancelled, expected: true},
		{name: "running to abandoned", from: JobStatusRunning, to: JobStatusAbandoned, expected: true},
		{name: "running to invalid", from: JobStatusRunning, to: "invalid_status", expected: false},

		// Terminal states are append-only sinks
		{name: "succeeded to running", from: JobStatusSucceeded, to: JobStatusRunning, expected: false},
		{name: "succeeded to failed", from: JobStatusSucceeded, to: JobStatusFailed, expected: false},
		{name: "succeeded to cancelled", from: JobStatusSucceeded, to: JobStatusCancelled, expected: false},
		{name: "succeeded to abandoned", from: JobStatusSucceeded, to: JobStatusAbandoned, expected: false},

		{name: "failed to running", from: JobStatusFailed, to: JobStatusRunning, expected: false},
		{name: "failed to succeeded", from: JobStatusFailed, to: JobStatusSucceeded, expected: false},
		{name: "failed to cancelled", from: JobStatusFailed, to: JobStatusCancelled, expected: false},
		{name: "failed to abandoned", from: JobStatusFailed, to: JobStatusAbandoned, expected: false},

		{name: "cancelled to running", from: JobStatusCancelled, to: JobStatusRunning, expected: false},
		{name: "cancelled to succeeded", from: JobStatusCancelled, to: JobStatusSucceeded, expected: false},
		{name: "cancelled to failed", from: JobStatusCancelled, to: JobStatusFailed, expected: false},

		{name: "abandoned to running", from: JobStatusAbandoned, to: JobStatusRunning, expected: false},
		{name: "abandoned to succeeded", from: JobStatusAbandoned, to: JobStatusSucceeded, expected: false},
		{name: "abandoned to failed", from: JobStatusAbandoned, to: JobStatusFailed, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidTransition(tt.from, tt.to)
			if got != tt.expected {
				t.Errorf("ValidTransition(%q, %q) = %v; want %v", tt.from, tt.to, got, tt.expected)
			}

			j := &Job{Status: tt.from}
			if j.CanTransitionTo(tt.to) != tt.expected {
				t.Errorf("Job.CanTransitionTo(%q) from %q = %v; want %v", tt.to, tt.from, j.CanTransitionTo(tt.to), tt.expected)
			}
		})
	}
}

func TestJobIDGenerator(t *testing.T) {
	t.Run("format and regex compliance", func(t *testing.T) {
		fixedTime := time.Date(2026, 10, 6, 12, 34, 56, 0, time.UTC)
		gen := NewJobIDGenerator(func() time.Time { return fixedTime }, nil, nil)
		id, err := gen.Generate()
		if err != nil {
			t.Fatalf("Generate() error = %v", err)
		}

		if !IsValidJobID(id) {
			t.Fatalf("generated id %q does not match JobIDRegex", id)
		}
		if len(id) > 64 {
			t.Errorf("job id %q exceeds maximum length 64", id)
		}
		if !strings.HasPrefix(id, "job-20261006T123456Z-") {
			t.Errorf("expected UTC timestamp prefix, got %q", id)
		}
	})

	t.Run("uniqueness across batch", func(t *testing.T) {
		gen := NewJobIDGenerator(nil, nil, nil)
		seen := make(map[string]bool)
		for i := 0; i < 1000; i++ {
			id, err := gen.Generate()
			if err != nil {
				t.Fatalf("Generate() error at iteration %d: %v", i, err)
			}
			if seen[id] {
				t.Fatalf("duplicate job id generated: %q", id)
			}
			seen[id] = true
		}
	})

	t.Run("collision retry succeeds", func(t *testing.T) {
		attempts := 0
		exists := func(id string) bool {
			attempts++
			return attempts < 3 // Collide twice, succeed on 3rd attempt
		}
		gen := NewJobIDGenerator(nil, nil, exists)
		id, err := gen.Generate()
		if err != nil {
			t.Fatalf("Generate() error = %v", err)
		}
		if !IsValidJobID(id) {
			t.Fatalf("invalid id: %q", id)
		}
		if attempts != 3 {
			t.Errorf("expected 3 collision attempts, got %d", attempts)
		}
	})

	t.Run("collision retry limit failure", func(t *testing.T) {
		alwaysExists := func(id string) bool { return true }
		gen := NewJobIDGenerator(nil, nil, alwaysExists)
		_, err := gen.Generate()
		if err == nil || !strings.Contains(err.Error(), "retry limit exceeded") {
			t.Fatalf("expected retry limit error, got %v", err)
		}
	})

	t.Run("random source read error", func(t *testing.T) {
		gen := NewJobIDGenerator(nil, bytes.NewReader(nil), nil) // Empty reader triggers EOF
		_, err := gen.Generate()
		if err == nil {
			t.Fatal("expected error on exhausted reader, got nil")
		}
	})

	t.Run("validation edge cases", func(t *testing.T) {
		valid := "job-20261006T031500Z-3fa9c1d27b40"
		if !IsValidJobID(valid) {
			t.Errorf("%q should be valid", valid)
		}

		invalids := []string{
			"",
			"job-20261006T031500Z-3fa9c1d27b4",     // 11 hex
			"job-20261006T031500Z-3fa9c1d27b400",   // 13 hex
			"job-20261006T031500Z-3FA9C1D27B40",    // uppercase
			"run-20261006T031500Z-3fa9c1d27b40",    // wrong prefix
			"job-20261006031500Z-3fa9c1d27b40",     // missing T
			"../job-20261006T031500Z-3fa9c1d27b40", // path traversal
		}
		for _, inv := range invalids {
			if IsValidJobID(inv) {
				t.Errorf("invalid ID %q was accepted", inv)
			}
		}
	})
}

func TestErrorCatalogAndTypedErrors(t *testing.T) {
	requiredCodes := []string{
		ErrCodeBackupBusy,
		ErrCodeJobNotFound,
		ErrCodeJobNotCancellable,
		ErrCodePersistenceUnavailable,
		ErrCodeDeadlineExceeded,
		ErrCodeAbandoned,
		ErrCodeWorkerFailed,
		ErrCodeWorkerBusy,
		ErrCodeUnverifiedResult,
		DestErrCodeTransferFailed,
		DestErrCodeVerifyFailed,
		DestErrCodeConfigInvalid,
		DestErrCodePrevDestinationFailed,
	}

	for _, code := range requiredCodes {
		msg := ErrorMessage(code)
		if msg == "" || msg == "internal error" {
			t.Errorf("code %q has missing or generic error message: %q", code, msg)
		}
		// Invariant: Error messages must never contain sensitive tokens
		if strings.Contains(msg, "/") || strings.Contains(msg, "cn=") || strings.Contains(msg, "password") {
			t.Errorf("code %q message %q contains potential sensitive substrings", code, msg)
		}
	}

	if msg := ErrorMessage("unknown_code"); msg != "internal error" {
		t.Errorf("unknown code should return 'internal error', got %q", msg)
	}

	t.Run("BusyError matches ErrBusy", func(t *testing.T) {
		err := &BusyError{ActiveJobID: "job-1", ActiveKind: "data"}
		if !errors.Is(err, ErrBusy) {
			t.Error("BusyError must satisfy errors.Is(err, ErrBusy)")
		}
		if err.Error() != ErrorMessage(ErrCodeBackupBusy) {
			t.Errorf("unexpected BusyError string: %s", err.Error())
		}
		if err.ActiveJobID != "job-1" || err.ActiveKind != "data" {
			t.Errorf("BusyError lost fields: %+v", err)
		}
	})

	t.Run("PersistenceUnavailableError matches ErrPersistenceUnavailable", func(t *testing.T) {
		underlying := errors.New("disk write failure")
		err := &PersistenceUnavailableError{Err: underlying}
		if !errors.Is(err, ErrPersistenceUnavailable) {
			t.Error("PersistenceUnavailableError must satisfy errors.Is(err, ErrPersistenceUnavailable)")
		}
		if !errors.Is(err, underlying) {
			t.Error("PersistenceUnavailableError must unwrap underlying error")
		}
		if err.Error() != ErrorMessage(ErrCodePersistenceUnavailable) {
			t.Errorf("unexpected string: %s", err.Error())
		}
	})

	t.Run("JobNotFoundError matches ErrJobNotFound", func(t *testing.T) {
		err := &JobNotFoundError{JobID: "job-none"}
		if !errors.Is(err, ErrJobNotFound) {
			t.Error("JobNotFoundError must satisfy errors.Is(err, ErrJobNotFound)")
		}
		if err.JobID != "job-none" {
			t.Errorf("unexpected JobID: %s", err.JobID)
		}
	})

	t.Run("JobNotCancellableError matches ErrJobNotCancellable", func(t *testing.T) {
		err := &JobNotCancellableError{JobID: "job-1", Status: "succeeded"}
		if !errors.Is(err, ErrJobNotCancellable) {
			t.Error("JobNotCancellableError must satisfy errors.Is(err, ErrJobNotCancellable)")
		}
		if err.Status != "succeeded" {
			t.Errorf("unexpected Status: %s", err.Status)
		}
	})
}

func TestNoSensitiveInformationSentinel(t *testing.T) {
	sentinels := []string{
		"super-secret-password-12345",
		"cn=Directory Manager,dc=example,dc=com",
		"/private/tmp/sensitive/path",
		"/etc/shadow",
		"rclone_password=secret",
	}

	job := &Job{
		JobID:   "job-20261006T120000Z-abcdef012345",
		Kind:    "data",
		Trigger: JobTriggerManual,
		Status:  JobStatusFailed,
		RequestedBy: JobRequester{
			Type:        JobRequesterUser,
			Fingerprint: "a1b2c3d4e5f60718", // 16-hex fingerprint only
		},
		RequestID:      "req-12345",
		PolicyRevision: 1,
		CreatedAt:      time.Now().UTC(),
		StartedAt:      time.Now().UTC(),
		FinishedAt:     time.Now().UTC(),
		StagingCleanup: StagingCleanupDone,
		Error: &JobError{
			Code:    ErrCodeWorkerFailed,
			Message: ErrorMessage(ErrCodeWorkerFailed),
		},
		Local: &JobLocal{Verified: true},
		Destinations: []JobDestination{
			{
				ID:        "dest-1",
				Status:    DestStatusFailed,
				ErrorCode: DestErrCodeTransferFailed,
			},
		},
		Artifact: &JobArtifact{
			RunID: "20261006T120000Z-0123456789ab",
			Files: []JobArtifactFile{
				{
					Name:   "data.ldif.gz",
					Bytes:  1024,
					SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				},
			},
		},
	}

	b, err := json.Marshal(job)
	if err != nil {
		t.Fatalf("json.Marshal(job) error = %v", err)
	}

	serialized := string(b)
	for _, sentinel := range sentinels {
		if strings.Contains(serialized, sentinel) {
			t.Fatalf("sentinel token %q found in serialized job JSON: %s", sentinel, serialized)
		}
	}

	// Verify error catalog messages never contain any sentinel strings
	for code, msg := range errorCatalog {
		for _, sentinel := range sentinels {
			if strings.Contains(msg, sentinel) {
				t.Fatalf("sentinel token %q found in errorCatalog[%s]: %s", sentinel, code, msg)
			}
		}
	}
}
