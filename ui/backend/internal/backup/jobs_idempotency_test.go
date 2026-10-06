package backup

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/dasomel/ldapium/ui/backend/internal/idempotency"
)

const (
	idemKeyHash = "a3f1c0de00000000000000000000000000000000000000000000000000000001"
	idemFP      = "b4e2d1ef00000000000000000000000000000000000000000000000000000002"
	idemKeyID   = "0badc0de"
)

func idemReq(kind string, v idempotency.Verdict) RunRequest {
	return RunRequest{Kind: kind, Idempotency: &RequestIdempotency{
		KeyHash: idemKeyHash, Fingerprint: idemFP, KeyID: idemKeyID,
		Verify: func(keyID string, fp []byte) idempotency.Verdict { return v },
	}}
}

func TestStartJobWithKeyReturnsTheSameJobAndRunsOnce(t *testing.T) {
	e := newEnv(t)
	var runs int
	var mu sync.Mutex
	release := make(chan struct{})
	fw := &fakeWorker{run: func(ctx context.Context, kind, jobID string) ([]byte, error) {
		mu.Lock()
		runs++
		mu.Unlock()
		<-release
		return okOut(kind, jobID), nil
	}}
	m := e.manager(t, func(m *Manager) { free(m); m.runWorker = fw.fn })
	first, err := m.StartJob(context.Background(), idemReq("data", idempotency.VerdictSame))
	if err != nil {
		t.Fatal(err)
	}
	// While running, the same key is a hit, not backup_busy.
	_, err = m.StartJob(context.Background(), idemReq("data", idempotency.VerdictSame))
	var hit *IdempotentJobError
	if !errors.As(err, &hit) || hit.Job.JobID != first.JobID || hit.Verdict != idempotency.VerdictSame {
		t.Fatalf("second start = %v, want a same-job idempotency hit", err)
	}
	if hit.Job.Status != JobStatusRunning {
		t.Fatalf("hit carries status %q, want the job's current one", hit.Job.Status)
	}
	close(release)
	waitIdle(t, m)
	_, err = m.StartJob(context.Background(), idemReq("data", idempotency.VerdictSame))
	if !errors.As(err, &hit) || hit.Job.JobID != first.JobID || hit.Job.Status != JobStatusSucceeded {
		t.Fatalf("after completion: %v / %+v", err, hit)
	}
	mu.Lock()
	defer mu.Unlock()
	if runs != 1 {
		t.Fatalf("worker ran %d times, want 1", runs)
	}
	if got := len(m.Jobs("", "", 100)); got != 1 {
		t.Fatalf("job records = %d, want 1", got)
	}
}

func TestStartJobKeyVerdictsAreReturnedNotExecuted(t *testing.T) {
	e := newEnv(t)
	fw := &fakeWorker{}
	m := e.manager(t, func(m *Manager) { free(m); m.runWorker = fw.fn })
	if _, err := m.StartJob(context.Background(), idemReq("data", idempotency.VerdictSame)); err != nil {
		t.Fatal(err)
	}
	waitIdle(t, m)
	for _, v := range []idempotency.Verdict{idempotency.VerdictDifferent, idempotency.VerdictUnknownKey} {
		_, err := m.StartJob(context.Background(), idemReq("logs", v))
		var hit *IdempotentJobError
		if !errors.As(err, &hit) || hit.Verdict != v {
			t.Fatalf("verdict %v: err = %v", v, err)
		}
	}
	if got := len(m.Jobs("", "", 100)); got != 1 {
		t.Fatalf("a rejected key created a job: %d records", got)
	}
}

func TestStartJobWithoutKeyIsUnchanged(t *testing.T) {
	e := newEnv(t)
	m := e.manager(t, func(m *Manager) { free(m); m.runWorker = (&fakeWorker{}).fn })
	for i := 0; i < 2; i++ {
		if _, err := m.StartJob(context.Background(), RunRequest{Kind: "data"}); err != nil {
			t.Fatal(err)
		}
		waitIdle(t, m)
	}
	if got := len(m.Jobs("", "", 100)); got != 2 {
		t.Fatalf("keyless starts = %d records, want 2", got)
	}
}

func TestJobKeyRecordIsPersistedAndSurvivesRestartButIsNotExposed(t *testing.T) {
	e := newEnv(t)
	m := e.manager(t, func(m *Manager) { free(m); m.runWorker = (&fakeWorker{}).fn })
	job, err := m.StartJob(context.Background(), idemReq("data", idempotency.VerdictSame))
	if err != nil {
		t.Fatal(err)
	}
	waitIdle(t, m)

	raw, err := os.ReadFile(e.jobs)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{idemKeyHash, idemFP, idemKeyID} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("job file lacks %q", want)
		}
	}
	// What callers (and so the API) get never carries the record.
	for name, j := range map[string]*Job{"start": job, "get": mustGet(t, m, job.JobID), "list": m.Jobs("", "", 10)[0]} {
		b, _ := json.Marshal(j)
		if strings.Contains(string(b), idemKeyHash) || strings.Contains(string(b), idemFP) || strings.Contains(string(b), "idempotency") {
			t.Errorf("%s response exposes the idempotency record: %s", name, b)
		}
	}

	// A restart (a new manager on the same files) still recognises the key.
	m2 := e.manager(t, func(m *Manager) { free(m); m.runWorker = (&fakeWorker{}).fn })
	_, err = m2.StartJob(context.Background(), idemReq("data", idempotency.VerdictSame))
	var hit *IdempotentJobError
	if !errors.As(err, &hit) || hit.Job.JobID != job.JobID {
		t.Fatalf("after restart: %v", err)
	}
}

func mustGet(t *testing.T, m *Manager, id string) *Job {
	t.Helper()
	j, err := m.GetJob(id)
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func TestValidateJobRejectsMalformedIdempotencyRecord(t *testing.T) {
	base := func() *Job {
		return &Job{JobID: jobA, Kind: "data", Trigger: JobTriggerManual, Status: JobStatusSucceeded,
			RequestedBy: JobRequester{Type: JobRequesterUser}}
	}
	good := base()
	good.Idempotency = &JobIdempotency{KeyHash: idemKeyHash, Fingerprint: idemFP, KeyID: idemKeyID}
	if err := validateJob(good); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
	for name, rec := range map[string]*JobIdempotency{
		"short hash":       {KeyHash: "abc", Fingerprint: idemFP, KeyID: idemKeyID},
		"non-hex hash":     {KeyHash: strings.Repeat("z", 64), Fingerprint: idemFP, KeyID: idemKeyID},
		"path-like hash":   {KeyHash: "../../etc/passwd" + strings.Repeat("a", 48), Fingerprint: idemFP, KeyID: idemKeyID},
		"bad fingerprint":  {KeyHash: idemKeyHash, Fingerprint: "xyz", KeyID: idemKeyID},
		"bad key id":       {KeyHash: idemKeyHash, Fingerprint: idemFP, KeyID: "nothex!!"},
		"long key id":      {KeyHash: idemKeyHash, Fingerprint: idemFP, KeyID: "0123456789"},
		"missing key id":   {KeyHash: idemKeyHash, Fingerprint: idemFP},
		"missing finger":   {KeyHash: idemKeyHash, KeyID: idemKeyID},
		"uppercase digest": {KeyHash: strings.ToUpper(idemKeyHash), Fingerprint: idemFP, KeyID: idemKeyID},
	} {
		j := base()
		j.Idempotency = rec
		if err := validateJob(j); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestConcurrentSameKeyStartsCreateOneJob(t *testing.T) {
	e := newEnv(t)
	release := make(chan struct{})
	fw := &fakeWorker{run: func(ctx context.Context, kind, jobID string) ([]byte, error) {
		<-release
		return okOut(kind, jobID), nil
	}}
	m := e.manager(t, func(m *Manager) { free(m); m.runWorker = fw.fn })
	var wg sync.WaitGroup
	var mu sync.Mutex
	ids := map[string]int{}
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			job, err := m.StartJob(context.Background(), idemReq("data", idempotency.VerdictSame))
			var hit *IdempotentJobError
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ids[job.JobID]++
			case errors.As(err, &hit):
				ids[hit.Job.JobID]++
			default:
				t.Errorf("unexpected error %v", err)
			}
		}()
	}
	wg.Wait()
	close(release)
	waitIdle(t, m)
	if len(ids) != 1 {
		t.Fatalf("16 same-key starts produced %d distinct jobs: %v", len(ids), ids)
	}
}
