package httpapi

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/dasomel/ldapium/ui/backend/internal/idempotency"
)

var (
	bkMaster = strings.Repeat("a", 64)
	bkOther  = strings.Repeat("b", 64)
)

func withKeys(t *testing.T, current, previous string) func(*Server) {
	t.Helper()
	kr, err := idempotency.NewKeyring(current, previous)
	if err != nil {
		t.Fatal(err)
	}
	return func(s *Server) { s.idemKeys = kr }
}

func (h *jobsHarness) start(kind, dn, key string) (int, map[string]any, http.Header) {
	hdr := map[string]string{}
	if key != "" {
		hdr["Idempotency-Key"] = key
	}
	w := h.callWith("POST", "/api/v1/backups/jobs/"+kind, dn, "http://example.com", "", hdr)
	return w.Code, decode(h.tt, w), w.Header()
}

func TestBackupStartSameKeyReturnsTheSameJob(t *testing.T) {
	h := newJobsHarnessIn(t, t.TempDir(), jobsSlowWorker, withKeys(t, bkMaster, ""))
	code1, first, hdr1 := h.start("data", "cn=admin", idemKey)
	if code1 != 202 || hdr1.Get("Idempotent-Replayed") != "" {
		t.Fatalf("first: %d %v", code1, first)
	}
	id := first["job_id"].(string)

	code2, second, hdr2 := h.start("data", "cn=admin", idemKey)
	if code2 != 202 || second["job_id"] != id || hdr2.Get("Idempotent-Replayed") != "true" ||
		hdr2.Get("Location") != "/api/v1/backups/jobs/"+id || second["status"] != "running" {
		t.Fatalf("replay while running: %d %v %v", code2, second, hdr2)
	}
	if jobs := h.m.Jobs("", "", 10); len(jobs) != 1 {
		t.Fatalf("job records = %d, want 1 (a retry must not start a second backup)", len(jobs))
	}

	// A different key while the job runs is backup_busy, as before (D216-12 point 7).
	code3, busy, _ := h.start("data", "cn=admin", "another-key-0123456789")
	if code3 != 409 || busy["code"] != "backup_busy" || busy["active_job_id"] != id {
		t.Fatalf("other key while running: %d %v", code3, busy)
	}
	// And no key at all is the unchanged behaviour: busy too.
	if code4, busy, _ := h.start("data", "cn=admin", ""); code4 != 409 || busy["code"] != "backup_busy" {
		t.Fatalf("keyless while running: %d %v", code4, busy)
	}
}

func TestBackupStartKeyReplayReflectsCurrentStatusAndSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	h := newJobsHarnessIn(t, dir, jobsFastWorker, withKeys(t, bkMaster, ""))
	_, first, _ := h.start("data", "cn=admin", idemKey)
	id := first["job_id"].(string)
	h.waitStatus(t, id, "succeeded")

	code, again, hdr := h.start("data", "cn=admin", idemKey)
	if code != 202 || again["job_id"] != id || again["status"] != "succeeded" || hdr.Get("Idempotent-Replayed") != "true" {
		t.Fatalf("replay after completion: %d %v", code, again)
	}
	// A keyless retry after the job ended is a new run (unchanged behaviour).
	_, fresh, _ := h.start("data", "cn=admin", "")
	if fresh["job_id"] == id {
		t.Fatal("a keyless start must create a new job")
	}
	h.waitStatus(t, fresh["job_id"].(string), "succeeded")

	// Restart: new manager on the same files, same persisted key.
	h2 := newJobsHarnessIn(t, dir, jobsFastWorker, withKeys(t, bkMaster, ""))
	code, after, hdr := h2.start("data", "cn=admin", idemKey)
	if code != 202 || after["job_id"] != id || hdr.Get("Idempotent-Replayed") != "true" {
		t.Fatalf("after restart: %d %v", code, after)
	}
	if n := len(h2.m.Jobs("", "", 10)); n != 2 {
		t.Fatalf("job records after restart = %d, want 2", n)
	}
}

func TestBackupStartKeyRotationAndLostKey(t *testing.T) {
	dir := t.TempDir()
	h := newJobsHarnessIn(t, dir, jobsFastWorker, withKeys(t, bkMaster, ""))
	_, first, _ := h.start("data", "cn=admin", idemKey)
	id := first["job_id"].(string)
	h.waitStatus(t, id, "succeeded")

	// Rotated, the old key kept as previous: the record still verifies.
	h2 := newJobsHarnessIn(t, dir, jobsFastWorker, withKeys(t, bkOther, bkMaster))
	if code, again, _ := h2.start("data", "cn=admin", idemKey); code != 202 || again["job_id"] != id {
		t.Fatalf("with the previous key: %d %v", code, again)
	}
	// Different request under a verifiable key: reused.
	if code, env, _ := h2.start("logs", "cn=admin", idemKey); code != 422 || env["code"] != "idempotency_key_reused" {
		t.Fatalf("other kind: %d %v", code, env)
	}

	// The old key is gone entirely: neither replay nor reuse can be claimed.
	h3 := newJobsHarnessIn(t, dir, jobsFastWorker, withKeys(t, bkOther, ""))
	code, env, _ := h3.start("data", "cn=admin", idemKey)
	if code != 409 || env["code"] != "idempotency_outcome_unknown" || env["retryable"] != false {
		t.Fatalf("lost key: %d %v", code, env)
	}
	if n := len(h3.m.Jobs("", "", 10)); n != 1 {
		t.Fatalf("a lost key must not start a job: %d records", n)
	}
}

func TestBackupStartKeyScopeAndConflicts(t *testing.T) {
	h := newJobsHarnessIn(t, t.TempDir(), jobsFastWorker, withKeys(t, bkMaster, ""))
	_, first, _ := h.start("data", "cn=admin", idemKey)
	id := first["job_id"].(string)
	h.waitStatus(t, id, "succeeded")

	// Same key, other kind: 422, nothing started.
	if code, env, _ := h.start("logs", "cn=admin", idemKey); code != 422 || env["code"] != "idempotency_key_reused" || env["retryable"] != false {
		t.Fatalf("other kind: %d %v", code, env)
	}
	// Another administrator's identical key is independent and reveals nothing.
	code, other, hdr := h.start("data", "cn=admin2", idemKey)
	if code != 202 || other["job_id"] == id || hdr.Get("Idempotent-Replayed") != "" {
		t.Fatalf("other administrator: %d %v", code, other)
	}
	h.waitStatus(t, other["job_id"].(string), "succeeded")
	if n := len(h.m.Jobs("", "", 10)); n != 2 {
		t.Fatalf("records = %d, want 2", n)
	}
}

func TestBackupStartKeyNeedsAPersistentKeyAndAValidFormat(t *testing.T) {
	h := newJobsHarnessIn(t, t.TempDir(), jobsFastWorker, nil) // no UI_IDEMPOTENCY_KEY_FILE
	code, env, _ := h.start("data", "cn=admin", idemKey)
	if code != 422 || env["code"] != "idempotency_unsupported" {
		t.Fatalf("no key file: %d %v", code, env)
	}
	if n := len(h.m.Jobs("", "", 10)); n != 0 {
		t.Fatalf("a refused key started %d jobs", n)
	}
	// Without a key the route works as before even without a key file.
	if code, _, _ := h.start("data", "cn=admin", ""); code != 202 {
		t.Fatalf("keyless start: %d", code)
	}

	h2 := newJobsHarnessIn(t, t.TempDir(), jobsFastWorker, withKeys(t, bkMaster, ""))
	for _, bad := range []string{"short", "has space in the key!!", strings.Repeat("a", 129)} {
		if code, env, _ := h2.start("data", "cn=admin", bad); code != 400 || env["code"] != "invalid_request" {
			t.Errorf("key %q: %d %v", bad, code, env)
		}
	}
	if n := len(h2.m.Jobs("", "", 10)); n != 0 {
		t.Fatalf("bad keys started %d jobs", n)
	}
}

func TestBackupStartKeyBoundariesAreUnchanged(t *testing.T) {
	h := newJobsHarnessIn(t, t.TempDir(), jobsFastWorker, withKeys(t, bkMaster, ""))
	hdr := map[string]string{"Idempotency-Key": idemKey}
	for name, tc := range map[string]struct {
		dn, origin, body string
		status           int
		code             string
	}{
		"non-admin":      {"cn=user", "http://example.com", "", 403, "admin_required"},
		"foreign origin": {"cn=admin", "https://evil.example", "", 403, "origin_mismatch"},
		"body":           {"cn=admin", "http://example.com", `{"x":1}`, 400, "invalid_request"},
	} {
		w := h.callWith("POST", "/api/v1/backups/jobs/data", tc.dn, tc.origin, tc.body, hdr)
		if w.Code != tc.status || decode(t, w)["code"] != tc.code {
			t.Errorf("%s: %d %s", name, w.Code, w.Body.String())
		}
	}
	if n := len(h.m.Jobs("", "", 10)); n != 0 {
		t.Fatalf("rejected requests started %d jobs", n)
	}
	// An unknown kind is a 422 validation_failed and is not stored under the key.
	if code, env, _ := h.start("nope", "cn=admin", idemKey); code != 422 || env["code"] != "validation_failed" {
		t.Fatalf("unknown kind: %d %v", code, env)
	}
	if code, _, _ := h.start("data", "cn=admin", idemKey); code != 202 {
		t.Fatalf("the key is still free after a rejected kind: %d", code)
	}
}

func TestBackupStartKeyRecordHoldsNoKeyNoDNAndIsNotServed(t *testing.T) {
	dir := t.TempDir()
	h := newJobsHarnessIn(t, dir, jobsFastWorker, withKeys(t, bkMaster, ""))
	_, first, _ := h.start("data", "cn=admin", idemKey)
	id := first["job_id"].(string)
	job := h.waitStatus(t, id, "succeeded")
	raw, err := os.ReadFile(filepath.Join(dir, "backup-jobs.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{idemKey, bkMaster, "cn=admin"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("job file contains %q", secret)
		}
	}
	if !strings.Contains(string(raw), `"key_id"`) || !strings.Contains(string(raw), `"fingerprint"`) {
		t.Errorf("job file lacks the fingerprint record: %s", raw)
	}
	for _, body := range []string{
		h.admin("GET", "/api/v1/backups/jobs/"+id).Body.String(),
		h.admin("GET", "/api/v1/backups/jobs").Body.String(),
		fmt.Sprint(job),
	} {
		if strings.Contains(body, "key_hash") || strings.Contains(body, `"key_id"`) || strings.Contains(body, "idempotency") {
			t.Errorf("the API serves the idempotency record: %s", body)
		}
	}
}

func TestBackupStartConcurrentSameKeyStartsOneJob(t *testing.T) {
	h := newJobsHarnessIn(t, t.TempDir(), jobsSlowWorker, withKeys(t, bkMaster, ""))
	var wg sync.WaitGroup
	var mu sync.Mutex
	ids := map[string]int{}
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := h.callWith("POST", "/api/v1/backups/jobs/data", "cn=admin", "http://example.com", "", map[string]string{"Idempotency-Key": idemKey})
			body := decode(t, w)
			mu.Lock()
			defer mu.Unlock()
			if w.Code != 202 {
				t.Errorf("status %d %v", w.Code, body)
				return
			}
			ids[body["job_id"].(string)]++
		}()
	}
	wg.Wait()
	if len(ids) != 1 {
		t.Fatalf("12 concurrent same-key starts produced jobs %v", ids)
	}
	if n := len(h.m.Jobs("", "", 20)); n != 1 {
		t.Fatalf("job records = %d, want 1", n)
	}
}
