package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/backup"
	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/session"
)

const (
	jobsTestRun    = "20261006T150000Z-0123456789ab"
	jobsFastWorker = "import sys,json\njid=sys.argv[sys.argv.index('--job-id')+1]\nprint(json.dumps({'run_id':'" + jobsTestRun + "','kind':'data','job_id':jid,'verified':True,'local_verified':True,'destinations':[{'id':'local','status':'succeeded'}]}))\n"
	jobsSlowWorker = "import signal,sys,time\nsignal.signal(signal.SIGTERM, lambda *a: sys.exit(0))\ntime.sleep(60)\n"
)

type jobsHarness struct {
	e    *echo.Echo
	m    *backup.Manager
	dir  string
	call func(method, path, dn, origin, content string) *httptest.ResponseRecorder
}

func newJobsHarness(t *testing.T, workerSource string) *jobsHarness {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found in PATH")
	}
	python, _ = filepath.Abs(python)
	dir := t.TempDir()
	op := filepath.Join(dir, "operator.json")
	cfg := fmt.Sprintf(`{"root":%q,"instance_id":"inst-1","destinations":[{"id":"local","name":"Local","type":"local"}],"log_paths":["/registered/log"]}`, filepath.Join(dir, "root"))
	if err := os.WriteFile(op, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	worker := filepath.Join(dir, "worker.py")
	if err := os.WriteFile(worker, []byte(workerSource), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := backup.New(filepath.Join(dir, "policy.json"), op, worker, python)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{backups: m, cfg: config.Config{BackupAdminDNs: []string{"cn=admin"}}}
	e := echo.New()
	e.HTTPErrorHandler = apiErrorHandler(e.DefaultHTTPErrorHandler)
	api := e.Group("/api", func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Response().Header().Set(echo.HeaderXRequestID, "req-test-1")
			c.Set(sessionContextKey, &session.Session{DN: c.Request().Header.Get("X-Test-DN")})
			return next(c)
		}
	})
	s.backupRoutes(api)
	h := &jobsHarness{e: e, m: m, dir: dir}
	h.call = func(method, path, dn, origin, content string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(content))
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Test-DN", dn)
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		return w
	}
	t.Cleanup(func() {
		deadline := time.Now().Add(30 * time.Second)
		for m.View().Running && time.Now().Before(deadline) {
			if job := m.ActiveJob(); job != nil {
				_, _ = m.CancelJob(job.JobID)
			}
			time.Sleep(20 * time.Millisecond)
		}
	})
	return h
}

func (h *jobsHarness) admin(method, path string) *httptest.ResponseRecorder {
	return h.call(method, path, "cn=admin", "http://example.com", "")
}

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("not JSON: %v: %s", err, w.Body.String())
	}
	return out
}

func (h *jobsHarness) waitStatus(t *testing.T, id, want string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		w := h.admin("GET", "/api/v1/backups/jobs/"+id)
		if w.Code != 200 {
			t.Fatalf("GET job = %d %s", w.Code, w.Body.String())
		}
		if job := decode(t, w); job["status"] == want {
			return job
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("job %s never reached %s", id, want)
	return nil
}

func TestBackupJobStartReturnsIDAndCompletes(t *testing.T) {
	h := newJobsHarness(t, jobsFastWorker)
	w := h.admin("POST", "/api/v1/backups/jobs/data")
	if w.Code != 202 {
		t.Fatalf("start = %d %s", w.Code, w.Body.String())
	}
	body := decode(t, w)
	id, _ := body["job_id"].(string)
	if !backup.IsValidJobID(id) || body["kind"] != "data" || body["status"] != "running" {
		t.Fatalf("body = %v", body)
	}
	if loc := w.Header().Get("Location"); loc != "/api/v1/backups/jobs/"+id {
		t.Fatalf("Location = %q", loc)
	}
	job := h.waitStatus(t, id, "succeeded")
	art, _ := job["artifact"].(map[string]any)
	by, _ := job["requested_by"].(map[string]any)
	if art["run_id"] != jobsTestRun || by["type"] != "user" || by["fingerprint"] != fingerprintIdentity("cn=admin") || job["request_id"] != "req-test-1" {
		t.Fatalf("job = %v", job)
	}
	if strings.Contains(w.Body.String()+fmt.Sprint(job), "cn=admin") {
		t.Fatal("the requester DN must never be recorded or returned")
	}
	if job["finished_at"] == nil || job["deadline_at"] == nil || job["cancel_requested_at"] != nil {
		t.Fatalf("time fields: %v", job)
	}

	list := decode(t, h.admin("GET", "/api/v1/backups/jobs?kind=data&status=succeeded&limit=5"))
	if jobs, _ := list["jobs"].([]any); len(jobs) != 1 {
		t.Fatalf("list = %v", list)
	}
	if jobs, _ := decode(t, h.admin("GET", "/api/v1/backups/jobs?status=failed"))["jobs"].([]any); jobs == nil || len(jobs) != 0 {
		t.Fatal("an empty list must be [] not null")
	}
	for _, q := range []string{"kind=x", "status=x", "limit=0", "limit=101", "limit=abc"} {
		if w := h.admin("GET", "/api/v1/backups/jobs?"+q); w.Code != 400 || decode(t, w)["code"] != "invalid_request" {
			t.Fatalf("%s = %d %s", q, w.Code, w.Body.String())
		}
	}
}

func TestBackupJobBoundaries(t *testing.T) {
	h := newJobsHarness(t, jobsFastWorker)
	for _, tc := range []struct {
		name, method, path, dn, origin, body string
		status                               int
		code                                 string
	}{
		{"non-admin start", "POST", "/api/v1/backups/jobs/data", "cn=user", "http://example.com", "", 403, "admin_required"},
		{"foreign origin start", "POST", "/api/v1/backups/jobs/data", "cn=admin", "https://evil.example", "", 403, "origin_mismatch"},
		{"body on start", "POST", "/api/v1/backups/jobs/data", "cn=admin", "http://example.com", `{"x":1}`, 400, "invalid_request"},
		{"unknown kind", "POST", "/api/v1/backups/jobs/nope", "cn=admin", "http://example.com", "", 422, "validation_failed"},
		{"non-admin get", "GET", "/api/v1/backups/jobs/job-20261006T150000Z-111111111111", "cn=user", "", "", 403, "admin_required"},
		{"non-admin list", "GET", "/api/v1/backups/jobs", "cn=user", "", "", 403, "admin_required"},
		{"unknown job id", "GET", "/api/v1/backups/jobs/job-20261006T150000Z-111111111111", "cn=admin", "", "", 404, "job_not_found"},
		{"malformed job id", "GET", "/api/v1/backups/jobs/..%2F..%2Fetc", "cn=admin", "", "", 404, "job_not_found"},
		{"kind word as get id", "GET", "/api/v1/backups/jobs/data", "cn=admin", "", "", 404, "job_not_found"},
		{"cancel unknown", "POST", "/api/v1/backups/jobs/job-20261006T150000Z-111111111111/cancel", "cn=admin", "http://example.com", "", 404, "job_not_found"},
		{"cancel non-admin", "POST", "/api/v1/backups/jobs/job-20261006T150000Z-111111111111/cancel", "cn=user", "http://example.com", "", 403, "admin_required"},
		{"cancel foreign origin", "POST", "/api/v1/backups/jobs/job-20261006T150000Z-111111111111/cancel", "cn=admin", "https://evil.example", "", 403, "origin_mismatch"},
		{"cancel with body", "POST", "/api/v1/backups/jobs/job-20261006T150000Z-111111111111/cancel", "cn=admin", "http://example.com", `{"x":1}`, 400, "invalid_request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := h.call(tc.method, tc.path, tc.dn, tc.origin, tc.body)
			if w.Code != tc.status || decode(t, w)["code"] != tc.code {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestBackupBusyNamesTheActiveJob(t *testing.T) {
	h := newJobsHarness(t, jobsSlowWorker)
	first := decode(t, h.admin("POST", "/api/v1/backups/jobs/data"))
	id := first["job_id"].(string)

	w := h.admin("POST", "/api/v1/backups/jobs/logs")
	env := decode(t, w)
	if w.Code != 409 || env["code"] != "backup_busy" || env["retryable"] != true || env["active_job_id"] != id || env["active_kind"] != "data" ||
		env["error"] != env["message"] || env["requestId"] != "req-test-1" {
		t.Fatalf("busy = %d %v", w.Code, env)
	}
	if jobs := h.m.Jobs("", "", 10); len(jobs) != 1 {
		t.Fatalf("a busy start must not create a second job: %d", len(jobs))
	}
	// The existing policy-save mapping keeps working and now names the job too.
	r := httptest.NewRequest("PUT", "/api/v1/backups/policies", strings.NewReader(`{"data":{"enabled":false,"interval_minutes":1440,"keep_days":30,"keep_count":30,"destinations":["local"]},"logs":{"enabled":false,"interval_minutes":60,"keep_days":7,"keep_count":168,"destinations":["local"]}}`))
	r.Header.Set("Origin", "http://example.com")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("If-Match", `"0"`)
	r.Header.Set("X-Test-DN", "cn=admin")
	rec := httptest.NewRecorder()
	h.e.ServeHTTP(rec, r)
	if rec.Code != 409 || decode(t, rec)["active_job_id"] != id {
		t.Fatalf("policy save while running = %d %s", rec.Code, rec.Body.String())
	}
}

func TestBackupCancelOverHTTP(t *testing.T) {
	h := newJobsHarness(t, jobsSlowWorker)
	id := decode(t, h.admin("POST", "/api/v1/backups/jobs/data"))["job_id"].(string)

	w := h.admin("POST", "/api/v1/backups/jobs/"+id+"/cancel")
	job := decode(t, w)
	if w.Code != 202 || job["cancel_requested_at"] == nil {
		t.Fatalf("cancel = %d %s", w.Code, w.Body.String())
	}
	done := h.waitStatus(t, id, "cancelled")
	if done["staging_cleanup"] != "done" {
		t.Fatalf("job = %v", done)
	}
	if w := h.admin("POST", "/api/v1/backups/jobs/"+id+"/cancel"); w.Code != 200 {
		t.Fatalf("second cancel = %d %s", w.Code, w.Body.String())
	}
	if st := h.m.View().States["data"].Status; st != "cancelled" {
		t.Fatalf("state = %q", st)
	}
}

func TestBackupCancelOfFinishedJobIsNotCancellable(t *testing.T) {
	h := newJobsHarness(t, jobsFastWorker)
	id := decode(t, h.admin("POST", "/api/v1/backups/jobs/data"))["job_id"].(string)
	h.waitStatus(t, id, "succeeded")
	w := h.admin("POST", "/api/v1/backups/jobs/"+id+"/cancel")
	env := decode(t, w)
	if w.Code != 409 || env["code"] != "job_not_cancellable" || env["retryable"] != false {
		t.Fatalf("%d %v", w.Code, env)
	}
}

func TestBackupPersistenceFailureIs503AndStartsNothing(t *testing.T) {
	h := newJobsHarness(t, jobsFastWorker)
	// A directory where the job file belongs makes every job write fail.
	if err := os.Mkdir(filepath.Join(h.dir, "backup-jobs.json"), 0700); err != nil {
		t.Fatal(err)
	}
	w := h.admin("POST", "/api/v1/backups/jobs/data")
	env := decode(t, w)
	if w.Code != 503 || env["code"] != "persistence_unavailable" || env["retryable"] != true || w.Header().Get("Retry-After") == "" {
		t.Fatalf("%d %v", w.Code, env)
	}
	if strings.Contains(w.Body.String(), h.dir) {
		t.Fatal("the response must not carry filesystem paths")
	}
	if h.m.View().Running || len(h.m.Jobs("", "", 10)) != 0 {
		t.Fatal("a failed start record must not start a worker or leave a job")
	}
}
