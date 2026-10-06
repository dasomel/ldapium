package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// settleWith builds a manager whose lock is free over a running jobA and returns
// the reconciled record.
func settleWith(t *testing.T, e *env) *Job {
	t.Helper()
	e.seed(t, runningJob(jobA, "data", time.Now().UTC().Add(-time.Minute)))
	m := e.manager(t, free)
	if m.View().Running {
		t.Fatal("a free lock must not leave the manager running")
	}
	job, err := m.GetJob(jobA)
	if err != nil {
		t.Fatal(err)
	}
	return job
}

func TestWorkerResultIsValidatedBeforeSettling(t *testing.T) {
	dests := func(n int) string {
		var parts []string
		for i := 0; i < n; i++ {
			parts = append(parts, fmt.Sprintf(`{"id":"d%d","status":"failed","error_code":"transfer_failed"}`, i))
		}
		return strings.Join(parts, ",")
	}
	withDest := func(d string) string {
		return fmt.Sprintf(`{"run_id":%q,"kind":"data","verified":false,"local_verified":true,"job_id":%q,"destinations":[%s]}`, runA, jobA, d)
	}
	invalid := map[string]func(t *testing.T, e *env){
		"another job's result": func(t *testing.T, e *env) { e.writeResult(t, jobA, okResult(jobB, runA)) },
		"wrong kind": func(t *testing.T, e *env) {
			e.writeResult(t, jobA, strings.Replace(okResult(jobA, runA), `"kind":"data"`, `"kind":"logs"`, 1))
		},
		"bare verified": func(t *testing.T, e *env) { e.writeResult(t, jobA, `{"verified":true}`) },
		"garbage":       func(t *testing.T, e *env) { e.writeResult(t, jobA, "not json at all") },
		"empty file":    func(t *testing.T, e *env) { e.writeResult(t, jobA, "") },
		"trailing data": func(t *testing.T, e *env) { e.writeResult(t, jobA, okResult(jobA, runA)+` {"verified":true}`) },
		"oversized": func(t *testing.T, e *env) {
			e.writeResult(t, jobA, strings.TrimSuffix(okResult(jobA, runA), "}")+`,"pad":"`+strings.Repeat("x", maxResultBytes)+`"}`)
		},
		"run_id traversal":        func(t *testing.T, e *env) { e.writeResult(t, jobA, okResult(jobA, "../x")) },
		"run_id absolute path":    func(t *testing.T, e *env) { e.writeResult(t, jobA, okResult(jobA, "/etc/passwd")) },
		"verified without run_id": func(t *testing.T, e *env) { e.writeResult(t, jobA, okResult(jobA, "")) },
		"verified without local": func(t *testing.T, e *env) {
			e.writeResult(t, jobA, strings.Replace(okResult(jobA, runA), `"local_verified":true`, `"local_verified":false`, 1))
		},
		"unknown destination status": func(t *testing.T, e *env) { e.writeResult(t, jobA, withDest(`{"id":"local","status":"pwned"}`)) },
		"unknown error code": func(t *testing.T, e *env) {
			e.writeResult(t, jobA, withDest(`{"id":"local","status":"failed","error_code":"rm -rf /"}`))
		},
		"destination id is a path": func(t *testing.T, e *env) { e.writeResult(t, jobA, withDest(`{"id":"../../etc","status":"failed"}`)) },
		"duplicate destination": func(t *testing.T, e *env) {
			e.writeResult(t, jobA, withDest(`{"id":"a","status":"failed"},{"id":"a","status":"failed"}`))
		},
		"too many destinations": func(t *testing.T, e *env) { e.writeResult(t, jobA, withDest(dests(maxJobDests+1))) },
		"verified with failed dest": func(t *testing.T, e *env) {
			e.writeResult(t, jobA, strings.Replace(okResult(jobA, runA), `"succeeded"`, `"failed"`, 1))
		},
		"result is a directory": func(t *testing.T, e *env) {
			if err := os.MkdirAll(filepath.Join(e.root, ".results", jobA+".json"), 0700); err != nil {
				t.Fatal(err)
			}
		},
		"result is a symlink": func(t *testing.T, e *env) {
			target := filepath.Join(e.dir, "elsewhere.json")
			if err := os.WriteFile(target, []byte(okResult(jobA, runA)), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(e.root, ".results"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(e.root, ".results", jobA+".json")); err != nil {
				t.Fatal(err)
			}
		},
		".results is a symlink": func(t *testing.T, e *env) {
			other := filepath.Join(e.dir, "other-results")
			if err := os.MkdirAll(other, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(other, jobA+".json"), []byte(okResult(jobA, runA)), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(other, filepath.Join(e.root, ".results")); err != nil {
				t.Fatal(err)
			}
		},
		"run disagrees with the manifest": func(t *testing.T, e *env) {
			e.writeResult(t, jobA, okResult(jobA, runA))
			e.writeRun(t, "data", runB, goodManifest(runB, jobA, nil), nil)
		},
	}
	for name, setup := range invalid {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			setup(t, e)
			job := settleWith(t, e)
			if job.Status != JobStatusAbandoned || job.Error == nil || job.Error.Code != ErrCodeResultInvalid {
				t.Fatalf("an invalid result must be unverifiable (abandoned/result_invalid), got %+v", job)
			}
			if job.Status == JobStatusSucceeded || job.Status == JobStatusFailed {
				t.Fatal("settled from an untrusted result")
			}
			if on := e.readJobs(t); len(on) != 1 || on[0].Status != JobStatusAbandoned {
				t.Fatalf("settlement not persisted: %+v", on)
			}
		})
	}

	t.Run("valid result settles succeeded", func(t *testing.T) {
		e := newEnv(t)
		e.writeResult(t, jobA, okResult(jobA, runA))
		job := settleWith(t, e)
		if job.Status != JobStatusSucceeded || job.Artifact == nil || job.Artifact.RunID != runA || len(job.Destinations) != 1 {
			t.Fatalf("%+v", job)
		}
	})
	t.Run("valid failed result settles failed with its destinations", func(t *testing.T) {
		e := newEnv(t)
		e.writeResult(t, jobA, withDest(`{"id":"local","status":"succeeded"},{"id":"s3","status":"failed","error_code":"transfer_failed"}`))
		job := settleWith(t, e)
		if job.Status != JobStatusFailed || job.Error.Code != ErrCodeWorkerFailed || len(job.Destinations) != 2 || job.Destinations[1].ErrorCode != DestErrCodeTransferFailed {
			t.Fatalf("%+v", job)
		}
	})
}

func TestManifestArtifactBoundary(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte(strings.Repeat("S", 4096)), 0600); err != nil {
		t.Fatal(err)
	}

	t.Run("crafted manifest names are dropped and sizes come from files inside the run dir", func(t *testing.T) {
		e := newEnv(t)
		good := "ldif-bytes"
		dir := e.writeRun(t, "data", runA, goodManifest(runA, jobA, map[string]string{
			"data.ldif.gz":        sum(good),
			"../../etc/passwd":    sum("x"),
			"/etc/passwd":         sum("x"),
			"sub/dir.txt":         sum("x"),
			"..":                  sum("x"),
			"back\\slash":         sum("x"),
			"linked.txt":          sum("x"),
			"bad-sum.txt":         "not-a-sha",
			"missing.txt":         sum("x"),
			"a-first.txt":         sum("zz"),
			".hidden-leading-dot": sum("x"),
		}), map[string]string{"data.ldif.gz": good, "bad-sum.txt": "b", "a-first.txt": "zz", ".hidden-leading-dot": "h"})
		if err := os.Symlink(outside, filepath.Join(dir, "linked.txt")); err != nil {
			t.Fatal(err)
		}
		man := findMatchingManifest(e.root, "data", jobA, "inst-1")
		if man == nil {
			t.Fatal("owned manifest not found")
		}
		var names []string
		for _, f := range man.Files {
			names = append(names, f.Name)
			if f.Name == "data.ldif.gz" && f.Bytes != int64(len(good)) {
				t.Fatalf("size must be the file's own size, got %d", f.Bytes)
			}
		}
		if fmt.Sprint(names) != "[a-first.txt data.ldif.gz]" {
			t.Fatalf("files = %v; want only flat names backed by regular files, sorted", names)
		}
	})

	t.Run("job record carries only the sanitized artifact", func(t *testing.T) {
		e := newEnv(t)
		e.writeRun(t, "data", runA, goodManifest(runA, jobA, map[string]string{"../../etc/passwd": sum("x"), "data.ldif.gz": sum("d")}), map[string]string{"data.ldif.gz": "d"})
		job := settleWith(t, e)
		if job.Status != JobStatusAbandoned || job.Artifact == nil || job.Artifact.RunID != runA || len(job.Artifact.Files) != 1 || job.Artifact.Files[0].Name != "data.ldif.gz" {
			t.Fatalf("%+v", job)
		}
	})

	rejected := map[string]func(t *testing.T, e *env){
		"complete.json is a symlink": func(t *testing.T, e *env) {
			real := filepath.Join(e.dir, "real-complete.json")
			b, _ := json.Marshal(goodManifest(runA, jobA, map[string]string{"data.ldif.gz": sum("d")}))
			if err := os.WriteFile(real, b, 0600); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(e.root, "data", runA)
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(real, filepath.Join(dir, "complete.json")); err != nil {
				t.Fatal(err)
			}
		},
		"run_id differs from the directory name": func(t *testing.T, e *env) {
			e.writeRun(t, "data", runA, goodManifest(runB, jobA, nil), nil)
		},
		"run directory is a symlink": func(t *testing.T, e *env) {
			other := e.writeRun(t, "data", runB, goodManifest(runA, jobA, nil), nil)
			if err := os.Symlink(other, filepath.Join(e.root, "data", runA)); err != nil {
				t.Fatal(err)
			}
		},
		"foreign owner": func(t *testing.T, e *env) {
			m := goodManifest(runA, jobA, nil)
			m["owner"] = "someone-else"
			e.writeRun(t, "data", runA, m, nil)
		},
		"foreign instance": func(t *testing.T, e *env) {
			m := goodManifest(runA, jobA, nil)
			m["instance_id"] = "inst-2"
			e.writeRun(t, "data", runA, m, nil)
		},
		"another job's manifest": func(t *testing.T, e *env) {
			e.writeRun(t, "data", runA, goodManifest(runA, jobB, nil), nil)
		},
	}
	for name, setup := range rejected {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			setup(t, e)
			if man := findMatchingManifest(e.root, "data", jobA, "inst-1"); man != nil {
				t.Fatalf("manifest must not be accepted: %+v", man)
			}
			if job := settleWith(t, e); job.Artifact != nil || job.Local != nil {
				t.Fatalf("no artifact may be recorded: %+v", job)
			}
		})
	}
}

func validJobJSON(t *testing.T, mutate func(*Job)) []byte {
	t.Helper()
	now := time.Date(2026, 10, 6, 10, 0, 0, 0, time.UTC)
	j := &Job{JobID: jobA, Kind: "data", Trigger: JobTriggerManual, Status: JobStatusFailed, RequestedBy: JobRequester{Type: JobRequesterUser, Fingerprint: "0123456789abcdef"},
		RequestID: "req-1", CreatedAt: now, StartedAt: now, FinishedAt: now, Error: &JobError{Code: ErrCodeWorkerFailed, Message: ErrorMessage(ErrCodeWorkerFailed)},
		Destinations: []JobDestination{{ID: "local", Status: DestStatusSucceeded}},
		Artifact:     &JobArtifact{RunID: runA, Files: []JobArtifactFile{{Name: "data.ldif.gz", Bytes: 1, SHA256: sum("a")}}}}
	if mutate != nil {
		mutate(j)
	}
	b, err := json.Marshal(jobFile{Version: 1, Jobs: []*Job{j}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLoadJobFileValidatesEveryRecord(t *testing.T) {
	valid := validJobJSON(t, nil)
	cases := map[string][]byte{
		"null element":        []byte(`{"version":1,"jobs":[null]}`),
		"bad id":              validJobJSON(t, func(j *Job) { j.JobID = "not-a-job" }),
		"traversal id":        validJobJSON(t, func(j *Job) { j.JobID = "../x" }),
		"id with suffix path": validJobJSON(t, func(j *Job) { j.JobID = jobA + "/../../x" }),
		"unknown status":      validJobJSON(t, func(j *Job) { j.Status = "exploded" }),
		"unknown kind":        validJobJSON(t, func(j *Job) { j.Kind = "../data" }),
		"unknown trigger":     validJobJSON(t, func(j *Job) { j.Trigger = "cron" }),
		"unknown requester":   validJobJSON(t, func(j *Job) { j.RequestedBy.Type = "root" }),
		"DN as fingerprint":   validJobJSON(t, func(j *Job) { j.RequestedBy.Fingerprint = "cn=admin,dc=example,dc=org" }),
		"huge request id":     validJobJSON(t, func(j *Job) { j.RequestID = strings.Repeat("a", 1<<20) }),
		"huge error message":  validJobJSON(t, func(j *Job) { j.Error.Message = strings.Repeat("m", 1<<20) }),
		"unknown error code":  validJobJSON(t, func(j *Job) { j.Error.Code = "boom" }),
		"bad destination":     validJobJSON(t, func(j *Job) { j.Destinations[0].Status = "maybe" }),
		"artifact path name":  validJobJSON(t, func(j *Job) { j.Artifact.Files[0].Name = "../../etc/passwd" }),
		"artifact bad sha":    validJobJSON(t, func(j *Job) { j.Artifact.Files[0].SHA256 = "x" }),
		"artifact bad run id": validJobJSON(t, func(j *Job) { j.Artifact.RunID = "../run" }),
		"truncated":           valid[:len(valid)/2],
		"version 0":           bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":0`), 1),
		"version 2":           bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":2`), 1),
		"no version":          bytes.Replace(valid, []byte(`"version":1,`), nil, 1),
		"oversized file":      append(append([]byte{}, valid...), bytes.Repeat([]byte(" "), maxJobFileBytes+1)...),
		"duplicate ids": func() []byte {
			var f jobFile
			_ = json.Unmarshal(valid, &f)
			f.Jobs = append(f.Jobs, f.Jobs[0])
			b, _ := json.Marshal(f)
			return b
		}(),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			if err := os.WriteFile(e.jobs, content, 0600); err != nil {
				t.Fatal(err)
			}
			// End to end: startup must not panic and starts with an empty history.
			m := e.manager(t, free)
			if got := m.Jobs("", "", 100); len(got) != 0 {
				t.Fatalf("invalid file must start empty, got %+v", got)
			}
			if _, err := os.Stat(e.jobs); !os.IsNotExist(err) {
				t.Fatal("invalid file must be moved aside")
			}
			entries, _ := os.ReadDir(e.dir)
			quarantined := false
			for _, ent := range entries {
				quarantined = quarantined || strings.HasPrefix(ent.Name(), ".corrupt-")
			}
			if !quarantined {
				t.Fatal("no .corrupt-* file")
			}
		})
	}
	t.Run("symlinked job file", func(t *testing.T) {
		e := newEnv(t)
		real := filepath.Join(e.dir, "real.json")
		if err := os.WriteFile(real, valid, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, e.jobs); err != nil {
			t.Fatal(err)
		}
		if got, err := loadJobFile(e.jobs); err != nil || len(got) != 0 {
			t.Fatalf("symlinked job file must be quarantined: %v %v", got, err)
		}
	})
	t.Run("valid file loads", func(t *testing.T) {
		e := newEnv(t)
		if err := os.WriteFile(e.jobs, valid, 0600); err != nil {
			t.Fatal(err)
		}
		if got := e.manager(t, free).Jobs("", "", 10); len(got) != 1 || got[0].JobID != jobA {
			t.Fatalf("%+v", got)
		}
	})
}

// TestNoSensitiveInformationReachesRecordsErrorsOrLogs pushes secret-looking
// inputs through every path that can carry text into a job record, the job
// file, an error returned to a caller, or a log line.
func TestNoSensitiveInformationReachesRecordsErrorsOrLogs(t *testing.T) {
	e := newEnv(t)
	const (
		dn       = "cn=Directory Manager,dc=example,dc=com"
		password = "hunter2-S3cr3t-value"
		outside  = "/private/tmp/outside-root/secret.txt"
		rclone   = "rclone_password=Zx9-top"
	)
	sentinels := []string{dn, password, outside, rclone, e.policy, "/etc/shadow"}

	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	var failWrites atomic.Bool
	hostile := &fakeWorker{run: func(context.Context, string, string) ([]byte, error) {
		// stdout and the returned error both carry secrets, as a misbehaving
		// worker or rclone's stderr could.
		out := fmt.Sprintf(`{"run_id":%q,"verified":false,"local_verified":true,"destinations":[{"id":%q,"status":%q,"error_code":%q}]}`, dn, outside, password, rclone)
		return []byte(out), fmt.Errorf("worker said %s %s %s", password, outside, rclone)
	}}
	m := e.manager(t, func(m *Manager) {
		free(m)
		m.runWorker = hostile.fn
		m.writer = func(p string, d any) error {
			if p == e.jobs && failWrites.Load() {
				return fmt.Errorf("write %s: %s", e.policy, password)
			}
			return write(p, d)
		}
	})

	var errs []error
	// The requester identity and request ID are caller input: a DN / path must be dropped.
	job, err := m.StartJob(context.Background(), RunRequest{Kind: "data", ActorFingerprint: dn, RequestID: dn + outside})
	if err != nil {
		t.Fatal(err)
	}
	if job.RequestedBy.Fingerprint != "" || job.RequestID != "" {
		t.Fatalf("a DN/path must not be stored as identity or request id: %+v", job)
	}
	waitIdle(t, m)

	// Orphan reconciliation of a result file stuffed with secrets.
	e.seed(t, append(e.readJobs(t), runningJob(jobB, "data", time.Now().UTC()))...)
	e.writeResult(t, jobB, fmt.Sprintf(`{"job_id":%q,"kind":"data","run_id":%q,"verified":true,"local_verified":true,"destinations":[{"id":%q,"status":"succeeded"}],"note":%q}`, jobB, dn, outside, password))
	m2 := e.manager(t, func(m *Manager) { free(m); m.runWorker = hostile.fn })

	// Errors returned to callers.
	failWrites.Store(true)
	_, err = m.StartJob(context.Background(), RunRequest{Kind: "data"})
	errs = append(errs, err)
	_, err = m.GetJob(dn)
	errs = append(errs, err)
	_, err = m.GetJob("../../etc/shadow")
	errs = append(errs, err)
	_, err = m.CancelJob(outside)
	errs = append(errs, err)
	_, err = m.CancelJob(jobA) // terminal job
	errs = append(errs, err)
	_, err = m.StartJob(context.Background(), RunRequest{Kind: dn})
	errs = append(errs, err)

	var surfaces []string
	for _, er := range errs {
		if er == nil {
			t.Fatal("expected every probe to fail")
		}
		surfaces = append(surfaces, er.Error(), fmt.Sprintf("%v|%+v|%s", er, er, er))
	}
	for _, mgr := range []*Manager{m, m2} {
		b, _ := json.Marshal(mgr.Jobs("", "", 100))
		surfaces = append(surfaces, string(b))
	}
	raw, err := os.ReadFile(e.jobs)
	if err != nil {
		t.Fatal(err)
	}
	surfaces = append(surfaces, string(raw), logs.String())

	if got, _ := m2.GetJob(jobB); got.Status == JobStatusSucceeded {
		t.Fatalf("a result stuffed with secrets must not settle: %+v", got)
	}
	for _, s := range surfaces {
		for _, sentinel := range sentinels {
			if strings.Contains(s, sentinel) {
				t.Fatalf("sentinel %q leaked into: %.300s", sentinel, s)
			}
		}
	}
	// Control: the checks above can fail (the sentinel is reachable where text is allowed).
	if !strings.Contains(fmt.Sprint(errors.Unwrap(errs[0])), password) {
		t.Fatal("test setup: the writer error should carry the secret, hidden behind the fixed message")
	}
}
