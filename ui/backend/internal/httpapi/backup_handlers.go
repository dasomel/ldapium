package httpapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/dasomel/ldapium/ui/backend/internal/backup"
	"github.com/dasomel/ldapium/ui/backend/internal/idempotency"
	"github.com/labstack/echo/v4"
)

func (s *Server) StartBackground(ctx context.Context) {
	if s.backups != nil {
		s.backups.Start(ctx)
	}
	s.sweepIdempotency(ctx)
}
func (s *Server) backupRoutes(api *echo.Group) {
	g := api.Group("/v1/backups", s.requireBackupAdmin)
	g.GET("", func(c echo.Context) error {
		v := s.backups.View()
		c.Response().Header().Set("ETag", profileETag(v.Policies.Revision))
		return c.JSON(200, v)
	})
	g.PUT("/policies", s.handleBackupPolicies)
	g.PUT("/connections", s.handleBackupConnection)
	g.DELETE("/connections/:id", s.handleBackupConnection)
	// One path item per template: Echo and OpenAPI both need the same
	// parameter name at this position, so POST (start, id = kind) and GET
	// (id = job ID) share `:id` (D217-4).
	g.GET("/jobs", s.handleBackupJobList)
	g.POST("/jobs/:id", s.handleBackupRun)
	g.GET("/jobs/:id", s.handleBackupJobGet)
	g.POST("/jobs/:id/cancel", s.handleBackupJobCancel)
}

// backupBusy is the 409 for every ErrBusy mapping; it names the active job.
func (s *Server) backupBusy(c echo.Context) error {
	id, kind, _ := s.backups.ActiveJobInfo()
	return writeBackupBusy(c, id, kind)
}

// backupJobError maps the typed job errors to registered codes.
func (s *Server) backupJobError(c echo.Context, err error) error {
	var persist *backup.PersistenceUnavailableError
	switch {
	case errors.Is(err, backup.ErrBusy):
		var busy *backup.BusyError
		if errors.As(err, &busy) {
			return writeBackupBusy(c, busy.ActiveJobID, busy.ActiveKind)
		}
		return s.backupBusy(c)
	case errors.Is(err, backup.ErrJobNotFound):
		return writeAPIError(c, 404, codeJobNotFound, "backup job not found", err)
	case errors.Is(err, backup.ErrJobNotCancellable):
		return writeAPIError(c, 409, codeJobNotCancellable, "backup job is not cancellable", err)
	case errors.As(err, &persist):
		// 503: the record could not be written, so nothing started / no signal went out.
		return writeAPIError(c, 503, codePersistenceUnavailable, "", err)
	}
	return writeAPIError(c, 422, codeValidationFailed, "kind/source unavailable", err)
}

// requireBackupWrite is requireProfileWrite plus the empty-body rule shared by
// the run and cancel actions: their only input is the path.
func requireBackupWrite(c echo.Context) error {
	if err := requireProfileWrite(c); err != nil {
		return err
	}
	if c.Request().ContentLength > 0 {
		return echo.NewHTTPError(400, "job body must be empty")
	}
	return nil
}

func (s *Server) handleBackupJobList(c echo.Context) error {
	kind, status := c.QueryParam("kind"), c.QueryParam("status")
	if kind != "" && kind != "data" && kind != "logs" {
		return echo.NewHTTPError(400, "kind must be data or logs")
	}
	switch status {
	case "", backup.JobStatusRunning, backup.JobStatusSucceeded, backup.JobStatusFailed, backup.JobStatusCancelled, backup.JobStatusAbandoned:
	default:
		return echo.NewHTTPError(400, "unknown job status")
	}
	limit := 20
	if raw := c.QueryParam("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 100 {
			return echo.NewHTTPError(400, "limit must be 1-100")
		}
		limit = n
	}
	jobs := s.backups.Jobs(kind, status, limit)
	if jobs == nil {
		jobs = []*backup.Job{}
	}
	return c.JSON(200, map[string]any{"jobs": jobs})
}

func (s *Server) handleBackupJobGet(c echo.Context) error {
	job, err := s.backups.GetJob(c.Param("id"))
	if err != nil {
		return s.backupJobError(c, err)
	}
	return c.JSON(200, job)
}

// handleBackupJobCancel: running -> 202 with the recorded cancel request, an
// already cancelled job -> 200 (idempotent), any other terminal job -> 409.
func (s *Server) handleBackupJobCancel(c echo.Context) error {
	if err := requireBackupWrite(c); err != nil {
		return err
	}
	job, err := s.backups.CancelJob(c.Param("id"))
	if err != nil {
		return s.backupJobError(c, err)
	}
	if job.Status == backup.JobStatusCancelled {
		return c.JSON(200, job)
	}
	log.Printf("backup_cancel_requested job_id=%s actor_fp=%s request_id=%q", job.JobID, fingerprintIdentity(currentSession(c).DN), requestIDOf(c))
	return c.JSON(202, job)
}
func (s *Server) requireBackupAdmin(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if s.backups == nil {
			return apiErr(404, codeFeatureDisabled, "backups disabled")
		}
		sess := currentSession(c)
		if sess != nil {
			for _, dn := range s.cfg.BackupAdminDNs {
				if sess.DN == dn {
					return next(c)
				}
			}
		}
		return apiErr(403, codeAdminRequired, "backup administrator required")
	}
}
func (s *Server) handleBackupPolicies(c echo.Context) error {
	if err := requireProfileWrite(c); err != nil {
		return err
	}
	raw := c.Request().Header.Get("If-Match")
	revision, err := strconv.ParseUint(strings.Trim(raw, `"`), 10, 64)
	if err != nil || raw != profileETag(revision) {
		return echo.NewHTTPError(428, "policy revision ETag required")
	}
	var p backup.Policies
	decoder := json.NewDecoder(http.MaxBytesReader(c.Response(), c.Request().Body, 16<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&p) != nil {
		return echo.NewHTTPError(400, "invalid backup policy JSON")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || p.Revision != 0 {
		return echo.NewHTTPError(400, "revision is server-managed; one JSON object required")
	}
	saved, err := s.backups.Save(p, revision)
	if errors.Is(err, backup.ErrConflict) {
		return echo.NewHTTPError(412, "backup policies changed; reload")
	}
	if errors.Is(err, backup.ErrBusy) {
		return s.backupBusy(c)
	}
	if err != nil {
		return echo.NewHTTPError(422, "invalid policy or persistence unavailable; reload and check configuration")
	}
	log.Printf("backup_policy_saved actor=%q revision=%d", currentSession(c).DN, saved.Revision)
	c.Response().Header().Set("ETag", profileETag(saved.Revision))
	return c.JSON(200, saved)
}
func (s *Server) handleBackupRun(c echo.Context) error {
	if err := requireBackupWrite(c); err != nil {
		return err
	}
	// D32: job input is only the fixed kind (the path); no commands, files or
	// destinations come from this request. The worker runs the saved policy
	// with operator-owned secrets. The requester is recorded as a one-way
	// fingerprint only (D217-12).
	idem, err := s.backupIdempotency(c)
	if err != nil {
		return err
	}
	job, err := s.backups.StartJob(context.Background(), backup.RunRequest{
		Kind:             c.Param("id"),
		Trigger:          backup.JobTriggerManual,
		RequesterType:    backup.JobRequesterUser,
		ActorFingerprint: fingerprintIdentity(currentSession(c).DN),
		RequestID:        requestIDOf(c),
		Idempotency:      idem,
	})
	var hit *backup.IdempotentJobError
	if errors.As(err, &hit) {
		return replayBackupStart(c, hit)
	}
	if err != nil {
		return s.backupJobError(c, err)
	}
	c.Response().Header().Set(echo.HeaderLocation, "/api/v1/backups/jobs/"+job.JobID)
	return c.JSON(202, map[string]string{"job_id": job.JobID, "kind": job.Kind, "status": job.Status})
}

// backupIdempotency reads the optional Idempotency-Key of a backup start (#216,
// D216-12). The key lives in the durable job record, so unlike the core routes
// it does not depend on the in-memory switch: it needs backups enabled (this
// route) and the persisted fingerprint key (UI_IDEMPOTENCY_KEY_FILE), without
// which a restart could not recognise the request and the key is refused
// instead of silently unprotected. No header: nil, the unchanged behaviour.
func (s *Server) backupIdempotency(c echo.Context) (*backup.RequestIdempotency, error) {
	values := c.Request().Header.Values(headerIdempotencyKey)
	if len(values) == 0 {
		return nil, nil
	}
	key, err := idempotency.ParseKey(values)
	if err != nil {
		return nil, apiErr(http.StatusBadRequest, codeInvalidRequest, err.Error())
	}
	if s.idemKeys == nil {
		return nil, apiErr(http.StatusUnprocessableEntity, codeIdempotencyUnsupported,
			"Idempotency-Key for backups needs the persisted fingerprint key (UI_IDEMPOTENCY_KEY_FILE); repeat the request without it")
	}
	// The kind is part of the request: the same key for another kind is a reuse.
	parts := [][]byte{[]byte(c.Request().Method), []byte("/api/v1/backups/jobs/" + c.Param("id"))}
	fp, keyID := s.idemKeys.Fingerprint(parts...)
	keys := s.idemKeys
	return &backup.RequestIdempotency{
		KeyHash:     idempotency.KeyHash(currentSession(c).DN, key),
		Fingerprint: hex.EncodeToString(fp),
		KeyID:       keyID,
		Verify: func(id string, stored []byte) idempotency.Verdict {
			return keys.Verify(id, stored, parts...)
		},
	}, nil
}

// replayBackupStart answers a keyed start whose key already started a job: the
// same 202 and Location for the same request (the body shows the job's current
// status; Location is the authority), 422 for another request, and 409
// outcome_unknown when the fingerprint key that made the record is gone.
func replayBackupStart(c echo.Context, hit *backup.IdempotentJobError) error {
	switch hit.Verdict {
	case idempotency.VerdictSame:
		h := c.Response().Header()
		h.Set(headerIdempotentReplayed, "true")
		h.Set(echo.HeaderLocation, "/api/v1/backups/jobs/"+hit.Job.JobID)
		return c.JSON(202, map[string]string{"job_id": hit.Job.JobID, "kind": hit.Job.Kind, "status": hit.Job.Status})
	case idempotency.VerdictDifferent:
		return apiErr(http.StatusUnprocessableEntity, codeIdempotencyKeyReused, "this Idempotency-Key was already used for a different request")
	}
	return apiErr(http.StatusConflict, codeIdempotencyOutcomeUnknown, "the Idempotency-Key cannot be verified (its fingerprint key is no longer configured); read the backup job list to check what was started")
}

func (s *Server) handleBackupConnection(c echo.Context) error {
	if err := requireProfileWrite(c); err != nil {
		return err
	}
	raw := c.Request().Header.Get("If-Match")
	revision, err := strconv.ParseUint(strings.Trim(raw, `"`), 10, 64)
	if err != nil || raw != profileETag(revision) {
		return echo.NewHTTPError(428, "backup revision ETag required")
	}
	if c.Request().Method == http.MethodDelete {
		err = s.backups.DeleteConnection(c.Param("id"), revision)
	} else {
		var connection backup.Connection
		decoder := json.NewDecoder(http.MaxBytesReader(c.Response(), c.Request().Body, 32<<10))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&connection) != nil {
			return echo.NewHTTPError(400, "invalid connection JSON")
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			return echo.NewHTTPError(400, "one JSON object required")
		}
		err = s.backups.SaveConnection(connection, revision)
	}
	if errors.Is(err, backup.ErrConflict) {
		return echo.NewHTTPError(412, "backup settings changed; reload")
	}
	if errors.Is(err, backup.ErrBusy) {
		return s.backupBusy(c)
	}
	if err != nil {
		return echo.NewHTTPError(422, err.Error())
	}
	log.Printf("backup_connection_changed actor=%q method=%s", currentSession(c).DN, c.Request().Method)
	view := s.backups.View()
	c.Response().Header().Set("ETag", profileETag(view.Policies.Revision))
	return c.JSON(200, view)
}
