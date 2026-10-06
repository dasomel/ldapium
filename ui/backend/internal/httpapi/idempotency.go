package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/idempotency"
)

// Idempotency-Key for the core user/group writes (change package
// api-conditional-writes, part B: D216-6..D216-10). A keyed write runs at most
// once per (subject, key); a retry with the same request replays the first
// result instead of executing again.
//
// Pipeline (D216-10): session -> Idempotency-Key lookup (a replay ends here,
// before If-Match is looked at) -> the handler (If-Match validation, assertion
// control) -> record. Records live in process memory only: the chart enables
// the feature for a single replica with a Recreate rollout, and a restart
// forgets every record (documented in docs/api.md).
//
// What a record keeps: the SHA-256 of subject||key, an HMAC fingerprint of
// method, route and normalized body, the key_id of the fingerprint key, and the
// result (status, Location, a body of at most 4 KiB). Never a request body, a
// password, a DN of the requester or the key itself.

const (
	headerIdempotencyKey      = "Idempotency-Key"
	headerIdempotentReplayed  = "Idempotent-Replayed"
	maxIdempotencyRequestBody = 64 << 10

	envelopeCodeKey    = "ldapium_envelope_code"
	outcomeUnknownKey  = "ldapium_outcome_unknown"
	outcomeUnknownText = "the result of this request could not be determined; read the resource to check its state before retrying"
)

// newIdempotency builds what the config asks for. The persisted keyring (from
// UI_IDEMPOTENCY_KEY_FILE) is returned on its own too: backup start needs it
// even when the in-memory store is off. The store is nil unless enabled.
func newIdempotency(cfg config.Config) (*idempotency.Store, *idempotency.Keyring, error) {
	var persisted *idempotency.Keyring
	if cfg.IdempotencyKey != "" {
		var err error
		if persisted, err = idempotency.NewKeyring(cfg.IdempotencyKey, cfg.IdempotencyPreviousKey); err != nil {
			return nil, nil, err
		}
	}
	if !cfg.IdempotencyEnabled {
		return nil, persisted, nil
	}
	keys := persisted
	if keys == nil {
		var err error
		if keys, err = idempotency.RandomKeyring(); err != nil {
			return nil, nil, err
		}
	}
	return idempotency.NewStore(keys, idempotency.Options{TTL: cfg.IdempotencyTTL}), persisted, nil
}

// sweepIdempotency drops expired completed records once a minute.
func (s *Server) sweepIdempotency(ctx context.Context) {
	if s.idem == nil {
		return
	}
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.idem.Sweep()
			}
		}
	}()
}

// idempotentRoute and idempotentPasswordRoute are route-level middleware for
// the D216-11 matrix. Only routes that list them honor the header; everywhere
// else it is ignored, as the matrix says.
func (s *Server) idempotentRoute(next echo.HandlerFunc) echo.HandlerFunc {
	return s.idempotent(next, false)
}

func (s *Server) idempotentPasswordRoute(next echo.HandlerFunc) echo.HandlerFunc {
	return s.idempotent(next, true)
}

func (s *Server) idempotent(next echo.HandlerFunc, password bool) echo.HandlerFunc {
	return func(c echo.Context) error {
		req := c.Request()
		values := req.Header.Values(headerIdempotencyKey)
		if len(values) == 0 {
			return next(c)
		}
		key, err := idempotency.ParseKey(values)
		if err != nil {
			return apiErr(http.StatusBadRequest, codeInvalidRequest, err.Error())
		}
		if s.idem == nil {
			return apiErr(http.StatusUnprocessableEntity, codeIdempotencyUnsupported,
				"Idempotency-Key is not enabled on this server; repeat the request without it")
		}

		raw, err := io.ReadAll(io.LimitReader(req.Body, maxIdempotencyRequestBody+1))
		if err != nil || len(raw) > maxIdempotencyRequestBody {
			return apiErr(http.StatusBadRequest, codeInvalidRequest, "request body too large or unreadable")
		}
		req.Body = io.NopCloser(bytes.NewReader(raw))
		canon, valid := canonicalJSON(raw)
		if !valid {
			// Not JSON: the handler answers 400 and a 400 is never stored.
			return next(c)
		}
		if password && generatesPassword(raw) {
			return apiErr(http.StatusUnprocessableEntity, codeValidationFailed,
				"a server-generated password cannot be combined with Idempotency-Key: it could not be replayed")
		}

		query := req.URL.Query().Encode() // sorted by key
		sess := currentSession(c)
		d := s.idem.Begin(sess.DN, key, []byte(req.Method), []byte(c.Path()+"?"+query), canon)
		switch d.Kind {
		case idempotency.KindReplay:
			return replayIdempotent(c, d.Result)
		case idempotency.KindConflict:
			return apiErr(http.StatusConflict, codeIdempotencyKeyConflict, "a request with this Idempotency-Key is still being processed; retry shortly")
		case idempotency.KindReused:
			return apiErr(http.StatusUnprocessableEntity, codeIdempotencyKeyReused, "this Idempotency-Key was already used for a different request")
		case idempotency.KindUnknownKey:
			return apiErr(http.StatusConflict, codeIdempotencyOutcomeUnknown, outcomeUnknownText)
		case idempotency.KindCapacity:
			return apiErr(http.StatusServiceUnavailable, codeIdempotencyCapacity, "")
		}
		return s.runIdempotent(c, next, d.Handle, password)
	}
}

// generatesPassword reports a password body that asks the server to generate
// the password (empty or absent): that response carries a secret and cannot be
// stored, so such a request cannot carry a key (AC-011).
func generatesPassword(raw []byte) bool {
	var body struct {
		Password string `json:"password"`
	}
	return json.Unmarshal(raw, &body) == nil && body.Password == ""
}

// canonicalJSON re-serializes a JSON body with sorted keys and no insignificant
// whitespace so that two spellings of one request fingerprint alike. An empty
// body is valid (DELETE, lock without body fields). ok is false for anything
// that is not exactly one JSON value.
func canonicalJSON(raw []byte) (canon []byte, ok bool) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, true
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return nil, false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, false
	}
	out, err := json.Marshal(v) // map keys are emitted sorted
	if err != nil {
		return nil, false
	}
	return out, true
}

// captureWriter buffers a response so the middleware can decide what the client
// finally gets (the handler's answer, or outcome_unknown) once the result of the
// directory operation is known. Headers go to the real writer's map directly.
type captureWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (w *captureWriter) Header() http.Header { return w.header }
func (w *captureWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
}
func (w *captureWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(b)
}

// runIdempotent executes the handler to completion and records its result.
func (s *Server) runIdempotent(c echo.Context, next echo.HandlerFunc, h *idempotency.Handle, password bool) error {
	req := c.Request()
	// The operation runs to its end even when the caller disconnects: ldapclient
	// checks its context only at the start of a call, and a request abandoned
	// half way would leave a result nobody records. The caller's retry then
	// finds the result (or the in-flight record) instead of a second execution.
	c.SetRequest(req.WithContext(context.WithoutCancel(req.Context())))

	res := c.Response()
	orig := res.Writer
	buf := &captureWriter{header: orig.Header()}
	res.Writer = buf

	var panicked any
	func() {
		defer func() { panicked = recover() }()
		if err := next(c); err != nil {
			s.echo.HTTPErrorHandler(err, c)
		}
	}()
	res.Writer = orig

	unknown, _ := c.Get(outcomeUnknownKey).(bool)
	if panicked != nil {
		log.Printf("idempotent_write_panic request_id=%s", logQuote(requestIDOf(c)))
		unknown = true
	}
	status := buf.status
	if status == 0 {
		status = http.StatusOK
	}
	code, _ := c.Get(envelopeCodeKey).(string)
	body := buf.body.Bytes()

	switch {
	case unknown:
		return s.finishUnknown(c, h, panicked)
	case status >= 200 && status < 300:
		if password {
			body = []byte("{}") // the stored reply of a credential route never holds more than this
		}
		if len(body) > idempotency.MaxResultBody {
			// The effect happened, the original reply is delivered below, but
			// a replay could not repeat it: record that honestly.
			h.Complete(unknownResult(c))
		} else {
			h.Complete(idempotency.Result{Status: status, Location: res.Header().Get(echo.HeaderLocation), Body: append([]byte(nil), body...)})
		}
	case code == codePartialFailure && len(body) <= idempotency.MaxResultBody:
		h.Complete(idempotency.Result{Status: status, Body: append([]byte(nil), body...), Envelope: true})
	default:
		h.Release() // ordinary 4xx/5xx: not stored, the key may be retried (D216-8)
	}

	orig.WriteHeader(status)
	_, err := orig.Write(buf.body.Bytes())
	return err
}

// finishUnknown records outcome_unknown and answers with it. The handler's own
// answer (a generic 500, or nothing after a panic) is discarded: the client must
// not be told "internal error, retry" about a write that may have happened.
func (s *Server) finishUnknown(c echo.Context, h *idempotency.Handle, panicked any) error {
	if panicked == http.ErrAbortHandler {
		h.Complete(unknownResult(c))
		panic(panicked)
	}
	h.Complete(unknownResult(c))
	res := c.Response()
	res.Committed, res.Status, res.Size = false, 0, 0
	hdr := res.Header()
	hdr.Del(echo.HeaderLocation)
	hdr.Del(echo.HeaderContentType)
	hdr.Del(echo.HeaderRetryAfter)
	return writeAPIError(c, http.StatusConflict, codeIdempotencyOutcomeUnknown, outcomeUnknownText, nil)
}

func unknownResult(c echo.Context) idempotency.Result {
	env := buildEnvelope(c, http.StatusConflict, codeIdempotencyOutcomeUnknown, outcomeUnknownText, nil, "", "")
	b, _ := json.Marshal(env)
	return idempotency.Result{Status: http.StatusConflict, Body: b, Envelope: true}
}

// replayIdempotent answers from a record. Error envelopes get this request's
// own requestId so the envelope contract (requestId == X-Request-Id) holds.
func replayIdempotent(c echo.Context, r idempotency.Result) error {
	h := c.Response().Header()
	h.Set(headerIdempotentReplayed, "true")
	if r.Location != "" {
		h.Set(echo.HeaderLocation, r.Location)
	}
	if r.Envelope {
		var env errorEnvelope
		if err := json.Unmarshal(r.Body, &env); err == nil {
			env.RequestID = h.Get(echo.HeaderXRequestID)
			return c.JSON(r.Status, env)
		}
	}
	if len(r.Body) == 0 {
		return c.NoContent(r.Status)
	}
	return c.Blob(r.Status, echo.MIMEApplicationJSON, r.Body)
}

// isOutcomeUnknown reports a failure after which a write may or may not have
// been applied: the connection died (go-ldap's ErrorNetwork, or a net error).
func isOutcomeUnknown(err error) bool {
	if ldap.IsErrorWithCode(err, ldap.ErrorNetwork) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne)
}

func markOutcomeUnknown(c echo.Context) { c.Set(outcomeUnknownKey, true) }
