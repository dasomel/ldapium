package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"strings"
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
	definitiveKey      = "ldapium_definitive"
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
		// A keyed request whose body cannot be normalised never reaches the
		// handler (D216-22, revised): the fingerprint and the body the handler
		// executes must be the same thing, and the handler's decoder reads only
		// the first JSON value and is case-insensitive about field names.
		canon, err := strictBody(req.Method, req.Header.Get(echo.HeaderContentType), raw)
		if err != nil {
			return apiErr(http.StatusBadRequest, codeInvalidRequest, err.Error())
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
	if len(bytes.TrimSpace(raw)) == 0 {
		return true
	}
	return json.Unmarshal(raw, &body) == nil && body.Password == ""
}

var errBodyNotNormalizable = errors.New("with Idempotency-Key the body must be exactly one JSON value, without duplicate or case-colliding field names, sent as application/json")

// strictBody normalises the body of a keyed request for fingerprinting and
// refuses everything that could make the fingerprint differ from what the
// handler executes: trailing data after the first value (the handler's decoder
// ignores it), invalid JSON, a field name given twice or twice under different
// case (encoding/json folds case, so the later one silently wins), a body on a
// DELETE (the handlers ignore it) and a wrong Content-Type. Once past this, the
// decoded struct is a function of the sorted-key canonical form. An empty body
// is valid (DELETE, lock without fields).
func strictBody(method, contentType string, raw []byte) ([]byte, error) {
	empty := len(bytes.TrimSpace(raw)) == 0
	if method == http.MethodDelete {
		if !empty {
			return nil, errBodyNotNormalizable
		}
		return nil, nil
	}
	if empty {
		return nil, nil
	}
	if mt, _, err := mime.ParseMediaType(contentType); err != nil || (mt != "application/json" && mt != "application/merge-patch+json") {
		return nil, errBodyNotNormalizable
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := walkNoDuplicates(dec); err != nil {
		return nil, errBodyNotNormalizable
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errBodyNotNormalizable
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, errBodyNotNormalizable
	}
	return json.Marshal(v) // map keys are emitted sorted
}

// walkNoDuplicates consumes one JSON value from dec and fails on a duplicate
// object key at any depth, comparing case-insensitively like encoding/json.
func walkNoDuplicates(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	if d == '[' {
		for dec.More() {
			if err := walkNoDuplicates(dec); err != nil {
				return err
			}
		}
		_, err := dec.Token()
		return err
	}
	var seen []string
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return err
		}
		key := k.(string)
		for _, other := range seen {
			if strings.EqualFold(key, other) { // the fold encoding/json uses
				return errBodyNotNormalizable
			}
		}
		seen = append(seen, key)
		if err := walkNoDuplicates(dec); err != nil {
			return err
		}
	}
	_, err = dec.Token()
	return err
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
	definitive, _ := c.Get(definitiveKey).(bool)
	body := buf.body.Bytes()
	// A server error nobody classified as a definitive directory answer may
	// hide an applied write: the key stays taken (outcome_unknown), whatever
	// text the handler chose.
	if status >= http.StatusInternalServerError && !definitive && code != codePartialFailure {
		unknown = true
	}

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
	case code == codePartialFailure:
		if len(body) > idempotency.MaxResultBody {
			// The DN in the body is unbounded. The attempt may have left an entry
			// behind, so the key must not be released: record that the outcome
			// is unknown (only the fixed code, never this body).
			h.Complete(unknownResult(c))
		} else {
			h.Complete(idempotency.Result{Status: status, Body: append([]byte(nil), body...), Envelope: true})
		}
	default:
		// Rejected before the write (validation, auth, If-Match 412, key
		// conflict) or answered definitively by the directory (404, 409,
		// 403, ...): not stored, the key may be retried (D216-8).
		h.Release()
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

// isOutcomeUnknown is deliberately conservative (D216-20): once a write may have
// been sent, the ONLY failure that proves "not applied" is a definitive answer
// from the server, a typed *ldap.Error carrying a result code the server
// returned. Everything else is unknown: a lost response arrives from go-ldap as
// a plain "unable to read LDAP response packet: EOF" error, and io.EOF,
// connection resets, deadlines, cancellations and go-ldap's own client-side
// codes (200-206: network, unexpected message/response, ...) say nothing about
// what the server did.
func isOutcomeUnknown(err error) bool {
	var le *ldap.Error
	if errors.As(err, &le) {
		return le.ResultCode >= ldap.ErrorNetwork && le.ResultCode <= ldap.ErrorEmptyPassword
	}
	return true
}

func markOutcomeUnknown(c echo.Context) { c.Set(outcomeUnknownKey, true) }

// markDefinitive notes that the directory itself answered with an error
// result, so a write that failed this way was not applied.
func markDefinitive(c echo.Context) { c.Set(definitiveKey, true) }
