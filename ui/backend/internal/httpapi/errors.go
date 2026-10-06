package httpapi

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// Every /api error leaves the server as one JSON envelope (change package
// api-error-envelope, D218-1):
//
//	{"error": "...", "message": "...", "code": "...", "requestId": "...", "retryable": false}
//
// error is the primary field; message is an identical, deprecated alias that
// the application-profile and backup screens still read (D218-4). code is a
// stable snake_case name from the closed, append-only table below. requestId
// is the X-Request-Id response header, so a client report can be matched to
// the server log line that carries the unredacted cause.
//
// The only /api errors that are not envelopes are the documented exceptions
// (D218-6): the GET /api/health/ldap probe body, redirects, and responses
// that never carry a body (OPTIONS 204, HEAD).
type errorEnvelope struct {
	Error     string `json:"error"`
	Message   string `json:"message"`
	Code      string `json:"code"`
	RequestID string `json:"requestId"`
	Retryable bool   `json:"retryable"`

	// State and DN exist only on partial_failure (#216, the documented
	// exception to the five-key envelope): which state a failed user creation
	// left behind, and the DN of the entry the caller must go and check.
	State string `json:"state,omitempty"`
	DN    string `json:"dn,omitempty"`

	// ActiveJobID and ActiveKind exist only on backup_busy (#217, D217-8):
	// the job that holds the single run slot, so a caller who lost the 202
	// can look it up. Naming it proves nothing about who started it.
	ActiveJobID string `json:"active_job_id,omitempty"`
	ActiveKind  string `json:"active_kind,omitempty"`
}

// Error codes (D218-3). Closed set: callers switch on these, so a name is a
// contract. New codes are appended here, in codeTable, in the golden list in
// errors_envelope_test.go and in docs/api.md in the same change; renaming or
// removing one is an API break. Codes reserved for #214-#217 are listed in
// docs/api.md and are added with the change that first emits them.
const (
	codeInvalidRequest       = "invalid_request"
	codeInvalidCredentials   = "invalid_credentials"
	codeUnauthenticated      = "unauthenticated"
	codeSessionExpired       = "session_expired"
	codeForbidden            = "forbidden"
	codeAdminRequired        = "admin_required"
	codeOriginMismatch       = "origin_mismatch"
	codeNotFound             = "not_found"
	codeFeatureDisabled      = "feature_disabled"
	codeMethodNotAllowed     = "method_not_allowed"
	codeConflict             = "conflict"
	codeAlreadyExists        = "already_exists"
	codeBackupBusy           = "backup_busy"
	codeRevisionConflict     = "revision_conflict"
	codeUnsupportedMediaType = "unsupported_media_type"
	codeValidationFailed     = "validation_failed"
	codeIfMatchRequired      = "if_match_required"
	codeLoginRateLimited     = "login_rate_limited"
	codeInternal             = "internal"
	codeUpstreamFailed       = "upstream_failed"
	codeKeycloakDisabled     = "keycloak_disabled"
	codeUnavailable          = "unavailable"
	// Backup jobs (#217): an unknown or malformed job ID, a cancel of a job
	// that is no longer running, and a start/cancel record that could not be
	// written (the worker was not started / no signal was sent).
	codeJobNotFound            = "job_not_found"
	codeJobNotCancellable      = "job_not_cancellable"
	codePersistenceUnavailable = "persistence_unavailable"
	// codePartialFailure: a user creation whose password step did not
	// complete (#216). 500, never retryable; carries state and dn.
	codePartialFailure = "partial_failure"
	// Idempotency-Key (#216, part B). The family is closed at these five
	// names (D218-3, D218-14).
	codeIdempotencyKeyConflict    = "idempotency_key_conflict"
	codeIdempotencyKeyReused      = "idempotency_key_reused"
	codeIdempotencyOutcomeUnknown = "idempotency_outcome_unknown"
	codeIdempotencyCapacity       = "idempotency_capacity"
	codeIdempotencyUnsupported    = "idempotency_unsupported"
	// Keyset listing (#215).
	codeCursorInvalid     = "cursor_invalid"
	codeSizeLimitExceeded = "size_limit_exceeded"
	codeScanLimitExceeded = "scan_limit_exceeded"
	codeScanTimeout       = "scan_timeout"
	// codeCurrentPasswordRejected: self-service password change whose current
	// password slapd refused to verify (#264, D264-1). 400, not 401: the UI
	// treats 401 as session loss.
	codeCurrentPasswordRejected = "current_password_rejected"
)

// Static 5xx texts (D218-8). The Keycloak ones are the pre-envelope phrases,
// kept so the UI shows what it always showed.
const (
	internalErrorMessage          = "internal error"
	unavailableErrorMessage       = "service temporarily unavailable"
	persistenceUnavailableMessage = "backup state could not be saved; retry"
	keycloakDisabledMessage       = "Keycloak admin connection is disabled"
	keycloakUpstreamMessage       = "Keycloak operation failed; reload observed state before retrying"
	// partialFailureMessage is true for every state: it promises nothing about
	// the password and does not say whether the entry still exists beyond
	// naming it; the state key and docs/api.md carry the distinction.
	partialFailureMessage = "user creation did not complete: the password step failed and the new entry was not removed as verified; " +
		"check the entry named in dn (state says what was and was not done), then set its password with POST /api/users/password " +
		"or remove it with DELETE /api/users?dn="
	scanTimeoutMessage = "the listing timed out; narrow it with q or try again later"

	idempotencyCapacityMessage = "idempotency record capacity reached; retry later"

	// retryAfterDefaultSeconds is the Retry-After of a retryable 429/503 whose
	// producer did not compute one (the login limiter does; see handleLogin).
	retryAfterDefaultSeconds = 5
	// retryAfterScanTimeoutSeconds: the scan already used its whole 30 s
	// request deadline, so an immediate retry of the same listing would only
	// time out again.
	retryAfterScanTimeoutSeconds = 30
)

// codeSpec is the status a code is emitted with and, for 5xx codes, the
// static body text (D218-8): a 5xx body never carries handler or cause text.
type codeSpec struct {
	status int
	static string
}

var codeTable = map[string]codeSpec{
	codeInvalidRequest:         {http.StatusBadRequest, ""},
	codeInvalidCredentials:     {http.StatusUnauthorized, ""},
	codeUnauthenticated:        {http.StatusUnauthorized, ""},
	codeSessionExpired:         {http.StatusUnauthorized, ""},
	codeForbidden:              {http.StatusForbidden, ""},
	codeAdminRequired:          {http.StatusForbidden, ""},
	codeOriginMismatch:         {http.StatusForbidden, ""},
	codeNotFound:               {http.StatusNotFound, ""},
	codeFeatureDisabled:        {http.StatusNotFound, ""},
	codeMethodNotAllowed:       {http.StatusMethodNotAllowed, ""},
	codeConflict:               {http.StatusConflict, ""},
	codeAlreadyExists:          {http.StatusConflict, ""},
	codeBackupBusy:             {http.StatusConflict, ""},
	codeRevisionConflict:       {http.StatusPreconditionFailed, ""},
	codeUnsupportedMediaType:   {http.StatusUnsupportedMediaType, ""},
	codeValidationFailed:       {http.StatusUnprocessableEntity, ""},
	codeIfMatchRequired:        {http.StatusPreconditionRequired, ""},
	codeLoginRateLimited:       {http.StatusTooManyRequests, ""},
	codeInternal:               {http.StatusInternalServerError, internalErrorMessage},
	codeUpstreamFailed:         {http.StatusBadGateway, keycloakUpstreamMessage},
	codeKeycloakDisabled:       {http.StatusServiceUnavailable, keycloakDisabledMessage},
	codeUnavailable:            {http.StatusServiceUnavailable, unavailableErrorMessage},
	codeJobNotFound:            {http.StatusNotFound, ""},
	codeJobNotCancellable:      {http.StatusConflict, ""},
	codePersistenceUnavailable: {http.StatusServiceUnavailable, persistenceUnavailableMessage},
	codePartialFailure:         {http.StatusInternalServerError, partialFailureMessage},

	codeIdempotencyKeyConflict:    {http.StatusConflict, ""},
	codeIdempotencyKeyReused:      {http.StatusUnprocessableEntity, ""},
	codeIdempotencyOutcomeUnknown: {http.StatusConflict, ""},
	codeIdempotencyCapacity:       {http.StatusServiceUnavailable, idempotencyCapacityMessage},
	codeIdempotencyUnsupported:    {http.StatusUnprocessableEntity, ""},
	codeCursorInvalid:             {http.StatusBadRequest, ""},
	codeSizeLimitExceeded:         {http.StatusUnprocessableEntity, ""},
	codeScanLimitExceeded:         {http.StatusUnprocessableEntity, ""},
	codeScanTimeout:               {http.StatusServiceUnavailable, scanTimeoutMessage},
	codeCurrentPasswordRejected:   {http.StatusBadRequest, ""},
}

// codeForStatus is the default code for a bare echo.NewHTTPError(status, ...)
// (D218-2): the ~100 handler sites that do not need a domain-specific code
// keep working unchanged. Anything not listed falls back to invalid_request
// (4xx) or internal (5xx), so a new producer can never break the envelope.
func codeForStatus(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return codeUnauthenticated
	case http.StatusForbidden:
		return codeForbidden
	case http.StatusNotFound:
		return codeNotFound
	case http.StatusMethodNotAllowed:
		return codeMethodNotAllowed
	case http.StatusConflict:
		return codeConflict
	case http.StatusPreconditionFailed:
		return codeRevisionConflict
	case http.StatusUnsupportedMediaType:
		return codeUnsupportedMediaType
	case http.StatusUnprocessableEntity:
		return codeValidationFailed
	case http.StatusPreconditionRequired:
		return codeIfMatchRequired
	case http.StatusBadGateway:
		return codeUpstreamFailed
	case http.StatusServiceUnavailable:
		return codeUnavailable
	}
	if status >= http.StatusInternalServerError {
		return codeInternal
	}
	return codeInvalidRequest
}

// codeError carries an explicit code inside an *echo.HTTPError (as its
// Internal error), so apiErr values stay plain *echo.HTTPError for every
// caller and test that type-asserts them.
type codeError string

func (e codeError) Error() string { return string(e) }

// apiErr is the typed producer for sites whose code cannot be inferred from
// the status alone (D218-14: new producers use it whenever the condition has
// a domain meaning).
func apiErr(status int, code, msg string) *echo.HTTPError {
	return echo.NewHTTPError(status, msg).WithInternal(codeError(code))
}

// retryableFor is the fixed rule of D218-5: "would sending the same request
// again, unchanged, plausibly succeed?". 412/428 are false on purpose (the
// caller must reload first), as is 500 (a partial effect is possible).
func retryableFor(code, method string) bool {
	switch code {
	case codeLoginRateLimited, codeUnavailable, codeScanTimeout, codeBackupBusy, codePersistenceUnavailable,
		codeIdempotencyKeyConflict, codeIdempotencyCapacity:
		return true
	case codeUpstreamFailed:
		return method == http.MethodGet || method == http.MethodHead
	}
	return false
}

// maxLogDetail bounds how much of an error text one log line carries.
const maxLogDetail = 512

// logQuote makes a client-influenced value (an inbound X-Request-Id, a method)
// safe for a log line: quoted, so control characters and newlines are escaped.
func logQuote(v string) string { return strconv.Quote(v) }

// logDetail renders an error for the log. LDAP diagnostics can carry text an
// attacker chose (a submitted username), including newlines, so the detail is
// escaped with strconv.Quote and cut at maxLogDetail bytes; a forged
// "[id] ..." line can then never appear as a separate log event.
func logDetail(err error) string {
	text := err.Error()
	if len(text) > maxLogDetail {
		text = strings.ToValidUTF8(text[:maxLogDetail], "") + "...(truncated)"
	}
	return strconv.Quote(text)
}

// writeAPIError is the single builder of the envelope; respondErr and
// apiErrorHandler both end here.
func writeAPIError(c echo.Context, status int, code, msg string, cause error) error {
	return writeAPIErrorExt(c, status, code, msg, cause, "", "")
}

// writeAPIErrorExt is writeAPIError plus the two partial_failure-only keys.
// Only codePartialFailure may carry state/dn; its 5xx text is the static one
// like every other 5xx (D218-8).
func writeAPIErrorExt(c echo.Context, status int, code, msg string, cause error, state, dn string) error {
	return c.JSON(status, buildEnvelope(c, status, code, msg, cause, state, dn))
}

// buildEnvelope applies every envelope rule (code fallback, static 5xx text,
// Retry-After, request ID) and returns the body without sending it, so a
// producer with an extra documented key (backup_busy) can add it first.
func buildEnvelope(c echo.Context, status int, code, msg string, cause error, state, dn string) errorEnvelope {
	if _, known := codeTable[code]; !known {
		code = codeForStatus(status)
	}
	recorderOf(c).APIError(code)
	reqID := c.Response().Header().Get(echo.HeaderXRequestID)
	req := c.Request()
	if status >= http.StatusInternalServerError {
		// D218-8: structurally impossible to leak. Whatever the handler or
		// the cause said goes to the log only, under the same request ID.
		if cause == nil {
			cause = errors.New(msg)
		}
		log.Printf("internal error [%s] %s %s: %s", logQuote(reqID), logQuote(req.Method), c.Path(), logDetail(cause))
		msg = codeTable[code].static
		if msg == "" {
			msg = internalErrorMessage
		}
	}
	if code != codePartialFailure {
		state, dn = "", ""
	}
	c.Set(envelopeCodeKey, code)
	retryable := retryableFor(code, req.Method)
	if retryable && (status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable) {
		if c.Response().Header().Get(echo.HeaderRetryAfter) == "" {
			wait := retryAfterDefaultSeconds
			if code == codeScanTimeout {
				wait = retryAfterScanTimeoutSeconds
			}
			c.Response().Header().Set(echo.HeaderRetryAfter, strconv.Itoa(wait))
		}
	}
	return errorEnvelope{Error: msg, Message: msg, Code: code, RequestID: reqID, Retryable: retryable, State: state, DN: dn}
}

// writeBackupBusy is the 409 backup_busy envelope plus the active job.
func writeBackupBusy(c echo.Context, activeJobID, activeKind string) error {
	env := buildEnvelope(c, http.StatusConflict, codeBackupBusy, "backup already running", nil, "", "")
	env.ActiveJobID, env.ActiveKind = activeJobID, activeKind
	return c.JSON(http.StatusConflict, env)
}

// domainStatus maps a domain sentinel to its status and code; ok is false
// for an error that is none of them.
func domainStatus(err error) (status int, code string, sentinel error, ok bool) {
	switch {
	case errors.Is(err, domain.ErrNotFound):
		return http.StatusNotFound, codeNotFound, domain.ErrNotFound, true
	case errors.Is(err, domain.ErrAlreadyExists):
		return http.StatusConflict, codeAlreadyExists, domain.ErrAlreadyExists, true
	case errors.Is(err, domain.ErrConflict):
		return http.StatusConflict, codeConflict, domain.ErrConflict, true
	case errors.Is(err, domain.ErrInvalidCredentials):
		return http.StatusUnauthorized, codeInvalidCredentials, domain.ErrInvalidCredentials, true
	case errors.Is(err, domain.ErrPermissionDenied):
		return http.StatusForbidden, codeForbidden, domain.ErrPermissionDenied, true
	case errors.Is(err, domain.ErrInvalidInput):
		return http.StatusBadRequest, codeInvalidRequest, domain.ErrInvalidInput, true
	case errors.Is(err, domain.ErrCurrentPasswordRejected):
		return http.StatusBadRequest, codeCurrentPasswordRejected, domain.ErrCurrentPasswordRejected, true
	case errors.Is(err, domain.ErrRevisionConflict):
		// A conditional write whose If-Match no longer matches (#216). The
		// sentinel text is fixed; no DN or filter ever reaches the body.
		return http.StatusPreconditionFailed, codeRevisionConflict, domain.ErrRevisionConflict, true
	}
	return 0, "", nil, false
}

// respondErr maps a domain/validation error to the envelope, so handlers
// never construct the body by hand and the mapping lives in exactly one
// place.
//
// The mapped cases are curated, user-facing conditions ("not found",
// ...). Their text is the sentinel's own fixed text, plus a diagnostic only
// when publicDiagnostic vouches for it (D218-15): ldapclient wraps the LDAP
// server's diagnostic text, which can carry DNs and attribute names, so any
// other wrapped text is replaced by the sentinel text and goes to the log.
// Anything that falls through to the default 500 is a failure this code did
// not anticipate — most commonly a raw *ldap.Error or a dial error carrying
// host and port — and is logged server-side under the request ID instead of
// being sent.
func respondErr(c echo.Context, err error) error {
	if status, code, sentinel, ok := domainStatus(err); ok {
		msg, withheld := publicDomainMessage(sentinel, err)
		if withheld {
			log.Printf("error detail withheld from response [%s] %s %s: %s", logQuote(c.Response().Header().Get(echo.HeaderXRequestID)), logQuote(c.Request().Method), c.Path(), logDetail(err))
		}
		return writeAPIError(c, status, code, msg, err)
	}
	if isOutcomeUnknown(err) {
		markOutcomeUnknown(c)
	} else {
		markDefinitive(c)
	}
	return writeAPIError(c, http.StatusInternalServerError, codeInternal, "", err)
}

// writeFromError converts whatever a handler or middleware returned into the
// envelope. apiErrorHandler calls it for every /api error.
func writeFromError(c echo.Context, err error) error {
	var he *echo.HTTPError
	if errors.As(err, &he) {
		code := ""
		var ce codeError
		if errors.As(he.Internal, &ce) {
			code = string(ce)
		}
		if code == "" {
			code = codeForStatus(he.Code)
		}
		msg, _ := he.Message.(string)
		if msg == "" {
			msg = strings.ToLower(http.StatusText(he.Code))
		}
		cause := he.Internal
		if _, isCode := cause.(codeError); isCode {
			cause = nil
		}
		if cause == nil {
			cause = fmt.Errorf("%s", msg)
		}
		return writeAPIError(c, he.Code, code, msg, cause)
	}
	return respondErr(c, err)
}
