package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/machineauth"
)

// Machine access audit (change package machine-principal-auth, D10, REQ-009).
//
// Every request that carries an Authorization header while machine auth is
// enabled produces exactly one structured line, whatever happens to it: an
// early return of the selection step, the Origin gate, a 404, a verification
// failure or a normal response. The line is emitted by a wrapper that sits
// outside all of those (see machineAuditMiddleware), not by the individual
// rejection sites, so a new early return cannot forget it.
//
// What the line never holds: the token or any piece of its signature, the
// Authorization value, a client secret, the bind password, or the text of a
// verifier error. The token appears only as a fingerprint, and the actor is
// the client id only after the signature and claims were verified.

const (
	machineEventName = "machine_access"
	// machineAuditProvider: the bearer token comes from an OIDC issuer. LDAP and
	// SSO login modes are about the browser path and are not what this is.
	machineAuditProvider = "oidc"
	machineActorUnknown  = "unknown"

	machineAuditKey = "machine_audit"
)

// Reasons: a closed set. The verifier's own reasons (machineauth.Reason) pass
// through unchanged; the rest come from the steps of the request path.
const (
	reasonOK              = "ok"
	reasonBadHeader       = "bad_header"          // Authorization present but malformed or repeated
	reasonMixed           = "mixed_credentials"   // bearer plus session cookie
	reasonBearerNotHere   = "bearer_not_accepted" // Authorization on a cookie-issuing public path
	reasonIgnoredPublic   = "ignored_public"      // public endpoint, Authorization has no meaning
	reasonNotAPI          = "not_api"             // not an /api path
	reasonNotFound        = "not_found"           // unknown /api path or method
	reasonOriginMismatch  = "origin_mismatch"     // Origin gate
	reasonPreflight       = "preflight"           // answered by CORS
	reasonScope           = "scope"               // not allowlisted, or scope not granted
	reasonRate            = "rate"                // IP throttle or client budget refused (429)
	reasonBindFailed      = "bind_failed"         // machine LDAP bind failed or timed out
	reasonCapacity        = "capacity"            // global LDAP concurrency slot unavailable
	reasonDeadline        = "deadline"            // request deadline expired in the directory
	reasonCanceled        = "canceled"            // the client went away mid-request
	reasonRequestRejected = "request_rejected"    // 4xx from the handler (validation, boundary)
	reasonUpstream        = "upstream_error"      // 5xx from the handler
	reasonInternal        = "internal"            // panic
)

// machineReasons is the closed set buildMachineEvent enforces.
var machineReasons = func() map[string]bool {
	m := map[string]bool{}
	for _, r := range []string{
		reasonOK, reasonBadHeader, reasonMixed, reasonBearerNotHere, reasonIgnoredPublic, reasonNotAPI,
		reasonNotFound, reasonOriginMismatch, reasonPreflight, reasonScope, reasonRate, reasonBindFailed,
		reasonCapacity, reasonDeadline, reasonCanceled, reasonRequestRejected, reasonUpstream, reasonInternal,
		string(machineauth.ReasonFormat), string(machineauth.ReasonAlg), string(machineauth.ReasonTyp),
		string(machineauth.ReasonKid), string(machineauth.ReasonSig), string(machineauth.ReasonIss),
		string(machineauth.ReasonAud), string(machineauth.ReasonAzp), string(machineauth.ReasonSA),
		string(machineauth.ReasonScope), string(machineauth.ReasonTime), string(machineauth.ReasonTTL), string(machineauth.ReasonJTI),
		string(machineauth.ReasonExpire), string(machineauth.ReasonJWKS),
	} {
		m[r] = true
	}
	return m
}()

// machineAuditState is what the steps of one request tell the wrapper. It is
// created by the wrapper, filled while the request runs and read once at the
// end; a request is served by one goroutine, so it needs no locking.
type machineAuditState struct {
	reason    string
	actor     string // the verified client id; empty until verification succeeded
	subjectFP string
	operation string
	bindDN    string
}

func auditStateOf(c echo.Context) *machineAuditState {
	st, _ := c.Get(machineAuditKey).(*machineAuditState)
	return st
}

// Setters are nil-safe so code paths that run without the wrapper (unit tests
// of a single step) need no special case.
func (s *machineAuditState) setReason(r string) {
	if s != nil && s.reason == "" {
		s.reason = r
	}
}

// forceReason overrides an earlier reason: a limiter refusal replaces the
// reason of the request class it cut short (a bad header from a throttled IP
// is audited as rate, not bad_header).
func (s *machineAuditState) forceReason(r string) {
	if s != nil {
		s.reason = r
	}
}

func (s *machineAuditState) setOperation(op string) {
	if s != nil {
		s.operation = op
	}
}

func (s *machineAuditState) setActor(p *machineauth.Principal) {
	if s != nil && p != nil {
		s.actor, s.subjectFP = p.ClientID, p.SubjectHash
	}
}

func (s *machineAuditState) setBindDN(dn string) {
	if s != nil {
		s.bindDN = dn
	}
}

// machineEvent is the structured record. token_fingerprint and subject_fingerprint
// are omitted when empty; bind_dn only appears when the request reached the
// directory identity.
type machineEvent struct {
	Event              string `json:"event"`
	Provider           string `json:"provider"`
	Actor              string `json:"actor"`
	RequestID          string `json:"request_id"`
	Operation          string `json:"operation"`
	Method             string `json:"method"`
	Status             int    `json:"status"`
	Result             string `json:"result"`
	Reason             string `json:"reason"`
	TokenFingerprint   string `json:"token_fingerprint,omitempty"`
	SubjectFingerprint string `json:"subject_fingerprint,omitempty"`
	BindDN             string `json:"bind_dn,omitempty"`
}

// machineEventInput is everything buildMachineEvent decides from. Nothing in
// it is a token or a raw error.
type machineEventInput struct {
	RequestID   string
	Method      string
	Status      int
	EnvelopeErr string // the response's error-envelope code, "" on success
	Reason      string
	Actor       string
	SubjectFP   string
	Operation   string
	BindDN      string
	TokenFP     string
}

// tokenFingerprint is the first 6 bytes of SHA-256 over the Authorization
// value, hex: enough to tell whether two lines carry the same credential, not
// enough to learn anything about it. Used only before verification succeeded,
// when no verified identity exists to log.
func tokenFingerprint(authorization string) string {
	if authorization == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(authorization))
	return hex.EncodeToString(sum[:6])
}

// buildMachineEvent assembles one line. It is pure: the reason is forced into
// the closed set (an unexpected one is derived from the response instead of
// being logged as given), and the actor is "unknown" unless a verified client
// id was recorded.
func buildMachineEvent(in machineEventInput) machineEvent {
	actor := in.Actor
	if actor == "" {
		actor = machineActorUnknown
	}
	result := "failure"
	switch {
	case in.Status == http.StatusTooManyRequests:
		result = "rate_limited"
	case in.Status < http.StatusBadRequest:
		result = "success"
	}
	reason := in.Reason
	if !machineReasons[reason] {
		reason = ""
	}
	if reason == "" {
		reason = reasonFromResponse(in.Status, in.EnvelopeErr, in.Method)
	}
	op := in.Operation
	if op == "" {
		op = "unknown"
	}
	ev := machineEvent{
		Event: machineEventName, Provider: machineAuditProvider, Actor: actor,
		RequestID: in.RequestID, Operation: op, Method: in.Method, Status: in.Status,
		Result: result, Reason: reason,
		SubjectFingerprint: in.SubjectFP, BindDN: in.BindDN,
	}
	// A verified actor already identifies the caller; the token fingerprint is
	// for the lines that have no verified identity.
	if actor == machineActorUnknown {
		ev.TokenFingerprint = in.TokenFP
	}
	return ev
}

// reasonFromResponse derives the reason for a response nobody labelled: the
// envelope code names the early returns that other layers own (Origin gate,
// router 404), the status class covers the rest.
func reasonFromResponse(status int, envelopeCode, method string) string {
	switch envelopeCode {
	case codeOriginMismatch:
		return reasonOriginMismatch
	case codeNotFound, codeMethodNotAllowed:
		return reasonNotFound
	case codeScopeDenied:
		return reasonScope
	}
	switch {
	case method == http.MethodOptions && status < http.StatusBadRequest:
		return reasonPreflight
	case status < http.StatusBadRequest:
		return reasonOK
	case status >= http.StatusInternalServerError:
		return reasonUpstream
	}
	return reasonRequestRejected
}

// machineAuditMiddleware is the outer wrapper. It is registered only when the
// feature is enabled, directly after RequestID and before everything that can
// answer early (CORS, Origin gate, selection, verification), so it sees the
// final status of every request that carries an Authorization header. A panic
// is logged as a 500 and re-raised for Recover.
func (s *Server) machineAuditMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) (err error) {
			req := c.Request()
			values := req.Header.Values("Authorization")
			if len(values) == 0 {
				return next(c)
			}
			st := &machineAuditState{}
			c.Set(machineAuditKey, st)
			method := req.Method
			if orig, _ := c.Get(origMethodKey).(string); orig != "" {
				method = orig
			}
			panicked := true
			defer func() {
				if !panicked {
					return
				}
				// Logged here, before Recover turns the panic into a response.
				logMachineEvent(buildMachineEvent(machineEventInput{
					RequestID: requestIDOf(c), Method: method, Status: http.StatusInternalServerError,
					Reason: reasonInternal, Actor: st.actor, SubjectFP: st.subjectFP,
					Operation: st.operation, BindDN: st.bindDN, TokenFP: tokenFingerprint(values[0]),
				}))
			}()
			if err = next(c); err != nil {
				c.Error(err)
			}
			panicked = false
			code, _ := c.Get(envelopeCodeKey).(string)
			logMachineEvent(buildMachineEvent(machineEventInput{
				RequestID: requestIDOf(c), Method: method, Status: c.Response().Status,
				EnvelopeErr: code, Reason: st.reason, Actor: st.actor, SubjectFP: st.subjectFP,
				Operation: st.operation, BindDN: st.bindDN, TokenFP: tokenFingerprint(values[0]),
			}))
			return err
		}
	}
}

func logMachineEvent(ev machineEvent) {
	line, err := json.Marshal(ev)
	if err != nil {
		// Plain strings and ints: cannot fail in practice. Never drop silently.
		log.Printf("machine event marshal error: %v", err)
		return
	}
	log.Println(string(line))
}
