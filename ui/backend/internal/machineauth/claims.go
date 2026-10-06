// Package machineauth verifies bearer access tokens issued by Keycloak to
// service clients (change package machine-principal-auth, D5/D8/D15). It has
// no HTTP-server dependency: claim validation is a pure function with an
// injected clock, and the JWKS key source takes an injected clock and fetcher,
// so every row of the policy tables is unit-testable without sleeping.
package machineauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"strings"
	"time"
)

// Reason is the fixed enum a failed verification reports. Raw errors from the
// JOSE library or from claim parsing never leave this package (D10): they can
// echo attacker-controlled text.
type Reason string

const (
	ReasonFormat Reason = "format" // size, compact JWS shape, undecodable payload
	ReasonAlg    Reason = "alg"
	ReasonTyp    Reason = "typ" // JOSE or payload typ
	ReasonKid    Reason = "kid" // missing or unknown kid
	ReasonSig    Reason = "sig"
	ReasonIss    Reason = "iss"
	ReasonAud    Reason = "aud"
	ReasonAzp    Reason = "azp" // azp/client_id, allowlist, SSO client
	ReasonSA     Reason = "sa_claims"
	ReasonScope  Reason = "scope"
	ReasonTime   Reason = "time" // iat/exp/nbf shape and skew
	ReasonTTL    Reason = "ttl"
	ReasonExpire Reason = "expired" // otherwise-valid token past exp+skew
	ReasonJWKS   Reason = "jwks_unavailable"
)

// MaxTokenBytes is the Authorization value cap of the D5 table (8 KiB).
const MaxTokenBytes = 8 << 10

// Policy is the immutable claim-validation configuration.
type Policy struct {
	Issuer   string
	Audience string
	// Clients is the set of service client ids the server permits (D3).
	Clients map[string]bool
	// DeniedClients are never accepted even when listed (the SSO browser client).
	DeniedClients map[string]bool
	// SAPrefix is the Keycloak service-account username prefix (D5 rule ii).
	SAPrefix string
	MaxTTL   time.Duration
	Skew     time.Duration
}

// Principal is what a fully verified token yields. Subject is only ever
// exposed as a fingerprint (D10).
type Principal struct {
	ClientID    string
	Scopes      []string
	SubjectHash string
	Expiry      time.Time
}

// Failure describes why verification did not produce a Principal.
type Failure struct {
	Reason Reason
	// Expired marks a purely expired token (401 token_expired, not token_invalid).
	Expired bool
	// Unavailable marks key-source trouble (503 + Retry-After, never 401).
	Unavailable bool
	// RetryAfter is whole seconds, 1..300, set when Unavailable.
	RetryAfter int
}

func invalid(r Reason) *Failure { return &Failure{Reason: r} }

// ValidateClaims applies the payload rules of the D5 table to an already
// signature-verified payload, in table order (cheap checks first). It never
// substitutes a default for a missing, null or mistyped claim.
func ValidateClaims(p Policy, payload []byte, now time.Time) (*Principal, *Failure) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var c map[string]json.RawMessage
	if err := dec.Decode(&c); err != nil || c == nil {
		return nil, invalid(ReasonFormat)
	}

	if s, ok := stringClaim(c, "typ"); !ok || s != "Bearer" {
		return nil, invalid(ReasonTyp)
	}
	if s, ok := stringClaim(c, "iss"); !ok || s != p.Issuer {
		return nil, invalid(ReasonIss)
	}
	if !audienceHas(c["aud"], p.Audience) {
		return nil, invalid(ReasonAud)
	}

	azp, okA := stringClaim(c, "azp")
	clientID, okC := stringClaim(c, "client_id")
	if !okA || !okC || azp != clientID || !p.Clients[azp] || p.DeniedClients[azp] {
		return nil, invalid(ReasonAzp)
	}

	// Service-account rule (D5): client_id == azp (above) AND preferred_username
	// == prefix+client_id AND a non-empty sub. AND, never OR; sid is not consulted.
	if u, ok := stringClaim(c, "preferred_username"); !ok || u != p.SAPrefix+clientID {
		return nil, invalid(ReasonSA)
	}
	sub, ok := stringClaim(c, "sub")
	if !ok {
		return nil, invalid(ReasonSA)
	}

	scopeRaw, ok := stringClaim(c, "scope")
	if !ok {
		return nil, invalid(ReasonScope)
	}

	iat, ok := timeClaim(c, "iat")
	if !ok || iat.After(now.Add(p.Skew)) {
		return nil, invalid(ReasonTime)
	}
	exp, ok := timeClaim(c, "exp")
	if !ok || !exp.After(iat) {
		return nil, invalid(ReasonTime)
	}
	if exp.Sub(iat) > p.MaxTTL {
		return nil, invalid(ReasonTTL)
	}
	if raw, present := c["nbf"]; present {
		nbf, ok := numericDate(raw)
		// null counts as present-but-invalid: no defaults.
		if !ok || nbf.After(exp) || nbf.After(now.Add(p.Skew)) {
			return nil, invalid(ReasonTime)
		}
	}
	// Expiry is last: a token that reaches it violates nothing else, so it is
	// the "purely expired" case.
	if now.After(exp.Add(p.Skew)) {
		return nil, &Failure{Reason: ReasonExpire, Expired: true}
	}

	sum := sha256.Sum256([]byte(sub))
	return &Principal{
		ClientID:    clientID,
		Scopes:      strings.FieldsFunc(scopeRaw, func(r rune) bool { return r == ' ' }),
		SubjectHash: hex.EncodeToString(sum[:6]),
		Expiry:      exp,
	}, nil
}

func stringClaim(c map[string]json.RawMessage, name string) (string, bool) {
	raw, ok := c[name]
	if !ok {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil || s == "" || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", false
	}
	return s, true
}

// audienceHas reports whether want is an exact member of the aud claim, which
// is a string or an array of strings. Missing, null, empty, non-string
// elements and the Keycloak default "account" alone all fail.
func audienceHas(raw json.RawMessage, want string) bool {
	if len(raw) == 0 || want == "" {
		return false
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return one == want
	}
	var many []json.RawMessage
	if err := json.Unmarshal(raw, &many); err != nil || len(many) == 0 {
		return false
	}
	found := false
	for _, el := range many {
		var s string
		if err := json.Unmarshal(el, &s); err != nil || bytes.Equal(bytes.TrimSpace(el), []byte("null")) {
			return false // one bad element poisons the claim
		}
		if s == want {
			found = true
		}
	}
	return found
}

func timeClaim(c map[string]json.RawMessage, name string) (time.Time, bool) {
	raw, ok := c[name]
	if !ok {
		return time.Time{}, false
	}
	return numericDate(raw)
}

// numericDate parses a JSON number of seconds since the epoch. Strings, null,
// booleans, non-finite and absurdly large values are rejected.
func numericDate(raw json.RawMessage) (time.Time, bool) {
	var n json.Number
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&n); err != nil || bytes.HasPrefix(bytes.TrimSpace(raw), []byte(`"`)) {
		return time.Time{}, false
	}
	f, err := n.Float64()
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || math.Abs(f) > 1e11 {
		return time.Time{}, false
	}
	sec := math.Floor(f)
	return time.Unix(int64(sec), int64((f-sec)*1e9)), true
}
