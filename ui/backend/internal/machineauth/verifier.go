package machineauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
)

// Verifier verifies a bearer token end to end: size, JOSE header (alg
// allowlist, typ, kid), signature through the KeySet, then ValidateClaims with
// an injected clock. It does not use go-oidc's IDTokenVerifier: that one has a
// hard-coded 5-minute nbf leeway and ID-token semantics, so the time claims
// and audience are validated here (REQ-011).
type Verifier struct {
	Policy Policy
	Algs   []jose.SignatureAlgorithm
	Keys   oidc.KeySet
	Now    func() time.Time
}

// Verify returns the Principal of a valid token or a *Failure. It never
// returns the underlying library error.
func (v *Verifier) Verify(ctx context.Context, token string) (*Principal, *Failure) {
	if token == "" || len(token) > MaxTokenBytes {
		return nil, invalid(ReasonFormat)
	}
	jws, err := jose.ParseSignedCompact(token, v.Algs)
	if err != nil || len(jws.Signatures) != 1 {
		return nil, invalid(classifyParseError(token, v.Algs))
	}
	hdr := jws.Signatures[0].Header
	// JOSE typ is required: JWT or at+jwt, case-insensitive. It does not
	// distinguish access from ID tokens (both are JWT in Keycloak); the payload
	// typ does.
	typ, _ := hdr.ExtraHeaders[jose.HeaderType].(string)
	if !strings.EqualFold(typ, "JWT") && !strings.EqualFold(typ, "at+jwt") {
		return nil, invalid(ReasonTyp)
	}
	if hdr.KeyID == "" {
		return nil, invalid(ReasonKid)
	}

	payload, err := v.Keys.VerifySignature(ctx, token)
	if err != nil {
		var un *UnavailableError
		switch {
		case errors.As(err, &un):
			return nil, &Failure{Reason: ReasonJWKS, Unavailable: true, RetryAfter: un.RetryAfter}
		case errors.Is(err, ErrUnknownKid):
			return nil, invalid(ReasonKid)
		case errors.Is(err, ErrMalformed):
			return nil, invalid(ReasonFormat)
		}
		return nil, invalid(ReasonSig)
	}
	return ValidateClaims(v.Policy, payload, v.Now())
}

// classifyParseError distinguishes a disallowed algorithm (none, HS*, RS512
// when not listed) from a malformed token, for the audit reason only.
func classifyParseError(token string, allowed []jose.SignatureAlgorithm) Reason {
	// Parse with every algorithm go-jose knows; if that succeeds the shape is
	// fine and only the allowlist rejected it.
	all := []jose.SignatureAlgorithm{
		jose.HS256, jose.HS384, jose.HS512, jose.RS256, jose.RS384, jose.RS512,
		jose.ES256, jose.ES384, jose.ES512, jose.PS256, jose.PS384, jose.PS512, jose.EdDSA,
	}
	if _, err := jose.ParseSignedCompact(token, all); err == nil {
		return ReasonAlg
	}
	// alg "none" (or any unknown name) is not a go-jose algorithm; a readable
	// header that names one is still an algorithm rejection.
	seg, _, _ := strings.Cut(token, ".")
	if raw, err := base64.RawURLEncoding.DecodeString(seg); err == nil {
		var h struct {
			Alg *string `json:"alg"`
		}
		if json.Unmarshal(raw, &h) == nil && h.Alg != nil {
			return ReasonAlg
		}
	}
	return ReasonFormat
}
