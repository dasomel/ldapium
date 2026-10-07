package machineauth

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

type verifyEnv struct {
	clock *fakeClock
	key   testKey
	v     *Verifier
	ks    *KeySet
	f     *fakeFetcher
}

func newVerifyEnv(t *testing.T) *verifyEnv {
	t.Helper()
	clock := newClock()
	key := rsaKey(t, "rsa1")
	f := newFetcher(clock, key)
	ks := newKeySet(clock, f)
	if err := ks.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &verifyEnv{clock, key, newVerifier(clock, ks), ks, f}
}

func (e *verifyEnv) verify(tok string) (*Principal, *Failure) {
	return e.v.Verify(context.Background(), tok)
}

// mod builds a token from the observed good claims with one change.
func (e *verifyEnv) mod(t *testing.T, f func(c map[string]any)) string {
	t.Helper()
	c := goodClaims(e.clock.Now())
	f(c)
	return signed(t, e.key, "JWT", "rsa1", c)
}

func TestVerify_PositiveControl(t *testing.T) {
	e := newVerifyEnv(t)
	p, fail := e.verify(e.mod(t, func(map[string]any) {}))
	if fail != nil {
		t.Fatalf("good token rejected: %+v", fail)
	}
	if p.ClientID != "machine-a" || strings.Join(p.Scopes, ",") != "profile,directory.users.read,email" {
		t.Errorf("principal = %+v", p)
	}
	if len(p.SubjectHash) != 12 || strings.Contains(p.SubjectHash, "sa-uuid") {
		t.Errorf("subject must only appear as a 6-byte fingerprint: %q", p.SubjectHash)
	}
	// aud as a plain string equal to the audience is also fine.
	if _, fail := e.verify(e.mod(t, func(c map[string]any) { c["aud"] = testAudience })); fail != nil {
		t.Errorf("string aud rejected: %+v", fail)
	}
	// JOSE typ variants (case-insensitive JWT / at+jwt).
	for _, typ := range []string{"JWT", "jwt", "at+jwt", "AT+JWT"} {
		tok := signed(t, e.key, typ, "rsa1", goodClaims(e.clock.Now()))
		if _, fail := e.verify(tok); fail != nil {
			t.Errorf("typ %q rejected: %+v", typ, fail)
		}
	}
	// EC key through the same verifier.
	ec := ecKey(t, "ec1")
	e.f.setKeys(e.key, ec)
	e.clock.Set(31) // budget gate open for the refresh the unknown kid triggers
	if _, fail := e.verify(signed(t, ec, "JWT", "ec1", goodClaims(e.clock.Now()))); fail != nil {
		t.Errorf("ES256 token rejected: %+v", fail)
	}
}

// AC-002: every negative token is signed with the real key and violates exactly
// one rule. Each row pairs with the positive control above.
func TestVerify_NegativeTable(t *testing.T) {
	e := newVerifyEnv(t)
	now := e.clock.Now().Unix()
	type row struct {
		name   string
		mutate func(c map[string]any)
		want   Reason
	}
	del := func(k string) func(map[string]any) { return func(c map[string]any) { delete(c, k) } }
	set := func(k string, v any) func(map[string]any) { return func(c map[string]any) { c[k] = v } }
	rows := []row{
		{"aud account only (string)", set("aud", "account"), ReasonAud},
		{"aud account only (array)", set("aud", []string{"account"}), ReasonAud},
		{"aud missing", del("aud"), ReasonAud},
		{"aud null", set("aud", nil), ReasonAud},
		{"aud numeric array", set("aud", []any{1, 2}), ReasonAud},
		{"aud array with number poison", set("aud", []any{testAudience, 7}), ReasonAud},
		{"aud empty array", set("aud", []string{}), ReasonAud},
		{"aud substring", set("aud", "ldapium-api-2"), ReasonAud},
		{"unknown iss", set("iss", "https://evil.example.org/realms/r"), ReasonIss},
		{"iss trailing slash", set("iss", testIssuer+"/"), ReasonIss},
		{"iss missing", del("iss"), ReasonIss},
		{"id token (typ ID)", func(c map[string]any) { c["typ"] = "ID"; c["aud"] = "machine-a"; c["scope"] = "openid" }, ReasonTyp},
		{"refresh token", set("typ", "Refresh"), ReasonTyp},
		{"payload typ missing", del("typ"), ReasonTyp},
		{"payload typ lowercase", set("typ", "bearer"), ReasonTyp},
		{"azp not allowed", func(c map[string]any) {
			c["azp"], c["client_id"], c["preferred_username"] = "rogue", "rogue", "service-account-rogue"
		}, ReasonAzp},
		{"azp != client_id", set("azp", "machine-b"), ReasonAzp},
		{"client_id missing", del("client_id"), ReasonAzp},
		{"azp missing", del("azp"), ReasonAzp},
		{"client_id numeric", set("client_id", 5), ReasonAzp},
		{"sso browser client (listed but denied)", func(c map[string]any) {
			c["azp"], c["client_id"], c["preferred_username"] = "ldapium-sso", "ldapium-sso", "service-account-ldapium-sso"
		}, ReasonAzp},
		// EVIDENCE 2.9 rows: human password-grant token, exchange tokens, lightweight.
		{"password-grant human token (row 4)", func(c map[string]any) {
			delete(c, "client_id")
			delete(c, "clientHost")
			delete(c, "clientAddress")
			c["preferred_username"], c["sid"] = "alice", "sid1"
		}, ReasonAzp},
		{"exchange of SA token (row 7)", func(c map[string]any) {
			delete(c, "client_id")
			delete(c, "clientHost")
			delete(c, "clientAddress")
		}, ReasonAzp},
		{"exchange of human token (row 8)", func(c map[string]any) {
			delete(c, "client_id")
			c["preferred_username"], c["sub"], c["sid"] = "alice", "alice-uuid", "s"
		}, ReasonAzp},
		{"lightweight token (row 2)", func(c map[string]any) {
			for k := range c {
				if k != "azp" && k != "scope" && k != "typ" && k != "exp" && k != "iat" && k != "iss" && k != "sub" {
					delete(c, k)
				}
			}
		}, ReasonAud}, // aud is gone too; any rejection is the point, aud is checked first
		{"profile scope removed (row 5): no preferred_username", del("preferred_username"), ReasonSA},
		{"service_account scope removed (row 6)", func(c map[string]any) {
			delete(c, "client_id")
			delete(c, "preferred_username")
		}, ReasonAzp},
		{"preferred_username same but client_id absent", func(c map[string]any) { delete(c, "client_id") }, ReasonAzp},
		{"client_id present but username is another client's", set("preferred_username", "service-account-machine-b"), ReasonSA},
		{"username equals prefix only", set("preferred_username", "service-account-"), ReasonSA},
		{"sub missing", del("sub"), ReasonSA},
		{"sub empty", set("sub", ""), ReasonSA},
		{"scope missing", del("scope"), ReasonScope},
		{"scope not a string", set("scope", []string{"a"}), ReasonScope},
		{"iat missing", del("iat"), ReasonTime},
		{"iat string", set("iat", "1790000000"), ReasonTime},
		{"iat null", set("iat", nil), ReasonTime},
		{"iat future skew+1", set("iat", now+31), ReasonTime},
		{"exp missing", del("exp"), ReasonTime},
		{"exp string", set("exp", "1790000300"), ReasonTime},
		{"exp == iat", set("exp", now), ReasonTime},
		{"exp < iat", set("exp", now-10), ReasonTime},
		{"lifetime MAX_TTL+1", set("exp", now+601), ReasonTTL},
		{"nbf future skew+1", set("nbf", now+31), ReasonTime},
		{"nbf within 5m but beyond skew (go-oidc would accept)", set("nbf", now+200), ReasonTime},
		{"nbf string", set("nbf", "1"), ReasonTime},
		{"nbf null", set("nbf", nil), ReasonTime},
		{"nbf after exp", func(c map[string]any) { c["nbf"] = now + 301; c["exp"] = now + 300 }, ReasonTime},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			p, fail := e.verify(e.mod(t, r.mutate))
			if fail == nil {
				t.Fatalf("accepted: %+v", p)
			}
			if fail.Reason != r.want || fail.Unavailable || fail.Expired {
				t.Errorf("failure = %+v, want reason %s", fail, r.want)
			}
		})
	}
}

// AC-012: the boundary table, through the real signature verifier and the
// local key source, with the injected clock. skew=30s, MAX_TTL=10m.
func TestVerify_TimeBoundaries(t *testing.T) {
	e := newVerifyEnv(t)
	base := e.clock.Now().Unix() // token iat/exp relative to this; the clock moves
	tok := func(mut func(c map[string]any)) string {
		c := goodClaims(e.clock.Now())
		c["iat"], c["exp"] = base, base+300
		if mut != nil {
			mut(c)
		}
		return signed(t, e.key, "JWT", "rsa1", c)
	}
	cases := []struct {
		name    string
		nowSec  int // clock seconds after t0 (base == t0)
		mut     func(c map[string]any)
		wantOK  bool
		expired bool
		reason  Reason
	}{
		{"exp+skew-1 ok", 300 + 29, nil, true, false, ""},
		{"exp+skew ok", 300 + 30, nil, true, false, ""},
		{"exp+skew+1 expired", 300 + 31, nil, false, true, ReasonExpire},
		{"iat = now+skew ok", 0, func(c map[string]any) { c["iat"] = base + 30; c["exp"] = base + 330 }, true, false, ""},
		{"iat = now+skew+1 bad", 0, func(c map[string]any) { c["iat"] = base + 31; c["exp"] = base + 331 }, false, false, ReasonTime},
		{"iat = now+skew-1 ok", 0, func(c map[string]any) { c["iat"] = base + 29; c["exp"] = base + 329 }, true, false, ""},
		{"nbf = now+skew ok", 0, func(c map[string]any) { c["nbf"] = base + 30 }, true, false, ""},
		{"nbf = now+skew+1 bad", 0, func(c map[string]any) { c["nbf"] = base + 31 }, false, false, ReasonTime},
		{"nbf = now+skew-1 ok", 0, func(c map[string]any) { c["nbf"] = base + 29 }, true, false, ""},
		{"nbf = now+5m bad (go-oidc leeway not used)", 0, func(c map[string]any) { c["nbf"] = base + 300 }, false, false, ReasonTime},
		{"ttl = MAX_TTL ok", 0, func(c map[string]any) { c["exp"] = base + 600 }, true, false, ""},
		{"ttl = MAX_TTL+1 bad", 0, func(c map[string]any) { c["exp"] = base + 601 }, false, false, ReasonTTL},
		{"exp = iat+1 ok", 0, func(c map[string]any) { c["exp"] = base + 1 }, true, false, ""},
		{"exp = iat bad", 0, func(c map[string]any) { c["exp"] = base }, false, false, ReasonTime},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e.clock.Set(tc.nowSec)
			p, fail := e.verify(tok(tc.mut))
			if tc.wantOK {
				if fail != nil {
					t.Fatalf("rejected: %+v", fail)
				}
				return
			}
			if fail == nil {
				t.Fatalf("accepted: %+v", p)
			}
			if fail.Reason != tc.reason || fail.Expired != tc.expired {
				t.Errorf("failure = %+v, want %s expired=%v", fail, tc.reason, tc.expired)
			}
		})
	}
}

func TestVerify_SignatureAndAlgorithmAttacks(t *testing.T) {
	e := newVerifyEnv(t)
	claims := goodClaims(e.clock.Now())
	good := signed(t, e.key, "JWT", "rsa1", claims)

	t.Run("tampered signature", func(t *testing.T) {
		if _, fail := e.verify(tamper(good)); fail == nil || fail.Reason != ReasonSig {
			t.Errorf("failure = %+v, want sig", fail)
		}
	})
	t.Run("tampered payload", func(t *testing.T) {
		parts := strings.Split(good, ".")
		forged := goodClaims(e.clock.Now())
		forged["scope"] = "profile audit.read"
		tok := parts[0] + "." + b64(mustJSON(forged)) + "." + parts[2]
		if _, fail := e.verify(tok); fail == nil || fail.Reason != ReasonSig {
			t.Errorf("failure = %+v, want sig", fail)
		}
	})
	t.Run("alg none", func(t *testing.T) {
		hdr := `{"alg":"none","typ":"JWT","kid":"rsa1"}`
		tok := b64(hdr) + "." + b64(mustJSON(claims)) + "."
		if _, fail := e.verify(tok); fail == nil || fail.Reason != ReasonAlg {
			t.Errorf("failure = %+v, want alg", fail)
		}
		tok = b64(hdr) + "." + b64(mustJSON(claims)) + ".AAAA"
		if _, fail := e.verify(tok); fail == nil || fail.Reason != ReasonAlg {
			t.Errorf("none with signature: %+v, want alg", fail)
		}
	})
	t.Run("HS256 with the RSA public key as the secret", func(t *testing.T) {
		sg, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: rsaPublicDER(t, e.key)},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), "rsa1"))
		if err != nil {
			t.Fatal(err)
		}
		obj, _ := sg.Sign([]byte(mustJSON(claims)))
		tok, _ := obj.CompactSerialize()
		if _, fail := e.verify(tok); fail == nil || fail.Reason != ReasonAlg {
			t.Errorf("failure = %+v, want alg", fail)
		}
		// Even if HS256 were allowlisted by mistake, the key type check holds:
		// the KeySet verifies with the RSA key, which cannot verify an HMAC.
		leaky := &Verifier{Policy: testPolicy(), Algs: []jose.SignatureAlgorithm{jose.HS256, jose.RS256}, Keys: e.ks, Now: e.clock.Now}
		if _, fail := leaky.Verify(context.Background(), tok); fail == nil {
			t.Error("HS256 token verified with an RSA key")
		}
	})
	t.Run("alg outside the allowlist (RS512)", func(t *testing.T) {
		k := e.key
		k.alg = jose.RS512
		tok := signed(t, k, "JWT", "rsa1", claims)
		if _, fail := e.verify(tok); fail == nil || fail.Reason != ReasonAlg {
			t.Errorf("failure = %+v, want alg", fail)
		}
	})
	t.Run("signed by an unlisted key but a known kid", func(t *testing.T) {
		other := rsaKey(t, "rsa1")
		if _, fail := e.verify(signed(t, other, "JWT", "rsa1", claims)); fail == nil || fail.Reason != ReasonSig {
			t.Errorf("failure = %+v, want sig", fail)
		}
	})
	t.Run("JOSE typ missing", func(t *testing.T) {
		if _, fail := e.verify(signed(t, e.key, "", "rsa1", claims)); fail == nil || fail.Reason != ReasonTyp {
			t.Errorf("failure = %+v, want typ", fail)
		}
	})
	t.Run("JOSE typ foreign", func(t *testing.T) {
		for _, typ := range []string{"JOSE", "at+jwt2", "application/jwt", "id+jwt"} {
			if _, fail := e.verify(signed(t, e.key, typ, "rsa1", claims)); fail == nil || fail.Reason != ReasonTyp {
				t.Errorf("typ %q: failure = %+v, want typ", typ, fail)
			}
		}
	})
	t.Run("kid missing", func(t *testing.T) {
		if _, fail := e.verify(signed(t, e.key, "JWT", "", claims)); fail == nil || fail.Reason != ReasonKid {
			t.Errorf("failure = %+v, want kid", fail)
		}
	})
	t.Run("size over 8 KiB", func(t *testing.T) {
		c := goodClaims(e.clock.Now())
		c["pad"] = strings.Repeat("a", MaxTokenBytes)
		if _, fail := e.verify(signed(t, e.key, "JWT", "rsa1", c)); fail == nil || fail.Reason != ReasonFormat {
			t.Errorf("failure = %+v, want format", fail)
		}
	})
	t.Run("garbage", func(t *testing.T) {
		for _, tok := range []string{"", "a.b.c", "x", "a.b", strings.Repeat("a", 100)} {
			if _, fail := e.verify(tok); fail == nil || fail.Unavailable {
				t.Errorf("%q: failure = %+v", tok, fail)
			}
		}
	})
	t.Run("rejections never leak library text", func(t *testing.T) {
		for _, reason := range []Reason{ReasonFormat, ReasonAlg, ReasonSig, ReasonKid} {
			if strings.Contains(string(reason), "go-jose") {
				t.Errorf("reason %q leaks", reason)
			}
		}
	})
}

func TestVerify_ExpiredIsReportedOnlyForOtherwiseValidTokens(t *testing.T) {
	e := newVerifyEnv(t)
	e.clock.Set(1000)
	// Valid but expired long ago.
	c := goodClaims(t0)
	_, fail := e.verify(signed(t, e.key, "JWT", "rsa1", c))
	if fail == nil || !fail.Expired || fail.Reason != ReasonExpire {
		t.Fatalf("failure = %+v, want expired", fail)
	}
	// Expired AND another violation: invalid, not expired.
	c["aud"] = "account"
	_, fail = e.verify(signed(t, e.key, "JWT", "rsa1", c))
	if fail == nil || fail.Expired || fail.Reason != ReasonAud {
		t.Fatalf("failure = %+v, want aud, not expired", fail)
	}
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// T-011 (REQ-002, D12): jti is mandatory only under Policy.RequireJTI; iat and
// jti are carried into the Principal; the flag off changes nothing.
func TestVerify_JTI(t *testing.T) {
	e := newVerifyEnv(t)
	delJTI := func(c map[string]any) { delete(c, "jti") }

	t.Run("flag off: missing/null/number/empty jti still accepted", func(t *testing.T) {
		for name, mut := range map[string]func(map[string]any){
			"missing": delJTI,
			"null":    func(c map[string]any) { c["jti"] = nil },
			"number":  func(c map[string]any) { c["jti"] = 7 },
			"empty":   func(c map[string]any) { c["jti"] = "" },
		} {
			if _, fail := e.verify(e.mod(t, mut)); fail != nil {
				t.Errorf("%s: rejected with flag off: %+v", name, fail)
			}
		}
	})
	t.Run("flag off: IssuedAt carried, JTI not required", func(t *testing.T) {
		p, fail := e.verify(e.mod(t, func(map[string]any) {}))
		if fail != nil {
			t.Fatalf("rejected: %+v", fail)
		}
		if !p.IssuedAt.Equal(e.clock.Now()) {
			t.Errorf("IssuedAt = %v, want %v", p.IssuedAt, e.clock.Now())
		}
	})

	e.v.Policy.RequireJTI = true
	for name, mut := range map[string]func(map[string]any){
		"missing": delJTI,
		"null":    func(c map[string]any) { c["jti"] = nil },
		"number":  func(c map[string]any) { c["jti"] = 7 },
		"empty":   func(c map[string]any) { c["jti"] = "" },
		"object":  func(c map[string]any) { c["jti"] = map[string]any{} },
	} {
		t.Run("flag on: "+name, func(t *testing.T) {
			p, fail := e.verify(e.mod(t, mut))
			if fail == nil {
				t.Fatalf("accepted: %+v", p)
			}
			if fail.Reason != ReasonJTI || fail.Unavailable || fail.Expired {
				t.Errorf("failure = %+v, want reason jti", fail)
			}
		})
	}
	t.Run("flag on: valid jti carried with iat", func(t *testing.T) {
		p, fail := e.verify(e.mod(t, func(c map[string]any) { c["jti"] = "abc-123" }))
		if fail != nil {
			t.Fatalf("rejected: %+v", fail)
		}
		if p.JTI != "abc-123" || !p.IssuedAt.Equal(e.clock.Now()) {
			t.Errorf("principal = %+v", p)
		}
	})
	t.Run("flag on: earlier rules keep their reasons", func(t *testing.T) {
		for name, tc := range map[string]struct {
			mut  func(map[string]any)
			want Reason
		}{
			"iat missing":   {func(c map[string]any) { delete(c, "iat"); delete(c, "jti") }, ReasonTime},
			"iat in future": {func(c map[string]any) { c["iat"] = e.clock.Now().Unix() + 31; delete(c, "jti") }, ReasonTime},
		} {
			if _, fail := e.verify(e.mod(t, tc.mut)); fail == nil || fail.Reason != tc.want {
				t.Errorf("%s: failure = %+v, want %s", name, fail, tc.want)
			}
		}
	})
}
