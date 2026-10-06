package httpapi

import "testing"

// The write Origin gate runs before the idempotency middleware: a keyed write
// from a foreign origin is refused with 403 and no key is ever recorded.
func TestIdempotency_OriginGateRunsBeforeAnyKeyIsRecorded(t *testing.T) {
	for _, tc := range []writeCase{
		{"user PUT", "PUT", "/api/users", putBody, ""},
		{"user DELETE", "DELETE", "/api/users?dn=" + targetDN, "", ""},
		{"password", "POST", "/api/users/password", `{"dn":"` + targetDN + `","password":"` + idemPw + `"}`, ""},
		{"group member add", "POST", "/api/groups/members", `{"groupDn":"` + targetGroup + `","memberDn":"` + targetDN + `"}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newIdemClient()
			s, ck := newIdemServer(t, c, nil)
			hdr := withKey(idemKey)
			hdr["Origin"] = []string{"https://evil.example"}
			rec := doReq(s, ck, tc.method, tc.path, tc.body, hdr)
			if rec.Code != 403 || envelopeOf(t, rec)["code"] != "origin_mismatch" {
				t.Fatalf("status %d %q, want 403 origin_mismatch", rec.Code, rec.Body.String())
			}
			if len(c.counts) != 0 || s.idem.Len() != 0 {
				t.Fatalf("writes=%v records=%d: nothing may happen before the gate", c.counts, s.idem.Len())
			}
			// The same key from the page's own origin is a fresh request.
			ok := withKey(idemKey)
			ok["Origin"] = []string{"http://example.com"}
			if rec := doReq(s, ck, tc.method, tc.path, tc.body, ok); rec.Header().Get("Idempotent-Replayed") != "" || rec.Code >= 400 {
				t.Fatalf("own origin = %d replayed=%q", rec.Code, rec.Header().Get("Idempotent-Replayed"))
			}
		})
	}
}
