package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/session"
)

var (
	cursorTestSecret = []byte("0123456789abcdef0123456789abcdef-secret")
	testPos          = domain.PagePosition{Key: "alice", DN: "uid=alice,ou=people,dc=example,dc=org"}
)

func testSession(id string) *session.Session {
	return &session.Session{ID: id, DN: "cn=admin,dc=example,dc=org"}
}

func newTestCursor(t *testing.T) (key []byte, binding, token string) {
	t.Helper()
	key = cursorKey(cursorTestSecret)
	binding = cursorBinding(key, testSession("sess-1"))
	token, err := encodeCursor(key, "users", "ali", binding, testPos)
	if err != nil {
		t.Fatal(err)
	}
	return key, binding, token
}

func TestCursorRoundTrip(t *testing.T) {
	key, binding, token := newTestCursor(t)
	got, err := decodeCursor(key, token, "users", "ali", binding)
	if err != nil {
		t.Fatalf("decodeCursor: %v", err)
	}
	if got != testPos {
		t.Errorf("position = %+v, want %+v", got, testPos)
	}
	if !strings.HasPrefix(token, "v1.") || strings.Count(token, ".") != 2 {
		t.Errorf("token %q is not v1.<payload>.<mac>", token)
	}
}

func TestCursorCarriesArbitraryBytesLosslessly(t *testing.T) {
	// A DN or key that is not valid UTF-8 must survive; JSON strings would not.
	key := cursorKey(cursorTestSecret)
	binding := cursorBinding(key, testSession("s"))
	pos := domain.PagePosition{Key: string([]byte{0xff, 0xfe, 'a'}), DN: "uid=\x80\x81,dc=e"}
	token, err := encodeCursor(key, "groups", "", binding, pos)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeCursor(key, token, "groups", "", binding)
	if err != nil || got != pos {
		t.Errorf("round trip = %+v, %v", got, err)
	}
}

func TestCursorRejectsEveryOneByteTamper(t *testing.T) {
	key, binding, token := newTestCursor(t)
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.\r\n \t+/="
	for i := 0; i < len(token); i++ {
		for _, r := range []byte(alphabet) {
			if r == token[i] {
				continue
			}
			mutated := token[:i] + string(r) + token[i+1:]
			if _, err := decodeCursor(key, mutated, "users", "ali", binding); err == nil {
				t.Fatalf("tampered cursor accepted: byte %d %q -> %q", i, token[i], r)
			}
		}
	}
}

// Go's base64 decoder skips CR and LF, so a token with a newline inside the MAC
// part would decode to the same MAC. A cursor must be accepted in exactly one
// spelling.
func TestCursorRejectsWhitespaceAndNonCanonicalSpellings(t *testing.T) {
	key, binding, token := newTestCursor(t)
	parts := strings.Split(token, ".")
	for _, ins := range []string{"\n", "\r", "\r\n", " ", "\t", "%0A"} {
		for i := 0; i <= len(token); i++ {
			mutated := token[:i] + ins + token[i:]
			if _, err := decodeCursor(key, mutated, "users", "ali", binding); err == nil {
				t.Fatalf("cursor with %q inserted at %d accepted: %q", ins, i, mutated)
			}
		}
	}
	// Non-zero trailing bits in the last base64 character decode to the same
	// bytes in a lenient decoder; only the canonical spelling may pass.
	last := parts[2][len(parts[2])-1]
	for _, r := range []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") {
		if r == last {
			continue
		}
		mutated := parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-1] + string(r)
		if _, err := decodeCursor(key, mutated, "users", "ali", binding); err == nil {
			t.Fatalf("non-canonical MAC spelling accepted: last char %q -> %q", last, r)
		}
	}
}

func TestCursorRejectsEveryTruncation(t *testing.T) {
	key, binding, token := newTestCursor(t)
	for n := 0; n < len(token); n++ {
		if _, err := decodeCursor(key, token[:n], "users", "ali", binding); err == nil {
			t.Fatalf("truncated cursor (%d of %d bytes) accepted", n, len(token))
		}
	}
	if _, err := decodeCursor(key, token+"A", "users", "ali", binding); err == nil {
		t.Error("cursor with trailing byte accepted")
	}
}

func TestCursorRejectsMisuse(t *testing.T) {
	key, binding, token := newTestCursor(t)
	tests := []struct {
		name     string
		key      []byte
		token    string
		resource string
		q        string
		binding  string
	}{
		{"users cursor on groups", key, token, "groups", "ali", binding},
		{"different q", key, token, "users", "alice", binding},
		{"q dropped", key, token, "users", "", binding},
		{"new login of the same DN is a new Session.ID", key, token, "users", "ali", cursorBinding(key, testSession("sess-2"))},
		{"session secret rotated", cursorKey([]byte("another-secret-another-secret-another-secret")), token, "users", "ali", binding},
		{"empty", key, "", "users", "ali", binding},
		{"not base64", key, "v1.!!!.???", "users", "ali", binding},
		{"junk", key, "garbage", "users", "ali", binding},
		{"over the length cap", key, token + strings.Repeat("A", maxCursorLen), "users", "ali", binding},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeCursor(tt.key, tt.token, tt.resource, tt.q, tt.binding)
			if !errors.Is(err, errCursorInvalid) {
				t.Errorf("err = %v, want errCursorInvalid", err)
			}
		})
	}
}

// signed builds a correctly MAC'd token around an arbitrary payload, to prove
// the other checks (version, unknown fields) hold even against a valid MAC.
func signed(key []byte, payload any) string {
	raw, _ := json.Marshal(payload)
	p := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("v1." + p))
	return "v1." + p + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestCursorRejectsValidMACWithWrongContent(t *testing.T) {
	key := cursorKey(cursorTestSecret)
	binding := cursorBinding(key, testSession("sess-1"))
	good := map[string]any{"v": 1, "r": "users", "k": []byte("a"), "d": []byte("b"), "q": "", "s": binding}
	if _, err := decodeCursor(key, signed(key, good), "users", "", binding); err != nil {
		t.Fatalf("control token rejected: %v", err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"unknown version": func(m map[string]any) { m["v"] = 2 },
		"unknown field":   func(m map[string]any) { m["x"] = 1 },
		"bad key type":    func(m map[string]any) { m["k"] = 5 },
	} {
		m := map[string]any{}
		for k, v := range good {
			m[k] = v
		}
		mutate(m)
		if _, err := decodeCursor(key, signed(key, m), "users", "", binding); !errors.Is(err, errCursorInvalid) {
			t.Errorf("%s: err = %v, want errCursorInvalid", name, err)
		}
	}
}

func TestCursorKeyIsSeparatedFromTheSessionSecret(t *testing.T) {
	key := cursorKey(cursorTestSecret)
	if string(key) == string(cursorTestSecret) {
		t.Fatal("cursor key equals the session secret")
	}
	// A cursor MAC'd directly with the session secret (what a holder of a
	// cookie-signing oracle could produce) must not verify.
	binding := cursorBinding(key, testSession("s"))
	raw, _ := json.Marshal(map[string]any{"v": 1, "r": "users", "k": []byte("a"), "d": []byte("b"), "q": "", "s": binding})
	p := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, cursorTestSecret)
	mac.Write([]byte("v1." + p))
	forged := "v1." + p + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if _, err := decodeCursor(key, forged, "users", "", binding); !errors.Is(err, errCursorInvalid) {
		t.Errorf("cursor MAC'd with the raw session secret was accepted: %v", err)
	}
}

func TestCursorBindingDoesNotExposeTheSessionID(t *testing.T) {
	key := cursorKey(cursorTestSecret)
	sess := testSession("super-secret-session-id-0123456789")
	binding := cursorBinding(key, sess)
	token, err := encodeCursor(key, "users", "", binding, testPos)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
	if strings.Contains(token, sess.ID) || strings.Contains(string(payload), sess.ID) {
		t.Error("the session ID appears in the cursor")
	}
	if cursorBinding(key, sess) != binding {
		t.Error("binding is not deterministic")
	}
	if cursorBinding(key, testSession("other")) == binding {
		t.Error("two sessions share a binding")
	}
}

func TestEncodeCursorRefusesOversizedTokens(t *testing.T) {
	key := cursorKey(cursorTestSecret)
	huge := domain.PagePosition{Key: "k", DN: strings.Repeat("x", maxCursorLen)}
	if _, err := encodeCursor(key, "users", "", "b", huge); err == nil {
		t.Error("an oversized cursor was emitted although decodeCursor would reject it")
	}
}
