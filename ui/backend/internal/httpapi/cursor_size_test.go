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
)

func payloadOf(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// Keys and DNs travel as plain JSON strings (one base64 layer, not two), so
// a long DN does not blow the 2048 byte cap at ~1030 bytes.
func TestCursorCarriesLongPositionsAsPlainStrings(t *testing.T) {
	key := cursorKey(cursorTestSecret)
	binding := cursorBinding(key, testSession("s"))
	dn := "uid=" + strings.Repeat("a", 900) + ",ou=people,dc=example,dc=org"
	pos := domain.PagePosition{Key: strings.Repeat("k", 300), DN: dn}
	token, err := encodeCursor(key, "users", "", binding, pos)
	if err != nil {
		t.Fatalf("a %d byte key+DN must fit: %v", len(pos.Key)+len(pos.DN), err)
	}
	if len(token) > maxCursorLen {
		t.Errorf("token is %d bytes, cap %d", len(token), maxCursorLen)
	}
	if !strings.Contains(payloadOf(t, token), dn) {
		t.Error("the DN is not a plain JSON string inside the payload")
	}
	got, err := decodeCursor(key, token, "users", "", binding)
	if err != nil || got != pos {
		t.Errorf("round trip = %+v, %v", got, err)
	}
}

// The cap still applies: a position that cannot fit is an error from
// encodeCursor (docs/api.md: the listing answers 500 internal and logs it).
func TestCursorOverTheCapStillFails(t *testing.T) {
	key := cursorKey(cursorTestSecret)
	pos := domain.PagePosition{Key: "k", DN: strings.Repeat("x", 1600)}
	if _, err := encodeCursor(key, "users", "", "b", pos); err == nil {
		t.Error("a token over the cap was minted")
	}
	// Just below the cap works.
	pos.DN = strings.Repeat("x", 1380)
	token, err := encodeCursor(key, "users", "", "b", pos)
	if err != nil || len(token) > maxCursorLen {
		t.Errorf("1380 byte DN: len=%d err=%v", len(token), err)
	}
}

// Old-format (v1: base64-in-JSON) tokens are rejected as cursor_invalid even
// with a valid MAC, never reinterpreted as plain strings.
func TestCursorOldFormatIsRejected(t *testing.T) {
	key := cursorKey(cursorTestSecret)
	binding := cursorBinding(key, testSession("s"))
	raw, _ := json.Marshal(map[string]any{"v": 1, "r": "users", "k": []byte("alice"), "d": []byte("uid=alice"), "q": "", "s": binding})
	p := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("v1." + p))
	old := "v1." + p + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if _, err := decodeCursor(key, old, "users", "", binding); !errors.Is(err, errCursorInvalid) {
		t.Errorf("v1 token: err = %v, want errCursorInvalid", err)
	}
}

// Non-UTF-8 bytes use the base64 fallback, flagged in the payload; the flag
// is only canonical when a value really needs it.
func TestCursorFallbackIsFlaggedAndCanonical(t *testing.T) {
	key := cursorKey(cursorTestSecret)
	binding := cursorBinding(key, testSession("s"))
	pos := domain.PagePosition{Key: string([]byte{0xff, 'a'}), DN: "uid=ok"}
	token, err := encodeCursor(key, "users", "", binding, pos)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payloadOf(t, token), `"b":true`) {
		t.Errorf("fallback not flagged: %s", payloadOf(t, token))
	}
	flagged := map[string]any{"v": 2, "r": "users", "k": base64.StdEncoding.EncodeToString([]byte("a")),
		"d": base64.StdEncoding.EncodeToString([]byte("b")), "q": "", "s": binding, "b": true}
	if _, err := decodeCursor(key, signed(key, flagged), "users", "", binding); !errors.Is(err, errCursorInvalid) {
		t.Errorf("flag without a non-UTF-8 value: err = %v, want errCursorInvalid", err)
	}
}

func signedRaw(key []byte, rawJSON string) string {
	p := base64.RawURLEncoding.EncodeToString([]byte(rawJSON))
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("v2." + p))
	return "v2." + p + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// json.Marshal HTML-escapes & < > (6 bytes each); the cursor must not.
func TestCursorDoesNotHTMLEscape(t *testing.T) {
	key := cursorKey(cursorTestSecret)
	binding := cursorBinding(key, testSession("s"))
	pos := domain.PagePosition{Key: strings.Repeat("&", 250), DN: "uid=" + strings.Repeat("<", 900) + ",dc=e"}
	token, err := encodeCursor(key, "users", "", binding, pos)
	if err != nil {
		t.Fatalf("250 '&' + 900 '<' must fit: %v", err)
	}
	if strings.Contains(payloadOf(t, token), `\u00`) {
		t.Error("&, < or > was escaped")
	}
	if got, err := decodeCursor(key, token, "users", "", binding); err != nil || got != pos {
		t.Errorf("round trip = %v", err)
	}
}

// Worst cases in post-encoding bytes (docs/api.md): control characters cost 6
// bytes each in JSON and a non-UTF-8 value goes through base64 twice. These
// still exceed the cap and are an error, never a malformed token.
func TestCursorWorstCaseInputsAreAnErrorNotAMalformedToken(t *testing.T) {
	key := cursorKey(cursorTestSecret)
	for name, pos := range map[string]domain.PagePosition{
		"250 control chars in the DN": {Key: "k", DN: strings.Repeat("\x01", 250) + strings.Repeat("a", 600)},
		"non-UTF-8 key, 1100 byte DN": {Key: string([]byte{0xff, 'a'}), DN: strings.Repeat("d", 1100)},
	} {
		token, err := encodeCursor(key, "users", "", "b", pos)
		if err == nil || token != "" {
			t.Errorf("%s: token of %d bytes minted (err %v)", name, len(token), err)
		}
	}
	// ...and the documented limits themselves still work.
	for name, pos := range map[string]domain.PagePosition{
		"ASCII 1380":        {Key: "k", DN: strings.Repeat("a", 1380)},
		"control chars 200": {Key: "k", DN: strings.Repeat("\x01", 200)},
		"non-UTF-8, 900 DN": {Key: string([]byte{0xff}), DN: strings.Repeat("d", 900)},
	} {
		if token, err := encodeCursor(key, "users", "", "b", pos); err != nil || len(token) > maxCursorLen {
			t.Errorf("%s: len %d err %v", name, len(token), err)
		}
	}
}

// Decoding re-encodes the payload and compares it with the exact signed bytes,
// so only the one canonical spelling is accepted even with a valid MAC.
func TestCursorDecodeIsByteCanonical(t *testing.T) {
	key := cursorKey(cursorTestSecret)
	binding := cursorBinding(key, testSession("s"))
	head := `{"v":2,"r":"users","k":"a","d":"b","q":"","s":"` + binding + `"}`
	if _, err := decodeCursor(key, signedRaw(key, head), "users", "", binding); err != nil {
		t.Fatalf("canonical control rejected: %v", err)
	}
	for name, raw := range map[string]string{
		"duplicate key":      `{"v":2,"r":"users","k":"x","k":"a","d":"b","q":"","s":"` + binding + `"}`,
		"case-variant key":   `{"V":2,"r":"users","k":"a","d":"b","q":"","s":"` + binding + `"}`,
		"null value":         `{"v":2,"r":"users","k":null,"d":"b","q":"","s":"` + binding + `"}`,
		"explicit b false":   `{"v":2,"r":"users","k":"a","d":"b","q":"","s":"` + binding + `","b":false}`,
		"lone surrogate":     `{"v":2,"r":"users","k":"\ud800","d":"b","q":"","s":"` + binding + `"}`,
		"escaped plain char": `{"v":2,"r":"users","k":"\u0061","d":"b","q":"","s":"` + binding + `"}`,
		"extra whitespace":   `{"v":2, "r":"users","k":"a","d":"b","q":"","s":"` + binding + `"}`,
	} {
		if _, err := decodeCursor(key, signedRaw(key, raw), "users", "", binding); !errors.Is(err, errCursorInvalid) {
			t.Errorf("%s: err = %v, want errCursorInvalid", name, err)
		}
	}
}
