package ldapclient

import (
	"bytes"
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

const (
	testCSN  = "20261006123456.123456Z#000000#001#000000"
	testUUID = "0f9edc0e-5571-1041-945b-c76ad85cdc75"
)

// tlv encodes one short-form BER element (all test values are < 128 bytes
// except where long form is handled by the length helper).
func tlv(tag byte, content ...[]byte) []byte {
	body := bytes.Join(content, nil)
	var length []byte
	switch {
	case len(body) < 0x80:
		length = []byte{byte(len(body))}
	default:
		length = []byte{0x81, byte(len(body))}
	}
	return append(append([]byte{tag}, length...), body...)
}

func equalityMatch(attr, value string) []byte {
	return tlv(0xa3, tlv(0x04, []byte(attr)), tlv(0x04, []byte(value)))
}

func wantControl(filterBER []byte) []byte {
	return tlv(0x30,
		tlv(0x04, []byte("1.3.6.1.1.12")),
		[]byte{0x01, 0x01, 0x01}, // criticality TRUE as go-ldap encodes it (BER: any non-zero; slapd honors it, see EVIDENCE.md)
		tlv(0x04, filterBER),
	)
}

func TestRevisionControlsEncoding(t *testing.T) {
	ctrls, err := revisionControls(testCSN)
	if err != nil {
		t.Fatal(err)
	}
	if len(ctrls) != 1 {
		t.Fatalf("got %d controls, want 1", len(ctrls))
	}
	if got := ctrls[0].GetControlType(); got != "1.3.6.1.1.12" {
		t.Errorf("control type = %q", got)
	}
	got := ctrls[0].Encode().Bytes()
	want := wantControl(equalityMatch("entryCSN", testCSN))
	if !bytes.Equal(got, want) {
		t.Errorf("wire bytes differ\n got % x\nwant % x", got, want)
	}
}

func TestIdentityControlsEncoding(t *testing.T) {
	ctrls, err := identityControls(testUUID, testCSN)
	if err != nil {
		t.Fatal(err)
	}
	got := ctrls[0].Encode().Bytes()
	and := tlv(0xa0, equalityMatch("entryUUID", testUUID), equalityMatch("entryCSN", testCSN))
	want := wantControl(and)
	if !bytes.Equal(got, want) {
		t.Errorf("wire bytes differ\n got % x\nwant % x", got, want)
	}
}

func TestRevisionControlsEmptyIsUnconditional(t *testing.T) {
	ctrls, err := revisionControls("")
	if err != nil || ctrls != nil {
		t.Fatalf("revisionControls(\"\") = %v, %v; want nil, nil (no control on the header-less path)", ctrls, err)
	}
}

// Anything that is not a well-formed CSN/UUID must be refused before it can
// reach a filter string, including filter-injection attempts.
func TestControlsRefuseMalformedValues(t *testing.T) {
	bad := []string{
		"*",
		"x",
		testCSN + ")(objectClass=*",
		"(entryCSN=" + testCSN + ")",
		testCSN + "\x00",
		"20261006123456.123456Z#000000#001#00000\\29",
	}
	for _, v := range bad {
		if _, err := revisionControls(v); !errors.Is(err, domain.ErrInvalidInput) {
			t.Errorf("revisionControls(%q) err = %v, want ErrInvalidInput", v, err)
		}
		if _, err := identityControls(testUUID, v); !errors.Is(err, domain.ErrInvalidInput) {
			t.Errorf("identityControls(uuid, %q) err = %v, want ErrInvalidInput", v, err)
		}
		if _, err := identityControls(v, testCSN); !errors.Is(err, domain.ErrInvalidInput) {
			t.Errorf("identityControls(%q, csn) err = %v, want ErrInvalidInput", v, err)
		}
	}
}

func FuzzRevisionControls(f *testing.F) {
	f.Add(testCSN)
	f.Add("")
	f.Add("a)(b=*")
	f.Fuzz(func(t *testing.T, v string) {
		ctrls, err := revisionControls(v)
		if v == "" {
			return
		}
		if domain.ValidCSN(v) != (err == nil) {
			t.Fatalf("revisionControls(%q) err=%v but ValidCSN=%v", v, err, domain.ValidCSN(v))
		}
		if err == nil && len(ctrls) != 1 {
			t.Fatalf("valid CSN produced %d controls", len(ctrls))
		}
	})
}

func TestMapErrAssertionFailed(t *testing.T) {
	err := mapErr("update user", ldap.NewError(ldap.LDAPResultAssertionFailed, errors.New("assertion failed")))
	if !errors.Is(err, domain.ErrRevisionConflict) {
		t.Errorf("assertionFailed -> %v, want ErrRevisionConflict", err)
	}
	// unavailableCriticalExtension must NOT degrade into a client error or an
	// unconditional write: it stays an unclassified (500) failure.
	err = mapErr("update user", ldap.NewError(ldap.LDAPResultUnavailableCriticalExtension, errors.New("critical extension is unavailable")))
	for _, s := range []error{domain.ErrRevisionConflict, domain.ErrInvalidInput, domain.ErrNotFound, domain.ErrConflict} {
		if errors.Is(err, s) {
			t.Errorf("unavailableCriticalExtension mapped to %v", s)
		}
	}
}
