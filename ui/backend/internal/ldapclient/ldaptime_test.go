package ldapclient

import (
	"testing"
	"time"
)

func TestParseLDAPGeneralizedTime_Valid(t *testing.T) {
	got, ok := parseLDAPGeneralizedTime("20260812091501Z")
	if !ok {
		t.Fatal("expected ok=true for a well-formed GeneralizedTime value")
	}
	want := time.Date(2026, 8, 12, 9, 15, 1, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("parsed = %v, want %v", got, want)
	}
}

func TestParseLDAPGeneralizedTime_Empty(t *testing.T) {
	if _, ok := parseLDAPGeneralizedTime(""); ok {
		t.Error("expected ok=false for an empty string")
	}
}

func TestParseLDAPGeneralizedTime_IndefiniteLockSentinel(t *testing.T) {
	// draft-behera-ldap-password-policy's "locked until an administrator
	// intervenes" value: minute precision, no seconds field, so it does
	// not match the 14-digit layout. Must not parse "successfully" into a
	// bogus timestamp.
	if _, ok := parseLDAPGeneralizedTime("000001010000Z"); ok {
		t.Error("expected ok=false for the indefinite-lock sentinel value")
	}
}

func TestParseLDAPGeneralizedTime_Garbage(t *testing.T) {
	if _, ok := parseLDAPGeneralizedTime("not-a-timestamp"); ok {
		t.Error("expected ok=false for a non-timestamp string")
	}
}
