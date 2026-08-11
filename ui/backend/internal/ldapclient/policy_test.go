package ldapclient

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestEntryToPasswordPolicy_AllFieldsPresent(t *testing.T) {
	// Mirrors the actual cn=default entry seen on the running server.
	e := ldap.NewEntry("cn=default,ou=policies,dc=example,dc=org", map[string][]string{
		"cn":                 {"default"},
		"pwdAttribute":       {"userPassword"},
		"pwdCheckQuality":    {"1"},
		"pwdMinLength":       {"8"},
		"pwdInHistory":       {"5"},
		"pwdLockout":         {"TRUE"},
		"pwdMaxFailure":      {"5"},
		"pwdLockoutDuration": {"900"},
		"pwdMaxAge":          {"0"},
		"pwdSafeModify":      {"TRUE"},
	})

	p := entryToPasswordPolicy(e)

	if p.DN != e.DN {
		t.Errorf("DN = %q, want %q", p.DN, e.DN)
	}
	if p.CN != "default" {
		t.Errorf("CN = %q, want %q", p.CN, "default")
	}
	if p.PwdAttribute != "userPassword" {
		t.Errorf("PwdAttribute = %q, want %q", p.PwdAttribute, "userPassword")
	}
	assertIntPtr(t, "PwdMinLength", p.PwdMinLength, 8)
	assertIntPtr(t, "PwdInHistory", p.PwdInHistory, 5)
	// 0 is a real, meaningful value (no expiration) — must round-trip as
	// a non-nil pointer to 0, not be dropped as if absent.
	assertIntPtr(t, "PwdMaxAge", p.PwdMaxAge, 0)
	assertIntPtr(t, "PwdCheckQuality", p.PwdCheckQuality, 1)
	assertIntPtr(t, "PwdMaxFailure", p.PwdMaxFailure, 5)
	assertIntPtr(t, "PwdLockoutDuration", p.PwdLockoutDuration, 900)
	assertBoolPtr(t, "PwdLockout", p.PwdLockout, true)
	assertBoolPtr(t, "PwdSafeModify", p.PwdSafeModify, true)
}

func TestEntryToPasswordPolicy_AbsentFieldsAreNil(t *testing.T) {
	// A minimal, schema-valid pwdPolicy entry: only the MUST attribute is
	// present. Every optional field must come back nil, not a guessed
	// zero value — nil is what lets the UI tell "not configured" apart
	// from "configured to 0/false".
	e := ldap.NewEntry("cn=minimal,ou=policies,dc=example,dc=org", map[string][]string{
		"cn":           {"minimal"},
		"pwdAttribute": {"userPassword"},
	})

	p := entryToPasswordPolicy(e)

	if p.PwdMinLength != nil {
		t.Errorf("PwdMinLength = %v, want nil", p.PwdMinLength)
	}
	if p.PwdMaxAge != nil {
		t.Errorf("PwdMaxAge = %v, want nil", p.PwdMaxAge)
	}
	if p.PwdLockout != nil {
		t.Errorf("PwdLockout = %v, want nil", p.PwdLockout)
	}
	if p.PwdSafeModify != nil {
		t.Errorf("PwdSafeModify = %v, want nil", p.PwdSafeModify)
	}
}

func TestBoolAttr_OnlyAcceptsLDAPBooleanSyntax(t *testing.T) {
	e := ldap.NewEntry("cn=x", map[string][]string{
		"a": {"TRUE"},
		"b": {"FALSE"},
		"c": {"true"}, // lowercase is not valid LDAP Boolean syntax (RFC 4517 §3.3.3)
	})

	assertBoolPtr(t, "a", boolAttr(e, "a"), true)
	assertBoolPtr(t, "b", boolAttr(e, "b"), false)
	if got := boolAttr(e, "c"); got != nil {
		t.Errorf("boolAttr(c) = %v, want nil for a non-canonical value", got)
	}
	if got := boolAttr(e, "missing"); got != nil {
		t.Errorf("boolAttr(missing) = %v, want nil", got)
	}
}

func assertIntPtr(t *testing.T, name string, got *int, want int) {
	t.Helper()
	if got == nil {
		t.Errorf("%s = nil, want %d", name, want)
		return
	}
	if *got != want {
		t.Errorf("%s = %d, want %d", name, *got, want)
	}
}

func assertBoolPtr(t *testing.T, name string, got *bool, want bool) {
	t.Helper()
	if got == nil {
		t.Errorf("%s = nil, want %v", name, want)
		return
	}
	if *got != want {
		t.Errorf("%s = %v, want %v", name, *got, want)
	}
}
