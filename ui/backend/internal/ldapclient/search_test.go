package ldapclient

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestCapEntries_UnderLimit(t *testing.T) {
	entries := []*ldap.Entry{
		ldap.NewEntry("uid=a,dc=example,dc=com", nil),
		ldap.NewEntry("uid=b,dc=example,dc=com", nil),
	}
	got, truncated := capEntries(entries, 5)
	if truncated {
		t.Errorf("truncated = true, want false")
	}
	if len(got) != 2 {
		t.Errorf("len(got) = %d, want 2", len(got))
	}
}

func TestCapEntries_AtLimit(t *testing.T) {
	entries := []*ldap.Entry{
		ldap.NewEntry("uid=a,dc=example,dc=com", nil),
		ldap.NewEntry("uid=b,dc=example,dc=com", nil),
	}
	got, truncated := capEntries(entries, 2)
	if truncated {
		t.Errorf("truncated = true, want false (exactly at the cap is not truncation)")
	}
	if len(got) != 2 {
		t.Errorf("len(got) = %d, want 2", len(got))
	}
}

func TestCapEntries_OverLimit(t *testing.T) {
	entries := []*ldap.Entry{
		ldap.NewEntry("uid=a,dc=example,dc=com", nil),
		ldap.NewEntry("uid=b,dc=example,dc=com", nil),
		ldap.NewEntry("uid=c,dc=example,dc=com", nil),
	}
	got, truncated := capEntries(entries, 2)
	if !truncated {
		t.Errorf("truncated = false, want true")
	}
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2", len(got))
	}
	if got[0].DN != "uid=a,dc=example,dc=com" || got[1].DN != "uid=b,dc=example,dc=com" {
		t.Errorf("cap kept the wrong entries: %v", got)
	}
}
