package ldapclient

import (
	"github.com/go-ldap/ldap/v3"
	"testing"
)

func TestRevocationValueRejectsAmbiguousValues(t *testing.T) {
	for _, values := range [][]string{nil, {""}, {"one", "two"}, {"one\n"}, {"one\r"}, {"one\x00"}} {
		if _, err := revocationValue(ldap.NewEntry("cn=x", map[string][]string{"cn": values}), "cn"); err == nil {
			t.Fatalf("accepted %q", values)
		}
	}
	e := &ldap.Entry{Attributes: []*ldap.EntryAttribute{{Name: "cn", Values: []string{"x"}}, {Name: "CN", Values: []string{"x"}}}}
	if _, err := revocationValue(e, "cn"); err == nil {
		t.Fatal("accepted duplicate attribute")
	}
}

func TestRevocationRowRequiresServerTimestamp(t *testing.T) {
	e := ldap.NewEntry("cn=jti-x", map[string][]string{"cn": {"jti-x"}, "ou": {"client"}, "createTimestamp": {"20261008000000Z"}})
	if _, err := revocationRow(e); err != nil {
		t.Fatal(err)
	}
	e = ldap.NewEntry("cn=jti-x", map[string][]string{"cn": {"jti-x"}, "ou": {"client"}, "createTimestamp": {"invalid"}})
	if _, err := revocationRow(e); err == nil {
		t.Fatal("accepted malformed timestamp")
	}
}
