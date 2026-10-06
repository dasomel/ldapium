package ldapclient

import (
	"slices"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestEntryCSNBecomesETag(t *testing.T) {
	e := ldap.NewEntry("uid=a,dc=x", map[string][]string{
		"uid": {"a"}, "cn": {"A"}, "sn": {"A"}, "entryCSN": {testCSN},
	})
	if got := entryToUser(e).ETag; got != `"`+testCSN+`"` {
		t.Errorf("user ETag = %q", got)
	}
	g := ldap.NewEntry("cn=g,dc=x", map[string][]string{"cn": {"g"}, "entryCSN": {testCSN}})
	if got := entryToDomainEntry(g).ETag; got != `"`+testCSN+`"` {
		t.Errorf("entry ETag = %q", got)
	}
}

// An unreadable (absent) or malformed entryCSN yields no ETag at all rather
// than a bogus one a client could echo back.
func TestMissingOrMalformedCSNOmitsETag(t *testing.T) {
	for _, vals := range [][]string{nil, {""}, {"garbage"}, {testCSN + ")("}} {
		attrs := map[string][]string{"uid": {"a"}, "cn": {"A"}, "sn": {"A"}}
		if vals != nil {
			attrs["entryCSN"] = vals
		}
		if got := entryToUser(ldap.NewEntry("uid=a,dc=x", attrs)).ETag; got != "" {
			t.Errorf("entryCSN %q produced ETag %q", vals, got)
		}
	}
}

func TestRequestedAttributesIncludeEntryCSN(t *testing.T) {
	if !slices.Contains(userAttrs, "entryCSN") || !slices.Contains(groupAttrs, "entryCSN") {
		t.Errorf("entryCSN is operational and must be requested by name: users %v groups %v", userAttrs, groupAttrs)
	}
}

// entryCSN is the revision, not an editable attribute: it is served via the
// ETag, never in the attributes map. userPassword stays redacted.
func TestEntryDoesNotExposeCSNOrPassword(t *testing.T) {
	e := ldap.NewEntry("uid=a,dc=x", map[string][]string{
		"uid": {"a"}, "entryCSN": {testCSN}, "userPassword": {"{SSHA}secret"}, "userPassword;binary": {"x"},
	})
	got := entryToDomainEntry(e)
	for k := range got.Attributes {
		if strings.EqualFold(k, "entryCSN") || strings.HasPrefix(strings.ToLower(k), "userpassword") {
			t.Errorf("attribute %q must not be in the response body", k)
		}
	}
	if got.ETag == "" {
		t.Error("ETag lost")
	}
}
