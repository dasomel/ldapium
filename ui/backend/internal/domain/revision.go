package domain

import (
	"errors"
	"regexp"
)

// ErrRevisionConflict means a conditional write was refused because the
// entry's revision no longer matches the one the caller read (LDAP result
// assertionFailed, 122). Nothing was written.
var ErrRevisionConflict = errors.New("resource was modified since it was read; reload and retry")

// A revision is the entry's entryCSN. These patterns are the only gate
// between a client-supplied header and an LDAP filter, so they are strict
// allow-lists (slapd emits uppercase hex) and anchored: nothing that does
// not match is ever concatenated into a filter.
var (
	csnPattern  = regexp.MustCompile(`^[0-9]{14}\.[0-9]{6}Z#[0-9A-F]{6}#[0-9A-F]{3}#[0-9A-F]{6}$`)
	uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// ValidCSN reports whether s is a well-formed entryCSN value.
func ValidCSN(s string) bool { return csnPattern.MatchString(s) }

// ValidEntryUUID reports whether s is a well-formed entryUUID value.
func ValidEntryUUID(s string) bool { return uuidPattern.MatchString(s) }

// ETagFromCSN renders csn as a quoted strong ETag, or "" when csn is not a
// well-formed entryCSN (an unreadable or odd revision is simply omitted).
func ETagFromCSN(csn string) string {
	if !ValidCSN(csn) {
		return ""
	}
	return `"` + csn + `"`
}

// CSNFromETag is the strict inverse of ETagFromCSN: exactly one quoted
// strong tag holding a well-formed entryCSN. Weak tags, lists, unquoted
// values and anything else report false.
func CSNFromETag(tag string) (string, bool) {
	if len(tag) < 2 || tag[0] != '"' || tag[len(tag)-1] != '"' {
		return "", false
	}
	csn := tag[1 : len(tag)-1]
	if !ValidCSN(csn) {
		return "", false
	}
	return csn, true
}
