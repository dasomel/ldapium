package httpapi

import (
	"regexp"
	"strings"
)

// D218-15: 4xx messages derived from LDAP diagnostics.
//
// ldapclient/errors.go wraps the server's diagnostic text after the domain
// sentinel ("invalid input: <diagnostic>"). That text is whatever slapd or an
// overlay chose to say and can carry DNs, attribute names or values, so it
// does not reach a response by default: publicDomainMessage replaces it with
// the sentinel's fixed text and the caller logs the original under the
// request ID.
//
// Exception, because the change-password screen shows these to the user and
// they are the only way a user learns why a new password was refused: the
// diagnostics below are known, fixed policy texts that contain no DN, no
// attribute value and no part of the password. They were enumerated from the
// shipped slapo-ppolicy and ppm (strings of ppolicy.so / ppm.so in the image)
// and confirmed live (see docs/changes/api-error-envelope/CHANGE.md, D218-15).
// Anything not on this list — including a future ppm/ppolicy message — is
// withheld until someone reviews it and adds it here, with a test.

// safeDiagnostics are matched exactly (after the sentinel prefix).
var safeDiagnostics = map[string]struct{}{
	// slapo-ppolicy constraint-violation texts.
	"Password fails quality checking policy":                    {},
	"Password is in history of old passwords":                   {},
	"Password is not being changed from existing value":         {},
	"Password is too young to change":                           {},
	"Password policy only allows one password value":            {},
	"User alteration of password is not allowed":                {},
	"Must supply old password to be changed as well as new one": {},
	"Must supply correct old password to change to new one":     {},
	// Value-free validation texts ldapclient raises itself.
	"uid, cn and sn are required":     {},
	"cn and sn are required":          {},
	"cn is required":                  {},
	"uid must not be empty":           {},
	"uid must be valid UTF-8":         {},
	"cn must be valid UTF-8":          {},
	"dn and newParentDN are required": {},
}

// ppm prefixes every message with `Password for dn="<user DN>" `, which is the
// part that must never leave the server. The DN is dropped; only the tail, and
// only when it matches one of ppm's own message shapes, is kept (numbers and
// the configured class name are the only variable parts). ppm's
// "contains N forbidden characters in <set>" is kept as the count alone: it is
// not established that <set> is policy configuration rather than password
// content.
var ppmDiagnostic = regexp.MustCompile(`(?s)^Password for dn=".*" (` +
	`contains tokens from the RDN` +
	`|does not pass required number of strength checks \(\d{1,3} of \d{1,3}\)` +
	`|has not reached the minimum number of characters \(\d{1,4}\) for class [A-Za-z0-9_-]{1,32}` +
	`|has reached the maximum number of characters \(\d{1,4}\) for class [A-Za-z0-9_-]{1,32}` +
	`|is too simple: it contains part of an attribute` +
	`)$`)

var ppmForbiddenChars = regexp.MustCompile(`(?s)^Password for dn=".*" contains (\d{1,4}) forbidden characters in .*$`)

// safeDiagnostic returns the publishable form of a wrapped LDAP diagnostic.
func safeDiagnostic(diag string) (string, bool) {
	if _, ok := safeDiagnostics[diag]; ok {
		return diag, true
	}
	if m := ppmDiagnostic.FindStringSubmatch(diag); m != nil {
		return "Password " + m[1], true
	}
	if m := ppmForbiddenChars.FindStringSubmatch(diag); m != nil {
		return "Password contains " + m[1] + " forbidden characters", true
	}
	return "", false
}

// safeMessagePrefixes are curated wrappers ldapclient puts in front of a
// sentinel; they are fixed text.
var safeMessagePrefixes = map[string]struct{}{
	"user created but setting password failed: ": {},
}

// publicDomainMessage returns the text a response may carry for err, which
// wraps sentinel, and whether anything was withheld. A bare sentinel is its
// own fixed text and passes through; otherwise only an allowlisted prefix and
// a safeDiagnostic survive.
func publicDomainMessage(sentinel, err error) (msg string, withheld bool) {
	full, base := err.Error(), sentinel.Error()
	if full == base {
		return base, false
	}
	i := strings.Index(full, base+": ")
	if i < 0 {
		return base, true
	}
	prefix := full[:i]
	if _, ok := safeMessagePrefixes[prefix]; prefix != "" && !ok {
		return base, true
	}
	safe, ok := safeDiagnostic(full[i+len(base)+2:])
	if !ok {
		return base, true
	}
	return prefix + base + ": " + safe, safe != full[i+len(base)+2:]
}
