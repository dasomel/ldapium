package ldapclient

import "time"

// ldapGeneralizedTimeLayout matches the plain, fraction-less UTC form of
// the GeneralizedTime syntax (RFC 4517 §3.3.13) that slapd's ppolicy
// overlay writes into pwdAccountLockedTime, e.g. "20260812091501Z".
const ldapGeneralizedTimeLayout = "20060102150405Z"

// parseLDAPGeneralizedTime parses a GeneralizedTime attribute value,
// reporting ok=false for anything that isn't the plain form above. In
// particular, the password policy draft's "locked until an administrator
// intervenes" sentinel ("000001010000Z" — minute precision, no seconds
// field) does not match this layout and is deliberately left unparsed
// rather than guessed at: callers should still treat the account as
// locked from the attribute's mere presence, just without a timestamp.
func parseLDAPGeneralizedTime(s string) (t time.Time, ok bool) {
	if s == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(ldapGeneralizedTimeLayout, s)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}
