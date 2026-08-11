package domain

// PasswordPolicy is the application's view of a pwdPolicy entry
// (draft-behera-ldap-password-policy, as implemented by slapd's ppolicy
// overlay). Every field beyond DN/CN/PwdAttribute is a pointer so the UI
// can tell "this attribute is absent from the entry" from "it's present
// and zero/false" — PwdMaxAge: 0, for instance, is a meaningful value (no
// expiration), not a missing one. Values are surfaced exactly as the
// server stores them; nothing here reinterprets or guesses at a rule the
// server didn't state.
type PasswordPolicy struct {
	DN string `json:"dn"`
	CN string `json:"cn"`
	// PwdAttribute names the password attribute this policy governs
	// (userPassword, in every case this app deals with). Required by the
	// pwdPolicy schema, so always present when the entry exists at all.
	PwdAttribute string `json:"pwdAttribute"`
	// PwdMinLength is the minimum acceptable password length.
	PwdMinLength *int `json:"pwdMinLength,omitempty"`
	// PwdInHistory is how many previous passwords the server remembers
	// and rejects reuse of.
	PwdInHistory *int `json:"pwdInHistory,omitempty"`
	// PwdMaxAge is how long (seconds) a password stays valid before it
	// must be changed; 0 means it never expires.
	PwdMaxAge *int `json:"pwdMaxAge,omitempty"`
	// PwdCheckQuality indicates whether/how strictly the server checks
	// password quality (0=off, 1=checked-if-possible, 2=required). It
	// does not itself describe what "quality" means.
	PwdCheckQuality *int `json:"pwdCheckQuality,omitempty"`
	// PwdLockout is whether too many failed binds locks the account.
	PwdLockout *bool `json:"pwdLockout,omitempty"`
	// PwdMaxFailure is how many consecutive failed binds trigger a lockout.
	PwdMaxFailure *int `json:"pwdMaxFailure,omitempty"`
	// PwdLockoutDuration is how long (seconds) a lockout lasts before it
	// clears on its own; 0 means it never clears automatically (an
	// administrator must unlock it).
	PwdLockoutDuration *int `json:"pwdLockoutDuration,omitempty"`
	// PwdSafeModify is whether a Password Modify request (RFC 3062) must
	// include the current password to succeed.
	PwdSafeModify *bool `json:"pwdSafeModify,omitempty"`
}
