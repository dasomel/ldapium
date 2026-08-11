package domain

import "time"

// User is the application's view of an LDAP person entry
// (objectClass inetOrgPerson/posixAccount, in practice).
type User struct {
	DN          string `json:"dn"`
	UID         string `json:"uid"`
	CN          string `json:"cn"`
	SN          string `json:"sn"`
	GivenName   string `json:"givenName,omitempty"`
	Mail        string `json:"mail,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	// MemberOf lists the DNs of groups this user belongs to, as computed
	// by the server's memberof overlay. It is read-only here; group
	// membership is changed via AddMember/RemoveMember on the group side.
	MemberOf []string `json:"memberOf,omitempty"`
	// Locked is true when the directory's password policy overlay has
	// locked this account (its pwdAccountLockedTime attribute is set),
	// typically after too many failed bind attempts. Clear it with
	// Client.Unlock.
	Locked bool `json:"locked"`
	// LockedAt is when the lock was applied, if pwdAccountLockedTime could
	// be parsed as a timestamp. It is nil both when the account isn't
	// locked and when it's locked "until an administrator intervenes" (a
	// policy sentinel value with no meaningful timestamp) — check Locked,
	// not LockedAt, to tell whether the account is locked.
	LockedAt *time.Time `json:"lockedAt,omitempty"`
}

// UserInput is the payload for creating or updating a user. Password is only
// set on creation; use SetPassword (RFC 3062) for changes.
type UserInput struct {
	UID       string `json:"uid"`
	CN        string `json:"cn"`
	SN        string `json:"sn"`
	GivenName string `json:"givenName,omitempty"`
	Mail      string `json:"mail,omitempty"`
	Password  string `json:"password,omitempty"`
}
