package domain

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
