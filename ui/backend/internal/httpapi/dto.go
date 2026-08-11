package httpapi

// loginRequest is the POST /api/login body. Identity is either a full DN
// or a bare uid resolved server-side per LDAP_USER_SEARCH_FILTER.
type loginRequest struct {
	Identity string `json:"identity"`
	Password string `json:"password"`
}

type meResponse struct {
	DN string `json:"dn"`
}

type userRequest struct {
	DN        string `json:"dn,omitempty"`
	UID       string `json:"uid,omitempty"`
	CN        string `json:"cn"`
	SN        string `json:"sn"`
	GivenName string `json:"givenName,omitempty"`
	Mail      string `json:"mail,omitempty"`
	Password  string `json:"password,omitempty"`
}

type groupRequest struct {
	DN          string `json:"dn,omitempty"`
	CN          string `json:"cn"`
	Description string `json:"description,omitempty"`
}

type setPasswordRequest struct {
	DN       string `json:"dn"`
	Password string `json:"password,omitempty"`
}

type memberRequest struct {
	GroupDN  string `json:"groupDn"`
	MemberDN string `json:"memberDn"`
}

type setPasswordResponse struct {
	GeneratedPassword string `json:"generatedPassword,omitempty"`
}

type createdResponse struct {
	DN string `json:"dn"`
}
