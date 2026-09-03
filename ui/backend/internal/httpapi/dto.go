package httpapi

import "github.com/dasomel/ldapium/ui/backend/internal/domain"

// userListResponse and groupListResponse wrap list results with a
// truncated flag so a listing cut off at ldapclient's maxListResults is
// always visible to the caller instead of looking like a complete result.
type userListResponse struct {
	Users     []domain.User `json:"users"`
	Truncated bool          `json:"truncated"`
}

type groupListResponse struct {
	Groups    []domain.Group `json:"groups"`
	Truncated bool           `json:"truncated"`
}

type passwordPolicyListResponse struct {
	Policies []domain.PasswordPolicy `json:"policies"`
}

// serverSettingsResponse only includes settings useful for directory
// administration. Connection hosts, certificate paths, and session secrets
// remain server-only infrastructure details.
type serverSettingsResponse struct {
	ApplicationVersion string       `json:"applicationVersion"`
	OpenLDAPVersion    string       `json:"openLdapVersion"`
	OSSVersions        []ossVersion `json:"ossVersions"`
	PasswordHash       string       `json:"passwordHash"`
	PasswordPolicy     bool         `json:"passwordPolicy"`
	UniqueAttributes   []string     `json:"uniqueAttributes"`
	LoadedModules      []string     `json:"loadedModules"`
	ActiveOverlays     []string     `json:"activeOverlays"`
	BaseDN             string       `json:"baseDn"`
	UserSearchBase     string       `json:"userSearchBase"`
	UserCreateBase     string       `json:"userCreateBase"`
	GroupSearchBase    string       `json:"groupSearchBase"`
	GroupCreateBase    string       `json:"groupCreateBase"`
	ConnectionSecurity string       `json:"connectionSecurity"`
	TLSVerified        bool         `json:"tlsVerified"`
	SessionTTLSeconds  int64        `json:"sessionTtlSeconds"`
	CookieSecure       bool         `json:"cookieSecure"`
}

type ossVersion struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// loginRequest is the POST /api/login body. Identity is either a full DN
// or a bare uid resolved server-side per LDAP_USER_SEARCH_FILTER.
type loginRequest struct {
	Identity string `json:"identity"`
	Password string `json:"password"`
}

type meResponse struct {
	DN string `json:"dn"`
}

type authConfigResponse struct {
	Mode string `json:"mode"`
}

type ldapHealthResponse struct {
	Reachable bool `json:"reachable"`
}

type logoutResponse struct {
	RedirectURL string `json:"redirectURL,omitempty"`
}

type userRequest struct {
	DN                 string `json:"dn,omitempty"`
	UID                string `json:"uid,omitempty"`
	CN                 string `json:"cn"`
	SN                 string `json:"sn"`
	GivenName          string `json:"givenName,omitempty"`
	Mail               string `json:"mail,omitempty"`
	Password           string `json:"password,omitempty"`
	Department         string `json:"department,omitempty"`
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizationalUnit,omitempty"`
}

type groupRequest struct {
	DN          string `json:"dn,omitempty"`
	CN          string `json:"cn"`
	Description string `json:"description,omitempty"`
}

type setPasswordRequest struct {
	DN string `json:"dn"`
	// OldPassword is required for self-service changes and forwarded as-is
	// to the RFC 3062 Password Modify operation; it is left empty when an
	// administrator resets another user's password. Whether it's actually
	// required is a directory policy decision (ppolicy's pwdSafeModify),
	// not something this handler enforces.
	OldPassword string `json:"oldPassword,omitempty"`
	Password    string `json:"password,omitempty"`
}

type unlockRequest struct {
	DN string `json:"dn"`
}

type lockRequest struct {
	DN string `json:"dn"`
}

type memberRequest struct {
	GroupDN  string `json:"groupDn"`
	MemberDN string `json:"memberDn"`
}

type moveEntryRequest struct {
	DN          string `json:"dn"`
	NewParentDN string `json:"newParentDn"`
}

type setPasswordResponse struct {
	GeneratedPassword string `json:"generatedPassword,omitempty"`
}

type createdResponse struct {
	DN string `json:"dn"`
}
