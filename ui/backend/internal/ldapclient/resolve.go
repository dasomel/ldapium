package ldapclient

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// LooksLikeDN reports whether input already appears to be a distinguished
// name (as opposed to a bare uid) by attempting to parse it as one. This
// governs whether the login form's identifier field is used directly as a
// bind DN or resolved via BuildUserFilter first.
func LooksLikeDN(input string) bool {
	if !strings.Contains(input, "=") {
		return false
	}
	_, err := ldap.ParseDN(input)
	return err == nil
}

// BuildUserFilter substitutes uid into filterTemplate (which must contain
// exactly one "%s"), escaping uid per RFC 4515 so it cannot inject
// additional filter clauses. It returns an error if filterTemplate has no
// placeholder or uid is empty.
func BuildUserFilter(filterTemplate, uid string) (string, error) {
	if uid == "" {
		return "", fmt.Errorf("uid must not be empty")
	}
	if !strings.Contains(filterTemplate, "%s") {
		return "", fmt.Errorf("user search filter template %q has no %%s placeholder", filterTemplate)
	}
	escaped := ldap.EscapeFilter(uid)
	return fmt.Sprintf(filterTemplate, escaped), nil
}
