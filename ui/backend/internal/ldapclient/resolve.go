package ldapclient

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
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
// additional filter clauses. It returns an error if filterTemplate does not
// contain exactly one placeholder, cannot form a valid LDAP filter, or uid is
// empty.
func BuildUserFilter(filterTemplate, uid string) (string, error) {
	if uid == "" {
		return "", fmt.Errorf("%w: uid must not be empty", domain.ErrInvalidInput)
	}

	placeholders := 0
	for i := 0; i < len(filterTemplate); i++ {
		if filterTemplate[i] != '%' {
			continue
		}
		if i+1 == len(filterTemplate) {
			return "", fmt.Errorf("%w: user search filter template %q ends with %%", domain.ErrInvalidInput, filterTemplate)
		}
		switch filterTemplate[i+1] {
		case 's':
			placeholders++
		case '%':
			// A literal percent is allowed, but it must not be mistaken for
			// an identity substitution that fmt.Sprintf will ignore.
		default:
			return "", fmt.Errorf("%w: user search filter template %q has unsupported format directive %%%c", domain.ErrInvalidInput, filterTemplate, filterTemplate[i+1])
		}
		i++
	}
	if placeholders != 1 {
		return "", fmt.Errorf("%w: user search filter template %q must contain exactly one %%s placeholder", domain.ErrInvalidInput, filterTemplate)
	}

	escaped := ldap.EscapeFilter(uid)
	filter := fmt.Sprintf(filterTemplate, escaped)
	if _, err := ldap.CompileFilter(filter); err != nil {
		return "", fmt.Errorf("%w: user search filter template %q produces an invalid LDAP filter: %v", domain.ErrInvalidInput, filterTemplate, err)
	}
	return filter, nil
}
