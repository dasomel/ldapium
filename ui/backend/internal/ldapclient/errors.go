package ldapclient

import (
	"errors"
	"fmt"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// mapErr translates a go-ldap error into one of the domain sentinel errors
// where a clear mapping exists, so the HTTP layer never needs to import
// go-ldap to interpret a failure. Unrecognized errors are wrapped as-is.
func mapErr(op string, err error) error {
	if err == nil {
		return nil
	}
	var le *ldap.Error
	if errors.As(err, &le) {
		switch le.ResultCode {
		case ldap.LDAPResultInvalidCredentials:
			// For a bind, the server deliberately sends no diagnostic text
			// here (to avoid user enumeration), so le.Err is empty and this
			// falls back to the generic message. For a self-service
			// Password Modify with a wrong current password, some servers
			// do include useful diagnostic text on this same result code —
			// e.g. slapd rejecting a mismatched old password under
			// ppolicy's pwdSafeModify — so it's surfaced when present
			// rather than always discarded.
			if le.Err != nil && le.Err.Error() != "" {
				return fmt.Errorf("%w: %s", domain.ErrInvalidCredentials, le.Err)
			}
			return domain.ErrInvalidCredentials
		case ldap.LDAPResultNoSuchObject:
			return domain.ErrNotFound
		case ldap.LDAPResultEntryAlreadyExists:
			return domain.ErrAlreadyExists
		case ldap.LDAPResultInsufficientAccessRights:
			return domain.ErrPermissionDenied
		case ldap.LDAPResultConstraintViolation, ldap.LDAPResultObjectClassViolation, ldap.LDAPResultInvalidAttributeSyntax:
			return fmt.Errorf("%w: %s", domain.ErrInvalidInput, le.Err)
		}
	}
	return fmt.Errorf("ldap %s: %w", op, err)
}
