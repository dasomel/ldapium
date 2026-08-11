package ldapclient

import (
	"errors"
	"fmt"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/openldap-suite/ui/backend/internal/domain"
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
