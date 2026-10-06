package domain

import "errors"

// Sentinel errors the LDAP layer maps its provider-specific errors onto, so
// the HTTP layer can translate them to status codes without importing an
// LDAP library.
var (
	ErrNotFound           = errors.New("entry not found")
	ErrAlreadyExists      = errors.New("entry already exists")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrPermissionDenied   = errors.New("permission denied")
	ErrInvalidInput       = errors.New("invalid input")
	// ErrConflict is for operations that are individually valid but
	// conflict with the current state of the directory in a way that
	// isn't "already exists" -- e.g. moving a non-leaf entry, which
	// OpenLDAP rejects until its children are moved or removed first.
	ErrConflict = errors.New("operation conflicts with current directory state")
)

// Errors the keyset listing (ListUsersPage/ListGroupsPage) reports. They stay
// distinct so the HTTP layer can give each its own status and machine code
// instead of a generic 500.
var (
	// ErrSizeLimitExceeded: the directory's own size limit (olcSizeLimit,
	// counted over the TOTAL of a paged search) stopped the scan. Never a
	// partial page.
	ErrSizeLimitExceeded = errors.New("directory size limit reached")
	// ErrScanLimitExceeded: the scan examined more than the per-request
	// candidate ceiling.
	ErrScanLimitExceeded = errors.New("scan limit exceeded")
	// ErrScanTimeout: the per-request or per-chunk deadline ran out.
	ErrScanTimeout = errors.New("scan timed out")
	// ErrBusy: another listing on the same session still holds the single
	// paged-search slot, and this request's deadline ran out waiting.
	ErrBusy = errors.New("another listing is in progress on this session")
)
