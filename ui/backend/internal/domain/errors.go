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
