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
)
