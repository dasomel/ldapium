// Package ldapclient defines the LDAP access boundary used by the HTTP
// layer. Handlers only ever see the Client interface, never a concrete LDAP
// library type, which is what makes them testable with a fake and keeps the
// domain package framework-free.
package ldapclient

import (
	"context"

	"github.com/dasomel/openldap-suite/ui/backend/internal/domain"
)

// Client is a single authenticated LDAP session, bound as one directory
// user. Every method executes as that user, so the directory's own ACLs are
// the sole authorization mechanism — the application never elevates
// privileges beyond what the bound user is permitted.
//
// A Client is not safe for concurrent use; callers must serialize access
// (the session store does this per session).
type Client interface {
	// WhoAmI returns the bound DN.
	WhoAmI() string

	// Close releases the underlying connection. Safe to call more than
	// once.
	Close() error

	// Tree returns the immediate children of parentDN. Pass the
	// configured base DN to list the root.
	Tree(ctx context.Context, parentDN string) ([]domain.TreeNode, error)

	// GetEntry returns the full attribute set of dn.
	GetEntry(ctx context.Context, dn string) (*domain.Entry, error)

	// ListUsers returns all user entries under base.
	ListUsers(ctx context.Context, base string) ([]domain.User, error)
	// CreateUser creates a new user entry under base and, if password is
	// non-empty, sets its initial password via the Password Modify
	// extended operation (RFC 3062).
	CreateUser(ctx context.Context, base string, in domain.UserInput) (string, error)
	// UpdateUser replaces the given attributes on the user at dn.
	UpdateUser(ctx context.Context, dn string, in domain.UserInput) error
	// DeleteUser removes the user entry at dn.
	DeleteUser(ctx context.Context, dn string) error
	// SetPassword changes the password of dn via RFC 3062 Password Modify.
	// When newPassword is empty the server generates one and returns it.
	SetPassword(ctx context.Context, dn, newPassword string) (generated string, err error)

	// ListGroups returns all groupOfNames entries under base.
	ListGroups(ctx context.Context, base string) ([]domain.Group, error)
	// CreateGroup creates a new groupOfNames entry under base.
	CreateGroup(ctx context.Context, base string, in domain.GroupInput) (string, error)
	// UpdateGroup replaces the given attributes on the group at dn.
	UpdateGroup(ctx context.Context, dn string, in domain.GroupInput) error
	// DeleteGroup removes the group entry at dn.
	DeleteGroup(ctx context.Context, dn string) error
	// AddMember adds memberDN to the group's member attribute.
	AddMember(ctx context.Context, groupDN, memberDN string) error
	// RemoveMember removes memberDN from the group's member attribute.
	RemoveMember(ctx context.Context, groupDN, memberDN string) error
}

// Dialer opens a new bound Client, authenticating dn/password via an actual
// LDAP bind. It is the only extension point the HTTP layer needs to log a
// user in; everything else flows through the returned Client.
type Dialer interface {
	Bind(ctx context.Context, dn, password string) (Client, error)
}
