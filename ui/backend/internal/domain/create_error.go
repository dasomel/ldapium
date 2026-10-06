package domain

// CreateState says what a failed two-step user creation left in the
// directory.
type CreateState string

const (
	// CreateRolledBack: the password step failed and the entry this request
	// created was removed again. Nothing remains; retrying is safe.
	CreateRolledBack CreateState = "rolled_back"
	// CreatePartial: the entry was created, the password step failed, and
	// the entry could not be proven to be this request's and removed. It is
	// still in the directory. Whether the password was applied is NOT known
	// (a lost response can hide a success), so nothing is promised about the
	// password or about being able to bind.
	CreatePartial CreateState = "partial"
	// CreateIdentityChanged: right after Add the entry was not verifiably
	// the one this request created and had not been touched by anyone else
	// (other creator or modifier, modified since creation, replaced, or the
	// identity could not be read). The password step was NOT attempted and
	// nothing was deleted; the entry belongs to someone else or is unverified.
	CreateIdentityChanged CreateState = "identity_changed"
	// CreateUnknown: the compensating delete was sent but its outcome could
	// not be observed (lost response), so the entry may or may not remain.
	CreateUnknown CreateState = "unknown"
)

// CreateError is returned by CreateUser when the entry was added but the
// password step failed. DN is the entry's DN (the same value a successful
// create returns); it is only meant to be surfaced for CreatePartial.
type CreateError struct {
	State CreateState
	DN    string
	// Err is the password-step failure, already mapped to a domain error.
	Err error
}

// Error is fixed text per state: the wrapped cause (directory diagnostics,
// which can contain DNs) is available through Unwrap for server-side logs
// only and is never part of the message.
func (e *CreateError) Error() string {
	switch e.State {
	case CreateRolledBack:
		return "user not created: setting the password failed"
	case CreateIdentityChanged:
		return "user entry was not verifiably created by this request; password not set and nothing deleted"
	case CreateUnknown:
		return "user created but the password step failed and removing the entry could not be confirmed"
	}
	return "user created but the password step failed and the entry could not be safely removed"
}

func (e *CreateError) Unwrap() error { return e.Err }
