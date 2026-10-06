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

func (e *CreateError) Error() string {
	if e.State == CreateRolledBack {
		return "user not created: setting the password failed: " + e.Err.Error()
	}
	return "user created but the password step failed and the entry could not be safely removed"
}

func (e *CreateError) Unwrap() error { return e.Err }
