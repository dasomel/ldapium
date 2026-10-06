package httpapi

import (
	"log"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// Conditional writes (#216): a write may carry If-Match with the strong ETag
// (the entry's entryCSN) the client last read. The condition is enforced by
// slapd inside the write itself (assertion control, see
// ldapclient/assertion.go), never by a read-then-write here, so there is no
// window in which a concurrent edit slips through.
//
// Opt-in only: no header means exactly the old unconditional behavior.
//
// Errors go through the single envelope (errors.go): a stale tag is
// domain.ErrRevisionConflict, mapped by domainStatus to 412 revision_conflict.

// ifMatchCSN extracts the revision condition of a write. It returns "" for
// "no condition": the header is absent, or it is "*" (RFC 9110: the entry
// must exist, which an unconditional write against a missing entry already
// reports as 404). Anything that is not exactly one quoted strong entryCSN
// tag (weak tags, lists, unquoted or malformed values, repeated headers) is
// a 400 so a typo can never silently become an unconditional write.
func ifMatchCSN(c echo.Context) (string, error) {
	values := c.Request().Header.Values("If-Match")
	switch {
	case len(values) == 0:
		return "", nil
	case len(values) > 1:
		return "", errInvalidIfMatch()
	case values[0] == "*":
		return "", nil
	}
	csn, ok := domain.CSNFromETag(values[0])
	if !ok {
		return "", errInvalidIfMatch()
	}
	return csn, nil
}

// rejectIfMatch refuses If-Match on an operation that cannot honor it: the
// RFC 3062 Password Modify extended operation has no way to carry a control,
// so accepting the header would be a silent no-op.
func rejectIfMatch(c echo.Context) error {
	if len(c.Request().Header.Values("If-Match")) == 0 {
		return nil
	}
	return echo.NewHTTPError(http.StatusBadRequest, "If-Match is not supported for password changes")
}

func errInvalidIfMatch() error {
	return echo.NewHTTPError(http.StatusBadRequest, "invalid If-Match: expected one strong entity-tag as returned in etag/ETag, or *")
}

// respondCreateFailure reports a user creation whose password step did not
// complete (see ldapclient/create_compensation.go for what each state
// guarantees), through the single envelope.
//
// rolled_back: the entry is gone and a retry is safe. It is a plain envelope
// (the status/code follow the password-step cause: invalid_request for a
// policy rejection, forbidden, else internal) whose text starts "user not
// created"; the directory's own text passes the same allowlist filter as every
// other 4xx (publicDomainMessage), so a ppm "Password for dn=..." diagnostic
// never reaches the response. Every other state is 500 partial_failure with
// the entry's dn (what a 201 would have carried: the one deliberate DN in an
// error body, the caller needs it to clean up), a state, and the static text.
// Directory text only goes to the log, escaped and bounded.
func respondCreateFailure(c echo.Context, ce *domain.CreateError, uid string) error {
	reqID := requestIDOf(c)
	fp := fingerprintIdentity(uid)
	if ce.State == domain.CreatePartial {
		log.Printf("user_create_partial request_id=%s uid_fp=%s cause=%s", logQuote(reqID), fp, logDetail(ce.Err))
		return writeAPIErrorExt(c, http.StatusInternalServerError, codePartialFailure, "", ce, string(ce.State), ce.DN)
	}

	log.Printf("user_create_rolled_back request_id=%s uid_fp=%s cause=%s", logQuote(reqID), fp, logDetail(ce.Err))
	if status, code, sentinel, ok := domainStatus(ce.Err); ok {
		msg, _ := publicDomainMessage(sentinel, ce.Err)
		return writeAPIError(c, status, code, "user not created: "+msg, ce.Err)
	}
	return writeAPIError(c, http.StatusInternalServerError, codeInternal, "", ce.Err)
}
