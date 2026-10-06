package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// Keyset ("cursor") mode of GET /api/users and GET /api/groups
// (docs/changes/api-cursor-pagination). A request with none of limit, cursor,
// q or sort is the legacy listing and is answered exactly as before.

const (
	defaultPageLimit = 50
	maxPageLimit     = 200 // same ceiling as GET /api/audit/actions
	maxPageQRunes    = 64
)

// listRequestTimeout bounds a whole keyset request, including the wait for the
// session's single paged-search slot. A var so tests can shorten it.
var listRequestTimeout = 30 * time.Second

// validationError reports which request field was rejected. The field name is
// the whole message: the rejected value is never echoed back.
type validationError struct{ field string }

func (e validationError) Error() string { return "invalid " + e.field }

// Error messages of the keyset mode. size_limit_exceeded names the three ways
// out so a caller is not left guessing (REQ-013).
const (
	msgInvalidCursor = "invalid cursor"
	msgSizeLimit     = "directory size limit reached; narrow with q, use an identity exempt from the limit, or ask the operator to set LDAP_PAGED_TOTAL_LIMIT (ldap.limits.pagedTotal)"
	msgScanLimit     = "too many candidate entries to scan; narrow the listing with q"
)

// pagedModeRequested is true when any keyset parameter is present, even with
// an empty value, so a typo such as `?limit=` fails loudly instead of quietly
// returning the legacy 5000-entry body.
func pagedModeRequested(c echo.Context) bool {
	params := c.QueryParams()
	for _, k := range []string{"limit", "cursor", "q", "sort"} {
		if _, ok := params[k]; ok {
			return true
		}
	}
	return false
}

// listPageRequest is a validated keyset request plus what is needed to mint
// the next cursor.
type listPageRequest struct {
	query    domain.PageQuery
	resource string
	key      []byte
	binding  string
}

// parseListPage validates the keyset parameters. Errors are validationError
// (422) or errCursorInvalid (400), both turned into responses by respondPageErr.
func (s *Server) parseListPage(c echo.Context, resource, defaultSort string) (listPageRequest, error) {
	limit := defaultPageLimit
	if raw, ok := c.QueryParams()["limit"]; ok {
		n, err := strconv.Atoi(raw[0])
		if err != nil || n < 1 || n > maxPageLimit {
			return listPageRequest{}, validationError{"limit"}
		}
		limit = n
	}
	if sortBy := c.QueryParam("sort"); sortBy != "" && sortBy != defaultSort {
		return listPageRequest{}, validationError{"sort"}
	}
	q, ok := normalizeQ(c.QueryParam("q"))
	if !ok {
		return listPageRequest{}, validationError{"q"}
	}

	key := cursorKey([]byte(s.cfg.SessionSecret))
	req := listPageRequest{
		query:    domain.PageQuery{Limit: limit, Q: q},
		resource: resource,
		key:      key,
		binding:  s.requestCursorBinding(c, key),
	}
	if token := c.QueryParam("cursor"); token != "" {
		pos, err := decodeCursor(key, token, resource, q, req.binding)
		if err != nil {
			return listPageRequest{}, err
		}
		req.query.After = &pos
	}
	return req, nil
}

// normalizeQ trims q and enforces the D215-2 limits: valid UTF-8, at most 64
// characters, no control characters. Filter metacharacters are legal; the
// LDAP layer escapes them.
func normalizeQ(raw string) (string, bool) {
	q := strings.TrimSpace(raw)
	if !utf8.ValidString(q) || utf8.RuneCountInString(q) > maxPageQRunes {
		return "", false
	}
	for _, r := range q {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	return q, true
}

// listContext derives the keyset request's deadline from the HTTP request, so
// a client that goes away also ends the directory work.
func listContext(c echo.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(c.Request().Context(), listRequestTimeout)
}

func (s *Server) handleListUsersPage(c echo.Context) error {
	req, err := s.parseListPage(c, "users", "uid")
	if err != nil {
		return respondPageErr(c, err)
	}
	ctx, cancel := listContext(c)
	defer cancel()
	page, err := currentSession(c).Bound.ListUsersPage(ctx, s.cfg.BaseDN, req.query)
	if err != nil {
		return respondPageErr(c, err)
	}
	next, err := nextCursor(req, page.HasMore, page.Next)
	if err != nil {
		return respondErr(c, err)
	}
	if page.Users == nil {
		page.Users = []domain.User{}
	}
	return c.JSON(http.StatusOK, userPageResponse{Users: page.Users, HasMore: page.HasMore, NextCursor: next})
}

func (s *Server) handleListGroupsPage(c echo.Context) error {
	req, err := s.parseListPage(c, "groups", "cn")
	if err != nil {
		return respondPageErr(c, err)
	}
	ctx, cancel := listContext(c)
	defer cancel()
	page, err := currentSession(c).Bound.ListGroupsPage(ctx, s.cfg.BaseDN, req.query)
	if err != nil {
		return respondPageErr(c, err)
	}
	next, err := nextCursor(req, page.HasMore, page.Next)
	if err != nil {
		return respondErr(c, err)
	}
	if page.Groups == nil {
		page.Groups = []domain.Group{}
	}
	return c.JSON(http.StatusOK, groupPageResponse{Groups: page.Groups, HasMore: page.HasMore, NextCursor: next})
}

// nextCursor mints the cursor for the position the scan last selected. It is
// empty unless more entries exist.
func nextCursor(req listPageRequest, hasMore bool, next *domain.PagePosition) (string, error) {
	if !hasMore || next == nil {
		return "", nil
	}
	return encodeCursor(req.key, req.resource, req.query.Q, req.binding, *next)
}

// respondPageErr is the one place keyset errors become responses; every one
// goes through the shared envelope builder. Nothing derived from an LDAP
// diagnostic is put in a body: the texts below are fixed, and the cause only
// reaches the (bounded, quoted) log line of 5xx responses.
func respondPageErr(c echo.Context, err error) error {
	var ve validationError
	switch {
	case errors.As(err, &ve):
		return writeAPIError(c, http.StatusUnprocessableEntity, codeValidationFailed, ve.Error(), nil)
	case errors.Is(err, errCursorInvalid):
		return writeAPIError(c, http.StatusBadRequest, codeCursorInvalid, msgInvalidCursor, nil)
	case errors.Is(err, domain.ErrSizeLimitExceeded):
		return writeAPIError(c, http.StatusUnprocessableEntity, codeSizeLimitExceeded, msgSizeLimit, nil)
	case errors.Is(err, domain.ErrScanLimitExceeded):
		return writeAPIError(c, http.StatusUnprocessableEntity, codeScanLimitExceeded, msgScanLimit, nil)
	case errors.Is(err, domain.ErrScanTimeout):
		return writeAPIError(c, http.StatusServiceUnavailable, codeScanTimeout, "", err)
	case errors.Is(err, domain.ErrBusy):
		c.Response().Header().Set(echo.HeaderRetryAfter, "2")
		return writeAPIError(c, http.StatusServiceUnavailable, codeUnavailable, "", err)
	case errors.Is(err, context.Canceled):
		// The client hung up; nobody is left to read a body.
		return c.NoContent(499)
	}
	return respondErr(c, err)
}
