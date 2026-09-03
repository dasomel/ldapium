package httpapi

import (
	"errors"
	"log"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// respondErr maps a domain/validation error to an HTTP status and a small
// JSON body, so handlers never construct echo.HTTPError by hand and the
// mapping lives in exactly one place.
//
// The six mapped cases below are deliberately curated, user-facing
// messages (validation feedback, "not found", etc.) and are safe to
// return verbatim. Anything that falls through to the default 500 is, by
// definition, a failure this code didn't anticipate — most commonly a raw
// *ldap.Error or a dial error surfacing connection details (host, port,
// even in-flight TLS/network diagnostics). That text is never sent to the
// client: it's logged server-side instead, tagged with the same request
// ID the access-log line for this request carries, so an operator can
// still find it without the client (or an attacker on an unauthenticated
// path like /login) learning anything about the directory's network
// topology.
func respondErr(c echo.Context, err error) error {
	switch {
	case errors.Is(err, domain.ErrNotFound):
		return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
	case errors.Is(err, domain.ErrAlreadyExists):
		return c.JSON(http.StatusConflict, map[string]string{"error": err.Error()})
	case errors.Is(err, domain.ErrConflict):
		return c.JSON(http.StatusConflict, map[string]string{"error": err.Error()})
	case errors.Is(err, domain.ErrInvalidCredentials):
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
	case errors.Is(err, domain.ErrPermissionDenied):
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	case errors.Is(err, domain.ErrInvalidInput):
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	reqID := c.Response().Header().Get(echo.HeaderXRequestID)
	log.Printf("internal error [%s] %s %s: %v", reqID, c.Request().Method, c.Path(), err)
	return c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal error", "requestId": reqID})
}
