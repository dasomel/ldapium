package httpapi

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/openldap-suite/ui/backend/internal/domain"
)

// respondErr maps a domain/validation error to an HTTP status and a small
// JSON body, so handlers never construct echo.HTTPError by hand and the
// mapping lives in exactly one place.
func respondErr(c echo.Context, err error) error {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, domain.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, domain.ErrAlreadyExists):
		status = http.StatusConflict
	case errors.Is(err, domain.ErrInvalidCredentials):
		status = http.StatusUnauthorized
	case errors.Is(err, domain.ErrPermissionDenied):
		status = http.StatusForbidden
	case errors.Is(err, domain.ErrInvalidInput):
		status = http.StatusBadRequest
	}
	return c.JSON(status, map[string]string{"error": err.Error()})
}
