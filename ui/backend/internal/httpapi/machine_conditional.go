package httpapi

import (
	"net/http"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/labstack/echo/v4"
)

// machineIfMatch is the D218-14/B3 write prerequisite. D25: keep the
// human parser unchanged; machine writes cannot opt out with a wildcard.
// Cost: callers must reread after conflicts. Escape hatch: disable writes.
// T-013 wires this only after all write gates have passed independent review.
func machineIfMatch(c echo.Context) (string, error) {
	values := c.Request().Header.Values("If-Match")
	if len(values) == 0 || (len(values) == 1 && values[0] == "") {
		return "", apiErr(http.StatusPreconditionRequired, codeIfMatchRequired, "If-Match is required for machine writes")
	}
	if len(values) != 1 {
		return "", machineInvalidIfMatch()
	}
	csn, ok := domain.CSNFromETag(values[0])
	if !ok {
		return "", machineInvalidIfMatch()
	}
	return csn, nil
}

func machineInvalidIfMatch() error {
	return apiErr(http.StatusBadRequest, codeInvalidRequest, "invalid If-Match: expected one strong entryCSN entity-tag")
}
