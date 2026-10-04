package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/dasomel/ldapium/ui/backend/internal/appprofile"
	"github.com/labstack/echo/v4"
)

func (s *Server) handleListMethods(c echo.Context) error {
	return c.JSON(200, map[string]any{"methods": s.profiles.Templates()})
}
func (s *Server) handlePutMethod(c echo.Context) error {
	if err := requireProfileWrite(c); err != nil {
		return err
	}
	match := c.Request().Header.Get("If-Match")
	rev, err := strconv.ParseUint(strings.Trim(match, `"`), 10, 64)
	if err != nil || match != profileETag(rev) {
		return echo.NewHTTPError(428, "method revision ETag required")
	}
	d := json.NewDecoder(http.MaxBytesReader(c.Response(), c.Request().Body, 32<<10))
	d.DisallowUnknownFields()
	var t appprofile.Template
	if d.Decode(&t) != nil {
		return echo.NewHTTPError(400, "invalid integration method JSON")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return echo.NewHTTPError(400, "trailing JSON")
	}
	if t.ID != c.Param("method") || t.Revision != 0 {
		return echo.NewHTTPError(400, "method id mismatch or server-owned revision")
	}
	if err = t.Validate(); err != nil {
		return echo.NewHTTPError(422, err.Error())
	}
	t, err = s.profiles.PutTemplate(t, rev)
	if errors.Is(err, appprofile.ErrConflict) {
		return echo.NewHTTPError(412, "method changed; reload before saving")
	}
	if err != nil {
		return echo.NewHTTPError(500, "could not persist method")
	}
	log.Printf("application_method_saved actor=%q id=%q revision=%d request_id=%q", currentSession(c).DN, t.ID, t.Revision, requestIDOf(c))
	c.Response().Header().Set("ETag", profileETag(t.Revision))
	return c.JSON(200, t)
}
