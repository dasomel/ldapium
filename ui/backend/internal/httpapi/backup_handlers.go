package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/dasomel/ldapium/ui/backend/internal/backup"
	"github.com/labstack/echo/v4"
)

func (s *Server) StartBackground(ctx context.Context) {
	if s.backups != nil {
		s.backups.Start(ctx)
	}
}
func (s *Server) backupRoutes(api *echo.Group) {
	g := api.Group("/v1/backups", s.requireBackupAdmin)
	g.GET("", func(c echo.Context) error {
		v := s.backups.View()
		c.Response().Header().Set("ETag", profileETag(v.Policies.Revision))
		return c.JSON(200, v)
	})
	g.PUT("/policies", s.handleBackupPolicies)
	g.PUT("/connections", s.handleBackupConnection)
	g.DELETE("/connections/:id", s.handleBackupConnection)
	g.POST("/jobs/:kind", s.handleBackupRun)
}
func (s *Server) requireBackupAdmin(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if s.backups == nil {
			return echo.NewHTTPError(404, "backups disabled")
		}
		sess := currentSession(c)
		if sess != nil {
			for _, dn := range s.cfg.BackupAdminDNs {
				if sess.DN == dn {
					return next(c)
				}
			}
		}
		return echo.NewHTTPError(403, "backup administrator required")
	}
}
func (s *Server) handleBackupPolicies(c echo.Context) error {
	if err := requireProfileWrite(c); err != nil {
		return err
	}
	raw := c.Request().Header.Get("If-Match")
	revision, err := strconv.ParseUint(strings.Trim(raw, `"`), 10, 64)
	if err != nil || raw != profileETag(revision) {
		return echo.NewHTTPError(428, "policy revision ETag required")
	}
	var p backup.Policies
	decoder := json.NewDecoder(http.MaxBytesReader(c.Response(), c.Request().Body, 16<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&p) != nil {
		return echo.NewHTTPError(400, "invalid backup policy JSON")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || p.Revision != 0 {
		return echo.NewHTTPError(400, "revision is server-managed; one JSON object required")
	}
	saved, err := s.backups.Save(p, revision)
	if errors.Is(err, backup.ErrConflict) {
		return echo.NewHTTPError(412, "backup policies changed; reload")
	}
	if errors.Is(err, backup.ErrBusy) {
		return echo.NewHTTPError(409, "backup already running")
	}
	if err != nil {
		return echo.NewHTTPError(422, "invalid policy or persistence unavailable; reload and check configuration")
	}
	log.Printf("backup_policy_saved actor=%q revision=%d", currentSession(c).DN, saved.Revision)
	c.Response().Header().Set("ETag", profileETag(saved.Revision))
	return c.JSON(200, saved)
}
func (s *Server) handleBackupRun(c echo.Context) error {
	if err := requireProfileWrite(c); err != nil {
		return err
	}
	// D32: job input is only the fixed kind; no commands, files or destinations
	// come from this request. Worker runs saved policy with operator-owned secrets.
	if c.Request().ContentLength > 0 {
		return echo.NewHTTPError(400, "job body must be empty")
	}
	if err := s.backups.Run(context.Background(), c.Param("kind")); err != nil {
		if errors.Is(err, backup.ErrBusy) {
			return echo.NewHTTPError(409, "backup already running")
		}
		return echo.NewHTTPError(422, "kind/source unavailable or status persistence failed")
	}
	log.Printf("backup_started actor=%q kind=%q", currentSession(c).DN, c.Param("kind"))
	return c.JSON(202, map[string]string{"status": "running", "kind": c.Param("kind")})
}

func (s *Server) handleBackupConnection(c echo.Context) error {
	if err := requireProfileWrite(c); err != nil {
		return err
	}
	raw := c.Request().Header.Get("If-Match")
	revision, err := strconv.ParseUint(strings.Trim(raw, `"`), 10, 64)
	if err != nil || raw != profileETag(revision) {
		return echo.NewHTTPError(428, "backup revision ETag required")
	}
	if c.Request().Method == http.MethodDelete {
		err = s.backups.DeleteConnection(c.Param("id"), revision)
	} else {
		var connection backup.Connection
		decoder := json.NewDecoder(http.MaxBytesReader(c.Response(), c.Request().Body, 32<<10))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&connection) != nil {
			return echo.NewHTTPError(400, "invalid connection JSON")
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			return echo.NewHTTPError(400, "one JSON object required")
		}
		err = s.backups.SaveConnection(connection, revision)
	}
	if errors.Is(err, backup.ErrConflict) {
		return echo.NewHTTPError(412, "backup settings changed; reload")
	}
	if errors.Is(err, backup.ErrBusy) {
		return echo.NewHTTPError(409, "backup already running")
	}
	if err != nil {
		return echo.NewHTTPError(422, err.Error())
	}
	log.Printf("backup_connection_changed actor=%q method=%s", currentSession(c).DN, c.Request().Method)
	view := s.backups.View()
	c.Response().Header().Set("ETag", profileETag(view.Policies.Revision))
	return c.JSON(200, view)
}
