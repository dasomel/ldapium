package httpapi

import (
	"net/http"
	"sort"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/metrics"
)

// metricsKey carries the active Recorder in the Echo context so the envelope
// builder, which only sees an echo.Context, can count API errors.
const metricsKey = "ldapium_metrics"

// EnableMetrics turns the process metrics on and returns the handler that
// serves them. cmd/server mounts it on its own listener (METRICS_ADDR); it is
// never registered on this server's router, so the public port cannot expose
// it (D218-10). Call it once, after New and before serving: the label sets are
// closed over the routes and error codes registered by then. Until it is
// called a no-op recorder is in place and nothing is collected.
func (s *Server) EnableMetrics(sessions func() int) http.Handler {
	routes := make([]string, 0, len(s.echo.Routes()))
	for _, r := range s.echo.Routes() {
		routes = append(routes, r.Path)
	}
	codes := make([]string, 0, len(codeTable))
	for code := range codeTable {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	options := metrics.Options{Routes: routes, Codes: codes, Sessions: sessions}
	if s.machine != nil && s.machine.revocation != nil {
		options.Revocation = func() (bool, uint64, uint64) {
			status := s.machine.revocation.status()
			return status.Ready, status.Successes, status.Failures
		}
	}
	reg := metrics.New(options)
	s.metrics = reg
	return reg.Handler()
}

// Recorder is the active recorder, for wiring the directory observer in main.
func (s *Server) Recorder() metrics.Recorder { return s.rec() }

// rec is the active recorder; a Server built without New (tests) has none.
func (s *Server) rec() metrics.Recorder {
	if s.metrics == nil {
		return metrics.Nop{}
	}
	return s.metrics
}

// metricsMiddleware is outermost so it also sees what Recover turns into an
// error response. The route label is Echo's matched pattern (c.Path()), never
// the request path; Registry maps anything unregistered to "unmatched".
func (s *Server) metricsMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			rec := s.rec()
			c.Set(metricsKey, rec)
			rec.InFlight(1)
			defer rec.InFlight(-1)
			start := time.Now()
			err := next(c)
			if err != nil {
				// Settle the response (the error handler writes it) so the
				// status below is the one the client sees.
				c.Error(err)
			}
			rec.ObserveHTTP(c.Path(), c.Request().Method, c.Response().Status, time.Since(start))
			return nil
		}
	}
}

func recorderOf(c echo.Context) metrics.Recorder {
	if r, ok := c.Get(metricsKey).(metrics.Recorder); ok {
		return r
	}
	return metrics.Nop{}
}

// handlePublicMetrics answers GET /metrics and /metrics/ on the public port
// with the 404 envelope. Without it the SPA fallback would return index.html
// with a 200, which scanners and health checks misread as "metrics are on"
// (D218-10). The real endpoint lives on the separate METRICS_ADDR listener.
func (s *Server) handlePublicMetrics(c echo.Context) error {
	return writeAPIError(c, http.StatusNotFound, codeNotFound, "not found", nil)
}
