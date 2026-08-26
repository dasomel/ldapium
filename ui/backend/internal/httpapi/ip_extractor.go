package httpapi

import (
	"net"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
)

// ipExtractorFor builds the echo.IPExtractor that c.RealIP() resolves
// through — the client-IP key the login limiter uses (D2/D7) — from
// cfg.TrustedProxies (config.go already validated it).
//
// Echo's own fallback (used whenever Echo#IPExtractor is left unset) takes
// the first X-Forwarded-For entry verbatim, which any client can forge
// arbitrarily; it must never be relied on here. Every mode below is
// explicit about what it trusts instead:
//
//   - "private" (default): echo.ExtractIPFromXFFHeader trusting
//     loopback/link-local/private-network hops. It walks
//     X-Forwarded-For from the right, skipping trusted hops, and returns
//     the first untrusted address — so a public client behind an
//     in-cluster ingress cannot spoof its way to a fresh budget: its real
//     address, appended by the ingress, is reached before anything it
//     supplied. Residual risk: a client whose own real address is itself
//     on a private/loopback/link-local range can still spoof.
//   - a comma-separated CIDR list: echo.ExtractIPFromXFFHeader trusting
//     ONLY the listed CIDRs — deliberately not a superset of "private".
//     Granting loopback/link-local/private-net trust on top would make
//     this mode no stricter than "private" (a private-origin client could
//     still spoof exactly as under "private"), defeating the point of an
//     operator naming their ingress explicitly. This is still safe for
//     direct/port-forward traffic: echo checks RemoteAddr first and
//     returns it untouched whenever it isn't one of the listed CIDRs, so
//     an unlisted peer's X-Forwarded-For is never honored.
//   - "none": echo.ExtractIPDirect(). X-Forwarded-For is ignored
//     entirely and every request keys on the raw TCP peer. Behind any
//     reverse proxy this means every client shares one budget, so an
//     unauthenticated party could exhaust it and lock out unrelated
//     users for a window — only correct with no proxy in front.
func ipExtractorFor(cfg config.Config) echo.IPExtractor {
	switch cfg.TrustedProxies {
	case "none":
		return echo.ExtractIPDirect()
	case "private", "":
		return echo.ExtractIPFromXFFHeader(echo.TrustLoopback(true), echo.TrustLinkLocal(true), echo.TrustPrivateNet(true))
	default:
		var opts []echo.TrustOption
		for _, entry := range strings.Split(cfg.TrustedProxies, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			// config.Load already validated every entry parses; a
			// failure here would mean that validation and this parsing
			// disagree, not that the operator did anything wrong, so
			// skip rather than let a malformed entry crash the server.
			if _, ipNet, err := net.ParseCIDR(entry); err == nil {
				opts = append(opts, echo.TrustIPRange(ipNet))
			}
		}
		return echo.ExtractIPFromXFFHeader(opts...)
	}
}
