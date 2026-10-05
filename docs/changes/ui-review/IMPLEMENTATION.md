
## Navigation order and distinct icons — 2026-10-03

D39 centralizes functional ordering and route icons for desktop/mobile navigation,
including optional local administration pages. Order: tree/users/groups,
applications/Keycloak, health/history/backups/replication/server-settings, test data.
Archive/Network/Fingerprint/Settings2 replace repeated Server icons; permissions use
ShieldCheck. Existing labels, routes and feature-flag visibility are preserved.
Root/integrated production builds passed (existing bundle warning). Real browser
checks on 8080 and 5173 confirmed all 11 expected routes in order and 11 distinct
SVG icons, on desktop and mobile. Local server rebuilt/restarted. Screenshots are
private local artifacts. Independent read-only review result recorded separately.
Review found no ordering/visibility/icon-uniqueness regressions. It additionally
identified a pre-existing mobile-dialog focus issue when resizing to desktop while
open; that unchanged dialog behavior is outside this navigation/icon change.

## UI-matched favicon — 2026-10-03

Replaced prior branch glyph with the same Lucide TerminalSquare paths used by the
console header, retaining the existing favicon background/accent colors. Versioned
favicon URL avoids stale browser caching. Root/integrated builds passed. Browser
checks on 8080/5173 verified the icon link, exact SVG response/MIME and successful
image decode. Initial probe used a relative request URL without baseURL and failed;
absolute URL fixed the verification script. Local server rebuilt/restarted.
