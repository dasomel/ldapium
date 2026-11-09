# Change: serve the management UI under a context path

- Change class: `C` (UI/API surface, session and SSO cookie scope)
- Related issue: #462
- Status: `Implemented` (PR pending)

## Problem

The UI only works at the origin root. Behind a shared ingress or reverse proxy
(`https://host/ldapium/`) every absolute path breaks: the backend routes
`/api`, `/llms.txt` and the SPA at `/`, the session cookie is `Path=/`, the SSO
cookie `Path=/api/sso`, SSO redirects and the logout URI are built as
`origin + "/..."`, and the frontend fetches `/api/...`, navigates to
`/api/sso/start` and runs `BrowserRouter` without a basename.

## Decisions

- **D1 — explicit runtime setting `UI_BASE_PATH`** (chart: `ui.basePath`).
  Empty or `/` = root (today's behaviour, byte-for-byte). Otherwise normalized
  to a leading `/`, no trailing `/`; each segment `[A-Za-z0-9._~-]+`, `.`/`..`
  rejected; invalid values fail startup like the other settings. Not derived
  from `X-Forwarded-Prefix`: a client-controlled header must not decide cookie
  scope or redirect targets. Cost: the prefix is configured once in the chart.
- **D2 — the backend serves the prefix itself; no ingress rewrite.** An echo
  `Pre` middleware strips the prefix before routing, so route registration,
  `isAPIPath`, the origin gate and the SPA fallback are unchanged. With a
  prefix set: `<prefix>` → `308` to `<prefix>/`; any path outside the prefix →
  the existing 404 JSON envelope. The match is exact and case-sensitive:
  only `<prefix>` or `<prefix>/…` is stripped (`<prefix>x` is outside), for
  every method (HEAD included); the `308` keeps the method. Everything after
  `Pre` — origin gate, `headPreMiddleware`, `isAPIPath`, metrics labels, route
  matching — sees the unprefixed path, which is why they need no change; a
  prefixed write (`POST <prefix>/api/...`) still passes through the origin
  gate. Any `Location` the backend builds from a path gets the prefix back
  through one helper (`s.url(path)`). The separate metrics listener is
  unaffected. Nested prefixes on one host (`/a` and `/a/b`) are unsupported:
  the outer session cookie would be sent to the inner app.
  Escape hatch: unset `UI_BASE_PATH` and front it with a rewriting proxy.
- **D3 — one image for every prefix.** Vite builds with `base: './'` (dev
  server keeps `/`). The backend reads the embedded `index.html` once at
  startup and injects, right after `<head>`:
  `<base href="<prefix>/">` and `<meta name="ldapium-base-path" content="<prefix>">`
  (content empty at root). The base element makes `./assets/...` resolve on
  deep links (`<prefix>/users/x`). index.html is served from that cached copy
  on every SPA fallback. `public/` references in index.html (`/favicon.svg`)
  are rewritten by Vite to `./favicon.svg`; JS chunks and CSS `url()` are
  emitted relative to their own file. The build output is checked for any
  remaining root-absolute `/assets/` or `/favicon` reference.
- **D4 — frontend reads the prefix from the meta tag** through one helper
  (`src/lib/base-path.ts`: `basePath()` and `withBase(path)`). Callers:
  `lib/api.ts` (`/api${path}`), `lib/app-profiles.ts`, `lib/backups.ts`,
  `lib/api-docs.ts` (openapi fetch and both curl builders, whose base URL
  becomes `origin + basePath`), `pages/LoginPage.tsx` (SSO start, 3 places),
  `pages/ApiDocsPage.tsx` (openapi.json and llms.txt links, displayed base
  URL), `components/api-docs/EndpointCard.tsx`; `BrowserRouter
  basename={basePath()}`. The server-supplied logout URL is already absolute.
  Router-internal `/...` paths stay as they are (resolved against basename).
- **D5 — cookie scope follows the prefix**: session `Path=<prefix>/`, SSO login
  cookie `Path=<prefix>/api/sso`; every Set-Cookie that clears them (logout,
  SSO callback success and failure) uses the same Path, or the browser keeps
  the old cookie. Two UIs under sibling prefixes on one host keep separate
  sessions. Root keeps `/` and `/api/sso`.
- **D6 — SSO and logout URLs carry the prefix**: callback
  `origin + prefix + /api/sso/callback` (the IdP client's redirect URI must be
  registered with the prefix — documented), post-login `prefix + /`, errors
  `prefix + /login?sso_error=…`, post-logout `prefix + /login?sso_logged_out=1`.
  The origin itself is still chosen by the existing `requestOrigin` /
  `SSO_CALLBACK_ORIGINS` allowlist (forwarded host/proto only from trusted
  proxies, unchanged); `CORS_ALLOWED_ORIGINS` stays origin-only.
- **D7 — OpenAPI**: `/api/v1/meta` returns `openapi: <prefix>/api/v1/openapi.json`;
  the served `openapi.json` gets `servers[0].url = <prefix>` (no trailing
  slash: OpenAPI appends each path, `/api/...`, to the server URL) when a
  prefix is set; the embedded file stays `/`.
- **D8 — chart**: `ui.basePath` → `UI_BASE_PATH`; liveness/readiness probes
  use `<basePath>/api/auth/config`; `NOTES.txt` prints the path; the template
  fails rendering when `ui.basePath` is invalid or an ingress path does not
  start with it.

## Not changed

Route table, auth/session semantics, the metrics listener, CORS/origin
allowlists, Keycloak federation, the server image.

## Verification

- Go unit tests, each at root and with `/ldapium`: config normalization and
  rejections (`ldapium`, `/a/`, `/a//b`, `/a/../b`, `/%2e`, spaces); routing of
  `/ldapium`, `/ldapium/`, `/ldapiumx`, `/`, `/api/...` outside the prefix,
  `/ldapium/api`, `/ldapium/api/`, GET and HEAD; a prefixed cross-origin POST
  still rejected by the origin gate; injected index.html and an asset; cookie
  `Path` on login, logout and SSO set/clear; SSO callback, redirect and logout
  URIs; meta `openapi` and the served `servers[0].url`; root output identical
  to today (routes, cookies, index bytes apart from the injected tags).
- Chart: helm template tests for env, probes, NOTES, invalid basePath and
  mismatched ingress path.
- Browser (Playwright, new `e2e/base-path.spec.ts` against a container with
  `UI_BASE_PATH=/ldapium`): login, sidebar navigation, deep-link reload, asset
  and API requests all under `/ldapium/` (no request to the origin root),
  cookie `Path=/ldapium/`; the existing suite unchanged at root.
- Build check: no root-absolute `/assets/` or `/favicon` in `web/dist`.
