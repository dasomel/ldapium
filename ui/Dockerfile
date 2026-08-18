#
# No `# syntax=docker/dockerfile:1` directive here, deliberately — the same
# rule the server image follows (see image/Dockerfile). That directive makes
# every build resolve and pull a remote Dockerfile frontend before doing any
# work; observed stalling this build past 10 minutes once its cached frontend
# image was no longer available locally. Nothing in this file needs BuildKit
# syntax (no RUN --mount, no COPY --link, no heredocs), so it buys nothing —
# and without it the image also builds on an air-gapped host.

# --- frontend build -----------------------------------------------------
FROM node:22-alpine AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
# Vite's outDir (../backend/web/dist, see vite.config.ts) lands the build
# directly where the Go embed directive below expects it.
RUN npm run build

# --- backend build --------------------------------------------------------
FROM golang:1.25-alpine AS backend
WORKDIR /src/backend
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
# Overwrite the placeholder dist/ with the real frontend build before
# go:embed picks it up.
COPY --from=frontend /src/backend/web/dist ./web/dist
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

# --- final image ------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS final
ARG APP_VERSION=development
ENV APP_VERSION=${APP_VERSION}
COPY --from=backend /out/server /server
# Numeric, not `USER nonroot:nonroot`. Kubernetes' runAsNonRoot check rejects
# a named user it cannot resolve to a uid ("image has non-numeric user
# (nonroot), cannot verify user is non-root"). 65532 is distroless's nonroot,
# confirmed from this image's own /etc/passwd.
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/server"]
