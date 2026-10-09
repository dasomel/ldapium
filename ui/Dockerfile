#
# No `# syntax=docker/dockerfile:1` directive here, deliberately — the same
# rule the server image follows (see image/Dockerfile). That directive makes
# every build resolve and pull a remote Dockerfile frontend before doing any
# work; observed stalling this build past 10 minutes once its cached frontend
# image was no longer available locally. Nothing in this file needs BuildKit
# syntax (no RUN --mount, no COPY --link, no heredocs), so it buys nothing —
# and without it the image also builds on an air-gapped host.

# --- frontend build -----------------------------------------------------
FROM node:26-alpine@sha256:aadf416b2cdce311a8811ba3f0608a61b77dbf997500e2eafe781b51f6a0b019 AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
# Vite's outDir (../backend/web/dist, see vite.config.ts) lands the build
# directly where the Go embed directive below expects it.
RUN npm run build

# --- backend build --------------------------------------------------------
FROM golang:1.27.2-alpine@sha256:85dc1069ac644ea3c527b177303a406eb3358192816cd7f9e5848eb658851673 AS backend
WORKDIR /src/backend
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
# Overwrite the placeholder dist/ with the real frontend build before
# go:embed picks it up.
COPY --from=frontend /src/backend/web/dist ./web/dist
# COPY of a directory copies its *contents* and creates the destination
# directory itself as 0755, discarding the source dir's mode (--chown only
# changes the owner). So the 0700 secrets dir must be copied as a child of a
# copied parent (/out/ldapium -> /var/lib/ldapium) to keep its mode; the Go
# side (internal/config/secrets.go) rejects anything but a private 0700 dir.
RUN mkdir -p /out/ldapium/secrets && chmod 700 /out/ldapium/secrets
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

# --- final image ------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS final
ARG APP_VERSION=development
ENV APP_VERSION=${APP_VERSION}
COPY --from=backend /out/server /server
COPY --from=backend --chown=65532:65532 /out/ldapium /var/lib/ldapium
# Numeric, not `USER nonroot:nonroot`. Kubernetes' runAsNonRoot check rejects
# a named user it cannot resolve to a uid ("image has non-numeric user
# (nonroot), cannot verify user is non-root"). 65532 is distroless's nonroot,
# confirmed from this image's own /etc/passwd.
USER 65532:65532
VOLUME ["/var/lib/ldapium/secrets"]
EXPOSE 8080

# The binary checks itself: this image has no shell and no curl, so a
# HEALTHCHECK has nothing else to call. Kubernetes ignores this and uses the
# chart's httpGet probes instead; it exists for `docker run` and docker
# compose, where the UI otherwise reports no health at all.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/server", "-healthcheck"]

ENTRYPOINT ["/server"]

# Opt-in backup-capable runtime. Default final target remains distroless.
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f AS backup-runtime
RUN apt-get update && apt-get install -y --no-install-recommends python3 ldap-utils rclone ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 65532 ldapium && useradd -u 65532 -g 65532 -M ldapium
COPY --from=backend /out/server /server
COPY --from=backend --chown=65532:65532 /out/ldapium /var/lib/ldapium
COPY backend/backup-tools/ /opt/ldapium/backup-tools/
ENV BACKUP_WORKER_PATH=/opt/ldapium/backup-tools/backup_worker.py
ENV BACKUP_PYTHON=/usr/bin/python3
ENV LDAPTLS_REQCERT=demand
USER 65532:65532
VOLUME ["/var/lib/ldapium/secrets"]
EXPOSE 8080
ENTRYPOINT ["/server"]

FROM final AS default
