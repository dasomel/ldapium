# syntax=docker/dockerfile:1

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
COPY --from=backend /out/server /server
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/server"]
