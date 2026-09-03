.DEFAULT_GOAL := help

KUBE_NAMESPACE ?=
KUBE_RELEASE ?=

.PHONY: help local-init local-up local-down local-logs local-credentials frontend-dev k8s-credentials k8s-ui-forward k8s-audit-export check licenses sbom

help: ## Show local development commands
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z0-9_-]+:.*##/ {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

local-init: ## Create a local .env with generated development credentials
	@if [ -e .env ]; then \
		echo ".env already exists; keeping its credentials unchanged."; \
	else \
		command -v openssl >/dev/null 2>&1 || { echo "openssl is required to generate local credentials." >&2; exit 1; }; \
		umask 077; \
		admin_password=$$(openssl rand -base64 24 | tr -d '\n'); \
		session_secret=$$(openssl rand -base64 48 | tr -d '\n'); \
		printf '%s\n' \
			'# Generated for local development. Never commit this file.' \
			'LDAP_ROOT_DN=dc=example,dc=org' \
			"LDAP_ADMIN_PASSWORD=$$admin_password" \
			"SESSION_SECRET=$$session_secret" > .env; \
		echo "Created .env with generated local credentials."; \
		echo "Run 'make local-up', then 'make local-credentials' to view the admin login."; \
	fi

local-up: local-init ## Start local OpenLDAP and the management UI
	@docker compose up --build -d
	@echo "Management UI: http://localhost:8080"
	@echo "Admin credentials: make local-credentials"

local-down: ## Stop local services without deleting LDAP data volumes
	@docker compose down

local-logs: ## Follow local OpenLDAP and UI logs
	@docker compose logs -f ldap ui

local-credentials: ## Print the local admin bind DN and password
	@./scripts/get-credentials.sh --local

frontend-dev: ## Start Vite on http://127.0.0.1:5173 (requires make local-up)
	@cd ui/frontend && npm run dev

k8s-credentials: ## Print credentials from the deployed OpenLDAP release
	@./scripts/get-credentials.sh $(if $(KUBE_NAMESPACE),--namespace $(KUBE_NAMESPACE)) $(if $(KUBE_RELEASE),--release $(KUBE_RELEASE))

k8s-audit-export: ## Export auditlog + accesslog as unified NDJSON, to stdout
	@./scripts/export-audit-log.sh $(if $(KUBE_NAMESPACE),--namespace $(KUBE_NAMESPACE)) $(if $(KUBE_RELEASE),--release $(KUBE_RELEASE))

k8s-ui-forward: ## Forward the deployed UI to http://127.0.0.1:8080 for Vite
	@command -v kubectl >/dev/null 2>&1 || { echo "kubectl not found on PATH" >&2; exit 1; }
	@target=$$(./scripts/get-credentials.sh --ui-service $(if $(KUBE_NAMESPACE),--namespace $(KUBE_NAMESPACE))) || exit 1; \
	ns=$${target%%/*}; svc=$${target#*/}; \
	echo "Forwarding svc/$$svc in namespace $$ns to http://127.0.0.1:8080"; \
	kubectl -n "$$ns" port-forward "svc/$$svc" 8080:8080

check: ## Run what CI runs, in the same order (minus the registry checks)
	@# Frontend first: ui/backend/web embeds the built SPA, so the Go module
	@# does not compile until ui/frontend has been built at least once.
	@cd ui/frontend && npm run lint && npm run build
	@cd ui/backend && test -z "$$(gofmt -l .)" || { echo "gofmt would reformat files in ui/backend" >&2; exit 1; }
	@cd ui/backend && go vet ./... && go test ./... && go build ./...
	@helm lint charts/ldapium
	@./scripts/check-versions.sh
	@./scripts/check-modules.sh
	@shellcheck -s sh image/entrypoint.sh
	@shellcheck scripts/*.sh scripts/test/*.sh
	@shellcheck charts/ldapium/files/tests/*.sh
	@./scripts/test-incident-evidence.sh
	@./scripts/licenses.sh --check
	@./scripts/check-make-parity.sh
	@# check-make-parity.sh's own comparison regex only matches top-level
	@# scripts/*.sh invocations in ci.yml, so it cannot see this one — a
	@# script living in a subdirectory (scripts/test/) is outside what that
	@# tool was written to compare. Listed here by hand instead of teaching
	@# the parity checker a new path shape for a single caller.
	@./scripts/test/test-export-audit-log.sh
	@./scripts/test/test-ship-audit-log.sh
	@./scripts/test/test-migration-dryrun.sh
	@cd ui/backend && go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...

licenses: ## Regenerate THIRD-PARTY-LICENSES.md from the dependency tree
	@./scripts/licenses.sh

sbom: ## Write SBOMs for the local images to ./sbom (requires syft)
	@command -v syft >/dev/null 2>&1 || { echo "syft not found: https://github.com/anchore/syft" >&2; exit 1; }
	@mkdir -p sbom
	@version=$$(awk '/^version:/ { print $$2; exit }' charts/ldapium/Chart.yaml); \
	for image in ldapium ldapium-ui; do \
		ref="ghcr.io/dasomel/$$image:$$version"; \
		echo "syft $$ref"; \
		syft "$$ref" -o spdx-json > "sbom/$$image.spdx.json"; \
		syft "$$ref" -o cyclonedx-json > "sbom/$$image.cdx.json"; \
	done
	@echo "wrote sbom/ — released images carry the same SBOM as a signed attestation:"
	@echo "  gh attestation verify oci://ghcr.io/dasomel/ldapium:<version> --repo dasomel/ldapium"
