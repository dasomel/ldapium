.DEFAULT_GOAL := help

KUBE_NAMESPACE ?=
KUBE_RELEASE ?=

.PHONY: help local-init local-up local-down local-logs local-credentials frontend-dev k8s-credentials k8s-ui-forward check licenses sbom

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

k8s-ui-forward: ## Forward the deployed UI to http://127.0.0.1:8080 for Vite
	@command -v kubectl >/dev/null 2>&1 || { echo "kubectl not found on PATH" >&2; exit 1; }
	@target=$$(./scripts/get-credentials.sh --ui-service $(if $(KUBE_NAMESPACE),--namespace $(KUBE_NAMESPACE))) || exit 1; \
	ns=$${target%%/*}; svc=$${target#*/}; \
	echo "Forwarding svc/$$svc in namespace $$ns to http://127.0.0.1:8080"; \
	kubectl -n "$$ns" port-forward "svc/$$svc" 8080:8080

check: ## Run everything CI runs, in the same order
	@# Frontend first: ui/backend/web embeds the built SPA, so the Go module
	@# does not compile until ui/frontend has been built at least once.
	@cd ui/frontend && npm run lint && npm run build
	@cd ui/backend && test -z "$$(gofmt -l .)" || { echo "gofmt would reformat files in ui/backend" >&2; exit 1; }
	@cd ui/backend && go vet ./... && go test ./... && go build ./...
	@helm lint charts/openldap
	@./scripts/check-versions.sh
	@shellcheck -s sh image/entrypoint.sh
	@shellcheck scripts/*.sh
	@shellcheck charts/openldap/files/tests/*.sh
	@./scripts/licenses.sh --check

licenses: ## Regenerate THIRD-PARTY-LICENSES.md from the dependency tree
	@./scripts/licenses.sh

sbom: ## Write SBOMs for the local images to ./sbom (requires syft)
	@command -v syft >/dev/null 2>&1 || { echo "syft not found: https://github.com/anchore/syft" >&2; exit 1; }
	@mkdir -p sbom
	@version=$$(awk '/^version:/ { print $$2; exit }' charts/openldap/Chart.yaml); \
	for image in openldap-suite openldap-suite-ui; do \
		ref="ghcr.io/dasomel/$$image:$$version"; \
		echo "syft $$ref"; \
		syft "$$ref" -o spdx-json > "sbom/$$image.spdx.json"; \
		syft "$$ref" -o cyclonedx-json > "sbom/$$image.cdx.json"; \
	done
	@echo "wrote sbom/ — released images carry the same SBOM as a signed attestation:"
	@echo "  gh attestation verify oci://ghcr.io/dasomel/openldap-suite:<version> --repo dasomel/openldap-suite"
