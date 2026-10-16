# 기여 가이드

ldapium은 OpenLDAP 자체를 fork하거나 수정하는 프로젝트가 아니라, 업스트림 OpenLDAP을 Kubernetes와 컨테이너 환경에서 재현 가능하게 패키징하는 프로젝트입니다. LDAP 동작 자체의 수정은 [OpenLDAP](https://www.openldap.org/) 업스트림에 기여하는 것을 원칙으로 합니다.

English | **한국어**

## 프로젝트의 주요 원칙

- **기본 인증 정보 금지**: 이미지, Helm chart, Compose 모두 추측 가능한 기본 비밀번호로 시작하지 않습니다.
- **샘플 데이터 금지**: 초기 디렉터리에는 base DN과 관리자 계정 외의 예제 사용자를 넣지 않습니다.
- **실측 우선**: 문서와 주석에는 실제로 확인한 내용과 실패했던 접근을 남깁니다.
- **권한 최소화**: UI는 기본적으로 로그인한 사용자의 LDAP identity로 bind하며 자체 서비스 계정이 없습니다. 예외는 SSO 경로뿐이며, 토큰에는 bind에 쓸 비밀번호가 없기 때문입니다. `cn=config` 접근이 필요한 기능은 어떤 UI 세션도 가질 수 없는 권한 수준이므로 이 프로젝트에 맞지 않습니다.

## 로컬 환경

```sh
make help
make local-init
make local-up
make local-credentials
```

`local-init`은 관리자 비밀번호와 세션 시크릿을 고정값으로 배포하는 대신 새로 생성하므로 개발 환경에도 기본 인증 정보가 없습니다. `.env`를 직접 작성한다면 필요한 항목은 `.env.example`에 있습니다.

프론트엔드 작업은 다음과 같이 실행합니다.

```sh
make frontend-dev
```

## PR 전 검증

`make check`는 CI가 실행하는 검사를 같은 순서로 실행합니다. `scripts/check-make-parity.sh`가 `make check`와 CI 양쪽에서 실행되어 둘이 어긋나면 실패합니다. 의도된 예외는 레지스트리에 접근하는 `scripts/check-base-images.sh`와 kubeconform 바이너리가 필요한 `scripts/verify-chart-schema.sh`입니다. `make check`에는 네트워크가 필요한 `govulncheck`도 포함됩니다.

```sh
make check
```

개별적으로 실행할 경우(Makefile의 `check` 타깃이 기준입니다):

```sh
# 프론트엔드를 먼저 빌드합니다. ui/backend/web이 빌드된 SPA를 embed하므로
# 한 번은 실행해야 Go 모듈이 컴파일됩니다.
cd ui/frontend && npm ci && npm run lint && npm run build
cd ui/backend  && gofmt -l . && go vet ./... && go vet -tags live ./... && go test ./... && go build ./...
helm lint charts/ldapium
./scripts/check-versions.sh
./scripts/check-modules.sh
shellcheck -s sh image/entrypoint.sh
shellcheck scripts/*.sh scripts/test/*.sh charts/ldapium/files/tests/*.sh
./scripts/test-incident-evidence.sh
./scripts/licenses.sh --check
./scripts/check-make-parity.sh
# 그 외 Makefile의 check 타깃에 나열된 ./scripts/test/test-*.sh 단계
cd ui/backend && go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...
```

`image/`를 변경했다면 단순히 `docker build` 성공만 확인하지 말고 실제 컨테이너 부팅까지 검증하고 PR에 관찰 결과를 남깁니다.

## Kubernetes 통합 검증

```sh
kind create cluster --name dev
docker build -t ldapium:dev image
kind load docker-image ldapium:dev --name dev
helm install directory charts/ldapium --namespace directory --create-namespace \
  --set image.repository=ldapium --set image.tag=dev --set image.pullPolicy=Never \
  --set auth.adminPassword="$(head -c 24 /dev/urandom | base64)" --wait
helm test directory --namespace directory --logs
```

## 어디서 무엇이 실행되는가

`make check`와 CI는 의도적으로 겹치지만, 대부분의 `make` 타깃에는 CI 대응이 없고 CI의 대부분에는 로컬 대응이 없습니다. 로컬 전용에는 `make licenses`(`THIRD-PARTY-LICENSES.md` 재생성, CI는 `--check`만 실행), `make sbom`, 로컬 개발 루프(`local-*`, `frontend-dev`, `k8s-credentials`, `k8s-ui-forward`, 선택적 JMeter 부하 프로파일은 `docs/scale-benchmarks.md`)가 있습니다. 반대로 CI에만 있는 단계는 kind 클러스터가 필요한 e2e workflow 전체(설치, TLS, upgrade, backup/restore, replication chaos, metrics, security, UI 브라우저, API, machine auth/write, Keycloak federation, SSSD), 레지스트리가 필요한 `base-images`, kubeconform, hadolint/CodeQL/Scorecard/Trivy, 게시된 이미지를 대상으로 하는 검사, 릴리스 workflow입니다. 전체 표는 영문 [CONTRIBUTING.md](CONTRIBUTING.md)의 "What runs where"를 참고하십시오.

## 커밋

[Conventional Commits](https://www.conventionalcommits.org/)를 사용합니다.

예:

사용 중인 scope는 `image`, `ui`, `chart`, `scripts`, `ci`, `docs`입니다.

```text
fix(ui): sizeLimitExceeded를 자식 항목 존재로 처리
feat(chart): backup status를 directory에 기록
fix(image): replication cold start election 수정
```

## 보안 이슈

보안 취약점은 공개 issue로 등록하지 말고 [SECURITY.md](SECURITY.md)의 비공개 신고 절차를 사용하십시오.
