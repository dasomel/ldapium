# 기여 가이드

ldapium은 OpenLDAP 자체를 fork하거나 수정하는 프로젝트가 아니라, 업스트림 OpenLDAP을 Kubernetes와 컨테이너 환경에서 재현 가능하게 패키징하는 프로젝트입니다. LDAP 동작 자체의 수정은 [OpenLDAP](https://www.openldap.org/) 업스트림에 기여하는 것을 원칙으로 합니다.

English | **한국어**

## 프로젝트의 주요 원칙

- **기본 인증 정보 금지**: 이미지, Helm chart, Compose 모두 추측 가능한 기본 비밀번호로 시작하지 않습니다.
- **샘플 데이터 금지**: 초기 디렉터리에는 base DN과 관리자 계정 외의 예제 사용자를 넣지 않습니다.
- **실측 우선**: 문서와 주석에는 실제로 확인한 내용과 실패했던 접근을 남깁니다.
- **권한 최소화**: UI는 기본적으로 로그인한 사용자의 LDAP identity로 동작합니다. SSO 경로에서만 별도 LDAP 서비스 계정을 사용합니다.

## 로컬 환경

```sh
make help
make local-init
make local-up
make local-credentials
```

프론트엔드 작업은 다음과 같이 실행합니다.

```sh
make frontend-dev
```

## PR 전 검증

```sh
make check
```

개별적으로 실행할 경우:

```sh
cd ui/frontend && npm ci && npm run lint && npm run build
cd ui/backend  && gofmt -l . && go vet ./... && go test ./...
helm lint charts/ldapium
shellcheck -s sh image/entrypoint.sh && shellcheck scripts/*.sh
./scripts/check-versions.sh
./scripts/licenses.sh --check
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

## 커밋

[Conventional Commits](https://www.conventionalcommits.org/)를 사용합니다.

예:

```text
fix(ui): sizeLimitExceeded를 자식 항목 존재로 처리
feat(chart): backup status를 directory에 기록
fix(image): replication cold start election 수정
```

## 보안 이슈

보안 취약점은 공개 issue로 등록하지 말고 [SECURITY.md](SECURITY.md)의 비공개 신고 절차를 사용하십시오.
