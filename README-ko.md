# ldapium

Kubernetes에서 사용할 수 있는 OpenLDAP 기반 디렉터리 스택입니다. OpenLDAP 2.6을 업스트림 소스에서 직접 빌드한 서버 이미지, 관리 UI, Helm chart를 하나의 프로젝트로 제공합니다.

English | **한국어**

[![CI](https://github.com/dasomel/ldapium/actions/workflows/ci.yml/badge.svg)](https://github.com/dasomel/ldapium/actions/workflows/ci.yml)
[![CodeQL](https://github.com/dasomel/ldapium/actions/workflows/codeql.yml/badge.svg)](https://github.com/dasomel/ldapium/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/dasomel/ldapium/badge)](https://scorecard.dev/viewer/?uri=github.com/dasomel/ldapium)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![OpenLDAP](https://img.shields.io/badge/OpenLDAP-2.6.15-informational)](https://www.openldap.org/)

> **상태: prototype**. 패키징이 이 프로젝트의 핵심이고 공개된 곳에서 판단받는 편이 낫기 때문에 일부러 일찍 공개했습니다. 이 README의 모든 내용은 실제로 실행 중인 환경에서 확인했지만, 아직 작성자 외의 누구도 실행해 보지 않았습니다. 이 문단을 믿는 대신 아래의 `helm test`로 설치를 직접 확인할 수 있습니다. 알려진 제한 사항은 [CHANGELOG.md](CHANGELOG.md)를 참고하세요.

> **Registry 안내:** 두 이미지와 OCI chart의 GitHub Release/GHCR package는 `0.1.0`, `0.1.1`, `0.2.0`, `0.2.1`에 대해 존재합니다. 설치할 버전은 "공급망"의 attestation 명령 등으로 직접 확인하십시오.

## 프로젝트 목적

기존 OpenLDAP 컨테이너와 Kubernetes chart는 최신 OpenLDAP 버전, ARM64 지원, 지속적인 유지보수, 관리 UI, 재현 가능한 Helm 배포를 한 번에 제공하기 어려웠습니다.

ldapium은 이 문제를 다음 구성으로 해결합니다.

- 업스트림 OpenLDAP 소스 직접 빌드(현재 2.6.15 LTS). 베이스 이미지 패키지에 딸려 오는 버전이 아니라 버전을 직접 고정합니다.
- `linux/amd64` 및 `linux/arm64` 지원(에뮬레이션이 아닌 네이티브 runner로 빌드하고, 베이스 계층의 보안 수정이 릴리스를 기다리지 않도록 주기적으로 재빌드)
- 기본 샘플 데이터 없음
- 기본 관리자 비밀번호 없음
- Kubernetes용 Helm chart
- 선택 가능한 관리 UI
- 단독 Docker Compose 실행
- 다중 제공자 replication
- 백업과 설치 검증용 `helm test`

## 구성 요소

런타임 경계, HA 토폴로지 및 Helm/Compose 배포 차이는
[아키텍처 가이드](docs/architecture.md)를 참고하십시오.

| 경로 | 설명 |
|---|---|
| `image/` | 업스트림 소스에서 빌드한 OpenLDAP 2.6.15 서버 이미지. overlay: `memberof`, `refint`, `ppolicy`, `unique`, `syncprov`. 백엔드 `back-mdb`, OpenSSL TLS, Cyrus SASL |
| `ui/` | DIT 브라우저, 사용자/그룹 관리, 비밀번호 설정 UI. 기본은 LDAP bind 로그인이며, 선택적 Keycloak SSO는 role로 제한된 전용 LDAP 서비스 계정을 사용합니다. Keycloak service client용 bearer 토큰 접근은 opt-in이며 기본은 읽기 전용이고 쓰기는 별도 스위치입니다(`docs/api.md`) |
| `charts/ldapium/` | 서버를 배포하는 Helm chart. UI는 선택 구성 요소입니다 |

## 설치

두 이미지와 chart는 GHCR에 게시되며 같은 git tag에서 만들어지므로 `0.2.1`은 어디서나 같은 의미입니다. 선택한 버전의 GitHub Release와 GHCR package가 있는지 확인하십시오.

### Kubernetes

```bash
helm install directory oci://ghcr.io/dasomel/charts/ldapium \
  --version 0.2.1 \
  --namespace directory --create-namespace \
  --set auth.adminPassword="$(openssl rand -base64 24)" \
  --set ldap.rootDN='dc=example,dc=org'
```

관리자 비밀번호는 기본값이 없습니다. 이미지가 비밀번호 없이는 기동을 거부하므로 chart도 렌더링을 거부합니다. 셸 히스토리와 `helm get values`에 남기지 않으려면 Secret을 직접 만들고 `auth.existingSecret`으로 지정하십시오.

자주 쓰는 옵션:

```bash
--set replicaCount=3      # N-way multi-provider replication, peer 자동 구성
--set ui.enabled=true     # 관리 UI. 첫 설치에는 --set ui.session.secret="$(openssl rand -base64 48)"도 필요
--set backup.enabled=true # data tree와 cn=config의 정기 dump
```

설치 후에는 다음 명령으로 실제 디렉터리 동작을 확인합니다.

```bash
helm test directory --namespace directory --logs
```

관리자로 bind하여 임시 항목을 만들고 지운 뒤 `memberof` overlay가 실제로 `memberOf`를 채웠는지 검증하며, 복제 설치에서는 항목이 모든 Pod에 도달하는지도 기다립니다. overlay가 빠져도 디렉터리 서버는 정상 기동하므로 이를 알아차릴 수 있는 검사는 이것뿐입니다.

모든 값, replication 설계, 백업/복원 절차와 RPO/RTO, 제자리 업그레이드 가능 범위와 사전 점검, 선택적 Keycloak SSO 설정은 `charts/ldapium/README.md`에 있습니다.

### TLS

`--set tls.enabled=true`와 `tls.crt`/`tls.key`/`ca.crt`를 담은 Secret을 지정하면 636 포트에
LDAPS 리스너가 열리고, 복제도 `ldaps://`로 전환됩니다. 인증서 검증은 엄격하게 동작하므로
알 수 없는 CA나 인증서에 없는 이름으로 접속하면 평문으로 낮아지지 않고 연결이 실패합니다.

`slapd`는 기동 시점에만 키 자료를 읽습니다. 따라서 인증서 갱신은 Secret 갱신 후 Pod 재시작까지가
한 절차이며, `replicaCount > 1`이면 rolling restart로 무중단 처리됩니다. CA 자체를 교체하는
2단계 절차를 포함한 런북은 `charts/ldapium/README.md#tls`에 있습니다.

### 이미지

- `ghcr.io/dasomel/ldapium:0.2.1` — OpenLDAP 서버
- `ghcr.io/dasomel/ldapium-ui:0.2.1` — 관리 UI

두 이미지는 `linux/amd64`와 `linux/arm64`를 대상으로 설계되어 있으며, release workflow가 성공적으로 끝나면 build provenance attestation이 함께 붙습니다.

### Docker Compose

Kubernetes 없이도 사용할 수 있습니다.

```bash
make local-up
make local-credentials
```

`replicaCount: 1`인 chart도 서버를 단독 실행하며(replication 자동 비활성화), 서버/UI 이미지는 Kubernetes를 전제하지 않아 `docker run`으로도 동일하게 동작합니다.

기본적으로 UI는 `http://localhost:8080`(`${UI_PORT}`), LDAP는 `ldap://localhost:389`(`${LDAP_PORT}`)에서 사용할 수 있고, 데이터는 이름 있는 `ldap-config`/`ldap-data` 볼륨에 보존되어 `docker compose down`(`-v` 없이)과 재생성 후에도 남습니다. 관리자 bind DN과 비밀번호는 `./scripts/get-credentials.sh --local`로 확인합니다(비밀번호를 터미널에 출력하며, `--password-only`는 다른 로컬 명령으로 파이프할 때만 사용). 기본 관리자 비밀번호나 세션 시크릿은 어디에도 내장되어 있지 않아 compose도 이를 지정하지 않으면 기동하지 않습니다.

로컬 Keycloak LDAP federation은 `make keycloak-up` 후 `http://127.0.0.1:8180/admin/`에서 확인하며 [로컬 Keycloak 테스트](docs/testing/keycloak-local.md)에 절차가 있습니다. UI를 수정할 때는 Compose를 유지한 채 `make frontend-dev`로 Vite(`http://127.0.0.1:5173`, API는 로컬 8080으로 proxy)를 따로 실행하고, 기존 Helm 배포를 대상으로는 `make k8s-credentials`와 `make k8s-ui-forward`를 사용합니다(`KUBE_NAMESPACE`, `KUBE_RELEASE`로 대상 선택).

Kubernetes 밖에서는 CronJob이 없으므로 `scripts/backup.sh`가 `docker run`/Compose 배포의 백업(data tree + `cn=config`를 `ldapsearch`로 dump, gzip, 보존 기간 정리, 디렉터리 `ou=operations`에 상태 기록)을 맡습니다.

```bash
export LDAP_ADMIN_PASSWORD=...   # 또는 --password-file
./scripts/backup.sh -b dc=example,dc=org -o ./backups
```

## 폐쇄망 설치

이미지, chart, SBOM, checksum은 `scripts/offline-bundle.sh`가 만든 하나의 디렉터리로 옮기고 `scripts/offline-install.sh`로 검증·설치합니다. `imagePullPolicy=Never`이므로 아카이브가 없으면 조용히 pull하지 않고 설치가 실패합니다. 절차는 `docs/air-gap.md`를 참고하십시오.

## 주요 보안 원칙

- 기본 관리자 비밀번호를 제공하지 않습니다.
- 기본 샘플 사용자/그룹을 만들지 않습니다.
- UI는 기본적으로 로그인한 사용자의 LDAP identity로 bind합니다.
- Kubernetes에서는 non-root와 최소 권한 security context를 사용합니다.
- 이미지에는 provenance와 SBOM을 연결할 수 있도록 release workflow가 구성되어 있으며, 확인은 다음 명령으로 합니다.

```bash
gh attestation verify oci://ghcr.io/dasomel/ldapium:0.2.1 --repo dasomel/ldapium
```

- SPDX/CycloneDX SBOM이 각 GitHub Release에 첨부됩니다.
- 의존성과 빌드 도구는 고정되고 강제됩니다. Go 모듈은 `go.sum`으로 검증하고 Actions는 commit SHA로 고정하며 `syft`와 `govulncheck`는 digest/버전으로 고정합니다([docs/dependency-policy.md](docs/dependency-policy.md)).
- 의존성 라이선스는 허용 목록 방식이며 `./scripts/licenses.sh --check`가 CI에서 목록 밖 라이선스나 오래된 [THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md)를 실패시킵니다. Trivy와 CodeQL도 실행됩니다.

## 개발

```bash
make help
make local-init
make local-up
make check
```

자세한 개발 절차는 [CONTRIBUTING.md](CONTRIBUTING.md)를 참고하십시오.

## 문서

- [영문 README](README.md)
- [한국어 README](README-ko.md)
- [한국어 기여 가이드](CONTRIBUTING-ko.md)
- [한국어 변경 기록](CHANGELOG-ko.md)
- [한국어 보안 정책](SECURITY-ko.md)
- [한국어 릴리스 가이드](RELEASING-ko.md)
- [한국어 법률/라이선스 안내](docs/legal-ko.md)
- [docs/ha-profile.md](docs/ha-profile.md) — HA 토폴로지, 장애 모드 표, RPO/RTO
- [docs/migration.md](docs/migration.md) — 단계적 전환, dry-run 조정, 롤백 런북
- [docs/product-boundary.md](docs/product-boundary.md) — 제품 범위, 비목표, 경계 책임
- [docs/pam-boundary.md](docs/pam-boundary.md) — 특권 접근 관리와 credential vault 경계
- [docs/air-gap.md](docs/air-gap.md) — 폐쇄망 설치

## 라이선스

프로젝트 자체의 원본 코드는 Apache-2.0입니다. 배포 이미지에는 OpenLDAP Public License 2.8로 제공되는 OpenLDAP 소프트웨어가 포함됩니다. 자세한 내용은 [NOTICE](NOTICE), [docs/OPENLDAP-PUBLIC-LICENSE-2.8.txt](docs/OPENLDAP-PUBLIC-LICENSE-2.8.txt), [THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md)를 참고하십시오.

OpenLDAP은 OpenLDAP Foundation의 등록 상표입니다. 이 프로젝트는 OpenLDAP Foundation과 제휴, 보증 또는 지원 관계에 있지 않으며 여기서 빌드되는 이미지는 공식 OpenLDAP 릴리스가 아닙니다.
