# ldapium

Kubernetes에서 사용할 수 있는 OpenLDAP 기반 디렉터리 스택입니다. OpenLDAP 2.6을 업스트림 소스에서 직접 빌드한 서버 이미지, 관리 UI, Helm chart를 하나의 프로젝트로 제공합니다.

English | **한국어**

[![CI](https://github.com/dasomel/ldapium/actions/workflows/ci.yml/badge.svg)](https://github.com/dasomel/ldapium/actions/workflows/ci.yml)
[![CodeQL](https://github.com/dasomel/ldapium/actions/workflows/codeql.yml/badge.svg)](https://github.com/dasomel/ldapium/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/dasomel/ldapium/badge)](https://scorecard.dev/viewer/?uri=github.com/dasomel/ldapium)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![OpenLDAP](https://img.shields.io/badge/OpenLDAP-2.6.15-informational)](https://www.openldap.org/)

> **상태: prototype**. 패키징이 이 프로젝트의 핵심이고 공개된 곳에서 판단받는 편이 낫기 때문에 일부러 일찍 공개했습니다. 이 README의 모든 내용은 실제로 실행 중인 환경에서 확인했지만, 아직 작성자 외의 누구도 실행해 보지 않았습니다. 이 문단을 믿는 대신 아래의 `helm test`로 설치를 직접 확인할 수 있습니다. 알려진 제한 사항은 [CHANGELOG.md](CHANGELOG.md)를 참고하세요.

> **Registry 안내:** 두 이미지와 OCI chart의 GitHub Release/GHCR package는 `0.1.0`, `0.1.1`, `0.2.0`, `0.2.1`, `0.3.0`에 대해 존재합니다. 설치할 버전은 "공급망"의 attestation 명령 등으로 직접 확인하십시오.

## 프로젝트 목적

기존 OpenLDAP 컨테이너와 Kubernetes chart는 최신 OpenLDAP 버전, ARM64 지원, 지속적인 유지보수, 관리 UI, 재현 가능한 Helm 배포를 한 번에 제공하기 어려웠습니다.

ldapium은 이 문제를 다음 구성으로 해결합니다.

- 업스트림 OpenLDAP 소스 직접 빌드(현재 2.6.15 LTS, syncrepl 수정 패치 1건 포함: [image/patches/](image/patches/)). 베이스 이미지 패키지에 딸려 오는 버전이 아니라 버전을 직접 고정합니다.
- `linux/amd64` 및 `linux/arm64` 지원(에뮬레이션이 아닌 네이티브 runner로 빌드하고, 베이스 계층의 보안 수정이 릴리스를 기다리지 않도록 주기적으로 재빌드)
- 기본 샘플 데이터 없음
- 기본 관리자 비밀번호 없음
- Kubernetes용 Helm chart
- 선택 가능한 관리 UI
- 단독 Docker Compose 실행
- 다중 제공자 replication
- 백업과 설치 검증용 `helm test`

## 주요 기능

모두 `main`에 병합된 기능이며 opt-in은 표시했습니다. 각 항목의 링크가 정본 문서이고, 검증 범위는 [docs/IMPLEMENTATION-STATUS.md](docs/IMPLEMENTATION-STATUS.md)에 있습니다.

**Replication / HA**

- N-way multi-provider replication, 매 기동마다 조정: [image/README.md](image/README.md#replication)
- opt-in 전용 읽기 전용 replication 계정과 `scripts/replication-identity.sh`(`ensure`, `retire`, `reconcile`, `rotate`, `rollback-admin`): [docs/migration.md](docs/migration.md)
- opt-in replication 점검 CronJob(`replication.check.*`)과 `LDAPiumReplicationCheckFailed` 알림: [docs/ha-profile.md](docs/ha-profile.md)
- HA 토폴로지 프로필, 장애 모드 표, RPO/RTO: [docs/ha-profile.md](docs/ha-profile.md)

**보안**

- 기본 관리자 비밀번호 없음. 지정하지 않으면 새 단독 서버가 첫 기동 시 무작위 값을 생성하고, UI는 세션 시크릿을 스스로 생성·보존하며, chart는 실제 `helm install`에서 두 Secret을 생성합니다. `scripts/get-credentials.sh`로 확인: [image/README.md](image/README.md)
- `ppolicy`, 기본 거부 ACL, opt-in 익명 읽기 범위 제한(`LDAP_ANONYMOUS_READ_BASE`): [image/README.md](image/README.md#access-control-acl)
- LDAPS/StartTLS(TLS 1.2 하한), opt-in `requireTls`, `disallowAnonBind`, `requireAuthc`: [charts/ldapium/README.md](charts/ldapium/README.md#hardening)
- `auditlog`/`accesslog`(읽기와 bind 포함)와 NDJSON export: [docs/audit-event-schema.md](docs/audit-event-schema.md)
- `userPassword`는 해시 상태로도 HTTP API 응답에 나가지 않음: [AGENTS.md](AGENTS.md)

**백업 / 복원**

- 무결성 manifest를 갖는 정기 백업 CronJob(`backup.enabled`): [charts/ldapium/README.md](charts/ldapium/README.md)
- `scripts/verify-backup.sh`, 빈 대상에 오프라인 복원하는 `scripts/restore.sh`: [docs/migration.md](docs/migration.md)
- Kubernetes 없는 환경용 `scripts/backup.sh`: [README.md](README.md#backups-without-kubernetes)
- opt-in UI 백업 페이지(스케줄, local/S3/FTP/SSH 대상): [ui/README.md](ui/README.md#scheduled-local--s3--ftp--ssh-backups)

**관측성**

- Prometheus exporter sidecar, ServiceMonitor, 알림 규칙, Grafana 대시보드(`metrics.*`): [charts/ldapium/README.md](charts/ldapium/README.md)
- opt-in UI 백엔드 `/metrics`(별도 listener): [docs/ui-operations.md](docs/ui-operations.md)
- `scripts/export-incident-evidence.sh`: 상태/replication/백업의 redact된 스냅샷: [docs/incident-evidence.md](docs/incident-evidence.md)

**관리 UI**

- DIT 브라우저, 사용자/그룹(cursor 페이지네이션, 생성/수정/삭제, 잠금/해제), 비밀번호 변경: [ui/README.md](ui/README.md)
- 운영 작업 이력, 서버 상태, 서버 설정, API 문서 페이지: [ui/README.md](ui/README.md)
- 애플리케이션 SSO 프로필, Keycloak SSO 로그인(opt-in): [docs/auth-provider-policy.md](docs/auth-provider-policy.md)

**HTTP API**

- `/api/v1`, 실행 중인 빌드가 제공하는 OpenAPI 3.1 명세, 단일 오류 봉투: [docs/api.md](docs/api.md)
- 조건부 쓰기(`ETag`/`If-Match`), opt-in `Idempotency-Key`: [docs/api.md](docs/api.md)
- opt-in Keycloak 머신 bearer: 읽기 전용 8개 오퍼레이션, 선택적 토큰 revocation, 별도 스위치의 범위 제한 쓰기(`setPassword` 포함): [docs/machine-auth-operations.md](docs/machine-auth-operations.md)

**클라이언트 / 마이그레이션 / 배포**

- 확인된 클라이언트 경계(SSSD/PAM/nsswitch, Windows/AD, Keycloak 경유 Kubernetes RBAC): [docs/client-compatibility.md](docs/client-compatibility.md)
- PAM/credential vault 경계: [docs/pam-boundary.md](docs/pam-boundary.md)
- 외부 LDAP/AD에서 단계적 전환, dry-run 조정 보고서: [docs/migration.md](docs/migration.md)
- 폐쇄망 번들과 설치: [docs/air-gap.md](docs/air-gap.md)
- 재현 가능한 규모 벤치마크(1M은 CI 규모, 10M 이상은 로컬): [docs/scale-benchmarks.md](docs/scale-benchmarks.md)

## 구성 요소

런타임 경계, HA 토폴로지 및 Helm/Compose 배포 차이는
[아키텍처 가이드](docs/architecture.md)를 참고하십시오.

| 경로 | 설명 |
|---|---|
| `image/` | 업스트림 소스에 syncrepl 패치 1건(#432)을 적용해 빌드한 OpenLDAP 2.6.15 서버 이미지. overlay: `memberof`, `refint`, `ppolicy`, `unique`, `syncprov`. 백엔드 `back-mdb`, OpenSSL TLS, Cyrus SASL |
| `ui/` | DIT 브라우저, 사용자/그룹 관리, 비밀번호 설정 UI. 기본은 LDAP bind 로그인이며, 선택적 Keycloak SSO는 role로 제한된 전용 LDAP 서비스 계정을 사용합니다. Keycloak service client용 bearer 토큰 접근은 opt-in이며 기본은 읽기 전용이고 쓰기는 별도 스위치입니다(`docs/api.md`) |
| `charts/ldapium/` | 서버를 배포하는 Helm chart. UI는 선택 구성 요소입니다 |

## 설치

두 이미지와 chart는 GHCR에 게시되며 같은 git tag에서 만들어지므로 `0.3.0`은 어디서나 같은 의미입니다. 선택한 버전의 GitHub Release와 GHCR package가 있는지 확인하십시오.

### Kubernetes

```bash
helm install directory oci://ghcr.io/dasomel/charts/ldapium \
  --version 0.3.0 \
  --namespace directory --create-namespace \
  --set auth.adminPassword="$(openssl rand -base64 24)" \
  --set ldap.rootDN='dc=example,dc=org'
```

관리자 비밀번호는 기본값이 없습니다. `auth.adminPassword`를 비워 두면 실제 `helm install`이 무작위 값을 release의 관리자 Secret에 생성하고 upgrade 때 `lookup`으로 재사용합니다. 클러스터에 접근하지 않는 오프라인 렌더(`helm template`, `--dry-run=client`, GitOps 컨트롤러)는 Secret을 볼 수 없어 실패합니다. 셸 히스토리와 `helm get values`에 남기지 않으려면 Secret을 직접 만들고 `auth.existingSecret`으로 지정하십시오.

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

- `ghcr.io/dasomel/ldapium:0.3.0` — OpenLDAP 서버
- `ghcr.io/dasomel/ldapium-ui:0.3.0` — 관리 UI

두 이미지는 `linux/amd64`와 `linux/arm64`를 대상으로 설계되어 있으며, release workflow가 성공적으로 끝나면 build provenance attestation이 함께 붙습니다.

### Docker Compose

Kubernetes 없이도 사용할 수 있습니다.

```bash
make local-up
make local-credentials
```

- 단독 실행: `replicaCount: 1`인 chart도 서버를 단독 실행하며(replication 자동 비활성화), 서버/UI 이미지는 Kubernetes를 전제하지 않아 `docker run`으로도 동일하게 동작합니다.

접속 정보와 데이터:

- UI: `http://localhost:8080` (`${UI_PORT}`)
- LDAP: `ldap://localhost:389` (`${LDAP_PORT}`)
- 데이터: 이름 있는 `ldap-config`/`ldap-data` 볼륨에 보존되며 `docker compose down`(`-v` 없이)과 재생성 후에도 남습니다.
- 관리자 bind DN과 비밀번호: `./scripts/get-credentials.sh --local`로 확인합니다. 비밀번호를 터미널에 출력하며, `--password-only`는 다른 로컬 명령으로 파이프할 때만 사용합니다.
- 기본 관리자 비밀번호나 세션 시크릿은 어디에도 내장되어 있지 않습니다. `LDAP_ADMIN_PASSWORD`/`SESSION_SECRET`을 비워 두면 서버가 무작위 관리자 비밀번호를 `ldap-data` 볼륨에 생성하고 UI가 세션 시크릿을 생성·보존합니다. 생성된 비밀번호는 `./scripts/get-credentials.sh --local`로 확인합니다.

개발 도구:

- `make keycloak-up`: 로컬 Keycloak LDAP federation을 `http://127.0.0.1:8180/admin/`에서 확인합니다. 절차는 [로컬 Keycloak 테스트](docs/testing/keycloak-local.md)에 있습니다.
- `make frontend-dev`: Compose를 유지한 채 Vite(`http://127.0.0.1:5173`)를 따로 실행하며, API는 로컬 8080으로 proxy합니다.
- `make k8s-credentials`, `make k8s-ui-forward`: 기존 Helm 배포를 대상으로 합니다. 대상은 `KUBE_NAMESPACE`, `KUBE_RELEASE`로 선택합니다.

Kubernetes 밖에서는 CronJob이 없으므로 `scripts/backup.sh`를 사용합니다.

- 대상: `docker run`/Compose 배포의 백업
- 동작: data tree와 `cn=config`를 `ldapsearch`로 dump하고 gzip 압축, 보존 기간이 지난 파일 정리, 디렉터리 `ou=operations`에 상태 기록

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
gh attestation verify oci://ghcr.io/dasomel/ldapium:0.3.0 --repo dasomel/ldapium
```

- SPDX/CycloneDX SBOM이 각 GitHub Release에 첨부됩니다.
- 의존성과 빌드 도구는 고정되고 강제됩니다. Go 모듈은 `go.sum`으로 검증하고 Actions는 commit SHA로 고정하며 `syft`와 `govulncheck`는 digest/버전으로 고정합니다([docs/dependency-policy.md](docs/dependency-policy.md)).
- 의존성 라이선스는 허용 목록 방식이며 `./scripts/licenses.sh --check`가 CI에서 목록 밖 라이선스나 오래된 [THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md)를 실패시킵니다. Trivy와 CodeQL도 실행됩니다.

## CI 검증 범위

pull request와 `main` push에서 실행되며(일부는 path 필터), mock이 아니라 실제 컨테이너나 kind 클러스터를 대상으로 합니다.

- `e2e.yml`: chart 설치와 `helm test`(단독/3노드), TLS와 인증서 교체, 마이그레이션 dry-run
- `upgrade-e2e.yml`: rolling 업그레이드와 롤백(단독/복제)
- `backup-restore.yml`: 백업, 검증, 손상 점검, 복원, 3노드 삭제 후 복원/재동기화
- `replication-chaos-e2e.yml`: 네트워크 분리, 동일 항목 충돌, 전용 replication 계정
- `security-e2e.yml`: ACL 부정 테스트, LDAP injection, audit/accesslog, chart security context
- `sssd-e2e.yml`, `keycloak-federation-e2e.yml`: SSSD 신원 조회, Keycloak LDAP federation
- `metrics-e2e.yml`, `ui-e2e.yml`: exporter 지표와 알림 규칙, UI 브라우저 회귀
- `machine-keycloak-e2e.yml`, `machine-write-e2e.yml`, `api-credentials-e2e.yml`: 머신 bearer 읽기/쓰기(실제 Keycloak), 생성된 credential과 API 오류 코드
- `offline-bundle.yml`: registry 없는 번들 설치

`release.yml`은 도달 가능한 취약점 스캔, rolling 업그레이드/롤백(단독/복제), 백업 복원과 3노드 복원, 머신 bearer 인증, 머신 쓰기, 생성된 credential + API 오류 코드가 해당 commit에서 모두 성공하지 않으면 tag를 거부합니다.

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

### 문서 색인

| 문서 | 목적 |
|---|---|
| [docs/ADOPTION-GUIDE.md](docs/ADOPTION-GUIDE.md) | 도입 경로와 첫 성공 기준 |
| [docs/IMPLEMENTATION-STATUS.md](docs/IMPLEMENTATION-STATUS.md) | 병합된 기능과 검증 범위 |
| [docs/architecture.md](docs/architecture.md) | 런타임 경계, HA 토폴로지, Helm/Compose 차이 |
| [docs/api.md](docs/api.md) | HTTP API 계약, 머신 bearer 인증 |
| [docs/ui-operations.md](docs/ui-operations.md) | UI 백엔드 운영(metrics, Origin 게이트, 조건부 쓰기, 멱등 키) |
| [docs/auth-provider-policy.md](docs/auth-provider-policy.md) | LDAP bind와 Keycloak SSO, 실패 시 동작 |
| [docs/machine-keycloak-client.md](docs/machine-keycloak-client.md) | 머신 호출용 Keycloak client 설정 |
| [docs/machine-ldap-account.md](docs/machine-ldap-account.md) | 머신 읽기 계정과 읽기 전용 ACL |
| [docs/machine-write-account.md](docs/machine-write-account.md) | 머신 쓰기 계정과 쓰기 ACL |
| [docs/machine-auth-operations.md](docs/machine-auth-operations.md) | 머신 인증 롤백, 긴급 차단, 호환성 |
| [docs/ha-profile.md](docs/ha-profile.md) | HA 토폴로지, 장애 모드, RPO/RTO |
| [docs/migration.md](docs/migration.md) | 단계적 전환, dry-run, 롤백, replication 계정 절차 |
| [docs/air-gap.md](docs/air-gap.md) | 폐쇄망 번들 검증과 설치 |
| [docs/client-compatibility.md](docs/client-compatibility.md) | SSSD, Windows/AD, Keycloak 등 클라이언트 호환 |
| [docs/audit-event-schema.md](docs/audit-event-schema.md) | 신원 감사 이벤트 스키마와 export |
| [docs/incident-evidence.md](docs/incident-evidence.md) | redact된 장애 증거 export |
| [docs/scale-benchmarks.md](docs/scale-benchmarks.md) | 재현 가능한 부하/규모 측정 |
| [docs/encryption-at-rest.md](docs/encryption-at-rest.md) | 저장 시 암호화의 책임 경계 |
| [docs/dependency-policy.md](docs/dependency-policy.md) | 고정, cooling window, 의존성 롤백 |
| [docs/legal-ko.md](docs/legal-ko.md) | 라이선스와 법률 안내 |
| [docs/product-boundary.md](docs/product-boundary.md) | 제품 범위와 비목표 |
| [docs/pam-boundary.md](docs/pam-boundary.md) | PAM/credential vault 경계 |
| [docs/agent-execution-security.md](docs/agent-execution-security.md) | 에이전트 구동 작업용 디렉터리 제어 프로필 |

## 라이선스

프로젝트 자체의 원본 코드는 Apache-2.0입니다. 배포 이미지에는 OpenLDAP Public License 2.8로 제공되는 OpenLDAP 소프트웨어가 포함됩니다. 자세한 내용은 [NOTICE](NOTICE), [docs/OPENLDAP-PUBLIC-LICENSE-2.8.txt](docs/OPENLDAP-PUBLIC-LICENSE-2.8.txt), [THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md)를 참고하십시오.

OpenLDAP은 OpenLDAP Foundation의 등록 상표입니다. 이 프로젝트는 OpenLDAP Foundation과 제휴, 보증 또는 지원 관계에 있지 않으며 여기서 빌드되는 이미지는 공식 OpenLDAP 릴리스가 아닙니다.
