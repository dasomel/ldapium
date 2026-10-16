# 변경 기록

이 문서는 ldapium의 주요 변경 사항을 한국어로 정리합니다. 형식은 [Keep a Changelog](https://keepachangelog.com/ko/1.1.0/)를 따르고 버전은 Semantic Versioning을 사용합니다.

English | **한국어**

하나의 Git tag `vX.Y.Z`가 Helm chart와 두 컨테이너 이미지를 같은 버전으로 배포합니다. `appVersion`은 빌드에 포함되는 OpenLDAP 버전을 의미합니다.

## [0.2.1] — 2026-10-16

유지보수 릴리스입니다. 의존성/베이스 이미지 갱신, 문서 정정 1건, machine 비밀번호 설정(`setPassword`)에 대한 실환경 검증 보강이 전부입니다. 동작이나 설정은 바뀌지 않으며 0.2.0에서의 업그레이드는 이미지/chart 버전 변경만 필요합니다.

### 이미지

- 이미지 빌드의 Go 툴체인을 `golang:1.27.2`로 갱신하고 UI backend 빌더 digest를 다시 고정했습니다.
- UI backend Go 모듈(`go-ldap/ldap/v3` 3.4.15, `prometheus/client_golang` 1.25.0)과 UI frontend 의존성(Radix UI, `vite`, `@playwright/test` 등)을 갱신했습니다.

### 문서

- **machine `setPassword` 재요청 응답 정정 (#417).** 0.2.0 노트와 `docs/api.md`는 이미 비밀번호가 설정된 계정에 대해 409라고 적었지만, 설정이 끝나면 pending 마커가 지워지므로 두 번째 요청은 마커 검사에서 403으로 거절됩니다. 409 `conflict`는 비밀번호는 있는데 정리 실패로 마커가 남은 항목에서만 나옵니다. 동작은 그대로이며 실제 Keycloak 토큰과 UI 이미지로 측정했습니다.
- machine write v2 후속 항목을 마무리했습니다(#417). 인수 기준 AC-005/AC-010 문구를 측정된 동작에 맞췄고, 결정 D417-1(`write-lock.ldif`에 privileged 그룹 `filter=` 보호막 없음)과 D417-2(중첩 privileged 그룹 잠금 위험은 수용, 하위 그룹을 `MACHINE_WRITE_PRIVILEGED_GROUPS`에 명시)를 기록했습니다.

### 릴리스 파이프라인과 CI

- `machine write (real Keycloak)` 릴리스 게이트가 실제 Keycloak 토큰, 환경 변수만으로 구성한 운영 UI 이미지, 실제 slapd로 `setPassword`까지 end-to-end 실행하고 평문/해시 비밀 스캔을 수행합니다(#427).
- release-critical이 아닌 새 job `machine write measurements (E-22, two-provider R-3)`가 매 변경마다 확인-쓰기 구간과 2-provider replication 측정을 반복합니다(#428, #430).
- GitHub Actions 버전을 갱신했습니다(#423).
- 의존성 갱신(#420–#424)은 `docs/dependency-policy.md`의 7일 cooling window가 지나기 전에 0.2.0 릴리스 작업과 함께 병합되었습니다.

## [0.2.0] — 2026-10-14

0.x 단계의 minor 릴리스이며 호환성에 영향을 주는 변경이 있습니다. 전체 항목과 근거는 영문 [CHANGELOG.md](CHANGELOG.md)를 참고하십시오.

### 호환성에 영향을 주는 변경

- **machine `deleteUser`/modrdn 축소 (Q16).** v2c LDAP 규칙을 적용하면 machine `deleteUser`와 modrdn은 `W_data`가 만든 항목에만 도달하고 나머지는 거절됩니다.
- **ppolicy 상태 속성이 본인에게 읽기 전용 (#399, #400).** 사용자는 자기 항목의 `pwdPolicySubentry`, `pwdReset`, `pwdStartTime`, `pwdEndTime`, `pwdAccountLockedTime`을 쓸 수 없습니다. ACL은 bootstrap 시점에만 기록되므로 기존 볼륨은 직접 업그레이드해야 합니다(`image/README.md`의 in-place upgrade).
- **`LDAP_ACCESSLOG_OPS`에 `extended`/`all`이 있으면 이미지가 기동을 거부합니다 (#398).** OpenLDAP 2.6.15 accesslog overlay가 첫 Password Modify에서 slapd를 중단시키기 때문이며 `writes reads bind`를 사용하십시오.
- **`UI_TRUSTED_PROXIES`에 CIDR 목록을 지정하면 목록의 대역만 `X-Forwarded-For`를 신뢰합니다.** 암묵적인 사설망 신뢰에 의존했다면 프록시 CIDR을 모두 명시하십시오(`private`, `none`은 그대로).
- **일부 non-browser 클라이언트에 영향:** `Origin` 헤더가 있는 상태 변경 `/api` 요청은 서버 자신의 origin이 아니면 403 `origin_mismatch`로 거절됩니다. `Origin`이 없는 요청(curl, 스크립트)과 `GET`/`HEAD`/`OPTIONS`는 영향이 없습니다.
- **Users/Groups 목록은 cursor API로 페이지를 넘기고 검색이 서버 측으로 바뀌었습니다 (#253).** 사용자는 `uid`/`cn`/`mail`/`displayName`, 그룹은 `cn`/`description`만 검색하며 전체 개수는 표시하지 않습니다.
- 현재 비밀번호가 틀린 self-service 비밀번호 변경은 `500`이 아니라 `400 current_password_rejected`를 반환합니다(#264). 4xx 메시지에서는 LDAP 진단 문자열을 제거했고 모든 `/api` 오류는 하나의 JSON envelope를 사용합니다.

### API

- **machine `setPassword` (v2c, #379).** `MACHINE_WRITE_ENABLED`와 `MACHINE_WRITE_CRED_ENABLED`가 켜져 있고 client ceiling에 `directory.users.password.write`가 있으면, machine client가 `createUser`에 `credentialPending: true`로 직접 만든 계정의 **초기** 비밀번호를 설정할 수 있습니다. 별도의 `W_cred` identity와 run-time premise 검사를 거치며, unlock은 사람 전용으로 유지됩니다. `W_cred`에는 lockout이 없는 password policy가 필요합니다(Q17).
- machine 그룹/잠금 쓰기(v2b), machine 사용자 쓰기와 LDAP machine-token revocation(#285, #286)은 모두 **기본 꺼짐**인 opt-in입니다.
- Keycloak service account용 machine bearer 인증(#214, 기본 꺼짐)과 `Idempotency-Key`, 조건부 쓰기(`If-Match`), backup job ID(#217), opt-in `/metrics`와 CORS 읽기(#218)가 추가되었습니다. 로그인 limiter의 상태 크기에도 상한을 두었습니다(#270).

### 이미지

- 설정 볼륨은 남았는데 데이터 볼륨이 사라진 경우 모든 모드에서 기동을 거부하고 복구 방법(데이터와 설정 claim을 모두 삭제하면 peer에서 다시 채움)을 안내합니다(#387).
- `LDAP_REPLICATION_IDENTITY`(`admin` 기본 / `prepare` / `dedicated`)로 replication 전용 identity로의 단계적 전환을 지원합니다(#229). 기본값은 동작이 바뀌지 않습니다.
- opt-in `LDAP_PAGED_TOTAL_LIMIT`으로 paged 검색의 총 결과 수 상한을 올릴 수 있습니다(#215).

### Helm chart / CI

- `ui.metrics.enabled`, `ui.machineAuth.write.*` 등 새 값이 추가되었고 모두 기본값은 꺼짐 또는 비어 있음입니다. chart는 write scope를 `allowedClients`에 부여하지 않습니다.
- 무거운 E2E job은 3개의 concurrency lane을 공유합니다.

## [0.1.1] — 2026-09-24

유지보수 릴리스입니다. 의존성/베이스 이미지 갱신과 0.1.0의 공급망 증거 생성을 막던 릴리스 파이프라인 수정이 전부이며, 동작이나 설정은 바뀌지 않습니다. 0.1.0에서의 업그레이드는 이미지/chart 버전 변경만 필요합니다.

- 베이스 이미지(`debian:trixie-slim`, `golang:1.27.1-bookworm`) digest와 UI frontend 의존성을 갱신했습니다.
- 라이선스 게이트가 Go/Node 의존성을 먼저 설치하도록 고쳐, 빈 목록을 생성하고 실패하던 문제를 해결했습니다(#191).
- GitHub Actions를 갱신했습니다(`docker/build-push-action` 7.4.0 포함).
- `main`/schedule/dispatch 실행의 concurrency group을 ref 대신 commit SHA 기준으로 바꿔, 늦게 시작한 이전 커밋의 실행이 HEAD의 E2E를 취소하지 못하게 했습니다. 문서만 바꾼 push는 필수가 아닌 E2E를 시작하지 않으며, 태그될 수 있는 커밋에 결과가 필요한 `ci.yml`, `e2e.yml`, `backup-restore.yml`, `upgrade-e2e.yml`은 매 push마다 실행됩니다.
- 의존성 갱신은 7일 cooling window(`docs/dependency-policy.md`)가 지나기 전에 maintainer 요청으로 병합되었습니다(#192–#195).

## [0.1.0] — 2026-08-18

첫 번째 프로토타입 릴리스입니다.

### 서버 이미지

- OpenLDAP 2.6.14 업스트림 소스를 직접 빌드
- `linux/amd64`, `linux/arm64` 지원
- 기본 샘플 데이터와 기본 관리자 비밀번호 없음
- `memberof`, `refint`, `ppolicy`, `unique`, `syncprov` 등의 overlay 지원
- N-way multi-provider replication 지원
- 대규모 디렉터리를 고려한 paging, size/time limit 및 file descriptor 설정

### 관리 UI

- Go backend + React frontend
- DIT 조회, 사용자/그룹 CRUD, 비밀번호 설정/변경, 계정 잠금 해제
- 로그인한 사용자의 LDAP identity 기반 동작
- 선택적인 Keycloak OIDC SSO + PKCE
- 한국어/영어 UI
- LDAP에서 백업 상태를 직접 조회하는 기능

### Helm chart

- StatefulSet + PVC + Headless Service
- `replicaCount > 1`에서 replication 자동 구성
- 선택적인 UI Deployment
- 디렉터리 백업 CronJob
- 설치 후 `helm test`를 통한 실제 LDAP 동작 검증

### 기타

- Docker Compose 기반 독립 실행
- Kubernetes/Compose 환경에서 credential 조회 스크립트
- 공급망 보안을 위한 provenance/SBOM 구조

### 알려진 제한 사항

- TLS end-to-end 검증이 아직 완료되지 않았습니다.
- 0.1.0은 첫 릴리스이므로 기존 버전에서의 upgrade path를 약속하지 않습니다.
- e2e workflow는 새로 구성되었으므로 독립 환경에서 지속적인 검증이 필요합니다.

[0.2.1]: https://github.com/dasomel/ldapium/releases/tag/v0.2.1
[0.2.0]: https://github.com/dasomel/ldapium/releases/tag/v0.2.0
[0.1.1]: https://github.com/dasomel/ldapium/releases/tag/v0.1.1
[0.1.0]: https://github.com/dasomel/ldapium/releases/tag/v0.1.0
