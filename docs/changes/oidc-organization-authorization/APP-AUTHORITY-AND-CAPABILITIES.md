# 범용 앱 권한 연동과 Keycloak 제어 책임 판단

Status: Draft · 2026-10-01 · [Change Package](CHANGE.md)

## 설계 판단

권장안은 LDAPium을 Keycloak의 대체 인가 엔진으로 만들기보다 사용자/그룹 중심의
연동 관리 UI로 확장하는 것이다. Keycloak의 client role/Composite/role mapping을
UI에서 읽고, 명시적으로 위임된 범위에 한해 Admin API로 변경한다. 앱 자원에 대한
실제 허용/거부는 해당 앱 또는 그 앱이 사용하는 인가 서비스가 수행한다.

“앱별 권한은 Keycloak에서 한다”는 표현은 역할 저장·할당·claim 발급 또는 Keycloak
Authorization Services 사용까지는 맞다. 앱이 claim/정책 판단을 강제하지 않으면
Keycloak 역할을 바꾸는 것만으로 repository/project/dashboard 접근이 바뀌지 않는다.
OIDC 로그인은 임의 OSS의 세부 권한 관리 API나 표준 역할 의미를 제공하지 않는다.

이 문서는 기존 CONTROL-PLANE의 역할 원본/자동 투영/외부 중앙 check 기본안과
OSS-PERMISSION-INTEGRATION의 고정 앱 rollout을 재검토하여 아래 단계로 대체한다.
기존 조직 범위와 Grant 단위 평가의 보안 원칙은 필요한 앱 프로파일에 유지한다.

## D15 — 역할 원본은 Keycloak, LDAPium은 위임된 UI

이유: 같은 역할을 DB와 Keycloak 양쪽에서 독립 편집하면 drift와 이중 writer가 생긴다.
비용: KC 장애 시 역할 편집 불가, 실제 version/권한 조회 필요.
탈출 경로: 연결 해제 시 KC 설정을 보존하고 UI를 읽기 전용으로 전환한다.

| 정보 | 단일 원본 | LDAPium 책임 |
|---|---|---|
| 사용자·그룹·직접 멤버십 | LDAP | 기존 domain/service를 통한 관리 |
| client role·Composite·KC 그룹 역할 연결 | Keycloak | read-through, 위임된 Admin API 편집; DB 사본은 비권위 캐시 |
| 로그인·MFA·토큰·KC Authorization Services 정책 | Keycloak | 연결 상태/선택된 설정 조회; 전체 정책 편집 기본 미지원 |
| 앱 내부 자원 ACL | 앱 또는 앱이 채택한 인가 서비스 | native adapter/export를 명시 선택한 경우만 관리 |
| 프로파일·claim 대응·조직→native scope 대응·operation·감사 | LDAPium DB | 연동 메타데이터 관리 |
| LDAPium 자체 조직 범위 정책 | LDAPium | 자체 API에 적용; 외부 앱에 자동 전파한다고 주장하지 않음 |

KC 편집은 특정 connection/realm/client/group/role에 대한 위임을 먼저 검사한다.
DB에는 현재 applied 역할과 별개인 무기한 desired role 원본을 만들지 않는다.
operation에는 편집 의도·기준 외부 상태 fingerprint·실행 결과를 저장할 수 있다.
실행 직전 KC 현재 상태가 달라졌으면 conflict; 부분 변경은 단계별로 표시한다.
KC Admin API에 범용 원자적 compare-and-swap이 있다고 가정하지 않는다.
실행 중 KC 수동 수정 경쟁은 재조회/drift로 검출하며 atomic consistency를 주장하지 않는다.

KC/GitOps가 역할을 관리하는 앱은 external-owner로 설정하여 LDAPium 편집을 막는다.
LDAPium-delegated 앱은 관리 대상으로 표시된 필드만 편집하고 KC 콘솔의 해당 쓰기 권한은
운영 절차/가능한 KC 권한 정책으로 분리한다. 자동 객체 인수와 강제 덮어쓰기는 금지한다.
대상 KC 버전에서 최소 권한 격리가 불가능하면 쓰기를 비활성화하거나 전용 realm을 요구한다.

### 제어 수준

| 수준 | 제공 기능 | 기본값 |
|---|---|---|
| Observe | KC client/roles/groups/claim 및 실제 앱 계약 조회 | 기본 ON |
| Delegate | 승인된 client role 할당/Composite/role mapping 편집 | 앱별 opt-in |
| Configure | client/claim mapper 생성·redirect·secret 관리 | 플랫폼 특권 opt-in; 초기 후속 단계 |
| Native provision | OSS ACL 산출 또는 native API 변경 | adapter별 opt-in, 버전 검증 필요 |
| Central decision | 앱 요청마다 LDAPium check 호출 | 별도 제품 경계 결정과 adapter 강제 검증 후 선택 |

## D16 — OSS 목록이 아닌 capability 기반 프로파일

이유: 앱 이름과 무관하게 지원 프로토콜·claim·native scope가 제각각이다.
비용: generic profile schema와 검증기, 버전별 adapter contract 필요.
탈출 경로: custom 앱은 설정 안내/export만 제공하고 unsupported 기능을 숨기지 않는다.

Narwhal 매트릭스의 13개 앱은 예시 fixture다. 고정 지원 목록·필수 rollout·특정 역할
이름으로 취급하지 않는다. 신규 OSS는 기존 프로파일 등록 또는 새로운 검증된 adapter
추가로 연동하며 LDAPium 핵심 인가 코드에 앱 이름 switch를 추가하지 않는다.

### ApplicationProfile

| 영역 | 필드/의미 |
|---|---|
| 대상 | application ID, instance ID, product/version/edition, owner |
| 인증 | native OIDC / gateway OIDC; client ID, issuer, audience, PKCE, 정확한 redirect |
| 소비 claim | token 종류(ID/access/userinfo), claim path, array/string, full path 여부 |
| 역할 | KC role ID→claim value→native role; role priority/default/deny; 복수 역할 규칙 |
| 범위 | none / app / organization / project / namespace / path / resource |
| 대응 | 조직 ID→native scope ID; 사용자/그룹 ID 대응; 자동 생성 여부 |
| 강제 지점 | native-app / gateway-admission / external-PDP / unknown |
| 관리 | authority(external/delegated), export/direct/read-only, managed fields, secret refs |
| 검증 | adapter/version, configured/observed/tested revision, last evidence, 회수 기한 |

역할 데이터는 KC에서 조회하고 profile은 ID/매핑만 저장한다. 원본 역할 삭제/재생성은
새 ID로 취급해 연결을 자동 승계하지 않는다. 앱 자체 admin 의미와 KC 관리자 역할은
분리한다. role 이름만 같다고 앱 사이에 동일 권한을 부여하지 않는다.

### Capability별 연동 경로

1. OIDC claim→native role: 앱이 해당 필드를 실제 소비하는지 검사하고 매핑 설정/export.
2. native group/project ACL: group claim과 별개로 앱의 native policy 등록 필요.
3. gateway admission-only: 서비스 진입만 제어; 내부 자원/데이터 범위 보장 미지원.
4. Kubernetes 등 기존 외부 인가: binding 산출; LDAPium check로 대체하지 않음.
5. Keycloak Authorization Services: 해당 앱의 enforcement/UMA/resource 모델이 실제
   지원될 때 선택한다. OIDC 연결만으로 자동 지원되지 않는다.
6. LDAPium check: 기존 인가가 없는 앱이 API/adapter를 강제할 때만 별도 선택한다.

처음에는 1/2/3/4의 계약 등록·검사·export를 제공한다. 5/6은 독립 설계 수용 후 진행한다.
Keycloak와 LDAPium을 동시에 동일 요청의 독립 최종 정책 원본으로 설정하지 않는다.
두 서비스가 각각 맡는 단계가 있다면 composition/deny/장애 동작을 명시해야 한다.

## UI와 API 추가/수정

앱 등록 wizard: 인증 방식 선택 → 기존 KC client 연결 → claim/역할 가져오기 →
native role/scope 매핑 → 지원 범위 확인 → 영향 preview → export/위임 실행 → 실제 검증.
어떤 OSS든 제품 이름 대신 capability와 원본 정보를 먼저 선택한다.
커스텀 매핑은 임의 스크립트 실행이 아니라 제한된 schema/template로 표현한다.

| 제안 /api/v1 endpoint | 계약 |
|---|---|
| GET /application-profile-types | capability schema와 지원 adapter 목록 |
| POST /applications | custom 포함 앱 instance 등록 |
| GET/PUT /applications/{id}/integration-profile | 프로파일 schema/authority/지원 범위 검증 |
| GET /applications/{id}/keycloak-roles | KC role/Composite read-through; stale 여부 명시 |
| POST /applications/{id}/keycloak-role-operations | 위임된 role 편집/매핑; 202 operation; 기준 fingerprint |
| POST /applications/{id}/mapping-preview | token/native role/범위 예상 효과와 unsupported 목록 |
| POST /applications/{id}/configuration-exports | native config 산출; 권한 적용 완료로 표시 안 함 |
| POST /applications/{id}/integration-verify | 해당 adapter의 bounded 실제 allow/deny 검증 |

기존 /applications/{id}/roles는 독립 DB role CRUD가 아니라 KC-backed facade로 재정의한다.
기존 permission-mappings는 claim/native 변환 메타데이터에만 해당한다.
DB revision의 If-Match는 KC의 원자성을 보장하지 않는다. 외부 상태 기준도 별도 검사한다.
커스텀 adapter 서버 upload/원격 코드 실행/Keycloak arbitrary proxy는 지원하지 않는다.

## 범용 추가 계획과 수용 기준

| 단계 | 작업 | 수용 기준 |
|---|---|---|
| G0 책임 확정 | 제품 경계·KC authority·DB metadata·optional PDP 정리 | 동일 객체/요청에 정책 원본 두 개 없음 |
| G1 generic schema/UI | 앱 등록·capability·claim·native scope·지원 상태 | 알려지지 않은 앱도 core 변경 없이 read-only/export 프로파일 등록 |
| G2 KC observe/delegate | 기존 역할 읽기, 제한된 mapping 편집, drift 검사 | 미위임 client/role 및 관리 특권 수정 거부; KC 자체 변경 conflict |
| G3 native export adapters | capability별 config renderer/검증기 | 앱별 role와 default 차이 표현; 미지원 조직 범위 publish 거부 |
| G4 adapter extension | 버전·schema·permission·test contract 정의 | 새 adapter는 negative/회수 테스트 통과 후 supported 표시 |
| G5 선택 기능 | native direct API, KC Auth Services 또는 LDAPium check | 대상 앱의 실제 강제·장애·회수 증거 없으면 활성화 불가 |

- `REQ-026 / AC-030`: Narwhal에 없는 custom OIDC 앱의 프로파일을 core 코드 변경 없이 등록.
- `REQ-027 / AC-031`: KC 원본 role 조회/위임 편집; local DB 사본 변경으로 권한이 활성화되지 않음.
- `REQ-028 / AC-032`: external-owner 앱은 조회/export만; delegated 범위 밖 편집 거부.
- `REQ-029 / AC-033`: gateway-only/app-only 앱에 subtree 권한을 publish하면 unsupported 거부.
- `REQ-030 / AC-034`: 같은 역할 이름의 두 앱에 독립 매핑; 한 앱 admin이 다른 앱에 전파 안 됨.
- `REQ-031 / AC-035`: native/GitOps/KC/optional-PDP별 실제 enforcement와 단일 원본 확인.

Narwhal AC-021–029는 capability별 예시 회귀 fixture로 유지한다. 모든 13개 앱을
연결해야 범용 기능이 완료되는 것은 아니다. 최소 custom 앱 1개와 서로 다른 capability
fixture로 확장성을 증명하며 인증-only와 권한 연동 verified를 별도로 표시한다.

## 근거와 잔여 판단

- [Keycloak Server Administration](https://www.keycloak.org/docs/latest/server_admin/): 앱 role/Composite/group mapping 및 Admin 권한.
- [Keycloak Admin REST API](https://www.keycloak.org/docs-api/latest/rest-api/index.html): 위임 UI 구현 경로.
- [Keycloak Authorization Services](https://www.keycloak.org/docs/latest/authorization_services/index.html): resource/policy 판단은 앱의 enforcement 통합 필요.

결론: 제한된 Keycloak 관리 UI는 적합한 확장 후보다. 모든 OSS 권한을 LDAPium이
재정의·저장·판단하는 기본안은 현재 제품 경계와 유지 비용상 권장하지 않는다.
해당 권고는 공식 기능과 기존 제품 경계에 기반한 설계 판단이며 런타임 검증 결과가 아니다.
