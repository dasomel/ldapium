# LDAPium UI·Keycloak 관리·외부 OSS 인가 API 설계

Status: Draft · 2026-10-01 · 상위 패키지: [CHANGE.md](CHANGE.md)

> 최신 원본/제어 판단은 [D15/D16](APP-AUTHORITY-AND-CAPABILITIES.md)을 따른다.
> 아래 D8–D11의 DB role 원본·KC 자동 투영·중앙 check 기본안은 초기 대안으로 남긴다.
> 수용 대상 기본안은 KC-backed 위임 UI와 범용 capability 프로파일이다.

OSS별 실제 권한 연결은 [OSS-PERMISSION-INTEGRATION.md](OSS-PERMISSION-INTEGRATION.md)의
Narwhal 호환/앱별 claim 계약, native adapter/GitOps export와 AC-021–029를 함께 적용한다.

## 목표와 기존 경계 변경

LDAPium UI를 사용자·조직·그룹·애플리케이션 권한을 설정하는 관리 지점으로 확장한다.
Keycloak은 인증·토큰 발급을 담당하고 LDAPium은 조직 범위 정책의 원본과 판단 API를
제공한다. 다른 OSS는 OIDC 로그인과 역할 claim을 사용하거나 LDAPium 인가 API를
호출한다. 전자는 제한된 역할 연동, 후자는 조직 범위까지 보장하는 연동이다.

현재 제품은 DB 없는 thin UI이며 범용 IGA/동기화 엔진을 제외한다. 이번 제안은
정책 DB와 단일 Keycloak realm 관리 기능을 추가하는 제품 경계 변경이다.
수용 시 product-boundary/architecture/운영 계약과 ADR을 함께 바꿔야 한다.
범용 다중 IdP 엔진·SCIM·승인 시스템·Keycloak 전체 관리 콘솔은 포함하지 않는다.

## 책임과 원본

| 정보/기능 | 원본 | UI/API 동작 |
|---|---|---|
| 계정·암호·사용자 프로필 | LDAP | 기존 LDAP 서비스 계층으로 생성·수정; 비밀번호 읽기 금지 |
| 일반/권한 그룹과 직접 멤버십 | LDAP | UUID 연결, 보호 그룹 작업을 인가 후 실행 |
| 조직 트리·자원 소유 조직 | LDAPium DB | 명시적 조직 ID; OU/그룹 트리에서 자동 추론 안 함 |
| 애플리케이션·역할·Composite 포함 관계 | LDAPium DB | managed Keycloak client roles로 투영 |
| Grant: group+role+org+scope | LDAPium DB | 한 행으로 저장·평가; 교차 합성 금지 |
| 인증·세션·MFA·토큰 | Keycloak | LDAPium이 토큰을 자체 발급하지 않음 |
| Keycloak client/mapper 설정 | 관리 대상 필드만 LDAPium DB | 미관리 필드와 객체는 보존 |
| 외부 OSS 자원/권한 연결 | OSS 자원 + 등록된 LDAPium 정책 | resource ID→org 소유권 등록, check API |

### D8 — 정책 원본을 DB로 변경

이유: UI 편집과 동시 변경, 감사, UUID 생성 상태를 지속적으로 관리해야 한다.
비용: DB 배포·migration·backup/restore 추가. 탈출 경로: export된 정책과 DB 백업으로
복구; 기존 LDAP-only legacy 모드는 DB 기능과 분리한다.
초기 대상 DB는 PostgreSQL을 제안하며 버전·driver는 패키지 수용 후 별도 검증한다.
SQLite/다중 DB 동시 지원은 초기 범위에서 제외한다.

주요 테이블: organizations, applications, roles, role_permissions, role_inclusions,
grants, resource_ownership, subject_links, group_links, managed_kc_objects,
operations, outbox, audit_events. UUID PK, revision, created_by/updated_by를 둔다.
Grant는 application_id/role_id/org_id/group_uuid/scope를 함께 보존한다.
조직은 단일 parent; role DAG와 조직 트리에 순환을 허용하지 않는다.
삭제는 참조가 있으면 409, 명시적 영향 검토 후 별도 철회 작업으로 수행한다.

### D9 — Keycloak을 제한된 관리 대상만 제어

이유: 사용자가 UI에서 설정한 역할을 OSS OIDC 토큰에 반영할 수 있어야 한다.
비용: Admin API 자격 증명과 부분 실패 처리. 탈출 경로: 미관리 객체는 읽기/수동 연결,
범위 제한을 제공하지 못하는 KC 버전에서는 쓰기 기능 비활성 또는 전용 realm 사용.

1개 설치에 LDAP 디렉터리 1개와 Keycloak realm 1개를 연결한다. 플랫폼 운영자가
connection URL/realm/secret reference를 등록한다. 비밀 값은 서버/Secret에만 저장하고
UI에는 마스킹된 상태만 노출한다. URL 변경은 플랫폼 특권이며 임의 SSRF·내부 endpoint
접근을 방지하는 allowlist/TLS 정책을 적용한다.

| Keycloak 기능 | 초기 범위 |
|---|---|
| 연결/버전/최소 권한 검사 | 지원 설계; actual pin과 권한 능력 감지 |
| LDAP federation와 group mapper | 기존 설정 연결·검사·동기화 실행; 신규 생성은 후속 단계 |
| OIDC client | 사전 등록 client 연결 및 명시적 managed client 생성 |
| Client Role / Composite | managed 애플리케이션의 역할만 생성·수정·삭제 |
| Group role mapping / claim mapper | 관리 대상 그룹/client의 허용 필드만 반영 |
| Client redirect URI | 플랫폼 운영자만 정확한 URI 등록; wildcard 기본 거부 |
| Client secret 회전 | 플랫폼 운영자 명시 작업; 일회 전달 또는 Secret 참조, 감사에 값 금지 |
| Realm 전역 설정·MFA·인증 flow·IdP·impersonation | 미지원; Keycloak 운영자가 관리 |
| realm-management 관리자 역할 변경 | 미지원; UI 권한 모델에 포함 금지 |

전용 confidential service account의 client credentials로 Admin REST API를 호출한다.
realm-admin을 기본 부여하지 않는다. 필요한 managed client/group/role 범위를 KC에서
제한하고 negative test로 확인한다. realm-management의 coarse 권한만 가능하면
LDAPium 자체 allowlist는 보조 장치일 뿐 KC 측 격리가 아니므로 전용 realm을 요구한다.
FGAP V1/V2 차이는 실제 pinned 버전에 맞춰 검증하며 최신 기능을 가정하지 않는다.

### D10 — DB desired state와 외부 applied state를 분리

이유: LDAP·DB·Keycloak 사이 단일 트랜잭션은 없다. 비용: outbox worker, 재시도/상태 UI.
탈출 경로: operation을 중지하고 원본을 남긴 채 운영자가 reconcile/rollback한다.

DB transaction으로 revision+desired state+outbox+감사를 기록한 후 worker가 반영한다.
API는 외부 변경을 포함하면 202+operation ID를 반환한다. 완료 전에 성공으로 표시하지 않는다.
상태: pending → applying → applied / failed / conflict. 제한된 backoff 재시도와 수동 재시도,
단계별 읽기 확인, actor/request ID를 기록한다. 같은 키 재시도는 중복 객체를 만들지 않는다.
고유 managed marker와 외부 ID를 저장하고 이름 일치만으로 외부 객체를 인수하지 않는다.

- 권한 추가는 DB와 필요한 외부 membership/role projection을 확인한 뒤 활성화한다.
- 권한 회수는 DB 판단에서 즉시 deny/tombstone 처리한 뒤 KC 역할 제거·LDAP 변경을 수행한다.
- 역할 변경은 새 revision 검증 후 publish한다. 새 권한의 부분 반영은 허용하지 않는다.
- 변경 검출: 미관리 객체는 수정 안 함; managed 필드의 KC 수동 변경은 conflict로 표시,
  review 없이 덮어쓰지 않는다. Grant 목록을 KC 역할 목록으로 역수입하지 않는다.
- LDAP 사용자 생성: pending DB ownership 예약 → LDAP 생성 → entryUUID 읽기 → DB 확정.
  미완료 자원은 일반 사용자에게 접근 거부; 실패 시 작업 ID로 복구하고 기존 자원 삭제 금지.
- LDAP 조회/수정 권한과 KC Admin API 계정은 별개다. DB 정책 회수만으로 직접 LDAP
  접속이나 이미 발급된 OSS JWT 권한이 즉시 사라지지 않는다.

## UI 흐름

| 화면 | 사용자 작업 | 서버 제약/피드백 |
|---|---|---|
| 조직 | 트리 생성, parent 이동, 소유 사용자/그룹 연결 | 이동 전 관리자 접근 확대·축소 영향 표시 |
| 사용자 | LDAP 계정 생성/편집, 조직 연결, 직접 그룹 가입 | UUID 식별; 보호 그룹·비밀번호 작업 별도 권한 |
| 그룹 | 일반/권한 그룹 구분, 멤버 관리 | 권한 그룹은 정책 운영자만 변경 |
| 애플리케이션 | OSS 이름, OIDC client 연결, 연동 방식 등록 | roles-only와 scoped-check 보장 차이 표시 |
| 역할 | 행위 등록, 포함 역할 편집 | 최종 권한 preview·순환 거부·플랫폼 특권 제외 |
| 권한 부여 | 그룹+앱 역할+조직+self/subtree 선택 | 사용자별·조직별 effective 권한과 영향 preview |
| 권한 테스트 | 사용자·행위·자원 선택 | allow/deny와 해당 Grant·revision 설명 |
| Keycloak 연결 | 연결/최소 권한 검사, managed 상태, 작업 재시도 | secret 비노출; pending/failed/conflict 표시 |
| 감사/회수 | 사용자 회수, 세션 무효화, 변경 이력 | 외부 토큰 지연과 실제 반영 상태 구분 |

UI는 별도 로직 대신 아래 API를 사용한다. 설정 변경에 CSRF 방어, 서버 capability와
낙관적 동시성 검사를 적용한다. org-admin은 범위 내 일반 구성원 작업만, policy-admin은
역할/Grant 편집만, platform-admin은 KC 연결/앱 연결 등 특권만 수행하도록 분리한다.
policy-admin도 허용 앱/조직 내에서만 Grant를 만들며 자신의 위임 한도를 넘길 수 없다.
권한 테스트의 사용자별 판단 근거는 관리 권한이 있는 범위에서만 공개한다.

## Management API — 제안 `/api/v1`

UUID 경로, 페이지 기반 opaque cursor, bounded limit, ETag/If-Match를 사용한다.
UI는 현재 cookie 세션, 자동화는 ldapium-management audience의 service token을 사용한다.
service caller의 관리 범위는 DB에서 별도 부여하며 bearer scope만으로 특권을 얻지 못한다.

| Endpoint | 용도 |
|---|---|
| GET/POST /organizations | 범위 제한 목록·조직 생성 |
| GET/PATCH/DELETE /organizations/{id} | 상세·표시 변경·참조 없는 조직 삭제 |
| POST /organizations/{id}/move | parent 변경 영향 검토 후 적용 |
| GET/POST /users, GET/PATCH/DELETE /users/{uuid} | LDAP 사용자와 원자성 제한이 있는 프로비저닝 작업 |
| GET/POST /groups, GET/PATCH/DELETE /groups/{uuid} | LDAP 그룹, 보호 그룹 검사 |
| PUT/DELETE /groups/{uuid}/members/{userUUID} | 멤버십 변경; 양쪽 범위 검사 |
| GET/POST /applications, GET/PATCH /applications/{id} | 앱과 연동 능력 등록 |
| GET/POST /applications/{id}/roles | 앱별 역할 등록 |
| PATCH/DELETE /applications/{id}/roles/{roleID} | 역할 수정/참조 검사 |
| PUT /applications/{id}/roles/{roleID}/includes | 포함 역할 ID 목록 replace; DAG 검사 |
| GET/POST /grants, PATCH/DELETE /grants/{id} | 역할·조직·scope 결합 부여/회수 |
| GET /users/{uuid}/effective-permissions | 관리 범위 내 유효 권한; 근거 revision |
| POST /policy/previews | 미적용 변경 영향·권한 확대/축소 계산 |
| POST /integrations/keycloak/test | 연결·버전·허용 객체/행위 테스트 |
| GET/PATCH /integrations/keycloak | 플랫폼 운영자 설정, secret reference만 응답 |
| POST /integrations/keycloak/reconcile | managed 객체 diff 적용; 전체 arbitrary proxy 금지 |
| GET /operations/{id}, POST /operations/{id}/retry | 실행 상태·권한 있는 작업 재시도 |
| GET /audit-events | 범위 제한 actor·decision·실행 결과 조회 |

모든 변경은 actor/action/target별 검사. Idempotency-Key는 caller+route로 범위를 나누고
body hash가 다르면 409; TTL과 보관 기한을 문서화한다. stale If-Match는 412,
참조/순환/동기화 충돌은 409, invalid 입력 400/422, 미인증 401, 권한 없음 403이다.
인가 조회 실패는 503이고 허용으로 변환하지 않는다. 외부 실행 상태는 202 operation으로
분리한다. 문서화된 오류 code/request_id만 노출하고 LDAP 내부 DN/비밀은 응답에서 제거한다.

## External OSS API — 역할 연동과 조직 범위 연동

### D11 — 지원 능력을 앱별로 선언

이유: OSS마다 지원하는 로그인/인가가 다르다. 비용: mapping 등록과 연동 시험.
탈출 경로: native role mapping만 가능한 앱은 그 한계 안에서 사용하거나 adapter를 추가한다.

| 모드 | 경로 | 보장 |
|---|---|---|
| OIDC roles-only | LDAP → KC groups/Client Roles → OSS native role mapping | 앱 역할만; 조직별 범위는 OSS 자체 지원 시에만 가능 |
| scoped-check | OSS backend/adapter → LDAPium check | 행위+대상 조직별 중앙 판단; OSS가 모든 경로에 강제해야 함 |

roles-only에서는 앱 역할+조직 Grant를 평면 `admin` claim으로 뭉개면 다른 조직 권한까지
확대된다. 앱 전체 범위 Grant 또는 OSS에서 확인된 scoped mapping만 KC에 투영한다.
지원 없는 scoped Grant의 roles-only publish는 UI/API에서 거부한다. KC 로그인만
연결했다고 사용자 프로비저닝·자동 회수까지 지원된다고 표시하지 않는다.

### Check API

```http
POST /api/v1/authorization/check
Authorization: Bearer <OSS service-account access token>
Content-Type: application/json

{
  "application_id": "grafana",
  "subject": {"issuer": "https://sso.example/realms/company", "sub": "kc-user-id"},
  "action": "dashboard.edit",
  "resource": {"type": "dashboard", "id": "dashboard-42"}
}
```

```json
{
  "allowed": false,
  "decision_id": "decision-uuid",
  "policy_revision": 42,
  "reason_code": "OUT_OF_SCOPE",
  "cache_ttl_seconds": 0
}
```

OSS service token은 지정 issuer/signature/audience `ldapium-authz`/expiry와 등록된
client ID를 검사한다. caller가 등록 앱에 대해서만 조회 가능하도록 제한한다.
임의 subject 질의는 일반 사용자가 아니라 등록된 trusted backend만 허용한다.
그 backend는 실제 OSS 사용자 토큰/세션을 검증하고 동일 `(iss, sub)`를 제출할 책임이 있다.
사용자 ID 문자열을 브라우저가 직접 입력한 값으로 전달해서는 안 된다. untrusted public
client의 임의 subject check는 미지원이다. decision은 caller/앱/사용자/action/resource에
한정되며 재사용 가능한 권한 증서나 LDAP 실행 권한이 아니다.

자원 소유 조직은 DB의 `(application_id,type,id)`에서 조회한다. OSS가 보낸 org_id를
그대로 신뢰하지 않는다. 미등록 자원·미등록 action은 deny. 자원 등록/이동 API는
check-only caller와 분리된 capability 및 허용 조직을 요구한다.

| Endpoint | 계약 |
|---|---|
| POST /authorization/check | 단일 자원 allow/deny; 평가 실패는 503 |
| POST /authorization/batch-check | 최대 100건 독립 결과; caller/app 제한·동일 revision |
| PUT /applications/{id}/resources/{type}/{resourceID} | 신뢰된 provisioning caller가 소유 조직 등록; If-Match |
| DELETE /applications/{id}/resources/{type}/{resourceID} | 소유권 제거 후 이후 요청 deny |
| POST /authorization/query-resources | 허용 자원 ID 목록의 bounded pagination; 범위 밖 자원 비노출 |

외부 OSS는 API timeout/503를 접근 거부로 처리한다. 권한 check 응답을 UI에서만 쓰지
않고 실제 read/write/export/admin 경로에 강제한다. 초기 positive cache는 0초이며
쿼리 규모가 커지면 revision 기반 snapshot/cursor를 검증 후 도입한다. policy changes가
있으면 cursor는 stale 오류를 반환하여 새 쿼리로 재시작한다. offline policy bundle,
webhook/이벤트 스트림, bearer delegation과 SDK는 후속 범위다.

## 역할 계층과 조직 범위 예시

Alice에게 engineering subtree의 dashboard-admin, service self의 audit-reader를
부여하면 platform의 dashboard 수정은 허용, engineering audit 조회는 거부한다.
Role admin이 editor/viewer를 포함하면 그 역할 권한을 해당 Grant 범위 안에서 획득한다.
새 자손 조직이 engineering 아래 생기면 subtree 범위에 포함되며, 다른 부모로 이동하면
범위에서 제외된다. 모든 상위 조직 구성원을 admin으로 승격하지 않는다.

## 수용 기준과 후속 단계

| ID | 추가 요구 / 수용 시나리오 |
|---|---|
| REQ-009 / AC-013 | UI에서 Grant 생성 후 재시작해도 보존; stale edit 412 |
| REQ-010 / AC-014 | KC managed 역할 투영·토큰 확인; unmanaged/client admin 권한 변경 거부 |
| REQ-011 / AC-015 | KC/LDAP 중간 장애·중복 재시도에서도 pending/failed 정확; 권한 조기 활성화 없음 |
| REQ-012 / AC-016 | 외부 OSS caller가 다른 앱/조직 질의·등록하면 거부; subject 위조 경로 차단 |
| REQ-013 / AC-017 | roles-only에서 지원 없는 scoped admin publish 거부; 회수 지연 측정 |
| REQ-014 / AC-018 | 정책 회수 후 check deny, 기존 OSS JWT의 잔여 지연 별도 보고 |
| REQ-015 / AC-019 | DB+LDAP+KC 복구 후 UUID/managed ID/revision 일치; pending 작업 안전 재개 |
| REQ-016 / AC-020 | UI 전체 여정·OSS read/write/export 우회·조직 이동 영향·비밀 비노출 검증 |

1. Class D 패키지 수용: 제품 경계·DB 운영·소유자·위임 한도·API 계약·회수 목표 확정.
2. UI/DB 정책과 LDAPium 자체 scoped 인가를 구현; Keycloak은 기존 연결 read-only.
3. managed client 연결·역할/Composite·claim mapping과 operation worker 검증.
4. 외부 check/resource API와 disposable OSS adapter 1개로 실제 사용자 여정 검증.
5. 지원 OSS별 compatibility matrix를 추가; client 생성/secret 회전은 후속 특권 기능.

검증은 기존 AC-001–012에 위 기준을 추가한다. KC Admin 권한 격리와 LDAP 실제 변경은
live 환경으로, 동시성·정책 계산은 unit/integration으로, UI/OSS는 browser+직접 HTTP로
확인한다. DB 백업뿐 아니라 LDAP UUID/KC 외부 ID 연결까지 복구 시험한다.
현재 구현·실행 검증 없음. 초기 정적 카탈로그 생성 제한은 DB pending workflow로 대체한다.

## 공식 근거

- [Keycloak Admin REST API](https://www.keycloak.org/docs-api/latest/rest-api/index.html): client, role, composite, group role mapping 관리 경로. pin별 확인 필요.
- [Keycloak Server Administration](https://www.keycloak.org/docs/latest/server_admin/): service account와 admin 권한, 역할/그룹 차이.
- [Keycloak Upgrading](https://www.keycloak.org/docs/latest/upgrading/index.html): FGAP V1/V2 차이; 버전 호환성 확인 필요.
- [제품 경계](../../product-boundary.md): DB 없는 UI 및 외부 IGA 경계의 현행 계약. 이 Draft가 자동 변경하지 않는다.
