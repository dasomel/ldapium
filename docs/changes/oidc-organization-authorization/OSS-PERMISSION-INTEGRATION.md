# OSS별 OIDC SSO·권한 연동 추가 계획

Status: Draft · 2026-10-01 · [설계 패키지](CHANGE.md) · [관리 UI/API](CONTROL-PLANE.md)

> 아래 OSS는 예시 fixture다. 필수 지원 목록이나 고정 구현 순서가 아니다.
> 범용 추가 계획/역할 원본은 [APP-AUTHORITY-AND-CAPABILITIES.md](APP-AUTHORITY-AND-CAPABILITIES.md)의
> G0–G5와 D15/D16을 우선한다. P0–P5는 예시 적용 시 참고 순서다.

## 목표와 근거

LDAPium UI에서 사용자/그룹에 앱별 역할과 범위를 부여하면 Keycloak의 client/claim과
OSS 자체 인가 설정까지 연결할 수 있게 한다. OIDC 로그인 성공이나 Portal 링크 노출을
앱 권한 적용 완료로 취급하지 않는다. 현재 기능 구현·라이브 배포 검증은 없다.

기준 자료는 Narwhal의 [app-sso-permission-matrix.md](../../../../idp/narwhal/docs/common/app-sso-permission-matrix.md),
[oidc-rbac-contract.md](../../../../idp/narwhal/docs/common/oidc-rbac-contract.md)이며
2026-10-01 로컬 checkout에서 읽었다. 경로는 sibling checkout을 전제로 하며 외부 저장소가
없으면 해당 근거는 이용할 수 없다. matrix는 committed 설정 요약이지 live 상태가 아니다.
참조된 client script, Argo CD RBAC script, Grafana template, Kubernetes RBAC도 읽어
매핑을 확인했다. companion Portal 코드와 모든 OSS의 실환경 동작은 검증하지 않았다.

## D12 — 공통 역할을 앱별 매핑으로 변환

이유: 동일 developer가 Argo CD에서는 제한된 sync, Grafana에서는 Editor,
Kubernetes에서는 namespace 쓰기를 의미한다. 비용: 앱/버전별 adapter 유지.
탈출 경로: 미지원 앱은 인증만 연결하고 권한 적용 상태를 미지원으로 표시한다.

```text
LDAP 그룹 멤버십
  → LDAPium Grant(앱, 역할, 조직 범위)
    → Keycloak client role / 호환 group claim
    → OSS 설정(Argo RBAC / Grafana role expression / K8s binding 등)
      → 실제 OSS API/UI 허용·거부 검증
```

`cluster-admin`, `developer`, `viewer`, `guest`는 Narwhal 호환 프로파일의 역할 그룹이다.
일반 조직 소속 그룹과 혼합하지 않는다. `cluster-admin`이라는 문자열을 보고 모든 OSS의
슈퍼관리자로 자동 변환하지 않는다. 예컨대 Kubernetes 대상은 내장 cluster-admin이 아닌
Narwhal `platform-admin`이다. 앱별 privilege 수준을 별도로 표시한다.

상위 역할이 포함 역할을 확장하는 것은 유지하되, 앱별 group deny/default/역할 우선순위는
다르므로 모든 앱에 동일 역할 그룹을 중복 발급하지 않는다. admin+guest 같은 다중 역할
조합을 preview와 E2E로 검증하며 애매하면 publish를 거부한다.

## 앱별 기준선과 추가 계획

아래 현재 값은 Narwhal matrix의 설정 기준선이다. 계획 열은 제안이지 지원 완료가 아니다.

| 앱 / client | 현재 권한 연결 | 추가 adapter/설정 계획 | 조직 범위·검증 핵심 |
|---|---|---|---|
| Argo CD / argocd | cluster-admin→admin; developer→tenants/* sync와 app/log 조회; viewer→readonly; guest→none+app get deny | groups→Casbin 역할, RBAC ConfigMap/AppProject 산출 | org→AppProject를 명시 매핑; tenants 밖 sync 거부; 기본 역할·deny·복수 그룹 검증 |
| Gitea / gitea | APISIX 로그인; org/repo는 자체 ACL; group-role 연결 없음; git/automation bypass 존재 | gateway admission과 Gitea org/team/repository permission을 별도 adapter로 설계 | org→Gitea org/team/repo; API/SSH/git/automation은 Gitea credential ACL로 별도 검사; gateway 통과만으로 권한 보장 금지 |
| Harbor / harbor | cluster-admin→OIDC system admin; 나머지 project 권한 자체 관리 | OIDC admin group 설정 + project별 OIDC group membership/role 산출 | org→project; project 관리자를 system admin으로 승격 금지; pull/push·robot account는 별도 ACL |
| Grafana / grafana | cluster-admin→Admin; developer→Editor; 나머지 모두 Viewer | OAuth role expression, 허용 그룹/strict 정책, org mapping 후보 | Admin과 GrafanaAdmin 구분; org/folder 지원은 설치 버전·OSS edition 확인; 미상/guest Viewer fallback을 명시 개선 |
| Prometheus / prometheus | APISIX 로그인만; 그룹 인가 없음 | route/service admission adapter; 조회 기능의 허용 그룹을 명시 | 외부 endpoint와 내부 우회 차단 검증; query 데이터의 조직 분리는 별도 backend 없으면 미지원 |
| Alertmanager / alertmanager | APISIX 로그인만; 그룹 인가 없음 | route/method/action admission; silence 변경 행위 별도 허용 | 조회/쓰기 경로 전체 inventory; URL 규칙만으로 조직별 silence 범위를 보장하지 않음 |
| Headlamp / headlamp | 토큰→Kubernetes API; group RBAC | cluster audience/groups와 RoleBinding/ClusterRoleBinding 산출 | org→namespace; 실제 사용자 token으로 namespace 읽기/쓰기/exec negative |
| Kubernetes Dashboard / kubernetes-dashboard | public PKCE/bootstrap token→Kubernetes API | public client PKCE+audience+같은 K8s binding adapter | 서버 SA로 사용자 권한 대체 금지; guest binding 없음; bootstrap·직접 API 동일 범위 |
| OpenBao / openbao | 기본 OIDC role default policy; cluster-admin 외부 그룹→광범위 * policy | OIDC role·bound audience·external group alias·경로 policy 산출 | org→명시된 secret path; default policy 효과 검사; wildcard 관리자는 opt-in 특권 |
| Velero UI / velero-ui | OAuth+/sso; group-role matrix 없음 | 설치 제품/버전의 identity 전달과 native ACL 조사 후 adapter 선택 | 사용자 대신 SA 실행 시 native 인가 보장 불가; adapter/API 강제 가능성 확인 전 authentication-only |
| Hubble UI / hubble | APISIX 로그인만; 그룹 인가 없음 | 서비스 admission 및 읽기 endpoint 제한 | 조직별 flow visibility는 backend 지원 확인 전 미지원 |
| NFS Quota / hubble 공유 | APISIX 로그인만; client 경계 공유 | 전용 nfs-quota client와 route 생성, 변경 endpoint admission | 공유 client 유지 시 independent-app 경계 불가로 표시; quota 쓰기는 backend 강제 필요 |
| Narwhal Portal / narwhal-portal | bare groups→4개 역할; route/API scope; tools roles는 링크 표시 | Portal 역할/팀 scope/도구 가시성 산출을 각각 구분 | team scope는 UI visibility 의미를 그대로 기록; 실제 API scope는 별도 검증; refresh 후 group 재평가·회수 시험 |

Kubernetes 호환 계약: 토큰 `groups`에는 bare name을 쓰고 `oidc:`는 apiserver가 붙인다.
developer는 cluster-wide read와 dev namespace workload write를 분리한다. guest는 K8s
binding을 만들지 않는다. Headlamp/Dashboard 토큰의 Kubernetes audience는 client audience와
별개로 검사한다. 정책 산출 과정에서 이를 cluster-wide write로 넓히지 않는다.

## D13 — claim·역할 이행을 두 모드로 분리

이유: 기존 소비자는 bare groups를 읽으며 client role을 자동 소비하지 않는다.
비용: 호환 기간과 앱별 새 claim 설정 필요. 탈출 경로: 검증된 이전 contract revision으로 복원.

| 프로파일 | claim 계약 | 적용 원칙 |
|---|---|---|
| narwhal-compat-v1 | 기존 groups=[cluster-admin/developer/viewer/guest]; full.path=false | 기존 shared role group 동작을 보존; 앱별 독립 권한 부여라고 주장하지 않음 |
| per-app-v1 | resource_access.<client>.roles 또는 명시적 app group 값 | 앱별 adapter가 소비하는 필드를 확인하고 OSS 설정을 함께 바꿈 |

예: Alice를 Grafana admin으로 만들기 위해 realm 공통 cluster-admin 그룹에 넣지 않는다.
그 작업은 Harbor system admin/OpenBao 특권까지 확대할 수 있다. 신규 모드는 Grafana의
client role/앱 전용 그룹만 부여하고 Grafana adapter를 같은 revision으로 전환한다.

- AppRoleMapping: application_id, source role ID, claim path/value, native role,
  native scope, admission/default, precedence, supported version/edition을 보관한다.
- client groups mapper는 realm 전체 그룹을 노출할 수 있다. per-app claim filtering은
  지원 여부를 adapter에서 검증한다. 일반 mapper만으로 필터 가능하다고 가정하지 않는다.
  필터 불가 시 client role claim을 소비하도록 설정하거나 미지원으로 차단한다.
- claim full path 여부·ID/access/userinfo 중 실제 소비 위치·requested scopes·audience·
  public/confidential/PKCE 계약을 앱 프로파일에 기록한다. string role과 array groups를 혼동하지 않는다.
- 자동 onboard/가입과 실제 권한 부여를 구분한다. 기존 수동 로컬 ACL은 managed 표시가
  없으면 변경하지 않는다. target user ID와 issuer/sub/LDAP UUID 대응도 저장한다.
- fallback(default Viewer/default policy/default role)은 UI에서 노출하고 preview에 포함한다.
  신규 프로파일은 미매핑을 거부하는 것이 기본이며 기존 fallback 변경은 영향 확인 후 별도 적용한다.

## D14 — OSS native adapter와 GitOps 산출을 추가

이유: Keycloak 설정만으로 OSS ACL은 변경되지 않는다. 비용: adapter별 실행/검증과 credentials.
탈출 경로: direct adapter가 없으면 export만 제공하고 applied 상태로 표시하지 않는다.

초기에는 버전이 지정된 manifest/config/설정 안내 export를 기본 경로로 한다.
Narwhal GitOps 대상은 파일 산출→운영자가 Git 반영→Argo apply→관찰/검증으로 진행한다.
LDAPium이 GitOps와 같은 객체를 직접 수정하는 이중 writer를 만들지 않는다.
외부 git commit/push/PR 생성·실배포는 별도 명시적 실행 권한이 있어야 한다.

native API adapter는 실제 버전에서 지원되는 endpoint를 확인한 앱부터 선택적으로 제공한다.
KC adapter+OSS adapter의 전체 작업을 동일 operation으로 추적하되 외부 원자성을 주장하지
않는다. 신규 부여는 전체 검증 전 완료로 표시하지 않고, 제거는 native ACL/세션/JWT의
잔여 허용 가능성을 표시한다. roles-only 외부 앱을 LDAPium DB에서 즉시 deny한다고 해서
그 OSS 접근이 즉시 차단된다고 설명하지 않는다.

ApplicationIntegration 필드: adapter_id/version, app_version/edition, client_id, claim_contract,
native_endpoint/secret_ref, writer_mode(export/direct), managed_object_ids,
scope_bindings(org→project/namespace/path), observed_revision, test_results,
revocation_budget. secret 조회·임의 endpoint 요청·arbitrary upstream API proxy는 제공하지 않는다.

## UI/API 추가

애플리케이션 설정에 OIDC 연결·권한 매핑·조직 범위·진입 조건·적용 상태·권한 테스트 탭을 둔다.
관리자는 그룹별로 앱 역할을 선택하고 기존/변경 후 OSS 유효 권한과 다른 앱 영향도 본다.
앱 진입 권한은 Portal 링크 가시성과 별도 필드다. authentication-only, native-mapping,
scoped-native, scoped-check를 지원 능력으로 표시한다.

| Endpoint (제안 /api/v1) | 동작 |
|---|---|
| GET /integration-adapters | 지원 버전·edition·scope·apply/check 능력 목록 |
| GET/PUT /applications/{id}/sso-contract | client/claim/audience·redirect·token 소비 계약 |
| GET/PUT /applications/{id}/permission-mappings | 역할→claim→native role/scope 연결; ETag |
| GET/PUT /applications/{id}/scope-bindings | 조직→namespace/project/path 대응; ETag |
| POST /applications/{id}/integration-plan | desired↔observed diff·영향·privilege 확대·지원 불가 출력 |
| POST /applications/{id}/integration-exports | secret 없는 GitOps/config artifact 생성 |
| POST /applications/{id}/integration-apply | direct-capable managed 객체만 실행; 202 operation |
| POST /applications/{id}/integration-verify | 등록된 테스트 identity로 허용/거부 검사; 202 operation |
| GET /applications/{id}/integration-status | 단계별 상태와 evidence revision/시간 |

관리 API는 CONTROL-PLANE의 authn/위임 범위/If-Match/Idempotency-Key를 그대로 적용한다.
Keycloak 연결·native endpoint/Secret 변경은 플랫폼 특권, permission mapping은 위임된
앱·조직 내 정책 특권이다. verify는 impersonation을 쓰지 않으며 운영자가 발급한 테스트
identity/credential reference를 사용한다. 생산 비밀번호를 수집하거나 앱 동작을 임의 실행하지 않는다.

적용 상태는 configured, exported, pending, applied-unverified, verified, drifted, failed,
unsupported로 구분한다. verified에는 실제 테스트 revision과 제품 버전이 있어야 한다.
realm/client 역할만 반영되면 Keycloak 단계만 applied이고 앱 인가는 완료가 아니다.

## 요구사항과 검증 계획

| Requirement / Acceptance | 검증 시나리오 |
|---|---|
| REQ-017 / AC-021 | 예시 앱 프로파일에서 SSO·native policy·scope·Portal 가시성을 별도 표시 |
| REQ-018 / AC-022 | bare groups/full.path/audience 계약 검사; K8s만 oidc: 변환; guest binding 없음 |
| REQ-019 / AC-023 | Grafana 전용 admin 부여가 Harbor/OpenBao/Argo 특권으로 확대되지 않음 |
| REQ-020 / AC-024 | Argo tenants 외 sync 거부, K8s dev 외 write 거부, Harbor 다른 project push 거부 |
| REQ-021 / AC-025 | 미상·guest·다중 역할과 default policy의 effective 권한 확인; 미지원 scope publish 거부 |
| REQ-022 / AC-026 | gateway admission deny와 backend/SSH/git/API 우회 경로의 native ACL을 별도 검증 |
| REQ-023 / AC-027 | export만으로 applied/verified 표시 안 함; partial apply/drift/재시도에서 미관리 객체 보존 |
| REQ-024 / AC-028 | 앱별 group 회수 후 기존 세션/JWT/native ACL로 다시 시도해 실제 회수 기한 측정 |
| REQ-025 / AC-029 | NFS Quota 별도 client 전환 시 Hubble audience/cookie/redirect·접근에 회귀 없음 |

앱 프로파일마다 admin/developer/viewer/guest/미상/복수 역할/회수 사용자를 테스트하고
관리 UI에서 토큰 내용만 보는 것이 아니라 실제 app read/write/admin/직접 endpoint 결과를
기록한다. destructive 검증은 disposable 환경에서만 수행한다. 앱 pin·edition 미확정이면
supported 표시를 하지 않는다. Portal refresh-only group 갱신 한계는 새 토큰만으로
해결된다고 가정하지 않고 기존 session 권한을 따로 시험한다.

## 단계별 추가 계획

1. P0 계약/차이 조사: 13개 앱의 pin/edition·실제 설정·기본 권한·현재 writer·회수 기한 확보.
   누락된 gateway 인가와 NFS Quota 공유 client를 gap으로 등록한다.
2. P1 공통 UI/API: adapter catalog, mapping/scope 등록, 영향 preview, secret 없는 export,
   application별 claim 계약과 operation 상태를 먼저 구현한다.
3. P2 1차 native pilot: Argo CD·Grafana·Kubernetes(Headlamp/Dashboard) GitOps export와
   실제 allow/deny 검증. 기존 compat 모드를 보존하고 per-app 모드는 앱별로 전환한다.
4. P3 Harbor·OpenBao: project/path scope와 광범위 관리자 opt-in, native ACL 회수 검증.
5. P4 gateway 앱: Prometheus/Alertmanager/Hubble/NFS Quota admission, 우회 경로 차단,
   NFS Quota 전용 client 계획. native scope 없는 데이터 격리는 미지원으로 유지한다.
6. P5 Gitea·Velero UI·Portal: native identity/ACL adapter 확정, bypass/SA/세션 회수 검증.
   Portal 링크 가시성과 실제 인가는 각각 검증한다.

각 단계는 기준선→plan/export→명시적 배포→허용/거부·회수 증거→supported 표시 순서다.
부분 완료로 모든 OSS 지원을 선언하지 않는다. implementation Class D 수용과 독립 리뷰는
기존 패키지 절차를 따른다. 이번 작업은 계획 문서만 변경하며 Narwhal 파일은 수정하지 않는다.

## 공식 문서와 구현 시 확인할 항목

- [Argo CD RBAC](https://argo-cd.readthedocs.io/en/stable/operator-manual/rbac/): groups, default 역할·deny와 policy 검사.
- [Grafana Generic OAuth](https://grafana.com/docs/grafana/latest/setup-grafana/configure-access/configure-authentication/generic-oauth/): role expression·strict·org mapping, edition별 기능.
- [Harbor project membership](https://goharbor.io/docs/2.11.0/working-with-projects/create-projects/add-users/): OIDC group project 연결; 설치 버전 재확인.
- [APISIX OIDC](https://apisix.apache.org/docs/apisix/plugins/openid-connect/): 인증 기능; native 자원 인가를 대체하지 않음.

Gitea/OpenBao/Velero UI와 gateway 세부 adapter는 설치 제품 pin을 조사한 뒤 해당 버전
공식 API 문서를 확인한다. 본 문서는 조사하지 않은 API의 지원 가능성을 확정하지 않는다.
