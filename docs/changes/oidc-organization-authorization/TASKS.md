# Tasks: LDAP–Keycloak 조직 범위 인가

설계: [CHANGE.md](CHANGE.md). 아래 미완료 항목은 후속 구현 계획이며 이번 문서 작업의
완료 또는 기능 지원을 뜻하지 않는다. Class D 패키지 수용 전 broad implementation 금지.

최신 실행 순서는 [범용 계획 G0–G5](APP-AUTHORITY-AND-CAPABILITIES.md)다.
T-016의 role 원본과 T-017의 자동 KC 투영은 KC-backed 위임 편집으로 대체한다.
T-018/019의 외부 중앙 check는 선택 기능이며 T-041–044는 예시 adapter 작업이다.

## Inspect and accept

- [x] T-001 (REQ-001, REQ-008) 현재 SSO 계약과 서비스 계정 경계 확인.
- [x] T-002 (REQ-003, REQ-004) 공식 RBAC/Keycloak/범위 상속 근거 조사.
- [x] T-003 (REQ-001–008) 사용자·그룹·권한·조직 범위와 수용 시나리오 작성.
- [x] T-006 (REQ-017–025) Narwhal 매트릭스/공통 계약을 읽고 [앱별 추가 계획](OSS-PERMISSION-INTEGRATION.md) 작성.
- [ ] T-007 (REQ-017, REQ-021) 선정한 예시/대상 앱 pin·edition·실제 ACL·default·writer·회수 기준선 조사.
- [x] T-008 (REQ-026–031) 범용 capability 프로파일 및 Keycloak 원본/위임 판단 작성.
- [ ] T-050 (REQ-026–031) G0–G1 원본/제품 경계 확정·generic profile schema/UI/API.
- [ ] T-051 (REQ-027, REQ-028) G2 KC read-through·위임 편집·fingerprint/conflict.
- [ ] T-052 (REQ-026, REQ-029, REQ-030) G3–G4 capability별 export·adapter extension contract.
- [ ] T-053 (REQ-031) G5 native direct/외부 PDP 필요성을 앱별 평가; 기본 의존성 추가 금지.
- [ ] T-004 (REQ-001–008) 담당자 지정·열린 결정 확정·패키지 수용·ADR 작성.
- [ ] T-005 (AC-006, AC-012) 모든 API/LDAP 작업 inventory와 legacy 기준선 확보.

## Implement after acceptance

- [ ] T-010 (REQ-001, REQ-002) 불변 UUID 연결과 직접 LDAP 멤버십 조회.
- [ ] T-011 (REQ-003, REQ-004) 역할 확장·정책 카탈로그·Grant 단위 범위 평가.
- [ ] T-012 (REQ-005) 모든 handler/query에 행위·속성·대상 인가 적용.
- [ ] T-013 (REQ-006) 보호 그룹·조직 이동·정책 변경의 특권 분리.
- [ ] T-014 (REQ-007) 세션 기한·회수·버전 rollout·실제 actor 감사 연결.
- [ ] T-015 (REQ-008) 명시적 legacy/scoped 전환, UI capabilities와 오류 처리.
- [ ] T-016 (REQ-009) 정책 DB migration·동시 편집·UI CRUD·backup/restore.
- [ ] T-017 (REQ-010, REQ-011) managed Keycloak Admin adapter·outbox·drift 검출.
- [ ] T-018 (REQ-012, REQ-013) external OSS check/resource API·capability 제한.
- [ ] T-019 (REQ-014–016) 실제 OSS adapter 여정·회수·복구·비밀 비노출 검증.
- [ ] T-040 (REQ-017–019) adapter catalog·앱별 claim/mapping/scope UI/API·preview/export.
- [ ] T-041 (REQ-018–020) Argo/Grafana/K8s pilot·per-app 전환·namespace/project negative 검증.
- [ ] T-042 (REQ-020, REQ-021, REQ-024) Harbor/OpenBao project/path·특권·회수 adapter.
- [ ] T-043 (REQ-022, REQ-025) gateway admission·직접 우회 검사·NFS Quota client 분리 계획.
- [ ] T-044 (REQ-017, REQ-022, REQ-024) Gitea/Velero UI/Portal native ACL·세션 연동.

## Verify and synchronize

- [ ] T-020 (AC-003–005) pure helper unit·negative 범위 테스트.
- [ ] T-021 (AC-001–012) pinned Keycloak+live LDAP+HTTP+browser E2E.
- [ ] T-022 (AC-009–011) 실제 시간 기반 회수·복제·장애·다중 UI 실험.
- [ ] T-023 (REQ-001–008) 독립 리뷰와 evidence 수집; 실패도 보존.
- [ ] T-024 (AC-013–020) [확장 설계](CONTROL-PLANE.md) 수용 시나리오 검증.
- [ ] T-025 (AC-021–029) OSS별 실제 read/write/admin·복수 그룹·회수·drift E2E.
- [ ] T-026 (AC-030–035) custom 앱·단일 원본·위임 범위·미지원 scope·독립 앱 매핑 검증.
- [ ] T-030 UI README/auth policy/product boundary/audit schema 동기화.
- [ ] T-031 ADR·릴리스·마이그레이션·rollback·지원 상태 갱신.


## First implementation slice — 2026-10-01

- [x] T-060 (REQ-026, REQ-029, REQ-030) Generic app profile model and capability validation.
- [x] T-061 (REQ-009 partial) Single-process atomic file persistence and revision conflicts.
- [x] T-062 (REQ-028 partial) Explicit admin DN gate, same-origin writes and strict JSON API.
- [x] T-063 (AC-030 partial) Arbitrary app registration UI, role mapping and configured status.
- [x] T-064 Persistence restart, HTTP negative tests and actual LDAP/browser journey.
- [ ] T-065 Independent implementation review; KC-backed observe/delegate remains next.

Evidence: [IMPLEMENTATION.md](IMPLEMENTATION.md). G1 is partially implemented;
no KC write, native application adapter, PostgreSQL/HA or organizational grants are complete.

## Completed integration baseline — 2026-10-01

This section supersedes the first-slice status above. The latest D15/D16 baseline
uses Keycloak as role authority; earlier DB/PDP/organization tasks remain future
alternatives and are not prerequisites to the current generic integration.

- [x] T-050 G0–G1 capability profile UI/API and responsibility boundaries.
- [x] T-051 G2 live catalog, explicit delegated writes and conflict detection.
- [x] T-052 G3–G4 generic contract, Grafana/ArgoCD exports and extension contract.
- [x] T-053 G5 evaluation: no native direct/PDP dependency added; unsupported scope rejected.
- [x] T-066 Actual Keycloak/browser/token inheritance and fresh-token revocation.
- [x] T-067 Actual Grafana OIDC Editor and unmatched login denial.
- [x] T-068 Helm persistence/Secret wiring and deployment guards.
- [x] T-030 Current UI/product/Helm operation documentation synchronized.
- [ ] T-065 Independent review remains outstanding (KC implementation is delivered).

Evidence and explicit limits: [IMPLEMENTATION.md](IMPLEMENTATION.md).
