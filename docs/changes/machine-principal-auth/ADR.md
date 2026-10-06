# ADR: 외부 HTTP API용 머신 주체 인증 — Keycloak bearer, 읽기 전용, 기본 꺼짐 (D1–D30)

- Status: `Accepted` — [CHANGE.md](CHANGE.md)(Revision 5, 2026-10-07 수용)의 결정을 승격한 기록이다. 구현은 단계 병합(기본 꺼짐): 단위 1 #272, 단위 2 #274, 단위 3 #276, 단위 4 #278. 라이브 Keycloak e2e·CI·release 게이트(단위 5a)는 이 ADR 작성 시점에 **미병합**이다.
- Owner: 미지정(CHANGE.md와 같음, 유지보수자 dasomel이 수용)
- Related issue: [#214](https://github.com/dasomel/ldapium/issues/214) (닫지 않음: 부분 PR)
- 위치 규약: 별도 ADR 디렉터리가 없으므로 변경 패키지 안의 `ADR.md`로 둔다([api-error-envelope](../api-error-envelope/ADR.md)와 같음). 근거·대안·검토 기록의 전문은 CHANGE.md, 실측은 [EVIDENCE.md](EVIDENCE.md).
- 정본 계약: [docs/api.md](../../api.md) "머신 bearer 인증". 운영: [Keycloak client](../../machine-keycloak-client.md), [LDAP 계정·ACL](../../machine-ldap-account.md), [롤백·긴급 차단](../../machine-auth-operations.md). 정책 예외: [auth-provider-policy §6](../../auth-provider-policy.md).
- ADR threshold: `required` — 신규 자격 증명 수용 경로, 신뢰 경계 확대, 정책 문서 예외.

## Context

외부 시스템·AI 에이전트가 쓸 수 있는 인증은 사람의 로그인 쿠키 재생뿐이었다. LDAP 모드는 (대개 관리자급) LDAP 비밀번호를 에이전트에 넘겨야 했고, SSO 모드는 무인 호출 경로가 없었다. 세션은 프로세스 메모리의 LDAP bind라서 서비스별 권한 분리·회수·감사 주체가 없고, 라우트별 scope가 없어 인증된 세션은 보호 오퍼레이션 45개 전부에 도달한다.

## Decisions (되돌리기 어려운 것만; 전체는 CHANGE.md)

| ID | 결정 | 탈출구 |
|---|---|---|
| D1 | Keycloak OIDC access token(`client_credentials`, Bearer)을 v1로 채택. 해시 저장 API 키·mTLS는 평가만 하고 보류. ldapium은 토큰·secret을 저장하지 않고 공개키로 검증만 한다 | 인증기를 단일 메서드 뒤에 두어 옵션 2 추가는 구현체 추가로 가능(첫 구현은 구체 타입) |
| D2 | 기존 경로에 `Authorization` 헤더 **존재** 기준으로 인증기를 선택한다(순수 `selectAuth`). 잘못된 `Authorization`은 쿠키로 폴백하지 않고(401), 유효 형식+쿠키는 400, 공개 로그인·SSO 4경로는 400. 쿠키 경로는 Authorization이 없으면 기존 그대로. Origin gate는 최외곽 불변, CORS 미확장 | `/api/v1/machine/...` 경로 복제로 전환 가능 |
| D3 | scope는 서버 코드의 정적 `operation→scope` allowlist(OpenAPI `x-machine-scope`와 1:1)로만 해석한다. 유효 권한 = 토큰 scope ∩ client별 서버 상한. 미등록은 기본 거부(403 `scope_denied`). `*` 상한 모드 없음 | 필요 시 별도 결정 |
| D4 | 실행 신원은 배포당 하나의 전용 읽기 전용 LDAP 계정, 요청마다 bind 후 종료. 관리자·프로파일 관리자·서비스 계정·rootdn과 `ParseDN` 동등이면 기동 실패. 읽기 전용은 **LDAP ACL이 강제**하고 실제 쓰기 시도로 증명한다 | 연결 풀, client→DN 매핑 |
| D5 | 토큰 검증 정본 표: alg allowlist, JOSE·payload `typ`, `kid`, `iss` 정확 일치, `aud` 정확 멤버십(`account` 불가), `azp == client_id`, 서비스 계정 판별(`client_id==azp` AND `preferred_username==prefix+client_id`, `sid` 미사용), scope, `iat`/`exp`/`nbf`/수명 상한. 사람·exchange·lightweight 토큰은 `client_id` 부재로 거부 | alg·prefix 설정화 |
| D6 | v1은 GET 읽기 전용. 비-GET(HEAD 포함)은 scope와 무관하게 거부. 허용 8개, 거부 37개(denylist 36 + `getMe`) | 쓰기는 별도 Class D 패키지 |
| D7 | 즉시 폐기 없음(introspection 없음). 짧은 수명 상한(`MACHINE_TOKEN_MAX_TTL`)과 skew. **긴급 차단은 서버측 allowlist 제거/기능 끄기 + 모든 replica 교체**이고 Keycloak client 비활성화는 이미 발급된 토큰을 폐기하지 않는다(실측) | introspection(후속) |
| D8·D15 | JWKS는 fail closed·커스텀 KeySet·조회 예산 게이트·stale-if-error, issuer/JWKS는 https만(로컬 테스트 예외 env+WARN), 전용 HTTP client(5s·리다이렉트 금지·1 MiB·키 20개) | 캐시·간격 설정 범위 조정, 내부 CA 번들(후속) |
| D9 | 남용 제한 순서: 문법 → IP 실패 throttle(**서명·JWKS 이전**) → 전역 인증 동시성 → 검증 → 검증된 client 예산 → 전역 LDAP 슬롯. 모든 상태에 상한. 한도는 replica별 | 공유 limiter는 ingress 계층 |
| D10 | 감사: `Authorization`을 실은 요청은 핸들러에 도달하는 한 정확히 한 줄(`event=machine_access`), actor는 검증된 client id만, 닫힌 reason enum, 토큰·원문 오류 미기록 | 별도 감사 저장소(후속) |
| D11·D12 | 머신 인증은 UI 인증 모드와 독립(issuer는 명시, 비면 SSO issuer 상속), 기본 꺼짐. 꺼지면 어떤 `MACHINE_*`도 읽지 않는다 | 플래그 한 줄 |
| D13·D14 | OpenAPI `securitySchemes.machineBearer`와 8개 오퍼레이션만의 `security`·`x-machine-scope`(additive). 런타임 deny-by-default 가드. 민감 base 경계: 머신의 `getEntry`/`listTree`는 `LDAP_BASE_DN` 밖(accesslog·config·Monitor 포함) 403, `audit.read` 없으면 `getMonitor`가 accesslog를 읽지 않음 | client별 subtree allowlist(별도 패키지) |
| D16 | 머신 cursor는 `HMAC("machine:"+len(iss)+":"+iss+client_id)`에 묶는다(임시 세션 ID 미사용) | 별도 cursor 키 |
| D17–D24 | 구현 중 확정: HEAD는 비-GET처럼 거부, `aud=account` 거부, 쉼표 결합 DN 목록의 RDN run 충돌 거부, refresh당 단일 5s deadline, `listTree` 자식 1000개 초과 422, DN 가드는 연결 이전, 머신 실패는 503, deadline은 ctx에 있을 때만 | — |
| D25 | **핸들러 이전에 Go HTTP 서버가 거절한 요청(431, 잘못된 요청 줄, 헤더 timeout, TLS·HTTP/2 사전 오류)은 감사·접근·오류 로그 어디에도 남지 않는다.** 서버 계층 훅은 `Authorization`을 볼 수 없어 오해를 부르는 줄만 만들기 때문에 만들지 않는다 | 기록이 필요하면 ingress/프록시 접근 로그 |
| D26–D29 | ACL 증명에서 확인: 비밀 속성 목록 8개, `cn=admin,cn=config` simple bind로 ACL 적용, 검색은 `B` 안에서 시작해야 함, 비밀번호 증명은 삭제+추가 형태(`pwdSafeModify`), `pwdLockout`으로 잘못된 bind 비밀번호가 계정을 잠금 | — |
| D30 | **미해결**: 머신 ACL은 `LDAP_REPLICATION_IDENTITY=prepare`와 함께 쓰지 않는다(`prepare`는 규칙이 `{0}`이어야 하고 머신 규칙이 `{0}`–`{2}`를 차지). 확인된 공존 순서는 복제 규칙 `{0}` + 머신 규칙 `{1}`–`{3}`이며 구현은 TASKS T-034 | T-034 |

## Compatibility and rollback

- 기본 꺼짐. 꺼진 상태에서 기존 경로·응답·쿠키·세션 모델은 바이트 단위로 같고(차트 렌더도 동일), OpenAPI는 additive(`machineBearer`, `x-machine-scope`)이며 오류 코드는 append-only(`token_invalid`, `token_expired`, `scope_denied`, `machine_rate_limited` 추가)다.
- 롤백: `MACHINE_AUTH_ENABLED=false`(Helm `ui.machineAuth.enabled=false`)로 재배포하고 모든 replica 교체와 이전 pod 0개를 확인한다. 영속 데이터가 없다. 절차: [machine-auth-operations.md](../../machine-auth-operations.md).
- `auth-provider-policy`는 로그인 provider 정책이며 불변이다. 머신 bearer는 세션·쿠키를 만들지 않는 별도 인바운드 인증으로 §6에 예외를 명시한다.

## Not verified

- 이 ADR 작성 시점에 **실제 Keycloak을 띄운 라이브 e2e(AC-001–AC-011, AC-015·AC-017, 양·음성 토큰, 키 회전·폭주, 긴급 차단 드릴)는 병합되지 않았다**(단위 5a). 토큰 거동은 EVIDENCE §2의 실제 Keycloak 26.7.4 관측과 단위 테스트(실제 서명 검증기·로컬 JWKS)에 근거한다.
- 다중 노드·복제·Kubernetes에서의 ACL 적용, 실제 프록시 뒤 XFF 위조, 실제 클러스터 설치는 실행하지 않았다.
- 공유 client scope에 audience mapper를 둔 경우의 SSO 토큰 오염은 실행하지 않았다.
