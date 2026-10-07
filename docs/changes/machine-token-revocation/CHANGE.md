# Change: 발급된 머신 토큰의 즉시 폐기와 대체 자격 증명(introspection·API 키·mTLS) 평가

- Change class: `D` — 인증 경계의 자격 증명 검증 규칙 변경(폐기 의미 추가), 신규 영속 상태(폐기 항목)와 LDAP 항목 의미 추가, 신뢰 경계(IdP 의존 또는 디렉터리 의존) 결정
- Owner: 미지정 — 수용 전 지정 필요
- Related issue: [#286](https://github.com/dasomel/ldapium/issues/286)(열림; 후속 구현 PR이 모든 범위를 덮기 전에는 닫지 않음). 선행: [#214](https://github.com/dasomel/ldapium/issues/214) [machine-principal-auth](../machine-principal-auth/CHANGE.md)의 비목표 "토큰 introspection·즉시 폐기, 분산 rate limit"(같은 문서 49행)
- Status: `Proposed (2026-10-07; 설계 제안, 미수용; 구현 없음)` — 이 문서는 **결정 제안과 열린 질문**이다. 수용 표시는 유지보수자만 한다.
- Accepted by / date: 미수용
- 작성일: 2026-10-07 (main `b0ada28` 기준 코드 읽기; Keycloak 라이브 실험은 하지 않았다 — "검증 상태" 절)

> 이 패키지는 코드 변경이 없다. 형식은 [machine-principal-auth](../machine-principal-auth/CHANGE.md)를 따르며(Problem → Requirements → 대안 비교 → 결정 D1… → 위협 모델 → 검증 계획 → 열린 질문),
> 결정 ID(D1…)는 이 패키지 안에서만 유효하다(부모 패키지의 D7 등은 "부모 D7"로 적는다).

## Problem

ldapium은 Keycloak이 발급한 access token을 **오프라인으로** 검증한다(서명·claim만; 토큰·secret 미저장, 부모 D1). 그 결과 한 번 발급된 토큰은 만료될 때까지 폐기할 수 없다.

- 검증기는 `iss`·`aud`·`azp`·SA 판별·`scope`·`iat`/`exp`/`nbf`/수명 상한만 본다(`ui/backend/internal/machineauth/claims.go:76-145`). 토큰 식별자 `jti`는 어디에서도 읽지 않는다(`grep -rn jti ui/backend/internal/machineauth/*.go ui/backend/internal/httpapi/machine*.go` 비테스트 결과 0건; `Principal`은 `ClientID`·`Scopes`·`SubjectHash`·`Expiry`뿐, `claims.go:59-64`).
- 만료 판정은 `now > exp + skew`(`claims.go:141`), 수명 상한은 `exp - iat ≤ MACHINE_TOKEN_MAX_TTL`(`claims.go:129`; 기본 10분, 범위 (0,1h] — `config/machine.go:161`), skew 기본 30 s(0–60 s; `config/machine.go:162`). 따라서 유출된 토큰의 최대 노출은 **남은 수명 + skew**, 최악 1시간+60초다.
- Keycloak client를 비활성화하거나 secret을 회전해도 이미 발급된 토큰은 검증을 통과한다(실제 Keycloak 26.7.4 관측: [부모 EVIDENCE §2.7](../machine-principal-auth/EVIDENCE.md)). 막히는 것은 새 토큰 발급뿐이다.
- 현재의 유일한 긴급 차단은 `MACHINE_ALLOWED_CLIENTS`에서 client를 빼거나 기능을 끄고 **모든 replica를 교체**하는 것이다(v1은 설정 리로드가 없다; [machine-auth-operations.md §2](../../machine-auth-operations.md), 부모 D7·REQ-018). 롤아웃이 필요하고, 전 replica 교체 확인 전에는 일부 replica가 여전히 토큰을 받는다.
- 이슈 #286이 요구하는 것: (1) 즉시 폐기 수단(introspection 또는 공유 denylist)을 평가·결정, (2) 부모 패키지가 구현하지 않은 옵션 2(API 키)·3(mTLS) 평가, (3) rate limit을 replica 간 공유할지 결정. 수용 조건은 각 옵션의 비용(핫 패스의 추가 IdP 의존, introspection 장애 시 fail-open/closed)을 적은 ADR과, 구현한다면 "롤아웃 없이 모든 replica에서 명시된 시간 안에 폐기 토큰이 실패함"을 보이는 라이브 드릴이다.

## Intent

운영자가 **롤아웃 없이**, 문서화된 상한 시간 안에, **모든 replica에서** 특정 머신 토큰(또는 한 client의 특정 시각 이전 발급분 전부)을 거부하게 만든다. 방식은 ldapium이 이미 쓰는 오프라인 검증을 유지하고 그 위에 폐기 확인 한 단계를 더하는 것이다. 폐기 저장소는 모든 replica가 이미 의존하는 디렉터리(LDAP)로 제안하고, 저장소 선택은 유지보수자 결정으로 남긴다(Q1). 기능은 기본 꺼짐이며 꺼진 상태에서 동작은 바뀌지 않는다.

## Scope

- In scope(수용 후 구현 시): 폐기 항목 모델(client cutoff, jti), 저장소·갱신·fail-closed 규칙, 검증 파이프라인 훅, 감사 reason, 운영 절차(순서 포함), 설정·Helm 값, 단위·계약·라이브 드릴, 문서.
- Affected(예상): `ui/backend/internal/machineauth`(jti 파싱, 폐기 스냅샷 순수 로직), `ui/backend/internal/httpapi/machine.go`(`serve` 훅, 갱신 루프), `internal/config/machine.go`, `charts/ldapium`(`ui.machineAuth.revocation.*`), `docs/machine-auth-operations.md`·`docs/audit-event-schema.md`·`docs/machine-ldap-account.md`, `scripts/test/test-machine-revocation-drill.py`.
- 대상: 운영자, 보안 검토자, 머신 API 소비자(응답 코드는 기존 401 `token_invalid` 그대로).

## Non-goals

- 쓰기·백업 등 머신 scope 확장([#285](https://github.com/dasomel/ldapium/issues/285)), 사람 세션 폐기(쿠키 경로 불변).
- API 키(옵션 3 아래 표의 C)와 mTLS 바인딩 토큰(D)의 **구현**. 이 패키지는 평가와 채택 조건만 기록한다(D9, D10).
- Keycloak 쪽 기능(not-before 푸시, 폐기 엔드포인트)에 의존하는 설계. 필요하면 별도 실험 후 후속(검증 상태 참조).
- 폐기 항목을 쓰는 HTTP API·UI(쓰기 경로 추가는 Class D 별도 패키지). v1 쓰기는 운영자가 `ldapadd`로 한다(Q4).
- replica 간 공유 rate limit 구현(D11은 "변경 없음"을 제안).

## Requirements

- `REQ-001` — 폐기된 토큰은 **롤아웃 없이**, `MACHINE_REVOCATION_REFRESH` + 조회 지연(+ LDAP 복제 지연) 안에 **모든 replica**에서 401이 된다. 이 상한을 문서와 드릴이 같은 수식으로 적는다.
- `REQ-002` — 두 폐기 단위를 지원한다: (a) client cutoff(그 client의 `iat ≤ T + MACHINE_CLOCK_SKEW`인 모든 토큰; T는 **디렉터리 서버가 항목 생성 시 찍은 시각**, D7), (b) 개별 `jti`(항목이 토큰의 `exp`를 싣는다). (a)는 항목 수가 토큰 수와 무관하다. (b)의 정리는 `exp + skew + REFRESH + MAX_STALE` 이후에만 허용하고, 정리는 항목을 쓰는 첫 단위의 도구가 수행한다(REQ-012).
- `REQ-003` — 폐기 저장소를 읽지 못하면 **fail closed**다: 스냅샷이 `MACHINE_REVOCATION_MAX_STALE`보다 오래되면 모든 머신 요청이 503(`unavailable`, `Retry-After`)이고, 최초 스냅샷 전에도 같다. 허용 폴백 없음.
- `REQ-004` — 폐기 확인은 서명·claim 검증 **이후**, 검증된 client 예산 획득 **이전**에 수행한다(부모 D9 순서 유지). 폐기 판정은 IP 실패 throttle에 실패로 센다(부모 `tk.fail()` 경로, `machine.go:319`).
- `REQ-005` — 기능 꺼짐(기본)에서 요청·응답·감사·OpenAPI는 기존과 동일하다. 켜면 새 외부 응답 코드는 없다(401 `token_invalid`·503 `unavailable` 재사용; 응답 본문은 어느 규칙이 실패했는지 말하지 않는다 — 부모 D10). 감사 reason에 `revoked`(와 jti 필수 시 `jti`)를 닫힌 집합에 추가한다.
- `REQ-006` — 폐기 항목은 자격 증명이 아니다: 토큰 원문·서명·secret을 저장하지 않는다(`jti`와 client id, 시각, 사유 메모만). 부모 REQ-014 유지(ldapium은 토큰·client secret을 저장하지 않는다). 폐기 저장소 읽기는 기존 머신 bind를 재사용하므로 새 자격 증명이 없다.
- `REQ-007` — 모든 상태 크기에 상한(항목 수, 항목 크기, 갱신 응답 크기)을 둔다. 상한 초과·형식 오류 항목은 해당 갱신을 실패로 취급하고 직전 스냅샷을 `MAX_STALE`까지만 유지한다(fail closed, D6).
- `REQ-008` — 폐기 갱신은 요청 경로에서 LDAP 호출을 늘리지 않는다: replica당 `REFRESH`마다 단일 비행 조회 1회, 요청당 비용은 메모리 조회 2회.
- `REQ-009` — 기존 allowlist·ceiling·scope 모델(부모 D3)과 긴급 차단 절차(allowlist 제거 + 전 replica 교체)는 그대로 유효하며 폐기 목록은 그 **앞의 빠른 수단**이다. 폐기 항목 때문에 새로 허용되는 요청은 없다(거부만 추가).
- `REQ-010` — 운영 문서는 순서를 강제한다: **Keycloak에서 새 토큰 발급 차단 → 폐기 항목 기록 → 같은 토큰으로 거부 확인**(순서가 뒤바뀌면 재발급 토큰이 cutoff 이후 `iat`로 통과한다. 남는 창은 D7에 명시).
- `REQ-012` — 성장 상한: 항목을 쓰는 도구는 추가 시마다 정리 가능한 jti 항목(위 시점 이후)을 지운다. 상한(`MAX_ENTRIES`)은 **정리 가능 항목을 제외한 활성 항목**에 적용하고, 활성 항목이 상한의 80%를 넘으면 WARN을 남긴다. 상한 초과·응답 크기 초과는 갱신 실패이며 `MAX_STALE` 후 fail closed(AC-004) — 그래서 정리 도구와 경보가 이 상태의 예방책이다.
- `REQ-011` — 라이브 드릴: 2 replica에서 토큰 통과 → 폐기 항목 기록 → 두 replica 모두 상한 시간 안에 401, 컨테이너 ID 불변(재시작·교체 없음), LDAP 중지 시 `MAX_STALE` 이후 503, 항목 제거 후 새 토큰은 통과.

## Acceptance scenarios

### `AC-001` — jti 폐기가 모든 replica에서 상한 시간 안에 적용됨
- Given 폐기 기능 켬, replica A·B, client `machine-a`의 유효 토큰 T(두 replica 모두 200).
- When 운영자가 T의 `jti` 폐기 항목을 디렉터리에 추가한다.
- Then `REFRESH + 조회 지연` 안에 A·B 모두 T에 401(`token_invalid`, 감사 `reason=revoked`). 두 replica의 컨테이너 ID·시작 시각이 불변이다. 같은 client의 다른 토큰 T2는 200.
- 증거: 드릴 로그(요청 시각 표), 상한 수식과 실측 최대 지연.

### `AC-002` — client cutoff
- Given client `machine-a`의 토큰 T1(iat=t1), 이어 T2(iat=t2>cutoff).
- When 운영자가 발급 차단 확인 후 cutoff 항목을 추가한다(T=서버가 찍은 `createTimestamp`, t1 < T < t2 - skew).
- Then T1 401(`revoked`), T2(발급 시각이 T+skew 이후) 200, 다른 client 토큰 200. 경계: `iat == T+skew`는 거부, `iat == T+skew+1`은 허용(T는 항목의 `createTimestamp`, 운영자 시각이 아님).

### `AC-003` — 폐기 저장소 장애는 fail closed
- When 디렉터리를 중지/차단한다.
- Then `MAX_STALE` 전에는 직전 스냅샷으로 판정(폐기된 토큰은 계속 거부), 이후 모든 머신 요청 503 `unavailable`+`Retry-After`(허용 아님). 복구 후 `REFRESH` 안에 정상화. 최초 스냅샷 전 기동 직후에도 503.

### `AC-004` — 잘못된/과대 항목
- When 형식 오류 항목, 항목 수 상한 초과, 응답 크기 초과가 생긴다.
- Then 해당 갱신은 실패(ERROR 로그, 카운터), 직전 스냅샷은 `MAX_STALE`까지만 유지, 그 뒤 503. 항목을 고치면 다음 갱신에서 복구. 어떤 경우에도 폐기 항목이 **무시되어 통과**되지 않는다.

### `AC-005` — 기본 꺼짐·호환
- 폐기 기능을 켜지 않은 배포의 기존 단위·계약·e2e·드릴이 무변경 통과. 켠 배포에서도 폐기 항목이 없으면 기존 허용/거부 결과가 동일(`TestMachine_*` 회귀).

### `AC-006` — 감사·비노출
- 폐기 거부는 `event=machine_access` 한 줄, `result=failure`, `reason=revoked`, actor는 검증된 client id. 폐기 항목 원문·토큰·서명 조각은 로그·응답에 없다(전 컨테이너 로그 secret scan 0건).

### `AC-007` — 긴급 차단 절차 호환
- 폐기 항목 없이 기존 절차(allowlist 제거 + 전 replica 교체, [machine-auth-operations.md](../../machine-auth-operations.md))가 그대로 동작한다. 폐기 기능과 allowlist 제거를 함께 써도 충돌하지 않는다.

## Architecture and decisions

- 관련 문서: [machine-principal-auth CHANGE](../machine-principal-auth/CHANGE.md)(D1·D5·D7·D9·D10·위협 모델), [ADR](../machine-principal-auth/ADR.md), [EVIDENCE §2.7](../machine-principal-auth/EVIDENCE.md), [machine-auth-operations.md](../../machine-auth-operations.md), [machine-keycloak-client.md](../../machine-keycloak-client.md), [machine-ldap-account.md](../../machine-ldap-account.md), [audit-event-schema.md](../../audit-event-schema.md).
- ADR threshold result: `required`(신뢰 경계·자격 증명 수용 규칙 변경). 압축 기록: [ADR.md](ADR.md).
- 현재 요청 경로(코드, 폐기 훅의 위치): `machine.go:284` `serve` → IP 실패 throttle(`admitIP`) → 전역 인증 슬롯(`acquireAuthSlot`) → `verifier.Verify`(`machine.go:303`; JWKS는 `machineauth/keyset.go`, 5 s fetch — `fetch.go:15`) → 실패면 `tk.fail()`(`:319`) → **검증된 client 예산 `budget.acquire`(`:333`)** → scope → LDAP bind(`machine_exec.go:89`, 요청마다) → 핸들러. 폐기 확인은 `Verify` 직후, `budget.acquire` 직전에 들어간다(REQ-004).
- 사실 확인: ldapium UI 서버는 클라이언트용 TLS 리스너가 없다(`ui/backend`의 비테스트 코드에서 `tls.Config`는 LDAP 다이얼 `ldapclient/dial.go:277`뿐; `ListenAndServeTLS`·`ClientAuth` 0건). TLS는 ingress가 종단한다고 전제한다(부모 위협 모델 "TLS 전제").

### 옵션 비교

평가축은 이슈가 요구한 비용(핫 패스 IdP 의존, 장애 시 fail-open/closed)에 부모 REQ-014(토큰·secret 미저장)와 폐기 지연, 운영 부담을 더했다.

| 항목 | A1: introspection(RFC 7662) 요청마다 | A2: introspection + TTL 캐시 | B: 짧은 TTL + 공유 denylist(jti/client cutoff) | C: 해시 저장 API 키 | D: mTLS 바인딩 토큰(RFC 8705) |
|---|---|---|---|---|---|
| 폐기 지연 | IdP 상태 즉시(IdP가 폐기를 아는 한; 아래 미검증) | 캐시 TTL N | `REFRESH`(기본 5 s) + 복제 지연 | 저장소 즉시 + 캐시 | 폐기가 아니라 **탈취 무력화**(개인키 없이는 사용 불가). 키 폐기는 인증서 수명·CRL |
| 핫 패스 추가 의존 | **Keycloak 매 요청**(+RTT, 인증 슬롯 장시간 점유) | Keycloak, 캐시 미스마다 | 없음(요청 경로 무변경; 백그라운드 갱신 1회/`REFRESH`) | 키 저장소 | TLS 종단(ingress) 인증서 전달 |
| IdP/저장소 장애 시 | fail-closed면 **머신 API 전체 정지**, fail-open이면 폐기가 조용히 무효(보안 반대로) | 위와 같되 TTL 동안 완충, 캐시 hit은 영향 없음 | 저장소=디렉터리. 머신 요청은 이미 요청마다 LDAP bind가 필요(`machine_exec.go:89`)라 **새 장애 도메인이 거의 없음**; `MAX_STALE` 후 fail-closed | 저장소 장애=인증 정지 | 인증서 검증은 오프라인 가능, 헤더 위조가 위험 |
| 새 비밀·신뢰 | introspection은 보호 자원 인증을 서버가 요구해야 함(RFC 7662 §4, MUST) → ldapium이 introspection용 **자격 증명을 보유**해야 한다. RFC 7662 §4는 방식을 규정하지 않고("토큰 엔드포인트에서 쓰는 어떤 client 인증 방식이든, OAuth 2.0 bearer 토큰 등" 가능) client secret은 한 예일 뿐이다. Keycloak이 introspection에서 실제로 받는 방식(secret, 서명 JWT, mTLS 등)은 **미검증**(T-001). secret이 아닌 방식(개인키·인증서)이어도 여전히 저장된 비밀이므로 부모 REQ-014 완화가 필요 + `aud`에 있는 resource client 필요(EVIDENCE §2.7: 현 구성의 `machine-a`·`ldapium-sso`는 introspect 불가) | 동일 | 없음(공개 식별자 `jti`·client id) | 키 해시 저장(영속, 복제·백업) + 발급 UX | 신뢰 CA 번들, XFCC 헤더 신뢰(`UI_TRUSTED_PROXIES` 유사 모델 신규) |
| Keycloak 의존 | 높음(핫 패스) | 중간 | 없음(오프라인 검증 유지) | 없음 → Keycloak 없는 배포용 | client 속성 설정 필요(미검증) |
| 비용·구현 | 클라이언트·자격 증명 보관·캐시·회로 차단·테스트 대량 | A1 + 캐시 | 저장소 스키마·ACL 확인·갱신 루프·절차 | 저장·발급·회전·감사 전부 신규(별도 패키지급) | ingress·TLS 구성·헤더 신뢰·cert 수명(별도 패키지급) |
| 폐기 단위 | 토큰·세션 단위(IdP 판단) | 동일 | jti(토큰), client cutoff(client 전체) | 키 id | 인증서 |
| 주요 위험 | IdP 장애=서비스 장애 또는 폐기 무효; 응답 지연이 인증 동시성 상한(부모 D9)을 소진 | TTL 동안 폐기 무효(RFC 7662 §4가 같은 절충을 경고) | 운영자 오기입(fail-closed라 가용성↓), cutoff 시계 오차 | 장기 유효 비밀 유출 | 헤더 위조, 인증서 수명 관리 |
| 권고 | 채택 안 함(D8) | **후속 옵션**(조건부, D8) | **권고(D1–D7)** | 별도 패키지(D9) | 별도 패키지, 탈취 방어용(D10) |

#### B의 저장소 변형

| 변형 | 장점 | 단점 | 폐기 지연 |
|---|---|---|---|
| **B-LDAP(권고)**: `ou=system,<root>` 아래(또는 `BASE_DN` 안) 폐기 항목 | 모든 replica가 이미 의존하는 저장소. 머신 ACL `{1}`이 `B`(기본 `LDAP_BASE_DN` 루트 전체) 읽기를 허용(`docs/machine-ldap-account.md:112`)해 기본 구성에서는 ACL 변경이 필요 없을 수 있음(**확인 필요**, T-002). 복제로 전파. fail-closed가 기존 가용성 모델과 일치 | LDAP 스키마·항목 의미 결정(Class D), `B`를 좁힌 배포는 ACL 조정 필요, 다중 provider 복제 지연(add-only·고유 RDN이라 충돌 없음) | `REFRESH` + 복제 지연 |
| B-file: ConfigMap/Secret 또는 마운트 파일 | LDAP 스키마 변경 없음, 구현 단순 | Kubernetes의 마운트 전파는 수십 초~분 단위로 알려져 있음(**미측정**), 파일 변경은 GitOps/배포 경로를 타기 쉬움(롤아웃 없이라는 요구와 충돌 가능), docker/compose는 바인드 마운트 필요 | 마운트 전파 + 폴링 |
| B-HTTP: 별도 폐기 서비스 | 유연 | 신규 서비스·신뢰 경계 | — (채택 안 함) |

### 결정 기록

| ID | 결정 | 이유 | 비용 | 탈출구 |
|---|---|---|---|---|
| D1 | **오프라인 검증을 유지하고 그 위에 폐기 확인을 더한다(옵션 B).** 폐기 저장소는 B-LDAP을 권고하고 최종 선택은 Q1 | 핫 패스에 새 외부 의존이 없고(요청당 메모리 조회), ldapium이 토큰·secret을 저장하지 않는다는 부모 D1·REQ-014를 지키며, 이슈가 요구한 "롤아웃 없이 모든 replica" 상한을 `REFRESH` 하나로 설명할 수 있다 | 운영자가 항목을 직접 써야 하고(Q4), 스키마·ACL 결정이 필요 | 저장소는 `revocation.Source` 한 메서드(스냅샷 반환) 뒤에 두어 B-file로 교체 가능(첫 구현은 구체 타입, 과설계 금지) |
| D2 | 폐기 단위는 **client cutoff**(`iat ≤ T`)와 **jti**. cutoff는 한 client의 모든 기발급 토큰을 한 항목으로 폐기하고, jti 항목은 토큰 `exp`를 `expires`에 싣고, `expires + skew + REFRESH + MAX_STALE`(모든 replica가 그 토큰을 만료로 거부하는 것이 확실해진 뒤)에만 정리 대상 | 유출된 특정 토큰은 jti로, "이 client가 의심스럽다"는 cutoff로 처리. cutoff만으로는 토큰 하나를 지울 수 없고 jti만으로는 토큰을 모를 때 대응 불가 | cutoff는 같은 초에 발급된 정상 토큰까지 거부 가능(`iat` 초 단위, fail closed) | 필요 없으면 jti만 구현(cutoff는 후속 단위) |
| D3 | 폐기 항목 위치·스키마는 새 객체 클래스를 만들지 않는 방향으로 설계하되 **정확한 objectClass/속성은 Q2로 남긴다**(cutoff의 T는 항목의 `createTimestamp`, 즉 디렉터리 서버 시계 — 항목 수정 금지, 변경은 삭제 후 재추가)(T-002에서 이미지 스키마에 실제로 존재하는 후보로 실측). 항목은 `kind`(`client-cutoff`/`jti`), `client`, `value`(T 또는 jti), `expires`, 사유 메모. 토큰·서명·secret 금지(REQ-006) | LDAP 스키마·연산 의미는 AGENTS.md상 설계 변경 | 후보 속성이 없으면 스키마 확장(이미지 변경) 필요 | B-file로 전환 |
| D4 | 갱신: replica당 `MACHINE_REVOCATION_REFRESH`(제안 기본 5 s, 범위 1–60 s)마다 머신 bind로 단일 비행 subtree 조회 1회, 메모리 스냅샷을 원자적으로 교체. 요청 경로는 스냅샷만 읽는다. 항목 수 상한 `MACHINE_REVOCATION_MAX_ENTRIES`(제안 10000), 응답 1 MiB 상한 | 요청당 LDAP 호출 증가 0, 상한은 부모 D9·D15의 "모든 상태에 상한" 원칙 | 5 s 주기 조회가 모든 replica에서 계속 발생(부하 미미: 1 조회/5 s/replica, 미측정) | 주기·상한 설정 범위 조정 |
| D5 | 폐기 거부는 기존 응답 재사용: 401 `token_invalid`(+`WWW-Authenticate`), 본문은 사유 비노출. 감사 reason `revoked` 추가(`jti` 필수 위반은 reason `jti`). 새 오류 코드 없음 | 부모 D10(본문은 실패한 규칙을 말하지 않음), api-error-envelope D218-14(새 코드는 표·골든·OpenAPI enum 동시 갱신)를 피한다 | 클라이언트가 "폐기"와 "무효"를 구분 못 함(의도) | 별도 코드가 필요하면 envelope 절차로 추가 |
| D6 | **fail closed**: 스냅샷 나이 > `MACHINE_REVOCATION_MAX_STALE`(제안 기본 `3×REFRESH`=15 s, 범위 `REFRESH`–10 m) 또는 최초 스냅샷 전이면 모든 머신 요청 503 `unavailable`+`Retry-After`. 형식 오류·상한 초과 항목은 갱신 실패로 취급(직전 스냅샷은 `MAX_STALE`까지만). 어떤 항목도 "무시하고 통과"하지 않는다 | (1) 머신 요청은 이미 LDAP bind에 의존하므로(`machine_exec.go:89-94`: bind 실패 503, 폴백 없음) 디렉터리 장애는 어차피 서비스 정지라 가용성 비용이 작다. (2) fail-open이면 폐기를 원하는 바로 그 사고 시점(장애·공격)에 폐기가 조용히 무효가 된다. 부모 REQ-008의 fail-closed 원칙과 같다 | 오기입한 항목 하나가 `MAX_STALE` 후 머신 API 정지(운영자 오류 비용) — 탈출구가 필요 | `MACHINE_REVOCATION_MODE=fail-open`은 **만들지 않는다**(Q3에서 유지보수자가 요구할 때만 별도 결정); 항목 삭제로 복구 |
| D7 | **cutoff 의미(서버 시계 기준)와 운영 순서.** cutoff 항목의 시각 T는 운영자가 쓰지 않고 **디렉터리 서버가 항목 생성 시 찍는 `createTimestamp`**다(운영자 시계 무관; 다중 provider에서는 항목이 생성된 노드의 시계 — 노드 시계 오차는 NTP 전제). 판정은 `iat ≤ T + MACHINE_CLOCK_SKEW`(여기서 skew는 **발급자(IdP)와 디렉터리/ldapium 시계 사이의 허용 오차** — 부모 `claims.go:122`가 같은 skew를 서버↔발급자 오차에 쓰는 것과 같은 가정이며 운영자 시계와는 무관). 순서: ① Keycloak에서 client 비활성화/secret 회전 후 **실제로 새 토큰 발급이 거부되는지 확인**(예: `client_credentials` 요청이 401) → ② 폐기 항목 기록 → ③ 사전 확보 토큰으로 401 확인 → ④ 백스톱: allowlist 제거 + 전 replica 교체. **남는 창(명시)**: (i) 발급 차단이 IdP 전 노드에 전파되기 전에 발급된 토큰은 ②보다 `iat`가 앞서므로 폐기되지만, 차단이 ①의 확인 이후에도 일부 노드에서 새지 않는다는 보장은 Keycloak 클러스터 거동에 달려 있다(미검증) → ①의 확인을 2회 이상 반복; (ii) IdP↔디렉터리 시계 오차가 `MACHINE_CLOCK_SKEW`보다 크면 `iat`가 T보다 뒤인 사고 토큰이 통과할 수 있다(NTP 전제 위반); (iii) 요청이 발급 차단 전에 시작돼 응답을 늦게 받아도 토큰의 `iat`는 발급 시각이라 `iat ≤ T`로 폐기된다 — 이 경우는 창이 아니다; (iv) 정상 토큰이 `T ~ T+skew` 사이에 발급되면 과폐기(fail closed, 새 토큰으로 해소). 창 (i)·(ii)가 받아들일 수 없으면 jti 폐기(알려진 토큰)와 백스톱을 병행 | cutoff는 "IdP 발급 차단 확인"이라는 절차 의존을 가진다 | skew만큼 정상 토큰 과폐기(fail closed) | 과폐기는 새 토큰으로 해소, jti 폐기 병행 |
| D8 | **introspection은 채택하지 않는다(v1).** A2(캐시)는 후속 옵션이며 채택 조건: (a) Keycloak이 SA 토큰의 폐기 상태를 introspection에 실제로 반영함을 라이브로 확인(T-001), (b) introspection 자격 증명(secret 또는 키/인증서) 보관을 허용하는 REQ-014 완화 결정, (c) fail-closed 정지 비용을 유지보수자가 수용. A1(매 요청)은 고려하지 않는다 | 핫 패스 IdP 의존, introspection 자격 증명 보관 필요(RFC 7662 §4: 인증 서버는 보호 자원의 인증을 MUST 요구하되 방식은 규정하지 않음; 비-secret 방식의 Keycloak 지원은 미검증), 인증 슬롯 점유, 폐기 상태의 Keycloak 반영 여부가 미검증(EVIDENCE §2.7은 호출 client가 `aud`에 없으면 `active:false`만 관측했고 `active:true` 경로·비활성화 후 상태는 실행하지 않았다, §2.8) | B 대비 IdP 독립성을 잃는다 | D1의 `Source` 인터페이스에 introspection 구현을 후속으로 추가 가능 |
| D9 | **API 키(C)는 이 패키지에서 구현하지 않는다.** 채택 조건: Keycloak 없는 배포의 실제 수요(부모 Q1 결정 유지) | 신규 영속 비밀 저장(해시), 발급·회전·감사 UX 전부 신규. 즉시 폐기는 쉽지만 새 자격 증명 클래스를 도입한다(부모 대안표 "옵션 2") | Keycloak 없는 소규모 배포는 즉시 폐기 대안이 없다 | 별도 Class D 패키지 |
| D10 | **mTLS 바인딩(D)은 구현하지 않는다.** 이 옵션은 폐기 지연이 아니라 **토큰 탈취 무력화**를 해결한다. 채택 조건: ingress가 클라이언트 인증서를 전달하는 구성의 실제 수요, Keycloak의 인증서 바인딩 토큰(`cnf.x5t#S256`, RFC 8705 §3.1) 지원 라이브 확인(미검증), 헤더 신뢰 모델 결정 | 앱에 TLS 리스너가 없어 ingress 종단+헤더 신뢰가 필요(위 사실 확인), 위조 위험은 `UI_TRUSTED_PROXIES` 수준의 별도 설계 | 탈취 위협의 근본 방어는 미룸 | B와 병행 가능(독립 직교) |
| D11 | **분산 rate limit은 변경하지 않는다.** 한도는 replica별(부모 D9)이며 공유 limiter는 ingress 계층 책임이다. 폐기 저장소(LDAP)를 limiter 공유에 재사용하지 않는다 | 요청 경로에 쓰기·원자 연산이 들어가면 LDAP 부하·fail 모드가 달라진다. 이슈의 둘째 항목은 "결정"만 요구 | replica 수 × 한도만큼 총량이 늘어남(문서화됨: operations §5 4항) | ingress rate limit 사용, 필요 시 별도 이슈 |
| D12 | 기본 꺼짐: `MACHINE_REVOCATION_ENABLED=false`(Helm `ui.machineAuth.revocation.enabled`). 머신 인증이 꺼져 있으면 무시(활성 시 기동 검증: 값 범위, `MAX_STALE ≥ REFRESH`). 켜면 토큰에 `jti`가 없는 경우 거부(`reason=jti`) — Keycloak access token은 `jti`를 싣는다(EVIDENCE §2.1 토큰 샘플의 `jti` 항목, RFC 9068 §2.2는 `jti` REQUIRED) | 폐기를 지정할 수 없는 토큰을 통과시키면 jti 폐기가 우회된다(contractual distrust) | `jti` 없는 IdP 토큰은 거부(설정 오류로 노출) | cutoff-only 모드(`jti` 불요)를 후속으로 분리 가능 |

### 폐기 판정 규칙 (D2·D6 정본)

검증된 `Principal(clientID, iat, jti)`에 대해 순서대로:

1. 스냅샷 없음 또는 `now - snapshot.refreshedAt > MAX_STALE` → 503(D6).
2. `snapshot.cutoff[clientID]`가 있고 `iat ≤ cutoff + MACHINE_CLOCK_SKEW`(cutoff=항목 `createTimestamp`) → 401 `revoked`.
3. `snapshot.jti` 집합에 `jti`가 있음 → 401 `revoked`.
4. 그 외 통과(기존 파이프라인 계속).

jti 항목은 `now > expires + MACHINE_CLOCK_SKEW + REFRESH + MAX_STALE`일 때만 스냅샷 구성에서 건너뛴다(검증기는 `now > exp + skew`에서 만료로 거부하므로 `claims.go:141` 그 경계 이전에는 항목이 필요하고, 뒤의 `REFRESH + MAX_STALE`는 replica별 스냅샷이 최악으로 늦은 경우의 여유). 건너뛰는 것과 서버에서 지우는 것은 별개이며 지우기는 REQ-012의 도구 책임이다.

### 위협 모델 (이 패키지가 다루는 부분)

| 위협 | 시나리오 | 통제 | 잔여 위험 |
|---|---|---|---|
| 토큰 탈취 후 노출 지속 | 유출된 bearer가 남은 TTL(최대 1h+skew) 동안 유효, 비활성화로 안 막힘 | jti/cutoff 폐기(D1–D2), 상한 `REFRESH`+복제 지연(REQ-001), 기존 allowlist 제거 백스톱 | 상한 시간 동안의 노출(기본 수 초), 폐기 사실을 모르는 탈취(탐지는 감사 로그 몫) |
| 폐기 우회(재발급) | 공격자가 secret도 가졌다면 폐기 후 새 토큰 발급 | D7 순서: 발급 차단 먼저 | 운영자가 순서를 어기면 우회됨 — 문서·절차 점검표로 완화 |
| 폐기 저장소 위조·변조 | 머신 계정이 폐기 항목을 쓰거나 지움 | 머신 bind는 읽기 전용(부모 D4·AC-018), 항목 쓰기는 관리자만 | 관리자 권한 탈취는 이 설계 밖 |
| 저장소 장애를 이용한 우회 | 디렉터리를 막아 폐기 판단을 무력화 | fail closed(D6): 막으면 서비스 정지이지 우회가 아님 | 가용성 공격은 가능(부모의 LDAP 의존과 동일) |
| 오기입으로 인한 자기 정지 | 형식 오류 항목이 갱신을 실패시킴 | 갱신 실패 시 `MAX_STALE`까지 직전 스냅샷 유지, ERROR 로그·카운터, 항목 삭제로 복구 | 운영자 오류의 가용성 비용 수용 |
| 정보 노출 | 머신 `getEntry`/`listTree`가 폐기 항목을 읽을 수 있음(`B` 안) | 항목에는 jti·client·시각·메모만(자격 증명 아님, REQ-006), 필요하면 `B` 밖 위치+전용 ACL | 폐기된 jti 목록이 `B` 안에서 읽힘(저위험) — Q2 |
| 시계 오차 | 발급자 `iat`와 디렉터리가 찍은 T의 시각 차 | T는 서버 시계(D7), `iat ≤ T+skew`, 경계 테스트(AC-002) | 오차가 skew를 넘으면 미폐기 가능 — D7의 남는 창 (ii), NTP 전제 |

### 장애 모드 요약 (fail-closed vs fail-open)

| 상황 | A1/A2 introspection | B(권고) |
|---|---|---|
| IdP(Keycloak) 중지 | fail-closed: 전체 정지(A2는 TTL 동안 hit만 통과) / fail-open: 폐기 무효(Keycloak 중지가 폐기 우회 수단이 됨) | **영향 없음**(JWKS 캐시·stale 규칙은 부모 D8 그대로) |
| 디렉터리(LDAP) 중지 | 영향 없음(단 머신 요청 자체가 bind 실패로 503) | 어차피 머신 요청 503. 폐기 확인은 `MAX_STALE`까지 스냅샷 사용 후 503 |
| 폐기 저장소만 비정상(항목 오류) | — | 갱신 실패 → `MAX_STALE` 후 503(D6) |
| 저장소가 느림 | 인증 슬롯 점유 → 부모 D9 전역 인증 동시성 상한 소진 | 요청 경로 영향 없음(백그라운드 갱신, 5 s 조회 예산) |

**제안 방향**: 폐기를 목적으로 도입하는 확인은 fail-open일 수 없다. B는 요청 경로를 건드리지 않으므로 fail-closed의 비용이 작다. A는 fail-closed의 비용이 큰 반면 fail-open은 목적을 무너뜨린다 — 이것이 A를 후속으로 미루는 가장 큰 이유다.

## Change impact

| Area | Impact / evidence needed |
|---|---|
| Source / API / command | `machineauth`(jti 파싱·`Principal` 확장·순수 폐기 스냅샷), `httpapi/machine.go` `serve` 훅·갱신 고루틴, `config/machine.go` 신규 env. 외부 API 계약 불변(401/503 재사용) |
| Dependencies / lockfiles | 신규 의존성 없음 목표(LDAP 클라이언트·go-ldap 재사용) |
| Runtime / toolchain | N/A |
| CI / CD | 기존 `machine bearer auth (real Keycloak)` job에 폐기 드릴 확장(단위 5); 신규 release 필수 job 없음(기존 job 이름 유지) |
| Release / packaging | 기본 꺼짐; 차트 값 추가, 릴리스 노트 |
| Generated output | `openapi.json` 변경 없음(응답 코드 재사용). 감사 스키마 문서 reason 추가 |
| Security / supply chain | 신규 영속 상태(폐기 항목)와 신뢰 입력(디렉터리 → 인증 결정). security-reviewer·Codex 독립 검토 필요(부모와 같은 Class D 절차) |
| LDAP / image | 후보 속성이 이미지 스키마에 없으면 `image/` 변경 → `.agents/skills/ldapium-directory-change/SKILL.md` 로드 필수. 머신 ACL `{1}`의 `B` 범위 확인(T-002) |
| Offline / air-gap | 영향 없음(Keycloak 추가 접근 없음) |
| Documentation / operations | `docs/machine-auth-operations.md`(1절 "즉시 폐기 없음"을 폐기 기능 유무에 따라 분기), `audit-event-schema.md`, `machine-ldap-account.md`, Helm README |
| Portfolio / downstream | 다운스트림 SDK 없음(부모 T-003 결과) |

## Verification plan

| Acceptance ID | Verification method | Environment | Expected evidence |
|---|---|---|---|
| `AC-001` | 라이브 드릴 확장: 2 replica, 토큰 통과 → 항목 추가 → 두 replica 401, 컨테이너 ID 불변 | docker compose(Keycloak 고정 태그 + slapd + UI 2개) | 시각 표, 최대 지연 ≤ 상한 수식 |
| `AC-002` | 단위(순수 스냅샷 판정, `iat == T`·`T+1`·skew 경계) + 라이브 | go test; 드릴 | 경계 표 |
| `AC-003` | 단위(fake clock: refresh 실패 시퀀스, `MAX_STALE` 경계, 최초 스냅샷 전) + 드릴(slapd 중지) | go test; 드릴 | 200/401/503 표, `Retry-After` |
| `AC-004` | 단위(형식 오류·상한 초과·크기 초과 소스) + 라이브 1건 | go test; 드릴 | "무시되어 통과" 0건 |
| `AC-005` | 기존 `go test ./...`·계약 테스트·기존 드릴(c)·e2e 무변경 + 꺼짐에서 새 env 미독출 | CI | 회귀 통과, 변이 시험 |
| `AC-006` | 단위(감사 한 줄·reason enum) + 전 컨테이너 로그 secret scan | go test; 드릴 | 줄 수 표, 검색 0건 |
| `AC-007` | 기존 드릴 18 검사 그대로 통과 + 폐기+allowlist 조합 1건 | 드릴 | 결과 표 |

LDAP wire 코드는 저장소 원칙대로 단위 테스트하지 않고 라이브로 검증한다(AGENTS.md "Testing philosophy"); 갱신 소스는 주입 가능한 함수 경계 뒤의 순수 스냅샷 로직만 단위 테스트한다. 모킹 프레임워크 도입 없음.

## Rollout, rollback and recovery

- Rollout: (1) 수용·ADR → (2) 순수 스냅샷·설정(꺼짐) → (3) 소스·갱신·훅(꺼짐) → (4) Helm·문서 → (5) 라이브 드릴·CI → (6) 스테이징 활성화. 모든 단계 기본 꺼짐. 세부는 [TASKS.md](TASKS.md).
- Rollback: `MACHINE_REVOCATION_ENABLED=false` 재배포(이때 폐기 항목은 무시됨 — 이전 폐기가 풀린다는 점을 문서화; 필요하면 allowlist 제거 병행). 코드 롤백 없이 기능 정지.
- Data recovery: 폐기 항목은 디렉터리 항목이므로 일반 LDAP 백업·복원 대상이다. 항목 삭제로 폐기를 해제한다. 토큰·키는 저장하지 않는다.
- Compatibility/migration: 현행 allowlist 모델과 긴급 차단 절차는 불변(REQ-009). 폐기 기능은 순수 additive이고 기존 배포는 값을 추가하기 전까지 변화가 없다.

## Evidence and durable synchronization

- 증거: [EVIDENCE.md](EVIDENCE.md)(코드 읽기·RFC 확인·미검증 목록). 구현 시 라이브 드릴 로그를 부모 패키지 관례로 추가.
- 지속 회귀 통제: 스냅샷 판정 단위 테스트, 폐기 드릴 CI 편입, 기동 시 설정 검증.
- 동기화할 문서: `docs/machine-auth-operations.md`, `docs/audit-event-schema.md`, `docs/machine-ldap-account.md`, `docs/machine-keycloak-client.md`(순서 안내), 부모 CHANGE의 Non-goals·D7·위협 모델에 후속 링크, [IMPLEMENTATION-STATUS](../../IMPLEMENTATION-STATUS.md).

## 검증 상태 (무엇을 확인했고 무엇을 확인하지 못했는가)

확인함(코드·문서 읽기, 2026-10-07, main `b0ada28`): 폐기 관련 현행 동작과 file:line(위 Problem·Architecture), `jti` 미사용, 요청 경로 순서, 머신 요청의 요청당 LDAP bind, UI 서버에 클라이언트 TLS 리스너 없음, 부모 문서의 비목표·D7·EVIDENCE §2.7.
RFC 원문 확인(rfc-editor.org 텍스트에서 해당 문장 직접 확인): RFC 7662 §4의 캐시 절충 경고(introspection 응답 캐시 시 TTL 동안 stale), RFC 8705의 `cnf`의 `x5t#S256` 확인 방법, RFC 9068의 `jti` REQUIRED, RFC 7009의 access token 폐기 지원 SHOULD. RFC 7662 §4의 "인증 서버는 보호 자원의 인증을 MUST 요구"(내려받은 텍스트 662행 부근)도 직접 확인했다.
**확인하지 못함(추측으로 쓰지 않음)**: (1) Keycloak 26.7.4가 비활성화된 client의 SA 토큰이나 폐기된 토큰에 대해 introspection에서 `active:false`를 돌려주는지(EVIDENCE §2.8: `active:true` 경로 미실행). (2) Keycloak의 not-before 정책·RFC 7009 폐기 엔드포인트가 SA access token에 의미가 있는지. (3) Keycloak의 인증서 바인딩 access token(`cnf.x5t#S256`) 발급 구성. (4) 이미지의 OpenLDAP 스키마에 폐기 항목에 쓸 수 있는 기존 속성이 무엇인지와 기본 머신 ACL이 후보 위치를 실제로 읽게 하는지(Q2, T-002). (5) 5 s 주기 조회의 실제 부하·복제 지연. (6) Kubernetes ConfigMap 마운트 전파 시간(B-file 비교의 근거로만 사용). (1)–(4)는 TASKS의 "Inspect" 단위에서 실측한다.

## Open questions and risks (유지보수자 결정 필요)

| ID | 질문 | 권고(초안) | 영향 |
|---|---|---|---|
| Q1 | 폐기 저장소: B-LDAP / B-file / (후속) introspection 중 무엇으로 시작하나 | B-LDAP | D1·D3, 이미지/ACL 변경 여부, 폐기 지연 모델 |
| Q2 | LDAP 항목의 위치·objectClass·속성(새 스키마 허용 여부), `B`를 좁힌 배포의 ACL 처리, 머신 `getEntry`로 폐기 항목이 읽혀도 되는가 | T-002 실측 후 기존 속성 재사용 우선, 새 스키마는 피함 | Class D 범위, 이미지 변경 |
| Q3 | 저장소 장애 시 fail-closed를 확정하나(fail-open 모드를 아예 두지 않음) | fail-closed 확정, fail-open 모드 없음 | D6, 가용성 비용 수용 |
| Q4 | 항목 쓰기 수단: v1은 운영자 `ldapadd` 문서화만 / 관리자 CLI 스크립트 / 후속 API·UI | 문서+스크립트(`scripts/`), API는 별도 Class D | 운영 부담, 쓰기 경로 추가 여부 |
| Q5 | 폐기 상한 목표: `REFRESH` 기본 5 s·`MAX_STALE` 15 s로 충분한가(요구 SLO가 있나) | 5 s / 15 s | 부하·가용성 비용 |
| Q6 | jti 필수화(없으면 거부)를 켜도 되는가, cutoff-only 모드가 필요한가 | 필수(Keycloak은 jti를 싣는다) | D12 |
| Q7 | introspection(A2)을 후속으로 열어 둘 의사가 있는가, introspection 자격 증명 보관(REQ-014 완화)을 허용하나 | 지금은 보류, 수요 시 별도 결정 | D8 |
| Q8 | API 키(C)·mTLS(D)의 실제 수요가 있는가(Keycloak 없는 배포, 인증서 기반 에이전트) | 수요 확인 전 보류 | D9·D10, 별도 패키지 |
| Q9 | rate limit 공유 여부: 현행 replica별 유지에 동의하나 | 유지(ingress에 위임) | D11 |
| Q10 | cutoff를 디렉터리 `createTimestamp` + skew로 판정하고 남는 창 (i)(ii)를 수용하나, 과폐기를 허용하나 | 수용, jti 폐기·백스톱 병행 | D7 |

위험: Keycloak 쪽 폐기 의미가 미검증이므로 A 계열 결론(D8)은 T-001 결과에 따라 바뀔 수 있다. 저장소(Q1) 결정 전에는 단위 2 이후를 시작하지 않는다.
