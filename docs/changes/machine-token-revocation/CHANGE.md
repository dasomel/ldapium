# Change: 발급된 머신 토큰의 즉시 폐기와 대체 자격 증명(introspection·API 키·mTLS) 평가

- Change class: `D` — 인증 경계의 자격 증명 검증 규칙 변경(폐기 의미 추가), 신규 영속 상태(폐기 항목)와 LDAP 항목 의미 추가, 신뢰 경계(IdP 의존 또는 디렉터리 의존) 결정
- Owner: dasomel (유지보수자)
- Related issue: [#286](https://github.com/dasomel/ldapium/issues/286)(열림; 후속 구현 PR이 모든 범위를 덮기 전에는 닫지 않음). 선행: [#214](https://github.com/dasomel/ldapium/issues/214) [machine-principal-auth](../machine-principal-auth/CHANGE.md)의 비목표 "토큰 introspection·즉시 폐기, 분산 rate limit"(같은 문서 49행)
- Status: `Accepted (2026-10-07, design direction decided by the maintainer; T-005 security gate passed on the Revision 5 review: no BLOCKER; Revision 6 folds in the non-blocking points)` — 수용은 설계 방향(Q1–Q10)에 대한 유지보수자 결정이며 보안 검토 관문(T-005)은 Revision 5 검토에서 BLOCKER 없음으로 통과했다. 구현은 TASKS.md 순서를 따른다(기본 꺼짐).
- Revision 2 (2026-10-07): T-001–T-004 실측 반영 — 미검증 문구를 [EVIDENCE.md](EVIDENCE.md) §4–§7의 측정 사실로 교체하고, 결정 **D4**(`MAX_ENTRIES` 기본값과 응답 상한의 모순, 서버 `olcSizeLimit`)를 수정하며 D3·D8·D10에 실측 사실을 적는다. 결정 방향(D1·D2·D6·D8 비채택)은 불변. 수용 표시 아님.
- Revision 3 (2026-10-07): T-005 보안 검토의 BLOCKER 3건(B1 빈·부분 스냅샷 fail-open, B2 운영자가 쓴 `expires`로 인한 조용한 폐기 해제, B3 복제 전제 미검증과 지연 노드) 해결 — **sentinel 항목과 heartbeat 도입(REQ-013)**, 보존 기간을 `createTimestamp` 기반으로 도출(D2), cutoff 변경을 "새 항목 먼저 추가 후 최댓값"으로(D3), 상한 수식·MAX_STALE 하한·크기·질의 형태(D4), 정보 노출 축소(REQ-006), 2노드 복제 실측(EVIDENCE §8, T-004b) 반영. 비차단 8건 포함.
- Revision 4 (2026-10-07): 재검토 BLOCKER B4'(sentinel 건수 N과 서버 측 만료 필터의 충돌 → 조용한 배포의 자기 정지) 해결 — N을 **sentinel `ts` 기준**으로 정의하고 보존 파라미터(`ret`)를 sentinel에 싣는다(REQ-013), heartbeat가 정리와 N 재계산을 맡는다, 2회 읽기 절차(D4). 비차단: `MAX_ENTRIES` 범위를 1–2500으로(1 MiB), 세대 역행 검사는 메모리뿐, 뒤처진 replica의 신선한 heartbeat 노출은 분 단위, UI 관리자 쓰기 거부, 머신 `getEntry`/`listTree` 명시 검사.
- Revision 5 (2026-10-07): 3차 검토 BLOCKER 2건 해결 — B1(건수만으로는 세 번의 읽기가 다른 노드에 닿을 때 폐기를 놓침 → sentinel에 항목 `cn`의 **SHA-256 digest**를 싣고 replica가 읽은 항목으로 재계산, 세 읽기를 **한 연결·한 노드**로 고정), B2(체크·Status 불일치 정리). 비차단: 값 조건부 modify(동시 heartbeat 쓰기 충돌은 실패), heartbeat 없음의 비용과 `init` 단계, sentinel 형식에 `ret`·digest, 조회 속성에 `modifyTimestamp`, replica는 나이로 항목을 건너뛰지 않음(도구가 정리하고 replica는 sentinel 기준으로 셈), 머신 DN의 `createTimestamp` 필터 라이브 확인(EVIDENCE §9), 레이아웃(AC-008·REQ-011 위치).
- Revision 6 (2026-10-07): 4차 검토(BLOCKER 없음) 반영 — T-005 체크, digest 모호성 제거(항목당 `cn` 정확히 1개, 개행 거부, 구분자 `\n`), `objectClass=device` 없는 stray 항목을 도구가 거부·탐지, REQ-006 "거부"로 확정, L4 로드밸런서 노드 교대 한계, rc 16 재시도, `ts`는 정리 뒤에 취함.
- Accepted by / date: dasomel (유지보수자) / 2026-10-07 — 근거: 유지보수자의 Q1–Q10 권고 수락(아래 "Resolved questions")이 설계 방향 수용이며, 보안 검토 관문(T-005)은 BLOCKER이 여러 차례 발견·해결된 뒤 Revision 5 검토에서 BLOCKER 없음으로 통과했다.
- 작성일: 2026-10-07 (main `b0ada28` 기준 코드 읽기; Revision 2에서 main `220f554` 기준 Keycloak 26.7.4·`ldapium` 이미지 라이브 실측 추가 — "검증 상태" 절)

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

- `REQ-001` — 폐기된 토큰은 **롤아웃 없이** 상한 시간 안에 **모든 replica**에서 401이 된다. 상한은 **조건부**다: `REFRESH + 2×L + 복제 지연`(L = 조회 예산 5 s: 갱신이 막 시작된 직후에 쓴 항목은 다음 갱신 시작 + 그 조회 완료를 기다린다), 갱신 실패 중에는 `max(위 값, MAX_STALE)`이며 `MAX_STALE`은 **조회 시작 시각**부터 잰다. 전제: (P1) 쓰기 도구가 정해진 주기로 heartbeat를 올린다(REQ-013), (P2) 모든 replica가 같은 provider 노드를 읽거나 읽기-자기쓰기 일관성이 있고, 노드 간 복제 지연이 `SENTINEL_MAX_AGE`보다 짧다. P1·P2가 깨지면 상한은 성립하지 않고, 뒤처진 노드는 `SENTINEL_MAX_AGE` 안에 fail closed로 드러난다(EVIDENCE §8: 분리된 노드는 rc 0과 오래된 데이터로 응답). 이 상한을 문서와 드릴이 같은 수식으로 적는다.
- `REQ-002` — 두 폐기 단위를 지원한다: (a) client cutoff(그 client의 `iat ≤ T + MACHINE_CLOCK_SKEW`인 모든 토큰; T는 **디렉터리 서버가 항목 생성 시 찍은 시각**, D7), (b) 개별 `jti`(항목은 `exp`를 싣지 않는다 — 운영자가 쓴 값은 신뢰하지 않는다, D2). (a)는 항목 수가 토큰 수와 무관하다. (b)의 정리는 `createTimestamp + MaxTTL + 3×skew + REFRESH + MAX_STALE` 이후에만 허용하고, 정리는 항목을 쓰는 첫 단위의 도구가 수행한다(REQ-012).
- `REQ-003` — 폐기 저장소를 읽지 못하면 **fail closed**다: 스냅샷이 `MACHINE_REVOCATION_MAX_STALE`보다 오래되면 **검증(Verify)을 통과한** 모든 머신 요청이 503(`unavailable`, `Retry-After`)이고, 최초 스냅샷 전에도 같다. 허용 폴백 없음. 이 검사는 `Verify` 뒤에만 하므로 인증되지 않은 호출자는 스냅샷 상태를 탐지할 수 없다(자기 토큰 검증 결과인 401을 받는다).
- `REQ-004` — 폐기 확인은 서명·claim 검증 **이후**, 검증된 client 예산 획득 **이전**에 수행한다(부모 D9 순서 유지). 폐기 판정은 IP 실패 throttle에 실패로 센다(부모 `tk.fail()` 경로, `machine.go:319`).
- `REQ-005` — 기능 꺼짐(기본)에서 요청·응답·감사·OpenAPI는 기존과 동일하다. 켜면 새 외부 응답 코드는 없다(401 `token_invalid`·503 `unavailable` 재사용; 응답 본문은 어느 규칙이 실패했는지 말하지 않는다 — 부모 D10). 감사 reason에 `revoked`(와 jti 필수 시 `jti`)를 닫힌 집합에 추가한다.
- `REQ-006` — 폐기 항목은 자격 증명이 아니다: 토큰 원문·서명·secret을 저장하지 않는다(`jti`와 client id뿐 — 자유 서술 메모는 두지 않는다: 머신 `getEntry`/`listTree`로 읽혀 노출될 수 있으므로 사유는 티켓 등 대역 외에 남긴다). 머신 경로의 `getEntry`/`listTree`는 revocations 서브트리를 API 수준에서 거부하고(기존 BaseDN 가드는 이를 통과시킴), UI 관리자(세션) 쓰기 경로도 이 서브트리의 항목·sentinel 쓰기를 거부한다(T-015: 머신 경로와 UI 관리자 쓰기 경로 모두 API 수준 denylist로 거부, 문서화로 대체하지 않음). 부모 REQ-014 유지(ldapium은 토큰·client secret을 저장하지 않는다). 폐기 저장소 읽기는 기존 머신 bind를 재사용하므로 새 자격 증명이 없다.
- `REQ-007` — 모든 상태 크기에 상한(항목 수, 항목 크기, 갱신 응답 크기)을 둔다. 클라이언트 조회 크기 한도는 `MAX_ENTRIES + 2`(sentinel 포함 +1 여유)이고 서버 `olcSizeLimit`보다 작아야 한다. 상한 초과·형식 오류 항목은 해당 갱신을 실패로 취급하고 직전 스냅샷을 `MAX_STALE`까지만 유지한다(fail closed, D6).
- `REQ-008` — 폐기 갱신은 요청 경로에서 LDAP 호출을 늘리지 않는다: replica당 `REFRESH`마다 단일 비행 조회 1회, 요청당 비용은 메모리 조회 2회.
- `REQ-009` — 기존 allowlist·ceiling·scope 모델(부모 D3)과 긴급 차단 절차(allowlist 제거 + 전 replica 교체)는 그대로 유효하며 폐기 목록은 그 **앞의 빠른 수단**이다. 폐기 항목 때문에 새로 허용되는 요청은 없다(거부만 추가).
- `REQ-010` — 운영 문서는 순서를 강제한다: **Keycloak에서 새 토큰 발급 차단 → 폐기 항목 기록 → 같은 토큰으로 거부 확인**(순서가 뒤바뀌면 재발급 토큰이 cutoff 이후 `iat`로 통과한다. 남는 창은 D7에 명시).
- `REQ-012` — 성장 상한: 항목을 쓰는 도구는 추가 시마다 정리 가능한 jti 항목(위 시점 이후)을 지운다. 상한(`MAX_ENTRIES`)은 **정리 가능 항목을 제외한 활성 항목**에 적용하고, 활성 항목이 상한의 80%를 넘으면 WARN을 남긴다. 상한 초과·응답 크기 초과는 갱신 실패이며 `MAX_STALE` 후 fail closed(AC-004) — 그래서 정리 도구와 경보가 이 상태의 예방책이다.
- `REQ-011` — 라이브 드릴: 2 replica에서 토큰 통과 → 폐기 항목 기록 → 두 replica 모두 상한 시간 안에 401, 컨테이너 ID 불변(재시작·교체 없음), LDAP 중지 시 `MAX_STALE` 이후 503, 항목 제거 후 새 토큰은 통과.
- `REQ-013` — **빈·부분·오래된 스냅샷은 성공이 아니다(sentinel, B1·B3·B4'·Revision 5).** 운영자 도구가 `ou=revocations` 아래에 만드는 sentinel 항목(`cn=sentinel`)은 `serialNumber`=세대(단조 증가 정수), `description`=`entries=<N>;digest=<sha256 hex>;ts=<epoch 초>;ret=<초>`를 싣는다. **`ts` = 도구가 그 쓰기를 한 시각, `ret` = jti 보존 기간(D2 공식), 대상 집합 S = `createTimestamp ≥ ts − ret`인 jti 항목 + 모든 cutoff 항목(sentinel 제외), N = |S|, digest = S의 `cn` 값(정확한 바이트, UTF-8; **항목당 `cn` 값은 정확히 1개이며 개행(`\n`)·널을 포함하면 도구가 쓰기를 거부**하고 replica도 다중값·개행 `cn`을 형식 오류=갱신 실패로 취급)을 바이트순으로 정렬해 구분자 `\n`으로 이어 붙인 문자열(마지막 줄 뒤에도 `\n` 없음)의 SHA-256** — S는 읽는 시각이 아니라 sentinel의 `ts`에 고정되므로 시간이 흘러도 바뀌지 않고, 건수가 같아도 항목 구성이 다르면(예: 항목 Y가 추가되고 X가 삭제됨) digest가 달라진다. **갱신 절차(단일 비행)는 한 번 맺은 연결 하나, 즉 한 노드에서 ① sentinel을 base 읽기 → ② 항목 검색(서버 필터 `(&(objectClass=device)(|(!(cn=jti-*))(createTimestamp≥ts−ret)))`) → ③ sentinel을 다시 읽어 세대가 ①과 같음을 확인(다르면 1회 재시도, 그래도 다르면 실패)** 한다. 연결은 갱신마다 새로 열고 세 읽기 사이에 끊기면 갱신 실패다. LDAP URL이 로드밸런서·라운드로빈 뒤에 있으면 L4(연결 단위)에서는 연결 고정이 노드 고정이 되지만 연산 단위로 노드를 바꾸는 LDAP 인지 프록시는 이 전제를 깨므로 지원하지 않는다(전제 P2). **L4 라운드로빈은 갱신마다 다른 노드에 닿을 수 있어**, 노드 간 지연이 있으면 세대 역행(iii) 실패와 503 깜박임이 생긴다 — replica마다 안정된 노드(고정 provider URL 또는 세션 고정)를 쓰는 것이 요구 사항이며 라운드로빈 URL은 이 한계를 감수하는 구성으로 문서화한다; digest가 다른 노드에서 읽은 경우도 걸러 준다. 다음 중 하나라도 위반하면 **갱신 실패**: (i) sentinel 없음(rc 0이어도: ACL 좁힘·`{n}` 순서 이동·새/뒤처진 노드; 새 배포는 `init`으로 먼저 만든다, T-013), (ii) 읽은 항목의 수 ≠ N 또는 **읽은 항목 `cn`들로 다시 계산한 digest ≠ sentinel의 digest**, (iii) 세대 < 지금까지 본 최대 세대(**스냅샷 역행 금지**; 같은 세대 허용; 이 기억은 **프로세스 메모리뿐이라 재시작하면 사라진다** — 재시작 뒤 첫 갱신은 (iv)의 신선도 검사와 fail-closed 시작(첫 스냅샷 전 503)만이 보호하며, 뒤처진 노드를 읽으면 최대 `SENTINEL_MAX_AGE`만큼의 역행을 받아들일 수 있다), (iv) `ts`가 `SENTINEL_MAX_AGE`(제안 기본 5 m, 범위 30 s–1 h)보다 오래됨 또는 `now + skew`보다 미래, 또는 서버의 sentinel `modifyTimestamp`와 `|modifyTimestamp − ts| > skew + 10 s`(도구 시계를 서버 시계에 묶는다; 머신 DN이 `modifyTimestamp`를 읽는다 — EVIDENCE §9), (v) `ret < 이 replica가 요구하는 보존 기간`(D2 공식을 replica 설정값으로 계산) 또는 `ret`이 1 d 초과(너무 짧으면 폐기가 풀리므로 거부; 길면 안전하므로 sentinel의 `ret`을 쓴다). **replica는 항목을 나이로 건너뛰지 않는다**: 서버 필터가 돌려준 항목은 모두 스냅샷에 넣고 digest로만 검증한다(정리는 도구의 책임). **heartbeat가 정리와 S 재계산을 함께 맡는다**: 주기 도구는 `ts`를 정하고 `createTimestamp < ts − ret`인 jti 항목을 지운 뒤(S에 안 속하므로 순서는 digest에 영향 없음) N·digest·세대·`ts`·`ret`을 쓴다. **sentinel 쓰기는 값 조건부 LDAP modify(옛 `description` 값 delete + 새 값 add)로 한다** — 동시에 도는 두 도구는 한쪽이 `no such value`(rc 16)로 실패하고 조용히 덮어쓰지 못한다(라이브 확인 EVIDENCE §9). 항목을 추가·제거할 때는 항목 먼저, sentinel 나중이며 순간적 불일치는 갱신 실패로 보이되 `MAX_STALE`까지 흡수된다. heartbeat는 `SENTINEL_MAX_AGE`의 1/3 이하 주기(CronJob 등, 운영 문서)이며 조용한 배포에서 항목이 보존 기간을 넘겨도 S가 갱신되므로 정지가 일어나지 않는다. heartbeat가 멈추면 문서화된 fail-closed로 `SENTINEL_MAX_AGE + MAX_STALE`(기본 약 5 m 15 s) 뒤 머신 API가 503이 된다(비용이며 의도). 쓰기 노드는 하나로 두는 것을 권장한다. **도구가 모르는 항목(수동 `ldapadd`로 `objectClass=device` 없이 만든 것 등)은 replica 필터에 안 걸려 조용히 보이지 않는다** — 그래서 도구의 add·heartbeat는 `objectClass` 필터 **없이** `ou=revocations`를 한 번 더 검색해 `device`가 아니거나 형식이 틀린 항목(stray)을 발견하면 쓰기를 거부하고 ERROR로 알린다("무시되어 통과" 방지, AC-004). digest는 도구가 존재한다고 믿는 항목을 센다. 도구의 sentinel 쓰기가 값 조건부 modify로 rc 16을 받으면 읽기부터 다시 계산해 재시도한다(제한 횟수), 그리고 `ts`는 **정리가 끝난 뒤** 취해 긴 정리가 `|modifyTimestamp − ts| ≤ skew + 10 s` 검사를 깨지 않게 한다.

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
- Then `MAX_STALE` 전에는 직전 스냅샷으로 판정(폐기된 토큰은 계속 거부), 이후 모든 머신 요청 503 `unavailable`+`Retry-After`(허용 아님). 복구 후 `REFRESH` 안에 정상화. 최초 스냅샷 전 기동 직후에도 검증을 통과한 요청은 503. 검증을 통과하지 못한 요청은 항상 401(스냅샷 상태가 노출되지 않음).

### `AC-004` — 잘못된/과대 항목
- When 형식 오류 항목(다중 `ou`, 잘못된 접두어), 항목 수 상한 초과, 응답 크기 초과, **rc 0인데 sentinel 없음(빈 응답 포함: ACL 좁힘·뒤처진/새 노드)**, 항목 수 ≠ sentinel의 N, sentinel 세대 역행, sentinel `ts`가 `SENTINEL_MAX_AGE`보다 오래됨(분리된 노드), `ret`가 replica 요구보다 짧음이 생긴다.
- Then 해당 갱신은 실패(ERROR 로그, 카운터), 직전 스냅샷은 `MAX_STALE`까지만 유지, 그 뒤 검증을 통과한 요청은 503. 항목을 고치거나 노드가 따라잡으면 다음 갱신에서 복구. 어떤 경우에도 폐기 항목이 **무시되어 통과**되지 않으며 rc 0이라는 사실만으로 갱신이 성공하지 않는다. 갱신 중 LDAP bind가 실패(rc 49)하면 재시도를 백오프(최소 60 s, 두 배씩 15 m 상한)해 머신 DN의 ppolicy 잠금(기본 5회 실패/900 s)을 피한다.

### `AC-005` — 기본 꺼짐·호환
- 폐기 기능을 켜지 않은 배포의 기존 단위·계약·e2e·드릴이 무변경 통과. 켠 배포에서도 폐기 항목이 없으면 기존 허용/거부 결과가 동일(`TestMachine_*` 회귀).

### `AC-006` — 감사·비노출
- 폐기 거부는 `event=machine_access` 한 줄, `result=failure`, `reason=revoked`, actor는 검증된 client id. 폐기 항목 원문·토큰·서명 조각은 로그·응답에 없다(전 컨테이너 로그 secret scan 0건).

### `AC-007` — 긴급 차단 절차 호환
- 폐기 항목 없이 기존 절차(allowlist 제거 + 전 replica 교체, [machine-auth-operations.md](../../machine-auth-operations.md))가 그대로 동작한다. 폐기 기능과 allowlist 제거를 함께 써도 충돌하지 않는다.

### `AC-008` — 조용한 배포에서 항목이 보존 기간을 넘겨도 정지하지 않음
- Given jti 폐기 항목 1개(N=1)와 heartbeat만 도는 배포.
- When 항목이 `createTimestamp + ret`을 지난다(드릴은 `ret`을 최솟값 근처로 줄여 가속).
- Then heartbeat가 항목을 지우고 N=0·세대 증가로 sentinel을 갱신, replica 갱신은 계속 성공, 머신 요청은 계속 200(503 없음). heartbeat를 멈추면 `SENTINEL_MAX_AGE` 뒤 갱신 실패 → `MAX_STALE` 뒤 503(의도된 fail closed). `ts` 고정 상태에서 시간이 지나도 N 불일치가 생기지 않는다.

## Architecture and decisions

- 관련 문서: [machine-principal-auth CHANGE](../machine-principal-auth/CHANGE.md)(D1·D5·D7·D9·D10·위협 모델), [ADR](../machine-principal-auth/ADR.md), [EVIDENCE §2.7](../machine-principal-auth/EVIDENCE.md), [machine-auth-operations.md](../../machine-auth-operations.md), [machine-keycloak-client.md](../../machine-keycloak-client.md), [machine-ldap-account.md](../../machine-ldap-account.md), [audit-event-schema.md](../../audit-event-schema.md).
- ADR threshold result: `required`(신뢰 경계·자격 증명 수용 규칙 변경). 압축 기록: [ADR.md](ADR.md).
- 현재 요청 경로(코드, 폐기 훅의 위치): `machine.go:284` `serve` → IP 실패 throttle(`admitIP`) → 전역 인증 슬롯(`acquireAuthSlot`) → `verifier.Verify`(`machine.go:303`; JWKS는 `machineauth/keyset.go`, 5 s fetch — `fetch.go:15`) → 실패면 `tk.fail()`(`:319`) → **검증된 client 예산 `budget.acquire`(`:333`)** → scope → LDAP bind(`machine_exec.go:89`, 요청마다) → 핸들러. 폐기 확인은 `Verify` 직후, `budget.acquire` 직전에 들어간다(REQ-004).
- 사실 확인: ldapium UI 서버는 클라이언트용 TLS 리스너가 없다(`ui/backend`의 비테스트 코드에서 `tls.Config`는 LDAP 다이얼 `ldapclient/dial.go:277`뿐; `ListenAndServeTLS`·`ClientAuth` 0건). TLS는 ingress가 종단한다고 전제한다(부모 위협 모델 "TLS 전제").

### 옵션 비교

평가축은 이슈가 요구한 비용(핫 패스 IdP 의존, 장애 시 fail-open/closed)에 부모 REQ-014(토큰·secret 미저장)와 폐기 지연, 운영 부담을 더했다.

| 항목 | A1: introspection(RFC 7662) 요청마다 | A2: introspection + TTL 캐시 | B: 짧은 TTL + 공유 denylist(jti/client cutoff) | C: 해시 저장 API 키 | D: mTLS 바인딩 토큰(RFC 8705) |
|---|---|---|---|---|---|
| 폐기 지연 | IdP 상태 즉시(실측: client·SA 사용자 비활성화, RFC 7009 폐기, not-before 모두 `active:false`로 반영 — EVIDENCE §4.2–§4.4) | 캐시 TTL N | `REFRESH`(기본 5 s) + 복제 지연 | 저장소 즉시 + 캐시 | 폐기가 아니라 **탈취 무력화**(개인키 없이는 사용 불가). 키 폐기는 인증서 수명·CRL |
| 핫 패스 추가 의존 | **Keycloak 매 요청**(+RTT, 인증 슬롯 장시간 점유) | Keycloak, 캐시 미스마다 | 없음(요청 경로 무변경; 백그라운드 갱신 1회/`REFRESH`) | 키 저장소 | TLS 종단(ingress) 인증서 전달 |
| IdP/저장소 장애 시 | fail-closed면 **머신 API 전체 정지**, fail-open이면 폐기가 조용히 무효(보안 반대로) | 위와 같되 TTL 동안 완충, 캐시 hit은 영향 없음 | 저장소=디렉터리. 머신 요청은 이미 요청마다 LDAP bind가 필요(`machine_exec.go:89`)라 **새 장애 도메인이 거의 없음**; `MAX_STALE` 후 fail-closed | 저장소 장애=인증 정지 | 인증서 검증은 오프라인 가능, 헤더 위조가 위험 |
| 새 비밀·신뢰 | introspection은 보호 자원 인증을 서버가 요구해야 함(RFC 7662 §4, MUST) → ldapium이 introspection용 **자격 증명을 보유**해야 한다. RFC 7662 §4는 방식을 규정하지 않고("토큰 엔드포인트에서 쓰는 어떤 client 인증 방식이든, OAuth 2.0 bearer 토큰 등" 가능) client secret은 한 예일 뿐이다. Keycloak 26.7.4가 introspection에서 받는 방식은 실측했다(EVIDENCE §4.1): `client_secret_basic`·`client_secret_post`·`private_key_jwt`·`client_secret_jwt`는 수락, **bearer·무인증은 401**, `tls_client_auth`는 디스커버리에 있으나 실행하지 않음. secret이 아닌 방식(개인키)이어도 여전히 저장된 비밀이므로 부모 REQ-014 완화가 필요 + `aud`에 있는 resource client 필요(EVIDENCE §2.7: 현 구성의 `machine-a`·`ldapium-sso`는 introspect 불가) | 동일 | 없음(공개 식별자 `jti`·client id) | 키 해시 저장(영속, 복제·백업) + 발급 UX | 신뢰 CA 번들, XFCC 헤더 신뢰(`UI_TRUSTED_PROXIES` 유사 모델 신규) |
| Keycloak 의존 | 높음(핫 패스) | 중간 | 없음(오프라인 검증 유지) | 없음 → Keycloak 없는 배포용 | client 속성 설정 필요(실측: `tls.client.certificate.bound.access.tokens=true`, 인증서 없이는 발급 400 — EVIDENCE §4.5) |
| 비용·구현 | 클라이언트·자격 증명 보관·캐시·회로 차단·테스트 대량 | A1 + 캐시 | 저장소 스키마·ACL 확인·갱신 루프·절차 | 저장·발급·회전·감사 전부 신규(별도 패키지급) | ingress·TLS 구성·헤더 신뢰·cert 수명(별도 패키지급) |
| 폐기 단위 | 토큰·세션 단위(IdP 판단) | 동일 | jti(토큰), client cutoff(client 전체) | 키 id | 인증서 |
| 주요 위험 | IdP 장애=서비스 장애 또는 폐기 무효; 응답 지연이 인증 동시성 상한(부모 D9)을 소진 | TTL 동안 폐기 무효(RFC 7662 §4가 같은 절충을 경고) | 운영자 오기입(fail-closed라 가용성↓), cutoff 시계 오차 | 장기 유효 비밀 유출 | 헤더 위조, 인증서 수명 관리 |
| 권고 | 채택 안 함(D8) | **후속 옵션**(조건부, D8) | **권고(D1–D7)** | 별도 패키지(D9) | 별도 패키지, 탈취 방어용(D10) |

#### B의 저장소 변형

| 변형 | 장점 | 단점 | 폐기 지연 |
|---|---|---|---|
| **B-LDAP(권고)**: `ou=system,<root>` 아래(또는 `BASE_DN` 안) 폐기 항목 | 모든 replica가 이미 의존하는 저장소. 머신 ACL `{1}`이 `B`(기본 `LDAP_BASE_DN` 루트 전체) 읽기를 허용(`docs/machine-ldap-account.md:112`)해 기본 구성에서는 ACL 변경이 필요 없다(**실측 확인**: `M`이 `ou=revocations,ou=system,<root>`를 읽고 쓰지는 못하며 `userPassword`는 못 읽는다 — EVIDENCE §5.2). 복제로 전파. fail-closed가 기존 가용성 모델과 일치 | LDAP 스키마·항목 의미 결정(Class D), `B`를 좁힌 배포는 revocation 서브트리용 규칙 1개를 `{2}`에 추가해야 함(실측 EVIDENCE §5.3), 다중 provider 복제: 항목은 add 위주이며 cutoff 변경도 새 항목 추가 후 옛 항목 삭제이므로 같은 RDN 충돌이 없다(Revision 3). 건강한 2노드의 전파는 1 s 미만이고 `createTimestamp`는 생성 노드 값 그대로 복제되지만(EVIDENCE §8), 분리·지연된 노드는 rc 0과 오래된 데이터를 돌려주므로 sentinel·heartbeat가 필요(REQ-013); 3노드 이상·동시 쓰기·노드 간 시계 오차는 **미검증** | `REFRESH` + 복제 지연 |
| B-file: ConfigMap/Secret 또는 마운트 파일 | LDAP 스키마 변경 없음, 구현 단순 | Kubernetes의 마운트 전파는 수십 초~분 단위로 알려져 있음(**미측정**), 파일 변경은 GitOps/배포 경로를 타기 쉬움(롤아웃 없이라는 요구와 충돌 가능), docker/compose는 바인드 마운트 필요 | 마운트 전파 + 폴링 |
| B-HTTP: 별도 폐기 서비스 | 유연 | 신규 서비스·신뢰 경계 | — (채택 안 함) |

### 결정 기록

| ID | 결정 | 이유 | 비용 | 탈출구 |
|---|---|---|---|---|
| D1 | **오프라인 검증을 유지하고 그 위에 폐기 확인을 더한다(옵션 B).** 폐기 저장소는 B-LDAP을 권고하고 최종 선택은 Q1 | 핫 패스에 새 외부 의존이 없고(요청당 메모리 조회), ldapium이 토큰·secret을 저장하지 않는다는 부모 D1·REQ-014를 지키며, 이슈가 요구한 "롤아웃 없이 모든 replica" 상한을 `REFRESH` 하나로 설명할 수 있다 | 운영자가 항목을 직접 써야 하고(Q4), 스키마·ACL 결정이 필요 | 저장소는 `revocation.Source` 한 메서드(스냅샷 반환) 뒤에 두어 B-file로 교체 가능(첫 구현은 구체 타입, 과설계 금지) |
| D2 | 폐기 단위는 **client cutoff**(`iat ≤ T`)와 **jti**. cutoff는 한 client의 모든 기발급 토큰을 한 항목으로 폐기하고, jti 항목은 **`exp`를 싣지 않고**(Revision 3, B2) `createTimestamp + MaxTTL + 3×skew + REFRESH + MAX_STALE`(모든 replica가 그 토큰을 만료로 거부하는 것이 확실해진 뒤, 아래 "폐기 판정 규칙" 도출)에만 정리 대상 | 유출된 특정 토큰은 jti로, "이 client가 의심스럽다"는 cutoff로 처리. cutoff만으로는 토큰 하나를 지울 수 없고 jti만으로는 토큰을 모를 때 대응 불가 | cutoff는 같은 초에 발급된 정상 토큰까지 거부 가능(`iat` 초 단위, fail closed) | 필요 없으면 jti만 구현(cutoff는 후속 단위) |
| D3 | 폐기 항목 위치·스키마는 새 객체 클래스를 만들지 않는 방향으로 설계하되 **정확한 objectClass/속성은 Q2로 남긴다**(cutoff의 T는 항목의 `createTimestamp`, 즉 디렉터리 서버 시계 — 항목 수정 금지, 변경은 **새 항목을 먼저 추가하고 client별 최대 T를 취한 뒤 옛 항목 삭제** — 공백 없음, Revision 3)(T-002 실측: 이미지 스키마의 구조적 클래스 `device`로 새 스키마 없이 가능 — `cn=jti-<jti>`/`cutoff-<client>-<nonce>`/`sentinel`, `ou`=client(항목당 **정확히 1개**), sentinel만 `serialNumber`=세대·`description`=`entries=<N>;digest=<sha256>;ts=<epoch>;ret=<초>`(REQ-013); `expires`·메모 속성은 두지 않음; `createTimestamp`는 서버가 찍고 클라이언트 쓰기는 `no user modification allowed`로 거부됨, EVIDENCE §5.1·§5.4). 항목의 종류는 `cn` 접두어(`jti-`/`cutoff-`/`sentinel`), client는 `ou`, 값은 `cn`의 jti 또는 `createTimestamp`. 토큰·서명·secret·자유 서술 금지(REQ-006) | LDAP 스키마·연산 의미는 AGENTS.md상 설계 변경 | 후보 속성이 없으면 스키마 확장(이미지 변경) 필요 | B-file로 전환 |
| D4 | 갱신: replica당 `MACHINE_REVOCATION_REFRESH`(제안 기본 5 s, 범위 1–60 s)마다 머신 bind로 단일 비행 subtree 조회 1회, 메모리 스냅샷을 원자적으로 교체. 요청 경로는 스냅샷만 읽는다. 항목 수 상한 `MACHINE_REVOCATION_MAX_ENTRIES`(**Revision 2: 제안 기본 2000, 범위 1–2500(기동 검증: `MAX_ENTRIES × 400 B ≤ 1 MiB` — 항목 약 250–390 B, 5000개는 1 MiB 초과), 서버 `olcSizeLimit`(이미지 기본 10000) 미만**), 응답 1 MiB 상한(유지). 갱신이 LDAP 결과 코드 4(`Size limit exceeded`)나 부분 결과를 받으면 갱신 실패(부분 결과로 스냅샷을 만들지 않음). **Revision 3 질의 형태**: 검색 base는 정확히 `ou=revocations,…`(설정 `MACHINE_REVOCATION_BASE_DN`; 루트 `BASE_DN`은 금지), 속성은 `cn ou serialNumber description createTimestamp modifyTimestamp`만(`description`은 sentinel에만 있음; `modifyTimestamp`는 sentinel 검사 (iv)에 필요), 클라이언트 크기 한도 `MAX_ENTRIES + 2`, 만료된 jti 항목은 서버 측 필터(`(&(objectClass=device)(|(!(cn=jti-*))(createTimestamp>=<sentinel ts − ret>)))` — `now`가 아니라 sentinel의 `ts` 기준, REQ-013; `objectClass=device`가 없으면 `ou=revocations` 컨테이너 항목이 `!(cn=jti-*)`에 걸려 N이 어긋남; 머신 DN으로 `createTimestamp` 필터가 평가됨을 라이브 확인, EVIDENCE §9)로 제외, 갱신은 **한 연결·한 노드에서** sentinel 읽기 → 항목 검색 → sentinel 재읽기(세대 확인)의 3단계이고 digest로 구성을 검증(REQ-013), sentinel·건수·세대·ts 검증(REQ-013). `MAX_STALE ≥ REFRESH + 5 s`(조회 예산)를 기동 검증한다 | 요청당 LDAP 호출 증가 0, 상한은 부모 D9·D15의 "모든 상태에 상한" 원칙 | 5 s 주기 조회가 모든 replica에서 계속 발생(부하 작음: 10000항목 조회가 단일 노드에서 약 50 ms, EVIDENCE §7; 2노드 복제는 EVIDENCE §8). **Revision 2 근거**: 항목 1개가 약 250–390 B라 10000개는 2.5–3.9 MB로 1 MiB 상한의 2.5–3.7배(둘을 함께 지킬 수 없음)이고, 비-root 머신 계정은 서버 `olcSizeLimit` 10000에서 `Size limit exceeded`와 10000개 부분 결과를 받으며 페이지 검색도 총량에 한도가 적용된다(EVIDENCE §7) | 주기·상한 설정 범위 조정 |
| D5 | 폐기 거부는 기존 응답 재사용: 401 `token_invalid`(+`WWW-Authenticate`), 본문은 사유 비노출. 감사 reason `revoked` 추가(`jti` 필수 위반은 reason `jti`). 새 오류 코드 없음 | 부모 D10(본문은 실패한 규칙을 말하지 않음), api-error-envelope D218-14(새 코드는 표·골든·OpenAPI enum 동시 갱신)를 피한다 | 클라이언트가 "폐기"와 "무효"를 구분 못 함(의도) | 별도 코드가 필요하면 envelope 절차로 추가 |
| D6 | **fail closed**: 스냅샷 나이 > `MACHINE_REVOCATION_MAX_STALE`(제안 기본 `3×REFRESH`=15 s, 범위 `REFRESH`–10 m) 또는 최초 스냅샷 전이면 모든 머신 요청 503 `unavailable`+`Retry-After`. 형식 오류·상한 초과 항목은 갱신 실패로 취급(직전 스냅샷은 `MAX_STALE`까지만). 어떤 항목도 "무시하고 통과"하지 않는다. **heartbeat가 멈추면 `SENTINEL_MAX_AGE + MAX_STALE`(기본 약 5 m 15 s) 뒤 머신 API가 503**(문서화된 비용) | (1) 머신 요청은 이미 LDAP bind에 의존하므로(`machine_exec.go:89-94`: bind 실패 503, 폴백 없음) 디렉터리 장애는 어차피 서비스 정지라 가용성 비용이 작다. (2) fail-open이면 폐기를 원하는 바로 그 사고 시점(장애·공격)에 폐기가 조용히 무효가 된다. 부모 REQ-008의 fail-closed 원칙과 같다 | 오기입한 항목 하나가 `MAX_STALE` 후 머신 API 정지(운영자 오류 비용) — 탈출구가 필요 | `MACHINE_REVOCATION_MODE=fail-open`은 **만들지 않는다**(Q3에서 유지보수자가 요구할 때만 별도 결정); 항목 삭제로 복구 |
| D7 | **cutoff 의미(서버 시계 기준)와 운영 순서.** cutoff 항목의 시각 T는 운영자가 쓰지 않고 **디렉터리 서버가 항목 생성 시 찍는 `createTimestamp`**다(운영자 시계 무관; 다중 provider에서는 항목이 생성된 노드의 시계 — 노드 시계 오차는 NTP 전제). 판정은 `iat ≤ T + MACHINE_CLOCK_SKEW`(여기서 skew는 **발급자(IdP)와 디렉터리/ldapium 시계 사이의 허용 오차** — 부모 `claims.go:122`가 같은 skew를 서버↔발급자 오차에 쓰는 것과 같은 가정이며 운영자 시계와는 무관). 순서: ① Keycloak에서 client 비활성화/secret 회전 후 **실제로 새 토큰 발급이 거부되는지 확인**(예: `client_credentials` 요청이 401) → ② 폐기 항목 기록 → ③ 사전 확보 토큰으로 401 확인 → ④ 백스톱: allowlist 제거 + 전 replica 교체. **남는 창(명시)**: (i) 발급 차단이 IdP 전 노드에 전파되기 전에 발급된 토큰은 ②보다 `iat`가 앞서므로 폐기되지만, 차단이 ①의 확인 이후에도 일부 노드에서 새지 않는다는 보장은 Keycloak 클러스터 거동에 달려 있다(미검증) → ①의 확인을 2회 이상 반복; (ii) IdP↔디렉터리 시계 오차가 `MACHINE_CLOCK_SKEW`보다 크면 `iat`가 T보다 뒤인 사고 토큰이 통과할 수 있다(NTP 전제 위반); (iii) 요청이 발급 차단 전에 시작돼 응답을 늦게 받아도 토큰의 `iat`는 발급 시각이라 `iat ≤ T`로 폐기된다 — 이 경우는 창이 아니다; (iv) 정상 토큰이 `T ~ T+skew` 사이에 발급되면 과폐기(fail closed, 새 토큰으로 해소). 창 (i)·(ii)가 받아들일 수 없으면 jti 폐기(알려진 토큰)와 백스톱을 병행 | cutoff는 "IdP 발급 차단 확인"이라는 절차 의존을 가진다 | skew만큼 정상 토큰 과폐기(fail closed) | 과폐기는 새 토큰으로 해소, jti 폐기 병행 |
| D8 | **introspection은 채택하지 않는다(v1).** A2(캐시)는 후속 옵션이며 채택 조건: (a) ~~Keycloak이 SA 토큰의 폐기 상태를 introspection에 반영하는지 라이브 확인~~ — **T-001에서 충족**: client·SA 사용자 비활성화·RFC 7009 폐기(발급 client 자격만 가능, 비발급 client는 400)·client/realm not-before가 모두 사전 발급 토큰의 introspection을 `active:false`로 만든다(EVIDENCE §4.2–§4.4; 비활성화는 되돌리면 `active:true`로 돌아옴), (b) introspection 자격 증명(secret 또는 키/인증서) 보관을 허용하는 REQ-014 완화 결정, (c) fail-closed 정지 비용을 유지보수자가 수용. A1(매 요청)은 고려하지 않는다 | 핫 패스 IdP 의존, introspection 자격 증명 보관 필요(RFC 7662 §4: 인증 서버는 보호 자원의 인증을 MUST 요구하되 방식은 규정하지 않음; Keycloak은 secret·`private_key_jwt`·`client_secret_jwt`를 받고 bearer는 받지 않음(실측 EVIDENCE §4.1) — 어느 방식이든 secret 또는 개인키 보관이 필요), 인증 슬롯 점유. 호출자가 토큰 `aud`에 없으면 오류 없이 `active:false`가 되어 설정 오류가 폐기로 오인됨(실측 §4.1). `active:true` 경로와 폐기 반영은 이제 실측으로 확인됨(§4) | B 대비 IdP 독립성을 잃는다 | D1의 `Source` 인터페이스에 introspection 구현을 후속으로 추가 가능 |
| D9 | **API 키(C)는 이 패키지에서 구현하지 않는다.** 채택 조건: Keycloak 없는 배포의 실제 수요(부모 Q1 결정 유지) | 신규 영속 비밀 저장(해시), 발급·회전·감사 UX 전부 신규. 즉시 폐기는 쉽지만 새 자격 증명 클래스를 도입한다(부모 대안표 "옵션 2") | Keycloak 없는 소규모 배포는 즉시 폐기 대안이 없다 | 별도 Class D 패키지 |
| D10 | **mTLS 바인딩(D)은 구현하지 않는다.** 이 옵션은 폐기 지연이 아니라 **토큰 탈취 무력화**를 해결한다. 채택 조건: ingress가 클라이언트 인증서를 전달하는 구성의 실제 수요, 헤더 신뢰 모델 결정. Keycloak의 인증서 바인딩 토큰(`cnf.x5t#S256`, RFC 8705 §3.1) 지원은 **실측 확인**: 속성 켠 client는 인증서 없이는 발급 400, 인증서를 주면 `cnf.x5t#S256`이 DER SHA-256과 일치하는 SA 토큰을 발급(EVIDENCE §4.5; 인증서를 헤더로 받는 구성에서 확인했고 실제 TLS 핸드셰이크는 미실행) | 앱에 TLS 리스너가 없어 ingress 종단+헤더 신뢰가 필요(위 사실 확인), 위조 위험은 `UI_TRUSTED_PROXIES` 수준의 별도 설계 | 탈취 위협의 근본 방어는 미룸 | B와 병행 가능(독립 직교) |
| D11 | **분산 rate limit은 변경하지 않는다.** 한도는 replica별(부모 D9)이며 공유 limiter는 ingress 계층 책임이다. 폐기 저장소(LDAP)를 limiter 공유에 재사용하지 않는다 | 요청 경로에 쓰기·원자 연산이 들어가면 LDAP 부하·fail 모드가 달라진다. 이슈의 둘째 항목은 "결정"만 요구 | replica 수 × 한도만큼 총량이 늘어남(문서화됨: operations §5 4항) | ingress rate limit 사용, 필요 시 별도 이슈 |
| D12 | 기본 꺼짐: `MACHINE_REVOCATION_ENABLED=false`(Helm `ui.machineAuth.revocation.enabled`). 머신 인증이 꺼져 있으면 무시(활성 시 기동 검증: 값 범위, `MAX_STALE ≥ REFRESH + 5 s`, `MAX_ENTRIES + 2 < 서버 sizelimit`은 문서화, `SENTINEL_MAX_AGE` 범위). 켜면 토큰에 `jti`가 없는 경우 거부(`reason=jti`) — Keycloak access token은 `jti`를 싣는다(EVIDENCE §2.1 토큰 샘플의 `jti` 항목, RFC 9068 §2.2는 `jti` REQUIRED) | 폐기를 지정할 수 없는 토큰을 통과시키면 jti 폐기가 우회된다(contractual distrust) | `jti` 없는 IdP 토큰은 거부(설정 오류로 노출) | cutoff-only 모드(`jti` 불요)를 후속으로 분리 가능 |

### 폐기 판정 규칙 (D2·D6 정본)

검증된 `Principal(clientID, iat, jti)`에 대해 순서대로:

1. (검증 통과 뒤에만) 스냅샷 없음 또는 `now - snapshot.queryStartedAt > MAX_STALE` → 503(D6). 나이는 마지막 **성공** 갱신의 조회 시작 시각부터 잰다.
2. `snapshot.cutoff[clientID]`가 있고 `iat ≤ cutoff + MACHINE_CLOCK_SKEW`(cutoff = 그 client의 cutoff 항목들 중 **최대** `createTimestamp`; client id는 대소문자 구분 정확 일치) → 401 `revoked`.
3. `snapshot.jti` 집합에 `jti`가 있음 → 401 `revoked`.
4. 그 외 통과(기존 파이프라인 계속).

**보존 기간(단일 공식)**: `ret = MaxTTL + 3×skew + REFRESH + MAX_STALE`. 도출: 폐기 시점 C에 존재하는 토큰은 `iat ≤ C + skew`이고 검증기가 `exp − iat > MaxTTL`을 거부하므로(`claims.go:129`) `exp ≤ C + skew + MaxTTL`, 그 토큰은 `now > exp + skew`(`claims.go:141`)에서 만료로 거부된다 — 즉 `C + MaxTTL + 2×skew` 이후이며, 3번째 `skew`는 sentinel `ts`가 skew만큼 미래일 수 있는 여유, `REFRESH + MAX_STALE`는 replica별 스냅샷이 최악으로 늦은 경우의 여유. **운영자가 쓴 `expires`는 쓰지도 믿지도 않는다**(오타·단위 오류가 조용히 폐기를 풀 수 있음, B2). 도구는 설정 **상한값**(1 h, 60 s, 60 s, 10 m → 3600 + 180 + 60 + 600 = 4440 s)을 `ret` 하한으로 쓴다(운영자는 늘릴 수만 있다). **jti 항목의 정리(삭제)는 도구(heartbeat)만 한다**; replica는 항목을 나이로 건너뛰지 않고 sentinel의 `ts`·`ret`로 정한 서버 필터가 돌려준 항목을 모두 판정에 쓰며 digest로 검증한다. cutoff 항목은 정리하지 않는다.

### 위협 모델 (이 패키지가 다루는 부분)

| 위협 | 시나리오 | 통제 | 잔여 위험 |
|---|---|---|---|
| 토큰 탈취 후 노출 지속 | 유출된 bearer가 남은 TTL(최대 1h+skew) 동안 유효, 비활성화로 안 막힘 | jti/cutoff 폐기(D1–D2), 상한 `REFRESH`+복제 지연(REQ-001), 기존 allowlist 제거 백스톱 | 상한 시간 동안의 노출(정상 시 수 초, 뒤처진 replica는 **분 단위**: 오래된 노드가 신선한 heartbeat를 보여 줄 수 있는 시간이 최대 `SENTINEL_MAX_AGE`(기본 5 m)), 폐기 사실을 모르는 탈취(탐지는 감사 로그 몫) |
| 폐기 우회(재발급) | 공격자가 secret도 가졌다면 폐기 후 새 토큰 발급 | D7 순서: 발급 차단 먼저 | 운영자가 순서를 어기면 우회됨 — 문서·절차 점검표로 완화 |
| 폐기 저장소 위조·변조 | 머신 계정이 폐기 항목을 쓰거나 지움 | 머신 bind는 읽기 전용(부모 D4·AC-018), 항목 쓰기는 관리자만 | 관리자 권한 탈취는 이 설계 밖 |
| 저장소 장애를 이용한 우회 | 디렉터리를 막아 폐기 판단을 무력화 | fail closed(D6): 막으면 서비스 정지이지 우회가 아님 | 가용성 공격은 가능(부모의 LDAP 의존과 동일) |
| 오기입으로 인한 자기 정지 | 형식 오류 항목이 갱신을 실패시킴 | 갱신 실패 시 `MAX_STALE`까지 직전 스냅샷 유지, ERROR 로그·카운터, 항목 삭제로 복구 | 운영자 오류의 가용성 비용 수용 |
| 정보 노출 | 머신 `getEntry`/`listTree`가 폐기 항목을 읽을 수 있음(`B` 안) | 항목에는 jti·client·시각만(자격 증명 아님, 메모 없음, REQ-006), 필요하면 `B` 밖 위치+전용 ACL | 폐기된 jti 목록이 `B` 안에서 읽힘(저위험) — Q2 |
| 시계 오차 | 발급자 `iat`와 디렉터리가 찍은 T의 시각 차 | T는 서버 시계(D7), `iat ≤ T+skew`, 경계 테스트(AC-002) | 오차가 skew를 넘으면 미폐기 가능 — D7의 남는 창 (ii), NTP 전제 |

| 뒤처지거나 분리된 provider를 읽음 / 빈 응답 | bind·조회는 성공(rc 0)하지만 폐기 항목이 없거나 오래됨 → 폐기 토큰 통과 | sentinel(건수·세대 역행 금지·ts 신선도, REQ-013): 위반 시 갱신 실패 → `MAX_STALE` 후 fail closed | `SENTINEL_MAX_AGE`(기본 5 m, 초 단위가 아님)까지의 노출: 뒤처진 노드의 sentinel `ts`가 아직 신선하다고 판정되는 시간(전제 P1·P2, REQ-001); 재시작한 replica는 세대 기억이 없음(REQ-013 (iii)), 도구가 sentinel을 안 올리면 정지로 드러남 |
| 운영자 오기입 `expires` | 단위·오타로 jti 폐기가 조기 해제 | `expires`를 쓰지 않음, 보존은 `createTimestamp` 기반 도출(D2) | 도구가 설정 상한값보다 짧게 보존하지 못하게 해야 함(T-013) |
| 머신 계정으로 폐기 목록 열람 | `getEntry`/`listTree`로 revoked client id·jti 읽음 | 메모 제거 + 머신 경로 revocations 서브트리 API 거부(T-015: `dnWithinBase(BaseDN, dn)`(`machine_guard.go:34,49`)는 revocations도 통과시키므로 `getEntry`의 `dn`·`listTree`의 base에 명시 검사 필요) + UI 관리자 쓰기 경로의 해당 서브트리 쓰기 거부(sentinel·항목 삭제 방지) | `ldapsearch -D $MACHINE_DN`로는 읽힘(ACL상 필수) — 저위험 |
| 갱신 bind 반복 실패 | 잘못된 머신 비밀번호로 5 s마다 bind → ppolicy 잠금 | rc 49 백오프(60 s→15 m) | 요청 경로 bind는 별개로 잠금 위험(기존, 운영 문서 13절) |

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
| `AC-004` | 단위(형식 오류·상한 초과·크기 초과·sentinel 없음/건수 불일치/세대 역행/ts 만료 소스, 주입 소스) + 라이브(ACL 좁힘으로 rc 0·0항목, 한 노드 분리, 갱신 bind 실패 백오프) | go test; 드릴 | "무시되어 통과" 0건, rc 0 단독 성공 0건 |
| `AC-008` | 단위(N이 `ts`에 고정: 항목이 나이를 먹어도 같은 sentinel이면 건수 일치, `ret` 검사) + 드릴 (h) | go test; 드릴 | 항목이 만료된 뒤에도 200 유지 표, heartbeat 정지 시 503 |
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

- 증거: [EVIDENCE.md](EVIDENCE.md)(코드 읽기·RFC 확인·T-001–T-004 라이브 실측·남은 미확인 목록). 구현 시 라이브 드릴 로그를 부모 패키지 관례로 추가.
- 지속 회귀 통제: 스냅샷 판정 단위 테스트, 폐기 드릴 CI 편입, 기동 시 설정 검증.
- 동기화할 문서: `docs/machine-auth-operations.md`, `docs/audit-event-schema.md`, `docs/machine-ldap-account.md`, `docs/machine-keycloak-client.md`(순서 안내), 부모 CHANGE의 Non-goals·D7·위협 모델에 후속 링크, [IMPLEMENTATION-STATUS](../../IMPLEMENTATION-STATUS.md).

## 검증 상태 (무엇을 확인했고 무엇을 확인하지 못했는가)

확인함(코드·문서 읽기, 2026-10-07, main `b0ada28`): 폐기 관련 현행 동작과 file:line(위 Problem·Architecture), `jti` 미사용, 요청 경로 순서, 머신 요청의 요청당 LDAP bind, UI 서버에 클라이언트 TLS 리스너 없음, 부모 문서의 비목표·D7·EVIDENCE §2.7.
RFC 원문 확인(rfc-editor.org 텍스트에서 해당 문장 직접 확인): RFC 7662 §4의 캐시 절충 경고(introspection 응답 캐시 시 TTL 동안 stale), RFC 8705의 `cnf`의 `x5t#S256` 확인 방법, RFC 9068의 `jti` REQUIRED, RFC 7009의 access token 폐기 지원 SHOULD. RFC 7662 §4의 "인증 서버는 보호 자원의 인증을 MUST 요구"(내려받은 텍스트 662행 부근)도 직접 확인했다.
**Revision 2에서 라이브로 확인함(2026-10-07, main `220f554`; [EVIDENCE.md](EVIDENCE.md) §4–§7)**: (1) Keycloak 26.7.4 introspection의 `active:true` 경로(resource client가 `aud`에 있을 때)와 수락되는 호출자 인증 방식(secret basic/post, `private_key_jwt`, `client_secret_jwt`; bearer·무인증은 401). 비활성화(client·SA 사용자)·RFC 7009 폐기·client/realm not-before 뒤 사전 발급 토큰은 introspection에서 `active:false`이고 오프라인 검증은 통과한다(폐기 뒤에도 JWKS 불변, `nbf` claim 없음). (2) 인증서 바인딩 토큰: 속성을 켜면 인증서 없이는 발급 거부, 인증서 헤더가 있으면 `cnf.x5t#S256`이 일치(실제 mTLS 핸드셰이크는 미실행). (3) 이미지 스키마의 `device` 항목 후보, 기본 머신 ACL `{0}`–`{2}`의 읽기·비밀 비노출·쓰기 거부, `B`를 좁힌 구성의 추가 규칙, `createTimestamp`의 서버 설정·쓰기 거부. (4) 10000항목 조회의 크기·지연과 서버 `olcSizeLimit` 한도(→ D4 수정). (5) 기존 드릴 18/18 통과(기준선).
**Revision 3에서 추가 확인(T-004b, EVIDENCE §8)**: 2노드 multi-provider에서 복제된 항목의 `createTimestamp`는 생성 노드 값 그대로이고 건강한 전파는 1 s 미만, 분리된 노드는 오류 없이 rc 0과 오래된 데이터로 응답(→ REQ-013).
**여전히 확인하지 못함(추측으로 쓰지 않음)**: (a) 3노드 이상·양쪽 동시 쓰기(last-write-wins)·노드 간 시계 오차에서의 `createTimestamp`·지연, 원격 노드·다중 replica에서의 조회 부하. (b) Kubernetes ConfigMap 마운트 전파 시간(B-file 비교의 근거로만 사용). (c) 실제 TLS 종단 mTLS 핸드셰이크와 `tls_client_auth` introspection. (d) 발급 차단이 Keycloak 다중 노드 클러스터에 전파되는 시간(D7 창 (i)).

## Open questions and risks (결정 완료 — 아래 "Resolved questions"; 표는 제안 당시 기록)

| ID | 질문 | 권고(초안) | 영향 |
|---|---|---|---|
| Q1 | 폐기 저장소: B-LDAP / B-file / (후속) introspection 중 무엇으로 시작하나 | B-LDAP | D1·D3, 이미지/ACL 변경 여부, 폐기 지연 모델 |
| Q2 | LDAP 항목의 위치·objectClass·속성(새 스키마 허용 여부), `B`를 좁힌 배포의 ACL 처리, 머신 `getEntry`로 폐기 항목이 읽혀도 되는가 | 기존 속성 재사용, 새 스키마는 피함 — T-002 실측: `device` 항목으로 가능(EVIDENCE §5.1), `B`를 좁힌 배포는 revocation 서브트리 규칙 1개 추가(§5.3) | Class D 범위, 이미지 변경 |
| Q3 | 저장소 장애 시 fail-closed를 확정하나(fail-open 모드를 아예 두지 않음) | fail-closed 확정, fail-open 모드 없음 | D6, 가용성 비용 수용 |
| Q4 | 항목 쓰기 수단: v1은 운영자 `ldapadd` 문서화만 / 관리자 CLI 스크립트 / 후속 API·UI | 문서+스크립트(`scripts/`), API는 별도 Class D | 운영 부담, 쓰기 경로 추가 여부 |
| Q5 | 폐기 상한 목표: `REFRESH` 기본 5 s·`MAX_STALE` 15 s로 충분한가(요구 SLO가 있나), `MAX_ENTRIES` 기본값(Revision 2 제안 2000, 서버 `olcSizeLimit` 미만) | 5 s / 15 s / 2000 | 부하·가용성 비용 |
| Q6 | jti 필수화(없으면 거부)를 켜도 되는가, cutoff-only 모드가 필요한가 | 필수(Keycloak은 jti를 싣는다) | D12 |
| Q7 | introspection(A2)을 후속으로 열어 둘 의사가 있는가, introspection 자격 증명 보관(REQ-014 완화)을 허용하나 | 지금은 보류, 수요 시 별도 결정 | D8 |
| Q8 | API 키(C)·mTLS(D)의 실제 수요가 있는가(Keycloak 없는 배포, 인증서 기반 에이전트) | 수요 확인 전 보류 | D9·D10, 별도 패키지 |
| Q9 | rate limit 공유 여부: 현행 replica별 유지에 동의하나 | 유지(ingress에 위임) | D11 |
| Q10 | cutoff를 디렉터리 `createTimestamp` + skew로 판정하고 남는 창 (i)(ii)를 수용하나, 과폐기를 허용하나 | 수용, jti 폐기·백스톱 병행 | D7 |

## Resolved questions (2026-10-07, 유지보수자가 권고안을 수락)

| ID | 결정 |
|---|---|
| Q1 | 폐기 저장소는 **B-LDAP**로 시작(D1·D3). B-file·introspection은 `Source` 뒤의 후속 교체 경로 |
| Q2 | **새 스키마 없음**: `device` 항목을 `ou=revocations,ou=system,<root>`에 둔다(EVIDENCE §5.1). `B`를 좁힌 배포는 revocations 서브트리 읽기 규칙 1개를 머신 `to dn.subtree=B` 규칙 뒤·머신 `to *` none 앞에 추가(위치는 이웃 규칙 기준이며 #277 아래에서는 `{1}`–`{3}`으로 밀림 — [machine-ldap-account.md](../../machine-ldap-account.md) 5.1). 머신 `getEntry`가 폐기 항목을 읽는 것은 API 수준 거부로 막는다(REQ-006, T-015) |
| Q3 | **fail-closed 확정**, fail-open 모드를 만들지 않는다(D6) |
| Q4 | 항목 쓰기는 **`scripts/` 스크립트 + 문서**(sentinel·heartbeat·정리 포함, T-013). 쓰기 API·UI는 별도 Class D |
| Q5 | `REFRESH` 기본 5 s, `MAX_STALE` 기본 15 s(`≥ REFRESH + 5 s`), `MAX_ENTRIES` 기본 **2000, 범위 1–2500**(Revision 2·4; 서버 `olcSizeLimit` 미만), `SENTINEL_MAX_AGE` 기본 5 m(Revision 3) |
| Q6 | **jti 필수**(없으면 reason `jti`로 거부), cutoff-only 모드는 후속(D12) |
| Q7 | introspection(A2)은 **보류**, 수요가 생기면 별도 결정. introspection 자격 증명 보관(REQ-014 완화)은 지금 허용하지 않는다(D8; T-001 실측으로 조건 (a)는 충족) |
| Q8 | API 키(C)·mTLS(D)는 **수요 확인 전 보류**(D9·D10) |
| Q9 | rate limit은 **replica별 유지**, 공유는 ingress에 위임(D11) |
| Q10 | cutoff는 디렉터리 `createTimestamp` + skew로 판정, 남는 창 (i)(ii)·과폐기 **수용**, jti 폐기·백스톱 병행(D7). 노드 간 시계 오차는 미실측이므로 NTP 전제를 운영 문서에 적는다 |

위험: Keycloak 쪽 폐기 의미는 T-001에서 실측되었고 D8(v1 비채택) 방향은 바뀌지 않았다(introspection은 기술적으로 가능하지만 자격 증명 보관·핫 패스 의존 비용은 그대로). 저장소(Q1) 결정 전에는 단위 2 이후를 시작하지 않는다.
