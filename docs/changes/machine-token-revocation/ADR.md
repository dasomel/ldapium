# ADR: 머신 토큰 즉시 폐기 — 오프라인 검증 + 디렉터리 폐기 목록(제안), introspection·API 키·mTLS는 보류 (D1–D12)

- Status: `Accepted (2026-10-07, design direction decided by the maintainer; T-005 security gate passed on the Revision 5 review: no BLOCKER; Revision 6 folds in the non-blocking points)` (Revision 2: T-001–T-004 실측, 3: 1차 BLOCKER 해결, 4: B4', 5: digest·연결 고정, 6: 4차 검토 비차단 반영) — [CHANGE.md](CHANGE.md)의 결정을 압축한 기록이다. 수용은 설계 방향에 대한 유지보수자 결정이고 T-005 보안 검토 관문은 Revision 5 검토에서 BLOCKER 없음으로 통과했다. 구현 없음.
- Owner: dasomel (유지보수자)
- Related issue: [#286](https://github.com/dasomel/ldapium/issues/286) (닫지 않음), 선행 [#214](https://github.com/dasomel/ldapium/issues/214)
- 위치 규약: 변경 패키지 안의 `ADR.md`([machine-principal-auth](../machine-principal-auth/ADR.md)와 같음). 근거·대안·검증 상태의 전문은 CHANGE.md, 확인 기록은 [EVIDENCE.md](EVIDENCE.md).
- ADR threshold: `required` — 신뢰 경계·자격 증명 수용 규칙 변경, 신규 영속 상태.

## Context

ldapium은 Keycloak access token을 오프라인으로 검증하며 토큰·secret을 저장하지 않는다(부모 D1). 발급된 토큰은 `exp + skew`까지 유효하고(`ui/backend/internal/machineauth/claims.go:129,141`), Keycloak client 비활성화·secret 회전은 기발급 토큰을 폐기하지 않는다(부모 EVIDENCE §2.7). 현재의 긴급 차단은 allowlist 제거 + 모든 replica 교체뿐이다(`docs/machine-auth-operations.md`). #286은 롤아웃 없이 즉시 폐기하는 방식을 평가하고 비용(핫 패스 IdP 의존, 장애 시 fail-open/closed)을 기록할 것을 요구한다.

## Decisions

| ID | 결정 | 탈출구 |
|---|---|---|
| D1 | 오프라인 검증 유지 + 폐기 확인 추가(옵션 B). 저장소는 디렉터리(B-LDAP) 권고, 최종 선택은 유지보수자(Q1) | `Source` 한 메서드 뒤에 두어 B-file·introspection으로 교체 가능 |
| D2 | 폐기 단위는 client cutoff(`iat ≤ T`)와 jti(운영자 `expires`는 쓰지 않음; `createTimestamp + MaxTTL + 3×skew + REFRESH + MAX_STALE` 후에만 정리 대상, Revision 3). cutoff의 T는 디렉터리 `createTimestamp`(서버 시계)이고 판정은 `iat ≤ T+skew` | jti만 먼저 구현 |
| D3 | 새 스키마 없이 기존 속성 재사용을 우선, 정확한 위치·속성은 실측(T-002) 후 확정(Q2). 토큰·서명·secret 저장 금지 | B-file |
| D4 | replica당 `REFRESH`(기본 5 s)마다 단일 비행 조회, 요청 경로는 메모리 스냅샷만 읽음. 항목·크기 상한(Revision 2: `MAX_ENTRIES` 기본 2000·범위 1–2500(Revision 4: `×400 B ≤ 1 MiB`)으로 1 MiB 응답 상한과 서버 `olcSizeLimit` 10000에 맞춤; `Size limit exceeded`·부분 결과는 갱신 실패) | 주기·상한 설정 |
| D5 | 기존 401 `token_invalid` 재사용, 감사 reason `revoked` 추가. 새 오류 코드 없음 | envelope 절차로 코드 추가 |
| D6 | **fail closed**: `MAX_STALE` 초과·최초 스냅샷 전·형식 오류는 (검증 통과 요청에) 503; **sentinel 없음·건수 불일치·세대 역행·heartbeat 만료는 갱신 실패**(rc 0만으로 성공 아님, REQ-013, Revision 3). fail-open 모드 없음 | 항목 삭제로 복구, 유지보수자 요구 시에만 별도 결정(Q3) |
| D7 | 운영 순서: Keycloak 발급 차단 → 폐기 기록 → 같은 토큰 확인 → (백스톱) allowlist 제거·교체. cutoff는 서버 시계 T + skew, 남는 창(IdP 전파·시계 오차)은 CHANGE.md D7에 명시 | 과폐기는 새 토큰으로 해소 |
| D8 | introspection은 v1 비채택. A2(캐시)는 후속, 조건: introspection 자격 증명 보관 허용(Keycloak 실측: secret·`private_key_jwt`·`client_secret_jwt` 수락, bearer 불가; 호출자는 토큰 `aud`의 resource client여야 함), 정지 비용 수용. Keycloak의 폐기 반영(비활성화·RFC 7009·not-before → `active:false`)은 실측 확인되어 조건에서 충족 | `Source` 구현 추가 |
| D9 | API 키는 별도 패키지(Keycloak 없는 배포 수요 확인 시) | — |
| D10 | mTLS 바인딩은 별도 패키지(탈취 무력화용, 폐기 지연 해결 아님; 앱에 TLS 리스너 없음; Keycloak의 `cnf.x5t#S256` 발급은 실측 확인) | B와 병행 가능 |
| D11 | 분산 rate limit 변경 없음(replica별, ingress에 위임) | ingress limiter |
| D12 | 기본 꺼짐. 켜면 `jti` 없는 토큰 거부 | cutoff-only 모드 후속 |

## Revision 6 — 비차단 반영
digest 입력은 항목당 `cn` 1개·개행 금지·구분자 `\n`으로 모호성을 없앴고, 도구는 `objectClass=device`가 없는 stray 항목을 필터 없는 검색으로 찾아 거부한다. 폐기 서브트리 쓰기는 머신·UI 관리자 경로 모두 API 수준에서 거부한다. L4 라운드로빈 URL은 노드 교대로 세대 역행 실패·503 깜박임을 일으킬 수 있으므로 replica마다 안정된 노드를 요구한다.

## Revision 5 — digest와 연결 고정
건수만으로는 세 번의 읽기가 서로 다른 노드에 닿을 때 항목 구성이 다른 것(Y 추가·X 삭제)을 놓칠 수 있다. sentinel에 대상 집합 S의 `cn` 정렬 SHA-256 digest를 싣고 replica가 읽은 항목으로 재계산하며, 갱신의 세 읽기를 한 연결·한 노드로 고정한다(연산 단위 노드 전환 프록시는 지원하지 않음, 전제 P2). heartbeat 쓰기는 값 조건부 modify라 동시 쓰기가 조용히 덮어쓰지 못한다. heartbeat가 멈추면 `SENTINEL_MAX_AGE + MAX_STALE`(기본 약 5 m 15 s) 뒤 503이 되는 것은 문서화된 fail-closed 비용이다(D6).

## Revision 4 — sentinel 건수 정의
sentinel의 N은 읽는 시각이 아니라 sentinel의 `ts` 기준(`createTimestamp ≥ ts − ret`인 jti + 모든 cutoff)이며 보존 기간 `ret`도 sentinel에 싣는다. heartbeat가 정리와 N 재계산을 함께 한다. 이렇게 하지 않으면 조용한 배포에서 항목이 만료·필터링되는 순간 건수 불일치로 `MAX_STALE` 후 머신 API가 정지한다(B4'). 세대 역행 기억은 메모리뿐이며 재시작 뒤 첫 갱신은 `ts` 신선도와 fail-closed 시작만이 보호한다.

## Revision 3 — 복제 속성 (ADR 기준 검증 상태)

| 속성 | 상태 |
|---|---|
| 복제된 항목의 `createTimestamp`는 생성 노드 값 그대로 | **실측(2노드, 같은 시계)** — EVIDENCE §8 |
| 건강한 2노드의 전파 지연 < 1 s | **실측** — EVIDENCE §8 |
| 분리된 노드는 오류 없이 rc 0과 오래된 데이터를 줌 | **실측** → sentinel·heartbeat(REQ-013) |
| REQ-001 상한은 전제 P1(heartbeat)·P2(같은 노드 읽기·복제 지연 < `SENTINEL_MAX_AGE`) 아래에서만 성립 | 설계 결정(조건부 상한) |
| 3노드 이상, 양쪽 동시 쓰기(last-write-wins), 노드 간 시계 오차, 라운드로빈 읽기에서의 역행 크기 | **미검증**(역행은 세대 검사로 방어하도록 설계) |

## Cost of each option (이슈 수용 조건)

| 옵션 | 핫 패스 추가 의존 | 저장소/IdP 장애 시 | 새 비밀 |
|---|---|---|---|
| A1 introspection 매 요청 | Keycloak 매 요청(+RTT, 인증 슬롯 점유) | fail-closed=머신 API 전면 정지, fail-open=폐기가 조용히 무효 | introspection 자격 증명 보관 필요(secret 또는 개인키; bearer는 Keycloak이 거부 — 실측) |
| A2 introspection + TTL | 캐시 미스마다 Keycloak | 위와 같음, TTL 동안 완충(TTL 동안 폐기 무효) | 동일 |
| B denylist(권고) | 없음(백그라운드 갱신) | 머신 요청은 이미 LDAP bind에 의존(`machine_exec.go:89`)이라 새 장애 도메인 없음; `MAX_STALE` 후 fail-closed | 없음 |
| C API 키 | 키 저장소 | 인증 정지 | 해시 저장(영속) |
| D mTLS 바인딩 | ingress 인증서 전달 | 헤더 신뢰 문제 | CA 번들 |

## Consequences

- 폐기 상한은 `REFRESH`(+조회·복제 지연)로 말할 수 있고 롤아웃이 필요 없다. 오프라인 검증과 IdP 독립성이 유지된다.
- 운영자가 항목을 쓰고 순서를 지켜야 한다. 오기입은 `MAX_STALE` 후 머신 API 정지로 나타난다(의도된 fail-closed).
- Keycloak 폐기·introspection 거동, 스키마·ACL 후보, 조회 규모는 T-001–T-004에서 실측했고([EVIDENCE.md](EVIDENCE.md) §4–§7) D4만 수정되었다. 남은 미확인(다중 provider 복제, 실제 mTLS 핸드셰이크 등)은 CHANGE.md "검증 상태"에 둔다.
