# ADR: 머신 토큰 즉시 폐기 — 오프라인 검증 + 디렉터리 폐기 목록(제안), introspection·API 키·mTLS는 보류 (D1–D12)

- Status: `Proposed` — [CHANGE.md](CHANGE.md)(2026-10-07)의 결정을 압축한 기록이다. 수용 표시는 유지보수자만 한다. 구현 없음.
- Owner: 미지정
- Related issue: [#286](https://github.com/dasomel/ldapium/issues/286) (닫지 않음), 선행 [#214](https://github.com/dasomel/ldapium/issues/214)
- 위치 규약: 변경 패키지 안의 `ADR.md`([machine-principal-auth](../machine-principal-auth/ADR.md)와 같음). 근거·대안·검증 상태의 전문은 CHANGE.md, 확인 기록은 [EVIDENCE.md](EVIDENCE.md).
- ADR threshold: `required` — 신뢰 경계·자격 증명 수용 규칙 변경, 신규 영속 상태.

## Context

ldapium은 Keycloak access token을 오프라인으로 검증하며 토큰·secret을 저장하지 않는다(부모 D1). 발급된 토큰은 `exp + skew`까지 유효하고(`ui/backend/internal/machineauth/claims.go:129,141`), Keycloak client 비활성화·secret 회전은 기발급 토큰을 폐기하지 않는다(부모 EVIDENCE §2.7). 현재의 긴급 차단은 allowlist 제거 + 모든 replica 교체뿐이다(`docs/machine-auth-operations.md`). #286은 롤아웃 없이 즉시 폐기하는 방식을 평가하고 비용(핫 패스 IdP 의존, 장애 시 fail-open/closed)을 기록할 것을 요구한다.

## Decisions

| ID | 결정 | 탈출구 |
|---|---|---|
| D1 | 오프라인 검증 유지 + 폐기 확인 추가(옵션 B). 저장소는 디렉터리(B-LDAP) 권고, 최종 선택은 유지보수자(Q1) | `Source` 한 메서드 뒤에 두어 B-file·introspection으로 교체 가능 |
| D2 | 폐기 단위는 client cutoff(`iat ≤ T`)와 jti(`expires+skew+REFRESH+MAX_STALE` 후에만 정리 대상). cutoff의 T는 디렉터리 `createTimestamp`(서버 시계)이고 판정은 `iat ≤ T+skew` | jti만 먼저 구현 |
| D3 | 새 스키마 없이 기존 속성 재사용을 우선, 정확한 위치·속성은 실측(T-002) 후 확정(Q2). 토큰·서명·secret 저장 금지 | B-file |
| D4 | replica당 `REFRESH`(기본 5 s)마다 단일 비행 조회, 요청 경로는 메모리 스냅샷만 읽음. 항목·크기 상한 | 주기·상한 설정 |
| D5 | 기존 401 `token_invalid` 재사용, 감사 reason `revoked` 추가. 새 오류 코드 없음 | envelope 절차로 코드 추가 |
| D6 | **fail closed**: `MAX_STALE` 초과·최초 스냅샷 전·형식 오류는 503. fail-open 모드 없음 | 항목 삭제로 복구, 유지보수자 요구 시에만 별도 결정(Q3) |
| D7 | 운영 순서: Keycloak 발급 차단 → 폐기 기록 → 같은 토큰 확인 → (백스톱) allowlist 제거·교체. cutoff는 서버 시계 T + skew, 남는 창(IdP 전파·시계 오차)은 CHANGE.md D7에 명시 | 과폐기는 새 토큰으로 해소 |
| D8 | introspection은 v1 비채택. A2(캐시)는 후속, 조건: Keycloak의 폐기 반영 라이브 확인, introspection 자격 증명(secret·키·인증서; 방식은 RFC가 규정하지 않고 Keycloak 지원은 미검증) 보관 허용, 정지 비용 수용 | `Source` 구현 추가 |
| D9 | API 키는 별도 패키지(Keycloak 없는 배포 수요 확인 시) | — |
| D10 | mTLS 바인딩은 별도 패키지(탈취 무력화용, 폐기 지연 해결 아님; 앱에 TLS 리스너 없음) | B와 병행 가능 |
| D11 | 분산 rate limit 변경 없음(replica별, ingress에 위임) | ingress limiter |
| D12 | 기본 꺼짐. 켜면 `jti` 없는 토큰 거부 | cutoff-only 모드 후속 |

## Cost of each option (이슈 수용 조건)

| 옵션 | 핫 패스 추가 의존 | 저장소/IdP 장애 시 | 새 비밀 |
|---|---|---|---|
| A1 introspection 매 요청 | Keycloak 매 요청(+RTT, 인증 슬롯 점유) | fail-closed=머신 API 전면 정지, fail-open=폐기가 조용히 무효 | introspection 자격 증명 보관 필요(secret이 필수는 아님, Keycloak 지원 방식 미검증) |
| A2 introspection + TTL | 캐시 미스마다 Keycloak | 위와 같음, TTL 동안 완충(TTL 동안 폐기 무효) | 동일 |
| B denylist(권고) | 없음(백그라운드 갱신) | 머신 요청은 이미 LDAP bind에 의존(`machine_exec.go:89`)이라 새 장애 도메인 없음; `MAX_STALE` 후 fail-closed | 없음 |
| C API 키 | 키 저장소 | 인증 정지 | 해시 저장(영속) |
| D mTLS 바인딩 | ingress 인증서 전달 | 헤더 신뢰 문제 | CA 번들 |

## Consequences

- 폐기 상한은 `REFRESH`(+조회·복제 지연)로 말할 수 있고 롤아웃이 필요 없다. 오프라인 검증과 IdP 독립성이 유지된다.
- 운영자가 항목을 쓰고 순서를 지켜야 한다. 오기입은 `MAX_STALE` 후 머신 API 정지로 나타난다(의도된 fail-closed).
- 미검증 항목(Keycloak 폐기·introspection 거동, 스키마·ACL 후보)은 TASKS T-001·T-002에서 실측하며 결과에 따라 이 ADR을 개정한다.
