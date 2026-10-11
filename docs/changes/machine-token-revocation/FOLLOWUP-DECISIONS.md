# 후속 결정 기록: API 키·mTLS(#360), 공유 rate limit(#361), introspection 백스톱(#362) (D13–D15)

- 상위 패키지: [CHANGE.md](CHANGE.md), [ADR.md](ADR.md)(D1–D12), [EVIDENCE.md](EVIDENCE.md). 결정 ID는 이 패키지 번호를 이어 D13부터 쓴다.
- 이슈: [#360](https://github.com/dasomel/ldapium/issues/360), [#361](https://github.com/dasomel/ldapium/issues/361), [#362](https://github.com/dasomel/ldapium/issues/362)(모두 [#286](https://github.com/dasomel/ldapium/issues/286)의 낮은 우선순위 후속)
- Status: **Proposed — maintainer acceptance pending** (D13, D14, D15 모두). 수용은 유지보수자의 몫이며 이 문서는 코드·설정을 바꾸지 않는다.
- 작성일: 2026-10-11. 근거는 저장소에 이미 기록된 측정만 쓰고 새 실측은 하지 않았다.

| ID | 이슈 | 제안 | 상태 |
|---|---|---|---|
| D13 | #360 | API 키·mTLS 바인딩은 v1에서 하지 않는다(won't-do for v1) | Proposed — maintainer acceptance pending |
| D14 | #361 | rate limit은 replica별 메모리 유지 | Proposed — maintainer acceptance pending |
| D15 | #362 | introspection은 기본으로 원하지 않음, 운영자 요구 시에만 opt-in 두 번째 방어선 | Proposed — maintainer acceptance pending |

## D13 — API 키·mTLS 바인딩 자격 증명 (#360)

**Context.** ADR D9·D10은 API 키(C)와 mTLS 바인딩 토큰(D)을 보류했다. 이슈의 수용 조건은 "원하는지 설계 결정, mTLS라면 실제 mTLS 종료 증거, 아니면 사유와 함께 won't-do"이다.

**Facts (저장소 근거).**
- 이 패키지의 목표는 폐기 **속도**다. mTLS 바인딩(RFC 8705)은 탈취된 토큰을 다른 곳에서 못 쓰게 할 뿐 폐기 속도를 바꾸지 않는다(ADR D10). 토큰을 쓰는 클라이언트 인증서 자체가 유출되면 같은 문제가 남는다.
- Keycloak은 `cnf.x5t#S256`을 발급한다(EVIDENCE §4.5). 단 이는 헤더 신뢰 구성(`ssl-client-cert` 헤더)에서 잰 것이며 실제 mTLS 핸드셰이크 종료는 실행하지 않았다.
- 앱에는 TLS 리스너가 없다(ADR D10). mTLS는 ingress가 인증서를 전달하고 앱이 `cnf`와 대조하는 헤더 신뢰 모델이 필요하며, 신뢰 경계(클라이언트가 보낸 헤더 위조 방지)가 새로 생긴다(ADR 비용표 D행).
- API 키는 키 해시의 영속 저장소가 필요하다(ADR 비용표 C행). ldapium은 토큰·secret을 저장하지 않는 원칙(부모 D1, REQ-006)이고, 이는 그 원칙을 깨고 새 인증 정지 도메인을 만든다.

**Options.** (a) 구현 안 함. (b) mTLS 바인딩만 별도 패키지. (c) API 키만 별도 패키지. (d) 둘 다.

**Decision (proposed).** (a) v1에서 구현하지 않고 #360은 won't-do로 닫는다. 두 옵션 모두 이 패키지가 푸는 문제(폐기 지연)를 풀지 않으며, 폐기는 D1–D7의 디렉터리 폐기 목록이 이미 맡는다.

**Cost.** 탈취 토큰의 재사용 방지(mTLS)와 Keycloak 없는 배포 지원(API 키)은 얻지 못한다. 토큰 탈취 노출은 `exp + skew`(기본 최대 10분+30초)와 폐기 목록으로 한정된다.

**Escape hatch / revisit trigger.** 다음 중 하나가 생기면 별도 Class D 패키지로 다시 연다. (1) 실제 mTLS 종료(ingress 인증서 검증 + 앱 `cnf` 대조)의 증거와 함께 탈취 무력화 요구가 확인됨. (2) Keycloak 없는 배포 수요가 확인됨(ADR D9). 이슈는 위 사유를 적어 닫고, 재개 시 새 이슈로 연다.

## D14 — 공유 rate limit (#361)

**Context.** 머신 IP 실패 throttle과 client 예산은 replica별 메모리 상태이며 replica 수만큼 한도가 늘어난다([machine-auth-operations.md](../../machine-auth-operations.md) 마지막 사전 점검 4번, ADR D11). #286은 공유 여부의 결정을 요구했다.

**Facts.**
- 공유하려면 모든 replica가 요청 경로에서 읽고 쓰는 저장소가 필요하다. 이는 핫 패스에 가용성 의존을 더한다. 폐기 갱신은 이를 피하려고 백그라운드 단일 비행 조회로 설계했다(REQ-008, 요청당 LDAP 호출 증가 0).
- 한도는 남용 완화 수단이지 인가 경계가 아니다. 부정확해도 인증·scope 판정은 바뀌지 않는다. 전역 한도는 ingress limiter에 위임한다(ADR D11).
- 머신 쓰기 패키지의 멱등 기록도 프로세스 메모리이며 단일 replica 제약을 수용했고 영속 저장소는 별도 변경이다([machine-write-scope CHANGE.md](../machine-write-scope/CHANGE.md) Q8).

**Options.** (a) replica별 메모리 유지. (b) LDAP·Redis 등 공유 저장소. (c) 하이브리드(로컬 + 주기 동기화).

**Decision (proposed).** (a) 유지한다. 한도 정확도를 위해 핫 패스에 가용성 의존을 추가하지 않는다. 전역 상한이 필요한 운영자는 ingress limiter를 쓴다.

**Cost.** 유효 한도가 `replica 수 × 설정값`이다(문서화됨). 한 client가 replica마다 예산을 따로 쓴다.

**Escape hatch / revisit trigger.** #285의 영속 멱등 저장소(Q8의 "별도 변경")가 **다른 이유로** 도입될 때 같은 저장소로 공유 한도를 함께 평가한다. 그 전에는 구현하지 않는다. 이슈의 수용 조건("공유 저장소가 다른 이유로 생길 때만 구현")과 같다.

## D15 — introspection 백스톱 (#362)

**Context.** 설계는 오프라인 JWT 검증 + LDAP 폐기 목록이다(D1). 매 요청 또는 TTL 캐시 introspection(RFC 7662)은 ADR D8에서 v1 비채택이었다. 이슈는 opt-in 두 번째 방어선으로 원하는지를 묻는다.

**Facts.**
- Keycloak 26.7.4 실측: 호출자 인증은 `client_secret_basic`·`client_secret_post`·`private_key_jwt`·`client_secret_jwt`를 받고 bearer는 불가, 호출자는 토큰 `aud`의 resource client여야 한다(EVIDENCE §4.1). 비활성화·RFC 7009 폐기 뒤 같은 토큰이 `active:false`가 된다(EVIDENCE §4.2–§4.3). 그러나 이는 현재 IdP 상태를 보므로 비활성화를 되돌리면 폐기도 사라진다.
- 어느 방식이든 ldapium이 secret 또는 개인키를 보관해야 한다. 이는 REQ-014/REQ-006의 "자격 증명 미보관" 원칙을 완화한다(Q7이 지금은 허용하지 않음).
- 비용표: 매 요청은 Keycloak RTT와 인증 슬롯 점유, TTL 캐시는 TTL 동안 폐기 무효(ADR 비용표 A1·A2).

**Options.** (a) 비채택(현행). (b) opt-in 캐시형(A2)을 `Source` 구현으로 추가. (c) 기본 켬.

**Decision (proposed).** 기본으로는 원하지 않는다(c 거부). 운영자가 **분 미만(sub-minute) 폐기**를 요구하고 그 요구가 디렉터리 폐기 목록의 상한(`REFRESH + 2×L + 복제 지연`, REQ-001)으로 충족되지 않을 때에 한해 (b)를 opt-in 두 번째 방어선으로 추가할 수 있다고 기록한다. 그때까지 구현하지 않는다.

**fail-closed vs fail-open (opt-in 시 정해야 할 값).**
- fail-closed: IdP 장애·지연 시 검증을 통과한 모든 머신 요청이 503. 폐기는 확실하지만 머신 API 가용성이 Keycloak에 묶인다. 폐기 목록의 D6(fail-closed)과 일관된다.
- fail-open: IdP 장애 시 오프라인 검증 결과만 쓴다. 가용성은 유지되나 장애 중 폐기가 조용히 무효이고, 장애를 일으킬 수 있는 공격자에게 우회가 된다. 폐기 백스톱의 목적에 반한다.
- 제안: opt-in을 만든다면 기본은 fail-closed이며 fail-open은 만들지 않는다(Q3와 동일). 캐시형은 TTL 동안 폐기 무효라는 창을 문서에 적는다.

**Cost.** 자격 증명 보관(Q7의 완화 필요), 핫 패스 IdP 의존, Keycloak 장애가 머신 API 정지로 번짐, resource client 구성 오류가 "폐기됨"처럼 조용히 보이는 위험(EVIDENCE §4.1).

**Escape hatch / revisit trigger.** (1) 운영자가 sub-minute 폐기를 명시적으로 요구하고 디렉터리 상한이 부족함이 측정으로 확인됨, 그리고 (2) 유지보수자가 introspection 자격 증명 보관을 허용(Q7 개정). 둘 다 충족되면 `Source` 뒤 구현으로 별도 Class D 변경을 연다. 켜지 않은 배포의 동작은 불변이다.
