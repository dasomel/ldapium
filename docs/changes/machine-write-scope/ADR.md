# ADR: 머신 주체 쓰기 범위 (D1, D3, D4, D5, D9, D19–D22, D26)

- Status: `Proposed` — [CHANGE.md](CHANGE.md)의 되돌리기 어려운 결정을 요약한 초안이다. CHANGE.md는 2026-10-07 유지보수자 결정으로 수용되었다(보안 검토 BLOCKER 4건 해소). 구현 단위가 병합되면 `Accepted`로 승격한다(T-050).
- Owner: 유지보수자(결정 기록: 대화)
- Related issue: [#285](https://github.com/dasomel/ldapium/issues/285)(닫지 않음). 연관: #277(병합), #286(병행 구현 중)
- 위치 규약: 이 저장소에는 별도 ADR 디렉터리가 없고 변경 패키지 안의 `ADR.md`로 둔다([api-conditional-writes ADR](../api-conditional-writes/ADR.md)와 같음). 근거·대안·위협 모델 전문은 CHANGE.md에 있다.

## Context

v1 머신 주체는 읽기 전용이다. 자동화가 사용자·그룹을 쓰려면 관리자급 비밀번호 재생 외에 길이 없다. 쓰기는 읽기와 질적으로 다른 위험(변조·삭제·권한 부여)을 가지며 신뢰 경계와 외부 계약을 늘린다(ADR threshold: `required`).

## Decisions

| ID | 결정 | 되돌리기 어려운 이유 | 탈출구 |
|---|---|---|---|
| D1 | 쓰기는 별개 플래그 `MACHINE_WRITE_ENABLED`·별개 표 `machineWriteOps`. v1 allowlist를 제자리에서 넓히지 않는다. | 계약(`machineBearer`)과 꺼진 상태의 바이트 동일성 | 표 합치기 |
| D3 | 쓰기 신원은 위험 구획별 `W_data`/`W_lock`/`W_cred`, 서로·`M`과 다른 DN. | 계정·Secret·ACL 구조 | 구획 합치기는 하지 않음 |
| D4 | client별 쓰기 DN은 만들지 않는다. LDAP 귀속은 구획 단위, client 귀속은 앱 감사. | 귀속 정밀도 상실 | 후속 변경(subtree/client별 `W`) |
| D5 | proxyAuthz(위임) 기각. | 복제 신원 거부 조건과 충돌, 위임은 권한 상승 표면 | 충돌 해소 후 재평가 |
| D9 | 머신 쓰기는 `Idempotency-Key` 필수·주체는 verified client·재시작 시 같은 키는 재실행됨(단일 replica). | 호출 계약, 메모리 저장소 한계 | 영속 멱등 저장소(별도 변경) |
| D19 | 보호 DN 거부 목록 + 대상 objectClass 단언. | 쓰기 의미(신원 보호) | 컨테이너 분리 배치 |
| D20 | 쓰기 가드는 엄격한 후손만 허용(상한 자신 거부). | 쓰기 계약 | — |
| D21 | 머신 `If-Match`는 단일 강한 태그만(428 새로 emit, `*` 거부). 사람 경로 불변. | 외부 계약 | — |
| D22 | 그룹 멤버십은 client별 허용 목록, 그룹 생성·수정·삭제는 첫 출하 제외, seed 멤버 결정 전에는 `createGroup` 불가. | `memberOf` 기반 권한 부여 | 허용 목록 확장·T-026 |
| D26 | 보호 DN·상한 판정은 문자열 비교가 아니라 형식 fail closed + slapd 관점 `entryDN`/`entryUUID` 정체성 대조(go-ldap `dn.go:483` 한계). | 쓰기 보호의 핵심 불변식 | — |

## Consequences

- 쓰기 켠 운영자는 단일 replica, 멱등 활성, `W_*` 계정·ACL, client 상한·그룹 허용 목록을 모두 설정해야 하며 하나라도 없으면 기동 실패한다.
- 교차 client 쓰기 격리는 앱 가드 1겹이다(D17). 하드 격리가 필요하면 D4의 확장이 필요하다.
- 발급된 토큰은 TTL 동안 유효(D12, #286 병행). 노출 상한의 최종 보안 승인은 T-013 병합 전에 받는다.
