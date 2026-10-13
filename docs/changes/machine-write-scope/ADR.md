# ADR: 머신 주체 쓰기 범위 (D1, D3, D4, D5, D9, D19–D22, D26)

- Status: `Proposed` — [CHANGE.md](CHANGE.md)의 되돌리기 어려운 결정을 요약한 초안이다. CHANGE.md는 2026-10-07 유지보수자 결정으로 수용되었다(보안 검토 BLOCKER 4건 해소). 구현 단위가 병합되면 `Accepted`로 승격한다(T-050). 2026-10-11 현재 D1/D3/D4/D5/D9/D19–D22/D26은 main에 구현되어 있고(T-013, 기본 꺼짐) 실측 증거가 있다([EVIDENCE.md](EVIDENCE.md) "T-004 live measurements": D4 귀속은 slapd `reqAuthzID`=W_data, D9 재시작 시 재실행은 실측 확인; D18은 Modify의 objectClass 값 ADD가 ACL을 통과하는 한계가 확인되어 2026-10-13 앱 가드 1겹으로 수용됨(#386 A, #390 (a))). **승격(`Accepted`)은 유지보수자 결정으로 남긴다.**
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

## Decision (#386, #390) — 수용 2026-10-13 (유지보수자)

D18의 "수정으로는 objectClass를 쓸 수 없다"는 현재 fragment(`{4}` `add`)에서 ACL만으로 성립하지 않는다(Modify 값 ADD 통과). 실측과 후보 전체: [EVIDENCE.md](EVIDENCE.md) "#386 objectClass value ADD"(`test-machine-write-t004-live.py` 5d/5e로 재현). **#386은 선택지 A를 수용한다**: 수정 경로 objectClass 방어는 앱 닫힌 본문 가드 1겹이고, 제안 B(`val.regex` 허용 목록)는 채택하지 않는다. 탈출구는 나중에 B로 이행. 패키지 상태(`Proposed`)는 바꾸지 않는다(승격은 별도 결정).

전제: 이미지·차트는 `olcAddContentAcl`을 설정하지 않는다(기본 FALSE, 5e가 단언). FALSE에서 slapd Add는 `entry`/`children`만 검사하고, TRUE이면 Add의 모든 속성 값에 `=a`가 필요하다.

| 선택지 | 내용 | 비용 | 탈출구 |
|---|---|---|---|
| **A (수용)** | 수정 경로 objectClass 방어를 앱 닫힌 본문 가드 1겹으로 명시 수용(D17과 같은 성격의 한계로 기록) | 없음(회귀 시험 있음) | B로 이행 |
| B (미채택, 탈출구) | `write-data.ldif` `{4}`를 `val.regex` 허용 목록(앱 고정 집합 top·person·organizationalPerson·inetOrgPerson·groupOfNames) + `add`로(C3). 실측: Modify 값 ADD 50, 사용자·그룹 Add 유지 — `olcAddContentAcl` FALSE·TRUE 모두 | fragment 한 줄, 허용 목록과 `users.go`/`groups.go` 고정 집합 동기화, 가이드, `test-machine-write-acl-live.py`·T-004 KNOWN-LIMIT 단언 의도적 반전, 운영 중 ACL 재적용 | `add` 규칙 복원 |
| B′ | objectClass를 `read`로(C6). FALSE에서는 B와 같은 효과 | B보다 단순하나 **`olcAddContentAcl` TRUE가 되면 사용자·그룹 생성이 50으로 깨진다**(실측) | `add` 규칙 복원 |
| C | constraint overlay objectClass 허용 목록 | Add 시점 추가 클래스까지 거부(19)하지만 전역(관리자 포함), 모든 사용 클래스 열거 필요, 비밀번호·목록 밖 속성은 못 막음 | overlay 속성 제거 |

Add 시점(추가 클래스, 목록 밖 속성, `userPassword`): 출하 상태(FALSE)에서는 A·B·B′ 어느 것도 막지 못하고(W_data가 비밀번호를 가진 bind 가능한 항목을 직접 생성, 실측), C는 추가 클래스만 전역으로 막는다. `olcAddContentAcl` TRUE + B는 셋 모두를 50으로 거부했지만(실측) 데이터베이스 전체·모든 비 root 신원의 Add에 영향을 주며(미측정) 별도 결정이다. **#390은 선택지 (a)를 수용한다**(CHANGE.md D17a): 생성 경로는 `createUser` 닫힌 본문(D15/D8b) 1겹이며 이는 수용된 한계다. 이유: 대안(`olcAddContentAcl` TRUE, constraint overlay, 별도 create 신원)은 전역 영향 또는 신원 모델 변경이다. 비용: `W_data`에 임의 Add를 시킬 수 있으면 선택한 비밀번호의 계정이 생긴다. 탈출구: `olcAddContentAcl` TRUE 또는 constraint overlay. 회귀 시험 `TestMachineWriteClosedFieldSet`. AC-008의 `none`은 Modify에만 성립한다.

## Consequences

- 쓰기 켠 운영자는 단일 replica, 멱등 활성, `W_*` 계정·ACL, client 상한·그룹 허용 목록을 모두 설정해야 하며 하나라도 없으면 기동 실패한다.
- 교차 client 쓰기 격리는 앱 가드 1겹이다(D17). 하드 격리가 필요하면 D4의 확장이 필요하다.
- 발급된 토큰은 TTL 동안 유효(D12, #286 병행). 노출 상한의 최종 보안 승인은 T-013 병합 전에 받는다.
