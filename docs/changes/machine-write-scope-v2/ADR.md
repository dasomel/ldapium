# ADR: 머신 쓰기 v2b·v2c — 그룹·잠금·비밀번호 구획 (D379-1–D379-18)

- Status: v2b 결정(D379-3/4/5/6/7, 2026-10-12 유지보수자 수용: Q2·Q3·Q4·Q7 권고대로; 구현 단위가 병합되면 `Accepted`로 승격) · v2c 결정(D379-9–D379-16)은 **`Accepted for implementation start (2026-10-13), pending security-reviewer + Codex gate`**(유지보수자: Q1 승인, Q5·Q6 권고대로; Q11–Q13 잠정 — 권고, 명시 확인 아님). F-4는 유지보수자가 2026-10-13에 D379-18(대기 계정 전용 정책)로 결정했고 D379-9·D379-13은 그에 맞춰 개정됐다(Revision 7). [CHANGE.md](CHANGE.md)의 되돌리기 어려운 결정 요약. Revision 1·2(2026-10-11)가 Codex 1·2차 보안 검토를 반영했다(D379-7·D379-10·D379-14·D379-15·D379-16). 실측 전에는 닫을 수 없는 출하 차단 위험은 CHANGE.md "Ship-gating open risks". 구현 단위가 병합되면 해당 결정을 `Accepted`로 승격한다.
- Owner: 유지보수자(v2b 수용 2026-10-12, v2c 착수 승인 2026-10-13 — security-reviewer·Codex 게이트 대기)
- Related issue: [#379](https://github.com/dasomel/ldapium/issues/379)(닫지 않음). 부모: [machine-write-scope ADR](../machine-write-scope/ADR.md)(D1/D3/D4/D5/D9, D19–D22, D26)
- 위치 규약: 변경 패키지 안의 `ADR.md`(부모와 같음). 근거·대안·위협 모델 전문은 CHANGE.md에 있다.

## Context

부모 패키지(#285)는 첫 출하에서 사용자·멤버십 쓰기 5개만 열고 그룹 생성·수정·삭제, 잠금, 비밀번호를 닫았다. 닫은 이유는 각각 권한 부여 의미(`CreateGroup`이 바인드 DN을 seed 멤버로 넣음, `ui/backend/internal/ldapclient/groups.go:86`), 가용성(관리자 잠금, lockout 무력화), 자격 증명 취급(Password Modify에 control 불가, `ldapclient/users.go:285-304`)이다. 이 ADR은 그것들을 어떤 조건으로 여는지를 정한다.

## Decisions

| ID | 결정 | 되돌리기 어려운 이유 | 탈출구 |
|---|---|---|---|
| D379-1 | v2b(그룹·잠금)와 v2c(비밀번호)를 따로 수용·출하. v2c는 v2b와 부모 CI 릴리스 게이트 이후. | 외부 계약(scope·오퍼레이션)이 단계별로 늘어남 | 단계별 철회 |
| D379-2 | v2b는 새 플래그 없음(scope 부여·기존 `MACHINE_WRITE_LOCK_ENABLED`), v2c는 `MACHINE_WRITE_CRED_ENABLED` + `W_cred` 신원. | 설정 계약 | — |
| D379-3 | 머신 `createGroup`의 seed는 고정 placeholder DN(`MACHINE_WRITE_GROUP_SEED_DN`), `W_data` DN 아님. | 생성된 그룹 데이터에 seed가 남음 | 요청 첫 멤버 방식(별도 결정) |
| D379-4 | 생성 그룹은 허용 목록에 자동 편입되지 않는다. | 멤버십 = 권한 부여의 승인 경계 | 그룹 서브트리 허용(별도 결정) |
| D379-5 | 머신 `patchGroup`은 `description`만. | 그룹 이름 = 다운스트림 역할 키 | 사람 경로 |
| D379-7 | v2b는 잠금만 연다. 머신 잠금 해제는 열지 않는다(사람 전용). 관리 잠금 표지는 ppolicy duration 0 잠금과 같은 형태이고 `Lock`이 ppolicy 잠금을 덮어써서 값 기반 해제 규칙은 우회된다. | 외부 계약(`unlockUser`는 거부 목록 유지) | 지속 표지 기반 해제(별도 승인, CHANGE.md D379-7) |
| D379-8 | 잠금·해제·비밀번호 대상의 특권 그룹 멤버 거부(`memberOf` 사전 읽기 + 성립 시 ACL filter). | 보호 의미 | — |
| D379-9 | 머신 `setPassword`는 관리자형 설정: `{dn,password}`만, `oldPassword`·빈 값·`If-Match` 금지, 키 필수, 멱등 비밀번호 모드. **(Rev. 7)** 출하 기본 정책의 `pwdSafeModify TRUE`가 관리자형 설정을 거부하므로 대기 정책이 붙은 표지 계정에서만 동작한다(D379-18). `W_cred`는 비밀번호 관리자(`manage`)가 아니다. | 외부 계약 | — |
| D379-10 | 첫 v2c 출하는 대기 표지(`employeeType`, client 태그)와 함께 `W_data`가 만든 계정의 초기 비밀번호만(ACL: `creatorsName` ∧ 표지 ∧ `!(userPassword=*)`). 비밀번호 없는 기존 계정은 대상 아님. | 계정 탈취 경계, 속성 점유 | 재설정(별도 승인), 전용 스키마 속성(별도 패키지) |
| D379-11 | 비밀번호 포함 `createUser`는 첫 출하에서 닫는다. | 보상 흐름의 단일 연결 가정 | 두 신원 흐름(CHANGE.md D379-11) |
| D379-12 | 비밀은 응답·감사·멱등 저장 본문·로그에 없음, 멱등 지문 HMAC은 비밀번호 포함(재사용 탐지). | 비밀 위생 | — |
| D379-13 | 비밀번호 정책은 slapd만 강제하고, 적용이 증명되기 전에는 v2c를 열지 않는다. **(Rev. 7)** 적용 정책은 대기 정책이며 `pwdCheckQuality 2` 필수(1이면 사전 해시 우회, F-6); 길이는 exop·plain Modify 모두 실측 적용. | 정책 단일 출처 | — |
| D379-18 | 대기 계정 전용 정책(`pwdSafeModify FALSE`, `pwdCheckQuality 2`)을 표지 계정에만. **(Rev. 8)** `olcAddContentAcl TRUE`(Q15, 선행 조건) 아래 `W_data`가 **Add 시점에만** 표지·정책을 싣는다(filter: `creatorsName=W_data` ∧ 표지 ∧ 비밀번호 없음 ∧ 비특권 ∧ 정책; Modify 부착·삭제는 50); `W_cred` 정리는 표지 값·정확한 정책 값만, `W_data`가 만든 항목만; 앱은 표지 정확히 하나·`pwdChangedTime` 있으면 409; 스윕 3개(stuck·TTL은 `W_cred` 정리, 외부는 경보+런북). F-9(#399) 선행. | 기동·ACL·정리 계약, 정책 항목, DB 전체 `olcAddContentAcl` | 원자적 plain Modify(F-5 창 없음, accesslog 해시 비용) |
| D379-14 | auditlog와 v2c 동시 활성 금지(차트), `M` accesslog 읽기와 v2c 상호 배제(값 수준 거부가 증명되기 전), 증거는 평문+해시 패턴 스캔. | 기능 상호 배제 | 값 수준 거부 증명 후 공존 |
| D379-15 | v2c 전제(ACL 원문, 기본·대상별 정책, 표지 게이트, accesslog 자식 항목 비노출, 특권 그룹 설정)를 UI가 기동 시·`setPassword` 직전·60초 주기로 검사, 실패 시 기동 거부 / 요청 503 / 비밀번호 오퍼레이션 503. 남는 창은 검사→쓰기 TOCTOU(R-4). | 기동·요청 계약, 카나리 운영 | 주기 조정 |
| D379-16 | 설정 읽기 전용 신원: `cn=config`의 메인 DB `olcAccess`와 ppolicy `olcPPolicyDefault`만 read. 범위 전체 ACL·정책 증명에 필요. | 신원·Secret 추가, `cn=config` ACL | 운영 점검 스크립트 결과에 의존(Q13, 노출 창 확대) |

D379-6(그룹 삭제 조건)은 되돌리기 쉬운 운영 결정이라 CHANGE.md에만 둔다.

## Consequences

- 자동화가 그룹을 만들고 멤버를 채우려면 운영자가 그 그룹을 허용 목록에 넣고 재배포해야 한다(D379-4).
- 비밀번호 자동화는 신규 계정의 초기 비밀번호만 가능하다. 재설정은 사람 경로(D379-10).
- `setPassword`의 대상 타입·특권 여부는 LDAP control로 원자적으로 걸 수 없어 `M` 사전 읽기(TOCTOU)와 `W_cred` ACL filter에 의존한다. ACL filter의 성립(EVIDENCE `E-07`/`E-08`/`E-16`)과 동시 Password Modify의 단일 성공(`E-17`)이 v2c 출하 조건이다.
- v2c를 켠 배포는 subtree마다 카나리 항목 3개와 설정 읽기 전용 신원을 유지해야 하며, 전제 검사가 실패하면 UI가 기동하지 않는다(D379-15/16). auditlog·`M` accesslog 읽기와는 함께 켤 수 없다(D379-14).
- 머신은 어떤 잠금도 풀 수 없다(D379-7). 잠금 해제 자동화는 사람 경로 또는 별도 승인.
- 그룹 권한이 그룹 멤버십으로 주어지는 사용자를 보호하려면 운영자가 `MACHINE_WRITE_PRIVILEGED_GROUPS`를 정확히 설정해야 한다.
- Revision 15 (2026-10-14, T-026 검토 반영·유지보수자 결정): 기동·주기 검사가 `W_cred` 무잠금 정책을 강제한다(Q18 (b)); 플래그만 끈 재배포는 403(Q19); M-3 `mail`·`uid` 바꿔치기는 수용 위험(문서 경고).
- Revision 14 (2026-10-14, T-026 개방): `setPassword`가 열렸다(D379-9/10). Q17 결정(무잠금): `W_cred`는 9.1 무잠금 정책을 갖고 무차별 대입 완화(긴 무작위 비밀번호·네트워크 제한·실패 bind 경보)는 운영자 책임이다. 플래그만 끈 재배포는 기동하고 `setPassword`는 bind 없이 거부된다(실제 Load 경로 403, 상태 코드는 Q19). T-028이 `W_cred` 정책을 강제할지는 Q18.
- Revision 10 (2026-10-14, 유지보수자 Q16 수용): v2c를 켜면 머신 `deleteUser`·modrdn은 `W_data`가 만들지 않은 사용자에게 50(v2a 계약 축소, 의도된 결과). 잔여 위험(스스로 만든 계정, 중첩 특권 그룹) 수용.
- Revision 9 (2026-10-13, Revision 8 재검토 반영, EVIDENCE.md §2h): M-3(유출된 `W_data` + `password.write` client로 삭제→대기 재생성→설정→특권 재가입) 완화 — 비-`W_data` 사용자 `entry` `=rsc`, 특권 그룹 `member` `=rsc`(둘 다 실측 50). 결과: v2c를 켜면 머신 `deleteUser`·modrdn이 `W_data`가 만든 사용자로 좁아진다; 잔여 위험(스스로 만든 계정, 중첩 특권 그룹)은 Q16. 롤백은 부착 차단 → 0건 확인 → 정리 권한 제거. R-3·AC-010c는 provider 하나 안에서만.
- Revision 8 (2026-10-13, 독립 검토 security-reviewer BLOCKER 0·MAJOR 2, Codex P1 3·P2 2 반영; 유지보수자 Q14 수용+스윕 강화, Q15 `olcAddContentAcl TRUE` 채택, F-9 #399 선행 조건; EVIDENCE.md §2g): 표지 규칙이 Modify에도 적용되던 문제(M-1)를 Add 전용 filter로 닫음, R-3은 단일 slapd에서만(다중 provider는 last-write-wins), 롤백 시 남은 부착을 정리 권한보다 먼저 지움, 정리 실패 창의 상한은 LDAP·`W_cred`가 살아 있을 때만 "스윕 한 주기".
- Revision 7 (2026-10-13, 유지보수자 F-4 결정, EVIDENCE.md §2f): D379-18 채택(`manage` ACL·기본 정책 변경 기각). 결과: 정리 전 짧은 창과 정리 실패 시 다음 스윕의 정리 시도까지 F-5 오라클이 남는다(고정 시간 상한 없음, Revision 9 정정; Q14 수용). Add 안의 부착은 `olcAddContentAcl FALSE`라 ACL이 막지 못한다(Q15, #386). F-7(accesslog `extended` → slapd 중단)·F-9(사용자가 자기 `pwdPolicySubentry`를 설정 가능)는 범위 밖 별도 이슈.
- Revision 6 (2026-10-13, v2c 설계 게이트 실측 EVIDENCE.md §2e; 결정 문구 불변, 개정 필요 표시): 출하 기본 정책의 `pwdSafeModify: TRUE`가 `W_cred`(`=w`)의 초기 설정을 전부 거부한다(F-4). 비밀번호 관리자(`manage`) 우회는 길이·품질 검사를 건너뛰어 D379-13을 깨고(기각), 대기 계정별 정책(safeModify FALSE, `pwdCheckQuality 2`)은 경계를 지키지만 비밀번호가 생긴 뒤 lockout 없는 일치 오라클(F-5)을 연다. ACL filter 경계(E-07 직접·E-08·E-16)와 동시 단일 성공(E-17)은 성립했으므로 D379-10은 유지된다. D379-9·D379-13 개정과 D379-16의 보강(`entry`, 메인 DB `none`)은 유지보수자 결정 대상이다.
- Revision 4 (2026-10-12, T-015 실측; 결정 불변): D379-7의 근거 (b)는 출하 이미지에서 사실이 아니다(`pwdLockoutDuration=0` 잠금은 표지가 아니라 타임스탬프를 남김). 해제 사람 전용은 근거 (a)(c)와 유지자 결정으로 유지. 중첩 특권 그룹 멤버 잠금 허용(수용한 잔여 위험)과 `write-lock.ldif`에 특권 filter가 없다는 사실은 실측으로 확인됨. 상세는 CHANGE.md Revision 4, EVIDENCE.md §2b.
