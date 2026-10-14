# Change: 머신 쓰기 범위 v2b·v2c — 그룹 생성·수정·삭제, 사용자 잠금, 비밀번호 구획(`W_cred`)

- Change class: `D` — 신규 자격 증명 쓰기 경로(`W_cred`), 비밀번호 취급, 권한 부여 의미(그룹·`memberOf`), 파괴적 디렉터리 동작(그룹 삭제·계정 잠금). AGENTS.md "Rules"에 따라 설계 변경이다. **하위 범위(v2b, v2c)마다 따로 수용한다**(#379 수용 조건 "Class D change per sub-scope, accepted before code").
- Owner: 유지보수자(수용 대기)
- Related issue: [#379](https://github.com/dasomel/ldapium/issues/379)(닫지 않음). 선행: [#285](https://github.com/dasomel/ldapium/issues/285) [machine-write-scope](../machine-write-scope/CHANGE.md)(v2a, 첫 출하 5개 오퍼레이션 구현됨, 기본 꺼짐). 연관: [machine-token-revocation](../machine-token-revocation/CHANGE.md)(#286, 구현됨, 기본 꺼짐).
- Status: **v2b `Accepted` (2026-10-12, 유지보수자; Q2·Q3·Q4·Q7 권고대로 결정)** · **v2c `Accepted for implementation start (2026-10-13), pending security-reviewer + Codex gate`** (유지보수자 2026-10-13: Q1 승인, Q5·Q6 권고대로; Q11·Q12·Q13은 명시 답변이 없어 권고안을 **잠정(provisional, recommendation, not explicitly confirmed)** 으로 따른다). 설계 게이트 실측은 [EVIDENCE.md §2e](EVIDENCE.md)이며 F-4(출하 기본 정책의 `pwdSafeModify: TRUE`가 `W_cred`의 모든 초기 설정을 거부)는 **유지보수자가 2026-10-13에 결정했다**: 대기 계정 전용 정책(`pwdSafeModify FALSE`, `pwdCheckQuality 2`)을 표지 계정에만 붙이고 정리 단계에서 표지와 함께 뗀다(D379-18; `manage` ACL·기본 정책 변경은 기각). D379-9·D379-13·REQ-010/014/018은 Revision 7로 개정했고 그 경로는 [EVIDENCE.md §2f](EVIDENCE.md)에서 실측했다. 독립 검토(security-reviewer: BLOCKER 0, MAJOR 2; Codex: P1 3, P2 2)와 유지보수자 결정(2026-10-13: **Q15 `olcAddContentAcl TRUE`를 v2c 선행 조건으로 채택**, **Q14 19/50 창 수용 + 스윕 강화**, **F-9(#399, 사용자의 자기 `pwdPolicySubentry` 쓰기)는 v2c 구현 전에 별도 PR로 고치는 선행 조건**)을 Revision 8로 반영했다(EVIDENCE §2g 실측). Revision 8 재검토(security-reviewer: BLOCKER 0, MAJOR 1, MINOR 4; Codex: P1 1, P2 2)는 Revision 9로 반영했다(EVIDENCE §2h). Q16은 2026-10-14 유지보수자가 **수용**했다(v2a `deleteUser`·modrdn 계약 축소, 아래 Q16). Revision 9에 대한 재검토는 아직이다. 전용 security-reviewer 라운드와 Codex critic은 아직이다(이 Status는 그 결과를 주장하지 않는다). **T-026(2026-10-14)이 `setPassword`를 열었다**(Revision 14): Q17 결정됨(무잠금), Revision 12의 T028-F1·D379-16 확장 수용 기록, 새 질문 Q18·Q19. T-026의 Class D 독립 검토·전용 security-reviewer는 아직이다. (2026-10-13 작성 당시: v2c 구현 단위는 하나도 착수하지 않았다.) v2b 구현은 TASKS T-010–T-015 순서로 진행하고 T-014 전까지 새 오퍼레이션은 도달 불가다. 관련 후속 이슈: [#390](https://github.com/dasomel/ldapium/issues/390). 아래 문장은 수용 전 작성 당시의 설계 문서 설명이다: **설계 문서다. 이 패키지는 코드·ACL·Helm·스크립트·`openapi.json`을 바꾸지 않는다.** 구현 단위(TASKS `Implement`)는 수용 전에는 하나도 착수하지 않는다. v2c는 부모 패키지 Resolved Q1에 따라 **별도 명시 승인**과 **전용 security-reviewer 라운드**가 수용 조건이다. Revision 1·2(2026-10-11)가 Codex 보안 검토 1·2차 지적을 반영했다(아래 "Revision"). 실측 없이는 닫을 수 없는 항목은 "Ship-gating open risks"에 있다.
- 작성일: 2026-10-11
- 형식: 부모 [machine-write-scope](../machine-write-scope/CHANGE.md)와 완료 예시 [machine-token-revocation](../machine-token-revocation/CHANGE.md)를 따른다. 코드 주장은 파일:줄(main `049fcc3` 기준, 경로 접두 `h/` = `ui/backend/internal/httpapi/`, `l/` = `ui/backend/internal/ldapclient/`, `c/` = `ui/backend/internal/config/`, `f/` = `scripts/test/fixtures/machine-acl/`)로 인용한다. 실행하지 않은 것은 "미검증"으로 표시하고 [EVIDENCE.md](EVIDENCE.md)의 라이브 계획(`E-xx`)에 연결한다.
- 결정 ID는 이 패키지 고유의 `D379-n`이다(부모의 `D1`–`D26`과 섞이지 않게). 부모 결정은 "부모 D22"처럼 쓴다.

> 부모 패키지의 결정은 **그대로 승계한다**: 쓰기 신원 구획 `W_data`/`W_lock`/`W_cred`(부모 D3), 오퍼레이션별 scope(D7), 엄격한 하위 가드(D20), 보호 DN·대상 타입(D19), 정규형 DN(D26), 머신 `If-Match` 강제(D21), 멱등 주체 = client(D9), 쓰기 감사(D6), 쓰기 한도(D8d), 긴급 차단(D12), 영구 거부(D2: `moveEntry`·백업·프로파일·`getMe`), `PUT` 미개방(Q2/D25), 서버 생성 비밀번호 금지(D16). 이 패키지는 그 위에 **어떤 오퍼레이션을 어떤 조건으로 더 여는지**만 정한다.

## Problem

부모 패키지는 첫 출하에서 그룹 생성·수정·삭제, 잠금, 비밀번호를 의도적으로 닫았다(부모 Resolved Q1/Q2, D22). 오늘 상태(코드 확인):

| # | 관찰 | 근거 |
|---|---|---|
| P1 | 열린 머신 쓰기는 5개뿐이다: `createUser`(비밀번호 없이)·`patchUser`·`deleteUser`·`addGroupMember`·`removeGroupMember`. 나머지 8개(`updateUser`, `setPassword`, `unlockUser`, `lockUser`, `createGroup`, `updateGroup`, `patchGroup`, `deleteGroup`)는 거부 목록 데이터에 있고, 줄이려면 `machineWriteOpenedBy`에 D-id가 있어야 한다. | `h/machine_write_scopes.go:15-21`, `h/machine_write_ops.go:34-47`, `h/machine_contract_test.go:51-54,65-71,533-558` |
| P2 | 클라이언트 상한에는 열린 scope만 들어갈 수 있다. `directory.users.lock`/`unlock`, `directory.groups.create`/`update`/`delete`, `directory.users.password.write`는 어휘에는 있지만 상한에 쓰면 기동 실패다. | `c/machine.go:89-113` |
| P3 | `CreateGroup`은 `groupOfNames`의 필수 `member`를 **바인드 DN**(`c.dn`)으로 채운다. 머신 경로에서는 그것이 `W_data`이므로, 그대로 열면 모든 머신 생성 그룹에 `W_data`가 멤버로 들어가고 memberof overlay가 `W_data` 항목에 `memberOf`를 단다. | `l/groups.go:61-95`(특히 `:86`), `image/ldifs/01-cn-config.ldif:108-121`(memberof·refint) |
| P4 | `W_data`는 보호 집합에 있으므로(`c/machine_write_scope.go:235-247`) 머신의 `removeGroupMember`는 그 seed 멤버를 지울 수 없다(`h/machine_write_guard.go:104-116`, `h/machine_write_pipeline.go:326-337`). P3을 그대로 열면 seed가 영구히 남는다. | 위 인용 |
| P5 | `RemoveMember`는 마지막 멤버를 지우면 slapd가 거부한다(`groupOfNames`는 `member` 1개 이상 필수). | `l/groups.go:198-219` 주석 |
| P6 | `PatchGroup`은 `cn`과 `description`을 Replace한다. 그룹 RDN은 `cn`이라(`buildGroupDN`, `l/groups.go:75`) `cn` 교체는 RDN 값을 지우는 수정이 된다. slapd가 `notAllowedOnRDN`(67)으로 거부할 것으로 예상하지만 **미검증**(`E-05`). | `l/groups.go:125-156` |
| P7 | `W_data` ACL의 쓰기 가능 속성 목록에 `description`이 **없다**. 즉 오늘 ACL로는 머신 `patchGroup`(설명 변경)이 LDAP에서 거부된다. | `f/write-data.ldif:58-60` |
| P8 | 잠금 구획은 설정·바인드 선택·ACL 조각이 이미 있다: `MACHINE_WRITE_LOCK_ENABLED`(기본 꺼짐)와 `MACHINE_WRITE_LOCK_BIND_DN`/`_PASSWORD`, `writeBindIdentity("lock")`, `W_lock`은 `pwdAccountLockedTime`만 write. 오퍼레이션만 열리지 않았다. | `c/machine_write.go:32-37,66-80`, `h/machine_write_ops.go:85-97`, `f/write-lock.ldif:13-47` |
| P9 | `Lock`/`Unlock`은 `writeRevisionControls(ctx, ifMatch, "inetOrgPerson")`을 쓰므로 머신 표지가 있으면 `(&(entryCSN=…)(objectClass=inetOrgPerson))` assertion이 실린다. `Lock`은 고정 값 Replace, `Unlock`은 값 없는 Replace라 **자연 멱등**이다. | `l/users.go:353-427`, `l/machine_write_assertion.go:30-47` |
| P10 | 비밀번호 설정은 RFC 3062 Password Modify 확장 연산이며 **control을 실을 수 없다**(go-ldap v3.4.14 `PasswordModifyRequest`). 따라서 `If-Match`(assertion)도, objectClass 단언도 LDAP 쪽에서 원자적으로 걸 수 없다. 사람 경로는 `If-Match`가 오면 400이다. | `l/users.go:285-304`, `l/create_compensation.go:40-47`, `h/conditional.go:49-54` |
| P11 | 비밀번호를 담은 `createUser`는 Add → Password Modify 2단계이고, 실패 시 보상 Delete는 `creatorsName == 바인드 DN`일 때만 한다. **두 단계가 같은 연결·같은 신원**이다. `W_data`(Add)와 `W_cred`(비밀번호)를 분리하면 이 구조를 그대로 쓸 수 없다. | `l/users.go:84-140`, `l/create_compensation.go:12-53` |
| P12 | 사람 경로 비밀번호 한도는 `sess.ID + "\x00" + DN`으로 키를 만든다. 머신 요청의 임시 세션은 `ID`가 비어 있으므로(부모 P1) 그대로 쓰면 **모든 client가 같은 키 공간**을 공유한다. 이 한도는 틀린 현재 비밀번호(`oldPassword`) 반복을 막는 용도다. | `h/user_handlers.go:169-182` |
| P13 | 멱등 미들웨어는 비밀번호 라우트에 대해 서버 생성 요청을 키와 함께 422로 거부하고, 성공 응답을 `{}`로만 저장한다. 그러나 머신 쓰기 파이프라인은 `s.idempotent(r.execute, false)`, 즉 **비밀번호 플래그 없이** 기록을 시작한다. | `h/idempotency.go:99-103,141-144,339-341`, `h/machine_write_pipeline.go:382` |
| P14 | 멱등 기록은 요청 본문이 아니라 HMAC 지문(method·route·정규화 본문)과 4 KiB 이하 결과만 보관한다. 지문 입력에는 본문의 비밀번호가 포함된다. | `h/idempotency.go:33-36` |
| P15 | 머신 쓰기 본문은 오퍼레이션별 닫힌 필드 집합만 받는다. 현재 집합에는 `password`·`oldPassword`가 없다(그래서 D15·D16이 구조적으로 지켜진다). | `h/machine_write_attributes.go:13-59` |
| P16 | 기본 비밀번호 정책: `pwdCheckQuality: 1`, `pwdMinLength`, `pwdInHistory: 5`, `pwdLockout: TRUE`, `pwdSafeModify: TRUE`. 앱의 `validate.Password`는 비어 있지 않음과 1024자 상한만 본다(정책은 slapd 몫). **관리자형 재설정(요청자 ≠ 대상)에 이 정책이 적용되는지는 미검증**(`E-10`). | `image/entrypoint.sh:1341-1376`, `ui/backend/internal/validate/validate.go:60-80` |
| P17 | accesslog의 기본 `olcAccessLogOps`는 `reads bind`이며 쓰기 기록은 운영자가 `LDAP_ACCESSLOG_OPS`로 켤 때만 생긴다. `reqMod`는 속성 **값**을 담을 수 있다. 머신 감사 읽기는 속성 **이름**만 돌려준다. Password Modify가 accesslog에 해시를 남기는지는 **미검증**(`E-12`). | `image/entrypoint.sh:1267-1277`, `l/audit.go:25-30,257`, `h/machine_guard.go:18`, `f/accesslog-optin.ldif` |
| P18 | `M`의 ACL은 비밀 속성(`userPassword` 등)만 `none`이고 허용 base 안의 나머지(`memberOf` 포함)는 read다. 즉 `M` 사전 읽기로 대상의 `memberOf`는 볼 수 있지만 `userPassword` 존재 여부는 볼 수 없다. | `f/main-database.ldif` |
| P19 | `M` 사전 읽기(`WriteIdentityReader.Check`)는 대상이 기존 `inetOrgPerson`/`groupOfNames`이고 보호 항목(설정 + 고정 `cn=admin`·`cn=replicator`)이 아님을 slapd 관점으로 확인한다. `memberOf`는 아직 보지 않는다. | `l/machine_write_identity.go:79-117` |
| P20 | auditlog overlay(`LDAP_AUDIT_ENABLED`, 기본 `false`)는 **성공한 모든 쓰기**를 LDIF로 `LDAP_AUDIT_FILE`(기본 `/dev/stdout`, 즉 slapd 컨테이너 로그)에 쓴다. 속성 제외 설정은 이 저장소에 없다. Password Modify의 결과 Modify가 해시된 `userPassword`를 그 LDIF에 남기는지는 **미검증**(`E-12`)이지만, 남긴다면 해시는 로그 수집 파이프라인 전체로 퍼진다. 평문 센티널 스캔으로는 해시를 찾지 못한다. | `image/entrypoint.sh:504-505,1176-1199` |
| P21 | accesslog DB의 머신 읽기 옵트인은 `M`에게 accesslog **전체** read를 준다(`to * by M read`). 즉 `reqMod`/`reqOld`에 해시가 있으면 `M` 자격 증명으로 LDAP을 직접 읽어 해시를 얻는다(HTTP 응답은 속성 이름만 주므로 HTTP 경로와 별개). | `f/accesslog-optin.ldif:1-9`, `l/audit.go:25-30` |
| P22 | 관리 잠금 표지 `000001010000Z`는 사람 `lockUser`만의 것이 아니다: ppolicy가 `pwdLockoutDuration=0`으로 잠근 계정도 같은 "시각 없음" 형태를 남기고(`l/users.go:382-390` 주석), `Lock`은 Replace라 이미 걸린 ppolicy 잠금(시각 값)을 표지로 **덮어쓴다**(`l/users.go:392-401`). 따라서 값만으로 "누가 왜 잠갔는지"를 구별할 수 없다. `M`의 비밀 목록에 `pwdAccountLockedTime`은 없어 `M`은 값을 읽을 수 있다. | `l/users.go:382-427`, `f/main-database.ldif` |
| P23 | `creatorsName`은 slapd가 Add 시 바인드 DN으로 채우는 운영 속성이며, 기존 보상 흐름이 "이 요청이 만든 항목"의 증거로 이미 쓴다(D216-5). ACL `filter=`에서 `creatorsName`이 평가되는지는 **미검증**(`E-16`). | `l/create_compensation.go:17-26` |

## Intent

부모 패키지가 남긴 두 단계를 **서로 독립된 수용 단위**로 설계한다.

- **v2b**: 그룹 생성·수정(설명만)·삭제와 사용자 **잠금**. 잠금 **해제는 사람 전용으로 남긴다**(D379-7). `W_data`/`W_lock` 구획 안에서 끝나며 새 자격 증명을 만들지 않는다. 권한 부여(그룹)와 가용성(잠금)의 경계를 부모 D22·D19 위에서 닫는다.
- **v2c**: 비밀번호 구획 `W_cred`. 새 LDAP 신원·새 Secret·새 ACL 조각과 머신 `setPassword`를 연다. 비밀번호 쓰기는 계정 탈취와 직결되므로 **이 기능이 대기 표지와 함께 만든 계정의 초기 비밀번호만**(재설정 아님, 비밀번호 없는 기존 계정 아님) 여는 것을 권고하고, 전제를 UI가 기동 시 스스로 증명하며(D379-15), 비밀(평문·해시)이 응답·감사·멱등 기록·로그에 0건임을 라이브로 증명한 뒤에만 연다.

## Scope

- In scope(설계): 오퍼레이션별 쓰기 표, scope·구획 매핑, `createGroup` seed 멤버(부모 D22), 그룹 허용 목록과 생성 그룹의 관계, 잠금·비밀번호 대상 제한(특권 멤버 거부), `W_cred` ACL 스케치, 머신 `setPassword` 계약(본문·헤더·멱등·한도·감사), 비밀번호 포함 `createUser` 결정, 위협 모델, 수용 시나리오, 작업 분해, 라이브 증거 계획.
- Affected(구현 시): `h/machine_write_ops.go`·`h/machine_write_scopes.go`·`h/machine_write_attributes.go`·`h/machine_write_pipeline.go`·`h/machine_write_runtime.go`·`h/machine_contract_test.go`, `c/machine.go`·`c/machine_write*.go`, `l/groups.go`(머신 경로 seed), `l/machine_write_identity.go`(특권 멤버 확인), `f/write-data.ldif`(`description`), 신규 `f/write-cred.ldif`, `docs/machine-write-account.md`·`docs/machine-auth-operations.md`·`docs/api.md`·`docs/audit-event-schema.md`·`llms.txt`·OpenAPI, 차트 `ui.machineAuth.write.*`, 라이브 시험 스크립트, CI 릴리스 게이트.
- 대상: 외부 자동화(온보딩/오프보딩), 운영자, 보안 검토자.

## Non-goals

- 부모 D2 영구 거부(`moveEntry`, 백업 8, 프로파일 14, `getMe`)와 `PUT`(`updateUser`·`updateGroup`): 계속 닫는다.
- **서버 생성 비밀번호**(`generatedPassword`): 머신 경로 영구 금지(부모 D16·Q10). 이 패키지는 다시 열지 않는다.
- **현재 비밀번호 확인형 변경**(`oldPassword`, 셀프서비스 의미): 머신은 다른 사용자의 비밀번호를 "관리자로서" 설정한다. 머신 본문에 `oldPassword`는 없다(D379-9).
- 비밀번호·해시 **읽기**: 불변(`entryRedactedAttrs`, AGENTS.md "Attribute exposure").
- 비밀번호 **재설정**(이미 비밀번호가 있는 계정)과 **비밀번호가 원래 없는 기존 계정**(SSO·외부 인증)의 비밀번호 설정: 첫 v2c 출하에서 제외 권고(Q5). 연다면 별도 승인.
- 머신 잠금 **해제**(`unlockUser`): v2b에서 열지 않는다(D379-7). 관리 잠금과 ppolicy 잠금을 값으로 구별할 수 없어(P22) 어떤 해제 규칙도 lockout 무력화를 막지 못한다. 연다면 아래 D379-7 "탈출구"의 지속 표지 설계로 별도 승인.
- client별 쓰기 DN(부모 D4)·위임(부모 D5)·다중 replica 멱등(부모 Q8): 변경 없음.
- 그룹 허용 목록의 패턴/서브트리 확장: 첫 v2b 출하에서 제외 권고(Q3).
- 사람 UI·쿠키 경로의 그룹·잠금·비밀번호 동작: 바이트 불변.

## Requirements

- `REQ-001` — 단계 독립·기본 꺼짐: v2b와 v2c는 각각 별도 수용·별도 PR·별도 증거로 열리며, 어느 쪽도 다른 쪽 없이 안전하다. 꺼진 상태(오퍼레이션 미등록, scope 미허용)의 응답·OpenAPI·감사·거부 목록은 v2a와 바이트 동일하다. v2c는 **별개 플래그** `MACHINE_WRITE_CRED_ENABLED`(기본 `false`)가 켜지고 `W_cred` 신원이 유효할 때만 열린다.
- `REQ-002` — 거부 목록 축소 규칙: 오퍼레이션을 여는 PR은 `machineWriteOps`·`machineWriteCatalog`·`config.MachineWriteOpenScopes`·`machineWriteOpenedBy`(이 패키지의 `D379-n` 인용)·OpenAPI `x-machine-scope`를 같은 PR에서 바꾼다. `updateUser`·`updateGroup`은 거부 목록에 남는다(D13 계약, `h/machine_contract_test.go:533-558`).
- `REQ-003` — seed 멤버: 머신 경로의 `createGroup`은 `W_data` DN을 seed로 쓰지 않는다. seed는 설정된 **고정 비특권 placeholder DN**(`MACHINE_WRITE_GROUP_SEED_DN`)이며, 그 DN은 보호 집합에 들어가 머신이 멤버로 넣거나 빼거나 수정·삭제할 수 없다(D379-3). 사람 경로의 seed(`c.dn`)는 불변이다.
- `REQ-004` — 그룹 대상 제한: `patchGroup`·`deleteGroup`의 대상은 (a) 엄격한 상한 하위(부모 D20), (b) 보호 집합·특권 그룹 아님(부모 D19/D22), (c) 그 client의 `MACHINE_WRITE_GROUPS`(정확 DN)에 있음, (d) `groupOfNames` 단언(assertion + `M` 사전 읽기)을 모두 만족해야 한다. `createGroup`의 부모는 `GroupCreateBase`이고 그것이 상한 자신이거나 하위여야 한다(`h/group_handlers.go:23-43`). 생성된 그룹은 **자동으로 허용 목록에 들어가지 않는다**(Q3).
- `REQ-005` — `patchGroup`은 `description`만: 머신 `patchGroup` 본문은 `dn`과 `description`(문자열 또는 `null`)만 받는다. `cn`(RDN) 변경은 머신 경로에서 400이다. `W_data` ACL에 `description` write를 추가한다(P7).
- `REQ-006` — 잠금 구획: `lockUser`는 `W_lock`으로만 실행하고(`MACHINE_WRITE_LOCK_ENABLED=true` 필수, 꺼져 있으면 오퍼레이션 도달 불가), scope는 `directory.users.lock`, 엄격한 `If-Match`(부모 D21)와 `inetOrgPerson` 단언, `Idempotency-Key` 필수. `unlockUser`와 `directory.users.unlock`은 거부 목록·미개방 어휘에 남는다(상한에 쓰면 기동 실패, `c/machine.go:103-113`).
- `REQ-007` — 특권 멤버 거부: 잠금·비밀번호 설정의 대상 사용자가 `MACHINE_WRITE_PRIVILEGED_GROUPS` 중 하나의 멤버이면(`M` 사전 읽기의 `memberOf`) 쓰기 없이 403이다. LDAP ACL 백스톱(`W_lock`/`W_cred` 규칙의 `filter=(!(memberOf=<특권 그룹>))`)은 라이브로 성립이 확인될 때만 "백스톱"이라 부른다(`E-07`). 이 검사는 부모 D19(f)(관리자 권한이 그룹으로 주어지는 사용자는 DN 보호 집합에 없음)의 v2b/v2c용 보강이다. **D379-17(구현 T-013)**: `memberOf`가 비어 있다는 것은 `M` ACL·overlay 부재와 구별되지 않으므로, 대상의 `memberOf`(속성 이름은 대소문자 무시)와 각 특권 그룹의 `member` 목록을 둘 다 읽는다. 그룹을 읽을 수 없거나 없거나 `member`가 비어 보이면, 특권 목록이 비어 있으면 거부(fail closed)이고, lock scope 상한이 있으면 `MACHINE_WRITE_PRIVILEGED_GROUPS`가 비어 있지 않아야 기동한다. **수용한 잔여 위험**: 중첩 그룹(특권 그룹의 하위 그룹 멤버)과 읽은 뒤 추가된 멤버십(TOCTOU)은 보지 못한다. T-015 라이브 드릴이 중첩 그룹 사례를 기록한다.
- `REQ-008` — 잠금 해제는 사람 전용: 머신 경로의 `POST /api/users/unlock`은 scope·플래그와 무관하게 403 `scope_denied`·bind 0이다(부모 D13 거부 목록). 이유: (a) 머신 `lockUser`→(태그 재조회)→`unlockUser` 왕복이 ppolicy 잠금(시각 값)을 표지로 덮어쓴 뒤 해제하는 우회가 되고, (b) `pwdLockoutDuration=0` ppolicy 잠금은 표지와 같은 형태라 구별 불가하며, (c) 메모리 한도는 재시작·replica로 초기화된다(P22). 디렉터리 상태로 지속되는 구별 수단이 생기기 전에는 열지 않는다(D379-7).
- `REQ-009` — `W_cred` 신원: `MACHINE_WRITE_CRED_BIND_DN`/`_PASSWORD`, `M`·`W_data`·`W_lock`·관리자·서비스 계정·rootdn·복제 신원과 `ParseDN` 동등이면 기동 실패(부모 D3/D10 방식, 변형 표 재사용). `W_cred` DN은 보호 집합에 들어간다.
- `REQ-010` — `W_cred` ACL과 초기 비밀번호 대상: `W_cred`는 쓰기 상한 합집합 안에서 **이 기능으로 만든 계정**의 `userPassword`에만 **쓰기**(읽기 없음)를 갖는다. 조건은 ACL filter로 `(&(objectClass=inetOrgPerson)(creatorsName=<W_data DN>)(employeeType=ldapium-credential-pending:*)(!(userPassword=*))<특권 제외>)`(D379-10). 즉 (a) `W_data`가 만들었고(P23, 서버가 채우는 값), (b) 생성 시 자격 증명 대기 표지가 붙었고, (c) 아직 비밀번호가 없는 항목만. 표지가 없는 **기존 비밀번호 없는 계정**(SSO·외부 인증 사용자, 가져오기, v2a로 만든 계정)은 대상이 아니다 — **Revision 8 정정**: 이 문장은 표지·정책을 나중에 붙일 수 없을 때만 참이다. Revision 7까지의 `W_data` 표지 `add` 규칙은 Modify에도 적용되어 `W_data`(유출 시)가 v2a 계정에 표지를 붙일 수 있었다(검토 M-1). Revision 8은 `olcAddContentAcl TRUE`(Q15) 아래에서 표지·정책을 **Add 시점에만** 허용하고(규칙 filter가 자기 속성을 요구하므로 그 속성이 없는 항목의 Modify는 통과하지 못함), v2a·SSO 계정의 Modify 표지 부착은 50으로 실측됐다(§2g M-1). `userPassword` 쓰기 외에 `W_cred`가 갖는 **유일한** 쓰기는 표지 값 자체의 삭제(`employeeType`, `val.regex`로 표지 형식에 한정한 `=z`)다. 그 밖의 속성·항목 생성·삭제·`pwd*`·`memberOf`·시스템 컨테이너·복제 신원에는 `none`. **client 귀속은 앱만 강제한다**: ACL은 표지 태그를 구별하지 않으므로 `W_cred` 자격 증명을 직접 쓰는 주체는 어느 client의 대기 계정에도 설정할 수 있다(부모 D17과 같은 한계). filter 성립(`E-08`, `E-16`)은 출하 조건(R-1). **Revision 7 (D379-18)**: filter에 `(pwdPolicySubentry=<대기 정책 DN>)`을 더한다(다른 정책이 붙은 표지 계정은 50, EVIDENCE §2f D-4). `W_cred`의 두 번째 정리 쓰기는 그 정책 값 하나의 삭제(`val="<대기 정책 DN>"`의 `=z`)다. `entry` 규칙은 불필요하다(Password Modify는 `entry` 접근 없이 성공, §2e E-09).
- `REQ-011` — 머신 `setPassword` 계약: 본문은 정확히 `{"dn","password"}`이고 둘 다 비어 있지 않은 문자열이다. `oldPassword`·빈 `password`(서버 생성)·알 수 없는 필드 → 400, 쓰기 없음. `If-Match`가 오면 400(사람 경로와 같은 의미, P10). `Idempotency-Key` 필수(428). 멱등 기록은 **비밀번호 플래그를 켠 채로** 시작해 저장 본문이 `{}`를 넘지 않는다(P13).
- `REQ-012` — 비밀·해시 무노출: 비밀번호 **평문과 해시**는 HTTP 응답(성공·실패·재생), UI 감사 줄, 멱등 기록(지문 외), 프로세스 로그, slapd·Keycloak·UI 컨테이너 로그(auditlog stdout 포함, P20), `M`이 읽을 수 있는 accesslog(`reqMod`/`reqOld`, P21) 어디에도 나오지 않는다. 오류 메시지에 값이 섞이지 않는다. 증명은 평문 센티널 스캔 **과** 해시 패턴 스캔(`{SSHA}`·`{SSHA256}`·`{SSHA512}`·`{ARGON2}`·`{CRYPT}`·`{PBKDF2…}`·`{SHA}`·`{MD5}`·`{SMD5}`와 LDIF base64 형식 `userPassword::`, `e1NTSEF9`·`e0FSR09OMn0` 등 접두)으로 한다(`E-13`). 노출 경로 차단은 D379-14(auditlog 금지, accesslog 값 수준 거부 또는 `M` 읽기 상호 배제).
- `REQ-013` — 비밀번호 한도와 동시성: `setPassword`는 client 쓰기 예산(부모 D8d)에 더해 **대상 전역 직렬화**(키 = 대상 `entryUUID`, 동시에 1건)와 **비밀번호 전용 전역 예산**(기본 1 rps)을 둔다. 앱 경로에서 같은 대기 계정에 쓸 수 있는 client는 표지 태그의 주인 하나뿐이므로 동시성의 대상은 같은 client의 서로 다른 `Idempotency-Key`와, 앱을 우회한 `W_cred` 직접 호출이다. 직렬화는 replica 안에서만 유효하므로 "정확히 한 건" 보장은 LDAP 쪽(`E-17`)에서 증명돼야 하며 그 전에는 경계를 주장하지 않는다(R-3). 사람 경로 `passwordLimiter` 키(`sess.ID`)는 쓰지 않는다(P12).
- `REQ-014` — 정책·ACL 전제의 **실행 시 강제**: `MACHINE_WRITE_CRED_ENABLED=true`이면 UI는 D379-15의 검사를 **기동 시 + 매 `setPassword` 직전 + 60초 주기**로 실행한다. 기동 시 실패 → 기동하지 않음. 요청 직전 실패 → 그 요청 503(쓰기 없음). 주기 실패 → 비밀번호 오퍼레이션만 503. 검사는 표본(카나리)이 아니라 **범위 전체**를 덮는다: `olcAccess` 원문 대조(D379-16)로 모든 상한 subtree에 대해 `W_cred`의 실효 권한이 고정 규칙 묶음과 같음을, 대상별 실효 정책(`pwdPolicySubentry` 또는 기본 정책)의 임계값을 증명한다. 남는 노출 창은 "검사 읽기 → 쓰기" 사이의 TOCTOU뿐이며 그 상한을 R-4로 명시한다. 문서·운영 점검 스크립트는 보조다. 정책을 앱에 복제하지 않고 정책 **값**을 읽어 하한과 비교만 한다(validate.go:60-70). **Revision 7 (D379-18)**: 검사 2는 대기 정책 항목(`MACHINE_WRITE_CRED_PENDING_POLICY_DN`)도 `M`으로 읽어 `pwdAttribute=userPassword`, `pwdCheckQuality ≥ 2`(F-6), `pwdMinLength ≥` 하한, `pwdSafeModify FALSE`를 확인하고, 기본 정책의 `pwdSafeModify TRUE`도 확인한다(기본에서 꺼지면 F-5가 모든 계정에 열림). 검사 5의 대기 카나리에는 사전 해시 plain Modify 프로브(기대 19)를 더해 quality 2의 실효를 본다. 주기 검사는 두 `M` 스윕을 더한다: "대기 정책 ∧ `pwdChangedTime`"(정리 실패 → 정리 재시도, 재실패 시 비밀번호 오퍼레이션 503 + 경보)과 "대기 정책 ∧ 표지 없음"(Add 경로의 부착·F-9 자기 부착 → 경보).
- `REQ-015` — 비밀번호 포함 `createUser`: 첫 v2c 출하에서 **열지 않는다**(부모 D15 유지; Q6). 자동화는 `createUser`(비밀번호 없이) → `setPassword`(초기)로 합성한다. 열기로 결정하면 D379-11의 두 신원 흐름을 따른다.
- `REQ-016` — 감사: 새 오퍼레이션도 부모 D6의 한 줄 규칙을 따르고 `compartment`에 `lock`/`cred`가 나타난다. 비밀번호 오퍼레이션 줄에는 비밀번호 길이·지문도 남기지 않는다.
- `REQ-017` — 긴급 차단: `MACHINE_WRITE_CRED_ENABLED=false` 재배포와 `W_cred` 비밀번호 회전/잠금이 각각 다음 요청부터 비밀번호 쓰기를 503으로 멈추고 다른 구획(`W_data`·`W_lock`·`M`)에는 영향이 없음을 드릴로 증명한다(부모 D12 방식).
- `REQ-018` — 자격 증명 대기 표지: 머신 `createUser`는 본문 `credentialPending: true`일 때만(그 client가 `directory.users.password.write`도 갖고 v2c가 켜져 있을 때만) `employeeType: ldapium-credential-pending:<client 태그>`를 Add에 싣는다. 태그는 `SHA-256("machine:"+len(iss)+":"+iss+client id)`의 앞 16 hex(부모 D9 주체 구성과 같은 입력). 표지는 머신 `patchUser` 닫힌 목록 밖이라 어떤 client도 나중에 붙이거나 바꿀 수 없다. `setPassword`는 `M` 사전 읽기로 표지 태그 == 요청 client 태그, `creatorsName` == `W_data`를 확인한다(다른 client가 만든 대기 계정 거부). 성공 후 `W_cred`가 표지 값을 지운다(D379-10의 정리 단계). **Revision 7 (D379-18)**: 표지가 붙은 Add 직후 같은 요청에서 `W_data`가 Modify로 대기 정책을 붙이고(ACL: 정확한 DN, 표지 항목만, add만 — §2f D-2), 부착이 실패하면 `W_data` 연결로 보상 Delete(`creatorsName == W_data`, 기존 D216-5 규칙)를 한다. 정리 단계는 표지 값과 정책 값을 **한 Modify**로 지운다(§2f D-6).

## Acceptance scenarios

### `AC-001` — 꺼짐 불변(v2b·v2c 공통)
이 패키지의 PR이 병합돼도 새 scope를 client 상한에 넣지 않은 배포에서는 8개 미개방 오퍼레이션이 403 `scope_denied`·bind 0이고, OpenAPI·계약 시험·읽기 전용 증명(`scripts/test/test-machine-acl-readonly-live.py`)·v2a 드릴(`scripts/test/test-machine-write-drill.py`)이 변하지 않는다. `MACHINE_WRITE_CRED_ENABLED`를 켜고 `W_cred`가 없으면 기동 실패한다.

### `AC-002` — `createGroup` seed
머신 `createGroup` 후 새 그룹의 `member`는 정확히 `MACHINE_WRITE_GROUP_SEED_DN` 하나이고 `W_data` DN이 아니다. `W_data` 항목의 `memberOf`는 변하지 않는다. 머신이 seed DN을 `addGroupMember`/`removeGroupMember`의 멤버로, 또는 `patchUser`/`deleteUser`의 대상으로 쓰면 연결 전 403이다. seed DN 미설정에서 `directory.groups.create`를 상한에 쓰면 기동 실패한다. 사람 경로 `createGroup`은 여전히 바인드 DN을 seed로 쓴다.

### `AC-003` — 그룹 대상 제한
허용 목록 밖 그룹·특권 그룹·보호 DN(대소문자·OID 타입·공백 변형)·상한 자신·사용자 DN에 대한 `patchGroup`/`deleteGroup`은 쓰기 없이 403이고, `If-Match` 없음 428, 낡은 태그 412다. 생성 직후의 그룹은 허용 목록에 넣기 전까지 `patchGroup`/`deleteGroup`/멤버 연산이 403이다.

### `AC-004` — `patchGroup` 범위
`description` 설정·`null` 제거는 성공, `cn`을 담은 머신 본문은 400(쓰기 없음), 알 수 없는 필드 400. 사람 경로의 `cn` 변경 거동은 변하지 않는다(현재 거동은 `E-05`로 기록).

### `AC-005` — 잠금, 그리고 해제 거부
`W_lock`이 꺼진 배포에서 lock scope를 상한에 쓰면 기동 실패. 켠 배포에서: 강한 `If-Match`+키로 잠금 → 대상 `pwdAccountLockedTime=000001010000Z`, 같은 키 재시도는 재생, 그룹 DN 대상은 단언 실패로 쓰기 없음, 특권 그룹 멤버 대상은 403, 보호 DN 403. 이미 ppolicy로 잠긴 계정(시각 값)에 머신 잠금을 하면 값이 표지로 바뀜(더 엄격해짐)을 기록하고, 그 뒤에도 머신 해제 경로가 없음을 단언한다. 잠긴 계정은 단순 bind가 실패한다(이미 발급된 다운스트림 세션·토큰은 영향 없음을 문서화). `directory.users.unlock`을 상한에 쓰면 기동 실패다.

### `AC-005b` — 해제 우회 거부(ppolicy 시각 잠금, duration 0 잠금, 왕복, 재시작)
각각에서 머신 `POST /api/users/unlock`은 403 `scope_denied`·bind 0이고 대상의 `pwdAccountLockedTime`은 변하지 않는다: (a) 무차별 대입으로 ppolicy가 잠근 계정(시각 값), (b) `pwdLockoutDuration=0` 정책으로 잠긴 계정(표지 형태, P22), (c) 같은 client가 `lockUser` 직후 같은 대상에 해제, (d) (c)를 UI 재시작 뒤 반복, (e) 다른 client가 해제. 사람 경로 해제는 바이트 불변이다(`h/user_handlers.go:200-221`). 변이: 해제를 열린 표에 넣으면 이 시험이 실패한다.

### `AC-006` — `W_lock`·`W_data` 구획 경계(LDAP 직접)
`W_lock`으로 직접 `ldapmodify`해 `pwdAccountLockedTime` 외 속성 수정, 항목 Add/Delete, `userPassword` 수정은 전부 `insufficientAccessRights`. `W_data`로 `pwdAccountLockedTime` 수정도 거부(`f/write-data.ldif:49-51`). 특권 그룹 멤버에 대한 `W_lock` 직접 쓰기 결과를 기록한다(`E-07`: ACL filter 백스톱 성립 여부).

### `AC-007` — `W_cred` 신원·ACL
`W_cred`가 다른 신원과 같으면 기동 실패(변형 표). 직접 LDAP로: `W_cred`는 상한 안에서 `W_data`가 표지와 함께 만든 비밀번호 없는 `inetOrgPerson`에 Password Modify 성공, 이미 비밀번호가 있는 항목·상한 밖·시스템 컨테이너·복제 신원·그룹·특권 멤버·`W_*`/`M` 자신에는 실패, `userPassword` **읽기** 실패, Add/Delete 실패, `employeeType`의 **표지 형식 값 삭제만** 성공(다른 `employeeType` 값 삭제·추가·교체와 그 밖의 모든 속성 쓰기는 실패). 설치 전후 기존 신원(`M`·`W_data`·`W_lock`·관리자·익명·복제 신원)의 접근 결과가 같고 `olcAccess` 인덱스가 정의된 순서다(부모 D11).

### `AC-007b` — 기존 비밀번호 없는 계정 거부(P1-a)
경로별로 나눈다. **앱 경로와 `W_cred` 직접 경로 모두 실패**: (a) 관리자가 만든 비밀번호 없는 SSO 사용자, (b) v2a 머신 `createUser`(표지 없음)로 만든 계정, (c) 관리자가 표지를 손으로 붙였지만 `creatorsName`이 `W_data`가 아닌 계정, (e) 비밀번호 설정 성공 후 관리자가 `userPassword`를 지운 계정(정리 단계가 표지를 지웠으므로). **앱 경로만 실패**: (d) client A의 표지가 붙은 계정에 client B가 요청 → 앱 403(쓰기 없음). 같은 (d)를 `W_cred`로 직접 하면 **성공하는 것이 설계상 기대값**이며 시험은 그 성공을 한계로 기록한다(REQ-010의 client 귀속 한계). 정리 실패로 표지가 남은 (e) 변형은 실패 모드 표대로 기록한다. 머신 `patchUser`로 `employeeType`을 보내면 400이다.

### `AC-008` — 머신 `setPassword` 계약
`password.write` scope 없음 403, 플래그 꺼짐 403(오퍼레이션 미도달), 본문 `oldPassword`·빈 `password`·필드 추가 400, `If-Match` 400, 키 없음 428, 같은 키+같은 본문 재시도는 `Idempotent-Replayed: true`와 `{}`, 같은 키+다른 비밀번호 422 `idempotency_key_reused`, 대상별 한도 초과 429. 응답 본문에 `generatedPassword`가 없다.

### `AC-009` — 비밀 무노출(T-031)
센티널 비밀번호(무작위 32자)로 성공·실패(정책 위반·ACL 거부·412 해당 없음·429·422)·재생 경로를 모두 실행한 뒤, 모든 HTTP 응답 본문·헤더, UI 감사 줄, UI·slapd·Keycloak 컨테이너 로그(`docker logs`, `LDAP_AUDIT_ENABLED=true` 구성의 auditlog stdout 포함), `LDAP_ACCESSLOG_OPS`에 쓰기를 넣은 구성의 `cn=accesslog` `reqMod`/`reqOld`(관리자 읽기와 `M` 읽기 각각)에서 센티널 평문 **과** 해시 패턴(REQ-012)이 0건이다. 해시가 발견되는 구성은 D379-14에 따라 기동·렌더가 거부되는 구성이어야 한다. 멱등 기록은 지문 외에 비밀을 담지 않음을 단위 시험으로 고정한다(메모리는 라이브로 덤프하지 않는다).

### `AC-010` — 정책 적용
`W_cred`로 `pwdMinLength` 미만·이력(`pwdInHistory`) 재사용 비밀번호를 설정하면 slapd가 거부하고 앱은 400/409 계열 오류 코드(기존 매핑)로 응답한다. 적용되지 않으면 v2c를 열지 않는다(REQ-014).

### `AC-010b` — 실행 시 강제: 범위별 오구성과 검사 후 변경(P1-c, 2차 P1-2/P1-3)
`MACHINE_WRITE_CRED_ENABLED=true`에서 다음 각각은 UI 기동 실패(비0 종료, 원인 코드만 로그, 값 없음)다: 정책 비활성 컨테이너; `W_cred` 규칙 묶음이 고정 원문과 다르거나 그 앞에 `W_cred`에 적용될 수 있는 다른 규칙이 있는 `olcAccess`(D379-16); **상한 subtree가 둘인데 둘째 subtree에만 더 느슨한 규칙**(예: `to dn.subtree=<둘째> attrs=userPassword by users write`를 `W_cred` 묶음 앞에 삽입)이 있는 구성 — 카나리가 첫째 subtree에만 있어도 원문 대조가 거부해야 한다; 기본 정책 임계값이 설정 하한 미만; 표지 카나리 프로브 실패; `M`이 `cn=accesslog`의 **자식 항목**을 하나라도 읽을 수 있는 구성(base는 숨기고 자식에 read를 준 구성 포함, D379-14); `MACHINE_WRITE_PRIVILEGED_GROUPS` 비어 있음. **대상별**: `pwdPolicySubentry`가 허용 목록 밖이거나 그 정책 임계값이 하한 미만인 대상은 그 요청만 403(쓰기 없음). **검사 후 변경**: 기동 후 느슨한 규칙을 삽입하면 다음 `setPassword`가 요청 직전 검사에서 503(쓰기 없음)이고, 요청이 없을 때도 60초 안에 주기 검사가 비밀번호 오퍼레이션을 닫는다. 검사 읽기와 쓰기 사이에 규칙을 바꾸는 경쟁은 R-4의 수용 창으로 기록한다.

### `AC-010c` — 동시 초기 설정(P2-b)
같은 대기 계정에 대해 (a) **같은 client**의 서로 다른 `Idempotency-Key` 두 요청을 동시에, (b) 앱을 우회한 `W_cred` 직접 Password Modify 병렬 N=10(서로 다른 값)을 보내면 각각 **정확히 한 건만** 성공하고 나머지는 쓰기 없이 실패한다(앱 경로는 직렬화 409/429 또는 ACL 거부, 직접 경로는 50). 최종 `userPassword`는 성공한 값으로만 bind된다. (c) **다른 client**의 동시 요청은 태그 검사로 쓰기 전에 403이다(AC-007b (d)와 같은 규칙). (b)가 성립하지 않으면 R-3이 열린 채로 남고 v2c는 출하하지 않는다. **Revision 9 범위(Codex P2)**: (b)의 "정확히 한 건"은 **한 provider 안에서만** 보장된다(단일 slapd 실측). 다중 provider에서는 앱 경로를 한 provider로 고정해도 `W_cred` 자격 증명으로 **다른 provider에 직접** 쓰는 경로는 막히지 않고, 복제는 last-write-wins다. 따라서 다중 provider 배포는 `W_cred` ACL 묶음을 고정 provider에만 설치하고(다른 provider에서는 `W_cred` none) 그것을 전제 검사로 확인해야 한다 — `cn=config`가 복제되는 구성에서는 이 방법이 성립하지 않는다(미실측, 출하 전 결정 필요).

### `AC-011` — 긴급 차단(구획별)
(a) `MACHINE_WRITE_CRED_ENABLED=false` 재배포 → `setPassword`는 쓰기·`W_cred` bind 없이 **503**(식별자 미구성; scope까지 ceiling에서 빠진 배포는 403), 다른 쓰기 영향 없음. **T-025 정정(2026-10-14)**: 플래그만 끄면 403이 아니라 503이다. 긴급 차단이 기동 실패가 되지 않게 503을 유지하며, T-026에서 확정한다(EVIDENCE.md §2k T025-F1). **T-026 확정 기록(2026-10-14, EVIDENCE.md §2m T026-F1)**: 유지보수자가 지킨 성질 — 플래그만 끈 재배포가 기동하고(상한의 `password.write`는 플래그와 무관하게 받는다, T026-D1) `W_cred` bind·쓰기가 0 — 은 그대로 확정이다. 다만 503은 T-025가 **코드로 만든** 구성(플래그만 끄고 다른 cred 값 유지)의 응답이었다: `config.Load`는 플래그가 꺼지면 다른 `MACHINE_WRITE_CRED_*`를 읽지 않으므로 실제 재배포에는 cred 상한이 없고 대상 가드가 연결 전에 **403 `scope_denied`**로 답한다(T-026 드릴이 두 구성을 모두 단언: Load 구성 403, 값 유지 구성 503, 둘 다 `W_cred` bind 0). 상태 코드를 503으로 맞출지는 **유지보수자 확인 대상(Q19)**이며 그때까지 문서는 실측대로 403이다. (b) `W_cred` 비밀번호 회전 → 다음 `setPassword` 503 `bind_failed`, `W_data`·`W_lock`·읽기 영향 없음. (c) 이미 bind된 진행 중 요청의 상한은 `MACHINE_REQUEST_TIMEOUT`(부모 EVIDENCE-drill.md와 같은 방식으로 실측).

### `AC-012` — 감사
각 새 오퍼레이션의 허용·거부·재생·LDAP 거부가 정확히 한 줄이며 `compartment`=`data`/`lock`/`cred`, actor=client id. 비밀번호 오퍼레이션 줄에 비밀번호 관련 필드(값·길이·지문)가 없다.

## Architecture and decisions

- Relevant design links: [machine-write-scope CHANGE/ADR](../machine-write-scope/CHANGE.md)(부모 D1–D26, 부록 A), [api-conditional-writes](../api-conditional-writes/CHANGE.md)(D216-2 Password Modify에 control 불가, D216-5 보상, D216-6/8 서버 생성 비밀번호), [machine-token-revocation](../machine-token-revocation/CHANGE.md)(폐기 훅 1단계), [docs/machine-write-account.md](../../machine-write-account.md), [docs/machine-auth-operations.md](../../machine-auth-operations.md).
- ADR threshold: `required`(새 자격 증명 쓰기 경로, 권한 부여 의미). 같은 패키지의 [ADR.md](ADR.md).

### 오퍼레이션별 쓰기 표

| operationId | 경로 | scope | 구획 | DN 형태 | `If-Match` | 대상 단언 | 추가 조건 | 단계 |
|---|---|---|---|---|---|---|---|---|
| `createGroup` | `POST /api/groups` | `directory.groups.create` | `W_data` | 생성(부모=`GroupCreateBase`, `cn`) | 없음(생성) | — | seed = `MACHINE_WRITE_GROUP_SEED_DN`(D379-3), 본문 `{cn, description?}`, `cn`은 D26 형식 | v2b |
| `patchGroup` | `PATCH /api/groups` | `directory.groups.update` | `W_data` | 대상 | 강한 태그 필수 | `groupOfNames` | 본문 `{dn, description}`만(D379-5), 허용 목록(REQ-004) | v2b |
| `deleteGroup` | `DELETE /api/groups` | `directory.groups.delete` | `W_data` | 대상(쿼리) | 강한 태그 필수 | `groupOfNames` | 허용 목록, 특권 그룹 거부, 리프 확인(부모 D8e) | v2b |
| `lockUser` | `POST /api/users/lock` | `directory.users.lock` | `W_lock` | 대상 | 강한 태그 필수 | `inetOrgPerson` | 특권 멤버 거부(REQ-007) | v2b |
| `unlockUser` | `POST /api/users/unlock` | `directory.users.unlock` | — | — | — | — | **열지 않음**: 사람 전용(D379-7, REQ-008) | — |
| `setPassword` | `POST /api/users/password` | `directory.users.password.write` | `W_cred` | 대상 | **금지**(400, P10) | `M` 사전 읽기(`inetOrgPerson`, `creatorsName`, 표지 태그) + ACL filter | 대기 표지가 붙은 계정의 초기 비밀번호만(REQ-010/018), 특권 멤버 거부, 대상 전역 직렬화·전역 예산, 멱등 비밀번호 모드, 성공 후 표지 정리, 기동 프로브 통과(D379-15) | v2c |
| `createUser` + `credentialPending` | `POST /api/users` | `…create` (+ 그 client 상한에 `…password.write`) | `W_data` | 생성 | 없음 | — | 본문 `credentialPending: true`일 때만 `employeeType` 대기 표지를 Add에 실음(REQ-018); 비밀번호 값은 받지 않음 | v2c |
| `createUser` + `password` | `POST /api/users` | `…create` + `…password.write` | `W_data`+`W_cred` | 생성 | 없음 | — | **첫 v2c 출하에서 열지 않음**(Q6, D379-11) | v2c 후속 |
| `updateUser`, `updateGroup` | `PUT` | — | — | — | — | — | 열지 않음(부모 Q2/D25) | — |

모든 행은 부모 파이프라인 순서(`h/machine_write_pipeline.go:20-48`: 폐기 → scope → 한도 → 파싱·정규형·엄격한 하위 → 보호 DN·허용 목록 → `If-Match` → 멱등 → `M` 사전 읽기 → 실행 → 감사)를 그대로 거친다. 새 오퍼레이션이 추가하는 것은 (1) 카탈로그 행(`machineWriteCatalog`), (2) 닫힌 본문 필드 집합(`machineWriteBodyAllowed`), (3) 생성 형태 `shapeCreate`의 그룹 분기(지금은 `uid`+`UserCreateBase`만, `h/machine_write_pipeline.go:287-296`), (4) `M` 사전 읽기의 `memberOf` 검사, (5) `setPassword`의 멱등 비밀번호 모드뿐이다.

### seed 멤버 옵션 (부모 D22, Q2)

| 항목 | A. 현행(`W_data` DN) | B. **고정 placeholder DN**(권고) | C. 요청의 첫 멤버 |
|---|---|---|---|
| 생성 직후 권한 효과 | `W_data`가 그룹 멤버 → `W_data` 항목에 `memberOf` | placeholder만 멤버, 아무 주체도 권한을 얻지 않음 | 요청한 사용자가 즉시 멤버 → 생성 = 권한 부여 |
| 허용 목록과의 관계 | — | 생성 후 멤버 변경은 운영자가 그룹을 허용 목록에 넣어야 가능 | 허용 목록에 없는 그룹(방금 생김)에 멤버를 넣는 셈 → 부모 D22 우회 |
| 머신이 seed를 제거 | 불가(`W_data`는 보호 집합, P4) → 영구 잔존 | 불가(placeholder도 보호 집합) → 의도된 "빈 그룹" 표지 | 가능(일반 멤버) → 마지막 멤버 제거는 slapd 거부(P5) |
| 다운스트림 영향 | `W_data`가 그룹 기반 ACL·역할 매핑에 걸릴 수 있음 | placeholder는 bind 불가 항목(비밀번호 없음)으로 둠 | 생성과 멤버십이 한 결정으로 묶임 |
| 구현 | 없음 | 설정 1개 + 기동 검증 + 머신 경로 seed 인자 | 본문 필드·멤버 검사 재사용 |
| 판정 | **기각** | **권고** | 기각(D22 허용 목록 의미를 깨뜨림) |

### `W_cred` ACL 스케치 (구현하지 않음, T-021에서 확정)

`f/write-data.ldif`·`f/write-lock.ldif`와 같은 형식·같은 위치 규칙(복제 `{0}`·`M` 묶음 뒤, 기존 allow 앞, 모든 규칙이 `by dn.exact=W_cred …` + `by * break`)을 따른다. 토큰 이름은 같은 관례(`@WCRED_DN@`, `@WRITE_DN@`, `@SYSTEM_DN@`, `@REPL_DN@`, `@PRIV_FILTER@`).

```
{0} to dn.subtree="@SYSTEM_DN@"                         by W_cred none
{1} to dn.exact="@REPL_DN@"                              by W_cred none
{2} to dn.subtree="@WRITE_DN@" attrs=userPassword
      filter=(&(objectClass=inetOrgPerson)(creatorsName=@WDATA_DN@)
                (employeeType=ldapium-credential-pending:*)
                (!(userPassword=*))@PRIV_FILTER@)
                                                         by W_cred =w      (E-08, E-16, E-07)
{2b} to dn.subtree="@WRITE_DN@" attrs=employeeType
      val.regex="^ldapium-credential-pending:[0-9a-f]{16}$"
                                                         by W_cred =z      (정리 단계, E-16)
{3} to attrs=userPassword,shadowLastChange,pwdHistory,…(write-lock.ldif:36과 같은 비밀·pwd* 목록),memberOf,pwdAccountLockedTime
                                                         by W_cred none
{4} to dn.subtree="@WRITE_DN@" attrs=entry               by W_cred =x? (E-09: Password Modify가 entry에 요구하는 최소 수준)
{5} to *                                                 by W_cred none
```

**Revision 7**: 이 스케치는 §2e·§2f 실측으로 다음처럼 바뀐다 — `{2}` filter에 `(pwdPolicySubentry=@PENDING_POLICY_DN@)` 추가, `{2c} to dn.subtree="@WRITE_DN@" attrs=pwdPolicySubentry val="@PENDING_POLICY_DN@" by W_cred =z`(`{3}` 앞), `{4}`(`entry`) 삭제. `W_data`에는 `{2}`(비밀·`pwd*` none) **앞에** `to dn.subtree="@WRITE_DN@" attrs=pwdPolicySubentry val="@PENDING_POLICY_DN@" filter=(employeeType=ldapium-credential-pending:*) by W_data add`가 더해진다. 실측된 형태는 EVIDENCE §2f.

`@PRIV_FILTER@`는 특권 그룹마다 `(!(memberOf=<그룹 DN>))`를 이어 붙인 것이다. 미검증 세 가지가 이 스케치의 성립 조건이다: (a) ACL `filter=`가 대상 항목의 `userPassword` 존재를 요청자 권한과 무관하게 평가하는지(`E-08`), (b) `memberOf` 부정 filter가 기대대로 평가되는지(`E-07`), (c) Password Modify가 `userPassword` `=w` 외에 `entry` 수준 접근을 요구하는지와 ppolicy 내부 갱신(`pwdChangedTime`·`pwdHistory`)이 `W_cred` ACL과 무관하게 되는지(`E-09`). 하나라도 성립하지 않으면 이 표를 개정하고 수용을 다시 받는다. `@WDATA_DN@`·표지 조건(`E-16`)은 Revision 1에서 추가됐다.

`W_data`에는 표지 Add용 규칙이 하나 더 필요하다: `to dn.subtree="@WRITE_DN@" attrs=employeeType val.regex="^ldapium-credential-pending:[0-9a-f]{16}$" by W_data add`. `add` 수준은 Add와 Modify의 값 추가를 구별하지 못하므로(부모 D18과 같은 한계) "생성 시에만"은 앱의 닫힌 본문이 강제한다. 그 한계의 폭: `W_data`가 침해되면 **`W_data`가 만든** 비밀번호 없는 계정에 표지를 붙일 수 있다(`creatorsName` 조건 때문에 그 밖의 계정은 불가). ~~비밀번호를 실제로 설정하려면 `W_cred`도 필요하다.~~ **Revision 8 정정**: 이 마지막 문장은 틀렸다 — `password.write`를 가진 정상 client 하나만 있으면 앱이 `W_cred`로 설정해 주므로, 유출된 `W_data` + 그런 client(표지 태그는 client가 계산 가능)로 기존 계정을 탈취할 수 있었다(검토 M-1). Revision 8에서 이 규칙은 Add 전용으로 바뀌었다(아래 D379-18 Rev. 8, §2g): `W_data`는 Modify로 표지·정책을 붙이거나 떼지 못한다(50). 남는 한계: 이미 대기인 항목에 **두 번째** 표지 값은 Modify로 붙는다(filter가 참이므로, §2g) → 앱 사전 읽기는 표지 값이 **정확히 하나**이고 그 태그가 요청 client의 것일 때만 진행한다.

**검증 상태(P1-a)**: 확인됨(코드 읽기) — `creatorsName`이 서버가 채우는 값이라는 점을 기존 보상 흐름이 전제로 쓴다(`l/create_compensation.go:17-26`); `employeeType`은 현재 어떤 머신 쓰기 목록·사람 DTO에도 없다(`h/machine_write_attributes.go:22-25`, `l/users.go:84-140`). 가정(미검증) — ACL `filter=`가 `creatorsName`·`employeeType` 부분 문자열·`userPassword` 부재를 `W_cred` 권한과 무관하게 평가함(`E-08`, `E-16`), `val.regex`가 `=z`를 그 값으로 한정함(`E-16`), 동시 Password Modify 중 정확히 하나만 filter를 통과함(`E-17`). `employeeType`을 다른 용도로 쓰는 배포가 있을 수 있으므로 속성 선택은 Q11이다.

### 실행 시 전제 검사 (D379-15·D379-16, P1-c, 2차 P1-2/P1-3)

`MACHINE_WRITE_CRED_ENABLED=true`일 때 UI는 아래 검사를 **기동 시**(실패 → 기동 거부), **매 `setPassword` 직전**(실패 → 그 요청 503, 쓰기 없음), **60초 주기**(실패 → 비밀번호 오퍼레이션만 503, 다음 성공 주기까지)로 실행한다. 모든 검사는 읽기이거나 **성공하면 안 되는 쓰기**라서 전제가 맞으면 디렉터리를 바꾸지 않는다. 결과 코드만 로그하고 값은 남기지 않는다.

| # | 검사 | 덮는 범위 | 기대 | 다르면 |
|---|---|---|---|---|
| 1 | **ACL 원문 대조**(D379-16): 설정 읽기 전용 신원 `MACHINE_WRITE_CRED_ACL_READER_DN`으로 메인 DB 설정 항목의 `olcAccess`를 읽어, (a) `W_cred` 규칙 묶음이 `f/write-cred.ldif`를 설정 값으로 치환한 원문과 **정확히 같고**, (b) 그 앞의 모든 규칙이 복제 신원·`M`·`W_data`·`W_lock`의 고정 묶음(각 fixture 치환 원문)뿐이며, (c) `@WRITE_DN@`·`@SYSTEM_DN@`·특권 filter가 현재 설정에서 계산한 값과 같다 | slapd ACL은 first-match라 (a)(b)가 성립하면 `W_cred`의 실효 권한은 **모든 subtree에서** 그 묶음으로 결정된다(묶음의 마지막이 `to * by W_cred none`). frontend DB ACL은 DB ACL 뒤에 붙으므로 영향 없음 | 일치 | 기동 거부 / 503 |
| 2 | **정책 값**: 같은 신원으로 ppolicy overlay의 `olcPPolicyDefault`를 읽고, `M`으로 그 정책 항목의 `pwdAttribute`·`pwdMinLength`·`pwdCheckQuality`·`pwdInHistory`를 읽어 설정 하한(`MACHINE_WRITE_CRED_MIN_LENGTH` 기본 12, quality ≥1, history ≥1)과 비교 | 기본 정책 | 하한 이상 | 기동 거부 / 503 |
| 3 | **대상별 정책**(요청 직전만): `M` 사전 읽기로 대상의 `pwdPolicySubentry`를 읽어, 없으면 검사 2의 기본 정책, 있으면 `MACHINE_WRITE_CRED_POLICY_DNS` 허용 목록 안이어야 하고 그 항목도 검사 2의 하한을 만족해야 한다 | 대상 하나하나(표본 아님) | 만족 | 그 요청 403 |
| 4 | **대상별 앱 게이트**(요청 직전만): 표지 태그 == 요청 client 태그, `creatorsName` == `W_data`, `pwdChangedTime` 없음(`M` 읽기 가능, `E-20`), 특권 멤버 아님 | 대상 하나하나 | 만족 | 그 요청 403 |
| 5 | **카나리 프로브**(기동·주기): 상한 subtree **마다** 둔 카나리 3개(비밀번호 있는 표지 / 표지 없는 무비밀번호 / 표지 있는 무비밀번호, 모두 관리 잠금 상태)에 `W_cred`로 Password Modify — 앞의 둘은 50, 셋째는 1자 값으로 19(정책 길이) | 검사 1·2의 **실효 확인**(원문 대조가 slapd 해석과 같다는 증거). **Revision 12(T028-F1)로 좁아짐**: 50 두 개는 비밀번호 항·표지 항을 각각 격리해 확인하고(표지 없는 카나리는 `W_data`가 만들고 대기 정책을 가짐), 19는 대기 정책이 `W_cred`에 적용됨만 보인다(ppolicy가 ACL보다 먼저 판정). 특권 filter·`CRED_DN` 경계 항은 카나리가 보지 않으며 검사 1이 유일한 통제다 | 50/50/19 | 기동 거부 / 503, 셋째가 성공하면 카나리 재설정 필요 로그 |
| 6 | **accesslog 자식 읽기**: `M`으로 `cn=accesslog` **subtree** 검색(크기 1, 속성 `reqMod`·`reqOld`) — base가 아니라 자식 항목을 실제로 요청 | `M`이 읽을 수 있는 모든 로그 항목 | 0건 | 기동 거부 / 503(D379-14 상호 배제). 공존 모드(Q12)에서는 아래 검사 7로 대체 |
| 7 | **공존 모드 전용 사후 확인**: 성공한 `setPassword`마다 `M`으로 그 쓰기의 accesslog 자식 항목(`reqAuthzID`=`W_cred`, `reqDN`=대상, `reqStart` ≥ 요청 시각)을 읽어 `reqMod`/`reqOld`에 `userPassword:` 값이 하나라도 보이면 비밀번호 오퍼레이션을 닫고 경보 | 실제 쓰기 기록 | 0건 | 503 + 경보(이미 한 건은 노출됐을 수 있음 → R-5) |
| 8 | 설정: `MACHINE_WRITE_PRIVILEGED_GROUPS`·`MACHINE_WRITE_CRED_SUBTREES` 비어 있지 않음, 카나리가 subtree마다 존재 | 설정 | 만족 | 기동 거부 |

**이 검사가 증명하지 못하는 것**(R-목록으로 이관): slapd auditlog 설정(검사 1의 신원은 메인 DB `olcAccess`와 ppolicy `olcPPolicyDefault`만 읽는다 → 차트가 `audit.enabled`(`charts/ldapium/values.yaml:395-408`)와 v2c 동시 활성을 렌더 실패로 거부, 차트 밖 배포는 문서, R-6); `M`이 아닌 다른 accesslog 독자(운영자가 ACL로 추가한 감사 계정)의 노출 — UI는 그 자격 증명이 없으므로 운영 점검 스크립트가 독자별로 검사 6을 재현한다(R-5); 품질·이력 규칙의 실효(검사 5는 길이만, R-7).

### 결정 기록

| ID | 결정 | 이유 | 비용 | 탈출구 |
|---|---|---|---|---|
| D379-1 | **두 하위 범위를 따로 수용·출하**: v2b(그룹·잠금)와 v2c(비밀번호). v2c는 v2b 병합과 v2a CI 릴리스 게이트(부모 T-025) 이후에만 착수한다. | 위험 등급이 다르고 v2c만 새 자격 증명을 만든다(#379) | 두 번의 수용·검토 | 한 단계만 철회 |
| D379-2 | **플래그**: v2b는 새 플래그를 만들지 않는다 — 그룹 오퍼레이션은 `MACHINE_WRITE_ENABLED`+client 상한의 scope가, 잠금은 기존 `MACHINE_WRITE_LOCK_ENABLED`(P8)가 켠다. v2c는 새 `MACHINE_WRITE_CRED_ENABLED`(기본 꺼짐)와 `MACHINE_WRITE_CRED_BIND_DN`/`_PASSWORD`. 플래그 꺼짐에서 해당 scope를 상한에 쓰면 기동 실패(부분 활성 없음, 부모 D10). | 운영자 옵트인은 scope 부여가 이미 담당, 비밀번호는 신원 자체가 새것 | 설정 항목 3개 | — |
| D379-3 | **seed = 고정 placeholder DN**(`MACHINE_WRITE_GROUP_SEED_DN`). 기동 검증: `createGroup` scope가 어느 상한에 있으면 필수, D26 형식, 보호 집합에 자동 포함, `W_*`·`M`·관리자와 달라야 함. 운영 가이드는 시스템 컨테이너 아래에 `userPassword` 없는 항목으로 만들게 한다(존재가 필수인지는 memberof `olcMemberOfDangling` 기본값에 달림, `E-04`). `l/groups.go`의 `CreateGroup`은 seed를 인자로 받는 머신 전용 경로를 갖고 사람 경로는 `c.dn` 그대로. | 생성이 권한 부여가 되지 않게, `W_data`에 `memberOf`가 붙지 않게(P3/P4) | 운영자가 항목 하나 생성 | 옵션 C(별도 결정) |
| D379-4 | **생성 그룹은 허용 목록에 자동 편입되지 않는다.** 멤버 변경·수정·삭제는 운영자가 `MACHINE_WRITE_GROUPS`에 정확 DN을 넣은 뒤에만. | 부모 D22의 "멤버십 = 권한 부여, 사람이 승인" 의미 유지 | 생성→멤버 추가 자동화에 재배포가 낌 | Q3: 그룹 서브트리 허용(별도 결정) |
| D379-5 | **`patchGroup`은 `description`만**, `cn` 거부. `W_data` ACL `{5}`에 `description` 추가. | 그룹 RDN 교체는 ModifyDN 의미이고(P6) 다운스트림 역할 이름 매핑을 조용히 바꿈 | 이름 변경 자동화 불가 | 사람 경로 |
| D379-6 | **`deleteGroup`**: 허용 목록·특권 그룹 거부·`If-Match`·`groupOfNames` 단언·리프 확인. 삭제 시 refint가 멤버의 `memberOf`를 정리하는 것은 의도된 효과(권한 회수)이며 비가역이다. | 그룹 삭제 = 다수 사용자의 권한 회수 | — | 감사·백업 복원 |
| D379-7 | **v2b는 잠금만 연다. 잠금 해제는 사람 전용**(Revision 2): `unlockUser`·`directory.users.unlock`은 거부 목록·미개방 어휘에 남는다. | 관리 잠금 표지는 ppolicy `pwdLockoutDuration=0` 잠금과 같은 형태이고 `Lock`은 ppolicy 시각 잠금을 표지로 덮어쓴다(P22). 따라서 "관리 잠금만 해제" 규칙은 잠금→해제 왕복으로 lockout을 무력화하고, 메모리 한도는 재시작·replica로 초기화된다(Codex 2차 P1-1). 값만으로는 안전한 해제 규칙이 없다 | 오프보딩 취소·잠금 해제 자동화 불가(사람 경로) | 별도 승인 설계: 머신 `lockUser`가 이미 잠긴 계정이면 거부(assertion `!(pwdAccountLockedTime=*)`)하고 같은 Modify에서 지속 표지(`W_lock` 전용 속성 값, client 태그)를 원자적으로 기록, 해제는 그 표지 + 표지 값을 assertion으로 요구하고 같은 Modify에서 지움. ppolicy 잠금에는 표지가 없으므로 해제 불가 |
| D379-8 | **특권 멤버 거부**(잠금·비밀번호): `M` 사전 읽기가 대상의 `memberOf`와 `MACHINE_WRITE_PRIVILEGED_GROUPS`의 교집합을 확인(`l/machine_write_identity.go` 확장), ACL filter는 성립 시 백스톱. | 관리자 잠금 = 가용성 공격, 관리자 비밀번호 설정 = 탈취. DN 보호 집합은 그룹으로 권한을 받은 사용자를 모른다(부모 D19f) | 읽기 1회의 TOCTOU(멤버십이 사전 읽기와 쓰기 사이에 바뀜) | ACL filter 백스톱(E-07) |
| D379-9 | **머신 `setPassword` = 관리자형 설정**: 본문 `{dn,password}`만, `oldPassword` 금지, 빈 값 금지, `If-Match` 금지, 키 필수, 멱등 비밀번호 모드, 사람 `passwordLimiter` 미사용. | `oldPassword` 경로는 셀프서비스 의미이고 그 한도 키가 머신에서 공유됨(P12). control 불가(P10) | `If-Match`로 막던 동시 수정 보호 없음 → 초기 전용·대상 한도로 보완 | — |
| D379-9 개정(Revision 7) | 출하 기본 정책의 `pwdSafeModify TRUE`는 rootdn·비밀번호 관리자 아닌 요청자의 "관리자형 설정"을 거부한다(F-4). 따라서 관리자형 설정은 **대기 정책이 붙은 표지 계정에서만** 동작하며(D379-18), `W_cred`를 비밀번호 관리자(`manage`)로 만들지 않는다. | `manage`는 ppolicy 길이·품질 검사를 건너뛴다(§2e E-10: 7자·2자 저장) | 대기 정책 항목·ACL 규칙 2개 | — |
| D379-10 | **첫 v2c 출하는 "이 기능으로 만든 계정의 초기 비밀번호"만**: `W_cred` ACL filter = `inetOrgPerson` ∧ `creatorsName=W_data` ∧ 대기 표지(`employeeType=ldapium-credential-pending:<태그>`) ∧ `!(userPassword=*)` ∧ 비특권. 표지는 머신 `createUser`가 `credentialPending: true`일 때만 Add에 싣고(REQ-018), `setPassword`는 표지 태그 == 요청 client 태그를 앱이 확인, 성공 후 `W_cred`가 표지를 지운다(`=z`, 값 정규식 한정). 재설정은 별도 승인. | 단순 `!(userPassword=*)`는 SSO·외부 인증 사용자처럼 **원래 비밀번호가 없는 기존 계정**을 전부 대상으로 만든다(Codex P1-a). `creatorsName`은 서버가 채워 위조 불가, 표지는 생성 의도와 client를 묶는다 | 속성 1개(`employeeType`) 점유, 정리 단계 실패 시 표지 잔존(아래) | Q5, Q11 |
| D379-11 | **비밀번호 포함 `createUser`는 첫 출하에서 닫는다**(부모 D15 유지). 열 경우의 설계: 한 요청 안에서 `W_data` 연결로 Add+신원 읽기, `W_cred` 연결로 Password Modify, 실패 시 `W_data` 연결로 보상 Delete(`creatorsName == W_data`이므로 기존 보상 규칙 성립, `l/create_compensation.go:17-26`). 두 bind·두 슬롯·두 실패 지점이 생긴다. | 합성(`createUser`→`setPassword`)의 실패 상태는 "비밀번호 없는 항목"으로 bind 불가라 안전하다. 두 신원 흐름은 보상 코드의 가정(단일 연결)을 바꾼다 | 자동화가 호출 2번 | Q6 |
| D379-12 | **비밀 위생**: 응답은 `{}`, 멱등 저장 본문 `{}`(비밀번호 모드), 감사에 비밀번호 필드 없음, 오류 메시지에 값 없음. 멱등 지문의 HMAC 입력에는 비밀번호가 포함된다(키 재사용 탐지에 필요) — 잔여 위험: keyring과 기록을 함께 얻은 공격자의 오프라인 추측. 지문에서 비밀번호를 빼면 같은 키+다른 비밀번호가 **재생**되어(새 비밀번호 미적용) 더 위험하다. | REQ-012 | — | 영속 저장소 설계 시 재검토 |
| D379-13 | **정책은 slapd가 강제**: `W_cred` 설정에 ppolicy 길이·품질·이력이 적용됨을 증명해야 연다(REQ-014). 앱에 정책 복제는 하지 않는다. **Revision 7**: 적용되는 정책은 대기 정책(D379-18)이며 `pwdCheckQuality 2`가 필수다 — 1에서는 `W_cred`를 직접 쓰는 주체가 사전 해시 값으로 길이를 우회한다(F-6, §2e; 2에서는 19, §2f D-4). 길이는 exop·plain Modify 모두에 적용됨을 실측했다. 이력(`pwdInHistory`)은 현재 비밀번호가 없는 초기 설정에서는 참조되지 않아 증명할 수 없다(초기 전용 범위에서는 무관). ppm `minQuality 1`의 품질 규칙은 측정으로 구별되지 않는다(R-7 잔여). | 정책 단일 출처(validate.go:60-70) | 증명 전 출하 불가 | — |
| D379-18 | **대기 계정 전용 정책**(유지보수자 2026-10-13, F-4): 기본 정책의 사본에 `pwdSafeModify FALSE`·`pwdCheckQuality 2`인 정책 항목(`MACHINE_WRITE_CRED_PENDING_POLICY_DN`)을 **표지 계정에만** 붙인다. 부착: 표지 Add 직후 `W_data` Modify(ACL `attrs=pwdPolicySubentry val="<DN>" filter=(employeeType=ldapium-credential-pending:*)` → `add`), 실패 시 보상 Delete. `W_cred` filter에 `(pwdPolicySubentry=<DN>)`. 정리: `W_cred`가 표지 값과 정책 값을 한 Modify로 삭제(`=z`, 정확한 값). 정리 실패는 주기 스윕이 찾아 재시도·503·경보. | safeModify는 비밀번호가 없는 대상도 거부한다(F-4). 기본 정책을 바꾸면 F-5 오라클이 모든 계정에 열리고, `manage`는 정책을 건너뛴다 | 정책 항목 1개, ACL 규칙 2개, 보상 경로, 스윕 2개; F-5 창(Q14) | 원자적 plain Modify(설정+정리 한 번, §2f D-7: 창 없음, 대신 accesslog `writes`에 해시 — F-8); `olcAddContentAcl TRUE`로 Add 안에서 부착(Q15) |
| D379-18 개정(Revision 8, 검토 반영) | **부착은 Add 시점에만**: 메인 DB `olcAddContentAcl TRUE`(Q15, v2c 선행 조건)에서 `W_data` 규칙 두 개(`employeeType` 표지 `val.regex`, `pwdPolicySubentry` `val="<DN>"`) 모두 filter `(&(objectClass=inetOrgPerson)(creatorsName=<W_data>)(employeeType=ldapium-credential-pending:*)(!(userPassword=*))(!(memberOf=<특권>))(pwdPolicySubentry=<DN>))`, `add`. Add에서는 새 항목이 filter를 만족하고(creatorsName은 ACL 검사 전에 채워짐), 그 속성이 없는 기존 항목의 Modify는 만족하지 못한다 → 부착 Modify·보상 경로가 없다(Add 하나가 원자적). `W_cred`: `userPassword` filter는 위와 같음; 정리는 표지 값(filter `(&(creatorsName=<W_data>)(pwdPolicySubentry=<DN>))`)과 정책 값(filter `(creatorsName=<W_data>)`)의 `=z`뿐. 앱: 사전 읽기는 표지 값 정확히 하나·태그 일치, `pwdChangedTime`이 있으면 **409**(재시도로 19/50 오라클을 만들지 않음); 정리 Modify는 요청 취소와 분리된 컨텍스트에서 실행. 주기 스윕 3개(아래 실패 모드). F-9(#399)는 선행 조건 | 검토 M-1(Modify 표지 부착), Codex P1(부착 filter), `olcAddContentAcl FALSE`에서는 Add가 속성 ACL을 보지 않음(§2f D-1) | DB 전체 스위치(rootdn 아닌 모든 Add 주체가 속성별 `add` 필요; 정상 createUser는 0으로 실측) | `olcAddContentAcl FALSE` + Modify 부착(Revision 7 형태, Add 경로 비제한) |
| D379-14 | **해시 경로 차단**(Codex P1-b): (a) **auditlog**(`LDAP_AUDIT_ENABLED`, stdout, P20)와 v2c는 함께 켜지 않는다 — 차트 렌더 실패, 차트 밖 배포는 문서(UI는 slapd 설정을 볼 수 없어 실행 시 강제 불가를 명시). (b) **accesslog**: `M`의 accesslog 옵트인(P21)과 v2c는 상호 배제가 기본이다 — 검사 6이 `M`의 `cn=accesslog` **자식 항목** 읽기를 거부 사유로 본다(base 검색은 증거가 아님: base에 `search`만 주고 자식에 `read`를 주면 해시가 그대로 읽힌다). 함께 쓰려면 accesslog DB 첫 규칙에 값 수준 거부(`to attrs=reqMod,reqOld val.regex="^userPassword:" by * none`)를 두고 그 성립을 `E-12`로 증명하고 검사 6을 검사 7(실제 쓰기의 자식 로그 항목을 `M`으로 읽어 확인)로 바꾼다(Q12). (c) 증거는 평문 센티널과 **해시 패턴** 스캔을 함께 쓴다(REQ-012, `E-13`). | 평문 스캔은 해시를 못 찾는다. 해시도 비밀이다(AGENTS.md "Attribute exposure") | auditlog·감사 읽기 옵트인과의 기능 상호 배제 | 값 수준 거부 증명 후 해제(Q12) |
| D379-15 | **실행 시 강제**(Codex 1차 P1-c, 2차 P1-2/P1-3): v2c 전제를 UI가 기동 시·요청 직전·60초 주기로 검사한다(위 "실행 시 전제 검사" 표가 정본). 카나리는 원문 대조의 실효 확인일 뿐 범위 증명이 아니다. accesslog는 base가 아니라 자식 항목 읽기로 검사한다. | 문서·점검 스크립트나 표본 프로브만으로는 다른 subtree·대상별 정책·검사 후 변경을 놓친다 | 요청마다 LDAP 읽기 몇 번(비밀번호 예산 1 rps라 감당 가능), subtree마다 카나리 3개 | 주기 조정 |
| D379-16 | **설정 읽기 전용 신원**(`MACHINE_WRITE_CRED_ACL_READER_DN`): `cn=config` DB에 `to dn.base="<메인 DB 설정 항목>" attrs=olcAccess` 와 `to dn.base="<ppolicy overlay 항목>" attrs=olcPPolicyDefault` 만 read, 그 밖 `none`. `W_*`·`M`·관리자와 다른 DN, 보호 집합 포함, 비밀번호는 Secret. | 범위 전체 ACL 증명은 `olcAccess` 원문 없이는 불가(UI는 지금 `cn=config`를 읽지 않음). `olcAccess`는 DN·filter만 담고 비밀이 아니다 | 신원·Secret 1개 추가, `cn=config` ACL 규칙 2개, ACL 구조가 이 신원에 노출 | Q13: 대신 운영 점검 스크립트 결과에 의존(노출 창 = 다음 점검까지) |

### 위협 모델

| 위협 | 시나리오 | 통제 | 잔여 위험 |
|---|---|---|---|
| 그룹 생성으로 권한 부여 | 머신이 그룹을 만들며 사용자(또는 `W_data`)를 멤버로 넣어 다운스트림 역할 획득 | seed = placeholder(D379-3), 생성 그룹 허용 목록 비편입(D379-4) | 다운스트림이 **그룹 이름 패턴**으로 역할을 주면 빈 그룹의 존재만으로도 의미가 생길 수 있음 → 운영 가이드 |
| 그룹 삭제로 권한 회수·서비스 거부 | 허용 목록 그룹 삭제로 다수 사용자의 역할 상실 | 허용 목록, 특권 그룹 거부, `If-Match`, 한도, 감사 | 허용 목록 안에서는 비가역 |
| 그룹 개명 | `cn` 변경으로 역할 매핑 변경 | `description`만(D379-5) | — |
| 관리자 잠금(가용성) | 관리자·운영자 계정 잠금 | 보호 DN, 특권 멤버 거부(D379-8) | 특권 그룹 설정 누락, 사전 읽기 TOCTOU |
| lockout 무력화 | 머신이 잠금→해제 왕복, 여러 client, 재시작으로 ppolicy 잠금을 풀어 무차별 대입을 돕는다 | 머신 해제 미개방(D379-7, AC-005b) | 머신 `lockUser`가 ppolicy 시각 잠금을 무기한 표지로 바꿀 수 있음(더 엄격해질 뿐, 해제는 사람) |
| 계정 탈취(비밀번호 설정) | 기존 사용자(비밀번호가 없는 SSO·외부 인증 사용자 포함)의 비밀번호를 알려진 값으로 설정해 로그인 | 표지·`creatorsName`·`!(userPassword=*)` ACL filter(D379-10), ACL 원문 대조·대상별 정책(D379-15/16), client 태그 확인, 특권 멤버 거부, 보호 DN, 상한, 기동 프로브 2·3 | ACL filter 미성립 시 출하 불가(E-08/E-16). **Revision 9 정정**: 탈취에 `W_cred` 침해는 필요 없다 — 유출된 `W_data` + `password.write`를 가진 정상 client 하나(앱이 `W_cred`로 설정)면 된다. 완화 전에는 관리자가 만든 특권 계정도 삭제→대기 재생성→설정→특권 그룹 재가입으로 탈취됐다(§2h M-3). 완화 (a)(비-`W_data` 사용자의 `entry` =rsc)·(b)(특권 그룹 `member` =rsc) 후 **남는 정확한 경계**: (1) `W_data`가 **스스로 만든** 계정(v2a createUser로 만든 SSO 사용자 포함)은 삭제·대기 재생성·설정이 가능하다(실측 0/0/0), (2) 특권 그룹의 **중첩** 그룹(`subadmins`) 멤버 추가는 막지 못한다(0). 두 가지 모두 수용 위험으로 유지보수자 결정에 올린다(Q16) |
| `W_cred` 침해 | `W_cred` 비밀번호 유출 | ACL이 표지 있는 `W_data` 생성 비밀번호 없는 비특권 계정으로 한정, 다른 쓰기 없음, 긴급 회전(AC-011) | 대기 중(표지 있음·비밀번호 없음) 계정에 비밀번호 설정 가능; ACL은 client 태그를 구별하지 않음 |
| `W_cred` 잠금 DoS | LDAP에 닿는 누구나 틀린 비밀번호 `pwdMaxFailure`(5)번으로 `W_cred`를 잠가 `setPassword`를 멈춤; 회전 뒤 거절된 요청도 실패 bind | 구획 분리(`W_data`·`W_lock`·읽기 무관), 잠금 해제 절차(`pwdAccountLockedTime` 삭제), 실패 bind 알림 | **Q17 결정(2026-10-14, 무잠금)**: 8.1이 무잠금 정책을 붙여 DoS를 없앤다. 남는 것: 추측 횟수 무제한 — 긴 무작위 비밀번호·네트워크 제한·실패 bind 경보(운영자 책임, 가이드 8.1). 8.1을 건너뛴 배포는 여전히 잠금 DoS(T-028이 강제하지 않음, Q18) |
| 비밀 유출 | 응답·감사·멱등·로그에 비밀번호 | D379-12, AC-009 센티널 스캔 | 멱등 HMAC 오프라인 추측(keyring 필요) |
| 해시 유출 | auditlog stdout·accesslog `reqMod`/`reqOld`에 해시, `M`이나 다른 감사 독자가 accesslog **자식 항목**을 직접 읽기 | auditlog 동시 활성 금지(차트), `M` 자식 읽기 상호 배제(검사 6), 공존 시 사후 확인(검사 7), 해시 패턴 스캔(D379-14) | 차트 밖 auditlog(R-6), `M` 외 감사 독자(R-5), 공존 모드의 첫 노출 1건(R-5) |
| 약한 비밀번호 | 머신이 정책 미달 비밀번호 설정, 또는 더 느슨한 사용자별 정책(`pwdPolicySubentry`)을 가진 대상에 설정 | slapd ppolicy(D379-13), 기본 정책 값 검사·대상별 정책 검사·카나리 길이 프로브(D379-15 검사 2·3·5), AC-010 | 품질·이력 규칙의 실효는 라이브 증거만(R-7) |
| 재시작 후 재실행 | 메모리 멱등 기록·한도 소실 후 같은 키 재실행(부모 D9) | 잠금은 자연 멱등 + `If-Match` 412, 그룹 생성은 `entryAlreadyExists`, 초기 비밀번호는 ACL이 두 번째 설정 거부 | 그룹 수정·삭제는 `If-Match`에 의존 |
| 교차 client | A가 B 영역의 그룹·사용자를 잠금/수정 | 앱 가드(상한·허용 목록), 감사 | 공유 `W_*` DN이라 LDAP은 client를 구별 못함(부모 D17) |
| 타입 혼동 | 사용자 DN으로 `deleteGroup`, 그룹 DN으로 `setPassword` | assertion(`groupOfNames`/`inetOrgPerson`), `setPassword`는 `M` 사전 읽기 + ACL filter `objectClass=inetOrgPerson` | `setPassword` 타입 확인은 control 불가로 TOCTOU(P10) |
| 동시 초기 설정 경쟁 | 서로 다른 client·키가 같은 대기 계정에 동시에 다른 비밀번호 설정 | 대상 전역 직렬화(replica 안), LDAP 쪽 단일 성공(`E-17`이 출하 조건) | `E-17` 전에는 경계 주장 불가 |

### 실패 모드

| 상황 | 동작 |
|---|---|
| `W_lock`/`W_cred` bind 실패 | 503 `bind_failed`, 다른 구획 폴백 없음, 읽기·다른 구획 영향 없음(부모 D10) |
| seed DN 미설정·형식 오류 | `createGroup` scope가 상한에 있으면 기동 실패 |
| 정책 위반 비밀번호 | slapd 거부(constraint violation 계열) → 기존 매핑, 멱등 기록은 확정 거부로 해제 |
| 이미 비밀번호가 있는 대상 | `W_cred` ACL 거부 → 403(쓰기 없음), 감사 `ldap_refused` |
| Password Modify 응답 유실 | `idempotency_outcome_unknown` 기록(기존 규칙), 클라이언트는 bind 시도로 확인 |
| 특권 그룹 설정 누락 | v2c: 기동 거부(검사 8). v2b 잠금: 운영 점검 스크립트(부모 T-023 확장)가 경고 |
| 표지 정리 실패(비밀번호 설정 성공 후 표지 삭제 실패) | 응답은 성공(비밀번호는 적용됨), 감사 `cleanup=failed`. `userPassword`가 있는 동안 ACL이 막으므로 즉시 위험은 없으나, 관리자가 나중에 비밀번호를 지우면 다시 대상이 된다 → 운영 점검이 "표지 ∧ 비밀번호 있음" 항목을 보고 |
| (Revision 7, **Revision 8에서 소멸**) 대기 정책 부착 실패 | Revision 8은 표지·정책을 같은 Add로 싣는다(원자적) — 부착만 실패하는 상태가 없고 Add 실패는 기존 createUser 실패와 같다 |
| (Revision 8) 버려진 대기 항목(설정이 거부됐거나 자동화가 포기, 비밀번호 없음) | 오라클 없음(비밀번호 없음). 단 나중에 사람이 비밀번호를 넣으면 safeModify가 꺼진 채가 된다 → **TTL 스윕**: `M` `(&(pwdPolicySubentry=<DN>)(creatorsName=<W_data>)(employeeType=ldapium-credential-pending:*)(!(pwdChangedTime=*)))` ∧ `createTimestamp` < 현재−`MACHINE_WRITE_CRED_PENDING_TTL` → `W_cred`가 표지·정책 정리(§2g: 거부된 특권 멤버 1건을 찾아 0으로 정리) |
| (Revision 9) 표지 없는 정책(`W_data`가 만든 항목에 정책만 남음; Add 전용 규칙 아래서는 생기지 않아야 함) | **orphan 스윕** `(&(pwdPolicySubentry=<DN>)(creatorsName=<W_data>)(!(employeeType=ldapium-credential-pending:*)))` → `W_cred`가 정책 값 정리(`W_cred` 정책 `=z` 규칙은 `creatorsName=W_data`만 요구) + 경보(생겼다는 것 자체가 규칙 위반 신호). §2g: 0건 |
| (Revision 8) 외부 부착(`creatorsName` ≠ `W_data`인 항목에 대기 정책: rootdn 수동, F-9 수정 전 자기 부착) | `W_cred`는 정리할 수 없다(filter, 50). **외부 스윕** `(&(pwdPolicySubentry=<DN>)(!(creatorsName=<W_data>)))` → 경보 + 운영 런북(관리자 `M` 검색 → 관리자 Modify로 정책 값 삭제, §2g에서 6건 모두 0) |
| (Revision 7) 정리 실패(설정 성공 후 표지·정책 삭제 실패) | 응답은 성공, 감사 `cleanup=failed`. 그 항목은 비밀번호 + 대기 정책(safeModify 꺼짐)이라 **F-5 오라클이 열린다**(인증된 누구나 "새 값 = 현재 값"을 19/50으로 판별, lockout 미집계, §2f D-5). `W_cred` 재설정은 불가(비밀번호 있음). 상한: 같은 요청 안의 1회 재시도(요청 취소와 분리된 컨텍스트, Revision 8) → 주기 스윕(`M`: `(&(pwdPolicySubentry=<DN>)(creatorsName=<W_data>)(pwdChangedTime=*))`)이 찾아 `W_cred`로 정리 → 그래도 실패하면 비밀번호 오퍼레이션 503 + 경보, 운영자가 런북으로 수동 정리. **상한(Revision 9, Codex P2)**: 고정된 시간 상한은 주장하지 않는다. 증거가 말하는 것은 "다음 스윕이 정리를 시도한다"뿐이고, 스윕의 처리량·backlog·항목별 Modify 실패는 측정하지 않았다. UI·`M`·`W_cred`·slapd가 모두 살아 있을 때도 마찬가지다. LDAP 장애, `W_cred` 회전·잠금(긴급 차단), UI 정지 중에는 창이 "복구 + 다음 스윕 한 주기" 또는 운영자 조치까지 열려 있다 — 그래서 긴급 차단·회전 런북에 수동 `M` 검색 + 관리자 정리 절차를 둔다(T-025) |
| 전제 검사 실패 | 기동 시: 비0 종료, 원인 코드만 로그. 요청 직전: 그 요청 503(쓰기 없음). 주기: 비밀번호 오퍼레이션만 503 `unavailable`, 다음 성공 주기까지. 다른 구획 영향 없음 |
| 설정 읽기 신원(`MACHINE_WRITE_CRED_ACL_READER_DN`) bind 실패 | 검사 1·2 불가 → 기동 시 거부, 실행 중이면 비밀번호 오퍼레이션 503(폴백 없음) |

## Change impact

| 영역 | 영향 |
|---|---|
| `h/machine_write_ops.go`·`machine_write_scopes.go` | 카탈로그 5행(그룹 3·잠금 1·비밀번호 1; 해제는 넣지 않음), 열린 표는 단계별로 추가 |
| `h/machine_write_attributes.go` | 닫힌 본문 집합: `createGroup {cn, description}`, `patchGroup {dn, description}`, `lockUser {dn}`, `setPassword {dn, password}` |
| `h/machine_write_pipeline.go` | 그룹 생성 DN 형태, 비밀번호 멱등 모드, 대상 전역 한도·직렬화, `credentialPending` 표지 부착, 표지 정리 단계 |
| `l/groups.go`·`l/users.go`·`l/machine_write_identity.go`·`l/machine_write_assertion.go` | 머신 경로 seed 인자, 표지 Add, `memberOf` 특권 검사·`creatorsName`·표지 태그 확인, `pwdPolicySubentry`·`pwdChangedTime` 읽기, `olcAccess` 원문 대조 |
| `c/machine.go`·`c/machine_write*.go` | 열린 scope, `MACHINE_WRITE_GROUP_SEED_DN`, `MACHINE_WRITE_CRED_*`(subtree별 카나리 DN, `_ACL_READER_*`, `_MIN_LENGTH`, `_POLICY_DNS` 포함), 기동 검증 |
| UI 기동·요청 | v2c 켬일 때 전제 검사(D379-15): 기동 시·`setPassword` 직전·60초 주기, 설정 읽기 신원(D379-16) |
| ACL | `f/write-data.ldif`에 `description`과 표지 `add` 규칙, 신규 `f/write-cred.ldif`, 신규 `cn=config` 읽기 규칙(D379-16), `W_lock`·`W_cred`에 특권 filter(성립 시), (선택) accesslog 값 수준 거부 |
| 문서·계약 | **(Q16)** `docs/api.md`·`docs/machine-write-account.md`·`docs/machine-auth-operations.md`·`llms.txt`·OpenAPI `deleteUser` 설명·CHANGELOG에 v2c 켬일 때의 `deleteUser`/modrdn 축소(비-`W_data` 사용자 50)를 명시. OpenAPI `security`·`x-machine-scope` additive, `docs/api.md`·`llms.txt`·`docs/machine-write-account.md`·`docs/machine-auth-operations.md`·`docs/audit-event-schema.md` |
| 차트 | `ui.machineAuth.write.cred.*`(Secret 참조, 카나리 DN), seed DN 값, `audit.enabled`(`charts/ldapium/values.yaml:395-408`)와 v2c 동시 활성 렌더 실패 |
| 사람 경로 | 변경 없음(목표, 회귀 시험으로 증명) |

### 호환·이행

기본 꺼짐. 새 scope를 상한에 쓰지 않으면 아무 것도 바뀌지 않는다. 오류 코드는 append-only. v2b를 켜는 순서: `W_data` ACL에 `description` 추가 → seed 항목 생성·설정 → (잠금) `W_lock` 계정·ACL·`MACHINE_WRITE_LOCK_ENABLED` → 상한에 scope. v2c: (선행) F-9 수정(#399) → `olcAddContentAcl TRUE`(Q15) → 대기 정책 항목 → `W_cred` 계정·ACL(+`W_data` Add 전용 규칙 2개) → `MACHINE_WRITE_CRED_ENABLED` → 상한에 scope. 롤백 순서(Revision 9, Codex P1): ① `MACHINE_WRITE_CRED_ENABLED=false`(또는 scope 제거) 재배포 + 진행 중 요청 drain → ② `W_data`의 Add 전용 표지·정책 규칙 제거(**부착 차단**) → ③ 스윕(또는 `M` 검색 + 관리자 정리)으로 `pwdPolicySubentry=<DN>` 0건 확인 → ④ 그다음 `W_cred` 정리 규칙 제거. ②보다 먼저 ③을 하면 늦은 Add가 0건 확인 뒤에 다시 붙인다(§2h: 0). ④를 ③보다 먼저 하면 남은 부착을 지울 수 없다. 정리 규칙을 먼저 지우면 `W_cred`는 남은 부착을 지울 수 없다(§2g: 50).

## Verification plan

- 단위: 카탈로그·열린 표·계약(D13 축소 게이트가 `D379-n`을 요구), 닫힌 본문 표(필드별 양·음성, `credentialPending`·`employeeType`), 그룹 생성 DN 형태, seed 기동 검증, 특권 멤버 검사, `unlockUser` 미개방(거부 목록), `olcAccess` 원문 대조 판정(일치·앞 규칙 추가·묶음 변형·토큰 불일치), 정책 하한 비교, 비밀번호 대상 직렬화, 표지 태그 계산·대조, 비밀번호 멱등 모드(저장 본문 `{}`, 서버 생성 422), 전제 검사 판정 표(결과 코드별, 기동·요청·주기), `W_cred` 기동 검증 변형 표, 감사 줄의 비밀번호 필드 부재.
- 라이브(실제 slapd, 새 컨테이너): [EVIDENCE.md](EVIDENCE.md) `E-01`–`E-23`. ACL은 앱을 거치지 않는 직접 `ldapmodify`/`ldappasswd`로, 오퍼레이션은 실제 Keycloak 토큰으로. 비밀 노출 스캔은 HTTP 응답·UI 감사·`docker logs`(UI/slapd/Keycloak)·**auditlog stdout**(`LDAP_AUDIT_ENABLED=true` 구성)·accesslog(`writes` 포함 구성, 관리자 읽기와 `M` 읽기 각각)에서 평문 센티널과 해시 패턴을 모두 찾는다(`E-13`).
- 변이 시험: seed를 `c.dn`으로 되돌림, 허용 목록 검사 제거, `patchGroup` `cn` 허용, 특권 멤버 검사 제거, `unlockUser`를 열린 표에 추가, 원문 대조에서 "앞 규칙" 검사 제거, 대상별 정책 검사 제거, accesslog 검사를 base 검색으로 되돌림, 비밀번호 멱등 모드 끔(`false`), `oldPassword` 허용, 표지 태그 대조 제거, ACL filter의 `creatorsName`/표지 조건 제거, 전제 검사 하나 제거 → 각각 시험이 실패해야 한다.

## Rollout, rollback and recovery

v2b·v2c 각각: 기본 꺼짐 병합 → 라이브 증명 → 운영자가 scope 부여. 롤백: scope 제거(재배포) 또는 구획 플래그 끔, ACL 조각 역순 제거. 긴급: 구획별 신원 회전(AC-011). 복구: 잘못 잠근 계정은 사람 경로로 해제, 잘못 설정된 초기 비밀번호는 사람 경로로 재설정.

## Evidence and durable synchronization

증거는 [EVIDENCE.md](EVIDENCE.md)에 실제 명령·출력(실패 포함, `research/README.md`). 구현 PR마다 OpenAPI·`docs/api.md`·`llms.txt`·운영 문서·CHANGELOG를 같은 PR에서 동기화하고 #379에 "Related to #379 (not closing yet)"로 기록한다(AGENTS.md "Issue tracker convention").

## Traceability matrix

| REQ | 결정 | AC | TASKS |
|---|---|---|---|
| REQ-001 | D379-1, D379-2 | AC-001 | T-010, T-020 |
| REQ-002 | D379-1 | AC-001 | T-014, T-026 |
| REQ-003 | D379-3 | AC-002 | T-010, T-011 |
| REQ-004 | D379-4, D379-6 | AC-003 | T-011 |
| REQ-005 | D379-5 | AC-004 | T-011, T-012 |
| REQ-006 | D379-2 | AC-005, AC-006 | T-013 |
| REQ-007 | D379-8 | AC-005, AC-007 | T-013, T-022 |
| REQ-008 | D379-7 | AC-005, AC-005b | T-013 |
| REQ-009 | D379-2 | AC-007 | T-020 |
| REQ-010 | D379-10 | AC-007, AC-007b | T-021, T-022 |
| REQ-011 | D379-9 | AC-008 | T-022 |
| REQ-012 | D379-12, D379-14 | AC-009 | T-022, T-024, T-028 |
| REQ-013 | D379-9 | AC-008, AC-010c | T-023 |
| REQ-014 | D379-13, D379-15, D379-16 | AC-010, AC-010b | T-002(E-10), T-024, T-028 |
| REQ-015 | D379-11 | AC-008 | — (Q6) |
| REQ-016 | D379-12 | AC-012 | T-013, T-023 |
| REQ-017 | — | AC-011 | T-025 |
| REQ-018 | D379-10 | AC-007b | T-029, T-021 |

## Open questions for the maintainer

각 항목에 권고안을 둔다. **[유지보수자]** 표시는 부모 Resolved Q1처럼 유지보수자의 명시 결정이 필요한 항목이고, 나머지는 권고대로 진행하되 이의가 있으면 수용 시 바꾼다.

1. **[유지보수자] v2c 착수 승인**(부모 Resolved Q1). **Resolved 2026-10-13: 승인**(전용 security-reviewer 라운드 + Codex critic이 수용 선행, 미실시). 권고: 이 설계를 수용하되 구현은 v2b 병합과 부모 T-025(CI 릴리스 게이트) 이후에 시작하고, 수용 전 전용 security-reviewer 라운드와 Codex critic 1회를 거친다.
2. **[유지보수자] seed 멤버**(부모 D22). 권고: 옵션 B 고정 placeholder DN(`MACHINE_WRITE_GROUP_SEED_DN`, bind 불가 항목, 보호 집합 자동 포함).
3. **[유지보수자] 생성 그룹의 허용 목록 편입**. 권고: 첫 v2b 출하는 자동 편입 없음(정확 DN 허용 목록 유지). 그룹 서브트리 허용(`MACHINE_WRITE_GROUP_SUBTREES`)은 다운스트림 역할 매핑이 그 서브트리를 참조하지 않는다는 운영 보증과 함께 별도 결정.
4. **[유지보수자] 잠금 해제를 잠금과 함께 열지**. 권고(Revision 2에서 다시 변경): **열지 않는다 — 해제는 사람 전용**. 값으로 관리 잠금과 ppolicy 잠금을 구별할 수 없고(P22) 잠금→해제 왕복이 우회가 되기 때문이다. 해제 자동화가 필요하면 D379-7 탈출구(지속 표지)를 별도 승인으로.
5. **[유지보수자] 초기 비밀번호만 vs 재설정 포함**. **Resolved 2026-10-13: 권고대로**(첫 출하 = 이 기능이 대기 표지와 함께 만든 계정의 초기 비밀번호만, 재설정 제외). `E-08`·`E-16`·`E-17`은 성립했으므로(EVIDENCE §2e) 다시 열지 않는다. 권고(Revision 1에서 변경): 첫 v2c 출하는 **이 기능이 대기 표지와 함께 만든 계정의 초기 비밀번호만**(ACL: `creatorsName=W_data` ∧ 표지 ∧ `!(userPassword=*)`, 앱: client 태그 대조). 비밀번호가 없는 기존 계정(SSO 등)은 대상이 아니다. 재설정은 별도 승인. `E-08`·`E-16`·`E-17` 중 하나라도 성립하지 않으면 이 질문을 다시 연다.
6. **[유지보수자] 비밀번호 포함 `createUser`**. **Resolved 2026-10-13: 권고대로**(열지 않음, `createUser` → `setPassword` 합성). 권고: 열지 않는다(부모 D15 유지). 합성 `createUser`→`setPassword`.
7. `patchGroup`의 `cn` 변경. 권고: 머신 경로에서 거부(`description`만).
8. 비밀번호 정책 비활성 배포(`LDAP_PASSWORD_POLICY_ENABLED=false`, `image/entrypoint.sh:1307`)에서 v2c를 허용할지. 권고(Revision 1에서 변경): **허용하지 않는다 — 실행 시 기동 거부**. 기동 프로브 4(D379-15)가 정책 미적용을 직접 관측하므로 UI가 `cn=config`를 읽지 않아도 거부할 수 있다. 운영 점검 스크립트는 보조다.
9. 비밀번호 대상 범위를 쓰기 상한보다 좁힐지(`MACHINE_WRITE_CRED_SUBTREES ⊆ MACHINE_WRITE_SUBTREES`). 권고: 예, 비면 비밀번호 쓰기 불가.
10. 특권 멤버 거부를 잠금·비밀번호 외(`patchUser`·`deleteUser`)에도 적용할지. 권고: 이 패키지 범위 밖이지만 같은 검사이므로 v2b 구현 시 v2a 오퍼레이션에도 적용하는 후속 이슈를 연다(관리자 `mail` 변경 = SSO 탈취, 부모 D19 시나리오).
11. **[유지보수자] 대기 표지 속성**. **잠정(provisional, recommendation, not explicitly confirmed, 2026-10-13)**: 권고대로 진행. 권고: `employeeType`(inetOrgPerson 표준 속성, 현재 앱·머신 목록 미사용) 값 `ldapium-credential-pending:<16 hex>`. 그 속성을 이미 쓰는 배포를 위해 속성 이름을 설정 가능하게 할지는 구현 시 결정(기본값은 고정). 전용 스키마 속성 추가는 이미지 스키마 변경이라 별도 패키지.
12. **[유지보수자] `M` accesslog 읽기(감사 옵트인)와 v2c의 공존**. **잠정(provisional, recommendation, not explicitly confirmed, 2026-10-13)**: 상호 배제로 진행. `E-12c`에서 값 수준 거부(`reqMod`·`reqOld` 각각 한 규칙)가 `M`에 대해 성립했으나 공존 결정은 여전히 별도다. 권고: 첫 v2c 출하는 **상호 배제**(검사 6: `M`이 accesslog 자식 항목을 하나라도 읽으면 거부). 값 수준 거부 규칙(`val.regex="^userPassword:"`)이 `E-12`에서 성립하면 공존을 별도 결정으로 열고 검사 7(실제 쓰기의 자식 항목 사후 확인)로 바꾼다. auditlog(`LDAP_AUDIT_ENABLED`)와 v2c는 차트에서 동시 활성 불가, 차트 밖 배포는 문서로만 막힌다는 잔여 위험(R-6)을 수용할지 함께 결정.
13. **[유지보수자] 설정 읽기 전용 신원(D379-16)**. **잠정(provisional, recommendation, not explicitly confirmed, 2026-10-13)**: 둔다. `E-21`이 성립 조건 두 가지를 더했다(규칙에 `entry` 포함, 메인 DB에 그 신원의 `none` 규칙). 권고: 둔다 — 범위 전체 ACL·기본 정책 증명은 `olcAccess`·`olcPPolicyDefault` 원문 없이는 불가능하다. 대안(운영 점검 스크립트 결과만 신뢰)은 노출 창이 "다음 점검까지"로 커지므로 그 경우 R-2를 수용으로 기록해야 한다.
14. **[유지보수자] F-5 창의 수용**(Revision 7). **Resolved 2026-10-13: 수용 + 스윕 강화**(Revision 8: stuck·TTL·외부 스윕, 분리 컨텍스트 정리, 409 사전 거부, 정직한 상한). 대기 정책이 붙은 계정은 비밀번호가 생긴 순간부터 정리 전까지 인증된 누구나 "현재 비밀번호와 같은가"를 lockout 없이 판별할 수 있다(19/50). 비밀번호가 없을 때는 오라클이 없다(§2f D-4). 권고: **수용** — 창은 정상 경로에서 같은 요청 안의 exop→정리 Modify 사이(ms)이고, 정리 실패 시 다음 주기 스윕이 정리를 시도하고 503·경보를 낸다(Revision 9: 고정 시간 상한은 주장하지 않음 — 스윕 처리량·backlog 미측정). 창을 0으로 하려면 탈출구(원자적 plain Modify, §2f D-7)를 택하되 accesslog `writes` 구성에 해시가 남는 비용(F-8, D379-14와 같은 상호 배제로 관리)을 진다.
15. **[유지보수자] `olcAddContentAcl TRUE`**(Revision 7). **Resolved 2026-10-13: v2c 선행 조건으로 채택**(아래 권고는 기각됨). 출하 값(FALSE)에서는 Add가 속성별 ACL을 보지 않아 `W_data`가 Add 안에 임의의 `pwdPolicySubentry`(·`userPassword`, #386)를 실을 수 있다(§2f D-1). TRUE면 Add 시점 부착도 ACL로 정확한 DN·표지 항목에 한정되고 `userPassword` Add도 50이 된다(D-3). 다만 메인 DB 전체 스위치라 rootdn이 아닌 모든 Add 주체에 영향이 있다. 권고: 첫 v2c 출하는 FALSE 유지 + Modify 부착(ACL 한정) + "표지 없는 대기 정책" 스윕, TRUE는 #386과 함께 별도 결정.
16. **[유지보수자] M-3 완화의 계약 영향과 잔여 위험**(Revision 9). **Resolved 2026-10-14: 수용** — **v2a 계약 축소(Q16, 2026-10-14 유지보수자 수용)**: v2c를 켠 배포(M-3 완화 규칙 (a) 설치)에서는 머신 `deleteUser`와 modrdn이 `W_data`가 만들지 않은 사용자(`creatorsName` ≠ `W_data`)에 대해 LDAP 50으로 거부되고 앱은 그것을 기존 매핑의 거부로 돌려준다. `W_data`가 만든 사용자와 v2c를 켜지 않은 배포는 바뀌지 않는다. 잔여 위험(스스로 만든 계정, 중첩 특권 그룹)도 권고대로 수용. 완화 (a)를 설치하면 머신 `deleteUser`(v2a)와 modrdn은 `W_data`가 만든 사용자에게만 동작한다(관리자가 만든 사용자 삭제는 50) — v2c를 켠 배포에서 v2a 계약이 좁아진다. 남는 위험: `W_data`가 스스로 만든 계정의 삭제→재생성→설정, 특권 그룹의 중첩 그룹. 권고: (a)·(b)를 `W_cred` 조각과 같이 설치하고(v2c 켤 때만), 두 잔여 위험을 수용하되 운영 가이드에 "v2a로 만든 계정을 SSO 신원으로 쓰는 배포는 v2c를 켜지 말 것"과 "특권 그룹의 하위 그룹을 `MACHINE_WRITE_PRIVILEGED_GROUPS`에 함께 나열할 것"을 둔다.
17. **[유지보수자] `W_cred` 잠금 정책**(T-025). **Resolved 2026-10-14: 결정됨(무잠금, (b))** — 가이드 8.1이 `W_cred`에 9.1 무잠금 정책(`wcred-policy.ldif`: `pwdLockout FALSE`, `pwdMaxFailure` 없음)을 설치 단계로 붙인다(T-026, EVIDENCE §2m). 무차별 대입 완화는 운영자 책임으로 가이드에 명시: 긴 무작위 `W_cred` 비밀번호(264비트), LDAP 도달 범위 제한(NetworkPolicy·방화벽), `W_cred` 실패 bind 경보 → 즉시 회전. T-028 검사는 이 정책을 읽지 않는다(허용은 실측, 강제 여부는 아래 Q18). 원래 질문: 기본 정책(`pwdLockout TRUE`, `pwdMaxFailure 5`)에서는 LDAP에 닿는 누구나 틀린 비밀번호 5번으로 `W_cred`를 잠가 `setPassword`를 멈출 수 있다(읽기·다른 구획은 무관, 라이브 실측 EVIDENCE.md §2k). `W_data`용 무잠금 정책(가이드 9.1)을 `W_cred`에 붙이면 잠기지 않는 것도 실측했다(13번 거절, T-028 기동 검사 통과). 대가: 잠금이 없으면 `W_cred` 비밀번호 추측이 제한되지 않는다(완화는 실패 bind 알림뿐). 선택지: (a) 기본 정책 유지(DoS 가능, 추측 제한), (b) 무잠금 정책(DoS 없음, 추측 무제한), (c) 짧은 잠금(`pwdLockoutDuration` 수 초~수 분). 권고 없음 — 위험 선호의 문제. 코드·가이드는 기본으로 아무것도 붙이지 않는다.

18. **[유지보수자] T-028이 `W_cred` 무잠금 정책을 강제할지**(T-026, Q17 후속). **사용자 결정 필요**: 지금 T-028은 `W_cred`의 정책을 읽지 않는다 — 무잠금 정책이 붙어도 통과(실측)하고, 빠져도 거부하지 않는다(가이드 8.1·8.6 확인이 유일한 통제). 강제하려면 새 검사(예: `M` 또는 `W_cred` 자신이 `W_cred`의 `pwdPolicySubentry`와 그 정책의 `pwdLockout`/`pwdMaxFailure`를 읽고, 잠그는 정책이면 기동 거부/503)가 필요하고, 그 읽기 권한(`M` 읽기 base가 `ou=system`을 덮지 않는 배포)과 실패 코드·드릴(기본 정책 잠금 함정 측정은 그 검사를 우회해야 함)을 정해야 한다. 선택지: (a) 강제 안 함(현재, 가이드 책임), (b) 기동·주기 검사로 강제(fail closed), (c) 경고 로그만. 권고 없음.
19. **[유지보수자] 플래그만 끈 재배포의 상태 코드**(T-026, AC-011 (a)). **사용자 결정 필요**: 실제(`config.Load`) 경로는 403 `scope_denied`("dn is not permitted"), T-025가 기록한 503은 코드로 만든 구성에서만 나온다(T026-F1). 둘 다 `W_cred` bind 0·기동 성공. 선택지: (a) 403 유지·문서화(현재, 코드 변경 없음; 대가: 운영자가 "권한 없음"으로 읽을 수 있음 — 운영 문서가 차단 신호로 설명), (b) 플래그가 꺼졌을 때 `setPassword`를 가드 전에 503으로 답하도록 코드 변경(긴급 차단을 일시 장애로 표시; `Retry-After` 여부도 결정).

## Ship-gating open risks

실측 없이는 닫을 수 없는 항목이다. 각 항목은 EVIDENCE.md 실험으로 닫히기 전까지 **v2c(또는 표시된 단계) 출하를 막는다**. 이 문서의 다른 곳에서 이 항목들을 성립한 것으로 주장하지 않는다.

| ID | 위험 | 닫는 실험 | 닫히지 않으면 |
|---|---|---|---|
| R-1 | ACL `filter=`가 `creatorsName`·표지 부분 문자열·`!(userPassword=*)`·`memberOf` 부정을 `W_cred` 권한과 무관하게 평가하는지, `val.regex`가 `=z`를 표지 값으로 한정하는지 | E-07, E-08, E-16 | 초기 전용 경계 철회, Q5 재결정 |
| R-2 | `olcAccess` 원문 대조가 slapd가 돌려주는 정규화 형식(인덱스 접두, 공백, 따옴표)과 안정적으로 일치하는지, 설정 읽기 신원 ACL이 그 두 속성만 노출하는지 | E-21 | D379-16 재설계 또는 Q13 대안(노출 창 = 점검 주기) 수용 |
| R-3 | 같은 대기 계정에 대한 동시 Password Modify 중 정확히 한 건만 성공하는지 | E-17 | 초기 전용 경계 철회 |
| R-4 | 전제 검사 읽기와 쓰기 사이의 TOCTOU: 그 사이 ACL·정책이 바뀌면 그 한 요청은 옛 전제로 실행된다. 상한 = 요청 직전 검사부터 쓰기 완료까지(≤ `MACHINE_REQUEST_TIMEOUT`, 기본 10초) × 비밀번호 전역 예산(1 rps) | E-22(창 실측) | **닫을 수 없음** — 수용 대상으로 유지보수자 결정에 올린다(Q13과 함께) |
| R-5 | accesslog가 실패·성공 Password Modify에 해시를 남기는지, `M` 외 감사 독자 노출, 공존 모드에서 검사 7이 첫 노출 1건을 사후에야 본다는 점 | E-12, E-23 | 상호 배제 유지(공존 불가) |
| R-6 | 차트 밖 배포에서 auditlog와 v2c 동시 활성 | (실험 아님, 구성 문제) | 문서 경고로 수용할지 유지보수자 결정(Q12) |
| R-7 | `W_cred`(대상≠요청자) 설정에 품질·이력 규칙이 적용되는지(검사 5는 길이만 증명) | E-10 | v2c 출하 중단(D379-13) |
| R-8 | ppolicy가 `W_cred` 설정 시 `pwdChangedTime`을 남기고 `M`이 읽을 수 있는지(검사 4의 근거) | E-20 | 검사 4에서 그 조건 제거, R-1에 의존 |

**2026-10-13 실측 후 상태**(EVIDENCE.md §2e, 근거·수치는 그곳): R-1 **닫힘**(filter 의미: E-07 직접 멤버·E-08·E-16 성립; 단 ACL보다 먼저 거부하는 정책이 없을 때 — F-4; 중첩 특권 멤버는 REQ-007 수용 위험). R-2 **닫힘**(E-21 안정성·노출 범위; 설계 추가 2건: 읽기 규칙에 `entry`, 메인 DB에 그 신원의 `none`). R-3 **단일 slapd에서 LDAP 수준으로 닫힘**(E-17 직접 경로 11라운드×10 + 최종 정책 5라운드×10, 매번 1건만 성공; 앱 경로 절반은 오퍼레이션 구현 후). **다중 provider에서는 닫히지 않는다**(Revision 8): 두 provider가 각각 "비밀번호 없음"을 보고 동시에 설정을 받아들일 수 있고, 복제는 `entryCSN` last-write-wins로 하나를 조용히 남긴다(AGENTS.md) — 성공 응답을 받은 client 중 하나의 비밀번호는 동작하지 않는다. 앱 경로 고정만으로는 부족하다(직접 `W_cred` 쓰기, AC-010c Revision 9): 다른 provider의 `W_cred` 차단이 필요하다(미실측). R-4 닫을 수 없음(E-22 미실행). R-5 **열림**(운영자 감사 독자·plain Modify 경로·거부된 쓰기의 시도 해시, F-8) → 상호 배제 유지. R-6 유지보수자 결정 대기(auditlog 해시 확인). R-7 **설계 변경 필요**(F-4 safeModify, F-6 사전 해시 우회; 이력은 초기 설정으로 증명 불가). R-8 **닫힘**(E-20).

## Not verified

- (2026-10-13 갱신) EVIDENCE.md §2b·§2d·§2e가 E-05·E-06·E-07–E-12·E-15·E-16·E-17(LDAP 직접)·E-19·E-20·E-21·E-23을 실측했다. 남은 것은 EVIDENCE.md §3. 아래는 작성 당시의 원문이다.
- `E-01`–`E-23` 전부(EVIDENCE.md): 이 패키지는 라이브로 아무 것도 실행하지 않았다. 특히 ACL `filter=`의 `userPassword` 부재·`creatorsName`·표지 부분 문자열·`memberOf` 부정 평가(E-07/E-08/E-16), 동시 Password Modify의 단일 성공(E-17), Password Modify의 ACL 요구 수준(E-09), 관리자형 설정에 대한 ppolicy 적용(E-10), accesslog·auditlog의 해시 기록과 값 수준 거부(E-12), 잠금 덮어쓰기·duration 0 잠금의 형태(E-19), `olcAccess` 원문 대조의 안정성(E-21), 검사→쓰기 창(E-22), accesslog 자식 항목 노출(E-23), `pwdChangedTime` 기록(E-20), `cn` 교체의 slapd 결과(E-05), `olcMemberOfDangling` 기본값의 seed 영향(E-04).
- 코드 사실(P1–P23의 줄 번호)은 main `049fcc3`에서 읽어 확인했다. 이후 변경으로 어긋날 수 있다.

## Revision

- 2026-10-14 Revision 14 (T-026 개방; 실측 EVIDENCE.md §2m). 설계 결정 문구는 불변.
  - **개방**: `setPassword`를 `machineWriteOps`·`config.MachineWriteOpenScopes`에 추가, `machineWriteOpenedBy`에 D379-9/D379-10. OpenAPI `machineBearer`/`x-machine-scope`, `docs/api.md`·`llms.txt`·CHANGELOG·차트 `ui.machineAuth.write.cred.*`(Secret 참조만).
  - **Q16**(Revision 10 수용)의 v2a `deleteUser`/modrdn 축소를 `docs/api.md`·OpenAPI `deleteUser` 설명·`llms.txt`·`docs/machine-write-account.md`·CHANGELOG에 명시.
  - **Q17 결정됨(2026-10-14, 무잠금)**: 가이드 8.1 + `wcred-policy.ldif`, 운영자 책임 명시. T-028 강제 여부는 Q18.
  - **Revision 12 확정(유지보수자 수용, 2026-10-14)**: T028-F1의 좁아진 카나리 역할(19는 대기 정책 적용만, 특권 filter·`CRED_DN` 경계 항은 검사 1만)과 D379-16 확장(설정 읽기 신원의 메인 DB `olcAddContentAcl` 읽기)을 수용으로 기록한다.
  - **AC-011 (a)**: T-025의 503 정정을 확정 기록하되, 실제 `config.Load` 경로는 403임을 실측(T026-F1) — 상태 코드 선택은 Q19.
  - **T026-D1**: 상한의 `directory.users.password.write`는 `MACHINE_WRITE_CRED_ENABLED`가 꺼져 있어도 기동한다(`directory.users.lock`과 다름). 이유: 플래그만 끄는 긴급 차단이 기동 실패가 되면 안 된다(T025-F1 유지보수자 결정). 대가: 플래그를 끈 채 상한에 scope를 남긴 오구성이 기동 시 드러나지 않음(요청 시 403, bind 0). 탈출구: lock처럼 기동 거부.

- 2026-10-14 Revision 13 (T-025 드릴 검토 반영; 실측 EVIDENCE.md §2k). AC-011 (a) 정정(플래그만 끄면 503, 유지보수자 결정), 열린 질문 Q17(`W_cred` 잠금 정책)과 위협 행 추가. 설계 결정 문구는 불변.
- 2026-10-14 Revision 12 (T-028 구현 검토: Codex P1 1, security-reviewer MAJOR 1·MINOR 5, BLOCKER 0; 실측 EVIDENCE.md §2j). 유지보수자 답(2026-10-14) 반영:
  - **T028-F1 (MAJOR, 유지보수자 결정 필요)**: ppolicy가 값을 ACL보다 먼저 판정하므로 대기 카나리의 19는 ACL이 그 계정을 허용한다는 증거가 아니다(표지를 지워도 19, 실측). 검사 5의 역할을 좁힌다: 비밀번호 있는 표지 카나리의 50은 `!(userPassword=*)` 항, **`W_data`가 만들고 관리자가 대기 정책만 붙인** 표지 없는 카나리의 50은 표지 항을 격리해 확인하고(표지를 붙이면 `canary_unmarked_accepted`, 실측), 19 두 개는 대기 정책(길이·quality 2)이 `W_cred`에 적용됨만 보인다. **특권 filter 항·`CRED_DN` 경계 항은 카나리로 확인되지 않으며 검사 1(원문 대조)이 유일한 통제다.** 이 좁아진 역할의 수용은 유지보수자 결정으로 남긴다. **(Revision 14: 2026-10-14 유지보수자 수용, 확정.)**
  - **D379-16 확장(Q2 수용)**: 설정 읽기 신원 규칙이 메인 DB 항목의 `olcAddContentAcl`도 read(읽기 전용)한다 — Q15 선행 조건을 검사 1에서 확인하기 위해서다. **(Revision 14: 수용 확정.)**
  - Q1: 이미지 기본 `pwdMinLength` 8 < 하한 12는 의도된 운영 부담 — v2c 배포는 `LDAP_PASSWORD_MIN_LENGTH>=12`. Q3: `MACHINE_WRITE_CRED_PENDING_TTL` 기본 24h(잠정). Q4: `MACHINE_WRITE_CRED_POLICY_DNS`는 그대로(사전 읽기가 대기 정책만 받으므로 현재 효과 없음, 문서에 명시).
  - Codex P1: 스윕 정리가 실패하면(검색 뒤 값이 바뀐 `noSuchAttribute` 포함) `M`으로 다시 읽어 남은 값만 지우고, 대기 정책 값이 없을 때만 정리로 센다(경쟁 실측). MINOR: accesslog 검사 filter `(|(objectClass=*)(reqMod=*)(reqOld=*)(reqDN=*))`; 검사가 실패한 주기의 스윕은 검색·계수만(`W_cred` 쓰기 없음); 기동 시 읽기 전용 스윕에서 stuck이 있으면 기동 거부; 마지막 주기가 2×주기보다 오래되면 비밀번호 오퍼레이션 503; 차트 가드 대소문자·공백 무시.

- 2026-10-14 Revision 11 (T-021 구현 검토: security-reviewer MAJOR 2·MINOR 4, Codex P1 3; 실측 EVIDENCE.md §2i). 결정 문구 중 M-3 (a)와 배포 형태만 바뀐다.
  - **MAJOR-1**: M-3 (a)가 `inetOrgPerson`만 덮어, 관리자가 만든 `person`·`organizationalPerson`·`account`/`posixAccount` 항목은 지우고 같은 DN의 대기 `inetOrgPerson`으로 재생성할 수 있었다. (a)의 filter를 클래스와 무관하게 `(&(!(objectClass=groupOfNames))(!(creatorsName=<W_data>)))`로 바꿨다(그룹은 v2b `deleteGroup` 때문에 제외). Q16의 축소는 "W_data가 만들지 않은 사용자"에서 "W_data가 만들지 않은 그룹 아닌 항목"(컨테이너 포함, 앱은 원래 컨테이너 삭제를 거부)으로 표현만 넓어진다.
  - **MAJOR-2 (세 번째 수용 위험, Q16과 같은 범주)**: (a)는 삭제·modrdn만 막는다. 유출된 `W_data`가 관리자가 만든 (특권) 사용자의 `mail`·`uid`를 바꾸고 그 옛 값의 대기 계정을 만들어 설정하면, 로그인 이름을 `mail`·`uid`로 해석하는 소비자에서 그 신원으로 로그인된다. `mail`·`uid`를 (a)에 넣으면 v2a `patchUser`(관리자가 만든 사용자의 `mail` 변경)가 Q16 수용 범위 밖으로 좁아지므로 넣지 않고 문서화했다(운영 가이드 8절: 불변 식별자 바인딩·변경 경보, 아니면 v2c를 켜지 않음). **유지보수자 확인 필요**로 남긴다.
  - **Codex P1**: `W_cred` 묶음은 고정 provider 하나에만, 다른 provider에는 `write-cred-deny.ldif`(`to * by W_cred none`), 점검 스크립트 `--wcred-unpinned`. 롤백 0건 확인은 검색 실패를 0으로 보지 않고(fail closed) provider마다 실행한다(복제 지연).
  - MINOR: DN의 filter·`sed` 메타문자 거부(가이드·점검 스크립트), 점검 스크립트가 설치와 인자에서 함께 빠진 특권 그룹을 알 수 없음을 명시, Q14 창 안의 자기 비밀번호 변경 명시, 재시작 후 `olcAddContentAcl`·배치 유지 실측.
- 2026-10-14 Revision 10 (유지보수자 Q16 수용). **v2a 계약 축소(Q16, 2026-10-14 유지보수자 수용)**: v2c를 켠 배포(M-3 완화 규칙 (a) 설치)에서는 머신 `deleteUser`와 modrdn이 `W_data`가 만들지 않은 사용자(`creatorsName` ≠ `W_data`)에 대해 LDAP 50으로 거부되고 앱은 그것을 기존 매핑의 거부로 돌려준다. `W_data`가 만든 사용자와 v2c를 켜지 않은 배포는 바뀌지 않는다. 문서 동기화 목록과 T-021/T-026에 반영.
- 2026-10-13 Revision 9 (Revision 8 재검토 반영; 실측 EVIDENCE.md §2h, 93/93, exit 0). Q16 추가.
  - **M-3**: `W_data`의 `entry` write는 Delete도 허용해, 유출된 `W_data` + `password.write` client로 관리자가 만든 특권 계정을 삭제→대기 재생성→설정→특권 재가입할 수 있었다(실측 재현). 완화 (a) 비-`W_data` `inetOrgPerson`의 `entry`는 `W_data`에 `=rsc`, (b) 특권 그룹 `member`는 `W_data`에 `=rsc` — 둘 다 성립(50). 부작용·잔여 위험은 Q16과 위협 표(정정).
  - MINOR: `olcAddContentAcl TRUE`에서 createGroup(+description) 0·사용자 description Add 50 단언; orphan 스윕을 운영 목록에 추가; TTL 조건(`createTimestamp<=`)을 `M`으로 실측; 분리 정리는 `context.WithoutCancel` + 제한 시간(T-022); F-9 단언은 #399 수정이 이미지에 있을 때만 50을 기대.
  - Codex P1: 롤백은 부착 차단 → 0건 확인 → 정리 권한 제거(늦은 Add 재부착 실측). Codex P2: 고정 시간 상한 주장 철회; AC-010c·R-3을 provider 하나로 한정하고 다른 provider의 `W_cred` 차단을 요구.

- 2026-10-13 Revision 8 (독립 검토 반영 + 유지보수자 Q14·Q15·F-9 결정; 실측 EVIDENCE.md §2g). D379-18 개정(Add 전용 부착), REQ-010·D379-18 근거 문장 정정, 실패 모드(버려진·외부 부착·정직한 상한), R-3 범위(단일 slapd), 롤백 순서, Q14·Q15 Resolved.
  - **M-1**: 표지 `add` 규칙이 Modify에도 적용되어 유출된 `W_data` + `password.write` client 하나로 기존(SSO·v2a) 계정을 대기로 만들 수 있었다. 이제 `olcAddContentAcl TRUE` + 자기 속성을 요구하는 filter로 Add 전용(§2g M-1: Modify 표지·정책 부착·삭제 6종 모두 50). 두 번째 표지 값은 붙으므로 앱은 표지 정확히 하나를 요구한다.
  - **Codex P1**: 부착·설정 filter = `creatorsName=W_data` ∧ 표지 ∧ `!(userPassword=*)` ∧ 비특권 ∧ 대기 정책; 정리 = 표지 값·정확한 정책 DN 값만, `W_data`가 만든 항목만(§2g: 교차 표 a만 0, 정리 음성 5종 50).
  - **Q15 실측**: TRUE에서 정상 createUser 0, `userPassword`를 실은 Add 50, 표지·정책 단독·다른 정책·상한 밖 Add 50.
  - **스윕**: stuck(비밀번호 있음)·TTL(버려진 대기)은 `W_cred`가 정리, 외부(`!(creatorsName=W_data)`)는 경보 + 런북 관리자 정리 — 정확한 집합으로 실측. 사전 읽기는 `pwdChangedTime`이 있으면 409.
  - **F-9**는 #399로 별도 PR에서 먼저 고친다(이 레인은 `image/entrypoint.sh`를 건드리지 않는다). F-7은 별도 이슈(여기서 열지 않음).

- 2026-10-13 Revision 7 (유지보수자 F-4 결정; 실측 EVIDENCE.md §2f, 스크립트 64/64, exit 0). D379-18 추가, D379-9·D379-13·REQ-010·REQ-014·REQ-018·실패 모드 개정, Q14·Q15 추가.
  - 부착은 `W_data` Modify(ACL: 정확한 DN, 표지 항목, add만 → 다른 DN·비표지·일반 계정 50); Add 안의 부착은 `olcAddContentAcl FALSE`라 ACL이 막지 못한다(D-1, #386) → 앱 닫힌 본문 + "표지 없는 대기 정책" 스윕이 보완(Q15). 일반 사용자는 다른 계정에 붙이지 못하지만(50) **자기 항목에는 아무 정책이나 붙일 수 있다**(이미지 `to * by self write`, F-9 — 기존 결함, 별도 이슈 필요, 여기서 열지 않음). 그런 항목은 `W_cred` 대상이 아니고 스윕이 찾는다.
  - 대기 정책 아래 7자 exop 19, 사전 해시 plain Modify 19(quality 2), 정상 exop 0; 다른 정책이 붙은 표지 계정 50; 정리 한 Modify로 표지·정책 삭제 후 기본 정책 복귀(safeModify, 오라클 소멸).
  - F-7(accesslog `extended` → slapd 중단)은 이 범위 밖이며 별도 이슈로 다룬다(여기서 열지 않음).

- 2026-10-13 Revision 6 (v2c 설계 게이트 실측, EVIDENCE.md §2e; 유지보수자 2026-10-13 v2c 착수 승인 — Q1 승인, Q5·Q6 권고대로, Q11–Q13 잠정). 결정 문구는 아직 바꾸지 않았다 — 아래는 **개정 결정이 필요한 실측**이다.
  - **F-4 (설계 변경 필요)**: 출하 기본 정책 `pwdSafeModify: TRUE`가 rootdn·비밀번호 관리자 아닌 요청자의 Password Modify를 대상에 비밀번호가 없어도 거부한다("Must supply old password", 50). 스케치의 `W_cred`(`=w`)로는 기본 정책 계정에 초기 비밀번호를 설정할 수 없다. 대안 실측: (A) `W_cred`를 비밀번호 관리자로(`=wm`) — 설정은 되지만 ppolicy가 길이·품질을 건너뛴다(7자·2자 저장) → D379-13 위반, 기각. (B) 대기 계정별 정책(기본 사본, `pwdSafeModify FALSE`, `pwdCheckQuality 2`)을 `W_data`가 Add 시 `pwdPolicySubentry`로 부착(Add 0, Modify 50) — 모든 ACL·정책 기대가 성립하지만 F-5가 생기고 정리 단계가 정책 부착도 지워야 한다. (C) 기본 정책의 safeModify 끄기 — F-5를 모든 계정에 열므로 기각. 결정 전에는 T-020/T-021을 시작하지 않는다.
  - **F-5**: `pwdSafeModify FALSE` 계정에 비밀번호가 있으면 인증된 누구나(`W_cred`·`M`·일반 사용자 실측) "새 값 = 현재 값"을 19(같음)/50(다름)으로 구별할 수 있고 `pwdFailureTime`이 남지 않아 lockout이 걸리지 않는다. 출하 기본(safeModify TRUE)은 맞는/틀린 옛 비밀번호 모두 53이라 이 오라클이 없다.
  - **F-6**: `pwdCheckQuality 1`(출하 값)에서는 `W_cred`가 직접 plain Modify로 사전 해시 값을 넣어 길이 규칙을 우회한다(2자 비밀번호 bind 성공). `pwdCheckQuality 2`면 19로 거부.
  - **F-7 (범위 밖 결함, 사람 경로 포함)**: `LDAP_ACCESSLOG_OPS`에 `extended`(또는 `all`)가 있으면 Password Modify 한 번에 slapd가 중단된다(`accesslog.c:1623` assertion, exit 133). 별도 이슈 필요.
  - **F-8 (P17·P21 정정)**: `writes reads bind`에서 exop는 성공·거부 모두 accesslog에 남지 않는다. plain Modify는 해시를 남기고, ACL로 **거부된** plain Modify도 시도 값의 해시를 남긴다. auditlog는 exop 해시를 남긴다(P20 확인).
  - 그 밖의 실측: Password Modify는 `entry` 접근이 전혀 필요 없다(스케치 `{4}` 불필요), `userPassword` 최소 수준은 `=w`(`=a`·`=z` 단독은 50); ppolicy 내부 갱신(`pwdChangedTime`)은 `W_cred`의 `none`과 무관; `M`은 `pwdChangedTime`·`creatorsName`·`employeeType`을 읽는다(R-8 닫힘); `W_data`는 relax로도 `creatorsName`을 위조하지 못한다(50).

- 2026-10-13 Revision 5 (#394 항목 1·3·4만, 유지보수자 승인; 실측은 EVIDENCE.md §2d). 항목 2·5·6은 열린 채로 남는다.
  - **D394-1** `write-lock.ldif` `{3}`을 `write` → **`add`**. slapd는 Delete와 Replace 모두에 삭제 권한을 검사하므로 `W_lock`은 표지를 추가만 하고 지우거나 덮어쓸 수 없다(삭제·값 삭제·빈 Replace·값 Replace 모두 50, Add 0, 같은 값 재Add 20). 머신 `lockUser`는 Replace 대신 Add를 보내고 20을 성공(멱등)으로, 19(ppolicy 타임스탬프 잠금 위의 Add, 단일 값 속성)를 409로 돌려준다. 사람 경로의 `Lock`(Replace)은 그대로다. Revision 4 F-1 (a)의 "머신 `lockUser`가 ppolicy 시각 잠금을 표지로 덮어씀"은 이제 머신 경로에서 일어나지 않는다(타임스탬프 유지, 409). `=a`도 같은 거부를 보였으나 `W_lock`의 그 속성 읽기를 잃어 `add`를 택했다.
  - **D394-3** `write-data.ldif`의 `description`을 닫힌 목록에서 빼 `{5}to dn.subtree=@WRITE_DN@ filter=(objectClass=groupOfNames) attrs=description`로 분리했다(조각 8 → 9 규칙, `W_lock` 시작 인덱스 +1). 사용자 항목의 `description` 쓰기는 ACL만으로 50이다. 출하 상태(`olcAddContentAcl` FALSE)의 Add는 속성 ACL을 보지 않으므로 생성 시점의 `description`은 여전히 앱의 닫힌 본문만 막는다(#386과 같은 한계).
  - **D394-4** `MACHINE_WRITE_GROUP_SEED_DN`은 `MACHINE_WRITE_DATA_BIND_DN`과 같은 컨테이너(`@SYSTEM_DN@`)의 **직계 자식**이어야 기동한다(예약 placeholder 형태). 바인드 가능 여부(`userPassword` 존재)는 설정 단계에서 알 수 없고 출하 신원 누구도 `userPassword`를 읽을 수 없으므로 검사하지 않는다 — 운영자 의무로 남는 잔여 위험.
  - 기존 배포: 이전 조각을 적용한 노드는 `docs/machine-write-account.md` 7절로 롤백 후 다시 적용해야 한다. 점검 스크립트는 이전 조각을 불일치로 보고한다(규칙 수·`add`·`filter=`를 구조 비교).

- 2026-10-12 Revision 4 (T-015 라이브 드릴 실측, EVIDENCE.md §2b; 결정 D379-3/5/6/7/17은 **바뀌지 않음**, 근거 문장만 정정).
  - **F-1** `pwdLockoutDuration=0` ppolicy 잠금은 출하 이미지에서 관리 잠금 표지(`000001010000Z`)와 **같은 값이 아니라** 잠금 시각 타임스탬프를 남긴다(`20261012141315Z`, 영구 잠금은 맞음). 따라서 D379-7 근거 (b) "표지와 같은 형태라 구별 불가"와 P22(b)는 이 빌드에서 사실이 아니다. 해제를 사람 전용으로 두는 Q4 결정은 유지자 결정이며 근거 (a)(`lockUser`→해제 왕복이 ppolicy 시각 잠금을 표지로 덮어쓴 뒤 해제하는 우회, 드릴로 덮어씀 확인)와 (c)(메모리 한도가 재시작·replica로 초기화)로 유지된다. 값으로 구별 가능하다는 사실은 D379-7 탈출구(별도 승인 설계)에서 다시 평가할 입력이다.
  - **F-2** 특권 그룹의 **중첩** 그룹 멤버(`lk4` ∈ `subadmins` ∈ `admins`)에 대한 `lockUser`는 204로 잠긴다. REQ-007/D379-17에서 수용한 잔여 위험을 실측으로 확인한 것이며 직접 멤버만 거부된다. 드릴이 이 거동을 고정해 변경을 알린다.
  - **F-3** 출하 `write-lock.ldif`에는 특권 그룹 `filter=`가 없다. `W_lock` 자격 증명을 직접 쓰면 특권 멤버의 `pwdAccountLockedTime`을 쓸 수 있으므로(드릴이 rc 0을 고정), `W_lock` 쓰기에 대한 방어는 `lockUser`의 애플리케이션 검사뿐이다. ACL 백스톱(E-07)은 이 fixture에는 없다.
  - 보조 사실: 시작 시 검증이 시드를 포함한 쓰기 상한과 허용 목록의 특권 그룹을 거부하므로(`must not overlap a protected identity`, `must not list a privileged group`) 요청 시 보호 집합 가드는 라이브 드릴로 단독 격리할 수 없고, 설정을 주입하는 단위 시험(`TestGroupPipeline_SeedIsProtectedWithoutTheCeiling`, `TestGroupPipeline_TargetRestrictions`)과 변이로 증명한다. 대상 타입 가드는 허용 목록에 사용자 DN을 올린 드릴 구성으로 단독 증명한다.

- 2026-10-12 Revision 3 (유지보수자 결정). v2b 수용, v2c는 `Proposed` 유지.
  - Q2: 옵션 B 고정 placeholder seed DN(`MACHINE_WRITE_GROUP_SEED_DN`) 수용(D379-3). Q3: 생성 그룹의 허용 목록 자동 편입 없음(D379-4). Q4: 잠금 해제는 사람 전용 유지(D379-7). Q7: 머신 `patchGroup`의 `cn` 변경 거부(D379-5).
  - Q1·Q5·Q6 및 v2c 전부(Q8–Q13 포함)는 보류. 전용 security-reviewer 라운드는 아직 없음(TASKS T-005 참조). 관련 후속 이슈 #390.

- 2026-10-11 Revision 1 (Codex 보안 검토, 커밋 `d96858f` 대상). 5건 모두 반영, Status는 `Proposed` 유지.
  - **P1-a** 비밀번호 없는 기존 계정(SSO·외부 인증)이 "초기 비밀번호" 대상이 되던 문제 → 대기 표지 + `creatorsName=W_data` + client 태그(D379-10, REQ-010/018, AC-007b, E-16). 확인/가정 구분은 ACL 스케치 아래 "검증 상태".
  - **P1-b** accesslog `M` 전체 읽기(`f/accesslog-optin.ldif`)와 auditlog stdout(`image/entrypoint.sh:1176-1199`)의 해시 노출, 평문 스캔의 한계 → D379-14(auditlog 금지·accesslog 상호 배제 또는 값 수준 거부), REQ-012·AC-009 해시 패턴 스캔, E-12/E-13 확장.
  - **P1-c** 문서·점검 스크립트에만 의존하던 활성화 → 실행 시 기동 거부(D379-15, REQ-014, AC-010b), Q8 권고 변경.
  - **P2-a** client+UUID 해제 한도가 client 수만큼 독립 예산 → 관리 잠금만 해제(디렉터리 상태 기반), 대상 전역 보조 한도와 재시작 한계 명시(D379-7, REQ-008, AC-005b, E-15/E-19), Q4 권고 변경.
  - **P2-b** 순차 재설정만 시험 → 서로 다른 client·키의 동시 Password Modify에서 정확히 한 건 성공 실험(E-17, AC-010c, REQ-013)을 경계 주장의 선행 조건으로.
  - 권고가 바뀐 질문: Q4, Q5, Q8. 새 질문: Q11, Q12.
- 2026-10-11 Revision 2 (Codex 2차 보안 검토, 커밋 `7dc18ba` 대상). Status `Proposed` 유지.
  - **P1-1** 해제 우회(`Lock`이 ppolicy 잠금을 표지로 덮어씀 `l/users.go:392-401`, duration 0 잠금이 같은 형태 `l/users.go:382-390`, 왕복·재시작) → v2b는 잠금만, 해제는 사람 전용(D379-7, REQ-006/008, AC-005/005b), 지속 표지 설계는 별도 승인 탈출구로.
  - **P1-2** 카나리 표본은 범위 증명이 아님, 10분 창 → 설정 읽기 전용 신원으로 `olcAccess`·`olcPPolicyDefault` 원문 대조(D379-16), 대상별 정책·앱 게이트를 요청 직전 검사, 주기 60초, 남는 TOCTOU 창을 R-4로 명시(D379-15, REQ-014, AC-010b).
  - **P1-3** accesslog base 검색은 비노출 증거가 아님 → 자식 항목 실제 읽기(검사 6), 공존 모드 사후 확인(검사 7), 자식 노출 시나리오(AC-010b), `M` 외 감사 독자는 R-5.
  - **P2 모순 3건**: AC-007b (d)는 앱 경로만 실패·직접 `W_cred`는 성공이 기대값으로 정리; AC-010c는 같은 client 다른 키 + 직접 병렬, 다른 client는 태그 검사로 403; `W_cred`의 유일한 비-`userPassword` 쓰기는 표지 값 삭제로 REQ-010·AC-007 통일.
  - 실측 없이는 닫을 수 없는 항목을 "Ship-gating open risks"(R-1–R-8)로 분리. 권고가 바뀐 질문: Q4(해제 미개방), Q12(자식 항목 검사). 새 질문: Q13.
