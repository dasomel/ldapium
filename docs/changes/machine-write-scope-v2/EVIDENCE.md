# Evidence: 머신 쓰기 v2b·v2c (설계 입력)

설계: [CHANGE.md](CHANGE.md) · 작업: [TASKS.md](TASKS.md)

- 수집일: 2026-10-11, main `049fcc3`. §1은 **소스 읽기**로 확인한 사실이고(T-001), §2는 **아직 실행하지 않은** 라이브 계획이다(T-002). 이 문서는 구현 증거가 아니며 코드·ACL·이미지를 바꾸지 않았다.
- 비밀 규칙: 라이브 실측에서 비밀번호는 실행마다 새로 만든 일회용 무작위 센티널을 쓰고, 여기에는 값이 아니라 "센티널 N건"과 해시 접두 여부만 기록한다. `userPassword` 값·해시는 출력에서 `<redacted>`로 바꿔 남긴다.

## 1. 소스 읽기로 확인한 사실 (T-001)

경로 접두는 CHANGE.md 머리말과 같다.

| 사실 | 위치 |
|---|---|
| 열린 머신 쓰기 5개, 거부 목록의 미개방 쓰기 8개, D-id 축소 게이트 | `h/machine_write_scopes.go:15-21`, `h/machine_contract_test.go:51-54,65-71,533-558` |
| 카탈로그는 5행, 구획은 `data`/`lock`, 대상 단언 클래스·`If-Match` 필요 여부를 행마다 가짐 | `h/machine_write_ops.go:23-47` |
| 구획→신원: `data`는 `W_data`, `lock`은 `MACHINE_WRITE_LOCK_ENABLED`일 때만 `W_lock`, 그 밖은 없음(폴백 없음) | `h/machine_write_ops.go:85-97` |
| 열린 scope 목록과 전체 어휘, 상한에 미개방 scope는 기동 실패 | `c/machine.go:85-113` |
| 잠금 신원 설정과 `W_data`≠`W_lock` 검사, 비밀번호 구획 설정 없음 | `c/machine_write.go:32-80` |
| 보호 집합: `M`, `W_data`, (`W_lock`), rootdn, `cn=replicator`, `cn=admin`, 백업·프로파일 관리자, 서비스 계정, 특권 그룹 | `c/machine_write_scope.go:226-248` |
| `CreateGroup`의 seed `member`는 바인드 DN | `l/groups.go:61-95` |
| `PatchGroup`은 `cn`·`description` Replace, `RemoveMember`의 마지막 멤버 제거는 slapd 거부 | `l/groups.go:125-156,198-219` |
| 머신 표지가 있으면 `(&(entryCSN=…)(objectClass=…))` assertion 강제 | `l/machine_write_assertion.go:30-47` |
| `Lock`=고정 값 Replace, `Unlock`=값 없는 Replace, 둘 다 `inetOrgPerson` 단언 사용 | `l/users.go:330-427` |
| `SetPassword`=RFC 3062, control 없음, 서버 생성 값 반환 가능 | `l/users.go:285-304`, `l/create_compensation.go:40-47` |
| 비밀번호 포함 생성은 Add→Password Modify, 보상은 `creatorsName == 바인드 DN` | `l/users.go:84-140`, `l/create_compensation.go:12-53` |
| 사람 비밀번호 한도 키 = `sess.ID + "\x00" + DN` | `h/user_handlers.go:169-182` |
| 사람 `setPassword`는 `If-Match`가 오면 400 | `h/user_handlers.go:136-138`, `h/conditional.go:49-54` |
| 멱등 비밀번호 모드: 서버 생성+키 422, 성공 저장 본문 `{}`; 머신 파이프라인은 모드 `false`로 시작 | `h/idempotency.go:99-103,141-144,339-341`, `h/machine_write_pipeline.go:382` |
| 멱등 기록 내용: subject‖key 해시, HMAC 지문, 결과 ≤4 KiB, 본문·비밀번호 없음 | `h/idempotency.go:33-36` |
| 머신 닫힌 본문 집합에 `password`·`oldPassword` 없음 | `h/machine_write_attributes.go:13-59` |
| 머신 생성 DN 형태는 사용자(`uid`+`UserCreateBase`)만 | `h/machine_write_pipeline.go:286-296` |
| `M` 사전 읽기는 타입·보호 항목만 확인, `memberOf`는 보지 않음 | `l/machine_write_identity.go:79-117` |
| `W_data` ACL 쓰기 목록에 `description` 없음, `pwdAccountLockedTime`·`memberOf`는 `none` | `f/write-data.ldif:49-60` |
| `W_lock` ACL: `pwdAccountLockedTime`만 write, 나머지 상한 안 read | `f/write-lock.ldif:30-47` |
| `M` ACL: 비밀 속성만 `none`, 허용 base는 read(`memberOf` 포함) | `f/main-database.ldif` |
| 기본 비밀번호 정책 값 | `image/entrypoint.sh:1341-1376` |
| accesslog 기본 ops는 운영자 설정 `LDAP_ACCESSLOG_OPS`(기본 `reads bind`), 실패도 기록 | `image/entrypoint.sh:1267-1277` |
| 머신 감사 읽기는 `reqMod`에서 속성 이름만 추출 | `l/audit.go:25-30,257` |
| memberof·refint overlay 구성 | `image/ldifs/01-cn-config.ldif:108-121` |
| auditlog overlay: 기본 꺼짐, 켜면 성공한 모든 쓰기를 LDIF로 `LDAP_AUDIT_FILE`(기본 `/dev/stdout`)에, 속성 제외 설정 없음 | `image/entrypoint.sh:504-505,1176-1199`, 차트 `charts/ldapium/values.yaml:395-408` |
| `M`의 accesslog 옵트인은 accesslog 전체 read(`to * by M read`) | `f/accesslog-optin.ldif:1-9` |
| 관리 잠금 표지 `000001010000Z`는 사람 `lockUser`와 `pwdLockoutDuration=0` ppolicy 잠금이 같은 형태, `Lock`은 Replace라 ppolicy 시각 잠금을 덮어씀; `M` 비밀 목록에 `pwdAccountLockedTime` 없음 | `l/users.go:382-427`, `f/main-database.ldif` |
| `creatorsName`을 "이 요청이 만든 항목" 증거로 쓰는 기존 보상 흐름 | `l/create_compensation.go:17-26` |
| `employeeType`은 머신 닫힌 본문·사람 사용자 생성/수정 경로 어디에도 없음 | `h/machine_write_attributes.go:22-25`, `l/users.go:84-140,204-225` |
| accesslog DB 기본 ACL: `cn=admin,cn=accesslog`만 read, 나머지 none; 사람 감사 화면은 세션 바인드로 읽음 | `image/entrypoint.sh:1245`, `l/audit_client.go:17-150` |
| UI는 현재 `cn=config`를 읽는 신원이 없다(설정 읽기는 운영 점검 스크립트만) | `scripts/test/test-check-machine-write-acl-live.sh`, `c/machine_write*.go` |

## 2. 라이브 실측 계획 (T-002, 미실행)

공통: 새 컨테이너(`ldapium:e2e`), `LDAP_PASSWORD_POLICY_ENABLED=true`, 부모 가이드([docs/machine-write-account.md](../../machine-write-account.md))로 `M`·`W_data`·`W_lock` 설치, `W_cred`는 CHANGE.md 스케치를 스크래치 LDIF로 적용(저장소 밖). 명령은 `docker exec -i`로 LDIF를 넘긴다(AGENTS.md). 각 항목은 실패도 기록한다.

| ID | 질문 | 방법 | 판정 → 영향 |
|---|---|---|---|
| E-01 | `W_data`로 `groupOfNames` Add(seed = placeholder DN)가 현재 ACL로 되는가 | 직접 `ldapadd` | 성공해야 함 → D379-3 |
| E-02 | seed가 placeholder일 때 `W_data` 항목의 `memberOf`가 변하지 않는가, placeholder 항목에 `memberOf`가 붙는가 | Add 전후 `ldapsearch memberOf` | 기록 → D379-3 운영 가이드 |
| E-03 | 사람 경로(`c.dn` seed)의 현재 거동 기준선 | 관리자 bind로 같은 Add | 기준선 |
| E-04 | placeholder DN이 **존재하지 않을 때** Add 결과(`olcMemberOfDangling` 기본값) | 없는 DN으로 Add | 성공/거부 기록 → seed 항목 생성이 필수인지 |
| E-05 | 그룹 `cn`(RDN) Replace의 slapd 결과 | `ldapmodify replace: cn` | `notAllowedOnRDN`(67) 예상 → D379-5 근거 |
| E-06 | `W_lock` 직접 쓰기: `pwdAccountLockedTime` 외·Add·Delete·`userPassword` 거부 | 직접 `ldapmodify`/`ldapadd`/`ldapdelete` | 전부 50 → AC-006 |
| E-07 | ACL `filter=(!(memberOf=<특권 그룹>))`가 `W_lock`/`W_cred` 쓰기를 특권 멤버에 대해 막는가 | 특권 그룹 멤버/비멤버 대상 직접 쓰기 | 멤버 거부·비멤버 허용이어야 백스톱 → D379-8 |
| E-08 | ACL `filter=(!(userPassword=*))`가 `W_cred`(userPassword 읽기 권한 없음)에 대해 "비밀번호 없는 항목만"으로 평가되는가 | 비밀번호 있음/없음 대상(둘 다 표지 있음)에 `ldappasswd -D W_cred -s <센티널> <dn>` | 없음만 성공해야 함 → D379-10, 불성립 시 Q5 재결정 |
| E-09 | Password Modify가 `userPassword` `=w` 외에 요구하는 최소 접근(`entry` 등), ppolicy 내부 갱신(`pwdChangedTime`·`pwdHistory`)이 `W_cred` ACL과 무관한가 | 수준을 줄여 가며 시도 | 최소 ACL 확정 → `f/write-cred.ldif` |
| E-10 | `W_cred`(대상 ≠ 요청자) 설정에 `pwdMinLength`·`pwdCheckQuality`·`pwdInHistory`가 적용되는가 | 짧은 값·이력 값 설정 시도 | 거부돼야 함 → D379-13, 미적용이면 v2c 중단 |
| E-11 | 초기 비밀번호 설정 후 같은 값 재설정(재시작 후 재실행 모사)의 결과 | 같은 센티널로 **순차** 두 번 | ACL 거부(E-08 성립 시) 기록 → 실패 모드 표. 동시성은 E-17이 별도로 다룬다(순차 결과만으로 경계를 주장하지 않음) |
| E-12 | Password Modify가 (a) accesslog(`LDAP_ACCESSLOG_OPS="writes reads bind"`)의 `reqMod`/`reqOld`, (b) auditlog(`LDAP_AUDIT_ENABLED=true`, stdout = `docker logs`)에 해시를 남기는가; (c) accesslog DB 첫 규칙 `to attrs=reqMod,reqOld val.regex="^userPassword:" by * none`이 `M`(옵트인 `f/accesslog-optin.ldif` 적용 상태)에게 그 값만 숨기고 다른 `reqMod` 값은 남기는가 | 각 구성으로 기동 후 관리자·`M` 각각 검색, `docker logs` 수집, 해시 패턴 grep(값은 `<redacted>`) | (a)(b) 존재 여부 → D379-14; (c) 성립 시 Q12 공존 선택지 |
| E-13 | 평문·해시 스캔(T-024): 응답 본문·헤더, UI 감사 줄, UI·slapd·Keycloak `docker logs`(auditlog 구성 포함), accesslog `reqMod`/`reqOld`(관리자·`M` 각각) | 모든 성공·실패·재생 경로 실행 후 `grep -c <센티널>`과 해시 정규식 `\{(SSHA(256\|384\|512)?\|ARGON2\|CRYPT\|PBKDF2[^}]*\|SHA(256\|384\|512)?\|S?MD5)\}`, LDIF base64 형식 `userPassword::`와 base64 접두(`e1NTSEF9`=`{SSHA}`, `e0FSR09OMn0`=`{ARGON2}`, `e0NSWVBUfQ`=`{CRYPT}`) | 0건 → AC-009. 해시가 나온 구성은 D379-14/T-028이 거부하는 구성이어야 함 |
| E-14 | `W_cred` 회전 후 다음 요청 503·진행 중 요청 상한 | 부모 `test-machine-write-drill.py` 방식 | 실측값 → AC-011 |
| E-15 | 해제 미개방 확인: ppolicy 시각 잠금·duration 0 잠금·`lockUser` 직후·UI 재시작 후·다른 client 각각에서 머신 해제 요청 | 실제 bind 실패 반복, duration 0 정책 대상, 머신 잠금 후 해제 | 전부 403·bind 0·`pwdAccountLockedTime` 불변 → AC-005b |
| E-16 | ACL `filter=`의 `(creatorsName=<W_data DN>)`와 `(employeeType=ldapium-credential-pending:*)`가 `W_cred` 권한과 무관하게 평가되는가; `val.regex`가 `W_cred` `=z`를 표지 값으로 한정하는가; `W_data` `add` 규칙으로 표지 Add가 되는가 | 관리자가 만든 비밀번호 없는 계정(표지 수동 부착 포함)·`W_data`가 만든 표지 없는 계정·표지 있는 계정에 `W_cred` Password Modify; `W_cred`로 다른 `employeeType` 값 삭제 시도 | 앞의 둘 거부, 셋째만 성공, 다른 값 삭제 거부 → D379-10, AC-007b |
| E-17 | 같은 대기 계정에 서로 다른 신원 경로·서로 다른 값의 Password Modify를 **동시에** 보낼 때 정확히 하나만 성공하는가 | `W_cred`로 병렬 N=10(서로 다른 센티널), 그리고 UI 경유로 서로 다른 client·`Idempotency-Key` 2개 동시; 끝에 각 센티널로 bind 시도 | 성공 1·나머지 50, 성공 값으로만 bind → REQ-013, AC-010c. 둘 이상 성공하면 초기 전용 경계 주장 철회·Q5 재결정 |
| E-18 | 전제 검사 판정: 각 오구성(정책 비활성, filter 없음, 표지 조건 없음, 카나리 미잠금·누락, 둘째 subtree만 느슨한 규칙, `M` accesslog 자식 읽기, 특권 그룹 비어 있음)에서 CHANGE.md 검사 1–8이 기대 코드와 다른 결과를 내는가, 정상 구성에서 디렉터리를 바꾸지 않는가(카나리 `entryCSN` 전후 동일) | 프로브와 같은 LDAP 연산을 직접 실행 | 판정 표 확정 → D379-15, AC-010b |
| E-19 | (Revision 2에서 목적 변경) `pwdLockoutDuration=0` ppolicy 잠금이 남기는 값과 사람·머신 `Lock` 표지가 같은지, 머신 `Lock`이 ppolicy 시각 잠금을 덮어쓰는지 | duration 0 정책으로 잠근 뒤 값 읽기, 시각 잠금 계정에 `Lock` | 같음/덮어씀이면 D379-7(해제 사람 전용)의 근거 확정 |
| E-20 | `W_cred`(대상≠요청자) 초기 설정 시 ppolicy가 `pwdChangedTime`을 남기고 `M`이 그 값을 읽을 수 있는가 | 설정 전후 `M`으로 `pwdChangedTime` 검색 | 남고 읽힘 → 검사 4 근거(R-8) |
| E-21 | 설정 읽기 신원 ACL(`cn=config`의 메인 DB `olcAccess`·ppolicy `olcPPolicyDefault`만 read)이 그 두 속성만 노출하는가; slapd가 돌려주는 `olcAccess` 값(인덱스 접두 `{n}`, 줄바꿈·공백 정규화)이 fixture 치환 원문과 안정적으로 대조되는가; 앞 규칙 삽입·묶음 변형·둘째 subtree 느슨한 규칙을 대조가 모두 잡는가 | 신원으로 `cn=config` 검색(다른 속성·항목 거부 확인), 변형 구성 6종 | 두 속성만, 대조 결정적 → D379-16(R-2) |
| E-22 | 검사→쓰기 창: 요청 직전 검사 직후 느슨한 규칙을 삽입했을 때 그 요청과 다음 요청의 결과, 주기 검사가 60초 안에 닫는지 | 검사 직후 `ldapmodify`로 규칙 삽입(타이밍 훅 있는 시험 빌드) | 그 한 요청만 옛 전제, 다음 요청 503 → R-4 창 실측 |
| E-23 | accesslog **자식 항목** 노출: (a) base에는 `search`만, 자식에는 `read`를 준 구성에서 `M`이 base 검색으로는 0건이지만 subtree 검색으로 `reqMod`/`reqOld`를 읽는지, (b) 실패한 Password Modify(카나리 프로브의 19/50)도 자식 항목을 남기는지, (c) 운영자가 추가한 감사 독자 DN으로 같은 읽기 | `writes reads bind` 구성, 각 신원으로 base·subtree 검색, 해시 패턴 grep(값 `<redacted>`) | (a)가 읽히면 검사 6이 거부해야 함; (b)(c) 결과 → R-5 |

## 3. Not verified

§2 전부(E-01–E-23). 이 패키지 작성 시점에는 컨테이너를 실행하지 않았다. Revision 1에서 E-08·E-11·E-12·E-13·E-15를 넓히고 E-16–E-19를 추가했고, Revision 2에서 E-15·E-19의 목적을 해제 미개방 확인으로 바꾸고 E-20–E-23을 추가했다. 이 실험들이 닫는 출하 차단 위험은 CHANGE.md "Ship-gating open risks"(R-1–R-8).
