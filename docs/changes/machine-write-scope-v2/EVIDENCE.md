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

## 2b. T-015 v2b live drill (2026-10-12, branch `feat/379-v2b-drill-open`)

`scripts/test/test-machine-write-v2b-live.py`, wired into `.github/workflows/machine-write-e2e.yml` (no path filter; the
job `machine write (real Keycloak)` that `release.yml` requires keeps its name). It exercises the four v2b operations
against real slapd (`ldapium:v2b`, built from `image/` of this tree) and the production UI image (`ldapium-ui:v2b`, built
from `ui/` of this tree), Keycloak `quay.io/keycloak/keycloak:26.7.4` service-account tokens, a directory prepared with the
documented `M`, `W_data`, `W_lock` fragments, and fresh containers per run. Local host: macOS, Docker Desktop 29.8.2 (not
Colima). **The drill can only run end to end on the tree that contains BOTH the T-015 drill commit and the T-014 opening
commit**, because T-014 is what makes the operations reachable (before it every one of them is 403 `scope_denied`). That is
intended: T-014's gate "T-015 green" is satisfied by running the drill on the final tree, which is what was done here.

Runs, failures included (command `LDAPIUM_IMAGE=ldapium:v2b LDAPIUM_UI_IMAGE=ldapium-ui:v2b python3 scripts/test/test-machine-write-v2b-live.py`):

| Run | Result | Cause |
|---|---|---|
| 1 | FAIL after 2 checks | drill bug: expected the fragment `directory.users.unlock` in the start-up error; the real message is `MACHINE_ALLOWED_CLIENTS names a write scope that no operation uses yet (machine-write-scope T-026/T-030)` |
| 2 | FAIL after 96 checks | **premise failure, see finding F-1**: the `pwdLockoutDuration=0` lock does not hold the machine marker value |
| 3 | PASS, **113 checks** | `All machine write v2b live checks passed: 113 checks in 51s.` (final tree; ten containers, 348297 bytes of logs scanned) |
| mutation | FAIL after 66 checks | UI image built with `CheckNotPrivileged` returning `nil` at once: `AssertionError: [D] "AC-005 lockUser on a DIRECT member of the privileged group" -> 403 (got 204 )` |

Regression on the same images: `test-machine-write-keycloak-live.py` 84 checks passed, `test-machine-write-drill.py` 61 checks
passed (unchanged scripts).

What the 113 checks established (AC ids as in CHANGE.md; real values from run 3):

- **AC-002 seed**: `createGroup` -> 201; the new group's `member` is exactly `uid=group-seed,ou=system,dc=example,dc=org`; the
  `W_data` entry's `memberOf` is `[]` before and after; the group is bound as `W_data` only (slapd accesslog). The placeholder
  entry's `memberOf` went from `[]` to the new group (the seed entry collects it, as designed). The human cookie `createGroup`
  still seeds with the bind DN (`['cn=admin,dc=example,dc=org']`). The seed as `addGroupMember`/`removeGroupMember` member, as
  `patchUser`/`deleteUser`/`lockUser` target, and as `deleteGroup` target: 403, zero `W_data`/`W_lock` binds.
- **createGroup bodies**: `cn` with a comma, a `member` field, an `objectClass` field, empty `cn` -> 400; client without the v2b
  scopes, and a token without the scope while the ceiling has it -> 403; duplicate `cn` -> 409; replay of the same key -> the stored
  201 with `Idempotent-Replayed: true` and no extra bind; other body, same key -> 422; no `Idempotency-Key` -> 428.
- **AC-003 targets**: just-created group, `g02`, ceiling root (also `OU=Groups , DC=EXAMPLE,DC=ORG`), an OID-typed spelling
  `2.5.4.3=g01,...`, a user DN, `W_data`, the seed, and the privileged group: 403 for `patchGroup`/`deleteGroup`
  (privileged: audit outcome `denied_protected`), zero binds, ETags of the privileged group, `g02`, root, `g01` unchanged.
  After the operator lists the created group's DN (a second replica with the DN in `MACHINE_WRITE_GROUPS`), `patchGroup` and
  `deleteGroup` on it succeed (204/204).
- **AC-004**: `description` set and `null` -> 204, `cn` unchanged; `cn`, `member`, unknown field -> 400; no `If-Match` -> 428;
  stale -> 412 `revision_conflict`, nothing written. `deleteGroup` on a listed group -> 204 and refint cleaned the member:
  `u02.memberOf` `['cn=gdel,ou=groups,dc=example,dc=org'] -> []` (D379-6, irreversible by design).
- **AC-005 lock**: `lockUser` -> 204, `pwdAccountLockedTime = 000001010000Z`, bound as `W_lock` not `W_data`, the locked account's
  correct password cannot bind (`ldapwhoami` fails); replay with the same key is the stored answer without another `W_lock` bind;
  another client with the same key is independent. Refused with zero `W_data`/`W_lock` binds: group DN (target-type assertion),
  `W_data`, `W_lock`, `M`, administrator, ceiling root, a **direct** member of the privileged group (audit `denied_protected`;
  the member can still bind), no `If-Match` (428), no key (428), weak `If-Match` (400), extra body field (400), no scope (403);
  stale `If-Match` -> 412. A ppolicy timestamp lock turned into the indefinite marker by `lockUser`
  (`['20261012141211Z'] -> ['000001010000Z']`: stricter, as AC-005 records).
- **REQ-007 / D379-17 fail closed**: with an ACL hiding the privileged group's `member` from `M`, a NON-member target is refused
  (403, no bind); a privileged group that does not exist -> 503 `unavailable` (fail closed, no bind, target not locked).
- **Nested group (accepted residual risk, recorded as the actual result)**: `uid=lk4` is a member of `cn=subadmins`, which is a member of the
  privileged `cn=admins`. `lk4.memberOf = ['cn=subadmins,...']`, `admins.member = [lk3, cn=subadmins]`. `lockUser` on `lk4` -> **204 and
  locked**. Only direct members are refused. This is the risk accepted on 2026-10-12 (REQ-007), not a regression; the drill pins the
  observed behaviour so a change in it is noticed.
- **AC-006**: `W_lock` direct `ldapmodify`/`ldapadd`/`ldapdelete` of `mail`, `userPassword`, `objectClass`, an entry Add, a group
  `member`, a group `description`, an entry Delete: all `Insufficient access`; `W_lock` writes `pwdAccountLockedTime`. `W_data` cannot write
  `pwdAccountLockedTime` or `userPassword`, can write a group `description`; replacing a group `cn` directly gives `Naming violation (64)`
  (E-05) and the group is not renamed. `W_lock` direct write of `pwdAccountLockedTime` on a PRIVILEGED member succeeded (rc 0): the
  fixture has no `memberOf` filter, so the application check is the only guard (E-07 observed; not an ACL backstop).
- **AC-005b unlock bypass**: with a token carrying every scope including `directory.users.unlock` in the Keycloak token (never in a
  ceiling): (a) a real ppolicy brute-force lock (timestamp), (b) a `pwdLockoutDuration=0` policy lock, (c) right after the same
  client's `lockUser`, (e) a different client on the machine-locked account, and (d) all of these again after a real `docker restart`
  of slapd and the UI: `POST /api/users/unlock` -> **403 `scope_denied`, `W_data`/`W_lock`/`M` bind counts identical before and
  after, `pwdAccountLockedTime` identical before and after** (example: `(13, 15, 55) -> (13, 15, 55)`). The directory state (machine
  marker, ppolicy timestamp, duration-0 lock) was identical across the restart. `PUT /api/users` is still 403. The audit log has no
  `unlockUser` operation line (an unregistered route has no operation id).
- **Start-up refusals**: `directory.groups.create` in a ceiling without `MACHINE_WRITE_GROUP_SEED_DN`; `directory.users.unlock` in a ceiling;
  lock scope with `MACHINE_WRITE_LOCK_ENABLED=false`; lock scope with empty `MACHINE_WRITE_PRIVILEGED_GROUPS`: the UI exits with the
  message and never serves.
- **Audit**: one `machine_access` line each for `lockUser` (compartment `lock`, `bind_dn` = `W_lock`), `createGroup`, `patchGroup`,
  `deleteGroup` (compartment `data`, `bind_dn` = `W_data`, `write_scope`, `target_kind`), no plaintext DN.
- **Secrets**: sentinel scan of all ten container logs (tokens and their segments, client secrets, bind and account passwords, the
  description sentinel, every `Idempotency-Key`): 0 hits.

### Findings that contradict or refine the design text (escalated, not decided)

- **F-1 (contradicts CHANGE.md P22(b) / D379-7 rationale (b), AC-005b (b))**: the design says a `pwdLockoutDuration=0` ppolicy lock has "the
  same form as the marker" `000001010000Z`. On this image (OpenLDAP with ppolicy as shipped) it does not: after three wrong binds under a
  policy with `pwdLockoutDuration: 0` the entry holds a TIMESTAMP (`20261012141315Z`, the lock time), exactly like a normal ppolicy lock, and
  stays locked (the correct password cannot bind). So the marker and a duration-0 lock ARE distinguishable by value here. This does not make the
  decision to keep unlock human-only wrong (the round trip `lockUser` -> unlock over a ppolicy lock still replaces a timestamp lock by the marker, observed above,
  and the in-memory limits do not survive a restart), but the stated reason (b) is not true on this build. CHANGE.md wording needs a maintainer decision;
  nothing was edited there. The drill's check for (b) therefore asserts "permanent lock, bind fails" and records the value shape instead of asserting equality.
- **F-2 (REQ-007 accepted risk, now measured)**: nested-group privileged membership is not recognised; `lockUser` on such a user returns 204 and locks it.
- **F-3 (E-07)**: the shipped `write-lock.ldif` has no privileged-group filter; a `W_lock` credential can lock a privileged member directly.

### Mutations (shown failing, then restored)

| Mutation | Result |
|---|---|
| `unlockUser` (POST `/api/users/unlock`) and `updateGroup` (PUT) added to `machineWriteOps`, `directory.users.unlock` added to `MachineWriteOpenScopes` | 15 tests fail: `TestMachineWriteLockCeilingNeedsW_lock`, `TestMachineWriteScopesInCeiling`, `TestOpenAPIMachineBearerEqualsCodeAllowlist`, `TestOpenAPIDeniedOperationsNeverCarryMachineBearer`, `TestOpenAPINoNonGetCarriesMachineBearer`, `TestMachineWriteOpenScopesEqualTheTable`, `TestMachineDenyListShrinkNeedsDID`, `TestMachine_EveryProtectedOperationExercised`, `TestMachine_EveryProtectedOperationExercisedWritesOn`, `TestGroupPipeline_ScopeAndProductionTable`, `TestMachineWriteSwitchRefusesStartupWithoutAPrerequisite`, `TestLockPipeline_ProductionOpensLockNotUnlock`, `TestWritePipeline_ProductionTableHasExactlyTheNineOperations`, `TestMachineWriteSettingsOffKeepV1Byte`, `TestMachineWriteRuntimeEnabledOpensOnlyTheNine` |
| `CheckNotPrivileged` returns `nil` immediately | unit: `TestCheckNotPrivilegedRejectsBeforeDial` fails; drill (mutated UI image): fails at the direct-privileged-member check (204 instead of 403), see run table |


### 2c. Review follow-up (Codex security review of 25bdee8 + dc445b3)

- The drill now has **121 checks** (run: `All machine write v2b live checks passed: 121 checks in 58s.`). New: start-up refusals for a seed inside a
  write ceiling (`must not overlap a protected identity`) and a privileged group on the allow-list (`must not list a privileged group`); the target-type
  guard ALONE (an allow-listed USER DN as `patchGroup`/`deleteGroup` target -> 403 `target is not permitted for machine writes`, its own message, no W bind) and
  `lockUser` on a group DN with that same message; ETags of the privileged group, `g02` and the ceiling root compared before and after (the earlier claim now matches
  the assertion); the duration-0 policy entry (`pwdLockoutDuration: 0`, `pwdMaxFailure: 3`), its assignment to `lk7` and the timestamp format of the lock are asserted;
  F-3 is a check, not a note.
- Why the seed and the privileged group cannot be isolated live: start-up validation rejects the layouts that would isolate them (above), which is a stronger layer in
  front of the request-time guard. The request-time guards are therefore pinned by unit tests that inject the config, and shown failing by mutation:
  - seed removed from `machineWriteIdentityDNs` -> `TestGroupPipeline_SeedIsProtectedWithoutTheCeiling` fails (`PATCH /api/groups ... 204`, `POST /api/users/lock ... 503`, ...).
  - privileged groups removed from `machineWriteProtectedDNs` -> `TestGroupPipeline_TargetRestrictions` fails (`PATCH privileged group ...: 204`, `binds=6`).
  - type check removed from `WriteIdentityReader.Check` (UI image rebuilt, drill re-run): the drill fails at check 50:
    `AssertionError: [C] target-type guard alone: patchGroup on an allow-listed USER DN -> 403 "target is not permitted", user untouched (412 ...)`. (The LDAP
    entryCSN/objectClass assertion is a second layer: it answered 412 and the user stayed untouched, but the app-level guard is gone.)

### 2d. #394 hardening, items 1, 3, 4 (2026-10-13, branch `feat/394-v2b-hardening`)

Real slapd (`image/` built as `ldapium:hard`), the UI built from the same tree (`ldapium-ui:hard`), local Colima Docker.

**ACL measurement before choosing the form** (scratch script, the fixtures applied after the three M rules, `pwdAccountLockedTime` rule of `W_lock`
substituted per run). rc per probe:

| W_lock level | Add marker | re-Add same | Modify-delete attr | Modify-delete value | Replace with nothing | Replace marker | Add marker over a timestamp | W_lock reads the attr |
|---|---|---|---|---|---|---|---|---|
| `write` (pre-#394) | 0 | 20 | **0** (unlocked) | 16 | **0** | 0 | 19 | yes |
| `add` (chosen) | 0 | 20 | 50 | 50 | 50 | 50 | 19 | yes |
| `=a` | 0 | 20 | 50 | 50 | 50 | 50 | 19 | **no** |

`W_data` with the split rule (`{5}` description + `filter=(objectClass=groupOfNames)`): user description replace / add / delete 50 / 50 / 50, group description
replace / delete 0 / 0, user `mail` replace 0, group `member` add 0, user Add carrying `description` **0** (`olcAddContentAcl` FALSE: Add does not evaluate
per-attribute rules, the #386 limit), group Add with description 0. slapd stores the rule as written
(`to dn.subtree="dc=example,dc=org" filter=(objectClass=groupOfNames) attrs=description by dn.exact="..." write by * break`), so the guide-vs-installed
byte comparison of `test-machine-write-acl-live.py` holds.

**Runs (all on this tree):**

| Run | Result |
|---|---|
| `scripts/test/test-machine-write-v2b-live.py` | `All machine write v2b live checks passed: 130 checks in 70s.` New: [A] a real bindable user / a seed under the base -> start-up error "reserved placeholder form"; [D] re-lock 204 as W_lock, value unchanged; [D] lockUser over a ppolicy timestamp lock -> 409 `conflict`, timestamp kept; [E] W_lock Modify-delete (attr / value), Replace (empty / other value) -> rc 50 each and the lock stays, second Add -> rc 20; [E] W_data replace / add of a USER description -> rc 50 |
| `scripts/test/test-machine-write-t004-live.py` | `All T-004 measurement checks passed: 53 checks in 44s.` New 5f: `OBS 5f W_data user description replace/add/delete: rc 50/50/50; group description replace/delete: rc 0/0; user mail replace: rc 0; user Add carrying description: rc 0` |
| `scripts/test/test-machine-write-acl-smoke.sh ldapium:hard` | `RESULT: all checks passed` (82 PASS; W_lock add 0, delete / empty Replace / Replace 50, lock still there; W_data user description 50) |
| `scripts/test/test-check-machine-write-acl-live.sh ldapium:hard` | `RESULT: all checks passed`; the checker on the real installed list: `RESULT status=pass checks=55 failed=0 rules=22` |
| `scripts/test/test-machine-write-acl-live.py` | `RESULT: 1488 checks passed, 0 failed, mutation=none, 123s` (n0, n1, p0, p1; W_data user description 50, W_lock delete / empty Replace / Replace 50, the backstop probes now use Add) |
| Upgrade path (scratch script, guide 4.2/7 commands as written): old fragments from `02b2dff` installed (8 + 6), section 7 `K=6` W_lock, default `K=9` on the old W_data **refused** (`not 9 contiguous values`, nothing deleted), `K=8` removes it, olcAccess byte-identical to before, new fragments installed (9 + 6) | `RESULT: upgrade path passed` (12 checks; after: user description 50, group description 0, W_lock add 0 / delete 50) |
| v2b drill, `write-lock.ldif` back to `write` (scratch, restored) | fails: `AssertionError: [E] #394 W_lock Modify-delete of the attribute of pwdAccountLockedTime is refused (rc 0, 50 expected)` |
| v2b drill, `filter=` removed from the description rule (scratch, restored) | fails: `AssertionError: [E] #394 W_data replace of a USER description is refused (rc 0, 50 expected)` |

**Unit tests and mutations (scratch, reverted):**

- `ldapclient`: `TestMachineLockModify_AddsTheIndefiniteMarker`, `TestMapMachineLockErr` (20 -> nil, 19 -> `ErrConflict`, 50/122/32 unchanged).
  Machine lock back to Replace -> the first fails; the 20 -> nil case removed -> the second fails.
- `config`: `TestMachineWriteGroupSeedRejects` gains six placement cases (a user inside a ceiling, a ceiling root, directly under the base, below the container,
  a sibling container, the container itself); the three ceiling-overlap cases now use a seed in the container plus a ceiling around it. The placement check
  replaced by `false` -> 6 subtests fail. A depth-equality clause survived its mutation (redundant with the parent comparison) and was removed.
- `scripts/test/test_machine_write_acl_check.py`: new cases (description rule without its filter, filter widened to `(objectClass=*)`, description back in the
  closed list, `W_lock` `write` instead of `add`) fail the checker; `filter=` dropped from `Rule.sig()` -> "description filter widened" passes the checker, so the test fails.

### 2e. v2c design gate: W_cred ship-gating experiments (2026-10-13, branch `feat/379-v2c-gate`)

Design gate only: no v2c code, no operation opened, no shipped fixture changed. Real slapd built from this tree
(`docker build -t ldapium:e2e -f image/Dockerfile ./image`, OpenLDAP `slapd 2.6.15`, image `sha256:76e8ffc187ac`), local Docker
Desktop (context `desktop-linux`). One fresh container per run with `LDAP_ACCESSLOG_OPS="writes reads bind"`,
`LDAP_AUDIT_ENABLED=true`, `LDAP_PASSWORD_POLICY_ENABLED=true` (shipped default policy: `pwdMinLength 8`, `pwdCheckQuality 1`,
`pwdInHistory 5`, `pwdSafeModify TRUE`, ppm `minQuality 1`), the shipped `M` / `W_data` / `W_lock` fragments, and a **scratch** `W_cred`
fragment (below). Two more short-lived containers for E-12d. Script: `scripts/test/test-machine-write-cred-experiments.py` (every probe is an
`OBS` line; every design expectation an `EXPECT PASS/FAIL` line; a FAIL does not stop the run, the script exits 1 listing them).

```
LDAPIUM_IMAGE=ldapium:e2e python3 scripts/test/test-machine-write-cred-experiments.py
...
45 of 51 expectations held, 6 failed, 47s.          (exit 1; run 6, the recorded run)
```

(In run 6 the six FAILs were design expectations that slapd did not meet: F-4, F-6 at quality 1, the `manage` length bypass, and F-7 twice.
§2f re-states them as expected refusals or known defects. Run 9 of the same script passes all 64 expectations, and its values for the §2e
probes are the same as in this table.)

Runs 1–5 were script development on the same image; run 2 is itself a result: with the shipped default policy **every** `W_cred`
Password Modify answered `Insufficient access (50)` / `Must supply old password to be changed as well as new one`, so the ACL probes in that
run proved nothing (all 50s came from ppolicy, not the ACL). Run 6 therefore measures the ACL on targets whose `pwdPolicySubentry` is a copy of
the default with `pwdSafeModify FALSE` (mode `pending`) and, separately, the "password administrator" alternative (mode `pwadmin`). Each refusal
is classified by its text: `safeModify`, `policy` (19), `acl` (50 without the safeModify text).

**ACL fragment tested** (main DB `{19}`–`{25}`, after `M` `{0}`–`{2}`, `W_data` `{3}`–`{12}` and `W_lock` `{13}`–`{18}`; tokens substituted;
`W_cred` cap = `ou=people`, `W_data` cap = the base):

```
{19} to dn.subtree="ou=system,dc=example,dc=org" by dn.exact="<W_cred>" none by * break
{20} to dn.exact="cn=replicator,dc=example,dc=org" by dn.exact="<W_cred>" none by * break
{21} to dn.subtree="ou=people,dc=example,dc=org" attrs=userPassword filter=(&(objectClass=inetOrgPerson)(creatorsName=<W_data>)(employeeType=ldapium-credential-pending:*)(!(userPassword=*))(!(memberOf=cn=admins,ou=groups,dc=example,dc=org))) by dn.exact="<W_cred>" =w by * break
{22} to dn.subtree="ou=people,dc=example,dc=org" attrs=employeeType val.regex="^ldapium-credential-pending:[0-9a-f]{16}$" by dn.exact="<W_cred>" =z by * break
{23} to attrs=userPassword,shadowLastChange,pwdHistory,pKCS8PrivateKey,userPKCS12,oathSecret,oathEncKey,oathTokenPIN,memberOf,pwdAccountLockedTime,pwdChangedTime,pwdFailureTime,pwdGraceUseTime,pwdReset,pwdPolicySubentry,pwdStartTime,pwdEndTime,pwdLastSuccess by dn.exact="<W_cred>" none by * break
{24} to dn.subtree="ou=people,dc=example,dc=org" attrs=entry by dn.exact="<W_cred>" =x by * break
{25} to * by dn.exact="<W_cred>" none by * break
W_data (inserted as its {6}): to dn.subtree="dc=example,dc=org" attrs=employeeType val.regex="^ldapium-credential-pending:[0-9a-f]{16}$" by dn.exact="<W_data>" add by * break
```

**Results (run 6, measured values):**

| ID | What was done | Result | Verdict |
|---|---|---|---|
| E-09/E-10 | `W_cred` `=w`, **shipped default policy**, correct pending account | `(50, safeModify)` "Must supply old password..." | **FAIL — design must change (F-4)** |
| E-08 | `W_cred` reads `userPassword`/`employeeType`/`creatorsName` | none returned | pass |
| E-08 | [pending] a: W_data-made, marker, no password | 0, the value binds | pass |
| E-08 | [pending] b: same but already has a password | `(50, acl)`, original password still binds | pass — `(!(userPassword=*))` holds for a non-reader |
| E-16 | [pending] c: marker by hand, admin-made; d: W_data-made, no marker; l: admin-made, marker added by W_data; e: pending outside the `W_cred` cap | all `(50, acl)` | pass |
| E-07 | [pending] f: pending DIRECT member of `cn=admins` | `(50, acl)` | pass — `(!(memberOf=...))` holds |
| E-07 | [pending] g: pending NESTED member (via `cn=subadmins`, no nestgroup overlay) | **0** (set) | as REQ-007 accepted (direct members only) |
| E-16 | [pending] h: group carrying the marker; i/j/k: `W_data`, `M`, `W_cred` | all `(50, acl)` | pass |
| E-16 | `creatorsName`: W_data Add → `uid=machine-write-data,...`; rootdn Add with explicit `creatorsName` → 19 `no user modification allowed`; rootdn **with relax** → 0 (stored); `W_data` with relax → 50 | — | pass (`W_data` cannot forge it; only the rootdn with relax can) |
| E-16 | `W_data` Modify on its own entry: add marker 0; add other `employeeType` 50; delete marker 50; add malformed marker 50; add marker to an **admin-made** entry 0 | — | pass (the admin-made case is stopped by `creatorsName`, row l) |
| E-16 | `W_cred` on `employeeType` after a set: delete the marker value 0 (other value kept); delete another value 50; delete the whole attribute 50; add a marker 50; replace 50 | — | pass — `val.regex` limits `=z` to the marker value |
| E-09 | [pending] `entry` level sweep (`userPassword =w`): none / `=x` / `=d` / `=c` / `=s` / `=r` | 0 for every level, **including none** | Password Modify needs **no** `entry` access: rule `{24}` is unnecessary |
| E-09 | [pending] `userPassword` level sweep: `=a` 50, `=z` 50, `=az` 0, `=w` 0, `write` 0, `=wm` 0 | — | minimum is `=w` (add **and** delete: the exop is a Replace) |
| E-09 | ppolicy state after the set (admin view) | `pwdChangedTime` written although `W_cred` has `none` on it | pass — ppolicy's internal mods bypass the requester ACL |
| E-09 | [pwadmin] `userPassword` rule `=wm`, shipped default policy: a 0; b, c, d, e, f, h, l refused `(50, safeModify)`; i/j/k `(50, acl)` | — | works, but see E-10 [pwadmin] |
| E-10 | [pending] 7-char exop `(19, policy)`, nothing stored; compliant set 0; 2-char cleartext plain Modify `(19, policy)` | — | pass — length applies to a requester ≠ target |
| E-10 | [pending] plain Modify with a **pre-hashed** `{SSHA}` value of a 2-char password | **0, and it binds** | **FAIL (F-6)** at `pwdCheckQuality 1` |
| E-10 | [pending-q2] same policy with `pwdCheckQuality 2`: compliant exop 0, 7-char 19, pre-hashed plain Modify `(19, policy)` and no bind | — | pass — quality 2 closes F-6 |
| E-10 | [pwadmin] 7-char exop **0 (stored)**; 2-char cleartext plain Modify **0**; pre-hashed 0 (binds) | — | **FAIL** — a ppolicy password administrator bypasses length/quality (D379-13 violated) |
| E-10 | history: after the admin cleared `userPassword` (1 `pwdHistory` entry), re-setting that previous value | 0 in every mode | `pwdInHistory` is not consulted when the entry has no current password — not provable through an initial set (R-7) |
| E-11 | [pending] second set on a: same value `(19, policy)`, other value `(50, acl)`, first value still binds; after cleanup + admin clearing `userPassword`, set again `(50, acl)` | — | pass (refused, first value kept); the 19/50 split is F-5 |
| E-17 | 11 rounds × N=10 parallel on one pending account: 6 exop-only + 2 exop/Modify mixed [pending], 2 exop + 1 mixed [pwadmin] | every round exactly **one** 0, nine 50; only the winning value binds (e.g. round 0 `[50,50,0,50,...]`, binds `[2]`) | pass (LDAP level) |
| E-20 | `M` reads on a after the set | `creatorsName`, `employeeType`, `pwdChangedTime`, `pwdPolicySubentry` — no `userPassword`; never-set entry has no `pwdChangedTime` | pass (R-8) |
| E-12a | accesslog after the successful **exop** on a | **no** record of the exop (rows: add/bind/modify of other ops only, 0 hashed values); refused exops (50 ACL, 19 policy, safeModify) leave no record either | exop path leaves no hash in accesslog (F-8) |
| E-12a | accesslog after a successful **plain Modify** of `userPassword` (t10b) | `userPassword:+ {SSHA}<redacted>` in `reqMod` | P21 holds for the plain Modify path |
| E-23b | `W_cred` plain Modify of b **refused** by the ACL (50) | 1 row with `userPassword:= {ARGON2}<redacted>` — the hash of the **attempted** value | refused writes leak the attempted hash (F-8) |
| E-12b | auditlog stdout (`docker logs`) for a | 1 `userPassword::` line, `{ARGON2}` (base64 `e0FSR09OMn0`, folded over two lines) | P20 confirmed: D379-14 (a) is required |
| E-13 (slice) | every plaintext sentinel vs. accesslog values and the slapd container log (auditlog included) | 0 hits | pass |
| E-12/E-23 | shipped accesslog ACL (`{0}to * by dn.exact="cn=admin,cn=accesslog" read by * none`): `M` reads nothing; with the opt-in `to * by M read`: `M` reads 1 `{SSHA}` hash + 20 other `reqMod` values | — | P21 confirmed for the opt-in |
| E-12c | `to attrs=reqMod val.regex="^userPassword:" by * none` and the same for `reqOld` (two rules: `val` needs a single attribute; one rule naming both is rejected with 80) in front of the opt-in | `M`: 0 hashed values, 20 other `reqMod` values kept; the accesslog rootdn still sees it | value-level deny works (Q12 option) |
| E-23a | base `search` + children `read` for `M` | base search returns nothing; subtree search returns the hash | check 6 must search children (confirmed) |
| E-23c | operator-added reader `uid=auditor` with `to * by auditor read` | auditor gets the hash, `M` (no opt-in) 0 | R-5 stays open |
| E-12d | `LDAP_ACCESSLOG_OPS="writes reads bind extended"` and `"all"`, one admin Password Modify exop | **slapd aborts**: `slapd: accesslog.c:1623: accesslog_response: Assertion '0' failed.`, container exit 133 | **FAIL (F-7)**, pre-existing, also the human path |
| E-21 | `cn=config` shipped ACL `{0}to *  by * none`; reader rules `attrs=olcAccess` / `attrs=olcPPolicyDefault` only → reader sees nothing; `attrs=entry,olcAccess` / `attrs=entry,olcPPolicyDefault` → exactly `olcDatabase={1}mdb,cn=config: [olcAccess]` and `olcOverlay={2}ppolicy,...: [olcPPolicyDefault]`; subtree search from `cn=config` 32 | — | pass with `entry` in the rule; the reader must filter on the granted attribute (`(olcAccess=*)`): `(objectClass=*)` is undefined for it (AGENTS.md) |
| E-21 | byte comparison of the 26 machine rules (fixture text, tokens substituted, folding undone, `{n}` stripped) with what slapd returns to the reader; again after `docker restart` | identical; identical | pass (R-2 stability) |
| E-21 | comparator mutations: (1) `to dn.subtree="ou=staff,..." attrs=userPassword by W_cred write` in front of the bundle, (2) `creatorsName` dropped from the filter, (3) a rule at `{0}` | comparator rejects all three, matches again after restore; real effect of (1): `W_cred` resets an **existing** staff password (0); of (2): `W_cred` sets the hand-marked admin-made c (0) | pass |
| E-21 | the reader identity in the **main** DB (no rule names it) | reads 58 entries under `ou=people` (image `by users read`) | D379-16 needs a main-DB deny for the reader (like `M` `{2}`) |

**Findings (escalated, not decided):**

- **F-4 (design-changing; D379-9, D379-13, the `W_cred` sketch).** The shipped default policy has `pwdSafeModify: TRUE`, and ppolicy applies
  it to every requester that is not the rootdn or a password administrator, **even when the target has no password**. The sketch's `W_cred`
  (`=w`) can therefore never set an initial password on a default-policy account. The ACL boundary itself holds (E-08/E-16/E-07/E-17 pass under
  a policy without safeModify), so **Q5 is not reopened**, but D379-9/D379-13 need a revision before T-020/T-021. Measured alternatives:
  (A) `W_cred` as password administrator (`=wm` on the filtered rule): works with the default policy, but ppolicy then skips length and quality
  (7-char and 2-char values stored) — violates D379-13, **rejected by measurement**. (B) a per-account pending policy (a copy of the default with
  `pwdSafeModify FALSE` and `pwdCheckQuality 2`) put on the entry by `W_data` at Add (`W_data` Add carrying `pwdPolicySubentry` → 0, stored;
  `W_data` Modify adding it → 50; Add is not checked per attribute, #386): every E-08/E-16/E-07/E-10/E-17 expectation holds, but it
  introduces F-5 and needs a cleanup that also removes `pwdPolicySubentry`. (C) `pwdSafeModify FALSE` in the default policy: F-5 on every
  account — not measured further, rejected by F-5.
- **F-5 (new risk under B/C).** On an account whose policy has `pwdSafeModify FALSE` and that **has** a password, any authenticated identity
  (measured: `W_cred`, `M`, an ordinary user) can test a guess: a Password Modify whose new value equals the current password answers 19
  (ppolicy's same-as-current/history check runs before the backend ACL), a wrong guess 50; `pwdFailureTime` is not written (0 → 0), so lockout
  never triggers. The shipped default (safeModify TRUE) answers 53 for a correct and a wrong old password (no oracle). Under B the pending policy
  must leave the entry in the same step as the marker; a failed cleanup leaves the oracle open.
- **F-6 (R-7).** `W_cred` used directly (not through the app's exop) can set a policy-violating password through a plain Modify with a
  pre-hashed value when `pwdCheckQuality` is 1 (the shipped value). `pwdCheckQuality 2` refuses it (19). The ACL cannot tell a Password Modify
  exop from a plain Modify, so the guard has to be the policy.
- **F-7 (defect outside this spec; also the human `setPassword` path).** With `extended` (or `all`) in `LDAP_ACCESSLOG_OPS`, one Password Modify
  exop aborts slapd (`accesslog.c:1623: accesslog_response: Assertion '0' failed.`, exit 133). The shipped default (`reads bind`) and the
  documented `writes reads bind` do not include `extended`. Not fixed here; needs its own issue (guard the value in `image/entrypoint.sh` or
  document it).
- **F-8 (refines P17/P21).** Under `writes reads bind` the exop (success or refusal) leaves **no** accesslog record, so the application path
  does not put the hash into accesslog; a plain Modify of `userPassword` does, including an ACL-refused one (the hash of the attempted value).
  `W_cred` used directly can therefore leak hashes of attempted values to every accesslog reader. auditlog carries the exop hash.

**Ship-gating risks after this run:** R-1 **closed** for the filter semantics (E-07 direct, E-08, E-16), conditional on a policy that does not
refuse before the ACL (F-4); nested privileged membership stays the accepted REQ-007 risk. R-2 **closed** for stability and exposure (E-21),
with two required design additions (`entry` in the reader rules, a main-DB deny for the reader). R-3 **closed at the LDAP level** (E-17, direct;
the app-path half needs the operation). R-4 not closable (E-22 not run, needs the implementation). R-5 **still open** (operator readers, the
plain-Modify path, F-8); mutual exclusion stays. R-6 still a maintainer decision (auditlog hash confirmed). R-7 **design must change** (F-4,
F-6; history is not provable through an initial set; ppm `minQuality 1` cannot be told apart from no quality check). R-8 **closed** (E-20).

**Not run in this gate:** E-01–E-06 (v2b, partly covered by §2b), E-13 in full (only the slapd-log/accesslog slice), E-14, E-15, E-18 (needs the
UI checks), E-19 (§2b), E-22 (needs the implementation's timing hook), the app-path halves of E-17/AC-010c (two `Idempotency-Key`s through
the UI: no operation exists). Colima was not used (Docker Desktop was the active context). The security-reviewer round and the Codex critic
of the v2c gate are run by the orchestrator after this change and are not claimed here.

### 2f. F-4 decided design: pending policy attach and cleanup (2026-10-13, same branch)

Maintainer decision (2026-10-13): a dedicated per-pending-account policy (`pwdSafeModify FALSE`, `pwdCheckQuality 2`), attached only to marker
accounts and removed together with the marker in the cleanup step. Rejected: the `manage` ACL and changing the default policy. Same script,
extended with the `D-0`–`D-7` probes. The expectations now pin **measured reality**: the F-4 baseline, the rejected `manage` alternative, F-6 at
quality 1, F-7 and F-9 are expected refusals or known defects (a change in slapd behaviour fails the run), so exit 0 means every expectation held.
The image was rebuilt under a private tag because the shared `ldapium:e2e` tag disappeared between runs (another lane).

```
docker build -q -t ldapium:v2cgate -f image/Dockerfile ./image      # sha256:bd53af25be9d
LDAPIUM_IMAGE=ldapium:v2cgate python3 scripts/test/test-machine-write-cred-experiments.py
...
64 of 64 expectations held, 0 failed, 48s.                         (exit 0; run 9)
```

Run 7 broke on the missing image. Run 8 had one real FAIL, which became F-9 below (a harness argument-order bug in the same probe was fixed
before it).

**Scratch ACL added on top of §2e** (stored by slapd exactly as written, read back as M/admin):

```
W_data (before its {2} none, as {5}):
  to dn.subtree="ou=people,dc=example,dc=org" attrs=pwdPolicySubentry val="cn=credential-pending,ou=policies,dc=example,dc=org"
     filter=(employeeType=ldapium-credential-pending:*) by dn.exact="<W_data>" add by * break
W_cred userPassword rule: the §2e filter + (pwdPolicySubentry=cn=credential-pending,ou=policies,dc=example,dc=org)
W_cred (before its secrets none):
  to dn.subtree="ou=people,dc=example,dc=org" attrs=pwdPolicySubentry val="cn=credential-pending,ou=policies,dc=example,dc=org"
     by dn.exact="<W_cred>" =z by * break
policy cn=credential-pending: copy of cn=default with pwdSafeModify FALSE, pwdCheckQuality 2 (pwdMinLength 8, pwdLockout TRUE, ppm kept)
```

| ID | Probe | Result |
|---|---|---|
| D-0 | `M` reads the pending policy entry | `pwdAttribute: userPassword`, `pwdMinLength: 8`, `pwdCheckQuality: 2`, `pwdSafeModify: FALSE`, `pwdLockout: TRUE`; a start-up check can compare all of them |
| D-1 | `W_data` **Add** (shipped `olcAddContentAcl` FALSE): marker + pending policy / **no marker** + pending policy / marker + **another** policy | 0 / **0** / **0**, all stored. At Add the ACL does not constrain `pwdPolicySubentry` (#386); only the app's closed body does |
| D-2 | `W_data` **Modify**: add the pending DN to a marker entry / another DN to a marker entry / the pending DN to a non-marker `W_data` entry / to ordinary `u01` / delete it | 0 / 50 / 50 / 50 / 50: Modify attach is ACL-limited to the exact DN, marker entries only, add only |
| D-2 | others attaching the pending policy: ordinary user on **another** account, `M`, `W_cred` | 50 / 50 / 50 |
| D-2 (F-9) | ordinary user on **itself** | **0, stored**: the image rule `{2}to * by self write` covers `pwdPolicySubentry`, so any user can pick **any** password policy for its own entry (pre-existing). `W_cred` on that user: 50 (no marker, not `W_data`-made, has a password); the `M` orphan sweep finds it |
| D-3 | `olcAddContentAcl TRUE` (database-wide switch, restored after): `W_data` Add marker + pending / no marker + pending / marker + other policy / plain user (closed list) / plain user carrying `userPassword` | 0 / **50** / **50** / 0 / **50**: with TRUE the Add-time attach is ACL-limited too, and the #386 `userPassword`-at-Add limit closes |
| D-4 | `W_cred` on a marker entry carrying the pending policy: 7-char exop / pre-hashed `{SSHA}` 2-char plain Modify / compliant exop | 19 / **19** (quality 2) / 0, the value binds |
| D-4 | `W_cred` on a marker entry carrying **another** policy (`cn=nolock`) | 50 (the new filter clause) |
| D-4 | `M` Password Modify on the pending entry **before** the set | 50: no password yet, no oracle |
| D-5 | after the set, before cleanup: `M` new = current / wrong guess | **19 / 50**: the F-5 oracle exists in this window |
| D-5 | `M` sweeps: `(&(pwdPolicySubentry=<pending>)(pwdChangedTime=*))` / `(&(pwdPolicySubentry=<pending>)(!(employeeType=ldapium-credential-pending:*)))` | 1 (the set-but-not-cleaned entry) / 2 (the D-1 no-marker Add and the F-9 self-attach) |
| D-6 | `W_cred` cleanup: delete **another** policy value / the whole attribute / marker value + pending policy value in **one** Modify | 50 / 50 / 0; nothing left (`employeeType` and `pwdPolicySubentry` gone) |
| D-6 | after cleanup: `M` new = current; `W_cred` exop; bind with the set password; stuck sweep | `(50, safeModify)`; `(50, safeModify)`; binds; 0 hits. The default policy applies again and the oracle is gone |
| D-7 | **atomic** alternative: one `W_cred` plain Modify = replace `userPassword` (cleartext) + delete marker value + delete pending policy value | 7-char: 19, entry unchanged; compliant: 0, binds, nothing left. accesslog (`writes`) holds the hash of that Modify (`userPassword:= {ARGON2}<redacted>`, F-8) |

**F-9 (pre-existing, outside this spec; a separate issue, not opened here).** Any authenticated user can set its own `pwdPolicySubentry`
(image rule `to * by self write`), so it can choose a weaker password policy for itself (and, with the pending policy, open the F-5 oracle on its
own account). It does not create a `W_cred` target.

**F-7 note (a separate issue, not opened here):** `LDAP_ACCESSLOG_OPS` containing `extended` (or `all`) aborts slapd on any Password Modify
exop (§2e E-12d; still reproduced in run 9 as an expected known defect). The v2c design does not depend on it, but an operator who adds
`extended` makes every `setPassword` (human or machine) a slapd crash.

### 2g. Revision 8: the design after the independent reviews (2026-10-13, same branch)

Inputs: security-reviewer (BLOCKER 0, MAJOR 2), Codex (P1 3, P2 2), and the maintainer's decisions: Q15 `olcAddContentAcl TRUE` becomes a v2c
prerequisite, Q14 accepts the 19/50 window with stronger sweeps, and F-9 (#399) is a prerequisite fixed in a separate PR. The same script gained a
`FINAL` phase on a **fresh** slapd with the revised rules. Every row below is an assertion, not an `OBS`.

```
LDAPIUM_IMAGE=ldapium:v2cgate python3 scripts/test/test-machine-write-cred-experiments.py
...
82 of 82 expectations held, 0 failed, 59s.          (run 12, exit 0)
```

Run 10 hung on a probe that read a password from `/dev/stdin` (killed, probe removed). Run 11 had 80 of 81: one FAIL, and the expectation was
wrong, not the design. The pending direct privileged member, whose set was refused, never gets a password, so the stuck sweep correctly does not see
it. That gap is the new TTL ("abandoned pending") sweep.

**Final rules** (main DB, `olcAddContentAcl: TRUE`; `T` = `(&(objectClass=inetOrgPerson)(creatorsName=<W_data>)(employeeType=ldapium-credential-pending:*)(!(userPassword=*))(!(memberOf=cn=admins,...))(pwdPolicySubentry=<pending policy>))`):

```
W_data {5}  to dn.subtree="ou=people,..." attrs=employeeType val.regex="^ldapium-credential-pending:[0-9a-f]{16}$" filter=T by <W_data> add by * break
W_data {6}  to dn.subtree="ou=people,..." attrs=pwdPolicySubentry val="<pending policy>" filter=T by <W_data> add by * break
            (both before W_data's secrets/pwd* `none`; at Add the new entry satisfies T, creatorsName is set before the ACL check;
             on Modify an entry without the attribute cannot satisfy T)
W_cred      attrs=userPassword filter=T =w
            attrs=employeeType val.regex=<marker> filter=(&(creatorsName=<W_data>)(pwdPolicySubentry=<pending policy>)) =z
            attrs=pwdPolicySubentry val="<pending policy>" filter=(creatorsName=<W_data>) =z
            (no `entry` rule; secrets none; to * none)
```

| Check | Result |
|---|---|
| Q15 `W_data` Add: marker + policy / ordinary createUser (closed list) | 0 / 0 |
| Q15 `W_data` Add: carrying `userPassword` / policy without marker / marker without policy / marker + **default** policy / marker + policy + `userPassword` / marker + policy outside the cred subtree | 50 each |
| M-1 `W_data` Modify: mark a v2a-made entry / mark an admin-made SSO entry / attach the policy to a v2a entry / both in one Modify / delete the marker / delete the policy | 50 each: the Modify path is closed |
| M-1 `W_data` Modify: a **second** marker value on an already-pending entry | **0** (two markers stored). The app pre-read must require exactly one marker value |
| Cross matrix, `W_cred` exop: a pending / b has a password / c admin-made pending / d v2a-made / f direct privileged / h group / i,j,k identities / m SSO entry marked by the admin | a 0 and binds; b, c, f, h, i, j, k, m 50 (acl); d 50 (safeModify: default policy); b keeps its password |
| nested privileged member g | 0 (REQ-007 accepted risk, unchanged) |
| pending policy: 7-char exop / pre-hashed `{SSHA}` plain Modify / compliant exop | 19 / 19 / 0 |
| Q14 window before cleanup: `M` new = current / wrong | 19 / 50; `M` reads `pwdChangedTime` on the set entry (the pre-read 409 signal) |
| F-9 on this image: ordinary user self-attach | 0. Still present (fixed by #399, a prerequisite); found by the foreign sweep |
| stuck sweep `(&(pwdPolicySubentry=P)(creatorsName=W_data)(pwdChangedTime=*))` | exactly {a, b (admin-set password), g, p2}: 4 |
| foreign sweep `(&(pwdPolicySubentry=P)(!(creatorsName=W_data)))` | exactly {c, h, m, human (F-9), M, W_cred, W_data (policy put on them by the test as targets)}: 7 |
| orphan `(&(pwdPolicySubentry=P)(creatorsName=W_data)(!(employeeType=...*)))` | none |
| abandoned (TTL) sweep `(&(pwdPolicySubentry=P)(creatorsName=W_data)(employeeType=...*)(!(pwdChangedTime=*)))` | exactly {f}; `W_cred` cleanup 0 |
| `W_cred` cleanup negatives: whole `employeeType` / whole `pwdPolicySubentry` / add the policy / foreign c / foreign m | 50 each |
| rollback ordering: `W_cred` cleanup rules removed first, then cleanup of a leftover | 50: leftovers must be removed **before** the grant |
| sweep cleanup (`W_cred`, one Modify: marker value + policy value) on the 4 stuck entries; admin runbook on 6 foreign entries | all 0; only the group h is left (the test leaves it out of the runbook) |
| after cleanup: `M` new = current on a; a binds | `(50, safeModify)`: no oracle; binds |
| E-17 with the final policy: 4 exop rounds + 1 exop/Modify mixed round, N=10 | each round exactly one 0, nine 50; the winner binds, three losers do not. Single slapd only: multi-provider is last-write-wins (not measured) |

Not measured here: the application parts of Revision 8 (exactly-one-marker pre-read, 409 on `pwdChangedTime`, cleanup in a detached context,
sweep scheduling and TTL value, runbook execution under an LDAP outage), multi-provider replication, and a re-review of Revision 8.

### 2h. Revision 9: re-review of Revision 8 (2026-10-13, same branch)

Re-review results: security-reviewer found 0 blockers, 1 major (M-3) and 4 minors; Codex found 1 P1 and 2 P2. Run 15 of the same script,
on a fresh slapd, with the `FINAL` phase extended:

```
LDAPIUM_IMAGE=ldapium:v2cgate python3 scripts/test/test-machine-write-cred-experiments.py
...
93 of 93 expectations held, 0 failed, 59s.          (run 15, exit 0)
```

Runs 13 and 14 each had one FAIL caused by a wrong expected set in the script (the stuck sweep correctly also found the M-3 victim taken over
before the mitigation), not by slapd. Both were fixed in the expectation.

**M-3 mitigation rules** (W_data, inserted before its secrets/`entry` write rules):

```
to dn.subtree="<W_data cap>" attrs=entry filter=(&(objectClass=inetOrgPerson)(!(creatorsName=<W_data>))) by <W_data> =rsc by * break   (a)
to dn.exact="<each privileged group>" attrs=member by <W_data> =rsc by * break                                                           (b)
```

| Check | Result |
|---|---|
| M-3 **without** mitigation: `W_data` deletes an admin-made member of `cn=admins` → re-Adds it as pending → `W_cred` sets it → `W_data` adds it to `cn=admins` | 0 / refint dropped the membership / 0 / 0, **binds** (takeover reproduced) / 0 |
| M-3 **with** (a)+(b): delete of the admin-made victim / re-Add / `W_cred` set / `W_data` adds a W_data-made account to `cn=admins` | 50 (victim kept, still in `cn=admins`) / 68 (exists) / `(50, safeModify)`, no bind / 50 |
| side effects of (a)+(b): delete a W_data-made user / patchUser `mail` on an admin-made user / modrdn an admin-made user / add a member to ordinary `g01` | 0 / 0 / **50** / 0. v2a `deleteUser` and modrdn of **non-W_data users** are refused once (a) is installed: a contract change (Q16) |
| residual (b): add a member to `cn=subadmins` (a nested group of `cn=admins`) | 0: nested privilege is not covered (as REQ-007) |
| residual (a): a **W_data-made** (v2a) account: delete / re-Add as pending / `W_cred` set | 0 / 0 / 0, binds: (a) cannot protect accounts W_data itself created |
| pending twin of an existing account under another RDN (same `uid`) | 19: the unique overlay (`uid`, `mail`, image default) refuses it |
| Q15 createGroup-shaped Add (groupOfNames + description) / user Add carrying description | 0 / 50 |
| TTL condition for `M`: abandoned sweep with `createTimestamp<=now-1h` / `<=now` | 0 entries / exactly the abandoned entry |
| F-9 on this image (no #399 fix): self-attach | 0, recorded. The script asserts 50 automatically once a rule naming `pwdPolicySubentry` with a `by self` limit is in the image |
| Codex P1 rollback, wrong order: all attachments cleaned, then a late Add with the attach rules still live | 0, the attachment is back |
| right order: attach rules removed first, then a late Add; then cleanup | 50; zero attachments, and then the cleanup grant may go |

Not measured: application parts (exactly-one-marker, 409, detached cleanup with `context.WithoutCancel` + timeout, sweep scheduling, backlog
and throughput), multi-provider (pinning, direct `W_cred` writes to another provider), and a re-review of Revision 9.

### 2i. T-021: the shipped W_cred / W_data v2c fragments (2026-10-14, branch `feat/379-t021-cred-acl`)

Fixtures `scripts/test/fixtures/machine-acl/write-cred.ldif` (7 rules) and `write-data-cred.ldif` (M-3 (a), (b) per privileged
group, Add-only marker, Add-only policy) carry the §2g/§2h rule texts; `docs/machine-write-account.md` section 8 installs them
(switch → policy → W_data v2c → W_cred) and rolls back in the Revision 9 order. The image default is unchanged (no
`olcAddContentAcl` in `image/entrypoint.sh`); only a v2c deployment sets it. Image `ldapium:t021` built from `197bb1b`.

| Run | Result |
|---|---|
| `test-machine-write-cred-experiments.py` (adds `FIXTURE`: fixture text == measured text, both files) | 96 of 96, exit 0 (D-2 now follows the same #399 detector as FINAL: self-attach 50 on this image) |
| `test-machine-write-acl-live.py`, 4 configurations, v2c phase each (guide blocks, every decision an assertion, E-17 10 parallel) | 2279 passed, 0 failed, exit 0 (after the Revision 11 fixes) |
| same, `LDAPIUM_WACL_MUTATE=m3-inetorgperson-only` / `drop-cred-filter` / `drop-m3-entry` (n0) | 7 / 6 / 22 named failures, exit 1 (e.g. "W_data cannot delete an admin-made person (50)", "W_cred ldappasswd of a pending account that already has a password 50") |
| `test-check-machine-write-acl-live.sh` (v2c section: pass with the v2c options; switch off, M-3 (a) removed, filter term dropped each non-zero; rollback byte-equal, order guards) | all passed, exit 0; real dump saved as `machine-acl-check/good-v2c.ldif` |
| `test_machine_write_acl_check.py` (v2c templates == fixtures, real v2c dump, 17 v2c faults, partial options = usage) | 31 tests OK |
| `test-machine-write-acl-smoke.sh`, `test-machine-acl-readonly-live.py` | all passed / 461 passed |

Revision 11 (review of `3c831b6`), all asserted in the runs above: M-3 (a) is class-independent — `W_data` delete of an admin-made
`person` / `organizationalPerson` / `account`+`posixAccount` / container 50, admin-made `groupOfNames` 0 (v2b `deleteGroup`); the pre-review
filter (mutation) lets the first three be deleted. MAJOR-2 recorded as a limit: `W_data` replaces an admin-made privileged user's `mail`
(0), a pending account takes the old value (0), `W_cred` sets it (0). Non-pinned provider (`write-cred-deny.ldif`): `W_cred` set 50,
cleanup 50, reads nothing; checker passes only with `--wcred-unpinned`. Zero-pending check: unreachable node and failed bind both exit
non-zero with `PENDING_LEFT=unknown`. After `docker restart`: `olcAddContentAcl: TRUE` and the v2c layout unchanged. The re-Add over a kept
victim is exactly 68. The checker refuses `( ) * \ | & "` in DNs (usage, 2).

Not covered here: the application parts (T-020 config, T-022 pre-checks and sweeps), multi-provider (`W_cred` on another provider),
the `cn=config` reader identity (D379-16), and a security review of the shipped fragments.

### 2j. T-028: the run-time premise checks and sweeps (2026-10-14, branch `feat/379-t028-preconditions`)

Application code: `ldapclient.CredPremise` (checks 1, 2, 5, 6 and the four sweeps; pure verdicts in
`machine_write_premise_acl.go` / `_verdict.go`, unit-tested) and the `httpapi` gate (start-up refusal, request 503,
60 s cycle; unit-tested with a fake checker). `setPassword` stays unreachable (T-026). Live: the exact checker,
compiled as the `live`-tagged test binary, run inside one fresh slapd (image `ldapium:t028` built from this tree,
accesslog `writes reads bind`) after the guide's 4.2/4.3, 8.2–8.5 and the new 8.8 blocks (reader account and ACL,
canaries in two cred subtrees `ou=a`/`ou=b` below the CRED_DN `ou=people`).

```
LDAPIUM_IMAGE=ldapium:t028 python3 scripts/test/test-machine-write-cred-premise-live.py
RESULT: 67 checks passed, 0 failed, mutation=none, 14s                                  (exit 0)
LDAPIUM_IMAGE=ldapium:t028 LDAPIUM_PREMISE_MUTATE=drop-acl-check python3 scripts/test/test-machine-write-cred-premise-live.py
RESULT: 63 checks passed, 4 failed, mutation=drop-acl-check, 16s                        (exit 1)
LDAPIUM_IMAGE=ldapium:t028 LDAPIUM_PREMISE_MUTATE=accesslog-base-search python3 scripts/test/test-machine-write-cred-premise-live.py
RESULT: 66 checks passed, 1 failed, mutation=accesslog-base-search, 15s                 (exit 1)
```

After the review (Revision 12; unmarked canary now W_data-made with the pending policy, re-read cleanup retry,
accesslog filter on reqMod/reqOld/reqDN, read-only sweep), same script:

```
(none)                  RESULT: 77 checks passed, 0 failed, 16s                                    (exit 0)
drop-acl-check          RESULT: 72 checks passed, 5 failed                                         (exit 1)
accesslog-base-search   RESULT: 75 checks passed, 2 failed                                         (exit 1)
accesslog-objectclass   RESULT: 76 checks passed, 1 failed (M reads reqMod/reqDN without objectClass) (exit 1)
sweep-nosuchattr-ok     RESULT: 76 checks passed, 1 failed (race: cleaned 2, orphan 1 instead of 1/0)  (exit 1)
```

New rows: the unmarked canary gaining a marker -> `canary_unmarked_accepted` (the marker term isolated); M with read on
`entry,reqMod,reqOld,reqDN` only (control: `(objectClass=*)` 0 entries, `(reqDN=*)` > 0) -> `accesslog_children_readable`;
a read-only sweep finds a stuck entry and leaves its policy; the marker deleted between search and cleanup (test hook) ->
the re-read retry removes the policy, `cleaned 1`, no orphan.

| Scenario (AC-010b unless noted) | start-up/periodic | request |
|---|---|---|
| baseline (guide layout, two cred subtrees, canaries in both) | ok | ok |
| looser `attrs=userPassword by users write` for the SECOND subtree only, in front of the W_cred bundle (real effect: W_cred resets an existing password there, 0) | `acl_cred_bundle_mismatch` | same |
| a rule at `{0}` | `acl_prefix_mismatch` | same |
| W_cred filter loses `(!(userPassword=*))` | `acl_cred_bundle_mismatch` | same |
| `olcAddContentAcl` removed | `acl_add_content_acl_off` | same |
| reader main-DB deny removed (real effect: the reader reads `ou=people`) / its `cn=config` grant removed | `acl_reader_rule_missing` / `reader_unreadable` | same |
| default `pwdMinLength 8` (the shipped value) / default `pwdSafeModify FALSE` | `policy_default_min_length` / `policy_default_safe_modify` | same |
| pending `pwdCheckQuality 1` / `pwdSafeModify TRUE` / `pwdMinLength 8` | `policy_pending_check_quality` / `_safe_modify` / `_min_length` | same |
| no `olcPPolicyDefault` (stands in for a policy-less node) | `policy_default_unknown` | same |
| `M`: accesslog base `search` + children `read` (control: base 0 entries, children readable) / the full opt-in | `accesslog_children_readable` | same |
| second subtree's pending canary loses the pending policy | `canary_pending_short_unexpected` | ok (no canaries) |
| second subtree's with-password canary loses its password | `canary_with_password_accepted` | ok |
| second subtree's pending canary loses its marker | **ok** (T028-F1) | ok |
| reader (E-21, D379-16): sees exactly the main DB entry and the ppolicy overlay with the granted attributes; nothing from `cn=config` with `(objectClass=*)`; nothing in the main DB; cannot write `olcAccess` (50) | — | — |
| sweeps: canaries only → 0/0/0/0; one stuck, one TTL (`P_TTL=2s`), one orphan, one foreign → found 1/1/1/1, cleaned 3, afterwards only the foreign entry and the 6 canaries carry the pending policy; second round foreign 1 only; W_cred policy `=z` rule removed → `sweep_stuck_cleanup_failed`, restored → cleaned | — | — |

Mutations: `drop-acl-check` (check 1 skipped) fails the `{0}`, filter-term and reader-rule scenarios in both modes, and
the second-subtree scenario in the request mode; in the start-up/periodic mode the second subtree's with-password
canary still catches that one (`canary_with_password_accepted`), which is the canaries' (narrowed, Revision 12) role. `accesslog-base-search`
fails exactly the hidden-base scenario (the opt-in returns the base entry itself and stays detected).

- **T028-F1 (refines check 5, escalated):** the pending canary that LOST its marker still answers 19 to the 1-character
  exop: ppolicy judges the value before the backend ACL (like F-5). The two 19 probes therefore prove that the pending
  policy (length, quality 2) applies to W_cred, not that the W_cred ACL admits a pending account; only check 1 proves the
  ACL. The 50 probes (with-password, unmarked carrying the pending policy so safeModify does not decide) do prove ACL
  refusals.
- The checker output carried no password value in any run (asserted per call).

Not covered here: E-22 (the check -> write window, R-4: setPassword is not reachable), the 60 s timing against a
running UI (unit-tested with a 5 ms period), the UI process's own non-zero exit (unit-tested through `newServer`),
multi-provider, and a policy-disabled container (`LDAP_PASSWORD_POLICY_ENABLED=false`; approximated by removing
`olcPPolicyDefault`).

### 2k. T-024: the password step through the app, secret scan (2026-10-14, branch `feat/379-t024-proof`)

`setPassword` stays closed in production (T-026). The application side is the `live`-tagged Go test
`TestCredSecretLive` (`ui/backend/internal/httpapi/machine_write_cred_live_test.go`): `newServer` with the
production table plus the `setPassword` catalog row (`machineDeps.writeOps`, as the unit tests) and the
`password.write` ceiling injected after construction; everything else is production (real dialer and
`W_data`/`W_cred` binds, real `M` pre-reads, real T-028 `CredPremise` at start-up / before each write / every
60 s, real limiters). Tokens come from the harness's in-process IdP (no Keycloak). It runs inside a fresh
slapd (image `ldapium:t024` built from `6f455e9`, `sha256:3bb7c6de0de6`, Docker Desktop) after the T-028
proof's setup (guide 4.2/4.3, 8.2–8.5, 8.8; two cred subtrees with canaries). Driver:
`scripts/test/test-machine-write-cred-secret-live.py`; 60 one-time 32-character sentinels per run, passed in a
0600 file, never printed (the driver's mask hides them).

```
LDAPIUM_IMAGE=ldapium:t024 python3 scripts/test/test-machine-write-cred-secret-live.py
RESULT: 168 checks passed, 0 failed, mutation=none, 32s                                       (exit 0)
LDAPIUM_T024_MUTATE=log-password             RESULT: 82 passed, 1 failed (UI log: sentinel found)   (exit 1)
LDAPIUM_T024_MUTATE=log-short                RESULT: 82 passed, 1 failed (the 11-character value)    (exit 1)
LDAPIUM_T024_MUTATE=drop-serialization       RESULT: 72 passed, 11 failed                           (exit 1)
LDAPIUM_T024_MUTATE=drop-client-concurrency  RESULT: 77 passed, 0 failed (T-023 lock answers 429)   (exit 0, layer check)
LDAPIUM_T024_MUTATE=drop-target-lock         RESULT: 77 passed, 0 failed (D8d answers 429)          (exit 0, layer check)
```

Configurations: `accepted` = accesslog `writes reads bind`, no auditlog (what the chart and T-028 accept);
`auditlog` = the same plus `LDAP_AUDIT_ENABLED=true` (what the chart refuses, D379-14 (a)). Both run every
path below.

| Path (app, both configurations) | Result |
|---|---|
| machine `createUser` `credentialPending` (marker + pending policy on the Add) | 201 |
| `setPassword` success | 200 `{}`; the value binds; marker and pending policy gone (cleanup, audit `cleanup=done`) |
| same key + same body / same key + other value | 200 `{}` `Idempotent-Replayed: true` / 422 `idempotency_key_reused`; only the first value binds |
| new key on the set and cleaned account | 403 (no marker), no Password Modify sent |
| `If-Match` / no key / `oldPassword` / 11 characters / another client's tag | 400 / 428 / 400 / 400 / 403, no Password Modify, the account still pending |
| E-10: pending `pwdMinLength` raised to 40, 32-character value | slapd 19 → **400 `invalid_request`**, nothing stored, no cleanup; the same key + body after restoring 12 runs again → 200 (the refusal released the key) |
| privileged direct member (pending) | 403, no Password Modify |
| cleanup fails (the cleanup Modify reaches slapd with a policy value the entry lacks, both attempts; review follow-up) | 200 `{}`, the value binds, marker and policy stay, audit `cleanup=failed`, log `machine_credential_cleanup_failed` without a value |
| before-write premise fails (pending `pwdCheckQuality` set to 1 after start-up; review follow-up) | 503 `unavailable`, no Password Modify, log `machine_cred_premise phase=request` with the result code only |
| LDAP ACL refusal: a pending account with a password and **no** `pwdChangedTime` (rootdn exop, then rootdn relax delete) | wrong value: W_cred 50 → 403 `forbidden`; the current value: 19 → 400 `invalid_request` (T024-D1) |
| stuck entry (password + `pwdChangedTime` + marker + pending policy put back by the rootdn): current value / wrong value | 409 / 409, same code and message, no Password Modify; control: `M` by direct LDAP still gets 19 / 50 (F-5, the accepted Q14 window) |
| E-17 / AC-010c (a): same client, two keys at once (Password Modify held 600 ms), 5 rounds | each round 200 + 429 `machine_rate_limited` with `Retry-After`, one Password Modify sent, only the winner binds |
| AC-010c (c): another client at the same time | 200 + 403 (tag) |
| production password budget (1 rps, burst 1), two accounts in one second | 200, then 429 + `Retry-After`; the second account untouched |
| E-10 by direct `W_cred` (after the scans) | pre-hashed `{SSHA}` 2-char plain Modify 19 (quality 2); 10-character exop 19 |

E-13 scan (plaintext sentinel searched at the shortest length sent, the 11-character prefix every sent value contains / base64 of the whole and the 11-character value at all three alignments / hash pattern: the E-13 regex,
`userPassword::` and the base64 prefixes of `{SSHA}`, `{SSHA256..512}`, `{ARGON2}`, `{CRYPT}`, `{PBKDF2`, `{SHA}`,
`{SHA2`, `{MD5}`, `{SMD5}`):

| Where | accepted | auditlog |
|---|---|---|
| every HTTP response: status, headers, body (setPassword and createUser, all paths) + the server's log, UI audit lines included | 0 / 0 / 0 | 0 / 0 / 0 |
| the Go test's own stdout/stderr | 0 / 0 / 0 | 0 / 0 / 0 |
| slapd `docker logs` | 0 / 0 / 0 | 0 / 0 / **58** (auditlog stdout) |
| `cn=accesslog` `reqMod`/`reqOld` as its rootdn, written during the test, the one public probe constant allowlisted (T024-F1) | 0 / 0 / 0 | 0 / 0 / 0 |
| the same, whole log, sentinels only (the seed's plain `userPassword` Adds before the test are found by the hash scan: positive control) | 0 / 0 | 0 / 0 |
| `cn=accesslog` as `M`: shipped ACL (0 entries readable); with the opt-in (`accesslog-optin.ldif`), the probe constant allowlisted | 0 / 0 / 0 | 0 / 0 / 0 |

The hash-bearing configurations are refused, asserted in the same run: auditlog → `test-chart-machine-write.sh`
"cred next to audit.enabled" (both variants) refuses to render; the `M` opt-in → T-028 check 6
`accesslog_children_readable`, `newServer` refuses to start. Controls: accesslog recorded the test's writes (the
`W_cred` cleanup Modify among them); the log-password mutation makes the UI-log row fail.

Decisions and findings:

- **T024-D1 (no response normalization; reversible).** The app path is not a password-confirmation oracle in the
  states the app can reach: during the request the per-client concurrency and the per-target lock answer 429
  whatever the value; after a set the pre-read answers 409 (`pwdChangedTime`, stuck or not) or 403 (no marker)
  whatever the value, before any Password Modify (both live above). The only state with a value-dependent answer
  (400 for the current value, 403 for a wrong one) is a password with no `pwdChangedTime`, which only the rootdn
  (relax) or an offline import makes; there every authenticated identity already gets the same 19/50 split by
  direct LDAP (F-5), so normalizing the app response would close nothing. Cost: in that state the app mirrors the
  split. Escape hatch: map the setPassword exop's 19 and 50 to one response if a non-rootdn path to that state
  appears.
- **T024-D2 (LDAP 19 is mapped; no change).** On the wire slapd's 19 goes through `mapSetPasswordErr` → `mapErr`
  → `domain.ErrInvalidInput` → 400 `invalid_request`, definitive (the key is released, the same key re-runs).
  The 409 for "ldap result 19" in `TestPasswordPipeline_DirectoryErrorTextNeverLeaks` comes from a fake that
  returns a raw `*ldap.Error` without `mapErr`; it tests text redaction, not the production mapping.
- **T024-F1 (maintainer decision 2026-10-14: keep the probe).** T-028 check 5's pre-hashed probe (a `W_cred`
  plain Modify, refused 19) leaves its attempted value in `cn=accesslog` (F-8) at start-up and every 60 s whenever
  `writes` is logged: 2 entries per check here (one per pending canary), readable by the accesslog rootdn and any
  accesslog reader. It was the hash of a random 2-character value (not secret, not request-derived); it is now the
  fixed public constant `ldapclient.canaryHashedProbe` = `{SSHA}` of `zz` with salt `ldapium!`
  (`{SSHA}wRvhGzOlOIRbYCuyzJDhNpazw1RsZGFwaXVtIQ==`, unit test `TestCanaryHashedProbeIsTheFixedPublicConstant`,
  guide 8.8 check 5), so the scan allowlists exactly that string and only in the probe entries (`reqType modify`,
  `W_cred`, a pending canary DN, `reqResult 19`); every other hash stays 0. The T-028 proof still passes on it
  (77/77).
- **T024-F2 (refines AC-010c (a)).** For one client the D8d per-client write concurrency (one in flight) answers
  the second request first ("client write budget exhausted"); the T-023 per-target lock is the layer behind it
  (it answers when the concurrency is raised: mutation `drop-client-concurrency`). With both removed the second
  request reaches slapd, which still lets only one Password Modify succeed (50 → 403, 2 sent: the LDAP half of E-17
  through the app). The 429 message names the budget, not the target.

Not covered here: Keycloak (the harness's in-process IdP signs the tokens; the password never reaches the IdP), the
UI as a container (`docker logs` of a UI image: the server ran in-process, its log captured whole), multi-provider
(R-3 stays one provider), E-22 and E-14, `pwdInHistory` (not provable through an initial set, R-7), the 60 s cycle
firing during the run (the run is shorter), and GitHub Actions.

## 3. Not verified

§2e(2026-10-13)가 E-07–E-12·E-16·E-17·E-20·E-21·E-23을 실측했다(E-17·E-12·E-13은 LDAP 직접 경로·slapd 로그 부분만). 남은 것: E-01–E-06, E-13(전체), E-14, E-15, E-18, E-19, E-22와 E-17의 앱 경로 절반. (2026-10-14 T-028, §2j: E-21의 설정 읽기 신원과 AC-010b의 직접 검사 부분을 앱 검사 코드로 실측; E-22는 `setPassword`가 열리지 않아 여전히 미실측.) (2026-10-14 T-024, §2k: E-13을 `live` 시험 서버(프로세스 안 UI)·slapd 로그·accesslog(rootdn·`M`) 범위에서, E-17 앱 경로 절반(한 provider), E-10 앱 경로를 실측 — E-13의 Keycloak·UI 컨테이너 부분은 아님. 여전히 미실측: Keycloak 컨테이너 로그(토큰은 하니스 내장 IdP), UI 컨테이너 `docker logs`(서버는 프로세스 안에서 실행, 로그 전체를 수집), 다중 provider, E-22·E-14, `pwdInHistory`, 실행 중 60초 주기 발화, GitHub Actions. T024-F1은 2026-10-14 결정(프로브 유지, 공개 상수로 고정·허용 목록).) §2b의 T-015 드릴이 부수적으로 본 것: E-05(그룹 `cn` 직접 replace -> `Naming violation (64)`), E-06의 `W_lock` 직접 쓰기 거부, E-07의 `W_lock` 특권 멤버 직접 쓰기(필터 없는 fixture에서 성공), E-15의 앱 경로 해제 우회 5종, E-19의 duration 0 잠금 값 형태(**마커와 다름**, F-1). 이것들은 T-002의 정식 실측을 대체하지 않는다.
이 패키지 작성 시점의 원문: §2 전부(E-01–E-23). 이 패키지 작성 시점에는 컨테이너를 실행하지 않았다. Revision 1에서 E-08·E-11·E-12·E-13·E-15를 넓히고 E-16–E-19를 추가했고, Revision 2에서 E-15·E-19의 목적을 해제 미개방 확인으로 바꾸고 E-20–E-23을 추가했다. 이 실험들이 닫는 출하 차단 위험은 CHANGE.md "Ship-gating open risks"(R-1–R-8).

T-015 드릴의 Not verified: GitHub Actions 러너에서의 실행(로컬 Docker Desktop에서만 실행; CI 결과는 PR에서), `MACHINE_WRITE_GROUP_SEED_DN`의 `olcMemberOfDangling` 경로(E-04, 드릴은 placeholder 항목을 만들어 둠), 차트의 `MACHINE_WRITE_GROUP_SEED_DN` 배선(2cd19eb로 `ui.machineAuth.write.groupSeedDN` 추가, 렌더 시험은 통과; 차트 `allowedClients` 스키마는 여전히 읽기 scope만 허용해 차트로 쓰기 scope 자체를 줄 수 없음), T-005의 security-reviewer 1라운드와 Class D 독립 검토(미실시).
