# 머신 쓰기 LDAP 계정과 쓰기 ACL (운영자 가이드, 설계 단위 T-020)

머신(bearer) 쓰기는 읽기 신원 `M`과 **다른** 별도 LDAP 계정으로만 실행된다(REQ-002, D3). 이 문서는 그 계정과 ACL 조각의
확정 LDIF·적용·확인·롤백 절차다. 읽기 계정은 [machine-ldap-account.md](machine-ldap-account.md)이고, 이 문서는 그 위에 얹힌다.

> **이 문서는 아무 쓰기 오퍼레이션도 열지 않는다.** `MACHINE_WRITE_ENABLED`와 쓰기 오퍼레이션 표(`machineWriteOps`)는 아직
> 비어 있고(T-013이 마지막에 연다), 이 ACL을 적용해도 ldapium의 머신 요청 경로는 달라지지 않는다. 계정과 ACL은 먼저 준비해 두는 것이다.
> ACL의 라이브 증명 전체는 T-021(예정)이고, 이 문서에 딸린 짧은 스모크
> [`scripts/test/test-machine-write-acl-smoke.sh`](../scripts/test/test-machine-write-acl-smoke.sh)는 아직 CI에 연결되어 있지 않다.

- 설계·근거: [CHANGE.md](changes/machine-write-scope/CHANGE.md) REQ-002/004/011, D1/D3/D11/D17/D18/D19/D26, AC-002/003(d)/008/010,
  Resolved Q3(구획 3개)·Q6(ACL 순서), 부록 A(오퍼레이션별 속성). [ADR.md](changes/machine-write-scope/ADR.md), [TASKS.md](changes/machine-write-scope/TASKS.md) `T-020`.
- 이 ACL 변경은 Class D다. 적용 전 [`AGENTS.md`](../AGENTS.md)와 `.agents/skills/ldapium-directory-change/SKILL.md`를 읽는다.
- 확정 LDIF(문서와 같은 텍스트):
  [`write-data.ldif`](../scripts/test/fixtures/machine-acl/write-data.ldif),
  [`write-lock.ldif`](../scripts/test/fixtures/machine-acl/write-lock.ldif);
  v2c(`W_cred`, 8절): [`write-data-cred.ldif`](../scripts/test/fixtures/machine-acl/write-data-cred.ldif),
  [`write-cred.ldif`](../scripts/test/fixtures/machine-acl/write-cred.ldif);
  v2c 전제 검사(8.8): [`config-reader.ldif`](../scripts/test/fixtures/machine-acl/config-reader.ldif),
  [`config-reader-main.ldif`](../scripts/test/fixtures/machine-acl/config-reader-main.ldif).

> **모든 LDAP 노드에 적용하고 6절로 확인하기 전에는 쓰기를 켜지 않는다.** `cn=config`의 ACL은 노드마다 따로이며 복제되지 않는다
> ([machine-ldap-account.md](machine-ldap-account.md) 12절). 규칙이 없는 노드에서 쓰기 계정은 평범한 사용자라 `by users read`로 전체를 읽고
> `by self write`로 자기 항목과 비밀번호를 바꾼다.

## 1. 무엇을 보장하고 무엇을 보장하지 않는가

| 기호 | 의미 |
|---|---|
| `M` | 읽기 전용 머신 계정([machine-ldap-account.md](machine-ldap-account.md)). 이 문서에서 **변하지 않는다** |
| `W_data` (`$WDATA_DN`) | 사용자·그룹 멤버십 쓰기 계정(`createUser`/`patchUser`/`deleteUser`/`addGroupMember`/`removeGroupMember`) |
| `W_lock` (`$WLOCK_DN`) | 잠금 계정(`pwdAccountLockedTime` 하나만, v2b 단계). 첫 출하에는 쓰이지 않지만 같은 방식으로 준비할 수 있다. 잠금은 v2b의 `lockUser`(T-014로 열림, `directory.users.lock`을 상한에 준 client만)만 쓰고, 해제는 사람 경로 전용이다(D379-7) |
| `W_cred` (`$WCRED_DN`) | 비밀번호 계정(v2c, 8절): `W_data`가 대기 표지·대기 정책과 함께 만든 비밀번호 없는 계정의 **초기** `userPassword`만 설정하고, 그 뒤 표지·정책 값만 지운다 |
| `$WRITE_DN` | 쓰기 subtree: **모든 client 상한의 합집합**을 덮는 한 지점 |
| `$SYSTEM_DN` | `M`·`W_*`·서비스 계정을 두는 컨테이너(예 `ou=system,<root>`). `$WRITE_DN`이 넓어져도 쓰기 신원이 닿지 않게 하는 거부 백스톱 |
| `$REPL_DN` | 복제 신원 항목 `cn=replicator,<root>`(엔트리포인트의 예약 DN, `image/entrypoint.sh`의 `ri_dn`). 루트 바로 아래라 `$SYSTEM_DN` 밖이다: 같은 이유의 거부 백스톱 |

ACL 조각을 적용하면 `W_data`는:

- `$WRITE_DN` 아래에서 **항목을 만들고 지우며**(`entry`·`children` write), 닫힌 속성 목록
  `uid, cn, sn, givenName, mail, departmentNumber, o, ou, description, member`만 쓴다(부록 A: createUser·patchUser·그룹 멤버 add/remove의 합집합, 그리고 v2b `patchGroup`의 `description`).
  `description`은 별도 규칙 `{5}`의 `filter=(objectClass=groupOfNames)`로 **그룹 항목에서만** 쓴다(#394). 사용자 항목의 `description` modify는 앱 가드가 없어도 50으로 거부된다(실측). 단, 출하 상태(`olcAddContentAcl` 기본 FALSE)의 Add는 속성별 ACL을 보지 않으므로 생성 시점의 `description`은 여전히 앱의 닫힌 본문만 막는다.
- `objectClass`는 **`add` 수준**만 받는다(D18). `replace`·`delete`는 거부된다. 그러나 ACL은 **항목 생성(Add)과 기존 항목에 값을 더하는 modify를
  구별하지 못한다**: 기존 항목에 `objectClass` 값을 **추가**하는 modify는 ACL을 통과한다(스모크가 이 한계를 고정한다).
  수정 경로가 `objectClass`를 절대 보내지 않게 하는 것은 앱 가드(T-012)다.
- 비밀 속성(`userPassword`, `pwdHistory` 등 `M`의 목록과 같음), `memberOf`, 모든 `pwd*` 상태 속성(잠금 포함)에는 **읽기·쓰기 모두 `none`**이다.
  `$WRITE_DN` 안의 나머지 속성(운영 속성 포함)은 읽기만 된다(`If-Match` assertion과 읽기에 필요). `telephoneNumber` 등 목록 밖 속성 쓰기는 거부된다.
- `$SYSTEM_DN` 아래(`M`, 자기 자신, `W_lock`, 서비스 계정), `$REPL_DN`(복제 신원 항목)과 `$WRITE_DN` **밖**은 읽지도 쓰지도 못한다. 이미지의 `by users read`·`by self write`는 닿지 않는다.
- `cn=config`, `cn=Monitor`, `cn=accesslog`, 관리자 항목에는 접근이 없다.

ACL이 **보장하지 않는 것**(앱 가드 하나뿐인 것, D17/D19/D26):

- **client 간 격리.** `W_data`는 모든 client가 공유하는 한 DN이라 ACL은 client A와 B의 subtree를 구별하지 못한다. 합집합 **밖**은 ACL이 막지만,
  합집합 **안**에서 A가 B의 subtree에 쓰는 것을 막는 것은 앱의 client별 상한(`MACHINE_WRITE_SUBTREES`) 가드뿐이다. 하드 격리가 필요하면 subtree마다
  별도 `W` DN이 필요하고 이는 후속 변경(D4 확장)이다.
- **보호 DN·대상 타입.** `$WRITE_DN` 안에 관리자·서비스 계정·`M`·`W_*`·그룹이 있어도 ACL은 `W_data`가 거기에 쓰는 것을 막지 않는다(`$SYSTEM_DN`
  백스톱은 `$SYSTEM_DN`과 `$REPL_DN`에 한정이다. **`cn=replicator`와 다른 모든 보호 신원은 `$WRITE_DN` 밖에 있거나 이 두 곳에 있어야 한다**: 루트를 `$WRITE_DN`으로 쓰면 그 밖의 신원 항목은 지킬 수 없다). 그 DN들을 쓰기 신원으로부터 지키고(D19) 사용자 DN에는 `inetOrgPerson`, 그룹에는 `groupOfNames`인지 단언하는 것(T-018),
  slapd 관점의 `entryDN`/`entryUUID` 정체성 대조(D26)는 앱 몫이다. **계정을 `$WRITE_DN`과 사용자·그룹 컨테이너 밖에 두는 것이 운영자의 몫이다.**
- **어떤 항목을 지우는가.** `entry`/`children` write는 `$WRITE_DN` 아래 모든 항목(컨테이너, 비어 있지 않은 항목 포함)에 대한 add/delete다. 컨테이너·루트 삭제 거부,
  리프만 삭제(D8e)는 앱 가드이고 비어 있지 않은 항목의 삭제 거부는 slapd(`notAllowedOnNonLeaf`)다.
- **`objectClass` 값 추가.** 위 두 번째 항목.
- **이름 변경·이동(ModifyDN).** `entry`/`children` write는 add·delete와 **modrdn·newsuperior를 구별하지 못한다**(`=azrscxd` 같은 세부 수준으로도 막히지 않는 것을
  라이브로 확인했고 스모크가 고정한다). `W_data`는 `$WRITE_DN` 안의 어떤 항목이든 이름을 바꾸거나 다른 컨테이너·다른 client subtree로 옮길 수 있다. 부록 A에는
  이름 변경 오퍼레이션이 없으므로 **앱은 어떤 머신 경로로도 rename/move를 노출해서는 안 된다**(`moveEntry`는 영구 거부, D2). 앱 가드에 버그가 있으면 항목이 client
  subtree 사이로 옮겨지고 DN 정체성이 바뀐다.
- **구획별 피해 반경(앱 가드가 뚫렸을 때).** `W_data`: `$WRITE_DN` 안의 모든 항목을 만들고 지우고 이동하며, 닫힌 속성 9개를 쓰고, **기존 항목에 보조 objectClass를 임의로
  추가**할 수 있다. 항목 **생성** 시의 objectClass는 ACL이 검사하지 않는다: 예를 들어 `groupOfNames` 그룹을 `member=<관리자 DN>`으로 만드는 것도 ACL은 막지 못한다.
  다만 속성 ACL이 각 클래스가 실을 수 있는 값을 묶는다(비밀·`pwd*`·`memberOf`는 어떤 클래스로도 못 쓰고, 목록 밖 속성은 읽기뿐이다). `W_lock`: `$WRITE_DN` 안
  모든 항목의 `pwdAccountLockedTime`을 걸고 풀 수 있다(서비스 거부: 사용자 로그인 차단). 이름 변경·생성·삭제·다른 속성은 못 한다. 두 계정 모두 `$SYSTEM_DN`·
  `$REPL_DN`·`$WRITE_DN` 밖은 닿지 않는다.
- **요청 단위 귀속.** LDAP 로그에는 `W_data`만 보인다. client 귀속은 앱 감사(D6)다.
- **파생 쓰기.** `memberOf`·refint 같은 오버레이의 내부 쓰기는 요청 신원의 속성 ACL로 막히지 않는다([EVIDENCE.md](changes/machine-write-scope/EVIDENCE.md) T-002).
  `memberOf`에 대한 직접 modify는 ACL보다 먼저 스키마(`NO-USER-MODIFICATION`)가 constraint violation(19)로 거부한다.

`W_lock`: `$WRITE_DN` 아래에서 `pwdAccountLockedTime`만 쓰고 나머지는 읽기만 한다. 항목 생성·삭제와 비밀·다른 `pwd*`·`memberOf`는 `none`이다.
어떤 사용자를 잠그는가(자기 자신·관리자·`M` 제외)는 앱 가드다.

## 2. 정해진 순서 (REQ-011, D11, Resolved Q6)

`cn=config`의 메인 DB `olcAccess`는 위에서부터 첫 일치 규칙을 쓴다. 규칙 묶음은 모두 `to <대상>` + `by dn.exact="<자기 DN>" …` + `by * break`로
**자기 DN에만** 작용하므로 서로 영향이 없다. 정해진 순서는 다음이다.

```text
{0}            복제 신원 규칙 (LDAP_REPLICATION_IDENTITY=prepare/dedicated일 때만; 항상 첫 값)
{0}..{2} 또는 {1}..{3}   M 읽기 규칙 3개 (machine-ldap-account.md 5절/5.1)
다음 9개        W_data 규칙 9개 (write-data.ldif); v2c를 켜면 그 {1}과 {2} 사이에 write-data-cred.ldif 3+그룹 수 개 (8절)
다음 6개        W_lock 규칙 6개 (write-lock.ldif, 선택)
다음 7개        W_cred 규칙 7개 (write-cred.ldif, v2c만, 8절)
다음 1개        설정 읽기 신원의 거부 규칙 (config-reader-main.ldif, v2c 고정 provider만, 8.8)
그 뒤           이미지의 기존 규칙, 원래 순서 그대로 (by self write / by users read / LDAP_ANONYMOUS_READ_BASE 규칙 …)
```

**쓰기 조각은 `M` 묶음 바로 뒤, 이미지의 모든 기존 allow 규칙 앞**에 둔다. 인덱스는 하드코딩하지 않고 설치 시 `olcAccess`를 읽어 계산한다
(복제 신원 유무·익명 읽기 분기에 따라 달라진다). 계산 규칙: **맨 앞에서부터 이어지는 값 중 복제 신원·`M`·`W_data`·`W_lock`의 DN을 이름으로 가진 값의 개수**가
시작 인덱스다. 두 조각 사이의 순서는 상관없다(서로 다른 DN에만 작용한다).

- `M` 규칙이 이미 있어야 위 배치가 된다. `M` 없이 쓰기 조각만 먼저 넣으면 쓰기 규칙이 `{0}`부터 놓이고, 나중에 `M` 가이드 5절(`{0}`–`{2}` 삽입)로 `M` 규칙을 넣으면 쓰기 규칙이 뒤로 밀려 같은 배치가 된다(`M` 규칙은 `M` DN에만 작용하므로 순서가 결과를 바꾸지 않는다). 이 순서의 라이브 증명은 이 스모크의 범위가 아니다(T-021).
- `prepare`/`dedicated`와 **공존한다**(이전의 "비공존" 전제는 폐기). `prepare`가 자기 규칙을 `{0}`에 넣으면 이미 있던 `M`·`W_*` 규칙은 한 칸 밀려
  같은 배치가 되고, 재시작은 "신원 규칙이 첫 값" 검사를 그대로 통과한다. 복제 규칙이 `{0}`인 노드에 이 가이드의 명령을 쓰면 4.2의 계산이 그 한 칸을 포함한다.
- `W` 규칙을 이미지 규칙 **뒤**에 붙이면 안 된다: `to attrs=userPassword,shadowLastChange by self write …`와 `to * by self write by users read`가 먼저 적용되어
  쓰기 신원이 자기 비밀번호·자기 항목을 바꾸고 범위 밖 전체를 읽는다. 조각의 마지막 규칙(`to * … none`)이 그 두 규칙이 쓰기 신원에 닿지 않게 막는다.

## 3. 준비

[machine-ldap-account.md](machine-ldap-account.md) 3절과 같은 변수·관리자 비밀번호 파일(`/tmp/.pw-admin`)을 쓴다. 추가 변수:

```sh
EXEC="docker exec -i ldapium"
ROOT_DN='dc=example,dc=org'
SYSTEM_DN="ou=system,$ROOT_DN"
WDATA_DN="uid=machine-write-data,$SYSTEM_DN"
WLOCK_DN="uid=machine-write-lock,$SYSTEM_DN"
WRITE_DN="ou=people,$ROOT_DN"
REPL_DN="cn=replicator,$ROOT_DN"   # image/entrypoint.sh의 예약 DN(스모크가 고정)
CFG_URI='ldapi://%2Fvar%2Flib%2Fopenldap%2Frun%2Fldapi'
MACHINE_DN="uid=machine,$SYSTEM_DN"
MAIN_DB_DN='olcDatabase={1}mdb,cn=config'
# v2c(8절)에서만:
WCRED_DN="uid=machine-write-cred,$SYSTEM_DN"
CRED_DN="ou=people,$ROOT_DN"                               # MACHINE_WRITE_CRED_SUBTREES (WRITE_DN 안의 한 지점)
READER_DN="uid=machine-cred-acl-reader,$SYSTEM_DN"         # MACHINE_WRITE_CRED_ACL_READER_DN (8.8)
PENDING_POLICY_DN="cn=credential-pending,ou=policies,$ROOT_DN"   # MACHINE_WRITE_CRED_PENDING_POLICY_DN
WCRED_POLICY_DN="cn=machine-writers,ou=policies,$ROOT_DN"  # W_cred 무잠금 정책(8.1, Q17; 9.1의 W_* 정책과 같은 항목)
PRIV_GROUPS="cn=admins,ou=groups,$ROOT_DN"                 # MACHINE_WRITE_PRIVILEGED_GROUPS와 같은 값(; 구분)
```

- `WRITE_DN`은 **모든 client 쓰기 상한의 합집합을 덮는 가장 좁은 항목**이다. 사용자와 그룹을 모두 쓰면(`addGroupMember`) 그룹 컨테이너도 덮어야 하므로
  보통 둘의 공통 부모이거나 루트다. 루트로 잡으면 `cn=replicator`(`$REPL_DN`)와 관리자·서비스 계정 항목이 `$WRITE_DN` 안에 들어오므로 **`$SYSTEM_DN`·`$REPL_DN` 거부 규칙만이 지킨다** — 그 밖의 보호 신원 항목은 `$SYSTEM_DN` 아래로 옮긴다. 서로 떨어진 subtree가 필요하면 공통 부모로 잡는다(`$SYSTEM_DN` 백스톱이 계정을 지킨다). 규칙의 `dn.subtree`는 한 지점이다.
- `WDATA_DN`/`WLOCK_DN`은 `M`·관리자·복제 신원·`BACKUP_ADMIN_DNS`·프로파일 관리자·`LDAP_SERVICE_ACCOUNT_DN`·rootdn과 `ParseDN` 동등이면 안 된다(기동 거부, REQ-002).
  서로도, `M`과도 달라야 한다. **`SYSTEM_DN` 아래 또는 `WRITE_DN` 밖**에 둔다.
- DN에 `|`, `&`, `\`가 들어 있으면 아래의 `sed` 치환을 쓰지 말고 LDIF를 직접 편집한다.
- 비밀번호를 argv·환경변수·채팅·이슈에 넣지 않는다. 0600 파일과 stdin만 쓴다.

## 4. 계정 만들기와 ACL 적용

### 4.1 계정 (강한 비밀번호, 각 계정마다 따로)

```sh
umask 077
openssl rand -base64 33 | tr -d '\n' > wdata.pw
openssl rand -base64 33 | tr -d '\n' > wlock.pw
printf 'dn: %s\nobjectClass: inetOrgPerson\nuid: machine-write-data\ncn: machine-write-data\nsn: machine-write-data\nuserPassword:: %s\n' "$WDATA_DN" "$(base64 < wdata.pw | tr -d '\n')" | $EXEC ldapadd -x -H ldap://127.0.0.1 -D "cn=admin,$ROOT_DN" -y /tmp/.pw-admin
printf 'dn: %s\nobjectClass: inetOrgPerson\nuid: machine-write-lock\ncn: machine-write-lock\nsn: machine-write-lock\nuserPassword:: %s\n' "$WLOCK_DN" "$(base64 < wlock.pw | tr -d '\n')" | $EXEC ldapadd -x -H ldap://127.0.0.1 -D "cn=admin,$ROOT_DN" -y /tmp/.pw-admin
$EXEC sh -c 'umask 077; cat > /tmp/.pw-wdata' < wdata.pw
$EXEC sh -c 'umask 077; cat > /tmp/.pw-wlock' < wlock.pw
```

`ou=system`이 없으면 먼저 만든다([machine-ldap-account.md](machine-ldap-account.md) 4절). 계정만으로는 권한이 없고 이 시점에서 평범한 사용자와 같다
(`by users read`, 자기 비밀번호 쓰기). **4.2를 바로 이어서 적용한다.** 틀린 비밀번호로 ldapium이 계속 bind하면 `pwdLockout` 정책으로 계정이 잠긴다
(`M`과 같은 제한, machine-ldap-account.md 13절).

### 4.2 `W_data` 적용 (시작 인덱스 계산, 중복 적용 거부)

`W_data` LDIF(저장소의 확정 파일은 [`write-data.ldif`](../scripts/test/fixtures/machine-acl/write-data.ldif); 아래 블록과 같고 스모크가 블록째 비교한다).
연속 줄의 앞 공백 두 칸은 필수다.

```ldif
dn: @MAIN_DB_DN@
changetype: modify
add: olcAccess
olcAccess: {0}to dn.subtree="@SYSTEM_DN@"
  by dn.exact="@WDATA_DN@" none
  by * break
olcAccess: {1}to dn.exact="@REPL_DN@"
  by dn.exact="@WDATA_DN@" none
  by * break
olcAccess: {2}to attrs=userPassword,shadowLastChange,pwdHistory,pKCS8PrivateKey,userPKCS12,oathSecret,oathEncKey,oathTokenPIN,memberOf,pwdAccountLockedTime,pwdChangedTime,pwdFailureTime,pwdGraceUseTime,pwdReset,pwdPolicySubentry,pwdStartTime,pwdEndTime,pwdLastSuccess
  by dn.exact="@WDATA_DN@" none
  by * break
olcAccess: {3}to dn.subtree="@WRITE_DN@" attrs=entry,children
  by dn.exact="@WDATA_DN@" write
  by * break
olcAccess: {4}to dn.subtree="@WRITE_DN@" attrs=objectClass
  by dn.exact="@WDATA_DN@" add
  by * break
olcAccess: {5}to dn.subtree="@WRITE_DN@" filter=(objectClass=groupOfNames) attrs=description
  by dn.exact="@WDATA_DN@" write
  by * break
olcAccess: {6}to dn.subtree="@WRITE_DN@" attrs=uid,cn,sn,givenName,mail,departmentNumber,o,ou,member
  by dn.exact="@WDATA_DN@" write
  by * break
olcAccess: {7}to dn.subtree="@WRITE_DN@"
  by dn.exact="@WDATA_DN@" read
  by * break
olcAccess: {8}to *
  by dn.exact="@WDATA_DN@" none
  by * break
```

이 블록을 `write-data.ldif`로 저장한다(저장소의 파일에는 머리 주석이 더 있다). 아래 블록은 (1) 시작 인덱스 `BASE`를 계산하고 — 맨 앞에서부터 이어지는 값 중
복제 신원·`M`·`W_data`·`W_lock`의 DN을 이름으로 가진 값의 개수다. `cn=replicator,<root>`는 엔트리포인트의 예약 DN이다(`image/entrypoint.sh`의 `ri_dn`;
바뀌면 `$REPL_DN`과 이 계산을 같이 바꾼다) — (2) **그 계정의 DN이 이미 `olcAccess`에 있으면 아무것도 바꾸지 않고 거부하며**(같은 LDIF를 두 번 적용하면 중복 규칙이 생겨 7절의
롤백이 거부한다), (3) 아니면 인덱스를 `BASE`만큼 밀어 적용한다. 온라인으로 즉시 적용된다(재시작 불필요). 호스트의 `awk`와 컨테이너 안 `ldapsearch`/`ldapmodify`를 쓴다.
`write-data.ldif`가 있는 디렉터리에서 실행한다.

```sh
FRAG="${FRAG:-write-data.ldif}"; WHO="${WHO:-$WDATA_DN}"   # W_lock은 4.3
ACLS=$($EXEC env MAIN_DB_DN="$MAIN_DB_DN" CFG_URI="$CFG_URI" sh -c 'ldapsearch -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin -LLL -o ldif-wrap=no -b "$MAIN_DB_DN" -s base olcAccess')
BASE=$(printf '%s\n' "$ACLS" | awk -v m="dn.exact=\"$MACHINE_DN\"" -v r="dn.exact=\"$REPL_DN\"" -v d="dn.exact=\"$WDATA_DN\"" -v l="dn.exact=\"$WLOCK_DN\"" '/^olcAccess: \{[0-9]+\}/ { if (stop) next; if (index($0,m) || index($0,r) || index($0,d) || index($0,l)) n++; else stop=1 } END { print n+0 }')
PRESENT=$(printf '%s\n' "$ACLS" | awk -v x="dn.exact=\"$WHO\"" 'index($0,x) { n++ } END { print n+0 }')
if [ "$PRESENT" != 0 ]; then
  echo "refusing: $PRESENT olcAccess values already name $WHO; roll back first (section 7)" >&2
else
  awk -v b="$BASE" '/^olcAccess: \{[0-9]+\}/ { s=$0; sub(/^olcAccess: \{/,"",s); i=s+0; sub(/^[0-9]+\}/,"",s); print "olcAccess: {" (i+b) "}" s; next } { print }' "$FRAG" | $EXEC env WDATA_DN="$WDATA_DN" WLOCK_DN="$WLOCK_DN" WRITE_DN="$WRITE_DN" SYSTEM_DN="$SYSTEM_DN" REPL_DN="$REPL_DN" MAIN_DB_DN="$MAIN_DB_DN" CFG_URI="$CFG_URI" sh -c 'sed -e "s|@WDATA_DN@|$WDATA_DN|g" -e "s|@WLOCK_DN@|$WLOCK_DN|g" -e "s|@WRITE_DN@|$WRITE_DN|g" -e "s|@SYSTEM_DN@|$SYSTEM_DN|g" -e "s|@REPL_DN@|$REPL_DN|g" -e "s|@MAIN_DB_DN@|$MAIN_DB_DN|g" | ldapmodify -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin'
fi
echo "BASE=$BASE"
```

`BASE`를 6.1에서 읽은 `olcAccess`와 대조한다(`M`을 설치했고 복제 신원이 없으면 `3`, 복제 신원이 `{0}`이면 `4`).

### 4.3 `W_lock` 적용 (선택, v2b)

잠금을 쓰지 않는 배포는 건너뛴다. `MACHINE_WRITE_LOCK_ENABLED=false`에서 `MACHINE_ALLOWED_CLIENTS`가 `directory.users.lock`을 상한에 쓰면 기동이 실패한다(REQ-006).
머신 `lockUser`는 `W_lock`으로 bind하기 전에 `M`이 대상의 `memberOf`와 각 `MACHINE_WRITE_PRIVILEGED_GROUPS` 그룹의 `member` 목록을 읽어, 하나라도 **직접** 속하면 403으로 거부한다(D379-8, D379-17). 그룹을 읽을 수 없으면(`M` ACL이 `member`를 숨김 포함) 거부이고, lock scope 상한에는 비어 있지 않은 `MACHINE_WRITE_PRIVILEGED_GROUPS`가 필요하다.
`memberOf` 값이 ASCII가 아니거나 파싱되지 않으면(OID 타입·이상한 공백·BER 포함) 특권 여부를 증명할 수 없으므로 그 사용자의 `lockUser`는 거부된다(fail closed, 보안이 아니라 가용성 영향: 그런 DN의 그룹에 속한 사용자는 머신으로 잠글 수 없다).
중첩 그룹 멤버십과 읽은 뒤 추가된 멤버십(TOCTOU)은 이 검사가 보지 못한다(수용한 잔여 위험, T-015 드릴이 실측으로 확인: 중첩 그룹 멤버는 잠긴다). 이 검사는 애플리케이션 보강이고, 위 ACL 조각에는 특권 그룹 filter가 없다(라이브 증명 전에는 ACL 백스톱이라 부르지 않는다).
정적 `openapi.json`은 `MACHINE_WRITE_ENABLED`가 꺼져 있어도 `createGroup`·`patchGroup`·`deleteGroup`·`lockUser`(앞의 다섯 개와 같이)에 `machineBearer`/`x-machine-scope`를 선언한다. 문서일 뿐 동작은 그대로이며, 스위치가 꺼져 있으면 모두 403 `scope_denied`·bind 0이다.
머신 경로에는 잠금 해제가 없다: `directory.users.unlock`은 상한에 쓸 수 없고 `unlockUser`는 어떤 표에도 없다(D379-7, AC-005b). 4.2의 블록을 `FRAG=write-lock.ldif WHO="$WLOCK_DN"`으로 실행한다(`W_data`의 9개가 `BASE`에 더해져 `W_lock`이 그 뒤에 놓인다).

```ldif
dn: @MAIN_DB_DN@
changetype: modify
add: olcAccess
olcAccess: {0}to dn.subtree="@SYSTEM_DN@"
  by dn.exact="@WLOCK_DN@" none
  by * break
olcAccess: {1}to dn.exact="@REPL_DN@"
  by dn.exact="@WLOCK_DN@" none
  by * break
olcAccess: {2}to attrs=userPassword,shadowLastChange,pwdHistory,pKCS8PrivateKey,userPKCS12,oathSecret,oathEncKey,oathTokenPIN,memberOf,pwdChangedTime,pwdFailureTime,pwdGraceUseTime,pwdReset,pwdPolicySubentry,pwdStartTime,pwdEndTime,pwdLastSuccess
  by dn.exact="@WLOCK_DN@" none
  by * break
olcAccess: {3}to dn.subtree="@WRITE_DN@" attrs=pwdAccountLockedTime
  by dn.exact="@WLOCK_DN@" add
  by * break
olcAccess: {4}to dn.subtree="@WRITE_DN@"
  by dn.exact="@WLOCK_DN@" read
  by * break
olcAccess: {5}to *
  by dn.exact="@WLOCK_DN@" none
  by * break
```

`W_lock`은 `pwdAccountLockedTime`을 **`add`** 수준으로만 받는다(#394). slapd는 Delete와 Replace 모두에 삭제 권한을 검사하므로 `W_lock` 자격 증명으로는 잠금을 **해제하거나 덮어쓸 수 없다**(값 삭제·속성 삭제·Replace 모두 50, 실측). 머신 `lockUser`는 Add로 표지를 쓰고, 이미 같은 표지가 있으면(`attributeOrValueExists`, 20) 성공으로 본다. ppolicy가 타임스탬프로 잠근 계정은 단일 값 속성이라 Add가 19로 거부되고 머신 `lockUser`는 409를 돌려준다(계정은 잠긴 채이며 표지로 바꾸려면 사람이 한다). ppolicy가 이 속성의 변경에 `manage`를 요구하지 않음을 라이브로 확인했다. 이전 조각을 적용한 노드는 7절의 "#394 이전 조각에서 올리기"대로 되돌린 뒤 4.2·4.3으로 다시 적용한다(점검 스크립트가 이전 조각을 불일치로 보고한다).

### 4.4 그룹 멤버십 쓰기는 `MACHINE_WRITE_GROUPS`가 있어야 한다 (안전한 기본값)

`addGroupMember`/`removeGroupMember`는 client별 `MACHINE_WRITE_GROUPS`(정확한 그룹 DN 목록, `MACHINE_WRITE_PRIVILEGED_GROUPS` 필수)에 있는 그룹에만 허용됩니다. 목록이 없거나 비어 있으면 그 client의 멤버 추가·제거는 **전부 403**입니다(허용 목록 비어 있음 = 거부). 사용자 쓰기(`createUser`/`patchUser`/`deleteUser`)는 `MACHINE_WRITE_SUBTREES`만으로 동작하고 이 목록과 무관합니다.

## 5. 속성이 여기서 나온 곳

`W_data`의 닫힌 목록은 [부록 A(T-002 확정 목록)](changes/machine-write-scope/CHANGE.md)의 합집합이다: createUser(`uid, cn, sn`; 선택 `givenName, mail, departmentNumber, o, ou`),
patchUser(`cn, sn, givenName, mail, departmentNumber, o, ou` Replace), 그룹 멤버 add/remove(`member`), v2b `patchGroup`(`description`), 생성 시 `objectClass`. `W_lock`: `pwdAccountLockedTime`.
`pwd*` 상태 속성 목록(`pwdAccountLockedTime`, `pwdChangedTime`, `pwdFailureTime`, `pwdGraceUseTime`, `pwdReset`, `pwdPolicySubentry`, `pwdStartTime`, `pwdEndTime`,
`pwdLastSuccess`)과 비밀 속성 8개는 이 이미지의 스키마·오버레이에서 도출했다(도출 명령은 machine-ldap-account.md 9절). 스키마·오버레이를 바꿨다면 다시 도출해 `{1}`의 목록에 더한다.
v2b `patchGroup`(D379-5)이 `description`을 더했고, #394가 이를 그룹 전용 규칙 `{5}`(`filter=(objectClass=groupOfNames)`)로 분리했다(조각 8개 → 9개). 오퍼레이션은 T-014로 열렸다. 이 조각을 적용하지 않은 배포에서는 `patchGroup`이 `W_data`의 ACL 거부(insufficientAccessRights)로 실패하므로, `directory.groups.update`를 상한에 주기 전에 이 조각을 모든 노드에 다시 적용한다.
부록 A가 다시 바뀌면 이 조각과 이 문서를 같이 바꾼다.

## 6. 적용 후 확인 (모든 노드)

### 6.1 `olcAccess` 읽기 (필수)

```sh
$EXEC ldapsearch -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin -LLL -o ldif-wrap=no -b "$MAIN_DB_DN" -s base olcAccess
```

기대: `[복제 신원 규칙] · M 3개 · W_data 9개 · [W_lock 6개] · 이미지 기존 규칙(원래 순서)`. 이 순서를 눈으로 대조하는 대신 읽기 전용 점검 스크립트
[`scripts/check-machine-write-acl.sh`](../scripts/check-machine-write-acl.sh)를 **모든 노드**에서 돌린다(`--container`/`--kube-pod`/`--input`, 사용법은 스크립트 머리말).
순서·누락·중복·비밀 속성 `none`·보호 항목 도달 불가 중 하나라도 어긋나면 비0으로 끝나고, 읽지 못했을 때도 통과로 처리하지 않는다(T-023). `W_data` DN이 들어간 값은 **정확히 9개**이고 연속이다.
`W_lock`은 정확히 6개다. 읽은 순서가 다르면 규칙을 쓰지 말고 7절로 되돌린다. v2c를 켠 노드의 기대 배치와 점검 인자는 8.6이다.

### 6.2 쓰기 계정으로 직접 확인 (허용과 거부)

허용(`W_data`, `$WRITE_DN` 안): 항목 add, `mail` replace, 그룹 `member`·`description` 쓰기, 항목 delete. `W_lock`: `pwdAccountLockedTime` 추가(설정)만. 해제(삭제·Replace)는 50이다.

```sh
printf 'dn: uid=probe,%s\nchangetype: add\nobjectClass: top\nobjectClass: person\nobjectClass: organizationalPerson\nobjectClass: inetOrgPerson\nuid: probe\ncn: probe\nsn: probe\n' "$WRITE_DN" | $EXEC ldapmodify -x -H ldap://127.0.0.1 -D "$WDATA_DN" -y /tmp/.pw-wdata
```

거부(모두 `Insufficient access (50)`여야 한다): `userPassword` 변경(정책 때문에 옛 값 삭제 + 새 값 추가를 한 modify에 둔 형태만 ACL까지 도달한다. `replace`는
ACL 이전에 정책이 거부해 증명이 못 된다), `objectClass` replace, `telephoneNumber`·그룹의 `owner` 등 목록 밖 속성, `$WRITE_DN` 밖 항목, `M`·`W_*`·관리자 항목, `cn=config`,
`W_data`가 `W_lock`의 `pwdAccountLockedTime`을 쓰는 것, `W_data`가 사용자 항목의 `description`을 쓰는 것. `memberOf` modify는 스키마가 먼저 `Constraint violation (19)`로 거부한다(ACL 증명이 아니다).
`W_data`로 `userPassword`·`pwdAccountLockedTime`·`memberOf`를 **읽어도** 나오지 않는다(관리자는 읽는다).

`M`은 여전히 읽기 전용이다: [machine-ldap-account.md](machine-ldap-account.md) 6.2의 모든 쓰기 시도가 50이고
[`test-machine-acl-readonly-live.py`](../scripts/test/test-machine-acl-readonly-live.py)는 녹색이다. 이 조각은 `M`과 다른 어떤 신원의 접근도 바꾸지 않는다
(조각의 모든 규칙이 `W` DN에만 작용하고 `by * break`로 끝난다).

## 7. 롤백

각 조각의 규칙이 **연속한 9개(`W_data`) / 6개(`W_lock`)이고 모두 그 계정 DN을 이름으로 가질 때만** 인덱스로 지운다. 아니면 거부하고 아무것도 바꾸지 않는다
(밀린 인덱스로 다른 규칙을 지우는 사고 방지). 복제 신원 규칙·`M` 규칙·이미지 규칙은 건드리지 않는다. 롤백하면 쓰기 계정은 일반 사용자로 돌아가므로
**먼저** 쓰기를 끈다(`MACHINE_WRITE_ENABLED=false`로 전 replica 교체). `W_lock`은 `K=6 WHO="$WLOCK_DN"`으로 같은 블록을 쓴다.
v2c 규칙을 넣은 노드는 **먼저 8.7**로 v2c를 되돌린다(그 전에는 `W_data`가 9개가 아니어서 이 블록이 거부한다).

```sh
K="${K:-9}"; WHO="${WHO:-$WDATA_DN}"
FIRST=$($EXEC env MAIN_DB_DN="$MAIN_DB_DN" CFG_URI="$CFG_URI" sh -c 'ldapsearch -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin -LLL -o ldif-wrap=no -b "$MAIN_DB_DN" -s base olcAccess' | awk -v x="dn.exact=\"$WHO\"" -v k="$K" '/^olcAccess: \{[0-9]+\}/ { if (index($0,x)) { s=$0; sub(/^olcAccess: \{/,"",s); i=s+0; if (n == 0) f=i; l=i; n++ } } END { if (n == k && l - f == k - 1) print f }')
if [ -z "$FIRST" ]; then
  echo "refusing: the rules of $WHO are not $K contiguous values" >&2
else
  { printf 'dn: %s\nchangetype: modify\ndelete: olcAccess\n' "$MAIN_DB_DN"; i=$((FIRST + K - 1)); while [ "$i" -ge "$FIRST" ]; do printf 'olcAccess: {%s}\n' "$i"; i=$((i - 1)); done; } | $EXEC env CFG_URI="$CFG_URI" sh -c 'ldapmodify -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin'
fi
```

**#394 이전 조각에서 올리기.** 이전 `W_data` 조각은 규칙 **8개**(`description`이 닫힌 목록 안), 이전 `W_lock` 조각은 지금과 같은 **6개**(`write`)다. 기본값 `K=9`로 이전 `W_data`를 지우면 "not 9 contiguous values"로 거부되므로 `K=8`을 준다: 먼저 `K=6 WHO="$WLOCK_DN"`, 그다음 `K=8 WHO="$WDATA_DN"`. 그 뒤 4.2(`W_data`, 9개)와 4.3(`W_lock`)을 적용하고 6.1을 확인한다. 사이 동안 쓰기 계정은 일반 사용자이므로 위와 같이 먼저 쓰기를 끈다.

롤백 후 6.1을 다시 읽어 `M`·복제·이미지 규칙만 원래대로 남았는지 확인한다(스모크는 적용 전 `olcAccess`와 **바이트 단위로 같게** 돌아감을 확인한다). 계정 항목은 남는다. 완전히 없애려면 관리자로 `ldapdelete`.

## 8. `W_cred`: 초기 비밀번호 구획 (v2c, T-021)

비밀번호 쓰기(머신 `setPassword`)는 v2c 단계다(설계: [machine-write-scope-v2 CHANGE.md](changes/machine-write-scope-v2/CHANGE.md) D379-9/10/13/18, Revision 8–14).
이 절은 그 **LDAP 부분**(계정·무잠금 정책·ACL·전제 검사 준비)을 다룬다. 앱 경로는 T-026부터 열려 있다: `MACHINE_WRITE_ENABLED`·`MACHINE_WRITE_CRED_ENABLED`(8.0 앱 설정 값)가 켜지고 client 상한에 `directory.users.password.write`가 있을 때만 머신 `setPassword`가 동작한다([api.md](api.md)). 이 절의 ACL만 적용하고 플래그를 끈 채로 두면 앱 경로는 동작하지 않는다(설정 읽기·전제 검사도 하지 않는다).
v2c를 켜지 않는 배포는 이 절 전체를 건너뛴다: `W_cred` 계정을 만들지 않고, 아래 어떤 규칙·스위치도 넣지 않는다(그때 `W_data`·`W_lock`은 비밀번호 속성에 `none`이고 직접 시도는 50이다, AC-008).

`W_cred`가 할 수 있는 것은 두 가지뿐이다(모두 직접 `ldappasswd`/`ldapmodify`로 실측, [EVIDENCE §2g·§2h](changes/machine-write-scope-v2/EVIDENCE.md)):

- `$CRED_DN` 아래 `inetOrgPerson` 중 **`W_data`가 만들었고**(`creatorsName`, 서버가 채워 위조 불가), 대기 표지(`employeeType: ldapium-credential-pending:<16 hex>`)와 대기 정책(`pwdPolicySubentry: $PENDING_POLICY_DN`)을 갖고, **비밀번호가 없고**, 특권 그룹의 **직접** 멤버가 아닌 항목의 `userPassword`를 `=w`로 설정한다. `manage`가 아니므로 ppolicy(대기 정책: 길이, `pwdCheckQuality 2`)가 적용된다: 짧은 값·사전 해시 값은 19.
- 그 뒤 정리: `W_data`가 만든 항목에서 표지 **값 하나**와 대기 정책 **값 하나**만 지운다(`=z`). 속성 전체 삭제·다른 값·정책 추가·다른 신원이 만든 항목은 50.

`W_data` 쪽 v2c 규칙([`write-data-cred.ldif`](../scripts/test/fixtures/machine-acl/write-data-cred.ldif))은 표지와 정책을 **Add 안에서만** 붙이게 하고(Q15 `olcAddContentAcl TRUE` 필요: FALSE에서는 Add가 속성 ACL을 보지 않는다), M-3 완화 두 규칙을 더한다:
(a) `W_data`가 만들지 않은 항목의 `entry`는 객체 클래스와 무관하게 `=rsc`(`groupOfNames`만 제외: v2b `deleteGroup`) — **v2c를 켠 배포에서 머신 `deleteUser`와 modrdn은 `W_data`가 만든 항목에만 동작한다**(관리자가 만든 `inetOrgPerson`·`person`·`organizationalPerson`·`account`/`posixAccount`·컨테이너는 LDAP 50, Q16 수용, v2a 계약 축소). `inetOrgPerson`만 막으면 다른 클래스의 관리자 항목을 지우고 같은 DN의 대기 `inetOrgPerson`으로 다시 만들 수 있었다(검토 MAJOR-1);
(b) 특권 그룹마다 `member`는 `=rsc`(탈취한 계정의 특권 재가입 차단).
남는 위험(수용, Q16): `W_data`가 **스스로 만든** 계정(v2a `createUser`로 만든 SSO 신원 등)은 삭제→대기 재생성→설정할 수 있다 — **v2a로 만든 계정을 SSO 신원으로 쓰는 배포는 v2c를 켜지 않는다.** 특권 그룹의 **중첩** 그룹은 (b)가 덮지 않는다 — 하위 그룹도 `MACHINE_WRITE_PRIVILEGED_GROUPS`(= `$PRIV_GROUPS`)에 함께 나열한다.
**세 번째 남는 위험(수용, 검토 MAJOR-2)**: (a)는 삭제·이름 변경만 막고 속성 쓰기는 막지 않는다. 유출된 `W_data`는 관리자가 만든(특권 포함) 사용자의 `mail`·`uid`를 다른 값으로 바꾼 뒤, 그 **옛 값**을 가진 대기 계정을 만들고 `password.write` client로 설정할 수 있다 — **로그인 이름이 `mail`·`uid`로 해석되는 소비자**(SSO·애플리케이션)에서는 그 신원으로 로그인된다. `mail`·`uid`를 (a)에 넣으면 v2a `patchUser`가 관리자가 만든 사용자의 `mail`을 못 바꾸게 되어 Q16이 수용한 축소(삭제·modrdn)를 넘으므로 넣지 않았다. 완화는 운영 쪽이다: 소비자가 사용자를 `entryUUID` 같은 불변 식별자로 묶거나, `mail`·`uid` 변경을 감사에서 경보한다. 이것을 받아들일 수 없는 배포는 v2c를 켜지 않는다.
이미 대기인 항목에 **두 번째** 표지 값은 Modify로 붙는다(filter가 참이므로): 앱 사전 읽기가 표지 값 정확히 하나를 요구한다(T-022).
설정과 정리 사이(Q14 창)에는 대기 정책(`pwdSafeModify FALSE`)이 그 계정에 적용된다: 이미지의 `by self write`로 사용자 자신도 옛 비밀번호 없이 `userPassword`를 바꿀 수 있고, 인증된 누구나 19/50 오라클을 쓸 수 있다. 정리가 실패하면 그 상태가 남으므로 stuck 스윕(`pwdChangedTime` 있음, T-022)이 정리를 재시도하고 경보한다 — 정리 전 자기 변경은 창을 다시 여는 것이 아니라 같은 창 안에 있다.
**다중 provider**(Codex P1): 같은 대기 계정에 두 provider가 동시에 "첫 비밀번호"를 받아들이면 복제가 `entryCSN` last-write-wins로 하나를 조용히 버린다(AGENTS.md). 그래서 `W_cred` 묶음(`write-cred.ldif`)은 앱이 비밀번호 쓰기를 고정한 **provider 하나에만** 넣고, 다른 모든 provider에는 같은 자리에 [`write-cred-deny.ldif`](../scripts/test/fixtures/machine-acl/write-cred-deny.ldif)(`to * by W_cred none`)를 넣는다(8.5). 규칙이 없으면 그 노드에서 `W_cred`는 평범한 사용자다.

`olcAddContentAcl TRUE`는 **메인 DB 전체 스위치**다: rootdn이 아닌 모든 Add 주체가 실는 속성마다 `add` 권한을 받아야 한다. 이 이미지의 규칙에서 실측한 영향: `W_data`의 정상 `createUser`(닫힌 목록)·`createGroup`(+`description`)은 0, `userPassword`·사용자 `description`을 실은 `W_data` Add는 50(#386 한계가 닫힘). 관리자(rootdn)·복제는 ACL을 거치지 않는다. 그 밖에 rootdn이 아닌 신원으로 Add하는 운영 자동화가 있으면 켜기 전에 그 신원으로 시험한다.

### 8.0 순서 (설치와 롤백, Revision 8–9)

설치(모든 노드에서, 이 순서대로): **(8.1 계정과 무잠금 정책) → 8.2 스위치 → 8.3 대기 정책 항목 → 8.4 `W_data` v2c 규칙 → 8.5 `W_cred` 묶음(고정 provider) 또는 거부 규칙(그 밖의 provider) → 8.6 확인 → 8.8 설정 읽기 신원·카나리.** 그 뒤에만 앱 플래그를 켠다. 8.3(데이터, 한 노드에서 한 번)은 8.2와 순서가 바뀌어도 되지만 둘 다 8.4보다 먼저다.
스위치가 먼저인 이유: 스위치 없이 8.4를 넣으면 Add 안의 표지·정책이 ACL 검사 없이 들어간다(D-1). `W_data` 규칙이 `W_cred`보다 먼저인 이유: `W_cred` 규칙은 표지·정책이 붙은 항목이 있어야 의미가 있고, 정리 권한은 부착 권한보다 오래 살아 있어야 한다.

롤백(8.7, 이 순서대로): **앱 플래그·scope 끄기 + 진행 중 요청 drain → 모든 provider에서 `W_data` 부착 규칙 2개 제거 → 모든 provider에서 대기 정책이 붙은 항목 0건 확인(남으면 정리) → `W_cred` 묶음 제거 → M-3 규칙 제거 → 스위치 끄기.**
부착 규칙을 먼저 빼야 한다: 부착 권한이 살아 있는 동안 늦게 도착한 Add는 "0건"을 확인한 뒤에도 다시 붙인다(실측, Codex P1). 정리 권한(`W_cred`)을 먼저 빼면 남은 부착을 `W_cred`가 지울 수 없다(50, 실측). M-3 규칙은 `W_cred`가 사라진 뒤에 뺀다(`W_cred`가 있는 동안 삭제→재생성 탈취를 막는다).

### 8.1 계정

4.1과 같다(강한 비밀번호, 자기 파일):

```sh
umask 077
openssl rand -base64 33 | tr -d '\n' > wcred.pw
printf 'dn: %s\nobjectClass: inetOrgPerson\nuid: machine-write-cred\ncn: machine-write-cred\nsn: machine-write-cred\nuserPassword:: %s\n' "$WCRED_DN" "$(base64 < wcred.pw | tr -d '\n')" | $EXEC ldapadd -x -H ldap://127.0.0.1 -D "cn=admin,$ROOT_DN" -y /tmp/.pw-admin
$EXEC sh -c 'umask 077; cat > /tmp/.pw-wcred' < wcred.pw
```

`$WCRED_DN`은 `$SYSTEM_DN` 아래에 두고 `M`·`W_data`·`W_lock`·관리자·복제 신원과 달라야 한다. `$CRED_DN`은 `$WRITE_DN` 안이어야 한다(Q9).

**무잠금 정책(필수, Q17 유지보수자 결정 2026-10-14).** 이미지 기본 정책(`pwdLockout TRUE`, `pwdMaxFailure 5`)에서는 LDAP에 닿는 누구나 틀린 비밀번호 5번으로 `W_cred`를 잠가 `setPassword`를 멈출 수 있다(잠긴 동안 올바른 Secret으로도 새 replica가 기동하지 않는다, [EVIDENCE §2l](changes/machine-write-scope-v2/EVIDENCE.md)). 그래서 `W_cred`에는 9.1의 무잠금 정책([`wcred-policy.ldif`](../scripts/test/fixtures/machine-acl/wcred-policy.ldif): `pwdLockout: FALSE`, `pwdMaxFailure` 없음)을 붙인다. 이미 같은 DN에 정책이 있으면 그 값이 무잠금인지 확인만 하고, 아니면 거부한다:

```sh
# v2c-wcred-policy
WCRED_POLICY_CN=${WCRED_POLICY_DN#cn=}; WCRED_POLICY_CN=${WCRED_POLICY_CN%%,*}
CUR=$($EXEC ldapsearch -x -H ldap://127.0.0.1 -D "cn=admin,$ROOT_DN" -y /tmp/.pw-admin -LLL -o ldif-wrap=no -b "$WCRED_POLICY_DN" -s base '(objectClass=pwdPolicy)' pwdLockout pwdMaxFailure 2>/dev/null)
if printf '%s\n' "$CUR" | grep -q '^dn: '; then
  if ! printf '%s\n' "$CUR" | grep -qx 'pwdLockout: FALSE' || printf '%s\n' "$CUR" | grep -q '^pwdMaxFailure:'; then
    echo "refusing: $WCRED_POLICY_DN exists and is not the no-lockout policy (pwdLockout FALSE, no pwdMaxFailure)"; exit 1
  fi
else
  sed -e "s|@WCRED_POLICY_DN@|$WCRED_POLICY_DN|g" -e "s|@WCRED_POLICY_CN@|$WCRED_POLICY_CN|g" wcred-policy.ldif \
    | $EXEC ldapadd -x -H ldap://127.0.0.1 -D "cn=admin,$ROOT_DN" -y /tmp/.pw-admin || exit 1
fi
printf 'dn: %s\nchangetype: modify\nreplace: pwdPolicySubentry\npwdPolicySubentry: %s\n' "$WCRED_DN" "$WCRED_POLICY_DN" \
  | $EXEC ldapmodify -x -H ldap://127.0.0.1 -D "cn=admin,$ROOT_DN" -y /tmp/.pw-admin || exit 1
echo "WCRED_POLICY=$WCRED_POLICY_DN"
```

`$WCRED_POLICY_DN`은 `cn=<이름>,…` 형태여야 하고(RDN이 `cn`), 기본 정책·대기 정책(`$PENDING_POLICY_DN`)과 달라야 한다. 정책 항목은 데이터라 복제된다(한 노드에서 한 번). 실행 시 전제 검사(T-028)는 이 정책을 보지 않는다: 붙여도 기동 검사가 통과하고(실측), 붙이지 않아도 기동을 거부하지 않는다 — **붙였는지는 이 절차와 8.6 확인이 책임진다.**

**대가와 운영자 책임.** 잠금이 없으면 디렉터리가 `W_cred` 비밀번호 추측 횟수를 제한하지 않는다. 그 완화는 운영자가 진다:

- **긴 무작위 비밀번호**: 위의 `openssl rand -base64 33`(264비트)보다 짧게 만들지 않고, 사람이 고르거나 다른 곳에 재사용하지 않는다. 회전도 같은 방법으로 만든다.
- **네트워크 제한**: LDAP 포트(389/636)에 닿는 주체를 UI pod·관리 경로·복제 peer로 좁힌다(Kubernetes NetworkPolicy, 방화벽). LDAP를 외부에 그대로 열어 둔 배포는 v2c를 켜지 않는다.
- **실패 bind 경보**: 9.1의 알림 2를 `$WCRED_DN`으로도 돌린다(accesslog에 `bind` 필요). `W_cred` 실패 bind가 회전 직후가 아닌데 늘면 즉시 회전한다(긴급 회전 절차: [machine-auth-operations.md](machine-auth-operations.md)).

### 8.2 스위치 `olcAddContentAcl TRUE` (Q15)

```sh
# v2c-switch-on
printf 'dn: %s\nchangetype: modify\nreplace: olcAddContentAcl\nolcAddContentAcl: TRUE\n' "$MAIN_DB_DN" | $EXEC env CFG_URI="$CFG_URI" sh -c 'ldapmodify -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin'
```

출하 이미지는 이 값을 설정하지 않는다(slapd 기본 FALSE). 이미지 기본값은 바꾸지 않는다: v2c를 켜는 배포만 켠다.

### 8.3 대기 정책 항목 (D379-18)

기본 정책(`cn=default,ou=policies,<root>`)의 **사본**에 `pwdSafeModify: FALSE`와 `pwdCheckQuality: 2`만 바꾼 항목이다. safeModify TRUE(기본)는 rootdn·비밀번호 관리자가 아닌 요청자의 관리자형 설정을 비밀번호가 없는 대상에도 거부하고(F-4), quality 1에서는 `W_cred`를 직접 쓰는 주체가 사전 해시 값으로 길이 규칙을 우회한다(F-6). 표지 계정에만 붙고 정리 단계가 지운다(그 뒤 기본 정책으로 돌아가 F-5 오라클이 사라진다). 기본 정책을 바꾸면 이 사본도 다시 만든다(8.7 후 8.3부터).

```sh
# v2c-policy
$EXEC ldapsearch -x -H ldap://127.0.0.1 -D "cn=admin,$ROOT_DN" -y /tmp/.pw-admin -LLL -o ldif-wrap=no -b "cn=default,ou=policies,$ROOT_DN" -s base \
  | awk -v dn="$PENDING_POLICY_DN" 'BEGIN { cn = dn; sub(/^cn=/, "", cn); sub(/,.*$/, "", cn) } /^dn: / { print "dn: " dn; next } /^(cn|pwdSafeModify|pwdCheckQuality):/ || /^$/ { next } { print } END { print "cn: " cn; print "pwdSafeModify: FALSE"; print "pwdCheckQuality: 2" }' \
  | $EXEC ldapadd -x -H ldap://127.0.0.1 -D "cn=admin,$ROOT_DN" -y /tmp/.pw-admin
```

`$PENDING_POLICY_DN`은 `cn=<이름>,ou=policies,<root>` 형태여야 한다(RDN이 `cn`). 항목은 데이터라 복제된다(한 노드에서 한 번).

### 8.4 `W_data` v2c 규칙 (4.2의 `W_data` 9개 **안에** 넣는다)

[`write-data-cred.ldif`](../scripts/test/fixtures/machine-acl/write-data-cred.ldif)(아래 블록과 같다). `{1}`은 특권 그룹마다 한 번씩 쓰인다(8.5의 명령이 펼친다).

```ldif
dn: @MAIN_DB_DN@
changetype: modify
add: olcAccess
olcAccess: {0}to dn.subtree="@WRITE_DN@" attrs=entry filter=(&(!(objectClass=groupOfNames))(!(creatorsName=@WDATA_DN@)))
  by dn.exact="@WDATA_DN@" =rsc
  by * break
olcAccess: {1}to dn.exact="@PRIV_GROUP_DN@" attrs=member
  by dn.exact="@WDATA_DN@" =rsc
  by * break
olcAccess: {2}to dn.subtree="@CRED_DN@" attrs=employeeType val.regex="^ldapium-credential-pending:[0-9a-f]{16}$" filter=(&(objectClass=inetOrgPerson)(creatorsName=@WDATA_DN@)(employeeType=ldapium-credential-pending:*)(!(userPassword=*))@PRIV_FILTER@(pwdPolicySubentry=@PENDING_POLICY_DN@))
  by dn.exact="@WDATA_DN@" add
  by * break
olcAccess: {3}to dn.subtree="@CRED_DN@" attrs=pwdPolicySubentry val="@PENDING_POLICY_DN@" filter=(&(objectClass=inetOrgPerson)(creatorsName=@WDATA_DN@)(employeeType=ldapium-credential-pending:*)(!(userPassword=*))@PRIV_FILTER@(pwdPolicySubentry=@PENDING_POLICY_DN@))
  by dn.exact="@WDATA_DN@" add
  by * break
```

위치는 `W_data`의 백스톱 두 개(`{0}` SYSTEM, `{1}` REPL) **바로 뒤**, 그 비밀·`pwd*` `none` 규칙 **앞**이다(그 규칙이 `pwdPolicySubentry`를 `none`으로 막기 전에 Add 전용 허용이 와야 한다). 8.5의 명령을 `FRAG=write-data-cred.ldif`로 실행한다. `W_data`가 4.2의 연속 9개를 정확히 갖고 있을 때만 적용하고(이미 v2c 규칙이 있거나 개수가 다르면 거부), 결과 `W_data` 규칙 수는 `9 + 3 + 특권 그룹 수`다.

### 8.5 `W_cred` 묶음 (`W_lock` 뒤)

[`write-cred.ldif`](../scripts/test/fixtures/machine-acl/write-cred.ldif)(아래 블록과 같다):

```ldif
dn: @MAIN_DB_DN@
changetype: modify
add: olcAccess
olcAccess: {0}to dn.subtree="@SYSTEM_DN@"
  by dn.exact="@WCRED_DN@" none
  by * break
olcAccess: {1}to dn.exact="@REPL_DN@"
  by dn.exact="@WCRED_DN@" none
  by * break
olcAccess: {2}to dn.subtree="@CRED_DN@" attrs=userPassword filter=(&(objectClass=inetOrgPerson)(creatorsName=@WDATA_DN@)(employeeType=ldapium-credential-pending:*)(!(userPassword=*))@PRIV_FILTER@(pwdPolicySubentry=@PENDING_POLICY_DN@))
  by dn.exact="@WCRED_DN@" =w
  by * break
olcAccess: {3}to dn.subtree="@CRED_DN@" attrs=employeeType val.regex="^ldapium-credential-pending:[0-9a-f]{16}$" filter=(&(creatorsName=@WDATA_DN@)(pwdPolicySubentry=@PENDING_POLICY_DN@))
  by dn.exact="@WCRED_DN@" =z
  by * break
olcAccess: {4}to dn.subtree="@CRED_DN@" attrs=pwdPolicySubentry val="@PENDING_POLICY_DN@" filter=(creatorsName=@WDATA_DN@)
  by dn.exact="@WCRED_DN@" =z
  by * break
olcAccess: {5}to attrs=userPassword,shadowLastChange,pwdHistory,pKCS8PrivateKey,userPKCS12,oathSecret,oathEncKey,oathTokenPIN,memberOf,pwdAccountLockedTime,pwdChangedTime,pwdFailureTime,pwdGraceUseTime,pwdReset,pwdPolicySubentry,pwdStartTime,pwdEndTime,pwdLastSuccess
  by dn.exact="@WCRED_DN@" none
  by * break
olcAccess: {6}to *
  by dn.exact="@WCRED_DN@" none
  by * break
```

고정 provider가 아닌 노드의 거부 규칙 [`write-cred-deny.ldif`](../scripts/test/fixtures/machine-acl/write-cred-deny.ldif):

```ldif
dn: @MAIN_DB_DN@
changetype: modify
add: olcAccess
olcAccess: {0}to *
  by dn.exact="@WCRED_DN@" none
  by * break
```

`@PRIV_FILTER@`는 `$PRIV_GROUPS`의 그룹마다 `(!(memberOf=<그룹>))`를 이어 붙인 것이다. filter·`sed`에 그대로 들어가므로 쓰이는 DN(`$PRIV_GROUPS`·`$CRED_DN`·`$PENDING_POLICY_DN`·`$WDATA_DN`·`$WCRED_DN`)에 `( ) * \ | & "`가 하나라도 있으면 블록이 거부한다(그런 DN은 LDIF를 직접 편집하고 점검 스크립트도 거부한다). **고정 provider가 아닌 노드는 `FRAG=write-cred-deny.ldif`로 실행한다**(같은 자리, 규칙 1개). 아래 블록이 8.4와 8.5를 모두 적용한다: `FRAG=write-data-cred.ldif`는 8.4의 위치(`W_data` 첫 규칙 + 2), 기본값 `FRAG=write-cred.ldif`는 4.2의 `BASE`(앞에서부터 이어지는 복제·`M`·`W_data`·`W_lock` 값의 수, `W_lock`이 없으면 `W_data` 바로 뒤)에 놓는다. 인덱스는 위치부터 차례로 다시 매긴다. `W_cred`가 이미 있거나, `W_data` v2c 규칙이 아직 없거나(순서 위반), `$PRIV_GROUPS`가 비어 있으면 아무것도 바꾸지 않고 거부한다. fixture가 있는 디렉터리에서 실행한다.

```sh
FRAG="${FRAG:-write-cred.ldif}"
ACLS=$($EXEC env MAIN_DB_DN="$MAIN_DB_DN" CFG_URI="$CFG_URI" sh -c 'ldapsearch -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin -LLL -o ldif-wrap=no -b "$MAIN_DB_DN" -s base olcAccess')
PRIV_FILTER=$(printf '%s' "$PRIV_GROUPS" | awk -v RS=';' '{ gsub(/^[ \t\n]+|[ \t\n]+$/, "") } $0 != "" { printf "(!(memberOf=%s))", $0 }')
NPRIV=$(printf '%s' "$PRIV_FILTER" | awk '{ print gsub(/memberOf=/, "") }')
WD_RULES=$(printf '%s\n' "$ACLS" | awk -v x="dn.exact=\"$WDATA_DN\"" '/^olcAccess: \{[0-9]+\}/ && index($0,x) { s=$0; sub(/^olcAccess: \{/,"",s); i=s+0; if (n == 0) f=i; l=i; n++ } END { if (n && l - f == n - 1) print n, f; else print 0, -1 }')
V2C_AT=
if printf '%s' "$PRIV_GROUPS$CRED_DN$PENDING_POLICY_DN$WDATA_DN$WCRED_DN" | grep -q '[()*\\|&"]'; then
  WHY='a DN contains ( ) * \ | & or ": not safe in a filter or the sed substitution; edit the LDIF by hand'
elif [ -z "$PRIV_FILTER" ]; then
  WHY='PRIV_GROUPS is empty (MACHINE_WRITE_PRIVILEGED_GROUPS is required for v2c)'
elif [ "$FRAG" = write-data-cred.ldif ]; then
  WHY='W_data must hold exactly its 9 contiguous rules of 4.2 and no v2c rules yet'
  set -- $WD_RULES; [ "$1" = 9 ] && V2C_AT=$(($2 + 2))
else
  WHY="W_cred is already present, or the W_data v2c rules (8.4, $((12 + NPRIV)) contiguous W_data rules) are not installed yet"
  HAVE=$(printf '%s\n' "$ACLS" | awk -v x="dn.exact=\"$WCRED_DN\"" 'index($0,x) { n++ } END { print n+0 }')
  set -- $WD_RULES
  if [ "$HAVE" = 0 ] && [ "$1" = $((12 + NPRIV)) ]; then
    V2C_AT=$(printf '%s\n' "$ACLS" | awk -v m="dn.exact=\"$MACHINE_DN\"" -v r="dn.exact=\"$REPL_DN\"" -v d="dn.exact=\"$WDATA_DN\"" -v l="dn.exact=\"$WLOCK_DN\"" '/^olcAccess: \{[0-9]+\}/ { if (stop) next; if (index($0,m) || index($0,r) || index($0,d) || index($0,l)) n++; else stop=1 } END { print n+0 }')
  fi
fi
if [ -z "$V2C_AT" ]; then
  echo "refusing: $WHY" >&2
else
  awk -v at="$V2C_AT" -v pg="$PRIV_GROUPS" '
    function flush(   k, n, g, d, r) { if (rule == "") return
      if (index(rule, "@PRIV_GROUP_DN@")) { n = split(pg, g, ";"); for (k = 1; k <= n; k++) { d = g[k]; gsub(/^[ \t]+|[ \t]+$/, "", d); if (d == "") continue; r = rule; gsub(/@PRIV_GROUP_DN@/, d, r); printf "olcAccess: {%d}%s", at + c++, r } }
      else printf "olcAccess: {%d}%s", at + c++, rule
      rule = "" }
    /^olcAccess: \{[0-9]+\}/ { flush(); s = $0; sub(/^olcAccess: \{[0-9]+\}/, "", s); rule = s "\n"; next }
    /^  / && rule != "" { rule = rule $0 "\n"; next }
    { flush(); print }
    END { flush() }' "$FRAG" | $EXEC env WDATA_DN="$WDATA_DN" WCRED_DN="$WCRED_DN" WRITE_DN="$WRITE_DN" CRED_DN="$CRED_DN" SYSTEM_DN="$SYSTEM_DN" REPL_DN="$REPL_DN" PENDING_POLICY_DN="$PENDING_POLICY_DN" PRIV_FILTER="$PRIV_FILTER" MAIN_DB_DN="$MAIN_DB_DN" CFG_URI="$CFG_URI" sh -c 'sed -e "s|@WDATA_DN@|$WDATA_DN|g" -e "s|@WCRED_DN@|$WCRED_DN|g" -e "s|@WRITE_DN@|$WRITE_DN|g" -e "s|@CRED_DN@|$CRED_DN|g" -e "s|@SYSTEM_DN@|$SYSTEM_DN|g" -e "s|@REPL_DN@|$REPL_DN|g" -e "s|@PENDING_POLICY_DN@|$PENDING_POLICY_DN|g" -e "s|@PRIV_FILTER@|$PRIV_FILTER|g" -e "s|@MAIN_DB_DN@|$MAIN_DB_DN|g" | ldapmodify -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin'
fi
echo "V2C_AT=$V2C_AT"
```

### 8.6 확인 (모든 노드)

`olcAccess`(6.1): `[복제] · M 3 · W_data 2 · W_data v2c 3+그룹 수 · W_data 7 · [W_lock 6] · W_cred 7(고정 provider) 또는 1(그 밖) · [설정 읽기 신원 거부 1(고정 provider, 8.8 후)] · 이미지 규칙`, 그리고 메인 DB에 `olcAddContentAcl: TRUE`. 재시작 뒤에도 같다(라이브 증명이 확인한다). 고정 provider가 아닌 노드는 점검 스크립트에 `--wcred-unpinned`를 더한다: 그 노드에 7개 묶음이 있으면(=`W_cred`가 비밀번호를 쓸 수 있으면) 비0이다. `--privileged-group`에는 `MACHINE_WRITE_PRIVILEGED_GROUPS`를 **그대로** 준다: 설치와 인자에서 같이 빠진 그룹은 스크립트가 알아낼 방법이 없다(디렉터리에 "특권 그룹" 표시가 없다). 점검 스크립트를 v2c 인자와 함께 돌린다(`--wcred-dn`·`--cred-dn`·`--pending-policy-dn`·`--privileged-group`을 모두 주면 v2c 배치를 요구하고, 빠지거나 `olcAddContentAcl`이 TRUE가 아니면 비0):

```sh
scripts/check-machine-write-acl.sh --container ldapium --root-dn "$ROOT_DN" --machine-dn "$MACHINE_DN" --system-dn "$SYSTEM_DN" --write-dn "$WRITE_DN" \
  --wdata-dn "$WDATA_DN" --wlock-dn "$WLOCK_DN" --wcred-dn "$WCRED_DN" --cred-dn "$CRED_DN" --pending-policy-dn "$PENDING_POLICY_DN" --privileged-group "cn=admins,ou=groups,$ROOT_DN"
```

직접 확인(라이브 증명 [`test-machine-write-acl-live.py`](../scripts/test/test-machine-write-acl-live.py)가 전부 단언한다): `W_data` Add — 표지+정책 0, 정상 사용자 0, `userPassword`·정책만·표지만·다른 정책·`$CRED_DN` 밖 표지 50; `W_data` Modify로 표지·정책 붙이기·떼기 50; `W_data`가 관리자가 만든 사용자 삭제·modrdn 50, 자기가 만든 사용자 삭제 0, 특권 그룹 `member` 50; `W_cred` `ldappasswd` — 대기 계정 0(그 값으로 bind), 비밀번호 있는 계정·관리자가 만든 대기형 항목·표지 없는 계정·특권 직접 멤버 50, 짧은 값 19; 정리(표지 값+정책 값 한 Modify) 0, 속성 전체 삭제 50; 정리 후 그 계정은 기본 정책(`M`의 같은 값 재설정 50, 오라클 없음).

`W_cred`의 무잠금 정책(8.1, Q17)은 데이터라 점검 스크립트가 보지 않는다. 관리자로 확인한다(값이 `$WCRED_POLICY_DN`이고, 그 항목에 `pwdLockout: FALSE`가 있고 `pwdMaxFailure`가 없어야 한다):

```sh
$EXEC ldapsearch -x -H ldap://127.0.0.1 -D "cn=admin,$ROOT_DN" -y /tmp/.pw-admin -LLL -b "$WCRED_DN" -s base '(objectClass=*)' pwdPolicySubentry
$EXEC ldapsearch -x -H ldap://127.0.0.1 -D "cn=admin,$ROOT_DN" -y /tmp/.pw-admin -LLL -b "$WCRED_POLICY_DN" -s base '(objectClass=*)' pwdLockout pwdMaxFailure
```

### 8.7 롤백 (8.0의 순서)

먼저 앱의 비밀번호 플래그·scope를 끄고 모든 replica에서 진행 중 요청이 끝나기를 기다린다. 그다음 아래 블록을 `WHAT=attach` → (0건 확인) → `WHAT=cred` → `WHAT=m3` 순서로 실행한다. 블록은 그 부분의 값들이 연속이고 개수가 맞을 때만(`attach` 2개, `cred` 7개 또는 고정 provider가 아닌 노드의 거부 규칙 1개, `m3` 1+그룹 수) 지우고, 순서를 어기면(`attach`가 남은 채 `cred`·`m3`, `W_cred`가 남은 채 `m3`) 아무것도 바꾸지 않고 거부한다.

```sh
WHAT="${WHAT:-attach}"
ACLS=$($EXEC env MAIN_DB_DN="$MAIN_DB_DN" CFG_URI="$CFG_URI" sh -c 'ldapsearch -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin -LLL -o ldif-wrap=no -b "$MAIN_DB_DN" -s base olcAccess')
pick() { printf '%s\n' "$ACLS" | awk -v x="dn.exact=\"$1\"" -v p="$2" '/^olcAccess: \{[0-9]+\}/ && index($0,x) && (p == "" || index($0,p)) { s=$0; sub(/^olcAccess: \{/,"",s); i=s+0; if (n && i != l + 1) bad=1; l=i; out = i " " out; n++ } END { if (bad) print "x"; else print n+0, out }'; }
ATTACH=$(pick "$WDATA_DN" ldapium-credential-pending); CRED=$(pick "$WCRED_DN" ''); M3=$(pick "$WDATA_DN" '=rsc')
case "$WHAT" in
  attach) SEL="$ATTACH"; OKN=2; GUARD=0 ;;
  cred) SEL="$CRED"; OKN="${CRED%% *}"; GUARD=0; [ "$OKN" = 1 ] || { OKN=7; GUARD="${ATTACH%% *}"; } ;;
  m3) SEL="$M3"; OKN="${M3%% *}"; GUARD="${ATTACH%% *}${CRED%% *}"; [ "$GUARD" = 00 ] && GUARD=0 ;;
  *) SEL=x; GUARD=x ;;
esac
set -- $SEL
if [ "$1" = x ] || [ "$1" = 0 ] || [ "$1" != "$OKN" ] || { [ "$WHAT" = m3 ] && [ "$1" -lt 2 ]; } || [ "$GUARD" != 0 ]; then
  echo "refusing: $WHAT rules are not the expected contiguous values, or an earlier rollback step is missing (section 8.0 order)" >&2
else
  shift; { printf 'dn: %s\nchangetype: modify\ndelete: olcAccess\n' "$MAIN_DB_DN"; for i in "$@"; do printf 'olcAccess: {%s}\n' "$i"; done; } | $EXEC env CFG_URI="$CFG_URI" sh -c 'ldapmodify -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin'
  echo "removed $WHAT"
fi
```

0건 확인(부착 규칙을 **모든 provider에서** 뺀 뒤, `W_cred` 묶음을 빼기 전). **provider마다** `EXEC`를 그 노드로 바꿔 실행하고 모두 `PENDING_LEFT=0`일 때만 넘어간다: 한 노드의 0은 복제가 아직 가져오지 않은 다른 provider의 늦은 Add를 보지 못한다(복제 지연). 검색이 실패하면(bind 실패·노드 응답 없음·잘못된 base) 0이 아니라 `PENDING_LEFT=unknown`과 비0 종료다:

```sh
LEFT_OUT=$($EXEC ldapsearch -x -H ldap://127.0.0.1 -D "cn=admin,$ROOT_DN" -y /tmp/.pw-admin -LLL -o ldif-wrap=no -b "$ROOT_DN" "(pwdPolicySubentry=$PENDING_POLICY_DN)" dn); LEFT_RC=$?
if [ "$LEFT_RC" != 0 ]; then
  echo "refusing: the zero check search failed (rc $LEFT_RC): this is not a zero" >&2; echo "PENDING_LEFT=unknown"; false
else
  PENDING_LEFT=$(printf '%s\n' "$LEFT_OUT" | awk '/^dn: / { n++ } END { print n+0 }'); echo "PENDING_LEFT=$PENDING_LEFT"
fi
```

0이 아니면 남은 항목에서 대기 정책 값과 표지 값만 지운다(관리자 런북; `W_data`가 만든 항목은 `W_cred`로도 같은 Modify가 된다). 그다음 0건을 다시 확인하고 `WHAT=cred`로 넘어간다.

```sh
# v2c-cleanup
$EXEC ldapsearch -x -H ldap://127.0.0.1 -D "cn=admin,$ROOT_DN" -y /tmp/.pw-admin -LLL -o ldif-wrap=no -b "$ROOT_DN" "(pwdPolicySubentry=$PENDING_POLICY_DN)" employeeType \
  | awk -v p="$PENDING_POLICY_DN" '/^dn: / { if (seen) print ""; seen = 1; print; print "changetype: modify"; print "delete: pwdPolicySubentry"; print "pwdPolicySubentry: " p; next } /^employeeType: ldapium-credential-pending:/ { print "-"; print "delete: employeeType"; print }' \
  | $EXEC ldapmodify -x -H ldap://127.0.0.1 -D "cn=admin,$ROOT_DN" -y /tmp/.pw-admin
```

마지막으로 스위치를 끈다(출하 상태처럼 값이 없게 된다). 대기 정책 항목은 아무 항목에도 붙어 있지 않으면 지워도 되고 남겨도 해가 없다. `W_cred` 계정은 남는다(지우려면 관리자 `ldapdelete`).

```sh
# v2c-switch-off
printf 'dn: %s\nchangetype: modify\ndelete: olcAddContentAcl\n' "$MAIN_DB_DN" | $EXEC env CFG_URI="$CFG_URI" sh -c 'ldapmodify -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin'
```

그 뒤 6.1이 4.2–4.3 직후와 **바이트 단위로 같다**(라이브 증명이 확인한다). `W_data`·`W_lock`까지 되돌리려면 그 다음에 7절이다(v2c 규칙이 남아 있으면 7절의 `K=9`는 "not 9 contiguous values"로 거부한다).

### 8.8 실행 시 전제 검사의 준비: 설정 읽기 신원과 카나리 (T-028)

`MACHINE_WRITE_CRED_ENABLED=true`인 UI는 설계의 "실행 시 전제 검사"(D379-15, [CHANGE.md](changes/machine-write-scope-v2/CHANGE.md) 표 1–8)를 **기동 시**(실패하면 비0 종료), **매 `setPassword` 직전**(실패하면 그 요청 503, 쓰기 없음), **60초마다**(실패하면 다음 성공 주기까지 비밀번호 오퍼레이션만 503)로 직접 실행한다. 로그에는 결과 코드만 남는다(`machine_cred_premise phase=startup|request|periodic result=<코드>`, DN·값 없음). 이 절은 그 검사가 읽고 쓰는 것을 준비한다: 8.1–8.6을 끝낸 **고정 provider**에서, 앱 플래그를 켜기 전에.

검사가 보는 것:

| # | 검사 | 실패 코드(예) |
|---|---|---|
| 1 | 설정 읽기 신원으로 메인 DB `olcAccess`를 읽어 2절 배치(`[복제] · M 3 · W_data(+v2c) · [W_lock] · W_cred 7 · 읽기 신원 거부 1`)와 **원문으로** 대조한다. 공백 연속은 하나로 보고, 리터럴은 대소문자까지 같아야 하며, DN 자리만 DN으로 비교한다. `@WRITE_DN@`은 모든 `MACHINE_WRITE_SUBTREES`의 공통 조상(가장 좁은 항목), `@CRED_DN@`은 모든 `MACHINE_WRITE_CRED_SUBTREES`의 공통 조상, `@SYSTEM_DN@`은 `W_data` DN의 부모, 특권 filter는 `MACHINE_WRITE_PRIVILEGED_GROUPS` 순서다. 같은 신원으로 `olcAddContentAcl: TRUE`도 본다 | `acl_prefix_mismatch`, `acl_cred_bundle_mismatch`, `acl_reader_rule_missing`, `acl_add_content_acl_off`, `reader_bind_failed` |
| 2 | `olcPPolicyDefault`가 가리키는 기본 정책: `pwdAttribute userPassword`, `pwdMinLength ≥ MACHINE_WRITE_CRED_MIN_LENGTH`, `pwdCheckQuality ≥ 1`, `pwdInHistory ≥ 1`, `pwdSafeModify TRUE`. 대기 정책: `pwdAttribute`, `pwdMinLength ≥` 하한, `pwdCheckQuality ≥ 2`, `pwdSafeModify FALSE`. `MACHINE_WRITE_CRED_POLICY_DNS`의 항목도 기본 정책의 하한(`pwdSafeModify` 제외). 값은 `M`으로 읽는다 | `policy_default_min_length`, `policy_pending_safe_modify`, … |
| 3·4 | 대상별(요청 직전): `M` 사전 읽기(T-022)가 대기 정책 정확히 하나·표지 정확히 하나·태그·`creatorsName`·`pwdChangedTime`·특권 멤버를 본다 | 그 요청 403/409 |
| 5 | 카나리(기동·주기만): subtree마다 세 항목에 `W_cred`로 Password Modify — 비밀번호 있는 표지 50(비밀번호 항), 표지 없는 무비밀번호 50(표지 항: `W_data`가 만들고 대기 정책만 있어 빠지는 항이 표지뿐), 대기 무비밀번호에 1자 값 19와 사전 해시(`{SSHA}`) plain Modify 19(대기 정책의 길이·quality 2가 `W_cred`에 적용됨). 사전 해시 값은 **공개 고정 상수**다(`zz`를 salt `ldapium!`로 해시한 `{SSHA}wRvhGzOlOIRbYCuyzJDhNpazw1RsZGFwaXVtIQ==`, 어떤 비밀·요청·계정과도 무관): accesslog가 `writes`를 기록하면 거부된 이 시도 값이 기동 시와 60초마다 `reqMod`에 남는다(F-8, T024-F1). 비밀 스캔은 이 한 값만 허용한다. **역할은 좁다**(T028-F1, CHANGE Revision 12): ppolicy가 ACL보다 먼저 값을 판정하므로 19는 ACL이 그 계정을 허용한다는 증거가 아니고, 특권 filter·`CRED_DN` 경계 항은 카나리로 보지 않는다 — 그 항들의 유일한 통제는 검사 1이다 | `canary_<항목>_unexpected`; `_accepted`이면 그 카나리를 다시 만든다 |
| 6 | `M`으로 `cn=accesslog` **subtree** 검색(크기 1, `reqMod`·`reqOld`): 항목 0건이어야 한다(base 검색은 증거가 아니다, D379-14) | `accesslog_children_readable` |
| 8 | 설정(`config.Load`): 특권 그룹·`MACHINE_WRITE_CRED_SUBTREES`가 비어 있지 않고 subtree마다 카나리 세트가 있다 | 기동 실패 |

검사가 증명하지 못하는 것은 설계 그대로다: auditlog(차트가 `audit.enabled`와 v2c를 함께 렌더하지 않는다, 차트 밖은 이 문서로만), `M` 외의 accesslog 독자(R-5), 검사 읽기와 쓰기 사이의 창(R-4).

**기본 정책의 길이(의도된 운영 부담, 유지보수자 2026-10-14).** 이미지의 기본 `pwdMinLength`는 8(`LDAP_PASSWORD_MIN_LENGTH`)이고 하한은 12 이상이라, v2c 배포는 `LDAP_PASSWORD_MIN_LENGTH>=12`(또는 하한 이상)가 필요하다. 그대로면 검사 2가 `policy_default_min_length`로 기동을 막는다. v2c를 켜는 배포는 `LDAP_PASSWORD_MIN_LENGTH`를 하한 이상으로 두거나(새 노드) 기본 정책 항목의 `pwdMinLength`를 고친 뒤 **8.3의 대기 정책 사본을 다시 만든다**(사본은 그 값을 복사한다).

**accesslog.** `M`의 accesslog 읽기 옵트인([`accesslog-optin.ldif`](../scripts/test/fixtures/machine-acl/accesslog-optin.ldif))과 v2c는 함께 쓸 수 없다(Q12 잠정: 상호 배제). base는 숨기고 자식에 read를 준 구성도 검사 6이 거부한다. `LDAP_ACCESSLOG_OPS`에 `extended`나 `all`을 넣지 않는다(F-7: Password Modify 한 번에 slapd가 중단된다).

설정 읽기 신원 계정(8.1과 같은 방식; `$READER_DN`은 `uid=machine-cred-acl-reader,$SYSTEM_DN`, `M`·`W_*`·관리자·복제 신원과 달라야 한다):

```sh
# v2c-reader-account
umask 077
openssl rand -base64 33 | tr -d '\n' > reader.pw
printf 'dn: %s\nobjectClass: inetOrgPerson\nuid: machine-cred-acl-reader\ncn: machine-cred-acl-reader\nsn: machine-cred-acl-reader\nuserPassword:: %s\n' "$READER_DN" "$(base64 < reader.pw | tr -d '\n')" | $EXEC ldapadd -x -H ldap://127.0.0.1 -D "cn=admin,$ROOT_DN" -y /tmp/.pw-admin
```

규칙은 두 곳이다. `cn=config` DB([`config-reader.ldif`](../scripts/test/fixtures/machine-acl/config-reader.ldif))에는 메인 DB 항목의 `olcAccess`·`olcAddContentAcl`과 ppolicy overlay 항목의 `olcPPolicyDefault`만 read(그 밖은 이미지의 `{0}to * by * none`; `entry`가 규칙에 있어야 한다, E-21):

```ldif
dn: olcDatabase={0}config,cn=config
changetype: modify
add: olcAccess
olcAccess: {0}to dn.base="@MAIN_DB_DN@" attrs=entry,olcAccess,olcAddContentAcl
  by dn.exact="@READER_DN@" read
  by * break
olcAccess: {1}to dn.base="@PPOLICY_DN@" attrs=entry,olcPPolicyDefault
  by dn.exact="@READER_DN@" read
  by * break
```

메인 DB([`config-reader-main.ldif`](../scripts/test/fixtures/machine-acl/config-reader-main.ldif))에는 `W_cred` 묶음 **바로 뒤**에 거부 규칙 하나(없으면 이 신원은 `by users read`로 메인 DB를 읽는다, E-21; 검사 1이 그 자리를 요구한다):

```ldif
dn: @MAIN_DB_DN@
changetype: modify
add: olcAccess
olcAccess: {0}to *
  by dn.exact="@READER_DN@" none
  by * break
```

아래 블록이 둘을 적용한다. `W_cred` 묶음(연속 7개)이 없거나, 읽기 신원이 이미 어느 DB에든 있거나, ppolicy overlay가 정확히 하나가 아니거나, `$READER_DN`에 `( ) * \ | & "`가 있으면 아무것도 바꾸지 않고 거부한다. 고정 provider에서만 실행한다(다른 provider에서는 앱이 검사하지 않는다). fixture가 있는 디렉터리에서 실행한다.

```sh
# v2c-reader-acl
PPOLICY_DN=$($EXEC env MAIN_DB_DN="$MAIN_DB_DN" CFG_URI="$CFG_URI" sh -c 'ldapsearch -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin -LLL -o ldif-wrap=no -b "$MAIN_DB_DN" -s one "(objectClass=olcPPolicyConfig)" dn' | sed -n 's/^dn: //p')
ACLS=$($EXEC env MAIN_DB_DN="$MAIN_DB_DN" CFG_URI="$CFG_URI" sh -c 'ldapsearch -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin -LLL -o ldif-wrap=no -b "$MAIN_DB_DN" -s base olcAccess')
CFG_ACLS=$($EXEC env CFG_URI="$CFG_URI" sh -c 'ldapsearch -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin -LLL -o ldif-wrap=no -b "olcDatabase={0}config,cn=config" -s base olcAccess')
RD_AT=$(printf '%s\n' "$ACLS" | awk -v c="dn.exact=\"$WCRED_DN\"" -v r="dn.exact=\"$READER_DN\"" '/^olcAccess: \{[0-9]+\}/ { s=$0; sub(/^olcAccess: \{/,"",s); i=s+0; if (index($0,r)) bad=1; if (index($0,c)) { if (n && i != l + 1) bad=1; l=i; n++ } } END { if (!bad && n == 7) print l + 1 }')
if printf '%s' "$READER_DN" | grep -q '[()*\\|&"]'; then
  echo 'refusing: READER_DN contains ( ) * \ | & or ": edit the LDIF by hand' >&2
elif [ -z "$PPOLICY_DN" ] || [ "$(printf '%s\n' "$PPOLICY_DN" | wc -l)" -ne 1 ]; then
  echo "refusing: not exactly one ppolicy overlay below $MAIN_DB_DN (LDAP_PASSWORD_POLICY_ENABLED=false refuses v2c)" >&2
elif [ -z "$RD_AT" ] || printf '%s\n' "$CFG_ACLS" | grep -qF "dn.exact=\"$READER_DN\""; then
  echo 'refusing: the W_cred bundle (8.5, 7 contiguous rules) is not installed, or the reader is already named' >&2
else
  $EXEC env READER_DN="$READER_DN" MAIN_DB_DN="$MAIN_DB_DN" PPOLICY_DN="$PPOLICY_DN" CFG_URI="$CFG_URI" sh -c 'sed -e "s|@READER_DN@|$READER_DN|g" -e "s|@MAIN_DB_DN@|$MAIN_DB_DN|g" -e "s|@PPOLICY_DN@|$PPOLICY_DN|g" | ldapmodify -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin' < config-reader.ldif
  $EXEC env READER_DN="$READER_DN" MAIN_DB_DN="$MAIN_DB_DN" RD_AT="$RD_AT" CFG_URI="$CFG_URI" sh -c 'sed -e "s|^olcAccess: {0}|olcAccess: {$RD_AT}|" -e "s|@READER_DN@|$READER_DN|g" -e "s|@MAIN_DB_DN@|$MAIN_DB_DN|g" | ldapmodify -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin' < config-reader-main.ldif
fi
echo "RD_AT=$RD_AT"
```

**카나리**(검사 5). `MACHINE_WRITE_CRED_SUBTREES`의 DN마다(`CANARY_BASE`) 세 항목을 만든다. 모두 관리 잠금 상태라, 프로브가 뜻밖에 성공해도 그 값으로 bind할 수 없다. 표지 태그 `0000000000000000`은 어떤 client 태그와도 같지 않으므로(앱 사전 읽기가 403) 앱 경로의 대상도 아니다. 카나리는 보호 집합에 들어가 머신 쓰기가 건드릴 수 없고, 스윕(8.9)도 건너뛴다.

```sh
# v2c-canaries
CANARY_BASE="${CANARY_BASE:-$CRED_DN}"
CANARY_UID="${CANARY_UID:-canary-cred}"
CMARK='ldapium-credential-pending:0000000000000000'
canary() { printf 'dn: uid=%s,%s\nobjectClass: inetOrgPerson\nuid: %s\ncn: %s\nsn: %s\n%s' "$CANARY_UID-$1" "$CANARY_BASE" "$CANARY_UID-$1" "$CANARY_UID-$1" "$CANARY_UID-$1" "$2"; }
# 비밀번호 있는 표지 / 대기(무비밀번호): W_data가 Add (표지 + 대기 정책, olcAddContentAcl TRUE 아래 Add 전용 규칙)
canary pw "employeeType: $CMARK
pwdPolicySubentry: $PENDING_POLICY_DN
" | $EXEC ldapadd -x -H ldap://127.0.0.1 -D "$WDATA_DN" -y /tmp/.pw-wdata
canary pending "employeeType: $CMARK
pwdPolicySubentry: $PENDING_POLICY_DN
" | $EXEC ldapadd -x -H ldap://127.0.0.1 -D "$WDATA_DN" -y /tmp/.pw-wdata
# 표지 없는 무비밀번호: W_data가 표지·정책 없이 Add(정상 createUser와 같은 모양), 관리자가 대기 정책만 붙인다.
# 그러면 W_cred filter에서 빠지는 항은 표지 하나뿐이라 그 50이 표지 항을 격리해 확인한다(safeModify가 아니라 ACL이 거부)
canary unmarked "" | $EXEC ldapadd -x -H ldap://127.0.0.1 -D "$WDATA_DN" -y /tmp/.pw-wdata
printf 'dn: uid=%s-unmarked,%s\nchangetype: modify\nadd: pwdPolicySubentry\npwdPolicySubentry: %s\n' "$CANARY_UID" "$CANARY_BASE" "$PENDING_POLICY_DN" | $EXEC ldapmodify -x -H ldap://127.0.0.1 -D "cn=admin,$ROOT_DN" -y /tmp/.pw-admin
# 첫째에 버리는 비밀번호, 셋 모두 관리 잠금
printf 'dn: uid=%s-pw,%s\nchangetype: modify\nreplace: userPassword\nuserPassword: %s\n' "$CANARY_UID" "$CANARY_BASE" "$(openssl rand -hex 24)" | $EXEC ldapmodify -x -H ldap://127.0.0.1 -D "cn=admin,$ROOT_DN" -y /tmp/.pw-admin
for u in pw unmarked pending; do
  printf 'dn: uid=%s-%s,%s\nchangetype: modify\nadd: pwdAccountLockedTime\npwdAccountLockedTime: 000001010000Z\n' "$CANARY_UID" "$u" "$CANARY_BASE" | $EXEC ldapmodify -x -H ldap://127.0.0.1 -D "cn=admin,$ROOT_DN" -y /tmp/.pw-admin
done
echo "CANARY_SET=uid=$CANARY_UID-pw,$CANARY_BASE|uid=$CANARY_UID-unmarked,$CANARY_BASE|uid=$CANARY_UID-pending,$CANARY_BASE"
```

subtree가 여럿이면 `CANARY_BASE`와 `CANARY_UID`를 바꿔 반복하고(uid가 겹치면 unique overlay가 거부한다), 출력된 세트들을 `;`로 이어 `MACHINE_WRITE_CRED_CANARIES`에 넣는다. 프로브가 성공한 카나리(`canary_*_accepted`)는 지우고 이 블록으로 다시 만든다.

롤백(8.7의 `WHAT=cred` **앞**): 메인 DB의 거부 규칙과 `cn=config`의 읽기 규칙 둘을 지운다. 블록은 개수가 맞을 때만(메인 1, `cn=config` 2) 지운다.

```sh
# v2c-reader-rollback
pickr() { $EXEC env B="$1" CFG_URI="$CFG_URI" sh -c 'ldapsearch -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin -LLL -o ldif-wrap=no -b "$B" -s base olcAccess' | awk -v x="dn.exact=\"$READER_DN\"" '/^olcAccess: \{[0-9]+\}/ && index($0,x) { s=$0; sub(/^olcAccess: \{/,"",s); out = (s+0) " " out; n++ } END { print n+0, out }'; }
RM=$(pickr "$MAIN_DB_DN"); RC=$(pickr 'olcDatabase={0}config,cn=config')
if [ "${RM%% *}" != 1 ] || [ "${RC%% *}" != 2 ]; then
  echo 'refusing: the reader rules are not exactly 1 (main) + 2 (cn=config)' >&2
else
  for pair in "$MAIN_DB_DN:${RM#* }" "olcDatabase={0}config,cn=config:${RC#* }"; do
    db=${pair%%:*}; set -- ${pair#*:}
    { printf 'dn: %s\nchangetype: modify\ndelete: olcAccess\n' "$db"; for i in "$@"; do printf 'olcAccess: {%s}\n' "$i"; done; } | $EXEC env CFG_URI="$CFG_URI" sh -c 'ldapmodify -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin'
  done
  echo 'removed reader'
fi
```

### 8.9 스윕과 경보 런북 (T-028)

기동 시에는 같은 네 검색을 **읽기만** 하고(정리 쓰기 없음), stuck 항목이 하나라도 있거나 검색이 실패하면 기동하지 않는다(`sweep_stuck_at_startup`; 아래 1–2의 관리자 정리 후 다시 시작). 주기 검사가 실패한 주기에도 스윕은 검색·계수만 하고 `W_cred`로 쓰지 않는다. 주기가 두 번(120초) 넘게 끝나지 않으면 요청 직전 검사가 `premise_cycle_stale`로 503이다.

60초 주기마다 UI는 `M`으로 `LDAP_BASE_DN` 아래를 네 번 검색하고(카나리 제외, 검색마다 최대 64건) 결과 개수만 로그한다(`machine_cred_sweep stuck=… ttl=… orphan=… foreign=… cleaned=… result=…`):

| 스윕 | filter | 동작 |
|---|---|---|
| stuck | `(&(pwdPolicySubentry=<대기 정책>)(creatorsName=<W_data>)(pwdChangedTime=*))` | `W_cred`가 표지 값·대기 정책 값을 한 Modify로 정리(F-5 창을 닫는다) |
| TTL | `…(employeeType=ldapium-credential-pending:*)(!(pwdChangedTime=*))(createTimestamp<=<지금−MACHINE_WRITE_CRED_PENDING_TTL>)` | `W_cred`가 정리(버려진 대기 계정) |
| orphan | `(&(pwdPolicySubentry=<대기 정책>)(creatorsName=<W_data>)(!(employeeType=ldapium-credential-pending:*)))` | `W_cred`가 정책 값 정리 + 경보 `machine_cred_alert kind=orphan` |
| foreign | `(&(pwdPolicySubentry=<대기 정책>)(!(creatorsName=<W_data>)))` | 경보 `machine_cred_alert kind=foreign`(`W_cred`는 지울 수 없다, 50) |

정리 Modify가 실패하면(검색 뒤 값이 바뀌어 `noSuchAttribute`인 경우 포함) `M`으로 그 항목을 다시 읽어 **남은 값만** 지우는 재시도를 한 번 하고, 다시 읽어 대기 정책 값이 없을 때만 정리된 것으로 센다. 재시도도 실패하거나, 검색이 실패하거나, 64건을 넘으면(backlog) `machine_cred_alert kind=sweep_failed result=<코드>`를 남기고 **다음 성공 주기까지 비밀번호 오퍼레이션이 503**이다. 다른 구획(`W_data`·`W_lock`·읽기)은 계속 동작한다.

경보를 받으면(관리자, 고정 provider):

1. `foreign`·`orphan`: 그 항목이 왜 대기 정책을 가졌는지 먼저 본다(관리자 수동 부착, #399 수정 전 이미지의 자기 부착, Add 전용 규칙을 우회한 쓰기). 그다음 8.7의 `# v2c-cleanup` 블록처럼 관리자로 대기 정책 값(과 있으면 표지 값)만 지운다. 카나리는 지우지 않는다.
2. `sweep_failed`(`sweep_stuck_cleanup_failed` 등): `W_cred` bind(회전·잠금, 9.1), 8.5 묶음의 `{3}`·`{4}` 정리 규칙, LDAP 상태를 확인한다. 정리 규칙이 고장이면 1과 같은 관리자 정리 후 묶음을 다시 넣는다. stuck 항목이 남아 있는 동안 그 계정에는 F-5 오라클이 열려 있다(Q14). `W_cred`가 회전·잠금 중이면 스윕이 정리할 수 없으므로 같은 관리자 정리를 손으로 한다: [machine-auth-operations.md "Manual cleanup while `W_cred` is rotated or blocked"](machine-auth-operations.md#manual-cleanup-while-w_cred-is-rotated-or-blocked-revision-8)(T-025, 라이브로 실행·검증).
3. `machine_cred_premise … result=<코드>`로 비밀번호 오퍼레이션이 닫혔으면 위 8.8 표의 코드로 원인을 찾는다. 고친 뒤 다음 주기(60초 안)에 `result=ok`가 나오면 다시 열린다. 기동이 막힌 경우는 고친 뒤 다시 시작한다.

### 8.0 앱 설정 값 (T-020)

T-020(v2c 설정·기동 검증)이 읽는 값 — `MACHINE_WRITE_ENABLED=true`이고 `MACHINE_WRITE_CRED_ENABLED=true`일 때만 읽으며, 꺼져 있으면 다른 `MACHINE_WRITE_CRED_*`는 읽지 않는다(REQ-001, 기본 `false`). 차트는 `ui.machineAuth.write.cred.*`로 같은 값을 렌더한다(비밀번호는 Secret 참조만). client 상한의 `directory.users.password.write`는 T-026부터 받는다: 플래그가 꺼져 있어도 기동하고 그때 `setPassword`는 bind 없이 403이다(긴급 차단, T026-D1/F1):

| 변수 | 규칙(어기면 기동 실패, 진단에 값 없음) |
|---|---|
| `MACHINE_WRITE_CRED_BIND_DN`/`_PASSWORD` | 둘 다 필수, 비밀번호는 다른 `W_*`와 같은 Secret 관례. DN은 D26 형식(`uid`/`cn`/`ou`/`dc`, 별칭·OID·이상한 공백 거부)이고 `M`·`W_data`·`W_lock`(켠 경우)·관리자·서비스 계정·rootdn·복제 신원과 `ParseDN` 동등이면 거부(REQ-009). 보호 집합에 들어가므로 이 DN을 담는 `MACHINE_WRITE_SUBTREES` 상한도 거부된다. |
| `MACHINE_WRITE_CRED_SUBTREES` | `client=dn|dn;…`, 비어 있으면 거부(검사 8). 각 DN은 **같은 client의** `MACHINE_WRITE_SUBTREES` 상한과 같거나 그 안이어야 하고(Q9), 특권 그룹 자신이나 그 아래는 거부. |
| `MACHINE_WRITE_PRIVILEGED_GROUPS` | v2c를 켜면 비어 있으면 거부(검사 8). |
| `MACHINE_WRITE_CRED_MIN_LENGTH` | 정책 하한, 기본 12. 12–1024 정수만(내릴 수 없다). 실제 비교는 T-028의 실행 시 검사. 머신 `setPassword`(T-022, T-026에서 개방)는 본문 비밀번호를 이 값과 **바이트**(UTF-8) 수로 비교해 미만이면 400이다(T022-D3) — 문자 수가 아니므로 비 ASCII 비밀번호는 문자 수가 이 값보다 적어도 통과할 수 있고, 그 경우의 문자 수 하한은 slapd 정책(`pwdMinLength`)이 맡는다. |
| `MACHINE_WRITE_CRED_RATE_LIMIT_RPS` | 비밀번호 전역 예산(REQ-013, T-023), 기본 1. 1–10 정수, burst 1 고정(T023-D2). 모든 client가 함께 쓰는 replica당 토큰 버킷이며 client 쓰기 예산(`MACHINE_WRITE_RATE_LIMIT_*`)과 별개다. 비면 `setPassword`는 429 `machine_rate_limited`와 다음 토큰까지의 `Retry-After`(초, ≥1). 같은 대상(`entryUUID`, client 무관)에 진행 중인 `setPassword`가 있으면 대기열 없이 즉시 429와 `Retry-After: 1`(T023-D3). 둘 다 쓰기 전 거부라 멱등 키는 풀린다. |
| `MACHINE_WRITE_CRED_PENDING_POLICY_DN` | 필수(D379-18). D26 형식, `LDAP_BASE_DN`의 엄격한 하위, 이미지 기본 정책(`cn=default,ou=policies,<base>`)과 다르고 보호 신원·특권 그룹·seed와 달라야 한다. |
| `MACHINE_WRITE_CRED_POLICY_DNS` | 선택, `;`로 구분한 대상별 정책 허용 목록(검사 3). **현재 효과 없음**: `setPassword` 사전 읽기(T-022)는 대기 정책이 정확히 하나인 대상만 받으므로 허용 목록의 정책을 가진 대상은 어차피 403이다. T-028은 목록의 정책 항목 값도 하한과 비교한다(유지보수자 Q4, 2026-10-14: 그대로 둔다). D26 형식, base의 엄격한 하위, 최대 16개, 대소문자 무시 중복 거부, 대기 정책 DN은 넣지 않는다. |

대기 정책과 허용 목록의 정책 항목도 보호 집합에 들어간다: 머신 쓰기는 정책 항목을 고칠 수 없고, 그 항목을 담는 쓰기 상한은 기동 실패다.
T-028(실행 시 전제 검사, 8.8)이 더 읽는 값:

| 변수 | 규칙 |
|---|---|
| `MACHINE_WRITE_CRED_ACL_READER_DN`/`_PASSWORD` | 필수(D379-16). `W_*` 신원과 같은 검사(D26 형식, `M`·관리자·서비스 계정·rootdn·복제 신원과 `ParseDN` 동등 거부)에 더해 `W_data`·`W_lock`·`W_cred`와도 달라야 한다. 보호 집합에 들어간다. 비밀번호는 Secret, 진단에 값 없음. |
| `MACHINE_WRITE_CRED_CANARIES` | 필수. `;`로 구분한 세트 `비밀번호있는표지|표지없는무비밀번호|대기무비밀번호`(최대 16). 모두 D26 형식, 서로·보호 DN과 다르고, 한 세트의 세 DN은 한 `MACHINE_WRITE_CRED_SUBTREES` DN의 엄격한 하위다. `MACHINE_WRITE_CRED_SUBTREES`의 DN마다 그 안에 세트가 하나 이상 있어야 한다(검사 8). 카나리는 요청 시 보호 집합에 들어간다. |
| `MACHINE_WRITE_CRED_PENDING_TTL` | TTL 스윕의 나이(기본 `24h`, `1h`–`720h`, Go duration). 이보다 오래된 대기(비밀번호 없음) 계정은 스윕이 표지·정책을 지운다 — 그 뒤의 `setPassword`는 403이다. |

## 9. 비밀번호 회전·다중 노드·잠금

`M`과 같다([machine-ldap-account.md](machine-ldap-account.md) 10·12·13절): 계정 항목과 비밀번호는 데이터라 복제되지만 `olcAccess`는 노드마다 따로이므로
**노드를 추가하거나 설정 볼륨을 새로 만들면 4.2를 다시 적용**한다. 비밀번호를 한 개씩 Secret에 두므로 회전 중에는 쓰기가 실패한다. 틀린 비밀번호가 5번 연속이면
계정이 900초 잠긴다(아래 9.1에서 실측하고 완화한다). 임시 비밀번호 파일은 마지막에 지운다:

```sh
$EXEC rm -f /tmp/.pw-admin /tmp/.pw-wdata /tmp/.pw-wlock
rm -f wdata.pw wlock.pw
```

### 9.1 `W_*` 잠금 자기 DoS와 완화 (D24, 실측: [EVIDENCE-drill.md](changes/machine-write-scope/EVIDENCE-drill.md) F)

이미지의 기본 정책(`cn=default,ou=policies,<root>`)은 `pwdLockout: TRUE`, `pwdMaxFailure: 5`, `pwdLockoutDuration: 900`이다. 실측한 거동(드릴 이미지, 실제 slapd):

- 틀린 비밀번호로 `W_data`를 **5번** bind하면 계정이 잠긴다. LDAP에 닿을 수 있는 누구나 이것을 일으킬 수 있다(자기 DoS). 잠긴 동안 UI의 쓰기는 **올바른 비밀번호로도 503**이고
  읽기(`M`)는 영향이 없다. UI의 거절된 쓰기도 요청마다 bind 1회이므로, 비밀번호 회전 뒤 쓰기 5건이 들어오면 UI 스스로 계정을 잠근다(5번째 쓰기에서 잠금 확인).
  잠금 중 올바른 비밀번호 bind는 잠금 시각을 연장하지 않는다.
- 관리자가 비밀번호를 다시 설정(`replace: userPassword`)하면 잠금도 풀린다(실측: 복구 직후 다음 쓰기 201). 비밀번호를 그대로 두고 풀려면
  `delete: pwdAccountLockedTime`(관리자). `pwdFailureTime`은 `NO-USER-MODIFICATION`이라 지울 수 없다(19).

완화는 **`W_*` 전용 정책** 하나다. 정책 항목을 만들고 `W_*` 항목의 `pwdPolicySubentry`로 지정한다(`M`과 일반 사용자는 기본 정책 그대로):

```ldif
dn: cn=machine-writers,ou=policies,dc=example,dc=org
objectClass: top
objectClass: device
objectClass: pwdPolicy
cn: machine-writers
pwdAttribute: userPassword
pwdLockout: FALSE

dn: uid=machine-write-data,ou=system,dc=example,dc=org
changetype: modify
replace: pwdPolicySubentry
pwdPolicySubentry: cn=machine-writers,ou=policies,dc=example,dc=org
```

- **`pwdLockout: FALSE`만 쓰고 `pwdMaxFailure`는 넣지 않는다.** `pwdMaxFailure: 5`를 남기고 플래그만 끄면(실측) 25번 실패 뒤 `pwdAccountLockedTime`이 **찍히지만**
  쓰기는 계속 되므로, 잠금 속성을 감시하는 알림이 거짓 양성이 된다.
- **`W_cred`에는 이 정책을 붙인다**(8.1, CHANGE.md Q17 유지보수자 결정 2026-10-14: 무잠금). 라이브 실측(T-025, [machine-auth-operations.md](machine-auth-operations.md)): 13번 거절 뒤에도 잠기지 않고 T-028 기동 검사가 통과한다. 잠금이 없으면 `W_cred` 비밀번호 추측이 제한되지 않으므로 8.1의 운영자 책임(긴 무작위 비밀번호·네트워크 제한·실패 bind 경보)이 그 완화다. `W_data`·`W_lock`에는 여전히 선택이다.
- 이 정책에서 25번 틀린 비밀번호 bind 뒤에도 잠기지 않고 쓰기가 계속 된다(실측). 비밀번호 회전 차단은 그대로 동작한다: 회전 뒤 거절된 쓰기 8건, 계정 잠금 없음,
  복구 직후 다음 쓰기가 성공한다.
- **대가**: 이 정책에서는 운영자가 `pwdAccountLockedTime`을 직접 넣어도 **무시된다**(실측: 영구 잠금 값을 넣은 뒤에도 쓰기 201). 긴급 차단은 비밀번호 회전(또는 쓰기만 끄는 재배포)만 쓴다.
- 대안(잠금을 유지): `pwdLockout: TRUE`, `pwdMaxFailure: 3`, `pwdLockoutDuration: 8`로 짧게 두면 잠금이 운영자 없이 풀린다(실측: 잠금 후 약 8초에 회복). 운영에서는 값을 더 크게 잡되
  "자동 회복 시간 = 쓰기 중단 시간"임을 받아들인다.

알림(둘 다 라이브로 확인한 쿼리):

```sh
# 1) 잠긴 쓰기 계정 (기본 정책을 쓰는 경우)
ldapsearch -x -H ldap://127.0.0.1 -D "cn=admin,$ROOT_DN" -y /tmp/.pw-admin -b "$SYSTEM_DN" '(&(objectClass=inetOrgPerson)(pwdAccountLockedTime=*))' dn
# 2) 쓰기 계정에 대한 실패 bind (accesslog에 bind가 켜져 있어야 한다: LDAP_ACCESSLOG_OPS에 bind 포함). W_cred(무잠금, 8.1)는 반드시 돌린다
ldapsearch -x -H ldap://127.0.0.1 -D cn=admin,cn=accesslog -y /tmp/.pw-admin -b cn=accesslog "(&(reqType=bind)(reqDN=$WDATA_DN)(reqResult=49))" reqDN
ldapsearch -x -H ldap://127.0.0.1 -D cn=admin,cn=accesslog -y /tmp/.pw-admin -b cn=accesslog "(&(reqType=bind)(reqDN=$WCRED_DN)(reqResult=49))" reqDN
```

앱 쪽 신호: 쓰기 요청이 503이고 `machine_access` 감사 줄의 `reason`이 `bind_failed`(UI 로그에 `machine LDAP bind failed`). 쓰기 신원 회전이나 잠금이 원인이면 읽기는 200이다.

## 10. 관련

- [machine-ldap-account.md](machine-ldap-account.md) (읽기 계정 `M`, 5.1 복제 신원과의 순서) · [machine-auth-operations.md](machine-auth-operations.md) · [machine-keycloak-client.md](machine-keycloak-client.md)
- [CHANGE.md](changes/machine-write-scope/CHANGE.md) · [TASKS.md](changes/machine-write-scope/TASKS.md) `T-020`/`T-021` · [EVIDENCE.md](changes/machine-write-scope/EVIDENCE.md)
- [replication-identity](changes/replication-identity/CHANGE.md) (복제 `{0}` 규칙, D51a)
