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
  [`write-lock.ldif`](../scripts/test/fixtures/machine-acl/write-lock.ldif).

> **모든 LDAP 노드에 적용하고 6절로 확인하기 전에는 쓰기를 켜지 않는다.** `cn=config`의 ACL은 노드마다 따로이며 복제되지 않는다
> ([machine-ldap-account.md](machine-ldap-account.md) 12절). 규칙이 없는 노드에서 쓰기 계정은 평범한 사용자라 `by users read`로 전체를 읽고
> `by self write`로 자기 항목과 비밀번호를 바꾼다.

## 1. 무엇을 보장하고 무엇을 보장하지 않는가

| 기호 | 의미 |
|---|---|
| `M` | 읽기 전용 머신 계정([machine-ldap-account.md](machine-ldap-account.md)). 이 문서에서 **변하지 않는다** |
| `W_data` (`$WDATA_DN`) | 사용자·그룹 멤버십 쓰기 계정(`createUser`/`patchUser`/`deleteUser`/`addGroupMember`/`removeGroupMember`) |
| `W_lock` (`$WLOCK_DN`) | 잠금 계정(`pwdAccountLockedTime` 하나만, v2b 단계). 첫 출하에는 쓰이지 않지만 같은 방식으로 준비할 수 있다 |
| `W_cred` | 비밀번호 계정. **설계만 있고 ACL 조각은 없다**(8절) |
| `$WRITE_DN` | 쓰기 subtree: **모든 client 상한의 합집합**을 덮는 한 지점 |
| `$SYSTEM_DN` | `M`·`W_*`·서비스 계정을 두는 컨테이너(예 `ou=system,<root>`). `$WRITE_DN`이 넓어져도 쓰기 신원이 닿지 않게 하는 거부 백스톱 |
| `$REPL_DN` | 복제 신원 항목 `cn=replicator,<root>`(엔트리포인트의 예약 DN, `image/entrypoint.sh`의 `ri_dn`). 루트 바로 아래라 `$SYSTEM_DN` 밖이다: 같은 이유의 거부 백스톱 |

ACL 조각을 적용하면 `W_data`는:

- `$WRITE_DN` 아래에서 **항목을 만들고 지우며**(`entry`·`children` write), 닫힌 속성 목록
  `uid, cn, sn, givenName, mail, departmentNumber, o, ou, member`만 쓴다(부록 A: createUser·patchUser·그룹 멤버 add/remove의 합집합).
- `objectClass`는 **`add` 수준**만 받는다(D18). `replace`·`delete`는 거부된다. 그러나 ACL은 **항목 생성(Add)과 기존 항목에 값을 더하는 modify를
  구별하지 못한다**: 기존 항목에 `objectClass` 값을 **추가**하는 modify는 ACL을 통과한다(스모크가 이 한계를 고정한다).
  수정 경로가 `objectClass`를 절대 보내지 않게 하는 것은 앱 가드(T-012)다.
- 비밀 속성(`userPassword`, `pwdHistory` 등 `M`의 목록과 같음), `memberOf`, 모든 `pwd*` 상태 속성(잠금 포함)에는 **읽기·쓰기 모두 `none`**이다.
  `$WRITE_DN` 안의 나머지 속성(운영 속성 포함)은 읽기만 된다(`If-Match` assertion과 읽기에 필요). `description` 등 목록 밖 속성 쓰기는 거부된다.
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
다음 8개        W_data 규칙 8개 (write-data.ldif)
다음 6개        W_lock 규칙 6개 (write-lock.ldif, 선택)
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
olcAccess: {5}to dn.subtree="@WRITE_DN@" attrs=uid,cn,sn,givenName,mail,departmentNumber,o,ou,member
  by dn.exact="@WDATA_DN@" write
  by * break
olcAccess: {6}to dn.subtree="@WRITE_DN@"
  by dn.exact="@WDATA_DN@" read
  by * break
olcAccess: {7}to *
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

잠금을 쓰지 않는 배포는 건너뛴다. 4.2의 블록을 `FRAG=write-lock.ldif WHO="$WLOCK_DN"`으로 실행한다(`W_data`의 8개가 `BASE`에 더해져 `W_lock`이 그 뒤에 놓인다).

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
  by dn.exact="@WLOCK_DN@" write
  by * break
olcAccess: {4}to dn.subtree="@WRITE_DN@"
  by dn.exact="@WLOCK_DN@" read
  by * break
olcAccess: {5}to *
  by dn.exact="@WLOCK_DN@" none
  by * break
```

`W_lock`은 `pwdAccountLockedTime`을 **`write`** 수준으로 받는다. ppolicy가 이 속성의 변경에 `manage`를 요구하지 않음을 라이브로 확인했다(스모크: 설정·해제 모두 성공).

## 5. 속성이 여기서 나온 곳

`W_data`의 닫힌 목록은 [부록 A(T-002 확정 목록)](changes/machine-write-scope/CHANGE.md)의 합집합이다: createUser(`uid, cn, sn`; 선택 `givenName, mail, departmentNumber, o, ou`),
patchUser(`cn, sn, givenName, mail, departmentNumber, o, ou` Replace), 그룹 멤버 add/remove(`member`), 생성 시 `objectClass`. `W_lock`: `pwdAccountLockedTime`.
`pwd*` 상태 속성 목록(`pwdAccountLockedTime`, `pwdChangedTime`, `pwdFailureTime`, `pwdGraceUseTime`, `pwdReset`, `pwdPolicySubentry`, `pwdStartTime`, `pwdEndTime`,
`pwdLastSuccess`)과 비밀 속성 8개는 이 이미지의 스키마·오버레이에서 도출했다(도출 명령은 machine-ldap-account.md 9절). 스키마·오버레이를 바꿨다면 다시 도출해 `{1}`의 목록에 더한다.
부록 A가 바뀌면(예: 그룹 수정 오퍼레이션을 열 때 `description`) 이 조각과 이 문서를 같이 바꾼다.

## 6. 적용 후 확인 (모든 노드)

### 6.1 `olcAccess` 읽기 (필수)

```sh
$EXEC ldapsearch -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin -LLL -o ldif-wrap=no -b "$MAIN_DB_DN" -s base olcAccess
```

기대: `[복제 신원 규칙] · M 3개 · W_data 8개 · [W_lock 6개] · 이미지 기존 규칙(원래 순서)`. `W_data` DN이 들어간 값은 **정확히 8개**이고 연속이다.
`W_lock`은 정확히 6개다. 읽은 순서가 다르면 규칙을 쓰지 말고 7절로 되돌린다.

### 6.2 쓰기 계정으로 직접 확인 (허용과 거부)

허용(`W_data`, `$WRITE_DN` 안): 항목 add, `mail` replace, 그룹 `member` add, 항목 delete. `W_lock`: `pwdAccountLockedTime` 설정과 해제.

```sh
printf 'dn: uid=probe,%s\nchangetype: add\nobjectClass: top\nobjectClass: person\nobjectClass: organizationalPerson\nobjectClass: inetOrgPerson\nuid: probe\ncn: probe\nsn: probe\n' "$WRITE_DN" | $EXEC ldapmodify -x -H ldap://127.0.0.1 -D "$WDATA_DN" -y /tmp/.pw-wdata
```

거부(모두 `Insufficient access (50)`여야 한다): `userPassword` 변경(정책 때문에 옛 값 삭제 + 새 값 추가를 한 modify에 둔 형태만 ACL까지 도달한다. `replace`는
ACL 이전에 정책이 거부해 증명이 못 된다), `objectClass` replace, `description` 등 목록 밖 속성, `$WRITE_DN` 밖 항목, `M`·`W_*`·관리자 항목, `cn=config`,
`W_data`가 `W_lock`의 `pwdAccountLockedTime`을 쓰는 것. `memberOf` modify는 스키마가 먼저 `Constraint violation (19)`로 거부한다(ACL 증명이 아니다).
`W_data`로 `userPassword`·`pwdAccountLockedTime`·`memberOf`를 **읽어도** 나오지 않는다(관리자는 읽는다).

`M`은 여전히 읽기 전용이다: [machine-ldap-account.md](machine-ldap-account.md) 6.2의 모든 쓰기 시도가 50이고
[`test-machine-acl-readonly-live.py`](../scripts/test/test-machine-acl-readonly-live.py)는 녹색이다. 이 조각은 `M`과 다른 어떤 신원의 접근도 바꾸지 않는다
(조각의 모든 규칙이 `W` DN에만 작용하고 `by * break`로 끝난다).

## 7. 롤백

각 조각의 규칙이 **연속한 8개(`W_data`) / 6개(`W_lock`)이고 모두 그 계정 DN을 이름으로 가질 때만** 인덱스로 지운다. 아니면 거부하고 아무것도 바꾸지 않는다
(밀린 인덱스로 다른 규칙을 지우는 사고 방지). 복제 신원 규칙·`M` 규칙·이미지 규칙은 건드리지 않는다. 롤백하면 쓰기 계정은 일반 사용자로 돌아가므로
**먼저** 쓰기를 끈다(`MACHINE_WRITE_ENABLED=false`로 전 replica 교체). `W_lock`은 `K=6 WHO="$WLOCK_DN"`으로 같은 블록을 쓴다.

```sh
K="${K:-8}"; WHO="${WHO:-$WDATA_DN}"
FIRST=$($EXEC env MAIN_DB_DN="$MAIN_DB_DN" CFG_URI="$CFG_URI" sh -c 'ldapsearch -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin -LLL -o ldif-wrap=no -b "$MAIN_DB_DN" -s base olcAccess' | awk -v x="dn.exact=\"$WHO\"" -v k="$K" '/^olcAccess: \{[0-9]+\}/ { if (index($0,x)) { s=$0; sub(/^olcAccess: \{/,"",s); i=s+0; if (n == 0) f=i; l=i; n++ } } END { if (n == k && l - f == k - 1) print f }')
if [ -z "$FIRST" ]; then
  echo "refusing: the rules of $WHO are not $K contiguous values" >&2
else
  { printf 'dn: %s\nchangetype: modify\ndelete: olcAccess\n' "$MAIN_DB_DN"; i=$((FIRST + K - 1)); while [ "$i" -ge "$FIRST" ]; do printf 'olcAccess: {%s}\n' "$i"; i=$((i - 1)); done; } | $EXEC env CFG_URI="$CFG_URI" sh -c 'ldapmodify -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin'
fi
```

롤백 후 6.1을 다시 읽어 `M`·복제·이미지 규칙만 원래대로 남았는지 확인한다(스모크는 적용 전 `olcAccess`와 **바이트 단위로 같게** 돌아감을 확인한다). 계정 항목은 남는다. 완전히 없애려면 관리자로 `ldapdelete`.

## 8. `W_cred`: 설계만 있고 ACL 조각이 없다

비밀번호 쓰기(`setPassword`, 서버 생성 비밀번호 금지)는 별도 승인 단계(Resolved Q1·D15·D16)이고 구현되지 않았다. 따라서 **`userPassword`/`pwd*`를 쓰는 ACL 조각은
이 패키지에 없다.** `W_data`·`W_lock`은 비밀번호 속성에 `none`이고(AC-008), 비밀번호 scope가 꺼진 배포에서 직접 시도는 ACL로 거부된다. `W_cred` 계정을 만들지 않는다.
후속 승인 시 별도 LDIF를 같은 방식(자기 DN에만 작용, 이미지 규칙 앞, 정해진 순서의 `W_lock` 뒤)으로 추가하고 이 절을 갱신한다.

## 9. 비밀번호 회전·다중 노드·잠금

`M`과 같다([machine-ldap-account.md](machine-ldap-account.md) 10·12·13절): 계정 항목과 비밀번호는 데이터라 복제되지만 `olcAccess`는 노드마다 따로이므로
**노드를 추가하거나 설정 볼륨을 새로 만들면 4.2를 다시 적용**한다. 비밀번호를 한 개씩 Secret에 두므로 회전 중에는 쓰기가 실패한다. 틀린 비밀번호가 5번 연속이면
계정이 900초 잠긴다. 임시 비밀번호 파일은 마지막에 지운다:

```sh
$EXEC rm -f /tmp/.pw-admin /tmp/.pw-wdata /tmp/.pw-wlock
rm -f wdata.pw wlock.pw
```

## 10. 관련

- [machine-ldap-account.md](machine-ldap-account.md) (읽기 계정 `M`, 5.1 복제 신원과의 순서) · [machine-auth-operations.md](machine-auth-operations.md) · [machine-keycloak-client.md](machine-keycloak-client.md)
- [CHANGE.md](changes/machine-write-scope/CHANGE.md) · [TASKS.md](changes/machine-write-scope/TASKS.md) `T-020`/`T-021` · [EVIDENCE.md](changes/machine-write-scope/EVIDENCE.md)
- [replication-identity](changes/replication-identity/CHANGE.md) (복제 `{0}` 규칙, D51a)
