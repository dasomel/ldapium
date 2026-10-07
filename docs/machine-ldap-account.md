# 머신 LDAP 계정과 읽기 전용 ACL (운영자 가이드)

`MACHINE_AUTH_ENABLED=true`일 때 머신(bearer) 요청은 **하나의 전용 LDAP 계정** `MACHINE_LDAP_BIND_DN`으로
요청마다 bind해서 실행된다. 이 계정이 읽기 전용이라는 사실을 **강제하는 것은 LDAP ACL**이다
(코드 가드는 보조). 이미지·차트는 이 계정과 ACL을 만들지 않는다(결정 Q2: 운영자가 수동 생성) —
이 문서가 그 절차와 확정 LDIF다.

- 설계·근거: [CHANGE.md](changes/machine-principal-auth/CHANGE.md) "머신 LDAP 계정·ACL"(D4/D14), AC-018.
- 증명: [`scripts/test/test-machine-acl-readonly-live.py`](../scripts/test/test-machine-acl-readonly-live.py)
  (실제 slapd, 세 구성, 변이 시험 포함), 결과는 [EVIDENCE.md](changes/machine-principal-auth/EVIDENCE.md) §4.
- 이 ACL 변경은 Class D다. 적용 전 [`AGENTS.md`](../AGENTS.md)와
  `.agents/skills/ldapium-directory-change/SKILL.md`를 읽는다.

> **모든 LDAP 노드에 적용하고 6절로 확인하기 전에는 `MACHINE_AUTH_ENABLED=true`로 켜지 않는다.**
> `cn=config`의 ACL은 노드마다 따로이고 복제되지 않는다(12절). 규칙이 없는 노드에서 이 계정은
> 평범한 사용자라 `by users read`로 전체를 읽고 `by self write`로 자기 비밀번호를 바꿀 수 있다.

## 1. 무엇을 보장하는가

| 기호 | 의미 |
|---|---|
| `M` (`$MACHINE_DN`) | 머신 전용 계정 DN. 허용 subtree **밖**에 두는 것을 권장한다(예 `uid=machine,ou=system,<root>`) |
| `B` (`$ALLOWED_DN`) | 머신이 읽을 수 있는 subtree. 기본은 `LDAP_BASE_DN`(루트 전체) |
| `MAIN_DB_DN` | 메인 DB의 설정 항목, 보통 `olcDatabase={1}mdb,cn=config` (아래에서 조회) |

규칙 3개(5절)를 적용하면 `M`은:

- `B` 안의 항목·속성을 **읽기만** 한다(검색·비교).
- 비밀 속성(9절 목록)은 요청 방식(`*`, `+`, 명시, 필터)과 무관하게 읽지 못한다.
- `B` 밖의 항목은 읽지 못한다(`entry`/`uid`/`objectClass` 힌트도 없다). 기존 `by users read`는 `M`에게 닿지 않는다.
- 어디서도 쓰지 못한다: add·modify·delete·modrdn, **자기 비밀번호**(`by self write`)와 자기 항목도.
- `cn=config`, `cn=Monitor`, `cn=accesslog`는 읽지 못한다(8절의 opt-in 전까지).
- `M`이 **아닌** 모든 신원(관리자·익명·일반 사용자·복제)은 규칙 3개가 모두 `by * break`로 끝나 기존 규칙 그대로다.

## 2. 하지 말 것

- **rootdn·관리자·서비스 계정 DN을 `MACHINE_LDAP_BIND_DN`으로 쓰지 않는다**(`LDAP_ADMIN_DN`, `cn=admin,cn=config`,
  `cn=monitoring,cn=Monitor`, `cn=admin,cn=accesslog`, 복제 계정, `BACKUP_ADMIN_DNS`, 프로파일 관리자,
  `LDAP_SERVICE_ACCOUNT_DN`). rootdn은 ACL을 우회한다. ldapium은 ParseDN 동등이면 기동을 거부한다.
- **쓰기를 주지 않는다.** `write`/`manage`/`by self write`를 `M`에 주는 규칙을 만들지 않는다.
- **규칙을 뒤에 붙이지 않는다.** 기존 `{0}to attrs=userPassword,shadowLastChange by self write …`와
  `by users read` 규칙이 먼저 적용되면 `M`이 자기 비밀번호를 바꾸고 `B` 밖 힌트를 읽는다. 반드시 `{0}`–`{2}`.
- **같은 LDIF를 두 번 적용하지 않는다**(중복 규칙이 생기고 인덱스가 밀린다). 적용 전 6절의 읽기로 확인한다.
- **`M` 비밀번호를 argv·환경변수·채팅·이슈에 넣지 않는다.** 0600 파일과 stdin만 쓴다.
- 비밀번호가 필요한 곳에서 `ldapi://` EXTERNAL을 쓰려 하지 않는다: 이 이미지에서 컨테이너 사용자(uid 999)와
  root의 EXTERNAL은 `cn=config` 접근이 없다. 아래 절차는 `cn=admin,cn=config`(관리자 비밀번호와 동일)를
  로컬 ldapi 소켓으로 simple bind한다.

## 3. 준비

아래 명령은 컨테이너 안에서 LDAP 도구를 실행한다. `EXEC`만 환경에 맞게 바꾼다
(Kubernetes: `EXEC="kubectl exec -i -n <ns> <pod> --"`; **노드마다** 반복).

```sh
EXEC="docker exec -i ldapium"
ROOT_DN='dc=example,dc=org'
MACHINE_DN="uid=machine,ou=system,$ROOT_DN"
ALLOWED_DN="$ROOT_DN"
CFG_URI='ldapi://%2Fvar%2Flib%2Fopenldap%2Frun%2Fldapi'
```

관리자 비밀번호를 컨테이너 안 0600 파일로 둔다(마지막에 지운다). `ADMIN_PASSWORD_FILE`은 호스트의
0600 파일이다.

```sh
$EXEC sh -c 'umask 077; cat > /tmp/.pw-admin' < "$ADMIN_PASSWORD_FILE"
```

메인 DB의 설정 DN을 조회한다(정확히 한 줄이어야 한다):

```sh
MAIN_DB_DN=$($EXEC env ROOT_DN="$ROOT_DN" CFG_URI="$CFG_URI" sh -c 'ldapsearch -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin -LLL -b cn=config "(olcSuffix=$ROOT_DN)" dn' | sed -n 's/^dn: //p')
echo "$MAIN_DB_DN"
```

## 4. 계정 만들기 (강한 비밀번호)

비밀번호는 호스트의 0600 파일에서 만들고(33바이트 난수, 44자) 그대로 `ldapium`의 Secret
(`MACHINE_LDAP_BIND_PASSWORD`)에 넣는다. 이 이미지의 기본 비밀번호 정책(ppm, 이력 5개, 최소 길이 8)을 통과한다.

```sh
umask 077
openssl rand -base64 33 | tr -d '\n' > machine.pw
```

`ou=system`이 없으면 만든 뒤(이미 있으면 건너뛴다) 계정 항목을 만든다. 비밀번호는 base64로 stdin에만 흐른다:

```sh
printf 'dn: ou=system,%s\nobjectClass: organizationalUnit\nou: system\n' "$ROOT_DN" | $EXEC ldapadd -x -H ldap://127.0.0.1 -D "cn=admin,$ROOT_DN" -y /tmp/.pw-admin
printf 'dn: %s\nobjectClass: inetOrgPerson\nuid: machine\ncn: machine\nsn: machine\nuserPassword:: %s\n' "$MACHINE_DN" "$(base64 < machine.pw | tr -d '\n')" | $EXEC ldapadd -x -H ldap://127.0.0.1 -D "cn=admin,$ROOT_DN" -y /tmp/.pw-admin
$EXEC sh -c 'umask 077; cat > /tmp/.pw-machine' < machine.pw
```

기본 정책에는 잠금이 있다(`pwdLockout: TRUE`, 실패 5회 후 900초). 틀린 비밀번호를 가진 ldapium이 요청마다
bind하면 `M`이 잠기고 모든 머신 요청이 503이 된다(13절).

계정만으로는 아무 권한이 없다. 이 시점에서 `M`은 일반 사용자와 같다(`by users read`, 자기 비밀번호 쓰기).
**5절을 바로 이어서 적용한다.**

## 5. ACL 적용

> **`LDAP_REPLICATION_IDENTITY=prepare`/`dedicated` 노드(#277, D30):** 복제 신원 규칙은 항상 `{0}`이고 머신 규칙은 그 바로
> 뒤 `{1}`–`{3}`이다. 이 절의 명령은 `{0}`–`{2}`용이다. 노드 `olcAccess`의 `{0}`이 복제 규칙(`dn.exact="cn=replicator,…"`)이면
> 바로 아래 5.1의 `{1}`–`{3}` 명령을 쓴다. **머신 규칙을 먼저 넣고 나중에 prepare를 켜도** 된다: prepare가 자기 규칙을 `{0}`에
> 넣으면 머신 규칙이 `{1}`–`{3}`으로 밀려 같은 배치가 된다. 머신 규칙을 `{0}`–`{2}`로 둔 채 복제 규칙이 `{3}` 이후에
> 놓이게 하면(예: 복제 규칙이 이미 `{0}`인데 이 절의 명령을 그대로 적용) prepare가 다음 재시작을 거부한다.

`M` 규칙 3개를 기존 모든 allow 규칙보다 **앞**(`{0}`–`{2}`)에 넣는다. `{n}`을 명시한 삽입은 기존 규칙을 뒤로 민다.
slapd는 위에서부터 첫 일치 규칙을 쓰고 `by * break`는 `M`이 아닌 신원을 다음 규칙으로 넘긴다.

- `{0}` 비밀 속성: `M`에게 `none`(읽기와 **자기 쓰기까지** 차단). `M`의 bind 자체는 영향이 없다 — bind 시점의
  요청자는 아직 익명이라 `by * break` 뒤 기존 `by anonymous auth`가 처리한다.
- `{1}` `B` 아래: `M`에게 `read`. `{0}`이 먼저라 비밀 속성은 열리지 않는다.
- `{2}` 나머지 전부: `M`에게 `none`. `M`의 결정은 여기서 끝나므로 기존 `by users read`·`by self write`에 닿지 않는다.

LDIF(저장소의 확정 파일은 [`scripts/test/fixtures/machine-acl/main-database.ldif`](../scripts/test/fixtures/machine-acl/main-database.ldif),
테스트가 이 블록과 같은지 검사한다). 연속 줄의 앞 공백 두 칸은 필수다.

```ldif
dn: @MAIN_DB_DN@
changetype: modify
add: olcAccess
olcAccess: {0}to attrs=userPassword,shadowLastChange,pwdHistory,pKCS8PrivateKey,userPKCS12,oathSecret,oathEncKey,oathTokenPIN
  by dn.exact="@MACHINE_DN@" none
  by * break
olcAccess: {1}to dn.subtree="@ALLOWED_DN@"
  by dn.exact="@MACHINE_DN@" read
  by * break
olcAccess: {2}to *
  by dn.exact="@MACHINE_DN@" none
  by * break
```

이 블록을 `main-database.ldif`로 저장하고 적용한다. 세 값은 컨테이너 안에서 치환되고, 온라인으로 즉시 적용된다
(slapd 재시작 불필요). DN에 `|`, `&`, `\`가 들어 있으면 이 치환을 쓰지 말고 LDIF를 직접 편집한다.

```sh
$EXEC env MACHINE_DN="$MACHINE_DN" ALLOWED_DN="$ALLOWED_DN" MAIN_DB_DN="$MAIN_DB_DN" CFG_URI="$CFG_URI" sh -c 'sed -e "s|@MACHINE_DN@|$MACHINE_DN|g" -e "s|@ALLOWED_DN@|$ALLOWED_DN|g" -e "s|@MAIN_DB_DN@|$MAIN_DB_DN|g" | ldapmodify -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin' < main-database.ldif
```

### 5.1 복제 신원 규칙이 `{0}`인 노드: `{1}`–`{3}`에 적용

같은 LDIF 파일을 인덱스만 한 칸씩 밀어(`{2}`→`{3}`, `{1}`→`{2}`, `{0}`→`{1}`) 넣는다. 복제 규칙은 `{0}`에 그대로 남고 머신 규칙은
그 뒤에서 기존 규칙보다 앞선다. 복제 규칙과 머신 규칙은 서로 다른 DN에만 적용되고 둘 다 `by * break`로 끝나므로 서로 영향이 없다.

```sh
$EXEC env MACHINE_DN="$MACHINE_DN" ALLOWED_DN="$ALLOWED_DN" MAIN_DB_DN="$MAIN_DB_DN" CFG_URI="$CFG_URI" sh -c 'sed -e "s|^olcAccess: {2}|olcAccess: {3}|" -e "s|^olcAccess: {1}|olcAccess: {2}|" -e "s|^olcAccess: {0}|olcAccess: {1}|" | sed -e "s|@MACHINE_DN@|$MACHINE_DN|g" -e "s|@ALLOWED_DN@|$ALLOWED_DN|g" -e "s|@MAIN_DB_DN@|$MAIN_DB_DN|g" | ldapmodify -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin' < main-database.ldif
```

## 6. 적용 후 확인 (모든 노드)

### 6.1 `olcAccess`를 읽어 순서 확인 (필수)

```sh
$EXEC ldapsearch -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin -LLL -o ldif-wrap=no -b "$MAIN_DB_DN" -s base olcAccess
```

기대: 처음 세 값이 위 규칙이고 `{0}`–`{2}`, 그 뒤로 기존 규칙이 **원래 순서대로** 이어진다. 이미지 기본 구성
(`LDAP_ANONYMOUS_READ_BASE` 미설정)의 예 — `M`이 들어간 줄은 정확히 세 줄이고 위치 0–2다:

```text
olcAccess: {0}to attrs=userPassword,shadowLastChange,pwdHistory,pKCS8PrivateKey,userPKCS12,oathSecret,oathEncKey,oathTokenPIN by dn.exact="uid=machine,ou=system,dc=example,dc=org" none by * break
olcAccess: {1}to dn.subtree="dc=example,dc=org" by dn.exact="uid=machine,ou=system,dc=example,dc=org" read by * break
olcAccess: {2}to * by dn.exact="uid=machine,ou=system,dc=example,dc=org" none by * break
olcAccess: {3}to attrs=userPassword,shadowLastChange by self write by anonymous auth by * none
olcAccess: {4}to attrs=entry,uid,objectClass by anonymous read by users read
olcAccess: {5}to * by self write by users read by anonymous none
```

운영자가 먼저 추가한 allow 규칙이나 `LDAP_ANONYMOUS_READ_BASE` 규칙(`{1}`–`{4}`)이 있어도 같다: 머신 규칙이 `{0}`–`{2}`,
나머지는 그 뒤. 복제 신원 규칙이 있는 노드(5.1)는 `{0}`이 복제 규칙, 머신 규칙이 `{1}`–`{3}`, 나머지는 그 뒤이며 `M`이 들어간
줄은 여전히 정확히 세 줄이다. **읽은 순서가 다르면 규칙을 쓰지 말고 11절로 되돌린다.**

### 6.2 `M`으로 부정 확인

`$EXEC`에 `-y /tmp/.pw-machine`을 쓴다. 기대 결과는 각 명령 아래에 적었다.

```sh
$EXEC ldapwhoami -x -H ldap://127.0.0.1 -D "$MACHINE_DN" -y /tmp/.pw-machine
```

`dn:uid=machine,…` (bind 성공).

```sh
$EXEC ldapsearch -x -H ldap://127.0.0.1 -D "$MACHINE_DN" -y /tmp/.pw-machine -LLL -b "$ALLOWED_DN" -s sub '(objectClass=*)' dn userPassword shadowLastChange pwdHistory '+'
```

`B` 안의 항목은 나오지만 `userPassword`/`shadowLastChange`/`pwdHistory` 줄은 없다(운영 속성 `+`도 비밀은 빠진다).

```sh
printf 'dn: %s\nchangetype: modify\nreplace: description\ndescription: probe\n' "$MACHINE_DN" | $EXEC ldapmodify -x -H ldap://127.0.0.1 -D "$MACHINE_DN" -y /tmp/.pw-machine
```

`ldap_modify: Insufficient access (50)`. 어떤 쓰기도 50이어야 한다(`ldapadd`, `ldapdelete`, `ldapmodrdn`, 자기 비밀번호 포함).
비밀번호 확인은 정책 때문에 `ldappasswd`나 `replace`가 ACL 이전에 거부되어 증명이 못 된다 — 아래 형태로 한다
(옛 값 삭제 + 새 값 추가를 한 modify에, 정책이 통과시키는 유일한 자기 변경 형태):

```sh
printf 'dn: %s\nchangetype: modify\ndelete: userPassword\nuserPassword: %s\n-\nadd: userPassword\nuserPassword: Probe-Pw-1aB-2cD\n' "$MACHINE_DN" "$(cat machine.pw)" | $EXEC ldapmodify -x -H ldap://127.0.0.1 -D "$MACHINE_DN" -y /tmp/.pw-machine
```

기대 `Insufficient access (50)`(ACL이 없으면 성공해서 `M`의 비밀번호가 바뀐다 — 그 경우 즉시 11절).

`B` 밖(`B`가 루트 전체이면 건너뛴다)과 설정 DB:

```sh
$EXEC ldapsearch -x -H ldap://127.0.0.1 -D "$MACHINE_DN" -y /tmp/.pw-machine -LLL -b cn=config -s sub '(objectClass=*)' dn
```

항목 없음(`No such object (32)`). `cn=Monitor`, `cn=accesslog`도 같다. **검색은 `B` 안에서 시작해야 한다**: `M`은 루트 항목에
접근이 없어, `B`가 루트보다 좁으면 루트에서 시작한 검색은 `B` 안의 항목이 있어도 `No such object (32)`다.

## 7. 허용 subtree 넓히기·좁히기

`B`는 규칙 `{1}`의 `dn.subtree`다. 바꾸려면 롤백(11절) 후 `ALLOWED_DN`을 바꿔 5절을 다시 적용한다. 규칙 한 줄만
수정하는 방법은 쓰지 않는다(순서·중복 실수가 나기 쉽다).

- 좁히기(예 `ou=people,<root>`): `M`의 항목과 `ou=system`이 `B` 밖이 되어 보이지 않는다. 다만 `B` 밖에서 검색을
  시작하는 호출(루트의 `listTree`, `B` 밖 `getEntry`)은 실패한다. 이 단위의 실제 증명은 slapd 수준이다 — 좁힌 `B`로
  UI 머신 호출 전체를 돌려 보지는 않았다.
- 넓히기: 기본 `B`가 `LDAP_BASE_DN`이다. 그보다 상위로 넓혀도 코드 가드가 `BASE_DN` 밖 DN을 거부하므로(D14) 효과가 없다. `B`가 루트 전체이면 `M`의 항목(`ou=system` 아래)도 `B` 안이라 비밀 속성 없이 읽힌다.
- 읽기 범위 밖으로 쓰기 권한을 늘리는 변경은 이 가이드의 범위가 아니다(별도 Class D).

## 8. 선택: monitor·accesslog (opt-in)

기본에서 `M`은 `cn=Monitor`·`cn=accesslog`를 읽지 못한다(두 DB의 기본 ACL이 `by * none`). `server.monitor.read`를 쓰는 배포만
monitor DB에, `audit.read`를 쓰는 배포만 accesslog DB에 한 규칙을 더한다. accesslog는 감사 메타데이터(행위자·대상 DN·필터,
`reqMod`)를 담으므로 `audit.read`를 정말 부여할 때만 한다. 설정 DN은 아래로 찾는다
(`olcSuffix=cn=accesslog`인 mdb와 `olcMonitorConfig` 항목).

```sh
$EXEC ldapsearch -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin -LLL -b cn=config '(|(olcSuffix=cn=accesslog)(objectClass=olcMonitorConfig))' dn
```

monitor DB (`@MONITOR_DB_DN@`는 위에서 찾은 `olcDatabase={n}monitor,cn=config`,
[`monitor-optin.ldif`](../scripts/test/fixtures/machine-acl/monitor-optin.ldif)):

```ldif
dn: @MONITOR_DB_DN@
changetype: modify
add: olcAccess
olcAccess: {0}to *
  by dn.exact="@MACHINE_DN@" read
  by * break
```

accesslog DB (`@ACCESSLOG_DB_DN@`, [`accesslog-optin.ldif`](../scripts/test/fixtures/machine-acl/accesslog-optin.ldif)):

```ldif
dn: @ACCESSLOG_DB_DN@
changetype: modify
add: olcAccess
olcAccess: {0}to *
  by dn.exact="@MACHINE_DN@" read
  by * break
```

각각 5절과 같은 방식(`MAIN_DB_DN` 대신 해당 DN)으로 적용한다. 이 두 블록은 단위 2의 라이브 시험이 적용해 쓴 것이다.
`cn=config`는 `M`에게 어떤 규칙도 주지 않는다. 롤백은 해당 DB에서 `delete: olcAccess` `{0}`.

## 9. 비밀 속성 목록 (이미지 스키마에서 도출)

규칙 `{0}`의 속성은 이 이미지가 로드하는 스키마(`core`, `cosine`, `inetorgperson`, `nis`와 로드된 오버레이 `ppolicy`, `otp`)에서
뽑았다.

| 속성 | 이유 |
|---|---|
| `userPassword` | 비밀번호 해시 |
| `shadowLastChange` | 이미지의 첫 규칙이 `userPassword`와 묶어 다루는 쌍(비밀은 아니지만 같은 경계) |
| `pwdHistory` | 이전 비밀번호 해시(ppolicy, `pwdInHistory` 기본 5) |
| `pKCS8PrivateKey`, `userPKCS12` | 개인 키 자료 |
| `oathSecret`, `oathEncKey`, `oathTokenPIN` | otp 오버레이의 토큰 비밀·암호화 키·PIN |

`pwdFailureTime`, `pwdAccountLockedTime`, `pwdChangedTime` 등은 계정 상태 메타데이터라 비밀로 보지 않았고 `B` 안에서 읽힌다.
다시 도출하려면(스키마·오버레이를 바꿨다면 반드시):

```sh
$EXEC ldapsearch -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin -LLL -b cn=schema,cn=config -o ldif-wrap=no olcAttributeTypes | grep -o -E "NAME ('[^']*'|\( [^)]*\))" | sed -E "s/NAME //; s/[()']//g" | tr ' ' '\n' | grep -i -v -E '^(olc|olm)' | grep -i -E 'pass|pwd|secret|credential|private|key|pkcs|cert|hash|token|otp|krb' | sort -u
```

출력에서 비밀인 것을 골라 규칙 `{0}`의 목록에 더한다(예: 이미지에 추가 스키마를 넣었다면). 이 목록의 **여덟 속성 모두**를 증명 스크립트가
`uid=secrets` 항목에 알아볼 수 있는 값으로 심고(`userPassword`, `shadowLastChange`, `userPKCS12`, `oathSecret`, `oathEncKey`,
`oathTokenPIN`은 `extensibleObject`로, `pKCS8PrivateKey`는 유효한 PKCS#8 DER로, `pwdHistory`는 운영 속성이라 그 항목의 비밀번호를
두 번 바꿔 생성), 관리자는 값을 읽고 `M`은 명시 목록·`*`·`+`·필터 어느 방식으로도 속성도 값도 받지 못함을 속성마다 검사한다.
속성마다 그 속성 하나만 규칙에서 뺀 변이가 해당 검사를 실패시킨다.

## 10. 비밀번호 회전

`ldapium`은 비밀번호를 한 개만 가지며 v1에는 리로드가 없다(재시작/롤아웃만). 새 비밀번호를 LDAP에 먼저 넣어야 하므로
**회전 중 머신 요청은 503**이다. 틀린 비밀번호로 bind가 5번 실패하면 `M`이 잠긴다(13절) — 순서를 지킨다.

1. 새 비밀번호를 만든다.
2. 새 비밀번호를 `ldapium`의 Secret(`MACHINE_LDAP_BIND_PASSWORD`)에 **먼저 준비**해 두고(적용은 아직 하지 않는다),
3. LDAP에서 `M`의 비밀번호를 바꾼 뒤,
4. 즉시 Secret을 적용하고 모든 `ldapium` replica를 교체한다.

```sh
umask 077
openssl rand -base64 33 | tr -d '\n' > machine.new.pw
$EXEC sh -c 'umask 077; cat > /tmp/.pw-machine-new' < machine.new.pw
$EXEC ldappasswd -x -H ldap://127.0.0.1 -D "cn=admin,$ROOT_DN" -y /tmp/.pw-admin -T /tmp/.pw-machine-new "$MACHINE_DN"
$EXEC sh -c 'mv /tmp/.pw-machine-new /tmp/.pw-machine'
mv machine.new.pw machine.pw
```

`M`의 비밀번호는 데이터(`ou=system` 항목)라 복제로 모든 노드에 전해진다(한 노드에서 한 번). 비밀번호 변경은 accesslog에 기록될 수
있으므로(REQ-005) `audit.read`를 부여하지 않은 `M`이 그 기록을 읽지 못한다는 점을 8절과 함께 확인한다.
잠긴 경우 관리자가 풀 수 있다:

```sh
printf 'dn: %s\nchangetype: modify\ndelete: pwdAccountLockedTime\n' "$MACHINE_DN" | $EXEC ldapmodify -x -H ldap://127.0.0.1 -D "cn=admin,$ROOT_DN" -y /tmp/.pw-admin
```

## 11. 롤백

`{0}`–`{2}`(복제 신원 규칙이 `{0}`이면 `{1}`–`{3}`)가 이 가이드의 `M` 규칙일 때만 그 세 개를 인덱스로 지운다. 아니면 거부하고 아무것도 바꾸지 않는다
(인덱스가 밀린 상태에서 다른 규칙을 지우는 사고를 막는 가드). 적용 전 `olcAccess`와 **바이트 단위로 같게** 돌아간다
(시험으로 확인). 복제 신원 규칙은 건드리지 않는다. 반대로 신원 규칙만 걷어내려면(`admin` 모드로 돌아가도 이미지는 이미 저장된 규칙을 지우지 않는다)
`{0}`이 신원 규칙(`cn=replicator,…`)인지 읽어 확인한 뒤 `delete: olcAccess` `{0}`과 같은 항목의 `olcLimits` 값을 지운다. 머신 규칙은
`{0}`–`{2}`로 올라오고 이 롤백은 `{0}`–`{2}` 가드로 계속 동작한다(`scripts/test/test-machine-acl-with-identity.sh`가 확인).
롤백하면 `M`은 일반 사용자로 돌아가므로(읽기 전체·자기 쓰기) 먼저 `MACHINE_AUTH_ENABLED=false`로 전
replica를 교체한다.

```sh
$EXEC env MACHINE_DN="$MACHINE_DN" MAIN_DB_DN="$MAIN_DB_DN" CFG_URI="$CFG_URI" ROOT_DN="$ROOT_DN" sh -c '
acl=$(ldapsearch -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin -LLL -o ldif-wrap=no \
        -b "$MAIN_DB_DN" -s base olcAccess)
o=0
if printf "%s\n" "$acl" | grep -q "^olcAccess: {0}.*dn.exact=\"cn=replicator,$ROOT_DN\""; then o=1; fi
n=$(printf "%s\n" "$acl" | grep -c "^olcAccess: {[$o-$((o+2))]}.*dn.exact=\"$MACHINE_DN\"")
if [ "$n" != 3 ]; then echo "refusing: the three rules after the replication rule (or {0}-{2}) are not the machine rules" >&2; exit 1; fi
printf "dn: %s\nchangetype: modify\ndelete: olcAccess\nolcAccess: {%s}\nolcAccess: {%s}\nolcAccess: {%s}\n" "$MAIN_DB_DN" $((o+2)) $((o+1)) $o \
  | ldapmodify -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin
'
```

롤백 후 6.1을 다시 읽어 원래 규칙만 남았는지 확인한다. 계정 항목은 남는다. 완전히 없애려면 관리자로 `ldapdelete "$MACHINE_DN"`.

## 12. 다중 노드·복제·재초기화

코드로 읽은 사실이다(`image/entrypoint.sh`의 `olcSyncrepl` 절; 다중 노드 라이브 확인은 이 단위에서 하지 않았다):

- 복제는 `olcDatabase={1}mdb`에만 `olcSyncrepl`(`searchbase=$LDAP_ROOT_DN`, `olcMultiProvider: TRUE`)로 설정된다. `cn=config`는
  그 검색 베이스 밖이며 `cn=config`용 복제 설정이 없다. 각 노드의 `cn=config`는 시작 시 템플릿에서 따로 렌더링된다
  (`slapmodify -n 0`).
- 따라서 **`M` 항목과 그 비밀번호(데이터)는 모든 노드로 복제되지만 `olcAccess`는 노드마다 따로다.** 5절은 모든 노드에서,
  6절은 모든 노드에서 확인한다. 클러스터에 노드를 추가하거나 노드 볼륨을 새로 초기화하면 그 노드에는 규칙이 없다 —
  다시 적용한다.
- `cn=config`는 설정 볼륨(`/etc/openldap/slapd.d`, 차트는 `config` PVC)에 있고 첫 기동에서만 템플릿으로 만들어진다
  (`.bootstrapped` 표식). 재시작·업그레이드는 규칙을 유지하지만 **설정 볼륨을 새로 만들면 규칙이 사라지고** 이미지 기본
  규칙만 렌더링된다. 재초기화 후에는 `M` 항목(데이터 볼륨)이 있어도 규칙이 없다.
- **`LDAP_REPLICATION_IDENTITY=prepare`/`dedicated`와 함께 쓸 수 있다(#277, D30).** 정해진 순서: 복제 신원 규칙 `{0}`, 머신 규칙
  `{1}`–`{3}`, 그 뒤 기존 규칙. 두 설치 순서 모두 같은 결과가 된다 — (a) prepare 후 5.1, (b) 머신 규칙(5절) 후 prepare(prepare가
  `{0}`에 삽입하면 머신 규칙이 `{1}`–`{3}`으로 밀린다). 재시작은 prepare의 "신원 규칙이 첫 값" 검사를 그대로 통과한다. 머신 규칙을
  지우는 롤백(11절)은 신원 규칙을 남긴다. 신원 규칙이 이미 `{0}`인 노드에 5절의 `{0}`–`{2}` 삽입을 쓰면 신원 규칙이 `{3}`으로 밀려
  다음 재시작에서 prepare가 거부하므로 5.1을 쓴다. 시험: `scripts/test/test-machine-acl-with-identity.sh`(실제 이미지, 두 순서·재시작·독립
  롤백)와 증명 스크립트의 구성 (d).

## 13. 알려진 제한

- **잠금**: 기본 정책이 `pwdLockout: TRUE`(5회 실패, 900초)다. 틀린 `MACHINE_LDAP_BIND_PASSWORD`로 5번 bind가 실패하면 `M`이 잠겨
  모든 머신 요청이 503이 된다. 풀기는 10절의 명령. 잠금 정책을 `M`만 다르게 하려면 별도 `pwdPolicy`를 `pwdPolicySubentry`로
  지정해야 하며 이 가이드는 그것을 다루지 않는다.
- **검색 시작 위치**: 6.2의 마지막 문단. `B`가 루트보다 좁으면 `B` 밖에서 시작하는 호출은 `noSuchObject`다.
- **ldapi EXTERNAL**: 2절. 설정 변경은 `cn=admin,cn=config` simple bind(관리자 비밀번호와 동일)로 한다.
- **UI 의존**: 이 ACL이 `M`에게 읽기를 줄 뿐 UI의 머신 경로가 어떤 DN으로 검색하는지는 `getEntry`/`listTree` 코드 가드(D14)가 정한다.
  `B`를 `LDAP_BASE_DN`으로 두는 구성은 단위 2의 라이브 시험(`scripts/test/test-machine-execution-live.py`)이 같은 LDIF로 실제 UI 요청을 돌려
  확인했다.
- **자동화 없음**: 계정 생성·ACL 적용은 수동이다(Q2). 차트의 `ui.machineAuth.*`는 UI 설정만 렌더하고 계정·ACL은 만들지 않는다([차트 README](../charts/ldapium/README.md)). Keycloak 쪽은 [machine-keycloak-client.md](machine-keycloak-client.md), 롤백·긴급 차단은 [machine-auth-operations.md](machine-auth-operations.md).

## 14. 마무리: 임시 비밀번호 파일 지우기

```sh
$EXEC rm -f /tmp/.pw-admin /tmp/.pw-machine /tmp/.pw-machine-new
rm -f machine.pw machine.new.pw
```
