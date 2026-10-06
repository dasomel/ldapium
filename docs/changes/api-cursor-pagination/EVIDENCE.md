# Evidence: `GET /api/users`·`/api/groups` 커서 페이지네이션

CHANGE.md T-002(라이브 스파이크)와 T-015(이미지·차트 opt-in)의 실측 기록. 모든 값은 이 변경의
작업 트리에서 빌드한 이미지(`docker build -t l3-ldap:1 -f image/Dockerfile ./image`, slapd 2.6.15)로
측정했다. 환경: macOS + Colima(Docker context `colima`), 이름 있는 볼륨, 로컬 단일 노드.
명령은 재현 가능하게 적었고, 출력은 실행 결과를 그대로 옮겼다.

## 1. 스파이크 — 서버 크기 제한 (T-002 (1)(2), AC-011·AC-012)

적재: `scripts/bench-generate-ldif.py --count 12000 --base dc=example,dc=org`를 오프라인 `slapadd -n 1`로
적재(부트스트랩된 이미지 볼륨에 `bench-load.sh`와 같은 방식), 이어서 일반 사용자
`uid=spike,ou=people,...`를 `ldapadd`·`ldappasswd`로 추가 → `ou=people` 아래 12001개 inetOrgPerson.
기본 설정(`LDAP_SIZE_LIMIT`=10000, `olcLimits` 없음).

### (a) 기본 동작: 일반 사용자는 paged search 총합이 10000에서 끊긴다, rootDN은 전부 읽는다

```
$ ldapsearch -x -LLL -D uid=spike,... -b ou=people,dc=example,dc=org -E 'pr=500/noprompt' '(objectClass=inetOrgPerson)' dn
rc=4 entries=10000          # Size limit exceeded (4)
$ ldapsearch -x -LLL -D cn=admin,dc=example,dc=org ... -E 'pr=500/noprompt' ...
rc=0 entries=12001
$ ldapsearch -x -LLL -D uid=spike,... (페이징 없음)
rc=4 entries=10000          # Size limit exceeded (4)
```

→ **CHANGE.md의 핵심 가정 확인**: 한도는 페이지 크기가 아니라 paged search **총합**에 걸린다.
클라이언트는 10000건을 받은 뒤에야 오류를 본다(go-ldap `Search` 호출자는 부분 결과를 버리고 오류만
받으므로 AC-011의 "부분 페이지 없음"이 성립).

### (b) `olcLimits: {0}users size.prtotal=…` 구문과 효과 (온라인 `ldapmodify`, `cn=admin,cn=config`)

```
$ ldapmodify -x -H ldapi://%2Fvar%2Flib%2Fopenldap%2Frun%2Fldapi -D cn=admin,cn=config -w … <<EOF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
add: olcLimits
olcLimits: {0}users size.prtotal=unlimited
EOF
modifying entry "olcDatabase={1}mdb,cn=config"
$ ldapsearch … -b "olcDatabase={1}mdb,cn=config" -s base olcLimits olcSizeLimit
olcSizeLimit: 10000
olcLimits: {0}users size.prtotal=unlimited
[non-admin paged pr=500]   rc=0 entries=12001
[non-admin UNPAGED]        rc=4 entries=10000 Size limit exceeded (4)
```

→ 구문 유효, **soft/hard는 `olcSizeLimit` 기본(10000)을 유지**한다(페이징 없는 검색은 여전히 10000에서 끊김).
`size.prtotal=11000`은 총합을 11000으로 제한한다(`rc=4 entries=11000`). anonymous 검색은 영향 없음
(`users`는 인증된 DN만; anonymous는 기본 10000에서 `Size limit exceeded`).

엔트리포인트가 렌더한 형태(`scripts/test/test-paged-total-limit.sh`, 1200건 + `LDAP_SIZE_LIMIT=500`,
기존 볼륨 재시작으로 적용):

```
PASS: unset: no olcLimits on the main database ()
PASS: unset: rootDN paged search reads everything (entries rc) (1201 0)
PASS: unset: non-root paged search stops at the size limit (500 4)
PASS: unlimited: olcLimits rendered on an existing volume ({0}users size.prtotal=unlimited)
PASS: unlimited: non-root paged search completes (1201 0)
PASS: unlimited: non-root UNPAGED search is still capped by olcSizeLimit (500 4)
PASS: unlimited: rootDN unaffected (1201 0)
PASS: 900: olcLimits replaced, not duplicated ({0}users size.prtotal=900)
PASS: 900: non-root paged search stops at the paged total (900 4)
PASS: unset again: olcLimits removed ()
PASS: operator olcLimits untouched when the variable is unset ({0}dn.exact=… time.soft=60)
PASS: operator olcLimits kept alongside ours when it is set ({0}users size.prtotal=unlimited|{1}dn.exact=… time.soft=60|)
test-paged-total-limit: all cases passed
```

테스트 우선 확인: 구현 전 이미지(`l3-ldap:1`, 변수 미구현)로 같은 스크립트를 돌리면 잘못된 값 케이스가
`FAIL: invalid LDAP_PAGED_TOTAL_LIMIT='abc': exit 0 …`(slapd가 그대로 기동)로 실패했다. 값 검증을
넣은 뒤 위처럼 통과.

### (c) `size.pr` / `size.hard`의 의미 (페이지당 상한)

```
olcLimits: {0}users size.prtotal=unlimited size.pr=200
  client pr=500 → rc=11 entries=0   Administrative limit exceeded (11)
  client pr=100 → rc=0  entries=12001
olcLimits: {0}users size.prtotal=unlimited size.hard=300
  client pr=500 → rc=0  entries=12001
  client pr=100 → rc=0  entries=12001
```

→ `size.pr`는 **클램프가 아니라 거부**다: 상한보다 큰 페이지를 요청하면 결과 0건과
`adminLimitExceeded(11)`. 그래서 이미지는 `size.pr`를 **설정하지 않으며**(`size.prtotal`만), 패키지의 페이지
크기 500(`searchPageSize`)과 충돌하지 않는다. `size.hard`는 `prtotal`이 있을 때 paged search를 막지 않았다
(`prtotal`이 paged 총합의 한도를 대체).

### (g) SSO 모드 서비스 계정은 rootDN인가

코드 확인(`ui/backend/internal/config/config.go`, `httpapi/sso.go`, `ui/README.md:60-64`,
`docs/auth-provider-policy.md`): SSO 모드는 `LDAP_SERVICE_ACCOUNT_DN`으로 bind한다. 이는 **배포별로 운영자가
부여하는 전용 계정**이며(`ui/README.md`: "Grant only this UI-specific account the required LDAP ACLs; it is
never provisioned automatically") 프로젝트가 rootDN으로 만들지 않는다 → rootDN이 아닌 한 일반 사용자와 같은
`olcSizeLimit`·paged total 제한을 받는다. SSO 배포에서 10000건 초과 순회가 필요하면
`LDAP_PAGED_TOTAL_LIMIT`를 켜거나 서비스 계정을 rootDN으로 두어야 한다(후자는 권한 과다라 비권장).

## 2. 리뷰 반영 후 증거 (H1/M1, fail-closed)

- `scripts/test/test-paged-total-limit.sh`는 저장된 문자열이 아니라 **실제로 적용되는 한도**를 검증한다. 이전
  구현(규칙을 `{0}`에 삽입, 값 모양만으로 소유 판단)의 이미지에서는 H1/M1 케이스 10개가 실패했고(예: 운영자의
  `dn.exact=... size.prtotal=100` 규칙이 뒤로 밀려 해당 DN이 `1202 0`을 받음, 운영자의 `users size.prtotal=800`이
  변수 미설정 기동에서 삭제됨), 수정 후 전부 통과한다. slapd는 같은 selector(`users`)의 규칙을 둘 허용하지 않아
  (`unable to add limit` → 설정 오류) 운영자의 `users` 규칙이 있으면 규칙을 추가하지 않는다.
- fail-closed: 소유 표식(`slapd.d/.paged-total-limit`)이 없거나·깨졌거나·읽을 수 없어도 규칙을 지우거나 넓히지
  않고, 설정 파일에 쓸 수 없어 modify가 실패해도 변경 전 `olcLimits`가 그대로 유지되며(백업 복원), 고정 문구
  한 줄만 로그에 남고 slapd는 이전 설정으로 기동한다. 이전 이미지에서는 이 실패가 엔트리포인트 종료로 이어졌다.
