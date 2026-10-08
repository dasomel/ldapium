# Evidence: 머신 토큰 즉시 폐기 (설계 입력)

설계: [CHANGE.md](CHANGE.md) · 작업: [TASKS.md](TASKS.md)

- 수집일: 2026-10-07, main `b0ada28`(§1–§3: 코드·문서·RFC 읽기); 같은 날 main `220f554`에서 T-001–T-004 라이브 실측(§4–§7)
- 이 문서는 구현 증거가 아니라 **설계 입력**이다. 코드는 변경하지 않았다. §4–§7은 실제 Keycloak 26.7.4와 `ldapium:e2e` 이미지(이 worktree에서 `ldapium:l286a`로 빌드)를 새 컨테이너에서 돌린 결과다.
- 비밀: 토큰·secret은 기록하지 않았다. 아래 출력의 `jti`·`sub`·`access_token`은 `<redacted>`, secret은 일회용 스파이크 값이며 기록하지 않았다. 스크래치 스크립트는 저장소 밖에 두었고 컨테이너·이미지·네트워크는 모두 삭제했다.

## 1. 코드·문서 읽기로 확인한 사실

| 사실 | 위치 / 재현 |
|---|---|
| `jti`는 검증기·미들웨어 어디에서도 읽히지 않는다 | `grep -rn jti ui/backend/internal/machineauth/*.go ui/backend/internal/httpapi/machine*.go`를 비테스트 파일로 걸러 0건. `Principal`은 `ClientID`·`Scopes`·`SubjectHash`·`Expiry`(`machineauth/claims.go:59-64`) |
| 만료·수명 규칙 | `exp - iat > MaxTTL`이면 거부 `claims.go:129`; `now > exp + skew`이면 만료 `claims.go:141`; `iat`는 `claims.go:121`에서 읽음 |
| TTL·skew 기본·범위 | `MACHINE_TOKEN_MAX_TTL` 기본 10m, 범위 (0,1h]: `config/machine.go:161`; `MACHINE_CLOCK_SKEW` 기본 30s, 범위 0–60s: `config/machine.go:162` |
| 요청 경로 순서 | `httpapi/machine.go:284` `serve` → `admitIP` → `acquireAuthSlot` → `Verify`(`:303`) → 실패 시 `tk.fail()`(`:319`) → `budget.acquire`(`:333`) → scope → `exec`(LDAP bind) |
| 요청마다 LDAP bind, 실패는 503·폴백 없음 | `httpapi/machine_exec.go:24-29,89-94` |
| JWKS 조회 전송 한도 | 5 s·1 MiB·키 20개: `machineauth/fetch.go:15-18` |
| 서버측 폐기 상태 없음, 설정 리로드 없음 | `docs/machine-auth-operations.md` §1·§2("v1은 설정을 다시 읽지 않으므로 재배포만이 반영 수단") |
| 머신 ACL이 `B`(기본 `LDAP_BASE_DN` 루트)를 `read`로 허용, 비밀 속성은 `none` | `docs/machine-ldap-account.md:110-113,152-154` (문서 읽기; 라이브 재확인은 T-002) |
| UI 서버에 클라이언트용 TLS 리스너 없음 | `grep -rn 'ListenAndServeTLS\|ClientAuth\|tls\.Config' --include='*.go' ui/backend/cmd ui/backend/internal` 비테스트·`machineauth` 제외 결과 `ldapclient/dial.go:277`(LDAP 다이얼)뿐 |
| 감사 reason 닫힌 집합(추가 대상) | `docs/audit-event-schema.md:428-` |
| 부모의 관측: client 비활성화·secret 회전 후 기발급 토큰은 검증 통과 | [부모 EVIDENCE §2.7](../machine-principal-auth/EVIDENCE.md) (실제 Keycloak 26.7.4, 부모 패키지에서 수집) |
| 부모의 관측: introspection은 호출 client가 `aud`에 없으면 `active:false`; `active:true` 경로는 미실행 | 부모 EVIDENCE §2.7, §2.8 |
| 부모 EVIDENCE §2.1의 SA 토큰 payload에 `jti` 필드가 있다(값은 기록하지 않음) | 부모 EVIDENCE §2.1 |

## 2. RFC 확인

rfc-editor.org의 RFC 텍스트(`https://www.rfc-editor.org/rfc/rfc<N>.txt`)를 2026-10-07에 내려받아 해당 문장을 직접 확인했다.

| RFC | 확인한 내용 |
|---|---|
| RFC 7662 §4 | introspection 응답은 보호 자원이 캐시할 수 있으나 캐시 TTL이 길수록 stale 위험이 커지는 절충이 있다. 덜 공격적인 캐시는 짧은 TTL, 환경에 따라 캐시를 끌 수 있다(§4 보안 고려 사항의 캐시 문단) |
| RFC 8705 | 인증서 바인딩 JWT access token은 `cnf`의 `x5t#S256`(DER 인증서의 SHA-256, base64url)로 확인한다 |
| RFC 9068 | JWT access token 프로파일에서 `jti`는 REQUIRED |
| RFC 7009 | 폐기 엔드포인트는 access token 폐기를 SHOULD로 지원하며, refresh token 폐기 시 같은 grant의 access token도 무효화하는 것이 SHOULD |

RFC 7662 §4: 인증 서버는 보호 자원의 인증을 MUST 요구한다(텍스트 662행 부근, 직접 확인). 방식은 규정하지 않는다("토큰 엔드포인트의 어떤 client 인증 방식이든, OAuth 2.0 bearer 토큰 등" 가능; 같은 문단, 직접 확인). 따라서 secret이 필수는 아니나 ldapium이 어떤 자격 증명(secret·개인키·인증서·bearer)을 보유해야 한다. Keycloak이 introspection에서 받는 방식은 미확인(§3 1번에 추가).

## 3. 미확인 항목 (§4–§7에서 실측한 것은 표시)

1. **실측함(§4)** — Keycloak 26.7.4: introspection 호출자 인증 방식(secret, 서명 JWT, mTLS 중 무엇을 받는가); 비활성화·폐기된 SA 토큰의 introspection `active` 값, `active:true` 경로.
2. **실측함(§4.3–§4.4)** — Keycloak: RFC 7009 폐기 엔드포인트와 not-before 정책이 offline JWT 검증을 하는 수신자에게 의미가 있는지(수신자가 push를 받거나 별도 확인을 해야 하므로 ldapium에는 직접 도움이 되지 않을 가능성이 있으나 미확인).
3. **실측함(§4.5)** — Keycloak: `cnf.x5t#S256` 인증서 바인딩 토큰의 발급 구성·SA 토큰 적용.
4. **실측함(§5)** — `ldapium:e2e` 이미지 스키마의 폐기 항목 후보 속성과 기본 머신 ACL의 실제 읽기 결과(`B` 좁힘 포함).
5. 5 s 주기 subtree 조회의 부하는 **단일 노드에서 실측함(§7)**. 2노드 multi-provider의 `createTimestamp` 복제와 분리된 노드의 응답은 **실측함(§8, T-004b)**. 3노드 이상, 양쪽 동시 쓰기, Kubernetes ConfigMap 마운트 전파 시간은 **미측정**.
6. 라이브 드릴을 이 패키지가 정의한 상한 수식과 비교하는 일 전체(구현 없음). 현재 드릴의 기준선만 §6에 기록.

## 4. T-001 — Keycloak 26.7.4 실측 (2026-10-07)

환경: `quay.io/keycloak/keycloak:26.7.4` `start-dev`(로컬 컨테이너, 호스트 포트 18286), realm `r286`, client `machine-a`(SA, secret 인증, 토큰 수명 300 s), resource client `ldapium-api`(secret)·`ldapium-api-jwt`(`client-jwt`, 공개 인증서 등록)·`ldapium-api-sj`(`client-secret-jwt`). `machine-a`에 audience mapper 3개(위 세 client, `introspection.token.claim=true`)를 달아 토큰 `aud`가 `["ldapium-api-jwt","ldapium-api-sj","ldapium-api","account"]`가 되게 했다. 스크립트는 Python 표준 라이브러리 + `openssl`(RS256 assertion 서명)만 썼다. 실행: `python3 -I spike.py`(저장소 밖 스크래치).

### 4.1 (a) introspection `active:true` 경로와 호출자 인증 방식

`POST /realms/r286/protocol/openid-connect/token/introspect`, 같은 SA 토큰 `T1`:

| 호출자 인증 | 결과 |
|---|---|
| `client_secret_basic`(`ldapium-api`, `aud`에 있음) | 200 `active:true` (응답 키: `acr active aud azp client_id email_verified exp iat iss jti preferred_username realm_access resource_access scope sub token_type typ username`) |
| `client_secret_post`(`ldapium-api`) | 200 `active:true` |
| `private_key_jwt`(`ldapium-api-jwt`, RS256 assertion) | 200 `active:true` |
| `client_secret_jwt`(`ldapium-api-sj`, HS256 assertion) | 200 `active:true` |
| `Authorization: Bearer <다른 SA의 access token>` | **401** `invalid_client` — bearer는 받지 않는다 |
| `Authorization: Bearer <토큰 자신>` | 401 `invalid_client` |
| 인증 없음 | 401 `invalid_client` |
| 잘못된 secret | 401 `invalid_client` ("Client authentication failed.") |
| `machine-a`(토큰 `azp`, 그러나 `aud`에 없음)로 인증 | 200 `{"active":false}` |
| `ldapium-api`가 자기 SA 토큰(`aud`에 자신 없음)을 introspect | 200 `{"active":false}` |
| 쓰레기 토큰 | 200 `{"active":false}` |

디스커버리: `introspection_endpoint_auth_methods_supported = [private_key_jwt, client_secret_basic, client_secret_post, tls_client_auth, client_secret_jwt]`(`tls_client_auth`는 실행하지 않음). → **비밀이 아닌 방식**(개인키 서명 assertion)도 받지만 어느 방식이든 ldapium이 자격 증명(secret 또는 개인키)을 보관해야 하며, **bearer 방식은 불가**. 또한 호출자는 반드시 토큰 `aud`에 있는 별도 resource client여야 한다(없으면 `active:false`로 조용히 실패 — 설정 오류가 "폐기됨"처럼 보인다).

### 4.2 (b) client 비활성화 이후, 그리고 상태가 바뀌는 다른 경우

| 조작(모두 `T1` 발급 **후**) | `T1` introspection | 새 토큰 발급 |
|---|---|---|
| client 비활성화 | **`active:false`** | 401 `invalid_client` |
| client 재활성화 | **`active:true` 다시** (상태 기반이며 폐기가 기록되지 않는다) | 200 |
| SA 사용자(`service-account-machine-a`) 비활성화 | `active:false` | 401 `invalid_request` ("User ... disabled") |
| client secret 회전 | `active:true`(영향 없음) | 옛 secret 거부(부모 EVIDENCE §2.7) |

→ 비활성화 직후 같은 토큰이 오프라인 검증은 통과(부모 §2.7)하지만 introspection은 `false`다. introspection은 **현재 IdP 상태**를 보며, 비활성화를 되돌리면 폐기도 사라진다.

### 4.3 (c) RFC 7009 폐기 엔드포인트(`/protocol/openid-connect/revoke`)

| 조작 | 결과 |
|---|---|
| 발급 client 자격(`machine-a`)으로 `T2` 폐기(`token_type_hint=access_token`) | 200 (빈 본문) |
| 폐기 뒤 `T2` introspection | **`active:false`** |
| 같은 client의 다른 토큰 `T3` introspection | `active:true`(토큰 단위 폐기) |
| resource client(`ldapium-api`) 자격으로 `T3` 폐기 | **400** `invalid_request` "Unmatching clients" — 발급 client만 폐기 가능 |
| 폐기 뒤 JWKS(`/certs`) | 불변(키 id 2개 그대로). 오프라인 검증은 서명과 `exp`만 보므로 **`T2`를 여전히 통과**시킨다 |

→ 폐기 엔드포인트는 IdP 쪽 상태(introspection)에만 반영된다. ldapium의 오프라인 검증에는 신호가 가지 않는다. 폐기를 호출하려면 **토큰 보유자(발급 client의 secret)** 가 필요해 운영자가 가진 토큰 하나를 대신 폐기하는 수단으로는 맞지 않는다.

### 4.4 (d) not-before / 로그아웃

| 조작 | 결과 |
|---|---|
| `GET client`의 `notBefore` | 0 |
| `POST /admin/realms/r286/clients/{id}/push-revocation`(admin URL 미설정) | 200 `{}`이지만 `notBefore`는 0 그대로, `T4` 여전히 `active:true` — 푸시는 정책을 바꾸지 않고 알리기만 한다 |
| `PUT client {notBefore: now+1}` | 204, `notBefore`가 저장됨. 2초 뒤 이전 토큰 `T4` **`active:false`**, 이후 발급한 `T5`(`iat` ≥ notBefore)는 `active:true` |
| realm `POST logout-all` | realm `notBefore`가 현재 시각으로 설정됨, 그 이전 토큰 `T5` `active:false`, 이후 발급한 `T6`은 `active:true` |
| SA 사용자 `POST users/{id}/logout` | 204지만 `T6` 여전히 `active:true`(SA 토큰은 세션이 없다: `GET users/{id}/sessions`는 `[]`, 토큰에 `sid` 없음) |

SA access token에는 `nbf` claim이 없고(`T5` 확인), 토큰 응답의 `not-before-policy`는 0이었다. 즉 **not-before 정책은 client·realm 단위 cutoff로 실재하며 introspection에서만 효력을 낸다.** 오프라인 검증자에게는 전달 수단이 없다(admin URL로의 push 없이는). → ldapium이 디렉터리 cutoff(D2)를 스스로 두는 설계는 Keycloak not-before와 같은 의미(`iat < T`)이지만 Keycloak 기능에 의존하지 않는다. 시간 해상도는 초 단위(`notBefore`=정수 초, `iat`=정수 초).

### 4.5 (e) 인증서 바인딩 access token

- 디스커버리: `tls_client_certificate_bound_access_tokens: true`, `mtls_endpoint_aliases` 존재.
- client 속성 `tls.client.certificate.bound.access.tokens=true`를 PUT(204)한 뒤 평문 HTTP로 `client_credentials` 요청: **400** `invalid_request` "Client Certification missing for MTLS HoK Token Binding" (인증서 없이는 발급 거부).
- 인증서를 전달하는 경로: 두 번째 일회용 Keycloak에 `KC_SPI_X509CERT_LOOKUP_PROVIDER=nginx`, `KC_SPI_X509CERT_LOOKUP__NGINX__SSL_CLIENT_CERT=ssl-client-cert`를 주고 요청 헤더 `ssl-client-cert: <URL 인코딩된 PEM>`을 보내자 **200**, 토큰에 `cnf: {"x5t#S256": "LYkYn3gA7VJCmC3Zw-1J7UgwnOjIFrRbTZVSfQdJxdA"}`가 실렸고 `openssl x509 -outform der | sha256`의 base64url과 **일치**(SA 토큰에도 적용됨, `token_type`은 `Bearer`).
- 이 경로는 Keycloak이 **헤더를 그대로 신뢰**하는 구성이다(TLS 종단은 실행하지 않았다: 실제 `--https-client-auth` mTLS 핸드셰이크는 **미실행**). bound 토큰을 `azp` client로 introspect하면 `aud`에 없어 `active:false`.

결론(D10 근거): 발급·`cnf` 바인딩은 Keycloak에서 가능하지만, ldapium이 이를 쓰려면 ingress가 클라이언트 인증서를 앱에 전달하고 앱이 `cnf.x5t#S256`과 대조하는 헤더 신뢰 모델이 필요하다(별도 설계, 미구현).

## 5. T-002 — 디렉터리 실측 (`ldapium:l286a` = 이 worktree의 `image/` 빌드, 새 컨테이너)

준비: `docker build -t ldapium:l286a -f image/Dockerfile ./image` 후 `docker run -e LDAP_ROOT_DN=dc=example,dc=org -e LDAP_ADMIN_PASSWORD=<일회용>`. 명령은 `docker exec -i`로, 비밀번호 파일은 `printf`로 만든다(개행 없이: `ldapsearch -y`는 파일 전체를 비밀번호로 쓴다 — 개행이 있으면 `Invalid credentials (49)`가 난다). 머신 계정·ACL은 [machine-ldap-account.md](../../machine-ldap-account.md) 4–5절 그대로(ACL은 `scripts/test/fixtures/machine-acl/main-database.ldif` 적용, `olcAccess` 읽기로 `{0}`–`{2}` 확인).

### 5.1 후보 objectClass·속성 (스키마 읽기)

`ldapsearch ... -b cn=schema,cn=config olcObjectClasses olcAttributeTypes`(633줄)에서:
- **새 스키마 없이 쓸 수 있는 구조적 클래스**: `device`(`MUST cn MAY serialNumber seeAlso owner ou o l description`), `applicationProcess`(`MUST cn MAY seeAlso ou l description`). `organizationalUnit`은 컨테이너용. `extensibleObject`는 보조 클래스로 존재하나 정의된 속성 타입만 쓸 수 있다.
- GeneralizedTime 문법 속성: 사용자 쓰기 가능한 일반 속성은 없다(`createTimestamp`·`modifyTimestamp`·`reqStart`·`reqEnd`·`pwd*`·`oathTimestamp` 등은 운영/전용). 즉 `expires`는 `serialNumber`(PrintableString, 에포크 초 문자열)나 `description`에 넣어야 한다. `pwdEndTime`(운영 속성)은 관리자가 `device` 항목에 쓸 수 있음을 확인(`ldapmodify add: pwdEndTime`, 읽기도 됨) — 의미가 비밀번호 정책용이라 권장하지 않는다.

**후보 매핑(새 스키마 없음)**: `ou=revocations,ou=system,<root>`(`organizationalUnit`) 아래 `objectClass: device`, `cn: jti-<jti>` 또는 `cutoff-<client>`(RDN으로 중복 방지), `ou: <client id>`, `serialNumber: <expires 에포크 초>`(jti 항목), `description: kind=<jti|client-cutoff>;memo=<사유>`. 실제로 두 항목을 `ldapadd`로 만들었고(`ou=system`·`ou=revocations`·사람 항목 `uid=alice`는 `organizationalUnit`/`inetOrgPerson`) 성공했다. 이미지 변경 없음. (Revision 3: 최종 설계는 `serialNumber`=expires와 `description` 메모를 쓰지 않고 sentinel에만 `serialNumber`·`description`을 쓴다 — CHANGE.md D3·REQ-013. 이 절의 실측은 속성이 쓰기·읽기 가능하다는 근거로 유효하다.)

### 5.2 기본 머신 ACL `{0}`–`{2}`(`B`=루트) 아래 `M`의 읽기

관측(명령은 `ldapsearch -x -D uid=machine,ou=system,dc=example,dc=org -y /tmp/.pw-machine`):

| 시도 | 결과 |
|---|---|
| `-b ou=revocations,ou=system,<root> -s sub '(objectClass=device)' '*' createTimestamp` | rc 0, 두 항목 모두 반환(`cn ou serialNumber description createTimestamp objectClass`) |
| 필터 `(&(objectClass=device)(ou=machine-a))` | rc 0, 두 항목 매칭 |
| `uid=alice`에 `userPassword '*' '+'` 요청 | `userPassword` **없음**(`grep -ci userpassword` = 0), 다른 속성은 반환 |
| `(userPassword=*)` 필터로 alice 검색 | 관리자는 매칭, `M`은 **무매칭**(필터 속성에 접근 없음 → undefined) |
| `M` 자기 항목의 `userPassword` | 없음 |
| `M`이 revocation 하위에 `ldapadd`(`cn=jti-evil`) | rc 50 `Insufficient access` "no write access to parent"; 항목 미생성 확인 |
| `M`이 revocation 항목 `ldapmodify changetype: delete` | rc 50, 항목 그대로 |

→ 기본 구성(`B`=루트)에서는 **ACL 변경 없이** `M`이 위치를 읽고 쓰지 못하며 비밀 속성은 여전히 못 읽는다.

### 5.3 `B`를 좁힌 구성 (1건: `B=ou=people,<root>`)

`{1}`을 `dn.subtree="ou=people,<root>"`로 교체(`olcAccess` 삭제 후 `{1}` 재추가):
- `M`이 `ou=people`는 읽음(`uid=alice` 조회 rc 0), `ou=revocations` 검색은 **rc 32 `No such object`**(숨겨짐) → 폐기 갱신이 실패한다(D6의 fail closed가 작동하는 조건).
- 해결: `{2}to dn.subtree="ou=revocations,ou=system,<root>" by dn.exact="<M>" read by * break`를 `{2}`에 삽입(기존 `{2}to *`는 `{3}`으로 밀림) → 두 항목이 `serialNumber`·`createTimestamp`와 함께 읽힘(rc 0).
- 그 뒤에도 `ou=system` 부모 항목(rc 32), `M` 자기 항목(rc 32), alice `userPassword`(0건), 루트 `organizationalUnit` 검색(rc 32)은 여전히 숨겨짐.
→ `B`를 좁힌 배포는 revocation 서브트리에 대한 규칙 1개를 별도로 추가해야 한다(문서화 대상: T-013).

### 5.4 `createTimestamp`는 서버가 찍고 클라이언트가 못 쓴다

- 관리자 `ldapmodify replace: createTimestamp` → rc 19 `Constraint violation` "createTimestamp: no user modification allowed".
- 관리자 `ldapadd`에 `createTimestamp: 19990101000000Z`를 넣은 항목 → rc 19 같은 오류, 항목 미생성.
- 정상 추가한 항목의 `createTimestamp: 20261007134710Z`는 컨테이너 시각(`date -u` → `20261007134713Z`, 3초 뒤)과 일치. 다른 속성을 `replace`해도 `createTimestamp`는 그대로이고 `modifyTimestamp`만 갱신(`20261007134713Z`).
- 형식은 초 단위 UTC GeneralizedTime(소수 초 없음). `M`의 읽기에도 `createTimestamp`가 보인다(5.2).
미실행: 다중 provider 복제에서 다른 노드로 복제된 항목의 `createTimestamp` 값(복제 후에도 생성 노드의 값이 유지된다는 가정은 이 실측 밖).

## 6. T-003 — 기준선

### 6.1 file:line 재확인 (main `220f554`, 이 worktree)

| 사실 | 확인 |
|---|---|
| `serve` 정의 | `ui/backend/internal/httpapi/machine.go:284` |
| 순서: `admitIP`(`:286`) → `acquireAuthSlot`(`:292`) → `Verify`(`:303`) → 실패 시 `tk.fail()`(`:319`) → `budget.acquire`(`:333`) → `machineOpFor`(`:348`) | `grep -n` 결과로 확인 |
| 요청마다 LDAP bind | `httpapi/machine_exec.go:89` `bound, err := x.dialer.Bind(ctx, x.bindDN, x.bindPassword)`, 실패는 503 `machine LDAP bind failed`(폴백 없음) |
| `jti` 미사용 | `grep -rn jti ui/backend/internal/machineauth/*.go ui/backend/internal/httpapi/machine*.go`를 테스트 파일 제외하고 실행한 결과 0건 |
| `Principal` | `machineauth/claims.go:59-64` — `ClientID Scopes SubjectHash Expiry`뿐(`iat`·`jti` 없음) |
| `iat` 읽기·skew | `claims.go:121-122`(`iat.After(now.Add(Skew))` 거부), 수명 `claims.go:129`, 만료 `claims.go:141`(`now.After(exp.Add(Skew))`) |

TASKS가 적은 `h/machine.go:284-345` 범위와 일치한다(폐기 훅 위치 = `:303` `Verify` 직후 ~ `:333` 직전).

### 6.2 기존 드릴 현재 결과

```
LDAPIUM_IMAGE=ldapium:l286a LDAPIUM_UI_IMAGE=ldapium-ui:l286a LDAPIUM_TEST_PREFIX=l286a-md- \
  python3 scripts/test/test-machine-revocation-drill.py
...
PASS: (a) the token issued BEFORE the disable STILL passes on every replica until it expires (documented: disabling the client is not revocation)
PASS: (b) after the rollout the SAME token is 401 token_invalid on every new replica, BIND COUNT 0
PASS: (c) with MACHINE_AUTH_ENABLED=false the bearer is ignored: the same 401 unauthenticated as a request without credentials, BIND COUNT 0
PASS: (d) rollback: with the original allowlist the still-unexpired svc-drill token passes again on every replica
PASS: no token or secret in the 10 container logs: []
All revocation drill checks passed: 18 checks in 23s.
```

성공 18/18, 실패 0(`ldapium-ui:l286a`는 `docker build -t ldapium-ui:l286a -f ui/Dockerfile ui`로 이 worktree에서 빌드, 종료 뒤 남은 컨테이너·네트워크 없음). 이 드릴은 **현재 기능에 대한** 기준선이다: 폐기 항목이 없으므로 jti·cutoff 폐기 검사는 아직 없다(T-017).

## 7. T-004 — 10000 항목 subtree 조회 (새 컨테이너, 단일 노드)

항목: `device`, `cn=jti-<uuid>`, `ou=machine-<n>`, `serialNumber`, `description=kind=jti;memo=incident-NNNNN leaked token`(LDIF 원본 2.51 MB). `ldapadd -c`로 10003개(상위 3 포함) 모두 성공. 머신 bind, 기본 ACL.

| 질의(머신 bind, `-s sub '(objectClass=device)'`) | 항목 수 | rc | LDIF 크기 | 지연(10회, 정렬, ms) |
|---|---|---|---|---|
| `*` + `createTimestamp` | 10000 | 0 | 2 840 000 B | 49 50 51 51 51 52 53 56 57 59 |
| `cn ou serialNumber description createTimestamp` | 10000 | 0 | 2 640 000 B | 47 47 48 49 49 49 50 50 52 54 |
| `ou serialNumber createTimestamp`(DN은 항상 반환) | 10000 | 0 | — | 45 46 46 46 47 47 47 48 48 50 |

지연은 컨테이너 안의 `ldapsearch` 프로세스 생성 + 루프백 + bind 포함 벽시계 시간이다(`date +%s%N`). 루프백 카운터(`/proc/net/dev` `lo`) 증가분은 한 번 질의당 약 3.87 MB / 3.76 MB / 2.53 MB(세 질의 순서, bind·TCP 프레이밍 포함 상한 근사).

서버 한계:
- 메인 DB `olcSizeLimit: 10000`(이미지 기본, `LDAP_SIZE_LIMIT`; `image/README.md:89`), `olcTimeLimit: 3600`, `olcSockbufMaxIncoming: 262143`(요청 쪽). 비-root 계정(머신 `M`)은 이 한도를 받는다.
- 항목을 5개 더해 10005개로 만든 뒤: **머신 bind는 rc 4 `Size limit exceeded`에 10000개만 받음**, 관리자(rootdn)는 10005개 전부. 페이지 검색(`pr=1000`)도 총량에 한도가 적용되어 같은 결과(rc 4, 10000개).

### 7.1 결론

- 항목 1개가 LDIF로 약 260 B, 루프백 카운터로 약 250–390 B이므로(DN만 90 B 이상) 이 모양의 항목은 **약 2700–4000개에서 1 MiB**에 닿는다. 10000개는 1 MiB 응답 상한의 약 2.5–3.7배다 — **D4의 `MAX_ENTRIES` 기본 10000과 응답 1 MiB 상한은 서로 모순된다**(둘 다 지키면 실제 한계는 약 2700–4000개).
- `MAX_ENTRIES`(10000)가 서버 `olcSizeLimit`(10000)와 같으면 한 항목만 넘쳐도 서버가 `Size limit exceeded`와 부분 결과를 돌려준다. 갱신 코드는 rc 4를 **갱신 실패**로 취급하고 부분 결과로 스냅샷을 만들지 않아야 한다(D6과 같은 방향, T-014에서 라이브로 검증). `MAX_ENTRIES`는 서버 한도 미만이어야 한다.
- 지연은 한 번에 약 50 ms 수준이라 5 s 주기·replica당 1회 부하는 작다(단일 노드, 다중 provider·원격 노드는 미측정).

## 8. T-004b — 2노드 multi-provider에서 `createTimestamp`·지연·분리 노드 (2026-10-07)

환경: `ldapium:l286a`(이 worktree 빌드) 2개, `LDAP_REPLICATION_ENABLED=true`, `LDAP_SERVER_ID=1/2`, `LDAP_REPLICATION_PEERS=<두 노드>`, `LDAP_REPLICATION_INTERVAL=00:00:00:05`, 같은 호스트·같은 도커 네트워크(시계 동일). 시작 직후 두 노드 `contextCSN`이 같음을 확인.

| 시도 | 결과 |
|---|---|
| node0에 `device` 항목 추가 후 node1을 폴링 | node1에 **145 ms**(폴링당 `docker exec` 오버헤드 포함 상한)에 나타남 |
| 항목의 `createTimestamp`·`entryCSN`·`creatorsName` | node0·node1이 **동일**(`20261007135737Z`, `entryCSN ...#001#...`): 복제된 항목의 `createTimestamp`는 **생성 노드가 찍은 값 그대로** 유지 |
| node1에서 같은 RDN을 삭제 후 재추가(cutoff 변경 모사) | 두 노드 모두 새 `createTimestamp`(`...135743Z`, `entryCSN ...#002#...` = node1이 생성)로 수렴 |
| node1을 네트워크에서 분리(`docker network disconnect`)하고 node0에 항목 추가, 12 s 뒤 node1 조회 | node1은 **rc 0, 이전 데이터(항목 1개)** 반환(node0은 2개). 관리자 bind도 성공. 즉 **뒤처진 노드는 오류 없이 오래된 스냅샷을 준다** — "항목 없음"과 구별되지 않음 |
| 네트워크 재연결 | **902 ms**(폴링 상한) 안에 따라잡음. 복제된 항목의 `createTimestamp`는 양쪽 동일 |

의미: (1) `createTimestamp`는 복제를 거쳐도 변하지 않으므로 D7의 T는 "항목을 만든 노드의 시계"다(이 실측의 두 노드는 같은 시계라 **노드 간 시계 오차의 영향은 미측정**). (2) 건강한 2노드의 전파는 1 s 미만이지만, 분리·지연된 노드는 rc 0과 오래된 데이터로 응답하므로 소비자는 이를 오류 없이 받아들일 수 있다 — 이를 막으려면 소비자 쪽 정상성 신호(CHANGE.md Revision 3의 sentinel·heartbeat)가 필요하다. 미실행: 3노드 이상, 양쪽 노드 동시 쓰기(entryCSN 기반 last-write-wins, AGENTS.md), 노드 간 시계 오차, 부하 중 지연.

## 9. 머신 DN의 `createTimestamp` 필터와 값 조건부 modify (Revision 5 라이브 확인, 2026-10-07)

환경: `ldapium:l286a`(이 worktree 빌드) 단일 노드, §5와 같은 머신 계정·기본 ACL `{0}`–`{2}`(`B`=루트), `ou=revocations,ou=system`에 `device` 항목 2개(`cn=jti-a`, `cn=jti-b`)와 `cn=sentinel` 1개.

| 시도(머신 bind, `-s sub`) | 결과 |
|---|---|
| `(&(objectClass=device)(createTimestamp>=20200101000000Z))` | 3개(전부) — 관리자 결과와 같음 |
| `(&(objectClass=device)(createTimestamp>=20991231000000Z))` | 0개 |
| `(&(objectClass=device)(createTimestamp<=<now>))` | 3개 |
| `(\|(!(cn=jti-*))(createTimestamp>=20991231000000Z))`(설계 필터에서 `objectClass=device` 뺌) | **`ou=revocations` 컨테이너 항목과 sentinel**이 반환됨 — 컨테이너에는 `cn`이 없어 `!(cn=jti-*)`가 참. 그래서 필터에 `objectClass=device`가 필요하다 |
| sentinel base 읽기 | `serialNumber`·`description`·`createTimestamp`·`modifyTimestamp` 모두 읽힘 |

→ 머신 DN은 `createTimestamp`에 대한 범위 필터(`>=`, `<=`)를 정상 평가하고 `modifyTimestamp`를 읽는다(필터 속성이 undefined가 되는 §1·AGENTS.md의 경우가 아님: 기본 ACL이 `B` 안 모든 속성에 `read`를 준다). 설계 변경 없음. `B`를 좁힌 구성(§5.3)에서는 revocations 규칙이 `to dn.subtree`이므로 같은 효과임을 이 항목에서 별도로 재측정하지는 않았다(**미실행**).

값 조건부 modify: 관리자가 sentinel `description`을 `delete: description`(옛 값 지정) + `add: description`(새 값)으로 갱신. 첫 쓰기 rc 0, 같은 옛 값을 쓰는 두 번째 쓰기는 **rc 16 `No such attribute`("modify/delete: description: no such value")**로 실패하고 값은 첫 쓰기 것(`ts=2`)으로 남음 → 동시에 도는 두 heartbeat는 조용히 덮어쓰지 못한다.

## 11. T-014 source draft (2026-10-08)

The LDAP source opens a fresh machine-bound connection per refresh. Sentinel / subtree / sentinel use that connection, a total five-second deadline, a server size limit of MAX_ENTRIES+2, and a one-entry streaming buffer. A changed sentinel is retried once within the original query budget. Fixed error messages prevent LDAP diagnostics from leaking into logs. Decoded retained rows are capped at 1 MiB; this does **not** bound go-ldap's allocation for an individual wire entry before decoding.

Local evidence (disposable `ldapium:revocation-review`, T-013 tool from draft #323):

```
LDAPIUM_IMAGE=ldapium:revocation-review \
LDAPIUM_REVOCATION_TOOL=/tmp/ldapium-revocation-tool/scripts/machine-revocation.sh \
go test -tags live ./internal/ldapclient -run TestRevocationReaderLive -count=1 -v
```

Observed: missing sentinel refused; init then empty snapshot accepted; tool-written JTI revoked and removal restored OK; real bad password returned rc49 classification; generation regression refused; unpublished row caused count mismatch; multivalued cn was malformed; hidden sentinel and clock-injected stale sentinel were refused; stopped LDAP failed refresh and old snapshot expired; restart recovered after restoring the disposable ACL, publishing heartbeat, and rereading Docker's dynamically reassigned host port. No token/credential values were printed. The harness initially failed because of an incorrect ldapi socket/auth choice, then because its old Docker host port was reused after restart; both were corrected before claiming recovery.

State-machine race tests verify retain/expire/recover, max-generation propagation, 60 s to 15 m credential backoff, reset on success, cancellation, and cumulative counters. Metrics appear only when the source is enabled, on the existing private metrics listener. The request path is unchanged (T-015).

Not yet verified: L4 node alternation, real partition/lagged replica, torn-sentinel retry live, response-size/entry-cap live, CI integration with the merged T-013 tool, and independent security review. T-014 remains unchecked. This draft alone does not enable token enforcement or complete #286.

Validation: `make check` exited 0 (frontend lint/build, backend formatting/vet including live tags, backend tests/build, shell/Helm/manifests/licenses and reachable vulnerability checks). Final live run passed in 5.193 s. Logs: `/tmp/ldapium-source-{check,live,tests}.log`. No entrypoint/image/schema/Helm/request-path changes.
