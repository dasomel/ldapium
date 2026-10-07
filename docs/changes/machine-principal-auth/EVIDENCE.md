# Evidence: 외부 HTTP API용 머신 주체 인증

설계: [CHANGE.md](CHANGE.md) · 작업: [TASKS.md](TASKS.md)

- 수집일: 2026-10-07 (T-001, T-004)
- 출처 1: **실제 Keycloak 26.7.4 실행**(`quay.io/keycloak/keycloak:26.7.4`, `start-dev`, 로컬 컨테이너)에서 관측한 토큰·JWKS·비활성화 거동과, 같은 realm에 대해 `go-oidc v3.21.0` 스크래치 프로그램(저장소 밖)을 돌려 얻은 검증기 거동.
- 출처 2: **코드 읽기** — `openapi.json` 집계(`jq`로 재확인)와 핸들러·미들웨어·설정 소스. 코드 읽기 결과는 Gemini 워커의 재집계 보고를 받아 작성자가 코드·OpenAPI 파일과 대조해 확인했고, 틀리거나 검증하지 못한 부분은 표시했다.
- 비밀 처리: 토큰 서명, `jti`, client secret, 관리자 비밀번호는 기록하지 않았다. 아래 claim 값은 비밀이 아닌 식별자·시간값이다.
- 이 문서는 구현 증거가 아니라 **설계 입력**이다. ldapium 코드에는 머신 인증이 아직 없다.

## 1. 오퍼레이션 집계 (코드 읽기)

`jq`로 `ui/backend/internal/httpapi/openapi/openapi.json`을 집계한 결과(재현 명령은 아래 “재현” 절).

| 구분 | 개수 |
|---|---|
| 전체 오퍼레이션 | 53 |
| 공개(`security: []`) | 8 |
| 세션 보호 | 45 (GET 20 + 비-GET 25) |
| 머신 허용 후보(기본 6 + opt-in 2) | 8 |
| 머신 거부 | 37 (denylist 36 + `getMe`) |

이전 패키지의 “48개 = 공개 8 + 보호 40”에서 빠진 5개: `patchUser`(PATCH `/api/users`), `patchGroup`(PATCH `/api/groups`), `getBackupJob`(GET `/api/v1/backups/jobs/{id}`), `listBackupJobs`(GET `/api/v1/backups/jobs`), `cancelBackupJob`(POST `/api/v1/backups/jobs/{id}/cancel`). 보호 GET 20개 = 허용 후보 8 + `getMe` 1 + 프로파일 8 + 백업 3.

### 코드 경계 관측

| 항목 | 관측 | 위치 |
|---|---|---|
| `getMonitor`가 감사 로그를 반환 | `MonitorStats`가 `recentLogsLocked(ctx, 50)`로 `cn=accesslog` 최근 50건을 `RecentLogs`에 넣는다(최선 노력). 행위자·대상 DN·검색 필터·변경 속성명 포함 | `ldapclient/monitor.go:98-101` |
| `getEntry`가 임의 DN을 `*`로 읽음 | `validate.DN`만 통과하면 BaseDN 하위 제한 없이 `[]string{"*","entryCSN"}` 조회 | `httpapi/tree_handlers.go:33-50`, `ldapclient/tree.go:106-125` |
| 속성 denylist 범위 | `entryRedactedAttrs`는 `userpassword`만. accesslog 항목의 `reqMod` 값(예: `userPassword:= {SSHA}…`)은 걸러지지 않음 | `ldapclient/tree.go:100` |
| 감사 DTO | `extractChangedAttrs`는 `reqMod`에서 속성 **이름**만 추출(값 미노출). 따라서 감사 DTO에는 이름 `userPassword`가 정상적으로 나올 수 있다 | `ldapclient/audit.go:27` |
| `*`를 요청해 그대로 반환하는 GET | `getEntry`뿐. users/groups/policies는 명시 속성 목록, tree는 `objectClass`, server-settings는 Root DSE `+` | recount 보고, `getEntry` 재확인 |
| SSO issuer 검증 | `parseHTTPURL`은 scheme이 http 또는 https이기만 하면 통과 → 원격 `http://` issuer 허용 | `config/config.go:562-581` |
| 커서 바인딩 | `HMAC("sid:" + sess.ID)`; 키는 `SESSION_SECRET`에서 유도(`cursorKey`) | `httpapi/cursor.go:58-71` |
| 로그인 limiter 상태 | `map[string][]time.Time`, 호출된 IP만 lazy prune, 상한·주기 sweep 없음 | `httpapi/login_limiter.go:19-60` |
| 미들웨어 순서 | `corsMiddleware`(설정 시) → `originGate` → … → `authed := api.Group("", s.requireSession)` | `httpapi/server.go:115-121,158` |
| CORS | `Authorization`을 허용 헤더로 두지 않음 | `httpapi/cors.go` |
| 기본 ACL | `to * by self write by users read`가 catch-all(`image/entrypoint.sh:894-895,905-906`); accesslog DB는 `cn=admin,cn=accesslog`만 read(`:1023`) | `image/entrypoint.sh` |
| 메인 DB ACL 선두 규칙 | `olcAccess: {0}to attrs=userPassword,shadowLastChange by self write by anonymous auth by * none`가 템플릿에서 이미 맨 앞. 뒤따르는 렌더링(`#__ANON_READ_ACCESS__`): `LDAP_ANONYMOUS_READ_BASE` 미설정 → `{1}to attrs=entry,uid,objectClass by anonymous read by users read`, `{2}to * by self write by users read by anonymous none`; 설정 → `{1}`(base 한정 anonymous/users read), `{2}to attrs=entry by anonymous search by users read`, `{3}to attrs=uid,objectClass by users read`, `{4}to * by self write by users read by anonymous none`. 즉 인증된 모든 DN이 `by users read`로 entry/uid/objectClass를 읽는다 | `image/ldifs/01-cn-config.ldif:90-93`, `image/entrypoint.sh:884-907` |
| rootdn 종류 | 메인 DB `olcRootDN: __LDAP_ADMIN_DN__`(기본 `cn=admin,<LDAP_ROOT_DN>`), monitor DB `cn=monitoring,cn=Monitor`, accesslog DB `cn=admin,cn=accesslog`, config DB `cn=admin,cn=config` | `01-cn-config.ldif:71,153`, `entrypoint.sh:1009`, `02-cn-config-admin.ldif:23-24` |
| monitor·accesslog DB ACL | monitor: `to * by dn.exact="cn=monitoring,cn=Monitor" read by * none`; accesslog: `{0}to * by dn.exact="cn=admin,cn=accesslog" read by * none` → 머신 DN은 기본 거부 | `01-cn-config.ldif:156`, `entrypoint.sh:1023` |
| DN 목록 직렬화 | `BACKUP_ADMIN_DNS`·`APP_PROFILES_ADMIN_DNS`는 **세미콜론** 구분(`splitEntries`: 공백 제거·중복 제거, 따옴표/escape 처리 없음) — DN 내부 쉼표가 있어 쉼표 목록은 쓸 수 없다 | `config/keycloak.go:69-78`, `config/config.go:206,234` |
| Origin gate 범위 | `/api` 경로의 POST/PUT/PATCH/DELETE이면서 `Origin` 헤더가 **있을 때만** 검사; GET과 `Origin` 없는 요청은 통과 | `httpapi/origin_gate.go:37-54` |
| SSO 초기화 실패 | `cfg.SSO.Enabled`이면 10s 컨텍스트로 `newOIDCAuthenticator`를 호출하고 실패하면 `New`가 오류를 반환(기동 실패) | `httpapi/server.go:79-86` |
| 로그인 limiter 의미 | 기본 한도 10회/1m(`UI_LOGIN_FAILURE_LIMIT`·`_WINDOW`), 슬라이딩 윈도우, 성공 시 초기화 없음(실패가 윈도우 밖으로 밀려날 때까지), `allow`와 `recordFailure`가 분리돼 동시 시도 overshoot 가능. 상태 무상한은 이슈 #270 | `httpapi/login_limiter.go`, `config/config.go:290-302` |
| 오류 코드 | `unavailable`(503)은 존재. `token_invalid`·`token_expired`·`scope_denied`는 예약만 되고 방출되지 않음 | `httpapi/errors.go`, api-error-envelope D218-3 |
| `openapi.json`·`llms.txt` | 코드 생성이 아닌 수작업 관리 | `httpapi/api_docs.go` |

재검증하지 못해 패키지에 옮기지 않은 항목: recount 보고의 핸들러 file:line 열(일부가 서로 다른 오퍼레이션에 같은 줄을 가리킴: 예 `getKeycloakRoles`/`getApplicationRoles`, `putBackupConnection`/`deleteBackupConnection`). 오퍼레이션 집합·R/W 분류는 `jq` 결과와 일치함을 확인했다.

## 2. 실제 Keycloak 26.7.4 관측 (T-004)

환경: realm `r214`, 클라이언트 `machine-a`/`machine-b`(service account, confidential), `ldapium-sso`(confidential, standard flow + direct access grant), 사용자 `alice`. `go-oidc v3.21.0`, `go-jose v4.1.4`(`ui/backend/go.mod`).

### 2.1 서비스 계정 access token (machine-a, audience mapper + `directory.read` 기본 scope; 서명 생략)

```
header : {"alg":"RS256","typ":"JWT","kid":"<kid>"}
payload: {"exp":<iat+300>,"iat":<iat>,"jti":"<redacted>","iss":"http://localhost:18214/realms/r214",
          "aud":["ldapium-api","account"],"sub":"<service-account user uuid>","typ":"Bearer","azp":"machine-a",
          "acr":"1","realm_access":{...},"resource_access":{"account":{...}},
          "scope":"profile directory.read email","email_verified":false,
          "clientHost":"192.168.65.1","preferred_username":"service-account-machine-a",
          "clientAddress":"192.168.65.1","client_id":"machine-a"}
```

- JOSE `typ`는 `JWT`(`at+jwt` 아님). `nbf` claim 없음. `sub`는 서비스 계정 사용자 UUID(client id 아님). 토큰 응답에 `id_token`·`refresh_token` 없음.
- 수명: realm 기본 `accessTokenLifespan` 300s(`exp-iat=300`). realm 600s 설정 시 600 확인. client 속성 `access.token.lifespan=120` 설정 시 `expires_in=120` 확인(client_credentials에도 적용).

### 2.2 `aud`

| 구성 | `aud` |
|---|---|
| 기본(mapper 없음) | 문자열 `"account"` (배열 아님) |
| `oidc-audience-mapper`(`included.custom.audience=ldapium-api`, `access.token.claim=true`) | 배열 `["ldapium-api","account"]` |
| 같은 realm의 mapper 없는 `machine-b` | `"account"` 유지 |

작동한 mapper 설정(`POST clients/{id}/protocol-mappers/models`):
`{"name":"aud-ldapium-api","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper","config":{"included.custom.audience":"ldapium-api","id.token.claim":"false","access.token.claim":"true","introspection.token.claim":"true"}}`

→ 검증기는 문자열·배열을 모두 받아야 하고, `account`는 항상 있으므로 **정확한 멤버십**으로만 판정한다. 전용 audience mapper 없이는 사용자 지정 `aud`가 생기지 않는다.

### 2.3 토큰 종류 구분

| 토큰 | payload `typ` | `aud` | `azp` | `client_id` | `sid` | `preferred_username` |
|---|---|---|---|---|---|---|
| SA access (machine-a) | `Bearer` | `[ldapium-api, account]` | machine-a | machine-a | 없음 | `service-account-machine-a` |
| SA ID token(`scope=openid`로 client_credentials 호출 시 **같이 발급됨**) | `ID` | `machine-a` | machine-a | 있음 | 없음 | — (`scope` claim 없음) |
| `ldapium-sso` 사람 access(password grant) | `Bearer` | `account` | ldapium-sso | **없음** | 있음 | `alice` |
| `ldapium-sso` ID token | `ID` | `ldapium-sso` | ldapium-sso | — | 있음 | — |
| Refresh token | `Refresh` | issuer URL | — | — | — | — |
| **machine-a에서 password grant로 발급한 사람 access**(같은 client에 direct access grant 활성) | `Bearer` | `[ldapium-api, account]` | machine-a | **없음** | 있음 | `alice` |

마지막 행이 핵심이다. `aud`·`azp`·`scope`가 SA 토큰과 **동일**하다. 구분 근거는 `client_id`/`clientHost`/`clientAddress` 존재와 `preferred_username == "service-account-<client>"`뿐이다(`sid` 부재도 이 표의 관측이지만 §2.9에서 refresh를 켠 SA 토큰은 `sid`를 가짐이 확인되어 구분 근거로 쓸 수 없다). JOSE `typ`는 access/ID 모두 `JWT`라 구분력이 없다.

### 2.4 scope

client scope `directory.read`(기본)·`directory.write`(optional)를 만들어 확인: scope 요청 없음 → `"profile directory.read email"`; `scope=directory.write` → `"profile directory.write directory.read email"`; `scope=bogus` → `invalid_scope`. `scope`는 공백 구분 문자열, 순서는 알파벳순 아님, 기본 `profile`/`email`이 항상 섞인다 → 서버 allowlist와의 교집합으로만 해석.

### 2.5 issuer

`iss`·`jwks_uri`·`token_endpoint`는 요청 Host를 따른다(`start-dev`, `KC_HOSTNAME` 없음; `X-Forwarded-*` 무시). `kc-r214:8080`로 받은 토큰은 `http://localhost:18214/...` issuer를 쓰는 검증기에서 거부된다. `KC_HOSTNAME=https://sso.example.test`면 호출 경로와 무관하게 모두 그 URL. `KC_HOSTNAME_BACKCHANNEL_DYNAMIC=true`면 issuer는 공개 URL, `jwks_uri`/`token_endpoint`는 요청 Host 기반(분리 가능, go-oidc는 discovery issuer == `NewProvider` 인자만 요구). 실행하지 않음: `oidc.InsecureIssuerURLContext` 분리.

### 2.6 discovery·JWKS

- `id_token_signing_alg_values_supported`에 `HS256/384/512` 포함 → go-oidc 기본(`SupportedSigningAlgs` 비움)은 provider 목록을 따르므로 **명시 allowlist 필수**. ES256-only 설정이 RS256 토큰을 `unexpected signature algorithm`으로 거부함을 확인.
- JWKS는 2키: `use=sig`(RS256)·`use=enc`(RSA-OAEP) → `use=sig`만 사용. 헤더에 `kid` 항상 존재.
- 회전: 새 rsa-generated provider(priority 200) 추가 → JWKS에 두 서명 키, 새 토큰은 새 kid, 옛 kid 토큰도 검증됨(overlap). 옛 provider 삭제 → JWKS에서 제거, 그 kid의 토큰은 `failed to verify id token signature`(잘못된 서명과 구분 불가 → 401).
- go-oidc 동작(소스 `verify.go`, `jwks.go` 확인): 키는 메모리에 무기한 캐시(TTL·Cache-Control 미사용), **kid 미스 또는 캐시된 kid의 서명 실패 시** 모두 JWKS 재조회(동시 요청 병합만 있고 최소 간격 없음). Keycloak 중지 상태에서 변조 토큰 → `fetching keys oidc: get keys failed … connection refused`(`fmt %w` 체인의 문자열로만 구분 가능, 타입 없음). 캐시된 kid의 유효 토큰은 IdP 중지 후에도 검증됨.
- go-oidc 시간 검증(`verify.go:261-280`): `SkipExpiryCheck`가 false일 때만 exp(오차 없음)와 nbf를 확인하고, nbf는 **하드코딩 5분 leeway**(설정 불가). nbf 검사가 `SkipExpiryCheck` 블록 **안**에 있으므로 `SkipExpiryCheck:true`로 두면 exp·nbf 모두 자체 검증으로 대체된다(`SkipExpiryCheck` 동작은 관측으로 확인, `Config.Now` 주입 가능: +1h → `token is expired`).
- go-oidc가 하지 않는 것: payload `typ`, `azp`/`client_id` 허용 목록, `exp-iat` 상한, scope 파싱, SSO client 제외, SA/사람 구분 → 자체 코드 필요.
- `Verifier(&oidc.Config{ClientID:"ldapium-api"})`는 `aud` 멤버십만 확인하며 배열·문자열 모두 처리(`machine-a`/`ldapium-sso`를 ClientID로 주면 `expected audience` 오류).

### 2.7 비활성화·회전·중지

- client 비활성화 → 새 `client_credentials`는 401 `invalid_client`. **비활성화 이전에 발급된 토큰은 비활성화 후에도 go-oidc 검증을 통과**(JWKS 불변 확인). 즉 비활성화는 이미 발급된 JWT를 폐기하지 않는다.
- secret 회전 → 옛 secret 401 `unauthorized_client`, 이미 발급된 토큰은 영향 없음.
- introspection은 호출 client가 토큰 `aud`에 없으면 `{"active":false}` → `aud=[ldapium-api, account]`에서는 `machine-a`·`machine-b`·`ldapium-sso` 모두 introspect 불가(후속 옵션은 `aud`에 있는 별도 resource client 필요). SA 토큰으로 `userinfo`는 `openid` scope 없으면 403.
- Keycloak 중지: JWKS 요청은 connection refused(curl exit 7).
- token exchange: 기본 설정에서는 비활성(“Standard token exchange is not enabled…”). 활성화 시 거동은 §2.9(2026-10-07 추가 실험).

### 2.8 실행하지 않음

legacy(v1) token exchange의 권한(management permissions) 경로 완성(§2.9: 이 이미지에서 `Feature not enabled`), audience mapper가 `ldapium-sso`와 공유된 client scope에 있을 때의 SSO 토큰 오염, `InsecureIssuerURLContext` 분리, 실제 시계 skew·nbf 경계, introspection `active:true` 경로. 해당 항목은 [TASKS.md](TASKS.md)의 e2e 항목으로 이관됐다.

### 2.9 추가 실험 (Revision 3, 2026-10-07, 실제 Keycloak 26.7.4)

같은 고정 이미지(`quay.io/keycloak/keycloak:26.7.4`, `start-dev`)에 별도 realm(`r214c`), 컨테이너·네트워크 이름 접미사 `r214c`로 실행하고 종료 후 제거했다. 모든 SA client는 §2.2의 audience mapper와 `directory.read` 기본 scope를 가진다. 서명·`jti`·시간 claim은 생략했다. 표의 “룰 (i)(ii)”는 CHANGE.md D5의 SA 판별(`client_id == azp`, `preferred_username == "service-account-" + client_id`).

| # | 구성 | 관측된 access token claim (요약) | `client_id` | `preferred_username` | `sid` | 룰 (i)(ii) |
|---|---|---|---|---|---|---|
| 1 | 기준: SA client_credentials | `azp=machine-a`, `aud=[ldapium-api,account]`, `typ=Bearer`, `clientHost`·`clientAddress` 있음 | `machine-a` | `service-account-machine-a` | 없음 | 통과 |
| 2 | **lightweight access token**(client 속성 `client.use.lightweight.access.token.enabled=true`) | `azp`·`scope`·`typ=Bearer`만 남음. `aud`·`client_id`·`preferred_username` 없음 | 없음 | 없음 | 없음 | **거부**(정상 SA 토큰이 깨짐 → lightweight OFF 필수) |
| 3 | **refresh 사용 SA**(`client_credentials.use_refresh_token=true`) | 응답에 `refresh_token`·`session_state` 추가, access token에 **`sid` 있음**; refresh token `typ=Refresh`, `aud`=issuer, `sid` 동일 | `machine-d` | `service-account-machine-d` | **있음** | 통과 → **`sid` 부재를 요건으로 쓰면 정상 SA가 거부됨** |
| 4 | 같은 refresh 사용 client에서 password grant 사람 토큰 | `azp=machine-d`, `aud`·`scope` 동일 | 없음 | `alice` | 있음 | 거부(`client_id` 없음) |
| 5 | `profile` default scope 제거 | `preferred_username` 없음 | 있음 | 없음 | 없음 | 거부(ii) |
| 6 | `profile`+`service_account` default scope 제거(`client_id`·`clientHost`·`clientAddress`는 `service_account` scope의 mapper가 공급) | `azp`·`scope`·`sub`만 | 없음 | 없음 | 없음 | 거부 |
| 7 | **standard token exchange**(client 속성 `standard.token.exchange.enabled=true`), subject=그 client의 SA 토큰, 요청 audience 없음 | 새 access token: `azp=machine-a`, `preferred_username=service-account-machine-a`, `sub`=SA 사용자 | **없음**(`clientHost` 없음) | `service-account-machine-a` | 없음 | **거부(i)** — 다만 (ii)만 검사하는 OR 규칙이면 통과 |
| 8 | standard exchange, subject=사람 토큰(`alice`, 같은 client password grant) | `azp=machine-a`, `preferred_username=alice`, `sub`=alice | 없음 | `alice` | 있음 | 거부 |
| 9 | exchange 요청 `audience=machine-x`(해당 audience 없음) / `audience=ldapium-api` | `invalid_request: Requested audience not available` / `invalid_client: Audience not found` | — | — | — | — |
| 10 | 다른 client(`machine-b`, standard exchange 미설정)가 machine-a의 SA 토큰으로 요청 | `access_denied: Client is not within the token audience` | — | — | — | — |
| 11 | **legacy `token-exchange` feature를 켠 서버**(`KC_FEATURES=token-exchange`)에서 `standard.token.exchange.enabled` **미설정**인 `machine-b`가 자기 SA 토큰을 exchange | **성공**: `azp=machine-b`, `preferred_username=service-account-machine-b`, `client_id` 없음 | 없음 | `service-account-machine-b` | 없음 | 거부(i) — 서버 feature가 켜지면 client 설정 없이도 exchange가 됨 |

해석:
- 서비스 계정 판별에서 `sid` 부재는 **쓸 수 없다**(행 3). `client_id`가 있고 `azp`와 같은 것이 사람·exchange·lightweight 토큰을 가르는 관측된 유일한 기준이다. exchange로 만든 SA 토큰은 `client_id`가 없어 거부되므로, 머신 client는 exchange를 쓸 수 없다(의도적).
- `client_id`·`preferred_username`을 공급하는 mapper(`service_account`·`profile` scope)를 지우거나 lightweight를 켜면 정상 SA 토큰이 전부 거부된다(fail closed). 운영 요건과 라이브 점검이 필요하다.
- 기본 서버(feature 미변경)에서는 exchange가 기본 비활성이다(§2.7). legacy feature를 켜면 client 설정 없이 exchange가 된다(행 11).
- legacy exchange의 management permissions 경로(`PUT clients/{id}/management/permissions`)는 이 서버에서 `Feature not enabled`로 완성하지 못했다(행 11 이후의 impersonation·audience 허용 시나리오는 미검증).
- `standard.token.exchange.enabled`·lightweight·refresh 설정은 모두 client 속성이며 `ldapium`이 읽을 수 없다 → 서버 쪽 방어는 토큰 claim 규칙뿐이고 설정 점검은 운영 문서·라이브 e2e의 몫이다.

## 3. 재현

```sh
O=ui/backend/internal/httpapi/openapi/openapi.json
jq '[.paths|to_entries[]|.key as $p|.value|to_entries[]|select(.key|test("^(get|put|post|delete|patch)$"))
     |{id:.value.operationId,m:.key,p:$p,sec:(.value.security|tostring)}]
    | length, (map(select(.sec=="[]"))|length), (map(select(.sec!="[]"))|length),
      (map(select(.sec!="[]" and .m=="get"))|length), (map(select(.sec!="[]" and .m!="get"))|length)' $O
# 53 8 45 20 25
```

## 4. 머신 ACL 읽기 전용 라이브 증명 (T-015 / T-026 / AC-018, 단위 3, 2026-10-07)

환경: Docker 29.8.2 (macOS), 이미지 `ldapium:a3`(`sha256:e8c48181691c…`, 이 브랜치의 `image/`를 변경 없이 빌드), UI 이미지
`ldapium-ui:a3`(`sha256:be3f0b49141a…`), OpenLDAP은 이미지 내장 빌드. 컨테이너는 `--network none`, 비밀은 0600 파일·stdin만.
스크립트: `scripts/test/test-machine-acl-readonly-live.py`. 관리 명령은 운영 가이드의 것과 문자 그대로 같다(스크립트가 가이드 본문에서
적용·조회·롤백 명령과 LDIF 블록이 동일함을 검사한다).

### 4.1 결과 (실제 실행; 수정 라운드 후 이미지 `ldapium:a3b`/`ldapium-ui:a3b`)

| 실행 | 결과 |
|---|---|
| 정상 | `RESULT: 349 checks passed, 0 failed, mutation=none, 20s`, 종료 0 (첫 라운드 238, 여덟 비밀 속성 증명 추가로 349) |
| 변이 11종: `scripts/test/test-machine-acl-mutations.sh` (구성 a만) | 전부 `detected`, 종료 0: `reorder` 16, `widen` 12, `nosecret` 35, `drop:<속성>` 8종(`userPassword` 8, 나머지 7)개 실패 검사 + 예상한 이름의 검사 포함 |
| 인프라 오류 대조: 같은 드라이버를 존재하지 않는 이미지로 실행 | 11종 전부 `NOT DETECTED (the run ended in an error, not in a failed check)`, 종료 1 (스크립트는 `ERROR: docker run: Unable to find image…`와 `RESULT: 6 checks passed, 0 failed`를 출력) |
| `test-machine-execution-live.py`(같은 LDIF, 새 비밀 속성 목록, 실제 UI 요청) | `69 PASS`, 종료 0 (단위 2의 `olcAccess` 기대 문자열을 새 목록에 맞게 한 줄 수정) |

**비밀 속성별 증명(수정 라운드):** 규칙 `{0}`이 보호하는 8속성 전부를 `uid=secrets,ou=people`에 알아볼 수 있는 값으로 심었다 — `userPassword`·`shadowLastChange`·
`userPKCS12`·`oathSecret`·`oathEncKey`·`oathTokenPIN`은 `extensibleObject`로(이 이미지의 slapd가 받는다), `pKCS8PrivateKey;binary`는 유효한 PKCS#8 DER(Ed25519 헤더+난수 32바이트),
`pwdHistory`는 운영 속성이라 그 항목의 비밀번호를 두 번 바꿔 생성. 속성마다 (1) 관리자 대조가 값을 읽음, (2) `M`이 명시 목록·`*`·`+`로 속성도 값도 받지 못함, (3) `(attr=*)` 필터가 아무것도
찾지 못함, 그리고 `M`이 같은 항목을 읽을 수 있음(빈 응답이 ACL 때문임)을 확인했다. 시드하지 못한 속성은 없다. 변이 `drop:<속성>`은 그 속성 하나만 규칙에서 빼며 해당 속성의 (2)·(3)이 실패한다.

변이가 실패시키는 검사의 예: `reorder`는 읽기 순서 확인과 함께 **자기 비밀번호 변경이 성공(rc 0)**한다. `widen`은 `B` 밖 항목이 반환되는 것, `nosecret`은 모든 비밀 속성이 반환되는 것을 잡는다.

### 4.2 세 구성 각각에서 확인한 것 (a: `LDAP_ANONYMOUS_READ_BASE` 미설정, b: `ou=people,<root>`, c: 운영자 선행 allow `{0}to attrs=description by users write`)

- 적용 전 대조(제어): `M`은 일반 사용자다 — `B` 밖을 읽고, 자기 항목을 쓰고, 자기 비밀번호를 바꾼다(`by self write`). (c)에서는 다른 항목의 `description`도 쓴다(운영자 규칙).
  이 규칙이 `M`에서 이것을 빼앗는다.
- 적용 직후 `olcAccess` 읽기: 머신 규칙 3개가 정확히 `{0}`–`{2}`(문자열 비교), 그 뒤로 기존 규칙이 원래 순서(a: 3개, b: 5개, c: 4개). `M`이 들어간 규칙은 위치 0–2뿐.
  monitor·accesslog DB의 `olcAccess`는 전후 동일.
- `M`: bind 성공; `B` 안 정확히 5개 항목을 읽음; 비밀 속성(명시·`*`·`+`·`* +`·필터 `(userPassword=*)` 등) 미반환(대조: 관리자는 값과 `pwdHistory`가 있음을 봄);
  `B` 밖 10개 프로브(루트·`ou=system`·자기 항목·`ou=other`·그룹·필터, `dn uid objectClass entry cn` 요청)는 항목 0개·rc 32(`noSuchObject`); 루트에서 시작한 subtree 검색도 rc 32;
  `cn=accesslog`(141항목, 대조)·`cn=Monitor`(81)·`cn=config`(7) 읽기는 항목 0개, rc 32.
- 쓰기 시도 17종(add 4곳, 다른 항목·자기 항목 modify, 자기 `userPassword`(삭제+추가 형태와 replace)·`shadowLastChange`, `ldappasswd` 2종, delete 2종, modrdn 2종): 모두 insufficient access
  (`ldapmodify`/`ldapadd`/`ldapdelete`/`ldapmodrdn` rc 50, `ldappasswd`는 rc 1과 `Result: Insufficient access (50)`). 이후 관리자 조회: 생성·이름 변경·삭제 없음, `M`의 `userPassword` 해시 불변, `M` bind 성공.
  (c)에서 `B` 안 다른 항목 modify도 50 — 운영자의 `by users write`가 뒤로 밀려 `M`에 닿지 않는다.
- 다른 신원 불변(적용 전후 같은 프로브 14종의 반환 코드와 정규화한 출력): 관리자(전체 검색·`userPassword` 읽기·쓰기), 익명(DN 목록·`uid` 검색·`userPassword` 검색·`ou=system` base), 일반 사용자(전체 검색·다른 사용자의
  `userPassword` 검색·`M` 읽기·다른 항목 쓰기 거부·자기 쓰기·**자기 비밀번호 변경 성공**). (a)/(b)/(c)의 익명 결과는 구성별로 달랐고 각 구성에서 전후가 같았다.
- 롤백: 문서의 롤백 명령 성공, 롤백 후 `olcAccess` 원문이 적용 전과 **바이트 단위로 동일**, `M`은 다시 `B` 밖을 읽음, 롤백을 한 번 더 실행하면 `refusing` 으로 거부되고 아무것도 바뀌지 않음.
- `B` 밖 응답은 (a)/(b)/(c)에서 동일(프로브별 rc·항목·정규화 출력 비교 10건).

### 4.3 운영 가이드 명령 직접 실행

가이드의 `sh` 블록 18개를 순서대로 새 컨테이너에서 실행했다(`bash`, 비밀 파일 제외): 준비·`MAIN_DB_DN` 조회(한 줄)·계정 생성(강한 비밀번호 44자)·ACL 적용·읽기·`M`으로 `whoami`/`+` 검색/쓰기/자기 비밀번호 변경/`cn=config`
읽기·opt-in DB DN 조회(`olcDatabase={2}mdb`, `{3}monitor`)·비밀 속성 도출·회전(`ldappasswd` 성공)·잠금 해제·롤백·정리. 기대 결과와 일치(쓰기 50, 비밀번호 변경 50, `cn=config` 32).
잠금: 틀린 비밀번호로 5번 bind(49) 후 `pwdAccountLockedTime` 삭제가 성공(잠겨 있었음), 잠기지 않았을 때는 `No such attribute (16)`.

### 4.4 관측으로 확인한 사실(설계 문서의 가정 보강)

- ldapi EXTERNAL은 이 이미지에서 uid 999와 root 모두 `cn=config`를 읽지 못함(`No such object (32)`). `cn=admin,cn=config` simple bind(ldapi 소켓)는 되고 변경이 온라인으로 즉시 적용됨.
- 인덱스를 명시한 `add: olcAccess`는 기존 규칙을 뒤로 밀고, `delete: olcAccess` + `{2}`,`{1}`,`{0}`은 원래 텍스트로 되돌림.
- 기본 비밀번호 정책: `pwdSafeModify: TRUE`(replace·`ldappasswd`는 정책이 먼저 50으로 거부), `pwdInHistory: 5`, `pwdLockout: TRUE`(5회/900s).
- `M`은 루트 항목에 접근이 없어 `B`가 루트보다 좁으면 루트에서 시작한 검색이 `B` 안 항목이 있어도 rc 32.

### 4.5 실행하지 않음

- 다중 노드·복제 라이브(복제 사실은 `entrypoint.sh` 코드 읽기), `LDAP_REPLICATION_IDENTITY=prepare`와의 상호작용(코드 읽기만, CHANGE.md D30; 공존 순서 `{0}` 복제 + `{1}`–`{3}` 머신은 별도 Codex 라이브 확인이며 이 PR의 시험이 아님, T-034), Kubernetes/차트 환경.
- 좁힌 `B`(예 `ou=people`)로 UI 머신 호출 전체를 돌리는 시험(slapd 수준만 증명; 기본 `B`는 단위 2 라이브 시험이 UI 요청까지 확인).
- CI에서의 실행(워크플로 연결은 이 PR, 첫 실행 결과는 PR 체크).

## 5. 실제 Keycloak 라이브 e2e (T-021 / T-025 / T-027 / T-028, 단위 5a, 2026-10-07)

환경: Docker 29.8.2(macOS, desktop-linux), 서버 이미지 `ldapium:a5a`(`sha256:b2db7a087844…`)·UI 이미지 `ldapium-ui:a5a`(`sha256:5cd93f39716f…`) — origin/main `767d6a7`의 `image/`·`ui/`를 변경 없이 빌드. Keycloak `quay.io/keycloak/keycloak:26.7.4`(`sha256:82a77884f3af…`, 이 저장소의 `keycloak-federation-e2e.yml`과 같은 정확한 태그), `start-dev`, `KC_HOSTNAME` 고정(스크립트는 항상 `127.0.0.1:<포트>`로 접근하므로 `iss`·`jwks_uri`가 주소와 무관하게 고정, §2.5). realm·scope·client·사용자는 스크립트가 admin REST로 만든다. 부정 토큰은 realm에 **가져온(import) RSA 키**(`rsa` key provider, `privateKey`+`certificate`)로 서명해 실제 JWKS로 검증되며, 실제 토큰과 한 claim만 다르다(시간 claim은 실제 토큰의 `iat`에서 계산 — Docker VM과 호스트의 시계 차이를 피함). 컨테이너·네트워크는 `ldapium-mk-`/`-mks-`/`-mj-`/`-md-` + 실행별 6자리 접두, 종료 시 EXIT/INT/TERM trap으로 제거(실행 후 남은 객체 0개 확인).

### 5.1 결과 (실제 실행, 위 이미지)

| 스크립트 | 결과 | 시간 |
|---|---|---|
| `scripts/test/test-machine-keycloak-live.py`(T-021) | `All machine Keycloak live checks passed: 71 checks`, 종료 0 | 105s |
| `scripts/test/test-machine-keycloak-settings-live.py`(T-028) | `All Keycloak client-settings checks passed: 33 checks`, 종료 0 | 46s |
| `scripts/test/test-machine-jwks-live.py`(T-025) | `All JWKS live checks passed: 34 checks`, 종료 0 | 232s |
| `scripts/test/test-machine-revocation-drill.py`(T-027) | `All revocation drill checks passed: 18 checks`, 종료 0 | 24s |

관측값(발췌):
- 양성: LDAP·SSO 두 모드 모두 `users`(cursor 2페이지)·`groups`(cursor 2페이지)·`entry`(2)·`tree`·`password-policies`·`monitor`(2)·`server-settings` 200, 12요청에 slapd accesslog의 머신 DN bind **정확히 12건**·관리자 bind 0. refresh 사용 SA 토큰은 `sid`를 실제로 갖고(비공허) 200.
- 부정: 40종 부정 토큰이 두 모드에서 각각 401, 머신 DN bind `26 → 26`(증가 0). 거부 37개(`openapi.json`에서 도출: 허용 8 + 거부 37)+HEAD+scope 부족+미등록 경로+민감 DN은 `29 → 29`. 401 본문 메시지는 코드당 하나(`invalid bearer token`/`token expired`), 이유 세부 없음. 실제 Keycloak 토큰의 만료(3s 수명, skew 0 컨테이너)는 `token_expired`·bind 0.
- 쿠키+bearer 400(`Set-Cookie` 없음)·foreign/`null` Origin POST 403 `origin_mismatch`·malformed·중복 `Authorization` 401·preflight `authorization` 거부는 모두 bind 0, GET+foreign Origin+유효 bearer만 200(bind 1).
- 한도: client 예산 burst 2 통과 후 3번째 `429 machine_rate_limited` `Retry-After: 1`, 다른 client 영향 없음, 요청마다 다른 위조 `X-Forwarded-For`로도 IP 실패 throttle(401×3 뒤 429)을 피하지 못하고 유효 토큰도 검증 전 429.
- JWKS 중단(Keycloak 중지): 캐시된 kid 200, 미지 kid `503 unavailable`+`Retry-After: 30`(두 번째 요청도 503), 복구 후 재시작 없이 미지 kid 401·캐시 kid 200(두 모드).
- 과권한 bind: 비밀 값(평문·해시·base64 변형, accesslog `reqMod` 10건 포함) 17개 응답에서 0건, accesslog·config·Monitor DN `getEntry` 403.
- 컨테이너 로그 secret scan(8개, 323,801 B): 토큰·JWT 세그먼트·client secret·bind/관리자 비밀번호·`userPassword` 값 0건. 감사: 허용·위조 서명(`actor=unknown`+fingerprint)·scope 거부 각각 정확히 1줄.
- 키 회전(JWKS 계수): 시작 시 discovery 1·JWKS 1. 마지막 조회 직후 새 kid 401·조회 0건, `MIN_REFRESH`(30s) 뒤 정확히 1건으로 200, 옛·새 kid 동시 200, 옛 키 제거 직후 옛 kid는 캐시로 200, TTL(60s) 뒤 1건 조회로 옛 kid 401·새 kid 200.
- 폭주: 알려진 kid+위조 서명 3,080건(3 스레드, 10s) 전부 401·**조회 0건**. 무작위 kid 24,196건(3 스레드, 65s) 전부 401·조회 **3건**(상한 1+⌈75.4/30⌉=4, 간격 30.0s·30.0s, discovery 1회), 폭주 중 캐시 kid 토큰 13회 모두 200.
- 적대적 응답(조회 거부·캐시 유지·미지 kid `503`+`Retry-After`, 캐시 kid 200): 2 MiB 본문, 302(대상 `/elsewhere/keys` 요청 0건), 7s 지연(5.0s에 끊김), 키 25+20개.
- discovery: 발급자 discovery가 막힌 채 UI 기동 → 쿠키 로그인·읽기 정상, bearer `503`+`Retry-After: 30`, 로그에 `ERROR`, 복구 32s 뒤 재시작 없이 200(discovery 시도 2건, 간격 30.0s). `http://` issuer는 예외 없이 `config: machine issuer URL must use https …`로 종료 1, 예외 플래그 시 `WARN … MACHINE_OIDC_INSECURE_HTTP is on`.
- 드릴: (a) 비활성화 후 새 토큰 401 `invalid_client`·이전 토큰 두 replica 모두 200; (b) 롤아웃 중 옛 replica가 같은 토큰을 받고, SIGTERM 후 진행 중 요청이 정상 응답(200)으로 끝난 뒤 exit 0, revision 1 컨테이너 0개, 새 replica 둘에서 같은 토큰 401·bind 0, Keycloak client를 다시 켜도 새 토큰 401; (c) 기능 off에서 bearer 401 `unauthenticated`(자격 증명 없는 요청과 동일)·bind 0, 쿠키 로그인·읽기·로그아웃 정상; (d) 원래 allowlist 복귀 시 미만료 토큰 200.

### 5.2 변이 시험 (부정 검사가 실제로 실패할 수 있음)

`ui/`를 임시 복사해 한 줄씩 깨뜨린 UI 이미지(`ldapium-ui:a5a-m1`…`m5`)로 같은 스크립트를 실행했다. 전부 종료 1, 첫 실패 검사:

| 변이 | 스크립트 | 첫 실패 |
|---|---|---|
| m1 검증기가 audience `account`를 받아들임 | keycloak-live | `aud account only (no audience mapper): expected 401 token_invalid, got 200` |
| m2 서비스 계정 규칙 생략(`client_id`는 `azp`로 대체, `preferred_username` 검사 삭제) | keycloak-live / settings | `the same client's HUMAN password-grant token: expected 401 token_invalid, got 200` / `profile scope removed (no preferred_username): 200` |
| m3 deny-by-default 가드 생략(미등록·비-GET도 허용) | keycloak-live | `GET /api/me: 200 {"dn":"uid=machine,ou=system,…"}`(37개 거부 배치에서) |
| m4 `MACHINE_ALLOWED_CLIENTS` 검사 삭제 | drill | `…-r2a: 429 client request budget exhausted`(401 기대; 허용 목록에 없는 client가 검증을 통과해 예산 단계에서 막힘) |
| m5 JWKS 조회 예산 게이트 제거 | jwks | `0s after the last fetch (< 30s): the NEW kid is refused, 401, and costs 0 upstream fetches` |

변이 이미지와 임시 복사본은 시험 후 삭제했다.

### 5.3 새로 관측한 사실

- 운영자 accesslog ACL opt-in이 없으면 최소권한 머신 DN은 `audit.read` scope를 가져도 accesslog를 읽지 못한다: `listAuditActions`는 디렉터리가 거부해 **403 `forbidden`**(`scope_denied` 아님), `getMonitor`는 200이되 `recentLogs`가 비어 있다. 과권한 컨테이너에서만 200+로그. (패키지의 "scope가 코드 가드를 통과해도 ACL이 백스톱" 설계와 일치; 첫 시험 기대값이 틀려 스크립트를 고쳤다.)
- 표준 exchange 토큰은 `preferred_username=service-account-<client>`를 갖고 `client_id`가 없다 — `preferred_username`만 보는 규칙이면 통과했을 토큰이 AND 규칙에서 거부됨(§2.9 행 7 재현, 사람 subject 행 8도). legacy `token-exchange` feature 서버에서는 client 설정 없이 자기 토큰 exchange가 성공하고(행 11 재현) 그 토큰도 거부. 기본 서버에서 `standard.token.exchange.enabled`가 없는 client의 exchange는 Keycloak이 `400 invalid_request`로 거부.
- T-004 미실행 가설 해소: audience mapper를 `ldapium-sso`가 쓰는 client scope와 **공유**하면 사용자 토큰에 `aud=[ldapium-api, account]`·`azp=ldapium-sso`가 실제로 생긴다(비공허 확인). 그래도 `client_id` 부재·`azp` 허용 목록 밖으로 401.
- 가져온 키(`rsa` provider)는 우선순위 1000으로 실제 토큰 서명에도 쓰이고 JWKS에 노출된다 — 부정 토큰을 서명하는 안전한 방법(실제 키는 건드리지 않음).
- JWKS 백오프 기저는 구현상 `MIN_REFRESH`다(`keyset.go` 주석: `Min is both the refresh-budget interval and the backoff base`, `b(n)=min(Min·2^(n-1), max(300s, Min))`). 기본값에서는 CHANGE.md의 30s→5m와 같고(`Retry-After: 30` 관측), `MIN_REFRESH=1s`로 설정하면 `Retry-After: 1`이 관측됐다. 문서 표는 기본값 기준이므로 불일치는 아니다.
- 폭주 시험은 요청마다 새 연결로 초당 약 2,400건까지 가능했고, IP 실패 throttle 한도(1000/1s 창)에 닿으면 JWKS까지 오지 못하고 429가 되므로 스크립트는 스레드당 5ms 간격으로 키 소스를 실제로 시험한다. 65초 폭주가 컨테이너 로그를 약 10.9 MB 만들었다(요청 로그 줄 약 5만 줄).
- 개발 중 실패(보존): 스크립트 기대값 오류 3건(위 ACL opt-in 2건, 응답 본문이 배열인 `listTree`에서 `.get` 호출), 폭주가 IP throttle에 걸려 `set(stats) == {401}` 실패 1건, 기동 직후 종료된 컨테이너의 포트 조회로 하네스 예외 1건. 모두 시험 코드의 문제였고 제품 결함은 발견되지 않았다.

### 5.4 운영자가 Keycloak client에 적용해야 하는 설정 (T-028이 `audit_client_settings()`로 점검)

| # | 설정 | 위반 시 관측 |
|---|---|---|
| ① | lightweight access token OFF(`client.use.lightweight.access.token.enabled`, 기본값) | `aud`·`client_id`·`preferred_username` 소실 → 전부 401 |
| ② | 기본 client scope `service_account`·`profile` 유지 | `client_id`/`preferred_username` 소실 → 전부 401 |
| ③ | token exchange 비허용(`standard.token.exchange.enabled` 기본 false, 서버에 legacy `token-exchange` feature 미사용) | exchange 토큰은 `client_id` 없음 → 401(이중 방어) |
| ④ | SA의 refresh token 사용은 허용(`client_credentials.use_refresh_token`; `sid`는 거부 사유 아님) | — (허용이 요건) |
| ⑤ | SA 전용 client: standard flow·direct access grants 비활성화, audience mapper(`aud`=`MACHINE_OIDC_AUDIENCE`)는 그 client(또는 머신 client만 쓰는 scope)에만, `ldapium-sso`와 공유하는 scope에 두지 않음 | 같은 client의 사람 토큰은 SA 토큰과 `aud`/`azp`/`scope`가 같음(`client_id`만 없음); mapper 부재 → `aud=account` → 401 |

### 5.5 실행하지 않음·한계

- 실제 만료는 3초 수명 client와 skew 0 컨테이너로 확인했다(기본 300s·skew 경계 표는 단위 AC-012). 기본값 1h의 STALE/EXPIRED 행과 시나리오 a–h의 정확한 조회 횟수는 fake clock 단위 시험의 몫이다.
- AC-010의 줄 수는 라이브에서 허용·검증 실패·scope 거부 3행만 확인했다(IP 429·client 429는 단위 `TestMachineAudit_RateRows`, 나머지 조기 반환 행도 단위).
- replica는 docker 컨테이너이며 Helm/pod가 아니다(`terminationGracePeriodSeconds`는 `docker stop -t 15`로 대체). `ui-e2e` 전체는 재실행하지 않고 (c)에서 최소 쿠키 흐름만 확인했다.
- 신뢰 프록시 뒤 XFF(실제 ingress), `oidc.InsecureIssuerURLContext` 분리, legacy exchange의 management permissions(impersonation) 경로, 다중 노드 LDAP은 실행하지 않았다.

### 5.6 CI 연결 (T-022)

`machine-keycloak-e2e.yml`의 job 이름은 `machine bearer auth (real Keycloak)`, `release.yml`의 `release_critical`에 같은 문자열을 추가했다. release.yml 단계의 bash 루프를 그대로 추출해 실행한 로컬 시뮬레이션:

```
job name in the workflow : 'machine bearer auth (real Keycloak)'
listed in release_critical: True ( 6 entries )
all listed checks succeeded on the SHA (including the new job name): exit 0
the new check never ran on the SHA: exit 1  ::error::release-critical check "machine bearer auth (real Keycloak)" did not succeed on abc123
a job name that does not match exactly: exit 1  (same error)
```

`actionlint`는 새 파일에서 기존 워크플로와 같은 `queue` 키 경고 1건만 낸다(이 actionlint 버전이 job concurrency의 `queue`를 아직 모름; 기존 12개 파일 동일). 실제 GitHub Actions: PR #281(커밋 `70f0588`)의 첫 실행에서 `gh pr checks`가 `machine bearer auth (real Keycloak)  pass  10m0s`를 보고했다 — job 이름이 `release_critical`의 문자열과 글자 그대로 같다(check run 이름 일치 확인).
