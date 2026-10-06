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

마지막 행이 핵심이다. `aud`·`azp`·`scope`가 SA 토큰과 **동일**하다. 구분 근거는 `client_id`/`clientHost`/`clientAddress` 존재, `sid` 부재, `preferred_username == "service-account-<client>"`뿐이다. JOSE `typ`는 access/ID 모두 `JWT`라 구분력이 없다.

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
- token exchange: 기본 비활성(“Standard token exchange is not enabled…”), 발급 경로 미검증.

### 2.8 실행하지 않음

token exchange 발급, audience mapper가 `ldapium-sso`와 공유된 client scope에 있을 때의 SSO 토큰 오염, `InsecureIssuerURLContext` 분리, 실제 시계 skew·nbf 경계, introspection `active:true` 경로. 해당 항목은 [TASKS.md](TASKS.md)의 e2e 항목으로 이관됐다.

## 3. 재현

```sh
O=ui/backend/internal/httpapi/openapi/openapi.json
jq '[.paths|to_entries[]|.key as $p|.value|to_entries[]|select(.key|test("^(get|put|post|delete|patch)$"))
     |{id:.value.operationId,m:.key,p:$p,sec:(.value.security|tostring)}]
    | length, (map(select(.sec=="[]"))|length), (map(select(.sec!="[]"))|length),
      (map(select(.sec!="[]" and .m=="get"))|length), (map(select(.sec!="[]" and .m!="get"))|length)' $O
# 53 8 45 20 25
```
