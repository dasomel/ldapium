# 머신 호출용 Keycloak client 설정 가이드 (운영자)

`MACHINE_AUTH_ENABLED=true`인 ldapium은 Keycloak **서비스 계정**(client credentials)이 받은 access token을
`Authorization: Bearer`로 받아 읽기 전용 GET 8개를 실행합니다([`api.md`](api.md) "머신 bearer 인증").
ldapium은 토큰의 claim으로 "이 토큰이 정말 그 client의 서비스 계정 access token인가"를 판정하므로,
**Keycloak client 설정이 틀리면 정상 토큰도 전부 401**이 됩니다(fail closed). 이 문서는 그 설정을 정리합니다.

- 근거: [EVIDENCE.md](changes/machine-principal-auth/EVIDENCE.md) §2(실제 Keycloak 26.7.4 관측), 특히 §2.2(`aud`)·§2.9(서비스 계정 판별 실험).
  아래 "관측" 표시는 그 실험에서 직접 확인한 것이고, 관리 콘솔의 메뉴 이름은 **문서 작성 시 다시 눌러 보지 않았습니다**(26.7.4 기준, 버전에 따라 다를 수 있음).
- 거부 규칙의 정본: [CHANGE.md](changes/machine-principal-auth/CHANGE.md) "토큰 검증 정책".
- LDAP 쪽 준비(전용 계정·ACL)는 [`machine-ldap-account.md`](machine-ldap-account.md), 긴급 차단·롤백은 [`machine-auth-operations.md`](machine-auth-operations.md).
- **실제 Keycloak을 띄워 이 설정의 양성·음성을 점검하는 라이브 e2e는 이 문서와 같은 단계에서 병합되지 않았습니다**(단위 5a, 진행 중). 아래 "잘못 설정하면" 표의 거동은 EVIDENCE의 실제 Keycloak 관측과, 같은 claim 형태를 고정한 ldapium 검증기 단위 테스트에 근거합니다.

## 1. 필요한 client 설정

머신 호출마다 **전용 client 하나**를 만들고 다른 용도(브라우저 로그인, SSO)와 섞지 않습니다.

| # | 설정 | 값 | 이유 · 어긴 경우 |
|---|---|---|---|
| 1 | Client authentication | **On**(confidential) | `client_credentials`는 secret이 필요합니다 |
| 2 | Service accounts roles | **On** | 서비스 계정 토큰의 발급 조건입니다 |
| 3 | Standard flow, Direct access grants, Implicit flow | **모두 Off** | 이 client로 사람이 password grant 토큰을 만들면 `aud`·`azp`·`scope`가 서비스 계정 토큰과 같습니다(관측 §2.3). ldapium은 `client_id` 부재로 거부하지만 발급 경로 자체를 닫는 것이 요건입니다 |
| 4 | **Lightweight access token** | **Off**(기본값) | 켜면 `aud`·`client_id`·`preferred_username`이 사라져 **모든 토큰이 거부**됩니다(관측 §2.9 행 2) |
| 5 | Default client scope `service_account`, `profile` | **유지** | `client_id`·`clientHost`·`clientAddress`와 `preferred_username`을 공급하는 mapper입니다. 지우면 모든 토큰이 거부됩니다(행 5·6) |
| 6 | **Audience mapper** | 이 client **전용** client scope에만 | 아래 2절. 없으면 `aud`가 `"account"`뿐이라 모든 토큰이 거부됩니다 |
| 7 | Token exchange | **허용하지 않음**: client 속성 `standard.token.exchange.enabled`는 false(기본), 서버에 legacy `token-exchange` feature를 켜지 않음 | exchange로 만든 토큰에는 `client_id`가 없어 ldapium이 거부합니다(행 7·8·11). 특히 legacy feature를 켜면 client 설정 없이도 exchange가 됩니다(행 11) |
| 8 | Access token lifespan | **≤ `MACHINE_TOKEN_MAX_TTL`**(기본 10분, 상한 1시간). Keycloak 기본은 300초 | `exp - iat`가 `MACHINE_TOKEN_MAX_TTL`을 넘는 토큰은 거부됩니다. client 속성 `access.token.lifespan`으로 client별로 줄일 수 있습니다(관측 §2.1) |
| 9 | Refresh token 사용(`client_credentials.use_refresh_token`) | 기본 Off, 켜도 됨 | 켜면 access token에 `sid`가 생기지만 ldapium은 `sid`를 보지 않습니다(행 3). 서비스 계정에는 굳이 켤 이유가 없습니다 |
| 10 | 필요한 scope | **client scope**로 부여 | 아래 3절. ldapium의 유효 권한 = 토큰 scope ∩ 서버의 client 상한(`MACHINE_ALLOWED_CLIENTS`) |
| 11 | 발급자 URL 고정 | 서버에 `KC_HOSTNAME`(또는 단일 호스트명) | `iss`는 요청 Host를 따릅니다(관측 §2.5). 토큰 `iss`는 `MACHINE_OIDC_ISSUER_URL`과 **바이트 단위로 같아야** 하며 후행 `/`도 구별됩니다 |

ldapium 쪽 짝: `MACHINE_ALLOWED_CLIENTS`에 이 client id를 넣어야 하고(`id=scope,scope;…`), SSO 브라우저 client(`SSO_CLIENT_ID`)는 넣을 수 없습니다(기동 실패).
머신 client의 `azp`/`client_id`가 허용 목록에 없으면 토큰은 401입니다.

## 2. audience mapper

ldapium은 `MACHINE_OIDC_AUDIENCE`(예: `ldapium-api`)가 토큰 `aud`의 **정확한 멤버**일 것을 요구합니다.
Keycloak은 기본으로 `aud`를 문자열 `"account"`로 두고, audience mapper를 붙이면 `["ldapium-api","account"]`(배열)가 됩니다(관측 §2.2).
`MACHINE_OIDC_AUDIENCE=account`는 기동 거부이고, 토큰에 `account`만 있어도 거부입니다.

관측에서 동작한 mapper 정의(`POST …/clients/{id}/protocol-mappers/models`, 또는 client scope의 mapper로 동일 설정):

```json
{"name":"aud-ldapium-api","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper",
 "config":{"included.custom.audience":"ldapium-api","id.token.claim":"false",
           "access.token.claim":"true","introspection.token.claim":"true"}}
```

**mapper는 이 client 전용 scope에만 둡니다.** `ldapium-sso`(UI SSO client)와 공유하는 client scope에 두면 SSO 사용자 토큰에도 `ldapium-api`가 들어갈 수 있습니다.
ldapium은 SSO client를 `azp`로 거부하므로 방어는 이중이지만, 공유 scope 오염 시나리오는 **아직 실제 Keycloak으로 확인하지 않았습니다**(TASKS T-021, 단위 5a).

## 3. scope 부여

- Keycloak에 ldapium이 아는 이름 그대로 client scope를 만듭니다: `directory.users.read`, `directory.groups.read`, `directory.tree.read`, `directory.entry.read`,
  `directory.policies.read`, `server.monitor.read`, 그리고 opt-in `audit.read`, `server.settings.read`. 오퍼레이션과의 대응은 [`api.md`](api.md).
- 해당 client의 **Default** client scope로 붙이면 `scope` 요청 파라미터 없이도 토큰에 들어가고, **Optional**이면 토큰 요청 때 `scope=…`로 요청해야 합니다. 토큰의 `scope`는 공백으로 구분된 문자열이며 `profile`·`email`이 항상 섞입니다(관측 §2.4).
- **Keycloak에서 scope를 부여해도 서버 상한에 없으면 403**입니다. 반대도 마찬가지입니다. 두 곳(Keycloak scope, `MACHINE_ALLOWED_CLIENTS`/Helm `ui.machineAuth.allowedClients`)이 모두 있어야 합니다.
- `audit.read`는 행위자·대상 DN과 변경 속성 이름을 노출하고, 서버 상한에 명시적으로 넣은 경우에만 동작합니다. 쓰려면 accesslog DB의 opt-in ACL이 따로 필요합니다([`machine-ldap-account.md`](machine-ldap-account.md) opt-in 절).

## 4. 토큰 받기와 확인

```bash
ISSUER=https://sso.example.com/realms/example     # = MACHINE_OIDC_ISSUER_URL
TOKEN=$(curl -sS -X POST "$ISSUER/protocol/openid-connect/token" \
  -d grant_type=client_credentials -d client_id=svc-reporting \
  --data-urlencode client_secret@/path/to/secret-file | jq -r .access_token)
```

(secret은 파일·Secret에서 읽고 셸 히스토리에 남기지 않습니다. 사용자 지정 scope가 Optional이면 `-d scope='directory.users.read'`를 추가합니다.)

토큰을 서명 검증 없이 **눈으로만** 확인할 때(비밀이 아닌 claim만 출력):

```bash
printf '%s' "$TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null \
  | jq '{typ,iss,aud,azp,client_id,preferred_username,scope,iat,exp,ttl:(.exp-.iat)}'
```

기대값(EVIDENCE §2.1·§2.9 행 1과 같은 형태): `typ="Bearer"`, `aud`에 `ldapium-api` 포함(배열), `azp == client_id == svc-reporting`,
`preferred_username == "service-account-svc-reporting"`, `scope`에 요청한 scope, `ttl ≤ MACHINE_TOKEN_MAX_TTL`.
`client_id`나 `preferred_username`이 없으면 위 표의 4번·5번 설정을 확인하세요. 이 토큰을 로그·티켓에 붙이지 마세요.

## 5. 잘못 설정하면 (관측된 토큰과 ldapium의 반응)

모두 401 `token_invalid`이고 LDAP bind는 시도되지 않습니다. 응답 본문은 사유를 말하지 않으며, 사유는 감사 로그의 `reason`에만 있습니다([`audit-event-schema.md`](audit-event-schema.md)).

| 상황(EVIDENCE §2.9의 행) | 토큰에서 달라지는 것 | `reason` |
|---|---|---|
| audience mapper 없음(§2.2) | `aud="account"`뿐 | `aud` |
| lightweight access token On(행 2) | `aud`·`client_id`·`preferred_username` 없음 | `aud` |
| `profile` scope 제거(행 5) | `preferred_username` 없음 | `sa_claims` |
| `profile`+`service_account` 제거(행 6) | `client_id`·`preferred_username` 없음 | `azp` |
| 같은 client의 password grant 사람 토큰(행 4) | `client_id` 없음, `preferred_username`=사람 | `azp` |
| standard / legacy token exchange로 만든 토큰(행 7·8·11) | `client_id` 없음 | `azp` |
| ID token(`scope=openid`로 client_credentials를 호출하면 같이 발급, §2.3) | payload `typ=ID` | `typ` |
| access token lifespan > `MACHINE_TOKEN_MAX_TTL` | `exp - iat`가 상한 초과 | `ttl` |
| 허용 목록에 없는 client | `azp`가 목록 밖 | `azp` |
| `MACHINE_OIDC_ISSUER_URL`과 다른 호스트명으로 받은 토큰 | `iss` 불일치 | `iss` |
| 키를 방금 회전해 새 `kid`가 아직 JWKS 캐시에 없음 | 정상 조회 후 미지 `kid` | `kid`(최대 30초, 아래 6절) |

`reason` 값 이름은 구현(`machine_audit.go`, `machineauth` 패키지)의 닫힌 집합입니다. 검증은 `typ`, `iss`, `aud`, `azp`/`client_id`, `preferred_username`, `scope`, 시간 순서로 진행하고 **처음 걸린 규칙**이 `reason`이 되므로, `client_id`가 없는 토큰(사람·exchange·`service_account` scope 제거)은 `azp`, `client_id`는 있으나 `preferred_username`이 다른 토큰(`profile` 제거)은 `sa_claims`입니다(`machineauth/claims.go`의 `ValidateClaims` 순서를 읽어 확인).
이 대응 중 **claim 형태에 대한 거부는 단위 테스트가 고정**하고(EVIDENCE §2.9 행 2·4–8 형태), 실제 Keycloak에서 각 구성을 만들어 ldapium으로 호출하는 점검은 단위 5a(미병합)의 몫입니다.

## 6. 키 회전과 JWKS

- 키 회전은 **overlap**으로 합니다: 새 서명 키를 추가해 두 키가 JWKS에 함께 있게 한 뒤 옛 키를 제거합니다(관측 §2.6: 옛 `kid` 토큰도 overlap 동안 검증됨). 옛 키를 곧바로 지우면 그 `kid`로 서명된 발급 토큰이 즉시 401입니다.
- ldapium은 JWKS를 10분(`MACHINE_JWKS_CACHE_TTL`) 캐시하고 조회는 최소 30초 간격(`MACHINE_JWKS_MIN_REFRESH`)입니다. 새 `kid`는 마지막 조회 성공 후 30초까지 401일 수 있습니다(문서화된 비용).
- Keycloak/JWKS가 닿지 않으면 알려진 `kid`는 stale 한도(`MACHINE_JWKS_MAX_STALE`, 기본 1시간) 안에서 로컬 검증되고, 그 밖에는 **503 + `Retry-After`**(fail closed)입니다. 서명 검증을 생략하는 폴백은 없습니다.
- issuer/JWKS는 https만 허용되며, ldapium Pod에서 도달 가능해야 합니다([`air-gap.md`](air-gap.md) "머신 인증과 issuer 도달성").

## 7. 하지 말아야 할 것

- 머신 client에 사람 로그인 흐름(Standard flow, Direct access grants)을 켜지 않는다.
- audience mapper를 `ldapium-sso`와 공유하는 scope에 두지 않는다.
- Keycloak client를 비활성화하는 것으로 **이미 발급된 토큰을 폐기했다고 생각하지 않는다.** 비활성화 뒤에도 사전 발급 토큰은 만료(최대 `MACHINE_TOKEN_MAX_TTL` + skew)까지 검증을 통과합니다(관측 §2.7). 긴급 차단은 서버 쪽 절차입니다: [`machine-auth-operations.md`](machine-auth-operations.md).
- secret 회전은 새 토큰 발급만 막고 기존 토큰에는 영향이 없습니다(관측 §2.7).
