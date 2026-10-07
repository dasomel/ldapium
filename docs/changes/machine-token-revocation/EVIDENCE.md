# Evidence: 머신 토큰 즉시 폐기 (설계 입력)

설계: [CHANGE.md](CHANGE.md) · 작업: [TASKS.md](TASKS.md)

- 수집일: 2026-10-07, main `b0ada28`
- 이 문서는 구현 증거가 아니라 **설계 입력**이다. 코드는 읽기만 했고 변경하지 않았다. Keycloak·OpenLDAP 라이브 실험은 하지 않았다(아래 "미확인").
- 비밀: 토큰·secret은 다루지 않았다.

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

## 3. 미확인 (T-001/T-002/T-004에서 실측)

1. Keycloak 26.7.4: introspection 호출자 인증 방식(secret, 서명 JWT, mTLS 중 무엇을 받는가); 비활성화·폐기된 SA 토큰의 introspection `active` 값, `active:true` 경로.
2. Keycloak: RFC 7009 폐기 엔드포인트와 not-before 정책이 offline JWT 검증을 하는 수신자에게 의미가 있는지(수신자가 push를 받거나 별도 확인을 해야 하므로 ldapium에는 직접 도움이 되지 않을 가능성이 있으나 미확인).
3. Keycloak: `cnf.x5t#S256` 인증서 바인딩 토큰의 발급 구성·SA 토큰 적용.
4. `ldapium:e2e` 이미지 스키마의 폐기 항목 후보 속성과 기본 머신 ACL의 실제 읽기 결과(`B` 좁힘 포함).
5. 5 s 주기 subtree 조회의 부하, 다중 provider 복제 지연, Kubernetes ConfigMap 마운트 전파 시간.
6. 라이브 드릴을 이 패키지가 정의한 상한 수식과 비교하는 일 전체(구현 없음).
