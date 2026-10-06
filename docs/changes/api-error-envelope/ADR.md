# ADR: HTTP API 오류 봉투, `/metrics` 리스너, CORS 정책 (D218-1 ~ D218-14, D264-1 ~ D264-3)

- Status: `Accepted` — [CHANGE.md](CHANGE.md)의 결정을 승격한 기록이다. CHANGE.md는 2026-10-06 유지보수자 지시로 수용되었고 구현은 #234, #240, #242, #246으로 `main`에 병합되었다.
- Owner: 미지정(CHANGE.md와 같음)
- Related issue: [#218](https://github.com/dasomel/ldapium/issues/218) (문서 후속: [#248](https://github.com/dasomel/ldapium/issues/248))
- 위치 규약: 이 저장소에는 별도 ADR 디렉터리가 없다. 변경 패키지 안의 `ADR.md`로 둔다(`docs/changes/<package>/`, T-051). 근거·대안·구현 결과의 전문은 [CHANGE.md](CHANGE.md)의 같은 ID에 있고, 이 문서는 되돌리기 어려운 결정과 그 탈출구만 요약한다.
- 정본 계약: [docs/api.md](../../api.md)(오류 형식, 코드 표, CORS, `/metrics`). 운영 절차: [docs/ui-operations.md](../../ui-operations.md).

## Context

외부 호출자는 `/api` 오류 본문을 한 가지로 파싱할 수 없었다(`{"error"}`, Echo 기본 `{"message"}`, 500만 `requestId`). 운영자에게는 UI 백엔드 프로세스의 지표가 없었고, 교차 출처 브라우저 호출에 대한 정책도 문서화되어 있지 않았다. 이 셋은 외부 계약, 신규 리스너·의존성, 인증 경계 인접 정책이라 되돌리기 어렵다(ADR threshold: `required`).

## Decisions

| ID | 결정 | 탈출구 |
|---|---|---|
| D218-1 | 모든 `/api` 오류는 `{error, message, code, requestId, retryable}` 한 형태다. `error`와 `message`는 같은 값이다. `requestId`는 camelCase(기존 500 본문·OpenAPI와 호환). 로그 스키마의 `request_id`는 바꾸지 않는다. | 필드 추가는 optional 키로만 가능. 제거는 D218-4. |
| D218-2 | 변환 지점은 모든 `/api` 오류가 지나가는 `apiErrorHandler` 하나다. `respondErr`는 같은 빌더를 쓴다. 기존 `echo.NewHTTPError`는 수정하지 않고 상태에서 기본 `code`를 정하며, 도메인 구분이 필요한 곳만 `apiErr(status, code, msg)`로 교체한다. | 구체 코드가 필요한 지점만 점진 교체. |
| D218-3 | `code`는 닫힌 snake_case 집합이며 append-only다. 이름 변경·삭제는 계약 변경이다. 골든 목록 테스트(`TestEnvelope_CodeTableMatchesGoldenList`)가 코드 집합을 고정한다. 표에 없는 4xx는 `invalid_request`, 5xx는 `internal`로 폴백한다. `token_invalid`, `token_expired`, `scope_denied`(#214)와 `cursor_expired`는 이름만 예약되어 있고 방출하지 않는다. | 새 코드는 표에 한 줄 추가(D218-14). |
| D218-4 | `message`는 `error`의 동일 사본이며 `/api/v1` 동안 유지한다. 문서에는 deprecated alias로 표기한다. 제거는 UI가 `error ?? message`로 옮겨 간 뒤 최소 한 릴리스가 지나고, 새 변경 패키지로만 가능하다. 이 ADR은 제거를 약속하지 않는다. | 롤백·호환은 아래 "Compatibility and rollback". |
| D218-5 | `retryable`은 "같은 요청을 그대로 다시 보내면 성공할 수 있는가"다. 429 `login_rate_limited`, 일시적 503, 409 `backup_busy`·`idempotency_key_conflict`는 true. 412·428은 재조회가 필요하므로 false, 500은 부분 적용 가능성 때문에 false, 502는 GET/HEAD만 true. `Retry-After`(정수 초)는 `retryable`인 429·503에만 붙는다. | 502를 false로 고정하는 것은 additive. |
| D218-6 | 봉투가 아닌 것은 2xx/3xx(`/api/sso/*` 리다이렉트 포함), `GET /api/health/ldap`의 `{"reachable": bool}`, 본문 없는 응답(`OPTIONS` 204, `HEAD`)뿐이다. 예외는 OpenAPI 드리프트 테스트의 허용 목록에 이름으로 둔다. | 새 예외는 이 결정의 개정을 요구한다. |
| D218-7 | `requestId`는 항상 `X-Request-Id` 응답 헤더 값이다. 새 ID 체계를 만들지 않는다. | — |
| D218-8 | 5xx의 `error`/`message`는 코드별 고정 문구 표에서만 가져온다. 핸들러가 `err.Error()`를 넘겨도 5xx 본문에는 실리지 않고 원문은 `requestId`와 함께 로그에만 남는다. 4xx는 핸들러 문구를 통과시킨다. | 문구 변경은 표 수정. |
| D218-9 | `/metrics`는 UI 백엔드 프로세스 지표(`ldapium_ui_*`)만 낸다. slapd 지표는 기존 `openldap_exporter` 사이드카(9330)가 맡는다. 라벨은 닫힌 집합이며 사용자·uid·DN·IP·경로 원문·오류 문자열은 라벨에도 값에도 넣지 않는다. | 지표 추가는 가산(라벨 상한 유지). |
| D218-10 | `METRICS_ADDR`(기본 빈 값 = 리스너 없음)를 설정하면 `GET /metrics`만 서빙하는 두 번째 리스너가 뜬다. 인증은 없고 보호는 네트워크 경계다. 공개 포트의 `GET /metrics`는 404 봉투다. 차트는 `ui.metrics.enabled`일 때만 별도 Service, UI 파드 NetworkPolicy(허용 피어 `ui.metrics.networkPolicy.from` 필수, 비면 렌더 실패), 선택적 ServiceMonitor/PodMonitor를 만든다. 공개 UI Service에는 지표 포트를 넣지 않는다. | `METRICS_ADDR` 비우기 또는 `ui.metrics.enabled=false`. 공개 포트 404 라우트를 빼면 SPA 폴백으로 돌아간다. |
| D218-11 | `github.com/prometheus/client_golang`을 쓴다. 전역 기본 레지스트리 대신 전용 `Registry`를 `internal/metrics`의 좁은 인터페이스 뒤에 가둔다. 비활성이면 no-op 구현이다. | 인터페이스 뒤를 직접 구현으로 교체할 수 있다. |
| D218-12 | CORS는 기본 꺼짐(헤더 없음)이다. `CORS_ALLOWED_ORIGINS`(정확한 `scheme://host[:port]`만)를 설정하면 목록의 Origin에 한해 `GET`/`HEAD` 읽기와 프리플라이트(`GET, HEAD, OPTIONS`)를 허용한다. 켜면 `Vary: Origin`이 모든 응답에 붙는다. 와일드카드·`null`은 기동 거부. 쓰기는 CORS로 열지 않으며 세션 쿠키는 `SameSite=Lax` 그대로다. | 교차 출처 쓰기가 필요하면 별도 변경 패키지로 쓰기 게이트를 확장. |
| D218-13 | 롤아웃은 additive다. 제거된 키가 없고 `/api/v1`은 유지된다. `/metrics`와 CORS는 기본 꺼짐이다. 병합은 봉투 → 쓰기 Origin 게이트 → `/metrics` → CORS 순서로 독립 병합·되돌리기가 가능했다. | 단계별 revert. |
| D218-14 | 후속 변경(#214-#217)의 규약: 새 오류 조건은 코드 한 줄을 표·골든 목록·OpenAPI `Error.code` enum에 같은 PR에서 추가한다. 새 생산자는 `apiErr`를 쓴다. 새 응답 헤더는 CORS 노출 목록과 OpenAPI에 반영한다. 5xx 문구는 고정 표에 추가한다. | — |

## Decisions after acceptance: current password rejected (#264)

| ID | 결정 | 탈출구 |
|---|---|---|
| D264-1 | `ldapclient`는 **`oldPassword`가 실린** Password Modify가 LDAP 결과 53(unwillingToPerform)이고 **진단 문구에 slapd 코어의 `unwilling to verify old password`가 대소문자 구분 부분 문자열로 들어 있을 때만** 도메인 센티널 `ErrCurrentPasswordRejected`를 낸다(`mapSetPasswordErr`, 전역 `mapErr`는 그대로). HTTP는 **400**, 새 안정 코드 **`current_password_rejected`**, `retryable:false`, 고정 문구(생산자가 넘기며 `codeTable.static`에는 넣지 않는다: 5xx 전용)다. **문구 게이트의 이유:** 결과 53은 현재 비밀번호와 무관한 경우에도 나온다. `olcReadOnly=TRUE`에서 현재 비밀번호가 맞아도 `operation restricted`(53)가 나오며 게이트 없이는 400 `current_password_rejected`가 되어 사용자에게 비밀번호를 다시 확인하라고 잘못 안내했다(실제 이미지·slapd에서 재현). **실패 시 닫힘:** 문구가 다르면 가려진 500으로 떨어진다. **수용한 비용:** 미래 slapd가 문구를 바꾸면 이 경우가 500으로 퇴행할 뿐, 잘못된 400이 되지는 않는다(slapd 2.6.15에서 약 20회 안정 관찰, 코어 `passwd.c`에 하드코딩). 400인 이유: 401이 아니라 기존 입력·정책 거절 관례(`invalid_request` 400 계열)와의 일관성이다. 403은 권한·Origin, 422는 별도 검증용으로 남긴다. 클라이언트(SPA)에는 401/403 전역 처리기가 없다. 코드는 표·골든 목록(35→36)·OpenAPI `Error.code`·docs/api.md에 같은 PR에서 추가한다(D218-14). | 센티널 분기를 제거하면 옛 동작(500 `internal`)으로 돌아간다. 코드는 append-only라 이름은 남는다. |
| D264-2 | 원인은 설계상 모호하다. slapd는 `pwdSafeModify`가 현재 비밀번호를 거부할 때와 현재 비밀번호 검증이 켜져 있지 않을 때 모두 53을 낸다. 그래서 고정 문구는 비밀번호가 틀렸다고 단정하지 않는다: `the current password was not accepted (or current-password verification is not enabled on the server)`. 본문에 DN·slapd 진단은 없고(센티널 문구만, D218-15), 원문(`LDAP Result Code 53 ...`)은 `requestId`와 함께 로그에 남는다. UI는 메시지 텍스트가 아니라 `code`로 분기해 번역된 `changePassword.ambiguousCurrentPassword`를 보여 준다. | 문구는 센티널 한 곳. UI 분기는 `err.code` 한 줄. |
| D264-4 | **수용한 위험.** (a) 이 이미지의 기본 정책(`pwdSafeModify TRUE`, `pwdMaxFailure 5`)에서 slapd 2.6.15 실측: Password Modify 확장 연산의 **틀린 현재 비밀번호는 ppolicy 잠금에 집계되지 않는다**(연속 7회 틀려도 `pwdFailureTime` 0). 인증된 세션이 후보 현재 비밀번호를 제한 없이 시험할 수 있다. 새 오라클은 아니다(변경 전에도 틀리면 500, 맞으면 204라 구분 가능했다). 신호만 더 선명해졌다. 후속 이슈로 추적한다(번호 없음, tracked in a follow-up issue). (b) 모호성의 사실: 결과 53 `unwilling to verify old password`는 현재 비밀번호가 **맞아도** 호출자가 대상의 `userPassword`를 읽을 수 없거나, 대상에 `userPassword`가 없거나 `{SASL}` 값일 때도 나온다. 그래서 고정 문구는 계속 모호해야 한다. | 문구 게이트(`oldPasswordNotVerified`)와 UI 분기는 각각 한 곳. 잠금 집계는 후속 이슈. |
| D264-3 | `oldPassword` 없는 요청(관리자 초기화)의 결과 53과, 분류되지 않은 그 밖의 모든 오류(LDAP 중단 포함)는 D218-8에 따라 가려진 500 `internal` 그대로다. #249의 "UI 분기 없음" 결정(EVIDENCE.md T-017)은 이 결정으로 대체된다: 이제 UI가 분기하는 근거는 `internal`이 아니라 전용 코드다. | — |

## Amendments after acceptance

구현 중 독립 검토가 CHANGE.md의 일부 결정을 바꾸었다. 현재 `main`의 동작은 아래가 기준이다.

- **쓰기 Origin 게이트는 CORS 목록과 무관하다(D218-D4가 D218-16(b)와 D218-12의 공유 문구를 대체).** 게이트는 요청 자신의 origin만 통과시킨다. 목록의 Origin이 보낸 쓰기도 403 `origin_mismatch`다. 이유: 목록의 같은 사이트 페이지가 프리플라이트 없는 단순 POST로 `SameSite=Lax` 쿠키를 실어 쓰기를 실행할 수 있었다. 테스트: `TestCORS_ListedOriginCannotWrite`, `TestOriginGate_EveryWriteRoute`.
- **`Origin` 헤더가 정확히 하나일 때만 값을 본다(D218-D6).** 게이트는 둘 이상이면 403, CORS는 무시한다. 빈 값과 `null`은 게이트가 거부한다.
- **4xx 메시지 정책(D218-15)과 쓰기 Origin 게이트(D218-16)는 이 ADR의 범위 밖 결정이지만 계약의 일부다.** 4xx 문구에서 LDAP 진단(DN 포함)은 고정 문구로 대체되고 원문은 로그에 남는다. 게이트는 `Origin` 헤더가 없는 요청(curl, 서비스)에 영향이 없다. 전문은 CHANGE.md.
- **`scan_timeout`은 `retryable: true`이며 `Retry-After`가 붙는다**(#256). D218-5의 일시적 503 규칙을 따른다.
- 코드 표는 구현과 함께 커졌다(#215-#217의 코드 포함). 정본은 [docs/api.md](../../api.md)의 표와 골든 목록이다.

## Compatibility and rollback

- 키를 읽는 클라이언트(`error` 또는 `message`)는 영향이 없다. 봉투를 되돌리려면 커밋을 revert하면 옛 본문이 돌아온다(설정·차트·이미지 변경 없음).
- `message`: 제거 시점은 미정이다(D218-4). 새 클라이언트는 `error`를 읽는다. 제거는 UI 이전, 최소 한 릴리스, 새 변경 패키지의 세 조건이 모두 필요하다.
- 쓰기 Origin 게이트는 `Origin`을 보내는 비브라우저 클라이언트에는 호환성을 깬다. 끄는 스위치는 없다(보안 기본값). 되돌리려면 변경을 revert한다. 프록시가 `Host`를 재작성하면 브라우저 쓰기가 403이 될 수 있다([운영 가이드](../../ui-operations.md)).
- `METRICS_ADDR`, `CORS_ALLOWED_ORIGINS`: 비우면 즉시 꺼진다. 차트는 `ui.metrics.enabled=false`, `ui.cors.allowedOrigins=[]`.

## Not verified

- Prometheus Operator CRD 하에서 ServiceMonitor/PodMonitor의 실제 스크랩은 렌더만 확인했다. 클러스터 NetworkPolicy 집행은 CNI에 달려 있다.
- 라이브 스크립트(`scripts/test/test-api-edge-codes-local.py`)와 `metrics-e2e.yml`은 이 문서 작성 중 다시 실행하지 않았다.
