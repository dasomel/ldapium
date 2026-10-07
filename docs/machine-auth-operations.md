# 머신 bearer 인증 운영: 롤백, 긴급 차단, 호환성

대상: `MACHINE_AUTH_ENABLED=true`로 켠 배포의 운영자. 기능 설명은 [`api.md`](api.md) "머신 bearer 인증", Keycloak 쪽은
[`machine-keycloak-client.md`](machine-keycloak-client.md), LDAP 쪽은 [`machine-ldap-account.md`](machine-ldap-account.md), 설계는
[CHANGE.md](changes/machine-principal-auth/CHANGE.md)(D7, REQ-018, AC-019)입니다.

> 이 절차의 라이브 드릴(`scripts/test/test-machine-revocation-drill.py`, 실제 Keycloak·slapd, revision당 UI replica 2개, 이전 컨테이너 0개 확인, 같은 토큰 401, 진행 중 요청 정상 종료)은 CI job `machine bearer auth (real Keycloak)`에서 실행됩니다(TASKS T-027). replica는 docker 컨테이너이며 Helm/pod가 아니고 `terminationGracePeriodSeconds`는 `docker stop -t 15`로 대체했습니다.
> 아래 절차는 코드와 차트를 읽어 확인했고(근거를 각 항목에 적었습니다), 위 드릴이 docker replica에서 실행했습니다. Kubernetes 클러스터(Helm 롤아웃)에서는 한 번도 실행해 보지 않았습니다(후속 #284).

## 1. 핵심: 토큰은 즉시 폐기되지 않는다

ldapium은 토큰을 저장하지 않고 요청마다 서명과 claim만 검증합니다(introspection 없음). 그러므로:

- **Keycloak client를 비활성화하거나 secret을 회전해도 이미 발급된 access token은 만료까지 검증을 통과합니다**(실제 Keycloak 26.7.4 관측,
  [EVIDENCE §2.7](changes/machine-principal-auth/EVIDENCE.md)). 막히는 것은 **새 토큰 발급**뿐입니다.
- 서버 쪽 조치를 하지 않았을 때의 최대 노출은 **남은 토큰 수명 + `MACHINE_CLOCK_SKEW`**(기본 10분 상한 + 30초 이내)입니다.
- 따라서 긴급 차단의 1차 수단은 **ldapium의 설정을 바꿔 모든 replica를 교체**하는 것이고, Keycloak 조치는 그 다음의 보조 수단입니다.

## 2. 긴급 차단 (토큰 유출·오용 의심)

순서를 지킵니다. 앞 단계가 끝나기 전에 3단계만 하면 이미 발급된 토큰은 그대로 쓸 수 있습니다.

**1) 서버에서 차단**: 아래 둘 중 하나로 설정을 바꿔 배포합니다. v1은 설정을 다시 읽지 않으므로(리로드 없음) **재배포(롤아웃)만이 반영 수단**입니다.

- 특정 client만: `MACHINE_ALLOWED_CLIENTS`(Helm `ui.machineAuth.allowedClients`)에서 그 client를 뺍니다. 그 client의 토큰은 401(`azp`가 목록 밖)이 됩니다. 목록이 비면 기동이 실패하므로 마지막 client를 빼려면 2번 방법을 씁니다.
- 기능 전체: `MACHINE_AUTH_ENABLED=false`(Helm `ui.machineAuth.enabled=false`). `Authorization`은 무시되고 쿠키 없는 요청은 기존 401 `unauthenticated`가 됩니다.

```bash
# Helm 예: client 하나를 빼거나 기능을 끈다 (values 파일을 고쳐 적용)
helm upgrade <release> ./charts/ldapium -n <ns> -f values.yaml          # allowedClients에서 제거
helm upgrade <release> ./charts/ldapium -n <ns> -f values.yaml --set ui.machineAuth.enabled=false
```

**2) 모든 replica가 교체됐는지 확인** — 롤아웃 도중에는 일부 pod가 아직 옛 설정으로 bearer를 받습니다.

```bash
D=<release>-ldapium-ui        # 차트의 UI Deployment 이름(ldapium.ui.fullname). 확인: kubectl get deploy -n <ns> -l app.kubernetes.io/component=ui
kubectl rollout status deploy/$D -n <ns>
# 이전 revision의 pod가 하나도 남지 않았는지: 모든 pod의 이미지/설정 세대가 새 것이어야 한다
kubectl get pods -n <ns> -l app.kubernetes.io/component=ui -o wide
kubectl get rs -n <ns> -l app.kubernetes.io/component=ui     # 이전 ReplicaSet의 READY/DESIRED가 0
```

그리고 **진행 중이던 요청이 끝났는지**: 차트는 기능이 켜져 있는 동안 `terminationGracePeriodSeconds`를 `max(30, 요청 timeout+5)`초로 둡니다
(`templates/ui-deployment.yaml`). 다만 서버의 graceful shutdown 대기는 코드에 **10초로 고정**되어 있어(`ui/backend/cmd/server/main.go`), `MACHINE_REQUEST_TIMEOUT`을 10초보다 크게 둔 배포에서는 pod 종료 시 10초를 넘긴 요청이 끊깁니다
(끊긴 요청은 어차피 응답이 없는 요청이지만, "모든 진행 요청이 정상 종료"를 전제로 하지 마세요. 이 불일치는 후속 과제로 기록했습니다).

**3) 같은 토큰으로 확인**: 차단 대상 client의 (유출된 것으로 보이는) 토큰이 아닌, 같은 client로 **차단 전에 받아 둔 테스트 토큰**을 보냅니다.

```bash
# $HDR: "Authorization: Bearer <token>" 한 줄이 든 0600 파일 (docs/api.md 예). 토큰을 인자에 쓰지 않는다(ps에 보임)
curl -sS -o /dev/null -w '%{http_code}\n' -H @"$HDR" https://ldapium.example.com/api/users
# client 제거: 401 (code token_invalid), 기능 끔: 401 (code unauthenticated)
```

**4) 그 다음 Keycloak**: client 비활성화 또는 secret 회전으로 새 토큰 발급을 막습니다. secret 유출이 원인이면 회전합니다. 이 단계만으로는 기존 토큰이 죽지 않습니다(1절).

**5) 감사 확인**: 차단 시각 이후 해당 client의 `event=machine_access` 줄에 `result=success`가 없는지 로그로 확인합니다
([`audit-event-schema.md`](audit-event-schema.md)). 단 핸들러 이전에 Go HTTP 서버가 거절한 요청은 이 줄이 없습니다(D25, 같은 문서). 접근 기록이 필요하면 ingress/프록시 접근 로그가 있어야 합니다.

추가로 LDAP 쪽을 막으려면(선택): 머신 계정을 잠그거나 삭제하고, ACL을 롤백합니다 — [`machine-ldap-account.md`](machine-ldap-account.md) 롤백 절. 롤백하면 그 계정은 일반 사용자 권한으로 돌아가므로 **먼저 `MACHINE_AUTH_ENABLED=false`로 전 replica를 교체**한 뒤에 합니다.

## 3. 롤백 (기능 정지, 코드 롤백 없음)

예기치 않은 401/403 오분류, 권한 노출 의심, JWKS 장애 파급이면 `MACHINE_AUTH_ENABLED=false`로 재배포하고 2절의 2)·3)과 같이 **모든 replica 교체와 이전 pod 0개**를 확인합니다.

- 영속 데이터가 없습니다(토큰·키를 저장하지 않음). 되돌릴 상태는 설정뿐입니다.
- 끄면 `Authorization`은 완전히 무시되고, 기존 쿠키 경로·응답·OpenAPI의 기존 오퍼레이션 의미는 그대로입니다(기본 꺼짐 상태와 같음).
- 머신 LDAP 계정과 ACL은 남습니다. 필요하면 `machine-ldap-account.md`의 롤백으로 지웁니다(끈 뒤에).

## 4. 호환성

- **기본 꺼짐**: `MACHINE_AUTH_ENABLED`를 켜지 않으면 어떤 `MACHINE_*`도 읽지 않으며 요청·응답·라우트가 달라지지 않습니다. Helm 기본 `ui.machineAuth.enabled=false`는 렌더 결과가 기능 추가 이전과 바이트 동일입니다(TASKS T-016).
- **OpenAPI는 additive**: `securitySchemes.machineBearer`와 허용 8개 오퍼레이션의 `security`(`cookieAuth` 유지)·`x-machine-scope`만 추가됐고, 기존 오퍼레이션의 기존 인증(`cookieAuth`)·경로·응답은 그대로입니다. 전역 기본 `security`는 `cookieAuth`입니다.
- **오류 코드는 append-only**: 새 코드 `token_invalid`, `token_expired`, `scope_denied`, `machine_rate_limited`가 닫힌 집합에 추가됐습니다(모르는 코드는 상태 코드로 처리하라는 기존 계약 그대로).
- **쓰기·비밀번호·백업·프로파일·`entry/move`·`getMe`는 어떤 경우에도 머신으로 호출할 수 없습니다**(403 `scope_denied`).
- 기능을 켜면 새로 생기는 요구: `UI_TRUSTED_PROXIES`를 `private`(기본) 대신 CIDR 목록 또는 `none`으로, 머신 전용 LDAP 계정과 ACL, 모든 LDAP 노드에서의 ACL 적용, issuer/JWKS 도달성(에어갭은 [`air-gap.md`](air-gap.md)).

## 5. 켜기 전 점검

1. 모든 LDAP 노드에 머신 ACL이 적용되고 규칙 순서가 `{0}`–`{2}`임을 읽어 확인([`machine-ldap-account.md`](machine-ldap-account.md)). `LDAP_REPLICATION_IDENTITY=prepare`와는 함께 쓰지 않음(D30).
2. Keycloak client가 [`machine-keycloak-client.md`](machine-keycloak-client.md) 요건을 충족(특히 audience mapper, lightweight Off).
3. ingress가 클라이언트가 보낸 `X-Forwarded-For`를 덮어쓰거나 정리하고, `UI_TRUSTED_PROXIES`가 그 ingress의 CIDR(또는 `none`)이며, **ingress/프록시 접근 로그가 켜져 있음**(핸들러 이전 거절은 ldapium 로그에 없음).
4. limiter는 replica별 상태입니다(전역 한도가 아님). replica 수만큼 한도가 늘어납니다.
