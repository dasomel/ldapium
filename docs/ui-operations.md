# UI 백엔드 운영 가이드: `/metrics`, 쓰기 Origin 게이트, 조건부 쓰기, 멱등 키

관리 UI(`ldapium-ui`)의 HTTP API를 운영하는 사람을 위한 절차와 주의점이다. 계약(필드·코드·상태)의 정본은 [api.md](api.md), 결정의 이유는 [오류 봉투 ADR](changes/api-error-envelope/ADR.md)와 [조건부 쓰기 ADR](changes/api-conditional-writes/ADR.md)에 있다. 차트 값은 [charts/ldapium/README.md](../charts/ldapium/README.md), 환경 변수는 [ui/README.md](../ui/README.md)가 정본이다.

> 검증 범위: 아래 YAML은 `helm template`으로 렌더해 확인했다. 클러스터에서 실제 스크랩·NetworkPolicy 집행·프록시 동작은 이 문서를 쓰는 동안 실행하지 않았다.

## `/metrics` 켜기와 스크랩

기본은 꺼짐이다. 켜지 않으면 리스너도 수집도 없다. 켜면 UI 프로세스 지표(`ldapium_ui_*`)만 나온다. slapd 지표는 기존 `metrics.*`의 exporter 사이드카(9330)가 맡는다.

### 차트

```yaml
ui:
  enabled: true
  metrics:
    enabled: true
    # 필수. 비어 있으면 렌더가 실패한다(NetworkPolicy의 빈 from은 "전체 허용"이기 때문).
    networkPolicy:
      from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: monitoring
    serviceMonitor:
      enabled: true     # Prometheus Operator를 쓸 때만. PodMonitor는 ui.metrics.podMonitor.enabled
```

| 항목 | 값 |
|---|---|
| 스크랩 대상 Service | `<release>-ldapium-ui-metrics` (포트 이름 `ui-metrics`, 기본 포트 `ui.metrics.port`=9331) |
| 경로 | `GET /metrics` (Prometheus 텍스트). 다른 경로는 404, 다른 메서드는 405 |
| 인증 | 없음. 보호는 네트워크 경계(NetworkPolicy 피어)다 |
| 공개 UI Service | 지표 포트를 싣지 않는다. 지표는 위 별도 Service로만 노출된다 |

### NetworkPolicy 피어

`ui.metrics.enabled`를 켜면 차트가 UI 파드를 선택하는 NetworkPolicy를 만든다. UI 파드가 처음으로 ingress 기본 거부가 되므로 다음을 확인한다.

- 지표 포트(9331)는 `ui.metrics.networkPolicy.from`의 피어만 접근한다. 값은 NetworkPolicy `from` 항목의 원본 목록이다(예: Prometheus가 있는 네임스페이스의 `namespaceSelector`).
- UI HTTP 포트(8080)는 `ui.networkPolicy.httpFrom`이 비어 있으면 모든 출처에 열려 있다(이 정책이 생기기 전과 같다). 인그레스 컨트롤러에서만 받으려면 그 피어를 `ui.networkPolicy.httpFrom`에 적는다.
- kubelet 프로브가 CNI에서 허용되는지는 클러스터에 달려 있다. 정책을 켠 뒤 UI 파드가 Ready인지 확인한다.
- `ui.metrics.port`는 8080이 될 수 없다(렌더 실패).

### 공개 포트의 `/metrics`

공개 UI 포트(8080)의 `GET /metrics`와 `/metrics/`는 항상 `application/json` 404 오류 봉투(`code: not_found`)다. 예전처럼 SPA의 `index.html`이 200으로 나오지 않는다. 헬스체크나 스캐너가 이 경로로 "지표가 켜져 있는지"를 판단하면 안 된다. 지표는 `METRICS_ADDR` 포트에만 있다.

### 차트 밖 배포

환경 변수 `METRICS_ADDR=host:port`를 설정한다(`LISTEN_ADDR`와 같은 포트·겹치는 호스트면 기동이 거부된다). 포트를 공개 네트워크에 열지 않는다.

### 끄기

차트는 `ui.metrics.enabled=false`, 차트 밖은 `METRICS_ADDR`를 비운다.

## 쓰기 Origin 게이트와 프록시

`/api`의 `POST`/`PUT`/`PATCH`/`DELETE` 요청에 `Origin` 헤더가 있으면 그 값은 서버 자신의 origin이어야 하고, 아니면 핸들러 전에 403 `origin_mismatch`다. `Origin`이 없는 요청(curl, 스크립트, 서비스)은 영향이 없다. 끄는 스위치는 없다.

- 서버의 자기 origin은 요청의 `Host`와 스킴이다. 스킴은 TLS 또는 `X-Forwarded-Proto` 계열 헤더에서 온다. `X-Forwarded-Host`는 쓰지 않는다.
- 프록시·Ingress가 브라우저의 `Host`를 보존하고 TLS 종단 시 `X-Forwarded-Proto: https`를 붙여야 브라우저 쓰기가 통과한다. `Host`를 재작성하거나 스킴을 전달하지 않으면 정상 UI 쓰기도 403이 된다. 증상: 로그인 후 사용자·그룹 저장이 `request origin not allowed`로 실패한다.
- `Origin` 헤더를 스스로 붙이는 HTTP 클라이언트 라이브러리는 그 헤더를 빼야 한다.
- `CORS_ALLOWED_ORIGINS`에 올린 origin도 쓰기는 통과하지 못한다(읽기 전용 목록).

## CORS (선택)

기본은 꺼짐이며 `Access-Control-*` 헤더가 없다. 같은 사이트의 다른 origin(예: `console.example.com` → `ldapium.example.com`)에서 읽기 호출이 필요할 때만 `CORS_ALLOWED_ORIGINS`(차트 `ui.cors.allowedOrigins`)에 정확한 `scheme://host[:port]`를 적는다. 다른 사이트에서는 세션 쿠키(`SameSite=Lax`)가 실리지 않으므로 목록이 의미가 없다. 켜면 `Vary: Origin`이 모든 응답에 붙는다.

## 조건부 쓰기: 412가 얼마나 나오는가

`If-Match`를 쓰는 클라이언트는 항목의 `entryCSN`(`etag`)이 바뀌면 412 `revision_conflict`를 받는다. 다른 관리자의 편집뿐 아니라 디렉터리의 부수 쓰기도 `entryCSN`을 올린다. 측정한 결과([EVIDENCE.md](changes/api-conditional-writes/EVIDENCE.md) (c)):

| 사용자 항목의 `entryCSN`을 올린다 | 올리지 않는다 |
|---|---|
| 속성 수정, 비밀번호 변경 | 읽기 |
| 실패한 바인드(ppolicy가 `pwdFailureTime` 기록), 실패를 지우는 다음 성공 바인드 | 실패 기록이 없는 성공 바인드(lastbind 꺼짐) |
| `LDAP_LASTBIND_ENABLED=true`일 때의 모든 성공 바인드 | 그룹에 추가·제거(`memberOf`), refint의 멤버 삭제 |

- 로그인 실패가 잦은 계정이나 lastbind를 켠 배포에서는 읽은 직후의 쓰기도 412가 될 수 있다. 데이터 손실이 아니라 안전한 실패이며, 항목을 다시 읽어 새 `etag`로 재시도하면 된다. 쓰기 응답은 새 태그를 주지 않으므로 연속 편집도 재조회가 필요하다.
- 추이 확인: 지표를 켰다면 `ldapium_ui_api_errors_total{code="revision_conflict"}`의 증가율을 본다. 사용자 편집 수에 비해 높으면 위 부수 쓰기를 의심한다.
- lastbind는 다중 provider 복제에서 켜지 않는 것을 권장한다([image/README.md](../image/README.md)).
- 복제된 디렉터리에서 조건은 쓰기를 받은 노드에서만 평가된다. 같은 태그로 두 노드에 동시에 쓰면 둘 다 통과하고 `entryCSN` 시각 last-write-wins로 한쪽이 조용히 사라질 수 있다. 쓰기 노드를 하나로 고정하는 것을 권장한다.

## 멱등 키: 단일 복제본 전제

`Idempotency-Key`의 코어 쓰기(사용자·그룹·엔트리 이동) 기록은 UI 프로세스의 메모리에 있다.

- 활성화는 `ui.idempotency.enabled=true`(서버 `UI_IDEMPOTENCY_ENABLED`)다. 차트는 `ui.replicaCount`가 **1**일 때만 `true`로 렌더하고 `strategy: Recreate`를 쓴다. 복제본이 2 이상이면 `false`로 남고 `helm install` 출력(`NOTES.txt`)이 경고하며, 키가 붙은 쓰기는 422 `idempotency_unsupported`로 거부된다. 복제본마다 기록이 달라 한 복제본의 재생 보증이 다른 복제본에서는 없기 때문이다.
- 재시작하면 기록이 사라진다(TTL 기본 24h, 전체 10,000건·신원당 1,000건). 재시작 뒤 같은 키로 재시도하면 새 요청으로 실행된다(생성은 409 `already_exists`, 삭제는 404). 상한에 도달하면 새 키만 503 `idempotency_capacity`로 거부한다.
- 백업 시작은 예외다. 키가 영속 job 기록에 있어 재시작 뒤에도 같은 job을 재생한다. `UI_IDEMPOTENCY_KEY_FILE`(차트는 백업이 켜지면 백업 PVC의 `.idempotency/key`로 지정)이 없으면 키는 422로 거부된다. 키 파일을 잃으면 기존 기록은 재생되지 않고 409 `idempotency_outcome_unknown`이 된다.
- 현재 활성 여부는 로그인한 세션으로 `GET /api/server-settings`의 `idempotencyEnabled`에서 읽는다.

## `message` 필드의 호환 메모

오류 본문의 `message`는 `error`와 같은 값의 deprecated alias다. `/api/v1`이 유지되는 동안 남고, 제거에는 새 변경 패키지·UI 이전·최소 한 릴리스가 필요하다. 소비자는 `error`를 읽도록 옮겨 두면 된다. 봉투 자체를 되돌려야 하면 커밋을 revert한다(설정·차트·이미지 변경 없음).
