# ldapium Helm chart

`image/`의 OpenLDAP 2.6.14 서버를 StatefulSet으로 배포하고, 선택적으로 관리 UI(`ui/`)를 함께 배포합니다.

English | **한국어**

## 빠른 시작

로컬 chart:

```bash
helm install ldap charts/ldapium \
  --set image.repository=<your-registry>/ldapium \
  --set auth.adminPassword="$(openssl rand -base64 24)"
```

OCI registry에서 릴리스 chart를 설치하는 경우:

```bash
helm install directory oci://ghcr.io/dasomel/charts/ldapium \
  --version 0.1.0 \
  --namespace directory --create-namespace \
  --set auth.adminPassword="$(openssl rand -base64 24)" \
  --set ldap.rootDN='dc=example,dc=org'
```

기본 관리자 비밀번호는 없습니다. `auth.adminPassword` 또는 `auth.existingSecret`이 없으면 `helm template`과 `helm install`이 실패합니다.

## HA / Replication

`replicaCount > 1`이면 StatefulSet에 N개의 pod가 생성되고 multi-provider replication이 자동으로 활성화됩니다. peer 목록은 `replicaCount`와 headless Service를 기준으로 자동 구성됩니다.

```yaml
replicaCount: 3
```

replication을 강제로 켜거나 끄려면 `replication.enabled`를 명시할 수 있습니다.

## 주요 값

| 값 | 기본값 | 설명 |
|---|---|---|
| `replicaCount` | `1` | LDAP 서버 replica 수 |
| `image.repository` | `ghcr.io/dasomel/ldapium` | 서버 이미지 |
| `image.tag` | Chart의 `appVersion` | 이미지 tag |
| `ldap.rootDN` | `dc=example,dc=org` | LDAP base DN |
| `ldap.passwordFailureInterval` | `900` | → `LDAP_PASSWORD_FAILURE_INTERVAL` (ppolicy가 실패한 bind를 잊기까지의 시간, 초) |
| `ldap.limits.idleTimeout` / `writeTimeout` | `600` / `30` | → `LDAP_IDLE_TIMEOUT` / `LDAP_WRITE_TIMEOUT` (초). [Hardening](#hardening) 참고 |
| `ldap.limits.connMaxPending` / `connMaxPendingAuth` | `100` / `1000` | → `LDAP_CONN_MAX_PENDING` / `LDAP_CONN_MAX_PENDING_AUTH` |
| `ldap.limits.sockbufMaxIncoming` / `sockbufMaxIncomingAuth` | `262143` / `4194303` | → `LDAP_SOCKBUF_MAX_INCOMING` / `LDAP_SOCKBUF_MAX_INCOMING_AUTH` (바이트) |
| `ldap.limits.maxFilterDepth` | `20` | → `LDAP_MAX_FILTER_DEPTH` |
| `ldap.limits.pagedTotal` | `""` | → `LDAP_PAGED_TOTAL_LIMIT`, 값이 있을 때만 렌더링. opt-in: 2147483647 이하의 양의 정수 또는 `unlimited`(`values.schema.json`이 검사: `1.5`, `0`, 음수, 더 큰 수는 다른 숫자로 바뀌지 않고 렌더 단계에서 실패). 인증된 일반(비관리자) 신원도 paged search에서 `olcSizeLimit`(10000)을 넘겨 읽을 수 있게 합니다. 관리자 DN은 원래 면제입니다. 이미지는 기존 규칙 **뒤에** `olcLimits: users size.prtotal=<값>`를 추가하므로 운영자가 DN에 건 규칙이 우선하고(slapd는 첫 일치 규칙만 적용; 운영자의 `users` 규칙이 있으면 아무것도 추가하지 않음), 자신이 기록해 둔 규칙만 바꾸거나 지웁니다. reconcile이 실패하면 이전 한도가 유지되지만, 한도를 더 조이는 요청이면 기동을 중단합니다. paged가 아닌 검색은 기존 상한을 유지하며, 설정하면 인증된 모든 사용자가 ACL이 허용하는 범위를 끝까지 페이징할 수 있으므로, API 클라이언트가 비관리자로 전체를 순회해야 할 때만 설정하십시오(미설정 시 `GET /api/users?limit=`는 `size_limit_exceeded`를 반환). 이미지 README의 "Paged-search total" 참고 |
| `ldap.lastBind.enabled` / `precision` | `false` / `3600` | → `LDAP_LASTBIND_ENABLED` / `LDAP_LASTBIND_PRECISION` (`pwdLastSuccess`, entry별 갱신 최소 간격(초)). opt-in. **replication 사용 시 끄십시오**(분리 중 비밀번호 변경이 되돌려질 수 있음, [Hardening](#hardening) 참고). replication과 함께 켜면 `ldap.lastBind.allowWithReplication=true`가 없는 한 렌더링이 실패합니다. |
| `ldap.hardening.requireTls` | `false` | → `LDAP_REQUIRE_TLS`. opt-in. `tls.enabled` 필요, `metrics.enabled`와 충돌 |
| `ldap.hardening.disallowAnonBind` | `false` | → `LDAP_DISALLOW_ANON_BIND`. opt-in. `ldap.anonymousReadBase`가 설정되었거나, `ui.enabled`이면서 `ui.ldap.userSearchFilter`가 비어 있지 않으면 chart가 실패 |
| `ldap.hardening.requireAuthc` | `false` | → `LDAP_REQUIRE_AUTHC`. opt-in. `disallowAnonBind`와 동일한 guard |
| `tls.ecName` | `""` | → `LDAP_TLS_EC_NAME`, 비어 있지 않을 때만 설정. 곡선을 하나로 고정하면 해당 곡선을 지원하지 않는 클라이언트(X25519/P-256 전용)가 끊길 수 있음 |
| `ldap.modules.*` | [Overlay modules](#overlay-modules) 참고 | → `LDAP_PPM_*`, `LDAP_DEREF_ENABLED`, `LDAP_CONSTRAINT_*`, `LDAP_NESTGROUP_ENABLED`, `LDAP_DYNLIST_ENABLED`, `LDAP_SSSVLV_MAIN_ENABLED`, `LDAP_OTP_ENABLED` |
| `networkPolicy.enabled` | `false` | 서버 pod용 NetworkPolicy 생성. [Hardening](#hardening) 참고 |
| `networkPolicy.ingressFrom` | `[{podSelector: {}}]` | 389/636 접근을 허용할 NetworkPolicy `from` peer 원문 (기본값: 같은 namespace). 비어 있으면 안 됨: `from: []`은 전체 허용을 의미하므로 chart가 렌더링 대신 실패함 |
| `networkPolicy.monitoringNamespaceSelector` | `kubernetes.io/metadata.name: monitoring` | 9330 포트 scrape를 허용할 namespace (`metrics.enabled`일 때만) |
| `auth.adminPassword` | 없음 | 관리자 비밀번호, 필수 |
| `auth.existingSecret` | 없음 | 기존 Secret에서 비밀번호 사용 |
| `tls.enabled` | `false` | TLS 활성화 여부. 현재 end-to-end 검증 필요 |
| `backup.enabled` | `false` | backup CronJob 활성화 |
| `ui.enabled` | `false` | 관리 UI 활성화 |
| `ui.sso.enabled` | `false` | Keycloak OIDC SSO 활성화 |

전체 값은 `values.yaml`에서 확인하십시오.

## 실제 운영 시 주의사항

- `helm upgrade --reuse-values`는 새 chart default를 자동으로 가져오지 않습니다.
- `--set`에서 DN 안의 쉼표는 값 구분자로 처리될 수 있으므로 DN은 values 파일로 관리하는 것이 안전합니다.
- replication은 backup이 아닙니다. 별도의 backup 기능을 활성화하십시오.
- TLS 설정은 렌더링뿐 아니라 실제 클러스터에서 end-to-end 동작을 확인해야 합니다.

## 설치 검증

```bash
helm test <release> --namespace <namespace> --logs
```

테스트는 관리자 bind, 디렉터리 entry 생성/삭제, `memberOf` overlay 동작 및 replication 환경의 전달 여부 등을 확인합니다.

## Hardening

**Group A, 기본 활성.** `ldap.limits.*`는 항상 렌더링되며, 이미지는 이 값들을 **매** 시작 시 `cn=config`에 반영하므로 values 변경이나 chart 업그레이드는 다음 pod 재시작 때 적용됩니다. `ldap.passwordFailureInterval`은 다릅니다. 첫 bootstrap 때만 기본 ppolicy entry에 기록되므로, 이후 변경하려면 `pwdFailureCountInterval`을 `ldapmodify`로 수정하거나 새 볼륨을 사용해야 합니다. 업그레이드하면 기존 설치본의 wire 동작이 바뀝니다. 600초 넘게 유휴 상태인 연결은 닫히고(health check를 하지 않는 pooled client는 요청 한 건이 실패할 수 있음), 20단계를 넘게 중첩된 filter는 거부됩니다. `connMaxPending*`와 `sockbufMaxIncoming*`는 slapd의 컴파일 기본값을 명시적으로 고정할 뿐 새로 제한을 거는 것이 아닙니다. opt-in을 끄면 이미지가 쓴 값과 정확히 같을 때만 `cn=config`에서 제거하고, 운영자가 `ldapmodify`로 넣은 값은 그대로 둡니다. `ldap.lastBind.*`는 opt-in(`false`)입니다. 활성화하면 bind 성공 시 entry별로 `ldap.lastBind.precision`초에 최대 한 번 `pwdLastSuccess`를 갱신하며, 이 쓰기는 replication됩니다. **경고:** multi-provider 배포에서는 lastBind를 끄십시오. 관찰된 1회 실행(반복 검증 없음)에서, 네트워크 분리 중 한 노드의 bind가 더 최신 `entryCSN`으로 `pwdLastSuccess`를 기록했고, 재연결 후 last-write-wins가 다른 노드의 비밀번호 변경을 되돌렸습니다(새 비밀번호는 실패하고 옛 비밀번호가 두 노드 모두에서 통과). 분리 중 다른 노드에서 한 비밀번호 변경과 잠금이 취소될 수 있습니다. replication이 켜져 있으면 `ldap.lastBind.allowWithReplication=true`가 없는 한 chart 렌더링이 실패합니다. `tls.ecName`은 기본적으로 설정되지 않습니다. 곡선을 하나(예: `secp384r1`)로 고정하면 X25519나 P-256만 제공하는 클라이언트가 끊길 수 있습니다.

**Group B, opt-in, 정상 동작하던 클라이언트를 깨뜨릴 수 있음.** 모두 기본값은 `false`입니다.

| Flag | 영향 |
|---|---|
| `ldap.hardening.requireTls` | chart의 metrics exporter sidecar를 포함해 평문 `ldap://` 클라이언트 전부. `tls.enabled=true`가 아니면 chart 렌더링이 실패하고, `metrics.enabled=true`일 때도 실패합니다. backup CronJob, `helm test` pod, UI 기본 URL은 `tls.enabled`이면 이미 `ldaps://`로 전환됩니다. |
| `ldap.hardening.disallowAnonBind` / `requireAuthc` | SSSD, Keycloak federation, UI의 bare-uid 로그인(`ui.ldap.userSearchFilter`)이 의존하는 익명 uid-to-DN 조회. 둘 중 하나를 `ldap.anonymousReadBase`와 함께 설정하거나, `ui.enabled`이면서 `ui.ldap.userSearchFilter`가 비어 있지 않으면 chart 렌더링이 실패합니다(전체 DN 로그인을 쓰려면 `""`로 설정). 해당 클라이언트를 bind DN 방식으로 옮기는 일은 사용자 책임입니다. |

`requireTls`를 쓰면 UI도 TLS 연결이 필요합니다. `ui.ldap.url`을 비워 두면 자동으로 `ldaps://`가 사용됩니다(`tls.enabled`가 필수이므로). `ui.ldap.url`을 평문 `ldap://` URL로 지정했다면 `ui.ldap.startTLS=true`(CA가 private이면 `ui.ldap.tlsCACert`도)를 설정해야 하며, 그러지 않으면 chart 렌더링이 거부됩니다. `ui/README.md`(`LDAP_START_TLS`)를 참고하십시오.

**NetworkPolicy.** `networkPolicy.enabled=true`는 서버 pod를 선택하므로 해당 pod에 대해 ingress default-deny가 적용됩니다. 허용 대상은 다음과 같습니다. `networkPolicy.ingressFrom`에서 오는 389/636(기본값: release namespace의 모든 pod), chart 자체의 서버 pod(replication), `ui.enabled`일 때 UI pod, `backup.enabled`일 때 backup pod, `metrics.enabled`일 때 `networkPolicy.monitoringNamespaceSelector`에서 오는 9330. egress는 제한하지 않습니다. CNI가 NetworkPolicy를 적용하지 않는 클러스터에서는 효과가 없습니다. `ingressFrom`을 좁힌다면 LDAP 클라이언트(SSSD gateway, Keycloak)가 있는 namespace를 모두 나열하십시오.

## Rollback / downgrade

구버전 이미지는 신버전이 `cn=config`에 쓴 속성을 **무시하지 않습니다**. `ldap.modules.ppmEnabled=true`(기본)이면 업그레이드된 볼륨에 `olcPPolicyCheckModule: /usr/lib/openldap/ppm.so`가 남고(`nestgroup` 활성 시 `nestgroup.la`도), `ppm.so`가 없는 구버전 이미지는 slapd가 시작하지 못합니다(config 로드 시 `lt_dlopen ... file not found`, crash loop). 이 모듈들이 없는 이미지로 롤백하기 전에 `ldap.modules.ppmEnabled=false`(및 켠 opt-in 모듈 전부 `false`)로 **신버전 이미지에서 한 번 재시작**해 reconcile이 배선을 제거하게 한 뒤 롤백하십시오. 실제로 확인: reconcile이 ppolicy overlay의 `olcPPolicyCheckModule`과 기본 policy의 `pwdUseCheckModule`/`pwdCheckModuleArg`를 제거했고, 이후 구버전 이미지가 같은 볼륨에서 정상 기동했습니다.

## Overlay modules

`ldap.modules.*`는 이미지 env 변수에 일대일로 대응합니다. 값을 바꾸면 다음 재시작 때 `cn=config`가 변경됩니다.

| 값 | 기본값 | Env | 용도 |
|---|---|---|---|
| `ppmEnabled` / `ppmMinClasses` | `true` / `1` | `LDAP_PPM_ENABLED` / `LDAP_PPM_MIN_CLASSES` | 비밀번호 품질 검사. 더 많은 문자 종류를 요구하려면 `ppmMinClasses`를 올립니다. ppm은 ASCII 문자 종류만 세므로 `ppmMinClasses` > 1이면 한글만으로 된 암호문은 거부됩니다. chart는 env를 항상 설정하므로 값이 매 시작 시 기본 policy에 다시 적용됩니다(offline 쓰기, 노드별, replication 안 됨). 다운그레이드 전에 `ppmEnabled=false`가 필요합니다(아래 참고). |
| `derefEnabled` | `true` | `LDAP_DEREF_ENABLED` | 클라이언트가 참조된 entry(group member)를 한 번의 search로 가져오게 합니다. |
| `constraintEnabled` / `constraintMailRegex` | `true` / `^[^@[:space:]]+@[^@[:space:]]+$` | `LDAP_CONSTRAINT_ENABLED` / `LDAP_CONSTRAINT_MAIL_REGEX` | 쓰기 시 형식이 잘못된 `mail`을 거부합니다. |
| `nestgroupEnabled` | `false` | `LDAP_NESTGROUP_ENABLED` | 중첩 group 확장. memberof와 상호작용하므로 사용 전에 `memberOf` 결과를 확인하십시오. |
| `dynlistEnabled` | `false` | `LDAP_DYNLIST_ENABLED` | 동적 group: `groupOfURLs` 구성원을 search 시점에 계산합니다. replication이 켜져 있으면 렌더링이 실패합니다(계산된 값이 syncrepl 스트림에 들어감). |
| `sssvlvMainEnabled` | `false` | `LDAP_SSSVLV_MAIN_ENABLED` | Server-side sort / virtual list view. 정렬 search마다 메모리를 사용하므로 필요한 클라이언트가 있을 때만 활성화하십시오. |
| `otpEnabled` | `false` | `LDAP_OTP_ENABLED` | OTP overlay. 해당 schema와 사용자별 OTP 데이터를 미리 준비해야 합니다. |

## Keycloak SSO

`ui.sso.enabled=true`이면 UI는 Keycloak OIDC authorization-code + PKCE 흐름을 사용합니다. 별도 confidential client secret과 LDAP service account를 사용하며 관리자 비밀번호를 재사용하지 않습니다.

예시는 영문 `README.md`와 `values.yaml`의 최신 설정을 기준으로 사용하십시오.
