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

## Keycloak SSO

`ui.sso.enabled=true`이면 UI는 Keycloak OIDC authorization-code + PKCE 흐름을 사용합니다. 별도 confidential client secret과 LDAP service account를 사용하며 관리자 비밀번호를 재사용하지 않습니다.

예시는 영문 `README.md`와 `values.yaml`의 최신 설정을 기준으로 사용하십시오.
