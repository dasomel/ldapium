export interface IntegrationGuide {
  id: string
  name: string
  kind: 'export' | 'manual' | 'generic' | 'gateway'
  summary: [string, string]
  scope: [string, string]
  steps: [string, string][]
  docs: string
  token: 'id_token' | 'access_token' | 'userinfo'
  roles: string[]
  claim?: string
  custom?: boolean
}

// Research references and supported boundaries: docs/changes/oidc-organization-authorization/OSS-UI.md.
export const integrationGuides: IntegrationGuide[] = [
  { id: 'generic', name: 'Custom OIDC app', kind: 'generic', token: 'access_token', roles: [],
    summary: ['어떤 앱이든 claim과 자체 권한을 연결', 'Connect any application’s claims and native permissions'],
    scope: ['앱이 지원하는 권한 규칙을 확인하세요.', 'Check the application’s native authorization rules.'],
    steps: [['앱의 OIDC client와 callback을 등록합니다.', 'Register the app’s OIDC client and callback.'], ['앱이 읽는 claim·토큰과 권한을 지정합니다.', 'Choose the claims, tokens and roles the app consumes.'], ['범용 계약을 앱 설정에 반영하고 허용·거부를 확인합니다.', 'Apply the generic contract and test allowed and denied access.']],
    docs: 'https://www.keycloak.org/docs/latest/server_admin/', },
  { id: 'grafana', name: 'Grafana', kind: 'export', token: 'id_token', roles: ['Admin', 'Editor', 'Viewer'],
    summary: ['그룹 claim → 조직 역할', 'Group claim → organization role'],
    scope: ['Admin은 조직 관리자입니다. 서버 전체 GrafanaAdmin은 내보내지 않습니다.', 'Admin manages an organization. Server-wide GrafanaAdmin is not exported.'],
    steps: [['Keycloak ID token에 groups를 포함합니다.', 'Include groups in the Keycloak ID token.'], ['그룹을 Admin·Editor·Viewer에 매핑합니다. 위쪽 행이 우선합니다.', 'Map groups to Admin, Editor or Viewer. Earlier rows take precedence.'], ['Generic OAuth 설정을 적용하고 미매핑 사용자 거부를 확인합니다.', 'Apply Generic OAuth settings and verify unmapped users are denied.']],
    docs: 'https://grafana.com/docs/grafana/latest/setup-grafana/configure-access/configure-authentication/generic-oauth/' },
  { id: 'argocd', name: 'Argo CD', kind: 'export', token: 'id_token', roles: ['admin', 'readonly'],
    summary: ['그룹 claim → RBAC 정책', 'Group claim → RBAC policy'],
    scope: ['내보내기는 앱 전체 admin·readonly만 지원합니다. 프로젝트별 권한은 AppProject에서 설정하세요.', 'Exports support app-wide admin/readonly. Configure project roles in AppProject.'],
    steps: [['OIDC 또는 Dex가 groups claim을 전달하도록 설정합니다.', 'Configure OIDC or Dex to deliver the groups claim.'], ['그룹과 RBAC 역할을 연결합니다.', 'Bind groups to RBAC roles.'], ['argocd-rbac-cm을 기존 정책과 병합하고 프로젝트 접근을 확인합니다.', 'Merge argocd-rbac-cm with existing policy and check project access.']],
    docs: 'https://argo-cd.readthedocs.io/en/stable/operator-manual/rbac/' },
  { id: 'harbor', name: 'Harbor', kind: 'manual', token: 'id_token', roles: [],
    summary: ['OIDC 그룹 + 프로젝트 멤버십', 'OIDC groups + project membership'],
    scope: ['OIDC Admin Group은 시스템 관리자입니다. 프로젝트 역할은 Harbor에서 별도로 부여합니다.', 'OIDC Admin Group grants system administration. Project roles are assigned separately in Harbor.'],
    steps: [['Harbor OIDC 설정에 issuer·client·Group Claim Name을 지정합니다.', 'Set issuer, client and Group Claim Name in Harbor OIDC settings.'], ['대상 그룹을 프로젝트 멤버로 추가하고 프로젝트 역할을 지정합니다.', 'Add the group as a project member and assign its project role.'], ['프로젝트별 pull·push 권한과 CLI secret 사용을 확인합니다.', 'Test project pull/push access and CLI secret authentication.']],
    docs: 'https://goharbor.io/docs/2.14.0/administration/configure-authentication/oidc-auth/' },
  { id: 'gitea', name: 'Gitea', kind: 'manual', token: 'id_token', roles: [],
    summary: ['그룹 claim → 조직·팀 → 저장소 권한', 'Group claim → organization/team → repository access'],
    scope: ['관리자 그룹은 인스턴스 권한입니다. 조직·팀과 저장소 접근은 Gitea에서 설정하세요.', 'Admin groups grant instance privileges. Configure team and repository access in Gitea.'],
    steps: [['OAuth2 인증 소스에 OIDC discovery URL을 등록합니다.', 'Register the OIDC discovery URL in an OAuth2 authentication source.'], ['group claim과 조직·팀 매핑을 설정합니다.', 'Configure the group claim and organization/team mappings.'], ['팀의 저장소 권한과 로그인 이후 멤버십 동작을 검증합니다.', 'Verify team repository permissions and post-login membership behavior.']],
    docs: 'https://docs.gitea.com/administration/authentication/' },
  { id: 'kubernetes', name: 'Kubernetes', kind: 'manual', token: 'id_token', roles: [],
    summary: ['OIDC 그룹 → RoleBinding', 'OIDC groups → RoleBinding'],
    scope: ['namespace는 RoleBinding으로 격리합니다. ClusterRoleBinding은 클러스터 전체에 적용됩니다.', 'RoleBinding scopes namespace access. ClusterRoleBinding applies cluster-wide.'],
    steps: [['API server의 JWT/OIDC issuer·audience·groups를 설정합니다.', 'Configure API server JWT/OIDC issuer, audience and groups.'], ['group prefix를 포함한 정확한 그룹 이름을 RBAC에 연결합니다.', 'Bind the exact group name, including its configured prefix, to RBAC.'], ['대상 namespace의 허용 작업과 다른 namespace의 거부를 확인합니다.', 'Test allowed actions in the target namespace and denial elsewhere.']],
    docs: 'https://kubernetes.io/docs/reference/access-authn-authz/rbac/' },
  { id: 'openbao', name: 'OpenBao', kind: 'manual', token: 'id_token', roles: [],
    summary: ['OIDC role·그룹 alias → 경로 정책', 'OIDC role/group aliases → path policies'],
    scope: ['groups claim만으로 경로 접근이 생기지 않습니다. OpenBao policy·identity group을 설정하세요.', 'Groups alone do not grant path access. Configure OpenBao policies and identity groups.'],
    steps: [['JWT/OIDC auth method에 issuer와 callback을 등록합니다.', 'Register issuer and callbacks in the JWT/OIDC auth method.'], ['role의 audience·claim 제약과 groups_claim·policy를 설정합니다.', 'Configure role audience/claim bounds, groups_claim and policies.'], ['identity group alias와 허용·거부 경로, token TTL을 검증합니다.', 'Verify identity group aliases, allowed/denied paths and token TTL.']],
    docs: 'https://openbao.org/docs/auth/jwt/' },
  { id: 'oauth2-proxy', name: 'OAuth2 Proxy / gateway', kind: 'gateway', token: 'id_token', roles: [],
    summary: ['그룹 allowlist → 앱 진입 허용', 'Group allowlist → application admission'],
    scope: ['진입 허용은 앱 내부 read·write·admin 권한을 부여하지 않습니다.', 'Admission does not grant read/write/admin privileges inside the app.'],
    steps: [['OIDC issuer·client와 groups claim을 설정합니다.', 'Configure the OIDC issuer, client and groups claim.'], ['allowed_groups를 설정하고 직접 접속 우회를 차단합니다.', 'Set allowed_groups and prevent direct access bypass.'], ['허용·미허용 그룹과 앱 자체 권한을 각각 검증합니다.', 'Test allowed/disallowed groups and native app permissions separately.']],
    docs: 'https://oauth2-proxy.github.io/oauth2-proxy/configuration/overview/' },
]
export function guideFor(id?: string, custom: IntegrationGuide[] = []) { return [...integrationGuides, ...custom].find((g) => g.id === id) ?? integrationGuides[0] }
