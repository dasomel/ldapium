import { ApiError } from './api'
import type { ApiErrorBody } from './types'

export interface ApplicationProfile {
  integration_type?: string
  id: string
  name: string
  client_id: string
  issuer: string
  claim_path: string
  token_source: 'id_token' | 'access_token' | 'userinfo'
  enforcement: 'native_app' | 'gateway_admission'
  scope: 'app'
  mappings: { keycloak_role: string; native_role: string }[]
  revision?: number
  status?: string
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api/v1/applications${path}`, {
    ...init, credentials: 'same-origin',
  })
  const body: unknown = await response.json()
  if (!response.ok) {
    const err = body as ApiErrorBody
    throw new ApiError(response.status, err.error ?? err.message ?? 'Application profile request failed')
  }
  return body as T
}

export const appProfiles = {
  list: () => call<{ applications: ApplicationProfile[] }>(''),
  save: (profile: ApplicationProfile, revision: number) =>
    call<ApplicationProfile>(`/${encodeURIComponent(profile.id)}/integration-profile`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'If-Match': `"${revision}"` },
      body: JSON.stringify(profile),
    }),
}

export interface KeycloakRole {
  id: string
  name: string
  composite: boolean
}
export interface KeycloakSnapshot {
  roles: KeycloakRole[]
  includes: Record<string, KeycloakRole[]>
  groups: { id: string; name: string; path: string }[]
  group_roles: Record<string, KeycloakRole[]>
  fingerprint: string
  writable: boolean
}
export interface RoleChange {
  action: 'create' | 'delete' | 'include_add' | 'include_remove' | 'group_add' | 'group_remove'
  role: string
  include?: string
  group_id?: string
}

export const integration = {
  verify: (id: string) => call<Record<string, unknown>>(`/${encodeURIComponent(id)}/integration-verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' } }),
  roles: (id: string) => call<KeycloakSnapshot>(`/${encodeURIComponent(id)}/keycloak-roles`),
  change: (id: string, fingerprint: string, change: RoleChange) => call<KeycloakSnapshot>(`/${encodeURIComponent(id)}/keycloak-role-operations`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'If-Match': `"${fingerprint}"` }, body: JSON.stringify(change),
  }),
  remove: async (id: string, revision: number) => {
    const res = await fetch(`/api/v1/applications/${encodeURIComponent(id)}/integration-profile`, {
      method: 'DELETE', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'If-Match': `"${revision}"` },
    })
    if (!res.ok) {
      const body = (await res.json()) as ApiErrorBody
      throw new ApiError(res.status, body.error ?? body.message ?? 'Delete failed')
    }
  },
  export: (id: string, adapter: string) => call<{ content: string; filename: string; warnings: string[]; status: string }>(`/${encodeURIComponent(id)}/configuration-export?adapter=${encodeURIComponent(adapter)}`),
  preview: (id: string, values: string[]) => call<{ native_roles: string[]; unmapped_values: string[] }>(`/${encodeURIComponent(id)}/mapping-preview`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ claim_values: values }),
  }),
}

export interface IntegrationMethod {
  id: string
  name: string
  summary: string
  scope_note: string
  documentation_url: string
  claim_path: string
  token_source: ApplicationProfile['token_source']
  enforcement: ApplicationProfile['enforcement']
  roles: string[]
  steps: string[]
  revision?: number
}
export const integrationMethods = {
  list: () => call<{ methods: IntegrationMethod[] }>('/integration-methods'),
  save: (method: IntegrationMethod, revision: number) => call<IntegrationMethod>(`/integration-methods/${encodeURIComponent(method.id)}`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json', 'If-Match': `"${revision}"` }, body: JSON.stringify(method),
  }),
}
