import type {
  ApiErrorBody,
  AuthConfig,
  Entry,
  Group,
  GroupFormInput,
  ListResult,
  LogoutResponse,
  Me,
  MonitorStats,
  PasswordPolicy,
  ServerSettings,
  TreeNode,
  User,
  UserFormInput,
} from './types'

/** Thrown for any non-2xx API response, carrying the server's message. */
export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api${path}`, {
    ...init,
    credentials: 'same-origin',
    headers: {
      ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
      ...init?.headers,
    },
  })

  if (res.status === 204) {
    return undefined as T
  }

  const text = await res.text()
  const body = text ? (JSON.parse(text) as unknown) : undefined

  if (!res.ok) {
    const err = body as ApiErrorBody | undefined
    throw new ApiError(res.status, err?.error ?? err?.message ?? res.statusText)
  }
  return body as T
}

function qs(params: Record<string, string | undefined>): string {
  const usp = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined) usp.set(k, v)
  }
  const s = usp.toString()
  return s ? `?${s}` : ''
}

export const api = {
  authConfig: () => request<AuthConfig>('/auth/config'),
  login: (identity: string, password: string) =>
    request<Me>('/login', { method: 'POST', body: JSON.stringify({ identity, password }) }),
  logout: () => request<LogoutResponse>('/logout', { method: 'POST' }),
  me: () => request<Me>('/me'),
  serverSettings: () => request<ServerSettings>('/server-settings'),
  monitorStats: () => request<MonitorStats>('/monitor'),

  tree: (dn?: string) => request<TreeNode[]>(`/tree${qs({ dn })}`),
  entry: (dn: string) => request<Entry>(`/entry${qs({ dn })}`),

  // An empty array is a normal response (the server may not run the
  // ppolicy overlay at all) — never treat "no policies" as an error.
  listPasswordPolicies: () =>
    request<{ policies: PasswordPolicy[] }>('/password-policies').then((r) => r.policies),

  listUsers: () =>
    request<{ users: User[]; truncated: boolean }>('/users').then(
      ({ users, truncated }): ListResult<User> => ({ items: users, truncated }),
    ),
  createUser: (input: UserFormInput) =>
    request<{ dn: string }>('/users', { method: 'POST', body: JSON.stringify(input) }),
  updateUser: (input: UserFormInput) =>
    request<void>('/users', { method: 'PUT', body: JSON.stringify(input) }),
  deleteUser: (dn: string) => request<void>(`/users${qs({ dn })}`, { method: 'DELETE' }),
  setPassword: (dn: string, password?: string, oldPassword?: string) =>
    request<{ generatedPassword?: string }>('/users/password', {
      method: 'POST',
      body: JSON.stringify({ dn, password, oldPassword }),
    }),
  unlockUser: (dn: string) => request<void>('/users/unlock', { method: 'POST', body: JSON.stringify({ dn }) }),

  listGroups: () =>
    request<{ groups: Group[]; truncated: boolean }>('/groups').then(
      ({ groups, truncated }): ListResult<Group> => ({ items: groups, truncated }),
    ),
  createGroup: (input: GroupFormInput) =>
    request<{ dn: string }>('/groups', { method: 'POST', body: JSON.stringify(input) }),
  updateGroup: (input: GroupFormInput) =>
    request<void>('/groups', { method: 'PUT', body: JSON.stringify(input) }),
  deleteGroup: (dn: string) => request<void>(`/groups${qs({ dn })}`, { method: 'DELETE' }),
  addMember: (groupDn: string, memberDn: string) =>
    request<void>('/groups/members', {
      method: 'POST',
      body: JSON.stringify({ groupDn, memberDn }),
    }),
  removeMember: (groupDn: string, memberDn: string) =>
    request<void>(`/groups/members${qs({ groupDn, memberDn })}`, { method: 'DELETE' }),
}
