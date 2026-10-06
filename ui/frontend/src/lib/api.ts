import type {
  ApiErrorBody,
  AuditActionsResponse,
  AuthConfig,
  Entry,
  Group,
  GroupFormInput,
  ListParams,
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
  /** The stable machine-readable `code` of the error envelope, when the
   * server sends one (older servers do not). */
  code?: string
  constructor(status: number, message: string, code?: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }
}

/** Optional per-request preconditions for the core user/group writes
 * (docs/api.md, "ETag / If-Match" and "Idempotency-Key"). Both are opt-in on
 * the server: leaving a field out sends today's unconditional request. */
export interface WriteOptions {
  /** The item's `etag` exactly as listed (a quoted strong ETag). */
  ifMatch?: string
  idempotencyKey?: string
}

function writeHeaders(opts?: WriteOptions): Record<string, string> {
  return {
    ...(opts?.ifMatch ? { 'If-Match': opts.ifMatch } : {}),
    ...(opts?.idempotencyKey ? { 'Idempotency-Key': opts.idempotencyKey } : {}),
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
    throw new ApiError(res.status, err?.error ?? err?.message ?? res.statusText, err?.code)
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
  auditActions: (limit?: number, before?: string) =>
    request<AuditActionsResponse>(`/audit/actions${qs({ limit: limit ? String(limit) : undefined, before })}`),

  tree: (dn?: string) => request<TreeNode[]>(`/tree${qs({ dn })}`),
  entry: (dn: string) => request<Entry>(`/entry${qs({ dn })}`),

  // An empty array is a normal response (the server may not run the
  // ppolicy overlay at all) — never treat "no policies" as an error.
  listPasswordPolicies: () =>
    request<{ policies: PasswordPolicy[] }>('/password-policies').then((r) => r.policies),

  listUsers: (params?: ListParams) =>
    request<{ users: User[]; truncated: boolean; hasMore?: boolean; nextCursor?: string }>(
      `/users${qs({ limit: params?.limit ? String(params.limit) : undefined, cursor: params?.cursor, q: params?.q })}`,
    ).then(
      ({ users, truncated, hasMore, nextCursor }): ListResult<User> => ({
        items: users ?? [],
        truncated: Boolean(truncated),
        hasMore,
        nextCursor,
      }),
    ),
  createUser: (input: UserFormInput, opts?: WriteOptions) =>
    request<{ dn: string }>('/users', { method: 'POST', body: JSON.stringify(input), headers: writeHeaders(opts) }),
  updateUser: (input: UserFormInput, opts?: WriteOptions) =>
    request<void>('/users', { method: 'PUT', body: JSON.stringify(input), headers: writeHeaders(opts) }),
  deleteUser: (dn: string, opts?: WriteOptions) =>
    request<void>(`/users${qs({ dn })}`, { method: 'DELETE', headers: writeHeaders(opts) }),
  setPassword: (dn: string, password?: string, oldPassword?: string) =>
    request<{ generatedPassword?: string }>('/users/password', {
      method: 'POST',
      body: JSON.stringify({ dn, password, oldPassword }),
    }),
  unlockUser: (dn: string) => request<void>('/users/unlock', { method: 'POST', body: JSON.stringify({ dn }) }),
  lockUser: (dn: string) => request<void>('/users/lock', { method: 'POST', body: JSON.stringify({ dn }) }),

  listGroups: (params?: ListParams) =>
    request<{ groups: Group[]; truncated: boolean; hasMore?: boolean; nextCursor?: string }>(
      `/groups${qs({ limit: params?.limit ? String(params.limit) : undefined, cursor: params?.cursor, q: params?.q })}`,
    ).then(
      ({ groups, truncated, hasMore, nextCursor }): ListResult<Group> => ({
        items: groups ?? [],
        truncated: Boolean(truncated),
        hasMore,
        nextCursor,
      }),
    ),
  createGroup: (input: GroupFormInput, opts?: WriteOptions) =>
    request<{ dn: string }>('/groups', { method: 'POST', body: JSON.stringify(input), headers: writeHeaders(opts) }),
  updateGroup: (input: GroupFormInput, opts?: WriteOptions) =>
    request<void>('/groups', { method: 'PUT', body: JSON.stringify(input), headers: writeHeaders(opts) }),
  deleteGroup: (dn: string, opts?: WriteOptions) =>
    request<void>(`/groups${qs({ dn })}`, { method: 'DELETE', headers: writeHeaders(opts) }),
  addMember: (groupDn: string, memberDn: string) =>
    request<void>('/groups/members', {
      method: 'POST',
      body: JSON.stringify({ groupDn, memberDn }),
    }),
  removeMember: (groupDn: string, memberDn: string) =>
    request<void>(`/groups/members${qs({ groupDn, memberDn })}`, { method: 'DELETE' }),
}
