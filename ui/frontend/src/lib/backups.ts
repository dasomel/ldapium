export type BackupConnection = { id: string; name: string; type: string; host: string; port: number; user: string; endpoint: string; region: string; bucket: string; prefix: string; known_hosts: string; allow_plaintext: boolean; password?: string; access_key?: string; secret_key?: string; credentials_set?: boolean }
export type BackupPolicy = { enabled: boolean; interval_minutes: number; keep_days: number; keep_count: number; destinations: string[] }
export type BackupPolicies = { revision: number; data: BackupPolicy; logs: BackupPolicy }
export type BackupView = { connections: BackupConnection[]; storage: Record<string, { bytes: number; copies: number; latest_bytes: number }>; policies: BackupPolicies; destinations: { id: string; name: string; type: string }[];
  states: Record<string, { status: string; local_verified: boolean; last_local_success: string; last_attempt: string; last_success: string; next_run: string; run_id: string; policy_revision: number }>;
  running: boolean; logs_available: boolean }
async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api/v1/backups${path}`, { credentials: 'same-origin', ...init })
  const body = await response.json()
  if (!response.ok) throw new Error(body.message ?? body.error ?? 'Backup request failed')
  return body as T
}
export const backups = {
  saveConnection: (c: BackupConnection, revision: number) => { const { credentials_set: _stored, ...body } = c; void _stored; return request<BackupView>('/connections', { method: 'PUT', headers: { 'Content-Type': 'application/json', 'If-Match': `"${revision}"` }, body: JSON.stringify(body) }) },
  deleteConnection: (id: string, revision: number) => request<BackupView>(`/connections/${encodeURIComponent(id)}`, { method: 'DELETE', headers: { 'Content-Type': 'application/json', 'If-Match': `"${revision}"` } }),
  get: () => request<BackupView>(''),
  save: (p: BackupPolicies) => request<BackupPolicies>('/policies', { method: 'PUT', headers: { 'Content-Type': 'application/json', 'If-Match': `"${p.revision}"` }, body: JSON.stringify({ data: p.data, logs: p.logs }) }),
  run: (kind: 'data' | 'logs') => request(`/jobs/${kind}`, { method: 'POST', headers: { 'Content-Type': 'application/json' } }),
}
