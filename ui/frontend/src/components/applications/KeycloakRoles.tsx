import { useState } from 'react'
import { useLanguage } from '@/context/LanguageContext'
import { integration, type KeycloakSnapshot, type RoleChange } from '@/lib/app-profiles'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'

export function KeycloakRoles({ applicationID }: { applicationID: string }) {
  const { language } = useLanguage()
  const ko = language === 'ko'
  const [snapshot, setSnapshot] = useState<KeycloakSnapshot>()
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [role, setRole] = useState('')
  const [include, setInclude] = useState('')
  const [group, setGroup] = useState('')

  async function refresh() {
    setBusy(true); setError('')
    try { setSnapshot(await integration.roles(applicationID)) }
    catch (err) { setError(err instanceof Error ? err.message : String(err)) }
    finally { setBusy(false) }
  }
  async function change(action: RoleChange['action']) {
    if (!snapshot) return
    if (!window.confirm(ko ? 'Keycloak 역할 설정을 실제로 변경하시겠습니까?' : 'Apply this role change to Keycloak?')) return
    setBusy(true); setError('')
    try { setSnapshot(await integration.change(applicationID, snapshot.fingerprint, { action, role, include, group_id: group })) }
    catch (err) { setError(err instanceof Error ? err.message : String(err)); setSnapshot(undefined) }
    finally { setBusy(false) }
  }
  return <section className="space-y-3 rounded border border-border p-4">
    <h2 className="font-semibold">{ko ? 'Keycloak 역할·그룹 연결' : 'Keycloak roles and group mappings'}</h2>
    <p className="text-xs leading-relaxed text-muted-foreground">{ko ? '역할 A가 B를 포함하면 A를 받은 사용자에게 B도 부여됩니다. 조직 상하 관계와는 별도로 설정합니다.' : 'If role A includes B, users granted A also receive B. This is configured separately from organization hierarchy.'}</p>
    <Button type="button" disabled={busy} onClick={refresh}>{ko ? '실제 역할 조회' : 'Load Keycloak roles'}</Button>
    {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
    {snapshot && <>
      <p className="text-sm">{snapshot.writable ? (ko ? '위임 편집 가능' : 'Delegated editing enabled') : (ko ? '조회 전용' : 'Read only')}</p>
      {snapshot.roles.length === 0 && <p className="text-sm text-muted-foreground">{ko ? '이 client에 등록된 역할이 없습니다.' : 'No roles are registered for this client.'}</p>}
      <ul className="text-sm">{snapshot.roles.map((r) => <li key={r.id}>
        <button type="button" className="underline" onClick={() => setRole(r.name)}>{r.name}</button>
        {snapshot.includes[r.name]?.length > 0 && ` → ${snapshot.includes[r.name].map((v) => v.name).join(', ')}`}
      </li>)}</ul>
      <ul className="text-sm">{snapshot.groups.map((g) => <li key={g.id}>{g.path}: {snapshot.group_roles[g.id]?.map((r) => r.name).join(', ') || '—'}</li>)}</ul>
      {snapshot.writable && <div className="space-y-2">
        <label className="grid gap-1 text-sm">{ko ? '역할 이름' : 'Role name'}<Input value={role} onChange={(e) => setRole(e.target.value)} disabled={busy} /></label>
        <div className="flex gap-2"><Button type="button" disabled={busy || !role} onClick={() => change('create')}>{ko ? '역할 생성' : 'Create role'}</Button>
          <Button type="button" variant="danger" disabled={busy || !role} onClick={() => change('delete')}>{ko ? '역할 삭제' : 'Delete role'}</Button></div>
        <label className="grid gap-1 text-sm">{ko ? '포함할 하위 역할' : 'Included role'}<Input value={include} onChange={(e) => setInclude(e.target.value)} disabled={busy} /></label>
        <div className="flex gap-2"><Button type="button" disabled={busy || !role || !include} onClick={() => change('include_add')}>{ko ? '상속 추가' : 'Add inheritance'}</Button>
          <Button type="button" disabled={busy || !role || !include} onClick={() => change('include_remove')}>{ko ? '상속 제거' : 'Remove inheritance'}</Button></div>
        <label className="grid gap-1 text-sm" htmlFor="managed-group">{ko ? '권한 부여 그룹' : 'Grant group'}</label>
        <select id="managed-group" value={group} onChange={(e) => setGroup(e.target.value)} disabled={busy} className="rounded border border-border bg-surface p-2">
          <option value="">{ko ? '그룹 선택' : 'Choose group'}</option>{snapshot.groups.map((g) => <option key={g.id} value={g.id}>{g.path}</option>)}
        </select>
        <div className="flex gap-2"><Button type="button" disabled={busy || !role || !group} onClick={() => change('group_add')}>{ko ? '그룹에 역할 부여' : 'Assign group role'}</Button>
          <Button type="button" disabled={busy || !role || !group} onClick={() => change('group_remove')}>{ko ? '그룹 역할 회수' : 'Revoke group role'}</Button></div>
      </div>}
    </>}
  </section>
}
