import { useEffect, useState, type FormEvent } from 'react'
import { KeycloakRoles } from '@/components/applications/KeycloakRoles'
import { IntegrationTools } from '@/components/applications/IntegrationTools'
import { useLanguage } from '@/context/LanguageContext'
import { type ApplicationProfile, appProfiles, integration } from '@/lib/app-profiles'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'

const empty: ApplicationProfile = {
  id: '', name: '', client_id: '', issuer: '', claim_path: 'groups',
  token_source: 'access_token', enforcement: 'native_app', scope: 'app', mappings: [],
}

export function ApplicationsPage() {
  const { language } = useLanguage()
  const ko = language === 'ko'
  const [profiles, setProfiles] = useState<ApplicationProfile[]>([])
  const [draft, setDraft] = useState<ApplicationProfile>({ ...empty })
  const [revision, setRevision] = useState(0)
  const [mappingText, setMappingText] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(true)
  const [available, setAvailable] = useState(false)

  useEffect(() => {
    let active = true
    appProfiles.list().then(({ applications }) => {
      if (active) { setProfiles(applications); setAvailable(true) }
    }).catch((err: unknown) => {
      if (active) setError(err instanceof Error ? err.message : String(err))
    }).finally(() => { if (active) setBusy(false) })
    return () => { active = false }
  }, [])

  function edit(profile?: ApplicationProfile) {
    const { revision: savedRevision, status: _status, ...fields } = profile ?? empty
    setDraft({ ...fields }); setRevision(savedRevision ?? 0)
    setMappingText(fields.mappings.map((m) => `${m.keycloak_role} = ${m.native_role}`).join('\n'))
    setNotice(''); setError('')
  }

  async function save(event: FormEvent) {
    event.preventDefault(); setError(''); setNotice(''); setBusy(true)
    try {
      const mappings = mappingText.split('\n').filter((line) => line.trim()).map((line) => {
        const parts = line.split('=')
        if (parts.length !== 2 || !parts[0].trim() || !parts[1].trim()) {
          throw new Error(ko ? '각 줄은 claim 값 = 앱 역할 형식이어야 합니다.' : 'Each line must be claim value = app role.')
        }
        return { keycloak_role: parts[0].trim(), native_role: parts[1].trim() }
      })
      const saved = await appProfiles.save({ ...draft, mappings }, revision)
      setProfiles((items) => [...items.filter((p) => p.id !== saved.id), saved].sort((a, b) => a.id.localeCompare(b.id)))
      edit(saved)
      setNotice(ko ? '프로파일을 저장했습니다. 앱 권한은 아직 적용되지 않았습니다.' : 'Profile saved. Application permissions have not been applied.')
    } catch (err) { setError(err instanceof Error ? err.message : String(err)) }
    finally { setBusy(false) }
  }

  async function remove() {
    if (!window.confirm(ko ? '프로파일만 삭제합니다. Keycloak과 앱 권한은 유지됩니다. 삭제할까요?' : 'Delete this profile only? Keycloak and application permissions are preserved.')) return
    setBusy(true); setError('')
    try { await integration.remove(draft.id, revision); setProfiles((items) => items.filter((p) => p.id !== draft.id)); edit() }
    catch (err) { setError(err instanceof Error ? err.message : String(err)) }
    finally { setBusy(false) }
  }

  function field(key: 'id' | 'name' | 'client_id' | 'issuer' | 'claim_path', label: string) {
    return <label className="grid gap-1 text-sm" key={key}>
      {label}
      <Input required value={draft[key]} disabled={busy || (key === 'id' && revision > 0)}
        onChange={(event) => setDraft({ ...draft, [key]: event.target.value })} />
    </label>
  }

  return <section className="space-y-4">
    <h1 className="text-xl font-semibold">{ko ? '앱 SSO 권한 연동' : 'Application SSO permissions'}</h1>
    <p className="text-sm text-muted-foreground">{ko
      ? '앱별 OIDC claim과 역할 대응을 등록합니다. 역할 원본은 Keycloak이며, 이 프로파일을 저장해도 Keycloak이나 앱 설정은 변경되지 않습니다.'
      : 'Register OIDC claims and role mappings for any app. Keycloak owns roles; saving a profile does not change Keycloak or application settings.'}</p>
    {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
    {notice && <p role="status" className="text-sm">{notice}</p>}
    {available && <div className="grid gap-6 lg:grid-cols-[250px_1fr]">
      <aside className="space-y-2">
        <Button disabled={busy} onClick={() => edit()}>{ko ? '새 앱' : 'New application'}</Button>
        {profiles.map((profile) => <button key={profile.id} disabled={busy} onClick={() => edit(profile)}
          className="block w-full rounded border border-border p-3 text-left text-sm">
          <strong>{profile.name}</strong><br />{profile.client_id} · {ko ? '설정 저장됨' : 'Configured'}
        </button>)}
      </aside>
      <form onSubmit={save} className="max-w-2xl space-y-4">
        {field('id', ko ? '앱 ID' : 'Application ID')}
        {field('name', ko ? '앱 이름' : 'Application name')}
        {field('client_id', 'Keycloak client ID')}
        {field('issuer', 'OIDC issuer (HTTPS)')}
        {field('claim_path', ko ? '역할 claim 경로' : 'Role claim path')}
        <label className="grid gap-1 text-sm">{ko ? '토큰 출처' : 'Token source'}
          <select value={draft.token_source} disabled={busy} onChange={(e) => setDraft({ ...draft, token_source: e.target.value as ApplicationProfile['token_source'] })} className="rounded border border-border bg-surface p-2">
            <option value="access_token">Access token</option><option value="id_token">ID token</option><option value="userinfo">Userinfo</option>
          </select>
        </label>
        <label className="grid gap-1 text-sm" htmlFor="app-enforcement">{ko ? '권한 검사 위치' : 'Enforcement'}
          <select id="app-enforcement" aria-label={ko ? '권한 검사 위치' : 'Enforcement'} value={draft.enforcement} disabled={busy} onChange={(e) => setDraft({ ...draft, enforcement: e.target.value as ApplicationProfile['enforcement'] })} className="rounded border border-border bg-surface p-2">
            <option value="native_app">{ko ? '앱 자체 권한' : 'Native application'}</option>
            <option value="gateway_admission">{ko ? 'Gateway 진입 검사만' : 'Gateway admission only'}</option>
          </select>
        </label>
        <p className="text-sm text-muted-foreground">{ko ? '현재 등록 범위는 앱 전체입니다. 조직별 권한은 아직 지원하지 않습니다.' : 'Profiles currently describe app-wide access. Organization-scoped permissions are not supported yet.'}</p>
        <label className="grid gap-1 text-sm">{ko ? '역할 매핑 (한 줄에 claim 값 = 앱 역할)' : 'Role mappings (claim value = app role, one per line)'}
          <textarea value={mappingText} disabled={busy} onChange={(e) => setMappingText(e.target.value)} rows={4} className="rounded border border-border bg-surface p-2 font-mono" />
        </label>
        {revision > 0 && <Button type="button" disabled={busy} onClick={remove}>{ko ? '프로파일 삭제' : 'Delete profile'}</Button>}
        <Button type="submit" disabled={busy}>{ko ? '프로파일 저장' : 'Save profile'}</Button>
        <p className="text-xs text-muted-foreground">{revision > 0 ? `Revision ${revision}` : ''}</p>
        {revision > 0 && <><KeycloakRoles key={draft.id} applicationID={draft.id} /><IntegrationTools key={`tools-${draft.id}`} applicationID={draft.id} /></>}
      </form>
    </div>}
  </section>
}
