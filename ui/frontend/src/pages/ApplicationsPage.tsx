import { useEffect, useState, type FormEvent } from 'react'
import { KeycloakRoles } from '@/components/applications/KeycloakRoles'
import { IntegrationTools } from '@/components/applications/IntegrationTools'
import { useLanguage } from '@/context/LanguageContext'
import { type ApplicationProfile, appProfiles, integration, integrationMethods, type IntegrationMethod } from '@/lib/app-profiles'
import { Button } from '@/components/ui/button'
import { IntegrationGuide } from '@/components/applications/IntegrationGuide'
import { MappingEditor } from '@/components/applications/MappingEditor'
import { MethodEditor } from '@/components/applications/MethodEditor'
import { type IntegrationGuide as Guide, guideFor } from '@/lib/oss-integration-guides'
import { ArrowRight, ShieldCheck, Plus } from 'lucide-react'
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
  const [mappings, setMappings] = useState<ApplicationProfile['mappings']>([])
  const [tab, setTab] = useState<'setup' | 'roles' | 'delivery'>('setup')
  const [methods, setMethods] = useState<IntegrationMethod[]>([])
  const [managingMethods, setManagingMethods] = useState(false)
  const customGuides: Guide[] = methods.map((m) => ({ id: m.id, name: m.name, kind: m.enforcement === 'gateway_admission' ? 'gateway' : 'manual', custom: true, claim: m.claim_path, token: m.token_source, roles: m.roles, summary: [m.summary, m.summary], scope: [m.scope_note, m.scope_note], steps: m.steps.map((s) => [s, s]), docs: m.documentation_url }))
  const guide = guideFor(draft.integration_type, customGuides)
  const savedProfile = profiles.find((p) => p.id === draft.id)
  const dirty = revision > 0 && savedProfile !== undefined && (
    (['name', 'client_id', 'issuer', 'claim_path', 'token_source', 'enforcement', 'integration_type'] as const).some((key) => (savedProfile[key] ?? '') !== (draft[key] ?? '')) ||
    JSON.stringify(savedProfile.mappings) !== JSON.stringify(mappings)
  )
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(true)
  const [available, setAvailable] = useState(false)

  useEffect(() => {
    let active = true
    Promise.all([appProfiles.list(), integrationMethods.list()]).then(([{ applications }, { methods: loadedMethods }]) => {
      if (active) { setProfiles(applications); setMethods(loadedMethods); setAvailable(true) }
    }).catch((err: unknown) => {
      if (active) setError(err instanceof Error ? err.message : String(err))
    }).finally(() => { if (active) setBusy(false) })
    return () => { active = false }
  }, [])

  function edit(profile?: ApplicationProfile) {
    const { revision: savedRevision, status: _status, ...fields } = profile ?? empty
    setDraft({ ...fields }); setRevision(savedRevision ?? 0)
    setMappings(fields.mappings.map((m) => ({ ...m }))); setTab('setup')
    setNotice(''); setError('')
  }

  async function save(event: FormEvent) {
    event.preventDefault(); setError(''); setNotice(''); setBusy(true)
    try {
      const validMappings = mappings.filter((m) => m.keycloak_role.trim() || m.native_role.trim()).map((m) => ({ keycloak_role: m.keycloak_role.trim(), native_role: m.native_role.trim() }))
      if (validMappings.some((m) => !m.keycloak_role || !m.native_role)) throw new Error(ko ? '각 매핑에 claim 값과 앱 역할을 모두 입력하세요.' : 'Each mapping needs both a claim value and an application role.')
      const saved = await appProfiles.save({ ...draft, mappings: validMappings }, revision)
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

  function selectGuide(id: string) {
    const selected = guideFor(id, customGuides)
    setDraft({ ...draft, integration_type: id, claim_path: selected.claim ?? 'groups', token_source: selected.token, enforcement: selected.kind === 'gateway' ? 'gateway_admission' : 'native_app' })
    if (selected.kind === 'gateway') setMappings([])
    setNotice(ko ? '연동 기본값을 선택했습니다. 저장 전 claim과 기존 매핑을 확인하세요.' : 'Integration defaults selected. Review claims and existing mappings before saving.')
  }

  return <section className="space-y-5">
    <header className="flex flex-wrap items-end justify-between gap-3">
      <div><h1 className="text-xl font-semibold">{ko ? '앱 SSO 권한 연동' : 'Application SSO permissions'}</h1>
        <p className="mt-1 text-sm text-muted-foreground">{ko ? '앱의 권한 모델에 맞춰 OIDC claim을 연결하고 적용할 설정을 준비합니다.' : 'Connect OIDC claims to each application’s permission model and prepare its configuration.'}</p></div>
      <span className="rounded-full border border-border px-3 py-1 text-xs text-muted-foreground">{profiles.length} {ko ? '등록된 앱' : 'registered apps'}</span>
    </header>
    <div className="flex flex-wrap items-center gap-2 rounded-console border border-border bg-surface px-4 py-3 text-xs">
      <span>{ko ? 'LDAP 사용자·그룹' : 'LDAP users / groups'}</span><ArrowRight className="size-3 text-muted-foreground" />
      <span className="flex items-center gap-1"><ShieldCheck className="size-3 text-accent" />Keycloak · OIDC claims</span><ArrowRight className="size-3 text-muted-foreground" />
      <span>{ko ? '앱 자체 권한 검사' : 'Application authorization'}</span>
      <span className="ml-auto text-muted-foreground">{ko ? '설정 저장과 실제 권한 적용은 별도 단계입니다.' : 'Saving configuration and applying access are separate steps.'}</span>
    </div>
    {error && <p role="alert" className="rounded-console border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">{error}</p>}
    {notice && <p role="status" className="rounded-console border border-accent/30 bg-accent/5 p-3 text-sm">{notice}</p>}
    {managingMethods && <MethodEditor methods={methods} onClose={() => setManagingMethods(false)} onSaved={(m) => { setMethods((items) => [...items.filter((v) => v.id !== m.id), m]); setManagingMethods(false); setNotice(ko ? '연동 방식을 저장했습니다. 새 카드를 선택해 앱에 사용할 수 있습니다.' : 'Method saved. Select its new card to use it in an application.'); }} />}
    {available && <div className="grid items-start gap-5 lg:grid-cols-[220px_1fr]">
      <aside className="space-y-3 lg:sticky lg:top-4">
        <Button disabled={busy} onClick={() => edit()} className="w-full"><Plus className="mr-1 size-4" />{ko ? '새 앱' : 'New application'}</Button>
        {profiles.map((profile) => <button key={profile.id} disabled={busy} onClick={() => edit(profile)}
          className={`block w-full rounded-console border p-3 text-left text-sm ${draft.id === profile.id ? 'border-accent bg-accent/5' : 'border-border bg-surface hover:bg-muted'}`}>
          <strong className="block truncate">{profile.name}</strong><span className="mt-1 block truncate font-mono text-[11px] text-muted-foreground">{profile.client_id}</span>
          <span className="mt-2 block text-[11px] text-muted-foreground">{guideFor(profile.integration_type, customGuides).name} · {ko ? '설정 저장됨' : 'Configured'}</span>
        </button>)}
        <p className="text-xs leading-relaxed text-muted-foreground">{ko ? '목록의 OSS는 시작을 돕는 예시입니다. 다른 앱은 Custom OIDC app으로 등록하세요.' : 'These OSS guides are starting points. Register any other app with Custom OIDC app.'}</p>
      </aside>
      <div className="min-w-0 rounded-console border border-border bg-surface">
        <div className="flex flex-wrap gap-1 border-b border-border p-2" role="tablist" aria-label={ko ? '연동 단계' : 'Integration stages'}>
          {(['setup', 'roles', 'delivery'] as const).map((key, n) => <button type="button" role="tab" key={key} tabIndex={tab === key ? 0 : -1} onKeyDown={(event) => {
            if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return
            event.preventDefault()
            const buttons = Array.from(event.currentTarget.parentElement!.querySelectorAll<HTMLButtonElement>('button:not(:disabled)'))
            const current = buttons.indexOf(event.currentTarget)
            const next = event.key === 'Home' ? 0 : event.key === 'End' ? buttons.length - 1 : (current + (event.key === 'ArrowRight' ? 1 : -1) + buttons.length) % buttons.length
            buttons[next]?.focus(); buttons[next]?.click()
          }} aria-selected={tab === key} aria-controls={`app-panel-${key}`} id={`app-tab-${key}`} disabled={busy || (key !== 'setup' && (revision === 0 || dirty))} onClick={() => setTab(key)} className={`rounded-console px-4 py-2 text-sm ${tab === key ? 'bg-muted font-semibold text-foreground' : 'text-muted-foreground'}`}>
            <span className="mr-2 font-mono text-xs">{n + 1}</span>{key === 'setup' ? (ko ? '앱·claim 설정' : 'App and claims') : key === 'roles' ? (ko ? 'Keycloak 역할' : 'Keycloak roles') : (ko ? '내보내기·검증' : 'Export and verify')}</button>)}
        </div>
        <div role="tabpanel" id={`app-panel-${tab}`} aria-labelledby={`app-tab-${tab}`} className="space-y-6 p-4 sm:p-6">
          {tab === 'setup' && <form onSubmit={save} className="space-y-6">
            <IntegrationGuide guide={guide} onSelect={selectGuide} disabled={busy} custom={customGuides} onManage={() => setManagingMethods(true)} />
            <section className="space-y-4 border-t border-border pt-5"><h2 className="text-sm font-semibold">{ko ? 'OIDC 연결 정보' : 'OIDC connection'}</h2>
              <div className="grid gap-4 sm:grid-cols-2">{field('id', ko ? '앱 ID' : 'Application ID')}{field('name', ko ? '앱 이름' : 'Application name')}{field('client_id', 'Keycloak client ID')}{field('issuer', 'OIDC issuer (HTTPS)')}{field('claim_path', ko ? '역할 claim 경로' : 'Role claim path')}
                <label className="grid gap-1 text-sm">{ko ? '토큰 출처' : 'Token source'}<select aria-label={ko ? '토큰 출처' : 'Token source'} value={draft.token_source} disabled={busy} onChange={(e) => setDraft({ ...draft, token_source: e.target.value as ApplicationProfile['token_source'] })} className="rounded-console border border-border bg-surface p-2"><option value="access_token">Access token</option><option value="id_token">ID token</option><option value="userinfo">Userinfo</option></select></label>
              </div>
              <label className="grid gap-1 text-sm" htmlFor="app-enforcement">{ko ? '권한 검사 위치' : 'Enforcement'}<select id="app-enforcement" aria-label={ko ? '권한 검사 위치' : 'Enforcement'} value={draft.enforcement} disabled={busy} onChange={(e) => setDraft({ ...draft, enforcement: e.target.value as ApplicationProfile['enforcement'] })} className="rounded-console border border-border bg-surface p-2"><option value="native_app">{ko ? '앱 자체 권한' : 'Native application'}</option><option value="gateway_admission">{ko ? 'Gateway 진입 검사만' : 'Gateway admission only'}</option></select></label>
            </section>
            {dirty && <p className="text-xs text-accent">{ko ? '변경사항을 저장하면 역할 조회와 내보내기를 사용할 수 있습니다.' : 'Save changes to use role observation and configuration export.'}</p>}
            <MappingEditor value={mappings} onChange={setMappings} roles={guide.roles} disabled={busy} />
            <p className="text-xs leading-relaxed text-muted-foreground">{ko ? '현재 프로파일은 앱 전체 매핑입니다. 프로젝트·namespace·경로·조직 범위는 앱에서 별도로 설정하고 검증하세요.' : 'Profiles describe app-wide mapping. Configure and verify project, namespace, path and organization scopes in the application.'}</p>
            <div className="flex flex-wrap items-center gap-3 border-t border-border pt-4"><Button type="submit" disabled={busy}>{ko ? '프로파일 저장' : 'Save profile'}</Button>{revision > 0 && <Button type="button" variant="danger" disabled={busy} onClick={remove}>{ko ? '프로파일 삭제' : 'Delete profile'}</Button>}<span className="ml-auto text-xs text-muted-foreground">{revision > 0 ? `Revision ${revision} · ${ko ? '앱 적용 미확인' : 'Application access unverified'}` : (ko ? '저장 후 역할과 내보내기를 사용할 수 있습니다.' : 'Save to enable roles and export.')}</span></div>
          </form>}
          {tab === 'roles' && <KeycloakRoles key={draft.id} applicationID={draft.id} />}
          {tab === 'delivery' && <IntegrationTools key={`${draft.id}-${revision}`} applicationID={draft.id} guide={guide} />}
        </div>
      </div>
    </div>}
  </section>
}
