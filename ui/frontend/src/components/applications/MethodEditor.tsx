import { useState, type FormEvent } from 'react'
import { useLanguage } from '@/context/LanguageContext'
import { integrationMethods, type IntegrationMethod } from '@/lib/app-profiles'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'

const empty: IntegrationMethod = { id: 'custom-', name: '', summary: '', scope_note: '', documentation_url: '', claim_path: 'groups', token_source: 'id_token', enforcement: 'native_app', roles: [], steps: [] }
export function MethodEditor({ methods, onSaved, onClose }: { methods: IntegrationMethod[]; onSaved: (m: IntegrationMethod) => void; onClose: () => void }) {
  const { language } = useLanguage(); const ko = language === 'ko'
  const [draft, setDraft] = useState<IntegrationMethod>(empty)
  const [roles, setRoles] = useState(''); const [steps, setSteps] = useState('')
  const [revision, setRevision] = useState(0); const [busy, setBusy] = useState(false); const [error, setError] = useState('')
  function edit(id: string) {
    const { revision: rev, ...m } = methods.find((v) => v.id === id) ?? empty
    setDraft(m); setRevision(rev ?? 0); setRoles(m.roles.join('\n')); setSteps(m.steps.join('\n')); setError('')
  }
  function field(key: 'id' | 'name' | 'summary' | 'scope_note' | 'documentation_url' | 'claim_path', label: string) {
    return <label className="grid gap-1 text-sm">{label}<Input required autoFocus={key === 'id'} type={key === 'documentation_url' ? 'url' : 'text'} value={draft[key]} disabled={busy || (key === 'id' && revision > 0)} onChange={(e) => setDraft({ ...draft, [key]: e.target.value })} /></label>
  }
  async function save(e: FormEvent) {
    e.preventDefault(); setBusy(true); setError('')
    try { onSaved(await integrationMethods.save({ ...draft, roles: roles.split('\n').map((v) => v.trim()).filter(Boolean), steps: steps.split('\n').map((v) => v.trim()).filter(Boolean) }, revision)) }
    catch (err) { setError(err instanceof Error ? err.message : String(err)) }
    finally { setBusy(false) }
  }
  return <section aria-label={ko ? '사용자 정의 연동 방식' : 'Custom integration method'} className="rounded-console border border-accent/40 bg-surface p-5">
    <div className="flex items-center justify-between gap-2"><h2 className="font-semibold">{ko ? '연동 방식 추가·관리' : 'Add / manage methods'}</h2><Button type="button" disabled={busy} onClick={onClose}>{ko ? '닫기' : 'Close'}</Button></div>
    <p className="mt-2 text-xs text-muted-foreground">{ko ? '여러 앱에서 재사용할 기본값과 안내를 정의합니다. 범용 계약을 제공하며 앱 API나 스크립트를 실행하지 않습니다.' : 'Define reusable defaults and guidance. Custom methods export generic contracts and do not execute app APIs or scripts.'}</p>
    <form onSubmit={save} className="mt-4 space-y-4">
      <label className="grid gap-1 text-sm">{ko ? '수정할 방식' : 'Method to edit'}<select value={revision ? draft.id : ''} disabled={busy} onChange={(e) => edit(e.target.value)} className="rounded-console border border-border bg-surface p-2"><option value="">{ko ? '새 방식' : 'New method'}</option>{methods.map((m) => <option key={m.id} value={m.id}>{m.name}</option>)}</select></label>
      <div className="grid gap-3 sm:grid-cols-2">{field('id', ko ? '방식 ID (custom- 접두사)' : 'Method ID (custom- prefix)')}{field('name', ko ? '방식 이름' : 'Method name')}{field('summary', ko ? '연동 방식 설명' : 'Method summary')}{field('scope_note', ko ? '권한 범위와 주의점' : 'Permission scope and limits')}{field('documentation_url', ko ? '설정 문서 URL (HTTPS)' : 'Documentation URL (HTTPS)')}{field('claim_path', ko ? '기본 claim 경로' : 'Default claim path')}</div>
      <div className="grid gap-3 sm:grid-cols-2"><label className="grid gap-1 text-sm">{ko ? '기본 토큰 출처' : 'Default token source'}<select value={draft.token_source} onChange={(e) => setDraft({ ...draft, token_source: e.target.value as IntegrationMethod['token_source'] })} className="rounded-console border border-border bg-surface p-2"><option value="id_token">ID token</option><option value="access_token">Access token</option><option value="userinfo">Userinfo</option></select></label>
        <label className="grid gap-1 text-sm">{ko ? '기본 검사 위치' : 'Default enforcement'}<select value={draft.enforcement} onChange={(e) => { setDraft({ ...draft, enforcement: e.target.value as IntegrationMethod['enforcement'] }); if (e.target.value === 'gateway_admission') setRoles('') }} className="rounded-console border border-border bg-surface p-2"><option value="native_app">Native application</option><option value="gateway_admission">Gateway admission</option></select></label></div>
      <div className="grid gap-3 sm:grid-cols-2"><label className="grid gap-1 text-sm">{ko ? '앱 역할 목록 (한 줄에 하나, 선택)' : 'Native roles (one per line, optional)'}<textarea rows={3} value={roles} disabled={busy || draft.enforcement === 'gateway_admission'} onChange={(e) => setRoles(e.target.value)} className="rounded-console border border-border bg-surface p-2" /></label><label className="grid gap-1 text-sm">{ko ? '설정 단계 (한 줄에 하나)' : 'Setup steps (one per line)'}<textarea required rows={3} value={steps} disabled={busy} onChange={(e) => setSteps(e.target.value)} className="rounded-console border border-border bg-surface p-2" /></label></div>
      {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
      <Button type="submit" disabled={busy}>{ko ? '연동 방식 저장' : 'Save method'}</Button>
      <p className="text-xs text-muted-foreground">{ko ? '방식을 수정해도 기존 앱 프로파일은 자동 변경되지 않습니다. 앱에서 다시 선택하고 저장해 적용하세요.' : 'Editing a method does not change existing app profiles. Select it again and save the app to apply new defaults.'}</p>
    </form>
  </section>
}
