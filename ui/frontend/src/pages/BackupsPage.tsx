import { useEffect, useState } from 'react'
import { BackupConnections } from '@/components/backups/BackupConnections'
import { Archive, Play, Save } from 'lucide-react'
import { backups, type BackupPolicies, type BackupPolicy, type BackupView } from '@/lib/backups'
import { useLanguage } from '@/context/LanguageContext'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { ErrorState, Spinner } from '@/components/ui/empty-state'

export function BackupsPage() {
  const { language } = useLanguage()
  const text = (ko: string, en: string) => language === 'ko' ? ko : en
  const [view, setView] = useState<BackupView | null>(null)
  const [draft, setDraft] = useState<BackupPolicies | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const dirty = !!draft && !!view && JSON.stringify(draft) !== JSON.stringify(view.policies)
  async function load(reset = false) {
    try { const result = await backups.get(); setView(result); setDraft(previous => reset || !previous ? result.policies : previous); setError('') }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Backup request failed') }
  }
  useEffect(() => { void load(); const timer = setInterval(() => { void load() }, 5000); return () => clearInterval(timer) }, [])
  function change(kind: 'data' | 'logs', patch: Partial<BackupPolicy>) {
    setDraft(previous => previous ? { ...previous, [kind]: { ...previous[kind], ...patch } } : previous)
    setMessage('')
  }
  async function save() {
    if (!draft) return
    setBusy(true); setError(''); setMessage('')
    try { const saved = await backups.save(draft); setDraft(saved); await load(); setMessage(text('백업 정책을 저장했습니다.', 'Backup policies saved.')) }
    catch (cause) { setError((cause as Error).message) }
    finally { setBusy(false) }
  }
  async function run(kind: 'data' | 'logs') {
    setBusy(true); setError(''); setMessage('')
    try { await backups.run(kind); await load(); setMessage(text('백업을 시작했습니다. 결과는 아래에 표시됩니다.', 'Backup started. Check the result below.')) }
    catch (cause) { setError((cause as Error).message) }
    finally { setBusy(false) }
  }
  function bytes(value?: number) { if (value === undefined) return '—'; if (value < 1024) return `${value} B`; const units = ['KiB', 'MiB', 'GiB', 'TiB']; let scaled = value / 1024; let unit = 0; while (scaled >= 1024 && unit < units.length - 1) { scaled /= 1024; unit++ } return `${scaled.toFixed(1)} ${units[unit]}` }
  function date(value?: string) { return !value || value.startsWith('0001-') ? '—' : new Date(value).toLocaleString(language === 'ko' ? 'ko-KR' : 'en-US') }
  const statusNames: Record<string, string> = { running: text('실행 중', 'Running'), succeeded: text('검증 완료', 'Verified'), failed: text('실패 — 연결·원본·운영자 설정 확인', 'Failed — check sources, connection and operator configuration'), interrupted: text('중단됨', 'Interrupted') }
  return <div className="max-w-6xl space-y-4">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div><h1 className="text-xl font-semibold">{text('백업 관리', 'Backup management')}</h1>
        <p className="mt-1 text-sm text-muted-foreground">{text('데이터와 로그의 실행 주기, 저장소, 보관 정책을 각각 관리합니다.', 'Manage independent schedules, destinations and retention for data and logs.')}</p></div>
      <Button disabled={!dirty || busy || view?.running} onClick={save}><Save />{text('정책 저장', 'Save policies')}</Button>
    </div>
    {error && <ErrorState message={error} onRetry={() => void load(true)} />}
    {message && <p role="status" className="text-sm">{message}</p>}
    {!view && !error && <Spinner />}
    {!view && error && <p className="text-sm text-muted-foreground">{text('백업 기능 활성화와 백업 관리자 권한을 확인하세요.', 'Check whether backups are enabled and your account is a backup administrator.')}</p>}
    {view && draft && <>
      <div className="rounded-console border border-border bg-surface p-4 text-sm text-muted-foreground">
        {text('자체 로컬 사본은 항상 보관하며, 선택한 외부 저장소로 검증 후 전송합니다. 등록된 인스턴스의 완료된 사본에만 보관 정책을 적용합니다. 원본 로그 파일은 삭제하거나 회전하지 않습니다.', 'A local copy is always retained. Selected remote copies are verified before completion. Retention applies only to completed copies owned by this instance. Live log files are never deleted or rotated.')}
        {dirty && <p className="mt-2 text-accent">{text('변경한 정책을 저장한 뒤 실행하세요.', 'Save changed policies before running a backup.')}</p>}
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        {(['data', 'logs'] as const).map(kind => {
          const policy = draft[kind]; const state = view.states[kind]
          const available = kind === 'data' || view.logs_available
          return <Card key={kind}>
            <CardHeader><CardTitle className="flex items-center gap-2"><Archive />{kind === 'data' ? text('데이터 백업', 'Data backup') : text('로그 백업', 'Log backup')}</CardTitle></CardHeader>
            <CardContent className="space-y-4">
              <p className="text-sm text-muted-foreground">{kind === 'data' ? text('LDAP 데이터·설정과 운영자가 등록한 자체 설정 파일을 압축합니다.', 'Archive LDAP data/configuration and registered application metadata.') : text('운영자가 등록한 로그 파일만 별도로 압축합니다.', 'Archive only the log files registered by the operator.')}</p>
              {!available && <p className="text-sm text-accent">{text('운영자 로그 원본 등록이 필요합니다.', 'The operator must register log sources first.')}</p>}
              <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={policy.enabled} disabled={!available || busy || view.running} onChange={event => change(kind, { enabled: event.target.checked })} />{text('예약 실행', 'Scheduled backups')}</label>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                {([{ key: 'interval_minutes', ko: '주기 (분)', en: 'Interval (minutes)', max: 525600 }, { key: 'keep_days', ko: '보관 (일)', en: 'Retention (days)', max: 3650 }, { key: 'keep_count', ko: '최대 사본', en: 'Copy limit', max: 10000 }] as const).map(field =>
                  <label key={field.key} className="space-y-1 text-xs text-muted-foreground">{text(field.ko, field.en)}<Input type="number" min={1} max={field.max} value={policy[field.key]} disabled={busy || view.running} onChange={event => change(kind, { [field.key]: Number(event.target.value) })} /></label>)}
              </div>
              <fieldset className="space-y-2"><legend className="mb-2 text-sm font-medium">{text('저장소', 'Destinations')}</legend>
                {view.destinations.map(target => <label key={target.id} className="flex items-center gap-2 text-sm"><input type="checkbox" checked={policy.destinations.includes(target.id)} disabled={target.type === 'local' || busy || view.running} onChange={event => change(kind, { destinations: event.target.checked ? [...policy.destinations, target.id] : policy.destinations.filter(id => id !== target.id) })} />{target.name} <span className="text-xs text-muted-foreground">{target.type === 'sftp' ? 'SSH / SFTP' : target.type.toUpperCase()}</span></label>)}
              </fieldset>
              <div className="grid grid-cols-2 gap-3 rounded-console bg-surface p-3 text-sm">
                <div><p className="text-xs text-muted-foreground">{text('최근 보관 사본 용량', 'Latest retained copy size')}</p><strong>{bytes(view.storage?.[kind]?.latest_bytes)}</strong></div>
                <div><p className="text-xs text-muted-foreground">{text('로컬 보관 총용량', 'Local retained size')}</p><strong>{bytes(view.storage?.[kind]?.bytes)}</strong><span className="ml-2 text-xs">{view.storage?.[kind]?.copies ?? 0} {text('개', 'copies')}</span></div>
              </div>
              <dl className="space-y-1 text-xs text-muted-foreground">
                <div>{text('상태', 'Status')}: <span role="status">{state?.status === 'failed' && state.local_verified ? text('로컬 검증 완료 · 외부 전송/보관 정리 실패', 'Local copy verified · remote delivery/retention failed') : statusNames[state?.status] ?? text('실행 기록 없음', 'Not run yet')}</span></div>
                <div>{text('마지막 성공', 'Last success')}: {date(state?.last_success)}</div>
                <div>{text('다음 예약', 'Next scheduled run')}: {policy.enabled ? date(state?.next_run) : text('비활성', 'Disabled')}</div>
                {state?.run_id && <div className="break-all">{text('마지막 검증 사본', 'Last verified copy')}: {state.run_id}</div>}
              </dl>
              <Button variant="outline" disabled={busy || view.running || dirty || !available} onClick={() => void run(kind)}><Play />{text('지금 백업', 'Back up now')}</Button>
            </CardContent>
          </Card>
        })}
      </div>
      <BackupConnections view={view} locked={dirty || busy} onSaved={result => { setView(result); setDraft(result.policies) }} />
    </>}
  </div>
}
