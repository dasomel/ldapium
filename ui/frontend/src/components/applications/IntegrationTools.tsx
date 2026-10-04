import { useState } from 'react'
import { Download, CheckCircle2, Circle } from 'lucide-react'
import { useLanguage } from '@/context/LanguageContext'
import { integration } from '@/lib/app-profiles'
import type { IntegrationGuide } from '@/lib/oss-integration-guides'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'

type Artifact = Awaited<ReturnType<typeof integration.export>>
export function IntegrationTools({ applicationID, guide }: { applicationID: string; guide: IntegrationGuide }) {
  const { language } = useLanguage()
  const ko = language === 'ko'
  const [adapter, setAdapter] = useState(guide.kind === 'export' ? guide.id : 'generic')
  const [values, setValues] = useState('')
  const [artifact, setArtifact] = useState<Artifact>()
  const [preview, setPreview] = useState<Awaited<ReturnType<typeof integration.preview>>>()
  const [observed, setObserved] = useState<Record<string, unknown>>()
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  async function run(kind: 'export' | 'preview' | 'observe') {
    setBusy(true); setError('')
    try {
      if (kind === 'export') { setArtifact(undefined); setArtifact(await integration.export(applicationID, adapter)) }
      else if (kind === 'observe') { setObserved(undefined); setObserved(await integration.verify(applicationID)) }
      else { setPreview(undefined); setPreview(await integration.preview(applicationID, values.split(';').map((v) => v.trim()).filter(Boolean))) }
    } catch (err) { setError(err instanceof Error ? err.message : String(err)) }
    finally { setBusy(false) }
  }
  function download() {
    if (!artifact) return
    const url = URL.createObjectURL(new Blob([artifact.content], { type: 'application/json' }))
    const link = document.createElement('a'); link.href = url; link.download = artifact.filename; link.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }
  return <section className="space-y-6">
    <div><h2 className="font-semibold">{ko ? '설정 내보내기와 적용 확인' : 'Configuration export and verification'}</h2><p className="mt-1 text-sm text-muted-foreground">{ko ? '설정을 준비한 뒤 앱 운영자가 적용합니다. Keycloak 조회와 실제 앱 접근 검증을 구분하세요.' : 'Prepare configuration for the app owner. Keycloak observation and real application access are separate checks.'}</p></div>
    <div className="grid gap-3 sm:grid-cols-3 text-xs">{[
      [true, ko ? '프로파일 저장됨' : 'Profile saved'],
      [Boolean(observed), ko ? 'Keycloak 카탈로그 조회' : 'Keycloak catalog observed'],
      [false, ko ? '실제 앱 접근 미확인' : 'Application access unverified'],
    ].map(([done, text]) => <div key={String(text)} className="flex items-center gap-2 rounded-console border border-border p-3">{done ? <CheckCircle2 className="size-4 text-accent" /> : <Circle className="size-4 text-muted-foreground" />}{text}</div>)}</div>
    {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
    <section className="space-y-3 rounded-console border border-border p-4">
      <h3 className="text-sm font-semibold">{ko ? '매핑 결과 미리보기' : 'Mapping preview'}</h3>
      <label className="grid gap-1 text-sm">{ko ? 'claim 값 (세미콜론 구분)' : 'Claim values (semicolon separated)'}<Input value={values} onChange={(e) => { setValues(e.target.value); setPreview(undefined) }} placeholder="/engineering; /platform" /></label>
      <Button type="button" disabled={busy || !values.trim()} onClick={() => run('preview')}>{ko ? '매핑 미리보기' : 'Preview mapping'}</Button>
      {preview && <div className="grid gap-3 sm:grid-cols-2 text-sm"><div><p className="mb-2 text-xs text-muted-foreground">{ko ? '매핑된 앱 역할' : 'Mapped application roles'}</p>{preview.native_roles.length ? preview.native_roles.map((r, n) => <span key={`${r}-${n}`} className="mr-1 inline-block rounded bg-accent/10 px-2 py-1 text-xs">{r}</span>) : '—'}</div><div><p className="mb-2 text-xs text-muted-foreground">{ko ? '미매핑 값' : 'Unmapped values'}</p><span>{preview.unmapped_values.join(', ') || '—'}</span></div></div>}
      <p className="text-xs text-muted-foreground">{ko ? '입력한 값의 계산 결과입니다. 인증이나 실제 앱 접근을 검증하지 않습니다.' : 'Calculated from the supplied values. This does not verify authentication or application access.'}</p>
    </section>
    <section className="space-y-3 rounded-console border border-border p-4">
      <h3 className="text-sm font-semibold">{ko ? '앱에 적용할 설정' : 'Configuration to apply'}</h3>
      {guide.kind !== 'export' && <p className="text-sm text-muted-foreground">{ko ? `${guide.name}는 범용 계약과 설정 안내를 제공합니다. 앱 자체 권한은 공식 문서에 따라 설정하세요.` : `${guide.name} provides a generic contract and setup guidance. Configure native permissions using the official docs.`}</p>}
      <div className="flex flex-wrap gap-2"><select aria-label={ko ? '설정 형식' : 'Configuration format'} value={adapter} onChange={(e) => { setAdapter(e.target.value); setArtifact(undefined) }} className="rounded-console border border-border bg-surface p-2 text-sm"><option value="generic">Generic OIDC contract</option>{guide.kind === 'export' && <option value={guide.id}>{guide.name}</option>}</select>
        <Button type="button" disabled={busy} onClick={() => run('export')}>{ko ? '설정 내보내기' : 'Export configuration'}</Button>
        {artifact && <Button type="button" onClick={download}><Download className="mr-1 size-3" />{ko ? '파일 다운로드' : 'Download file'}</Button>}</div>
      {artifact && <><p className="font-mono text-xs">{artifact.filename}</p>{artifact.warnings.map((w) => <p key={w} className="text-xs leading-relaxed text-muted-foreground">{w}</p>)}<details><summary className="cursor-pointer text-sm">{ko ? '생성된 설정 보기' : 'View generated configuration'}</summary><pre className="mt-2 max-h-80 overflow-auto rounded-console bg-muted p-3 text-xs">{artifact.content}</pre></details></>}
    </section>
    <section className="space-y-3 border-t border-border pt-4"><h3 className="text-sm font-semibold">{ko ? 'Keycloak 관측과 앱 검증' : 'Keycloak observation and app validation'}</h3>
      <Button type="button" disabled={busy} onClick={() => run('observe')}>{ko ? 'Keycloak 설정 확인' : 'Check Keycloak configuration'}</Button>
      {observed && <p role="status" className="text-sm">{ko ? 'Keycloak 역할 목록을 조회했습니다.' : 'Keycloak role catalog observed.'}{Array.isArray(observed.missing_keycloak_roles) && observed.missing_keycloak_roles.length > 0 && ` ${ko ? '없는 역할' : 'Missing roles'}: ${observed.missing_keycloak_roles.join(', ')}`}</p>}
      <ul className="list-disc space-y-1 pl-4 text-xs leading-relaxed text-muted-foreground"><li>{ko ? '새 토큰에 필요한 claim이 전달되는지 확인' : 'Verify required claims arrive in a fresh token'}</li><li>{ko ? '허용 사용자의 read·write와 미허용 사용자의 거부 확인' : 'Test allowed read/write and denial for unauthorized users'}</li><li>{ko ? '프로젝트·namespace·경로 경계와 권한 회수 후 기존 세션 확인' : 'Test project/namespace/path boundaries and existing sessions after revocation'}</li></ul>
    </section>
  </section>
}
