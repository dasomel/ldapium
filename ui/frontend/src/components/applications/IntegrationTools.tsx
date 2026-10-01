import { useState } from 'react'
import { useLanguage } from '@/context/LanguageContext'
import { integration } from '@/lib/app-profiles'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'

export function IntegrationTools({ applicationID }: { applicationID: string }) {
  const { language } = useLanguage()
  const ko = language === 'ko'
  const [adapter, setAdapter] = useState('generic')
  const [values, setValues] = useState('')
  const [output, setOutput] = useState('')
  const [warnings, setWarnings] = useState<string[]>([])
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  async function run(kind: 'export' | 'preview' | 'observe') {
    setBusy(true); setError(''); setOutput(''); setWarnings([])
    try {
      if (kind === 'export') {
        const artifact = await integration.export(applicationID, adapter)
        setOutput(artifact.content); setWarnings(artifact.warnings)
        const blob = new Blob([artifact.content], { type: 'application/json' })
        const url = URL.createObjectURL(blob)
        const link = document.createElement('a'); link.href = url; link.download = artifact.filename; link.click()
        setTimeout(() => URL.revokeObjectURL(url), 1000)
      } else if (kind === 'observe') {
        setOutput(JSON.stringify(await integration.verify(applicationID), null, 2))
      } else {
        const result = await integration.preview(applicationID, values.split(';').map((v) => v.trim()).filter(Boolean))
        setOutput(JSON.stringify(result, null, 2))
      }
    } catch (err) { setError(err instanceof Error ? err.message : String(err)) }
    finally { setBusy(false) }
  }
  return <section className="space-y-3 rounded border border-border p-4">
    <h2 className="font-semibold">{ko ? '권한 매핑 미리보기·설정 내보내기' : 'Mapping preview and configuration export'}</h2>
    <p className="text-sm text-muted-foreground">{ko ? '미리보기는 인증이나 실제 앱 권한 검증이 아닙니다. 내보낸 설정은 앱 운영자가 적용해야 합니다.' : 'Preview is not authentication or verified application access. The application owner must apply exported settings.'}</p>
    <label className="grid gap-1 text-sm">{ko ? 'claim 값 (세미콜론 구분)' : 'Claim values (semicolon separated)'}<Input value={values} onChange={(e) => setValues(e.target.value)} /></label>
    <Button type="button" disabled={busy} onClick={() => run('preview')}>{ko ? '매핑 미리보기' : 'Preview mapping'}</Button>
    <select aria-label={ko ? '설정 형식' : 'Configuration format'} value={adapter} onChange={(e) => setAdapter(e.target.value)} className="rounded border border-border bg-surface p-2">
      <option value="generic">Generic OIDC contract</option><option value="grafana">Grafana</option><option value="argocd">Argo CD</option>
    </select>
    <Button type="button" disabled={busy} onClick={() => run('export')}>{ko ? '설정 내보내기' : 'Export configuration'}</Button>
    <Button type="button" disabled={busy} onClick={() => run('observe')}>{ko ? 'Keycloak 설정 확인' : 'Check Keycloak configuration'}</Button>
    {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
    {warnings.map((w) => <p key={w} className="text-sm text-muted-foreground">{w}</p>)}
    {output && <pre className="max-h-80 overflow-auto rounded bg-muted p-3 text-xs">{output}</pre>}
  </section>
}
