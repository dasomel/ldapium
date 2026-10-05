import { ArrowRight, Plus, Trash2 } from 'lucide-react'
import { useLanguage } from '@/context/LanguageContext'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import type { ApplicationProfile } from '@/lib/app-profiles'

export function MappingEditor({ value, onChange, roles, disabled }: { value: ApplicationProfile['mappings']; onChange: (v: ApplicationProfile['mappings']) => void; roles: string[]; disabled: boolean }) {
  const { language } = useLanguage()
  const ko = language === 'ko'
  function update(n: number, field: 'keycloak_role' | 'native_role', text: string) { onChange(value.map((r, i) => i === n ? { ...r, [field]: text } : r)) }
  return <section className="space-y-3">
    <div className="flex items-center justify-between gap-2"><div><h2 className="text-sm font-semibold">{ko ? 'claim → 앱 권한 매핑' : 'Claim → application permission mapping'}</h2><p className="mt-1 text-xs text-muted-foreground">{ko ? '토큰에 실리는 값을 정확히 입력하세요. 그룹 경로의 /도 값에 포함됩니다.' : 'Match the exact token value, including / in a group path.'}</p></div>
      <Button type="button" disabled={disabled} onClick={() => onChange([...value, { keycloak_role: '', native_role: '' }])}><Plus className="mr-1 size-3" />{ko ? '매핑 추가' : 'Add mapping'}</Button></div>
    {value.length === 0 && <p className="rounded-console border border-dashed border-border p-4 text-sm text-muted-foreground">{ko ? '아직 매핑이 없습니다. 앱에서 사용할 그룹이나 역할을 추가하세요.' : 'No mappings yet. Add a group or role the application will consume.'}</p>}
    {value.map((row, n) => <div key={n} className="grid grid-cols-[1fr_auto_1fr_auto] items-center gap-2">
      <Input aria-label={`${ko ? 'claim 값' : 'Claim value'} ${n + 1}`} placeholder="/engineering" value={row.keycloak_role} onChange={(e) => update(n, 'keycloak_role', e.target.value)} disabled={disabled} />
      <ArrowRight className="size-4 text-muted-foreground" />
      {roles.length > 0 ? <select aria-label={`${ko ? '앱 역할' : 'Application role'} ${n + 1}`} value={row.native_role} onChange={(e) => update(n, 'native_role', e.target.value)} disabled={disabled} className="min-w-0 rounded-console border border-border bg-surface p-2 text-sm"><option value="">{ko ? '역할 선택' : 'Choose role'}</option>{[...new Set([...roles, ...(row.native_role ? [row.native_role] : [])])].map((r) => <option key={r}>{r}</option>)}</select>
        : <Input aria-label={`${ko ? '앱 역할' : 'Application role'} ${n + 1}`} placeholder="reader" value={row.native_role} onChange={(e) => update(n, 'native_role', e.target.value)} disabled={disabled} />}
      <button type="button" aria-label={`${ko ? '매핑 삭제' : 'Remove mapping'} ${n + 1}`} disabled={disabled} onClick={() => onChange(value.filter((_, i) => i !== n))} className="rounded p-2 text-muted-foreground hover:bg-muted hover:text-destructive"><Trash2 className="size-4" /></button>
    </div>)}
  </section>
}
