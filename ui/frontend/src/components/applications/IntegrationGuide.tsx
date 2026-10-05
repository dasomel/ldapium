import { ArrowRight, BookOpen, Boxes, ShieldCheck } from 'lucide-react'
import { useLanguage } from '@/context/LanguageContext'
import { integrationGuides, type IntegrationGuide as Guide } from '@/lib/oss-integration-guides'

export function IntegrationGuide({ guide, onSelect, disabled, custom = [], onManage }: { guide: Guide; onSelect: (id: string) => void; disabled: boolean; custom?: Guide[]; onManage: () => void }) {
  const { language } = useLanguage()
  const i = language === 'ko' ? 0 : 1
  return <section className="space-y-4">
    <div className="flex flex-wrap items-center justify-between gap-2"><div className="flex items-center gap-2"><Boxes className="size-4 text-accent" /><h2 className="font-semibold">{i === 0 ? '앱의 권한 연동 방식' : 'Application authorization model'}</h2></div><button type="button" disabled={disabled} onClick={onManage} className="text-sm text-accent underline">{i === 0 ? '연동 방식 추가·관리' : 'Add / manage methods'}</button></div>
    <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
      {[...integrationGuides, ...custom].map((g) => <button type="button" key={g.id} disabled={disabled} aria-pressed={guide.id === g.id} onClick={() => onSelect(g.id)}
        className={`rounded-console border p-3 text-left transition-colors ${guide.id === g.id ? 'border-accent bg-accent/10' : 'border-border bg-surface hover:bg-muted'}`}>
        <span className="flex items-center justify-between gap-2 text-sm font-semibold">{g.name}{guide.id === g.id && <ShieldCheck className="size-4 text-accent" />}</span>
        <span className="mt-1 block text-[11px] text-muted-foreground">{g.kind === 'export' ? (i === 0 ? '설정 내보내기 지원' : 'Configuration export') : g.kind === 'generic' ? (i === 0 ? '범용 OIDC 계약' : 'Generic OIDC contract') : g.kind === 'gateway' ? (i === 0 ? '진입 제어 안내' : 'Admission guide') : (g.custom ? (i === 0 ? '사용자 정의 방식' : 'Custom method') : (i === 0 ? '앱 자체 설정 안내' : 'Native setup guide'))}</span>
      </button>)}
    </div>
    <div className="rounded-console border border-border bg-muted/30 p-4">
      <div className="flex flex-wrap items-start justify-between gap-2"><div><h3 className="text-sm font-semibold">{guide.name}</h3><p className="mt-1 text-sm text-muted-foreground">{guide.summary[i]}</p></div>
        <a href={guide.docs} target="_blank" rel="noreferrer" className="flex items-center gap-1 text-xs text-accent underline"><BookOpen className="size-3" />{i === 0 ? '공식 연동 문서' : 'Official integration docs'}</a></div>
      <ol className="mt-4 grid gap-3 lg:grid-cols-3">{guide.steps.map((step, n) => <li key={n} className="flex gap-2 text-xs leading-relaxed"><span className="flex size-5 shrink-0 items-center justify-center rounded-full border border-border font-mono">{n + 1}</span>{step[i]}</li>)}</ol>
      <p className="mt-4 flex gap-2 border-t border-border pt-3 text-xs leading-relaxed text-muted-foreground"><ArrowRight className="mt-0.5 size-3 shrink-0" />{guide.scope[i]}</p>
    </div>
  </section>
}
