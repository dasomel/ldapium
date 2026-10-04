import { useEffect, useMemo, useState } from 'react'
import { BookOpen, FileJson, FileText, Search } from 'lucide-react'
import { useT } from '@/context/LanguageContext'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { EmptyState, ErrorState, Spinner } from '@/components/ui/empty-state'
import { Input } from '@/components/ui/input'
import { CodeBlock } from '@/components/api-docs/CopyButton'
import { EndpointCard } from '@/components/api-docs/EndpointCard'
import {
  buildLoginCurl, collectEndpoints, fetchOpenApi, filterEndpoints, groupByTag, METHODS,
  type Method, type OpenApiDoc,
} from '@/lib/api-docs'
import { cn } from '@/lib/utils'

export function ApiDocsPage() {
  const t = useT()
  const [doc, setDoc] = useState<OpenApiDoc | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [attempt, setAttempt] = useState(0)
  const [query, setQuery] = useState('')
  const [methods, setMethods] = useState<ReadonlySet<Method>>(new Set())
  const [descOpen, setDescOpen] = useState(false)
  const [openIds, setOpenIds] = useState<ReadonlySet<string>>(new Set())

  useEffect(() => {
    const ctl = new AbortController()
    setError(null)
    setDoc(null)
    fetchOpenApi(ctl.signal).then(setDoc).catch((err: Error) => { if (err.name !== 'AbortError') setError(err.message) })
    return () => ctl.abort()
  }, [attempt])

  const endpoints = useMemo(() => (doc ? collectEndpoints(doc) : []), [doc])
  const groups = useMemo(() => (doc ? groupByTag(doc, filterEndpoints(endpoints, query, methods)) : []), [doc, endpoints, query, methods])
  const origin = window.location.origin

  function toggleMethod(m: Method) {
    const next = new Set(methods)
    if (!next.delete(m)) next.add(m)
    setMethods(next)
  }
  function toggleOpen(id: string) {
    const next = new Set(openIds)
    if (!next.delete(id)) next.add(id)
    setOpenIds(next)
  }

  if (error) {
    return <div className="mx-auto max-w-4xl"><Card>
      <EmptyState icon={BookOpen} title={t('apiDocs.unavailableTitle')} description={t('apiDocs.unavailableHint')} action={<ErrorState message={error} onRetry={() => setAttempt((n) => n + 1)} />} />
    </Card></div>
  }
  if (!doc) return <div className="flex justify-center py-20"><Spinner /></div>

  return (
    <div className="mx-auto max-w-4xl space-y-4">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 space-y-1">
          <h1 className="text-lg font-semibold tracking-tight">{doc.info?.title ?? t('apiDocs.title')}</h1>
          <p className={cn('text-[13px] text-muted-foreground', descOpen ? 'whitespace-pre-line' : 'line-clamp-3')}>{doc.info?.description ?? t('apiDocs.subtitle')}</p>
          {doc.info?.description && <button type="button" aria-expanded={descOpen} onClick={() => setDescOpen((v) => !v)} className="text-[12.5px] font-medium text-accent hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">{descOpen ? t('apiDocs.showLess') : t('apiDocs.showMore')}</button>}
          <div className="flex flex-wrap items-center gap-2 pt-1">
            {doc.info?.version && <Badge>{t('apiDocs.version')} {doc.info.version}</Badge>}
            {doc.openapi && <Badge>OpenAPI {doc.openapi}</Badge>}
            {doc.servers?.[0] && <Badge>{t('apiDocs.servers')} {doc.servers[0].url}</Badge>}
          </div>
        </div>
        <div className="flex gap-2">
          <a className={cn('inline-flex h-9 items-center gap-2 rounded-console border border-border-strong px-3.5 text-[13px] font-medium hover:bg-muted')} href="/api/v1/openapi.json" target="_blank" rel="noreferrer"><FileJson aria-hidden="true" className="size-4" />{t('apiDocs.rawSpec')}</a>
          <a className={cn('inline-flex h-9 items-center gap-2 rounded-console border border-border-strong px-3.5 text-[13px] font-medium hover:bg-muted')} href="/llms.txt" target="_blank" rel="noreferrer"><FileText aria-hidden="true" className="size-4" />{t('apiDocs.llmsTxt')}</a>
        </div>
      </header>

      <Card>
        <CardHeader><CardTitle>{t('apiDocs.authTitle')}</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          <p className="text-[13px] text-muted-foreground">{t('apiDocs.authBody')}</p>
          <p className="text-[13px]"><span className="text-muted-foreground">{t('apiDocs.baseUrl')}: </span><code className="font-mono text-[12.5px]">{origin}</code></p>
          <CodeBlock code={buildLoginCurl(origin)} label={t('apiDocs.loginExample')} />
        </CardContent>
      </Card>

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-[14rem] flex-1">
          <Search aria-hidden="true" className="pointer-events-none absolute left-2.5 top-2.5 size-4 text-muted-foreground" />
          <Input type="search" aria-label={t('apiDocs.search')} placeholder={t('apiDocs.searchPlaceholder')} value={query} onChange={(ev) => setQuery(ev.target.value)} className="pl-8" />
        </div>
        <div role="group" aria-label={t('apiDocs.methodFilter')} className="flex flex-wrap gap-1">
          {METHODS.map((m) => (
            <Button key={m} type="button" size="sm" variant={methods.has(m) ? 'default' : 'outline'} aria-pressed={methods.has(m)} onClick={() => toggleMethod(m)} className="font-mono uppercase">{m}</Button>
          ))}
        </div>
      </div>

      {groups.length === 0 && <Card><EmptyState icon={Search} title={t('apiDocs.noMatches')} /></Card>}
      {groups.map((g) => (
        <section key={g.tag} aria-labelledby={`tag-${g.tag}`} className="space-y-2">
          <div>
            <h2 id={`tag-${g.tag}`} className="text-sm font-semibold capitalize">{g.tag} <span className="font-normal normal-case text-muted-foreground">· {g.endpoints.length} {t(g.endpoints.length === 1 ? 'apiDocs.endpointCountOne' : 'apiDocs.endpointCount')}</span></h2>
            {g.description && <p className="text-[12.5px] text-muted-foreground">{g.description}</p>}
          </div>
          <div className="space-y-1.5">
            {g.endpoints.map((e) => <EndpointCard key={e.id} doc={doc} endpoint={e} open={openIds.has(e.id)} onToggle={() => toggleOpen(e.id)} />)}
          </div>
        </section>
      ))}
    </div>
  )
}
