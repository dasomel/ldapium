import { useState } from 'react'
import { ChevronRight } from 'lucide-react'
import { useT } from '@/context/LanguageContext'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeadCell, TableRow } from '@/components/ui/table'
import { CodeBlock } from '@/components/api-docs/CopyButton'
import {
  buildCurl, endpointParams, jsonBody, resolveSchema, schemaTypeLabel,
  type Endpoint, type OpenApiDoc, type Schema,
} from '@/lib/api-docs'
import { cn } from '@/lib/utils'

const methodClass: Record<string, string> = {
  get: 'border-accent/30 bg-accent-muted text-accent',
  post: 'border-success/30 bg-success/10 text-success',
  put: 'border-border-strong bg-muted text-foreground',
  patch: 'border-border-strong bg-muted text-foreground',
  delete: 'border-danger/30 bg-danger/10 text-danger',
}

function SchemaRows({ doc, schema, prefix = '', depth = 0, seen = [] }: { doc: OpenApiDoc; schema: Schema; prefix?: string; depth?: number; seen?: string[] }) {
  const t = useT()
  const s = resolveSchema(doc, schema)
  const target = s.type === 'array' && s.items ? resolveSchema(doc, s.items) : s
  const props = Object.entries(target.properties ?? {})
  return <>
    {props.map(([name, raw]) => {
      const child = resolveSchema(doc, raw)
      // seen is the $ref cycle guard: a schema already on this path is listed but not expanded again.
      const refs = [raw.$ref, raw.items?.$ref].filter((r): r is string => !!r)
      const nested = depth < 3 && !refs.some((r) => seen.includes(r)) && (child.properties || (child.type === 'array' && child.items))
      return <SchemaRow key={prefix + name} name={prefix + name} child={child} required={target.required?.includes(name)}>
        {nested && <SchemaRows doc={doc} schema={raw} prefix={`${prefix}${name}.`} depth={depth + 1} seen={[...seen, ...refs]} />}
      </SchemaRow>
    })}
    {props.length === 0 && depth === 0 && <TableRow><TableCell colSpan={4} className="text-muted-foreground">{schemaTypeLabel(s)}</TableCell></TableRow>}
  </>
  function SchemaRow({ name, child, required, children }: { name: string; child: Schema; required?: boolean; children: React.ReactNode }) {
    return <>
      <TableRow>
        <TableCell className="font-mono text-[12px]">{name}</TableCell>
        <TableCell className="font-mono text-[12px]">{schemaTypeLabel(child)}</TableCell>
        <TableCell>{required ? t('apiDocs.yes') : ''}</TableCell>
        <TableCell className="text-muted-foreground">{child.description}</TableCell>
      </TableRow>
      {children}
    </>
  }
}

export function EndpointCard({ doc, endpoint: e, open, onToggle }: { doc: OpenApiDoc; endpoint: Endpoint; open: boolean; onToggle: () => void }) {
  const t = useT()
  const [origin] = useState(() => window.location.origin)
  const panelId = `ep-${e.method}-${e.path.replace(/[^a-z0-9]+/gi, '-')}`
  const params = open ? endpointParams(doc, e.op, doc.paths?.[e.path]) : []
  const body = open ? jsonBody(doc, e.op) : undefined
  const authKey = e.auth === 'public' ? 'apiDocs.authPublic' : e.auth === 'admin' ? 'apiDocs.authAdmin' : 'apiDocs.authSession'
  return (
    <div className="rounded-console border border-border bg-surface">
      <button type="button" aria-expanded={open} aria-controls={panelId} onClick={onToggle}
        className="flex w-full items-center gap-2 px-3 py-2.5 text-left hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
        <ChevronRight aria-hidden="true" className={cn('size-4 shrink-0 text-muted-foreground transition-transform', open && 'rotate-90')} />
        <span className={cn('w-16 shrink-0 rounded-full border px-2 py-0.5 text-center font-mono text-[11px] font-semibold uppercase', methodClass[e.method])}>{e.method}</span>
        <span className="min-w-0 break-all font-mono text-[12.5px]">{e.path}</span>
        <span className="hidden min-w-0 flex-1 truncate text-[12.5px] text-muted-foreground md:inline">{e.op.summary}</span>
        {e.machineScope && <Badge variant="accent" className="ml-auto shrink-0 font-mono" title={t('apiDocs.machineHint')}>{t('apiDocs.machine')}: {e.machineScope}</Badge>}
        <Badge variant={e.auth === 'public' ? 'success' : e.auth === 'admin' ? 'danger' : 'neutral'} className={cn('shrink-0', !e.machineScope && 'ml-auto')}>{t(authKey)}</Badge>
      </button>
      {open && (
        <div id={panelId} className="space-y-4 border-t border-border p-4">
          {e.op.summary && <p className="text-sm font-medium md:hidden">{e.op.summary}</p>}
          {e.op.description && <p className="whitespace-pre-line text-[13px] text-muted-foreground">{e.op.description}</p>}
          {params.length > 0 && (
            <section aria-label={t('apiDocs.parameters')} className="space-y-2">
              <h3 className="text-[13px] font-semibold">{t('apiDocs.parameters')}</h3>
              <div className="overflow-x-auto"><Table>
                <TableHead><TableRow><TableHeadCell>{t('apiDocs.colName')}</TableHeadCell><TableHeadCell>{t('apiDocs.colIn')}</TableHeadCell><TableHeadCell>{t('apiDocs.colType')}</TableHeadCell><TableHeadCell>{t('apiDocs.colRequired')}</TableHeadCell><TableHeadCell>{t('apiDocs.colDescription')}</TableHeadCell></TableRow></TableHead>
                <TableBody>{params.map((p) => (
                  <TableRow key={`${p.in}:${p.name}`}>
                    <TableCell className="font-mono text-[12px]">{p.name}</TableCell>
                    <TableCell>{p.in}</TableCell>
                    <TableCell className="font-mono text-[12px]">{schemaTypeLabel(resolveSchema(doc, p.schema))}</TableCell>
                    <TableCell>{p.required ? t('apiDocs.yes') : ''}</TableCell>
                    <TableCell className="text-muted-foreground">{p.description}</TableCell>
                  </TableRow>))}</TableBody>
              </Table></div>
            </section>
          )}
          {body && (
            <section aria-label={t('apiDocs.requestBody')} className="space-y-2">
              <h3 className="text-[13px] font-semibold">{t('apiDocs.requestBody')} <span className="font-mono text-[11px] font-normal text-muted-foreground">application/json</span></h3>
              <div className="overflow-x-auto"><Table>
                <TableHead><TableRow><TableHeadCell>{t('apiDocs.colName')}</TableHeadCell><TableHeadCell>{t('apiDocs.colType')}</TableHeadCell><TableHeadCell>{t('apiDocs.colRequired')}</TableHeadCell><TableHeadCell>{t('apiDocs.colDescription')}</TableHeadCell></TableRow></TableHead>
                <TableBody><SchemaRows doc={doc} schema={body.schema} seen={[e.op.requestBody?.content?.['application/json']?.schema?.$ref ?? '']} /></TableBody>
              </Table></div>
              <CodeBlock code={JSON.stringify(body.example, null, 2)} label={t('apiDocs.example')} />
            </section>
          )}
          {e.op.responses && (
            <section aria-label={t('apiDocs.responses')} className="space-y-2">
              <h3 className="text-[13px] font-semibold">{t('apiDocs.responses')}</h3>
              <div className="overflow-x-auto"><Table>
                <TableHead><TableRow><TableHeadCell>{t('apiDocs.colStatus')}</TableHeadCell><TableHeadCell>{t('apiDocs.colDescription')}</TableHeadCell><TableHeadCell>{t('apiDocs.colType')}</TableHeadCell></TableRow></TableHead>
                <TableBody>{Object.entries(e.op.responses).map(([code, r]) => {
                  const schema = r.content?.['application/json']?.schema
                  return (
                    <TableRow key={code}>
                      <TableCell className="font-mono text-[12px]">{code}</TableCell>
                      <TableCell className="text-muted-foreground">{r.description}</TableCell>
                      <TableCell className="font-mono text-[12px]">{schema ? schemaTypeLabel(schema.$ref ? { type: schema.$ref.split('/').pop() } : resolveSchema(doc, schema)) : ''}</TableCell>
                    </TableRow>)
                })}</TableBody>
              </Table></div>
            </section>
          )}
          <CodeBlock code={buildCurl(doc, e, origin)} label={t('apiDocs.curl')} />
        </div>
      )}
    </div>
  )
}
