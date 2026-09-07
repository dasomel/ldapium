import { useEffect, useState } from 'react'
import { History, RefreshCw, ShieldAlert } from 'lucide-react'
import { api, ApiError } from '@/lib/api'
import type { AuditEvent } from '@/lib/types'
import { useT } from '@/context/LanguageContext'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { EmptyState, ErrorState, Spinner } from '@/components/ui/empty-state'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeadCell, TableRow } from '@/components/ui/table'

function opBadgeVariant(op: string): 'neutral' | 'accent' | 'success' | 'danger' {
  switch (op) {
    case 'add':
      return 'success'
    case 'modify':
    case 'modrdn':
      return 'accent'
    case 'delete':
      return 'danger'
    default:
      return 'neutral'
  }
}

export function HistoryPage() {
  const t = useT()
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<ApiError | Error | null>(null)
  const [hasMore, setHasMore] = useState(false)
  const [nextBefore, setNextBefore] = useState<string | undefined>(undefined)
  const [historyStack, setHistoryStack] = useState<string[]>([])
  const [currentBefore, setCurrentBefore] = useState<string | undefined>(undefined)

  const [actorFilter, setActorFilter] = useState('')
  const [opFilter, setOpFilter] = useState('all')

  function load(before?: string) {
    setLoading(true)
    setError(null)
    api
      .auditActions(50, before)
      .then((res) => {
        setEvents(res.events || [])
        setHasMore(res.hasMore)
        setNextBefore(res.nextBefore)
        setCurrentBefore(before)
      })
      .catch(setError)
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    load()
  }, [])

  function handleNext() {
    if (nextBefore) {
      setHistoryStack((prev) => [...prev, currentBefore || ''])
      load(nextBefore)
    }
  }

  function handlePrev() {
    if (historyStack.length > 0) {
      const prevStack = [...historyStack]
      const prevBefore = prevStack.pop()
      setHistoryStack(prevStack)
      load(prevBefore === '' ? undefined : prevBefore)
    }
  }

  function handleRefresh() {
    setHistoryStack([])
    load()
  }

  const permissionDenied = error instanceof ApiError && error.status === 403

  const filteredEvents = events.filter((ev) => {
    if (actorFilter.trim()) {
      const q = actorFilter.trim().toLowerCase()
      if (!ev.actor.toLowerCase().includes(q)) return false
    }
    if (opFilter !== 'all') {
      if (ev.op.toLowerCase() !== opFilter.toLowerCase()) return false
    }
    return true
  })

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between pb-3">
          <div>
            <CardTitle className="flex items-center gap-2">
              <History className="size-4 text-accent" />
              {t('history.title')}
            </CardTitle>
            <p className="mt-1 text-[12.5px] text-muted-foreground">{t('history.subtitle')}</p>
          </div>
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={loading}>
            <RefreshCw className={`size-3.5 mr-1.5 ${loading ? 'animate-spin' : ''}`} />
            {t('history.refresh')}
          </Button>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap items-center gap-3">
            <div className="w-64">
              <Input
                placeholder={t('history.filterActor')}
                value={actorFilter}
                onChange={(e) => setActorFilter(e.target.value)}
                className="h-8 text-xs"
              />
            </div>
            <div className="w-40">
              <select
                value={opFilter}
                onChange={(e) => setOpFilter(e.target.value)}
                className="h-8 w-full rounded-console border border-border bg-surface px-2.5 text-xs text-foreground focus:border-accent focus:outline-none"
              >
                <option value="all">{t('history.allOps')}</option>
                <option value="add">add</option>
                <option value="modify">modify</option>
                <option value="delete">delete</option>
                <option value="modrdn">modrdn</option>
              </select>
            </div>
          </div>

          {loading && events.length === 0 && (
            <div className="flex items-center gap-2 py-8 text-[13px] text-muted-foreground">
              <Spinner /> {t('history.loading')}
            </div>
          )}

          {permissionDenied && (
            <EmptyState
              icon={ShieldAlert}
              title={t('history.permissionDeniedTitle')}
              description={t('history.permissionDeniedBody')}
            />
          )}

          {error && !permissionDenied && (
            <ErrorState
              message={error instanceof ApiError ? error.message : t('history.loadFailed')}
              onRetry={() => load(currentBefore)}
            />
          )}

          {!permissionDenied && !error && filteredEvents.length === 0 && !loading && (
            <EmptyState
              icon={History}
              title={t('history.noEvents')}
              description={t('history.noEventsDesc')}
            />
          )}

          {!permissionDenied && !error && filteredEvents.length > 0 && (
            <div className="space-y-3">
              <Table>
                <TableHead>
                  <TableRow>
                    <TableHeadCell>{t('history.colTime')}</TableHeadCell>
                    <TableHeadCell>{t('history.colOp')}</TableHeadCell>
                    <TableHeadCell>{t('history.colActor')}</TableHeadCell>
                    <TableHeadCell>{t('history.colTarget')}</TableHeadCell>
                    <TableHeadCell>{t('history.colAttrs')}</TableHeadCell>
                    <TableHeadCell>{t('history.colResult')}</TableHeadCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {filteredEvents.map((ev, idx) => (
                    <TableRow key={ev.correlationId || idx} data-testid="history-row">
                      <TableCell className="font-mono text-xs whitespace-nowrap">
                        {ev.time || ev.raw.reqStart || '—'}
                      </TableCell>
                      <TableCell>
                        <Badge variant={opBadgeVariant(ev.op)}>{ev.op}</Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs max-w-[180px] truncate" title={ev.actor} data-testid="history-actor">
                        {ev.actor}
                      </TableCell>
                      <TableCell className="font-mono text-xs max-w-[200px] truncate" title={ev.target || ''} data-testid="history-target">
                        {ev.target || '—'}
                      </TableCell>
                      <TableCell className="font-mono text-xs max-w-[220px]" data-testid="history-attrs">
                        {ev.raw.changedAttrs && ev.raw.changedAttrs.length > 0 ? (
                          <div className="flex flex-wrap gap-1">
                            {ev.raw.changedAttrs.map((attr) => (
                              <span
                                key={attr}
                                className="inline-block rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground"
                              >
                                {attr}
                              </span>
                            ))}
                          </div>
                        ) : (
                          '—'
                        )}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            ev.result === 'success'
                              ? 'success'
                              : ev.result === 'failure'
                              ? 'danger'
                              : 'neutral'
                          }
                        >
                          {ev.result}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>

              <div className="flex items-center justify-between border-t border-border pt-3">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handlePrev}
                  disabled={historyStack.length === 0 || loading}
                >
                  {t('history.prev')}
                </Button>
                <span className="text-xs text-muted-foreground">
                  {filteredEvents.length} {t('common.actions').toLowerCase()}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleNext}
                  disabled={!hasMore || loading}
                >
                  {t('history.next')}
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
