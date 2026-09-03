import { useEffect, useState } from 'react'
import { Activity, ShieldAlert } from 'lucide-react'
import { api, ApiError } from '@/lib/api'
import type { MonitorStats } from '@/lib/types'
import { useT } from '@/context/LanguageContext'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { EmptyState, ErrorState, Spinner } from '@/components/ui/empty-state'

import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeadCell, TableRow } from '@/components/ui/table'

// Shared with ServerSettingsPage's DefinitionRow — kept local rather than
// extracted, since the two pages' rows differ (numbers here, strings
// there) and the duplication is three lines.
function StatRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid grid-cols-[minmax(10rem,1fr)_minmax(0,2fr)] gap-4 px-3 py-2.5">
      <dt className="text-[12.5px] text-muted-foreground">{label}</dt>
      <dd className="font-mono text-[12.5px] tabular-nums">{value}</dd>
    </div>
  )
}

function formatNumber(n: number): string {
  return n.toLocaleString()
}

function formatUptime(seconds: number): string {
  if (seconds <= 0) return '0s'
  const d = Math.floor(seconds / 86400)
  const h = Math.floor((seconds % 86400) / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  const s = seconds % 60
  const parts: string[] = []
  if (d > 0) parts.push(`${d}d`)
  if (h > 0) parts.push(`${h}h`)
  if (m > 0) parts.push(`${m}m`)
  if (s > 0 || parts.length === 0) parts.push(`${s}s`)
  return parts.join(' ')
}

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

export function HealthPage() {
  const t = useT()
  const [stats, setStats] = useState<MonitorStats | null>(null)
  const [error, setError] = useState<ApiError | Error | null>(null)

  function load() {
    setError(null)
    api.monitorStats().then(setStats).catch(setError)
  }

  useEffect(load, [])

  const permissionDenied = error instanceof ApiError && error.status === 403

  return (
    <div className="max-w-3xl space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Activity className="size-4 text-accent" />
            {t('health.title')}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-[12.5px] text-muted-foreground">{t('health.subtitle')}</p>

          {!error && !stats && (
            <div className="flex items-center gap-2 py-6 text-[13px] text-muted-foreground">
              <Spinner /> {t('health.loading')}
            </div>
          )}

          {permissionDenied && (
            <EmptyState
              icon={ShieldAlert}
              title={t('health.permissionDeniedTitle')}
              description={t('health.permissionDeniedBody')}
            />
          )}

          {error && !permissionDenied && (
            <ErrorState message={error instanceof ApiError ? error.message : t('health.loadFailed')} onRetry={load} />
          )}
        </CardContent>
      </Card>

      {stats && (
        <>
          <Card>
            <CardHeader>
              <CardTitle>{t('health.connections')}</CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="divide-y divide-border rounded-console border border-border">
                <StatRow label={t('health.connectionsCurrent')} value={formatNumber(stats.connectionsCurrent)} />
                <StatRow label={t('health.connectionsTotal')} value={formatNumber(stats.connectionsTotal)} />
                <StatRow label={t('health.connectionsMaxFds')} value={formatNumber(stats.connectionsMaxFds)} />
              </dl>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>{t('health.operations')}</CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="divide-y divide-border rounded-console border border-border">
                {stats.operations.map((op) => (
                  <StatRow
                    key={op.name}
                    label={op.name}
                    value={`${formatNumber(op.completed)} / ${formatNumber(op.initiated)} ${t('health.operationCompleted').toLowerCase()}`}
                  />
                ))}
              </dl>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>{t('health.traffic')}</CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="divide-y divide-border rounded-console border border-border">
                <StatRow label={t('health.bytesSent')} value={formatNumber(stats.bytesSent)} />
                <StatRow label={t('health.entriesSent')} value={formatNumber(stats.entriesSent)} />
              </dl>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>{t('health.threads')}</CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="divide-y divide-border rounded-console border border-border">
                <StatRow label={t('health.threadsActive')} value={formatNumber(stats.threadsActive)} />
                <StatRow label={t('health.threadsMaxPending')} value={formatNumber(stats.threadsMaxPending)} />
                <StatRow label={t('health.threadsMax')} value={formatNumber(stats.threadsMax)} />
              </dl>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>{t('health.uptime')} &amp; {t('health.waiters')}</CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="divide-y divide-border rounded-console border border-border">
                <StatRow label={t('health.uptime')} value={`${formatUptime(stats.uptimeSeconds)} (${formatNumber(stats.uptimeSeconds)}s)`} />
                <StatRow label={t('health.waitersRead')} value={formatNumber(stats.waitersRead)} />
                <StatRow label={t('health.waitersWrite')} value={formatNumber(stats.waitersWrite)} />
              </dl>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>{t('health.database')}</CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="divide-y divide-border rounded-console border border-border">
                <StatRow label={t('health.databaseEntries')} value={formatNumber(stats.databaseEntries)} />
                <StatRow label={t('health.databasePagesUsed')} value={formatNumber(stats.databasePagesUsed)} />
                <StatRow label={t('health.databasePagesFree')} value={formatNumber(stats.databasePagesFree)} />
                <StatRow label={t('health.databasePagesMax')} value={formatNumber(stats.databasePagesMax)} />
              </dl>
            </CardContent>
          </Card>

          {stats.replicationCsns && stats.replicationCsns.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>{t('health.replication')}</CardTitle>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableHeadCell>{t('health.replicationProvider')}</TableHeadCell>
                      <TableHeadCell>{t('health.replicationCsn')}</TableHeadCell>
                      <TableHeadCell>{t('health.replicationTimestamp')}</TableHeadCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {stats.replicationCsns.map((rcsn) => (
                      <TableRow key={rcsn.serverId || rcsn.csn}>
                        <TableCell className="font-mono text-xs">{rcsn.serverId}</TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">{rcsn.csn}</TableCell>
                        <TableCell className="font-mono text-xs">{rcsn.timestamp || '—'}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}

          {stats.recentLogs && stats.recentLogs.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>{t('health.logsTitle')}</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-[12.5px] text-muted-foreground">{t('health.logsSubtitle')}</p>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableHeadCell>{t('health.logTime')}</TableHeadCell>
                      <TableHeadCell>{t('health.logOp')}</TableHeadCell>
                      <TableHeadCell>{t('health.logActor')}</TableHeadCell>
                      <TableHeadCell>{t('health.logTarget')}</TableHeadCell>
                      <TableHeadCell>{t('health.logDetails')}</TableHeadCell>
                      <TableHeadCell>{t('health.logResult')}</TableHeadCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {stats.recentLogs.map((log, idx) => (
                      <TableRow key={log.correlationId || idx}>
                        <TableCell className="font-mono text-xs whitespace-nowrap">{log.time || log.raw.reqStart || '—'}</TableCell>
                        <TableCell>
                          <Badge variant={opBadgeVariant(log.op)}>{log.op}</Badge>
                        </TableCell>
                        <TableCell className="font-mono text-xs max-w-[160px] truncate" title={log.actor}>
                          {log.actor}
                        </TableCell>
                        <TableCell className="font-mono text-xs max-w-[180px] truncate" title={log.target || ''}>
                          {log.target || '—'}
                        </TableCell>
                        <TableCell className="font-mono text-xs max-w-[200px] truncate">
                          {log.raw.filter ? (
                            <span title={log.raw.filter}>{log.raw.filter}</span>
                          ) : log.raw.changedAttrs && log.raw.changedAttrs.length > 0 ? (
                            <span title={log.raw.changedAttrs.join(', ')}>{log.raw.changedAttrs.join(', ')}</span>
                          ) : (
                            '—'
                          )}
                        </TableCell>
                        <TableCell>
                          <Badge variant={log.result === 'success' ? 'success' : log.result === 'failure' ? 'danger' : 'neutral'}>
                            {log.result}
                          </Badge>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}
        </>
      )}

      <div className="rounded-console border border-border bg-muted/40 px-3 py-2.5 text-[12.5px] text-muted-foreground">
        {t('health.scopeNote')}
      </div>
    </div>
  )
}
