import { useEffect, useState } from 'react'
import { Activity, ShieldAlert } from 'lucide-react'
import { api, ApiError } from '@/lib/api'
import type { MonitorStats } from '@/lib/types'
import { useT } from '@/context/LanguageContext'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { EmptyState, ErrorState, Spinner } from '@/components/ui/empty-state'

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
        </>
      )}

      <div className="rounded-console border border-border bg-muted/40 px-3 py-2.5 text-[12.5px] text-muted-foreground">
        {t('health.scopeNote')}
      </div>
    </div>
  )
}
