import { useEffect, useState } from 'react'
import { LockKeyhole, Server } from 'lucide-react'
import { api, ApiError } from '@/lib/api'
import type { OSSVersion, ServerSettings } from '@/lib/types'
import { useT } from '@/context/LanguageContext'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { ErrorState, Spinner } from '@/components/ui/empty-state'

function formatDuration(seconds: number): string {
  if (seconds % 3600 === 0) return `${seconds / 3600}h`
  if (seconds % 60 === 0) return `${seconds / 60}m`
  return `${seconds}s`
}

// Every value on this page is a label/value pair, so the grid + dt/dd
// treatment lives here rather than being retyped per row.
//
// wrap exists because the two kinds of value want opposite handling: a single
// value (a DN, a version) is truncated with the full text in a title, while
// the feature lists are long comma-joined strings that are only readable
// wrapped — truncating them would hide most of what they say.
function DefinitionRow({ label, value, wrap = false }: { label: string; value: string; wrap?: boolean }) {
  return (
    <div className="grid grid-cols-[minmax(10rem,1fr)_minmax(0,2fr)] gap-4 px-3 py-2.5">
      <dt className="text-[12.5px] text-muted-foreground">{label}</dt>
      <dd className={`font-mono text-[12.5px] ${wrap ? '' : 'truncate'}`} title={wrap ? undefined : value}>
        {value}
      </dd>
    </div>
  )
}

export function ServerSettingsPage() {
  const t = useT()
  const [settings, setSettings] = useState<ServerSettings | null>(null)
  const [error, setError] = useState<string | null>(null)

  function load() {
    setError(null)
    api
      .serverSettings()
      .then(setSettings)
      .catch((err) => setError(err instanceof ApiError ? err.message : t('settings.loadFailed')))
  }

  useEffect(load, [])

  const rows = settings
    ? [
        [t('settings.applicationVersion'), settings.applicationVersion],
        [t('settings.openLdapVersion'), settings.openLdapVersion],
        [t('settings.baseDn'), settings.baseDn],
        [t('settings.userSearchBase'), settings.userSearchBase],
        [t('settings.userCreateBase'), settings.userCreateBase],
        [t('settings.groupSearchBase'), settings.groupSearchBase],
        [t('settings.groupCreateBase'), settings.groupCreateBase],
        [t('settings.connectionSecurity'), settings.connectionSecurity],
        [t('settings.certificateVerification'), settings.tlsVerified ? t('settings.enabled') : t('settings.disabled')],
        [t('settings.sessionLifetime'), formatDuration(settings.sessionTtlSeconds)],
        [t('settings.secureCookie'), settings.cookieSecure ? t('settings.enabled') : t('settings.disabled')],
        [t('settings.passwordHash'), settings.passwordHash || t('settings.unknown')],
        [t('settings.passwordPolicy'), settings.passwordPolicy ? t('settings.enabled') : t('settings.disabled')],
        [t('settings.uniqueAttributes'), settings.uniqueAttributes.join(', ') || t('settings.none')],
      ]
    : []
  const ossVersions: OSSVersion[] = settings ? [...settings.ossVersions, ...__FRONTEND_OSS_VERSIONS__] : []

  return (
    <div className="max-w-3xl space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Server className="size-4 text-accent" />
            {t('settings.title')}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-[12.5px] text-muted-foreground">{t('settings.readOnlyNote')}</p>
          {error && <ErrorState message={error} onRetry={load} />}
          {!error && !settings && (
            <div className="flex items-center gap-2 py-6 text-[13px] text-muted-foreground">
              <Spinner /> {t('settings.loading')}
            </div>
          )}
          {settings && (
            <dl className="divide-y divide-border rounded-console border border-border">
              {rows.map(([label, value]) => (
                <DefinitionRow key={label} label={label} value={value} />
              ))}
            </dl>
          )}
          <div className="flex items-start gap-2 rounded-console border border-border bg-muted/40 px-3 py-2.5 text-[12.5px] text-muted-foreground">
            <LockKeyhole className="mt-0.5 size-4 shrink-0" />
            <p>{t('settings.securityNote')}</p>
          </div>
        </CardContent>
      </Card>
      {settings && (
        <Card>
          <CardHeader>
            <CardTitle>{t('settings.openLdapFeatures')}</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="divide-y divide-border rounded-console border border-border">
              <DefinitionRow
                label={t('settings.loadedModules')}
                value={settings.loadedModules.join(', ') || t('settings.none')}
                wrap
              />
              <DefinitionRow
                label={t('settings.activeOverlays')}
                value={settings.activeOverlays.join(', ') || t('settings.none')}
                wrap
              />
            </dl>
          </CardContent>
        </Card>
      )}
      {settings && (
        <Card>
          <CardHeader>
            <CardTitle>{t('settings.ossVersions')}</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="divide-y divide-border rounded-console border border-border">
              {ossVersions.map((component) => (
                <DefinitionRow key={component.name} label={component.name} value={component.version} wrap />
              ))}
            </dl>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
