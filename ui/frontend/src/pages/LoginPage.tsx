import { useEffect, useRef, useState, type FormEvent } from 'react'
import { Navigate, useSearchParams } from 'react-router-dom'
import { KeyRound, LockKeyhole, TerminalSquare } from 'lucide-react'
import { useAuth } from '@/context/AuthContext'
import { useT } from '@/context/LanguageContext'
import { ApiError } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { GlossaryTerm } from '@/components/ldap/GlossaryTerm'
import { Spinner } from '@/components/ui/empty-state'
import type { DictKey } from '@/lib/i18n/en'

// Failure codes the SSO callback distinguishes. Anything else maps to the
// generic message — the backend collapses most failures on purpose, so this
// only needs the ones it actually names.
const SSO_ERROR_KEYS: Record<string, DictKey> = {
  access_denied: 'login.ssoAccessDenied',
  not_authorized: 'login.ssoNotAuthorized',
  directory_account_not_found: 'login.ssoDirectoryAccountNotFound',
}

export function LoginPage() {
  const { dn, authMode, loading, login } = useAuth()
  const t = useT()
  const [searchParams] = useSearchParams()
  const [identity, setIdentity] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const redirectStarted = useRef(false)
  const ssoError = searchParams.get('sso_error')
  const ssoLoggedOut = searchParams.get('sso_logged_out') === '1'

  useEffect(() => {
    if (authMode !== 'sso' || ssoError || ssoLoggedOut || redirectStarted.current) return
    redirectStarted.current = true
    window.location.assign('/api/sso/start')
  }, [authMode, ssoError, ssoLoggedOut])

  if (dn) return <Navigate to="/tree" replace />

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      await login(identity, password)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('login.connectionError'))
    } finally {
      setBusy(false)
    }
  }

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Spinner />
      </div>
    )
  }

  if (!authMode) {
    return (
      <div className="flex min-h-screen items-center justify-center px-4">
        <p className="text-sm text-muted-foreground">{t('login.modeUnavailable')}</p>
      </div>
    )
  }

  const ssoErrorKey: DictKey | null = ssoError
    ? (SSO_ERROR_KEYS[ssoError] ?? 'login.ssoAuthenticationFailed')
    : null

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="mb-7 flex flex-col items-center gap-3 text-center">
          <div className="flex size-12 items-center justify-center rounded-console border border-border-strong bg-surface shadow-panel">
            <TerminalSquare className="size-6 text-accent" />
          </div>
          <div>
            <h1 className="text-lg font-semibold tracking-tight">Directory Console</h1>
            <p className="text-[13px] text-muted-foreground">{t('login.subtitle')}</p>
          </div>
        </div>

        {authMode === 'sso' ? (
          <>
            <div className="animate-console-in space-y-4 rounded-console border border-border bg-surface p-5 shadow-panel">
              <p className="text-center text-[13px] text-muted-foreground">
                {t(ssoLoggedOut ? 'login.ssoSignedOut' : 'login.ssoRedirecting')}
              </p>
              {ssoErrorKey && (
                <div className="rounded-console border border-danger/30 bg-danger/10 px-3 py-2 text-[13px] text-danger">
                  {t(ssoErrorKey)}
                </div>
              )}
              <Button type="button" onClick={() => window.location.assign('/api/sso/start')} className="w-full">
                <KeyRound className="size-4" />
                {t('login.continueWithKeycloak')}
              </Button>
              <a
                href="/api/sso/start"
                className="block text-center text-[12px] text-accent underline underline-offset-2 hover:text-accent/80"
              >
                {t('login.ssoFallbackLink')}
              </a>
            </div>
            <p className="mt-4 text-center text-[12px] text-muted-foreground">{t('login.ssoFooterNote')}</p>
          </>
        ) : (
          <>
            <form
              onSubmit={handleSubmit}
              className="animate-console-in space-y-4 rounded-console border border-border bg-surface p-5 shadow-panel"
            >
              <div className="space-y-1.5">
                <Label htmlFor="identity">
                  <GlossaryTerm term="dn">DN</GlossaryTerm>
                  {t('login.identityLabelJoiner')}
                  <GlossaryTerm term="uid">uid</GlossaryTerm>
                </Label>
                <Input
                  id="identity"
                  autoFocus
                  autoComplete="username"
                  placeholder="uid=jdoe,ou=people,dc=example,dc=com"
                  value={identity}
                  onChange={(e) => setIdentity(e.target.value)}
                  className="font-mono"
                  required
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="password">{t('login.passwordLabel')}</Label>
                <Input
                  id="password"
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </div>

              {error && (
                <div className="rounded-console border border-danger/30 bg-danger/10 px-3 py-2 text-[13px] text-danger">
                  {error}
                </div>
              )}

              <Button type="submit" disabled={busy} className="w-full">
                <LockKeyhole className="size-4" />
                {busy ? t('login.bindingBusy') : t('login.signInButton')}
              </Button>
            </form>

            <p className="mt-4 text-center text-[12px] text-muted-foreground">{t('login.footerNote')}</p>
          </>
        )}
      </div>
    </div>
  )
}
