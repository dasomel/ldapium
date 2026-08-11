import { useEffect, useState, type FormEvent } from 'react'
import { KeyRound } from 'lucide-react'
import { useAuth } from '@/context/AuthContext'
import { useToast } from '@/context/ToastContext'
import { useT } from '@/context/LanguageContext'
import { api, ApiError } from '@/lib/api'
import type { PasswordPolicy } from '@/lib/types'
import type { DictKey } from '@/lib/i18n/en'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'

type TFunction = ReturnType<typeof useT>

// A deployment can have more than one pwdPolicy entry (e.g. per-user
// overrides via pwdPolicySubentry, which this app doesn't read). We can
// reliably show one specific policy in exactly two cases: there's only
// one entry, or one of several is named "default" — the ppolicy overlay's
// own conventional name for the policy it falls back to. Anything more
// ambiguous than that, we refuse to guess which applies to this account.
function pickPrimaryPolicy(policies: PasswordPolicy[]): { policy: PasswordPolicy | null; ambiguous: boolean } {
  if (policies.length === 0) return { policy: null, ambiguous: false }
  if (policies.length === 1) return { policy: policies[0], ambiguous: false }
  const byDefaultName = policies.find((p) => p.cn === 'default')
  if (byDefaultName) return { policy: byDefaultName, ambiguous: false }
  return { policy: null, ambiguous: true }
}

const durationUnits: [DictKey, number][] = [
  ['changePassword.unit.day.one', 86400],
  ['changePassword.unit.hour.one', 3600],
  ['changePassword.unit.minute.one', 60],
  ['changePassword.unit.second.one', 1],
]

// Plain unit conversion of a policy's own second count — not a guess at
// what the policy means, just formatting (900 -> "15 minutes" / "15분").
// The unit words themselves come from the dictionary (day/hour/minute/
// second are language-dependent, unlike the number), with a one/many key
// pair per unit since English needs "1 day" vs "2 days" and Korean's two
// values are just identical text (see ko.ts).
function formatDuration(t: TFunction, seconds: number): string {
  if (seconds <= 0) return t('changePassword.unit.second.many', { n: 0 })
  for (const [oneKey, secs] of durationUnits) {
    if (seconds >= secs) {
      const n = Math.round(seconds / secs)
      const key: DictKey = n === 1 ? oneKey : (oneKey.replace('.one', '.many') as DictKey)
      return t(key, { n })
    }
  }
  return t('changePassword.unit.second.many', { n: seconds })
}

// Result code 53 ("Unwilling To Perform") with this specific diagnostic
// text is ambiguous by design, not a bug: slapd sends it both when the
// current password you typed is wrong (pwdSafeModify is on and rejected
// it) AND when current-password verification isn't enabled on the server
// at all — same code, same text, opposite causes. We can't tell which
// applies from here, so the message below points the user at their own
// input without asserting it's wrong. This composed message is ours, so
// it's translated; every other server-rejection message is shown exactly
// as slapd sent it (see the `return msg` below) — never run through t(),
// never reworded. Operators need to be able to search/match those
// against slapd's own docs and logs, and the wording changes across
// server versions, so a translation dictionary for them would just go
// stale.
function describeSetPasswordError(t: TFunction, err: unknown): string {
  if (!(err instanceof ApiError)) return t('changePassword.genericError')
  const msg = err.message
  if (/code 53/i.test(msg) && /verify old password/i.test(msg)) {
    return t('changePassword.ambiguousCurrentPassword')
  }
  return msg
}

/** Self-service password change for the logged-in user. Uses the same
 * /users/password endpoint as the admin "set password" action, just with
 * the caller's own DN and a current password — the directory's ACLs
 * (`by self write` on userPassword) and password policy decide whether
 * that's allowed, not this page. There are deliberately no client-side
 * password rules here: the server's ppolicy overlay is the source of
 * truth, and duplicating rules here could reject passwords the server
 * would accept, or vice versa. Server text is shown as-is for every other
 * rejection (e.g. quality/history violations) — see describeSetPasswordError
 * for the one deliberate exception. */
export function ChangePasswordPage() {
  const { dn } = useAuth()
  const { notify } = useToast()
  const t = useT()
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [policies, setPolicies] = useState<PasswordPolicy[] | null>(null)

  useEffect(() => {
    // Best-effort: if this fails, the form still works — it just won't
    // show requirements up front, same as before this feature existed.
    api
      .listPasswordPolicies()
      .then(setPolicies)
      .catch(() => setPolicies([]))
  }, [])

  const mismatch = confirmPassword.length > 0 && newPassword !== confirmPassword
  const { policy, ambiguous } = pickPrimaryPolicy(policies ?? [])

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!dn) return
    setError(null)
    if (newPassword !== confirmPassword) {
      setError(t('changePassword.mismatchError'))
      return
    }
    setBusy(true)
    try {
      await api.setPassword(dn, newPassword, currentPassword)
      notify('success', t('changePassword.successToast'))
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
    } catch (err) {
      // Show the directory's own rejection reason (e.g. a ppolicy quality
      // or history violation) rather than a generic message — the
      // server's policy is the actual source of truth for what's
      // allowed. One case gets reworded; see describeSetPasswordError.
      setError(describeSetPasswordError(t, err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="max-w-md space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <KeyRound className="size-4 text-accent" />
            {t('changePassword.title')}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-3.5">
            <p className="font-mono text-[12.5px] text-muted-foreground">{dn}</p>
            {policy && (
              <div className="space-y-1.5 rounded-console border border-border bg-muted/40 px-3 py-2.5 text-[12.5px]">
                <p className="font-medium text-foreground">{t('changePassword.requirementsHeading')}</p>
                <ul className="list-disc space-y-0.5 pl-4 text-muted-foreground">
                  {policy.pwdMinLength != null && <li>{t('changePassword.reqMinLength', { n: policy.pwdMinLength })}</li>}
                  {!!policy.pwdInHistory && (
                    <li>
                      {t(policy.pwdInHistory === 1 ? 'changePassword.reqHistory.one' : 'changePassword.reqHistory.many', {
                        n: policy.pwdInHistory,
                      })}
                    </li>
                  )}
                  {policy.pwdMaxAge != null && (
                    <li>
                      {policy.pwdMaxAge === 0
                        ? t('changePassword.neverExpires')
                        : t('changePassword.expiresAfter', { duration: formatDuration(t, policy.pwdMaxAge) })}
                    </li>
                  )}
                  {policy.pwdSafeModify != null && (
                    <li>
                      {policy.pwdSafeModify
                        ? t('changePassword.currentPasswordRequired')
                        : t('changePassword.currentPasswordNotRequired')}
                    </li>
                  )}
                </ul>
                {!!policy.pwdCheckQuality && <p className="text-muted-foreground">{t('changePassword.qualityNote')}</p>}
              </div>
            )}
            {ambiguous && <p className="text-[12px] text-muted-foreground">{t('changePassword.ambiguousPolicy')}</p>}
            <div className="space-y-1.5">
              <Label htmlFor="current-password">{t('changePassword.currentPasswordLabel')}</Label>
              <Input
                id="current-password"
                type="password"
                autoComplete="current-password"
                required
                autoFocus
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="new-password">{t('changePassword.newPasswordLabel')}</Label>
              <Input
                id="new-password"
                type="password"
                autoComplete="new-password"
                required
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="confirm-password">{t('changePassword.confirmPasswordLabel')}</Label>
              <Input
                id="confirm-password"
                type="password"
                autoComplete="new-password"
                required
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
              />
              {mismatch && <p className="text-[12px] text-danger">{t('changePassword.mismatchInline')}</p>}
            </div>
            <p className="text-[12px] text-muted-foreground">{t('changePassword.disclaimer')}</p>
            {error && (
              <div className="rounded-console border border-danger/30 bg-danger/10 px-3 py-2 text-[13px] text-danger">
                {error}
              </div>
            )}
            <Button type="submit" disabled={busy || mismatch} className="w-full">
              {busy ? t('changePassword.submitBusy') : t('changePassword.title')}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
