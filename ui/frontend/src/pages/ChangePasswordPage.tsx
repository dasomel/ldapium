import { useEffect, useState, type FormEvent } from 'react'
import { KeyRound } from 'lucide-react'
import { useAuth } from '@/context/AuthContext'
import { useToast } from '@/context/ToastContext'
import { api, ApiError } from '@/lib/api'
import type { PasswordPolicy } from '@/lib/types'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'

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

// Plain unit conversion of a policy's own second count — not a guess at
// what the policy means, just formatting (900 -> "15 minutes").
function formatDuration(seconds: number): string {
  if (seconds <= 0) return '0 seconds'
  const units: [string, number][] = [
    ['day', 86400],
    ['hour', 3600],
    ['minute', 60],
    ['second', 1],
  ]
  for (const [name, secs] of units) {
    if (seconds >= secs) {
      const n = Math.round(seconds / secs)
      return `${n} ${name}${n === 1 ? '' : 's'}`
    }
  }
  return `${seconds} seconds`
}

// Result code 53 ("Unwilling To Perform") with this specific diagnostic
// text is ambiguous by design, not a bug: slapd sends it both when the
// current password you typed is wrong (pwdSafeModify is on and rejected
// it) AND when current-password verification isn't enabled on the server
// at all — same code, same text, opposite causes. We can't tell which
// applies from here, so the message below points the user at their own
// input without asserting it's wrong.
function describeSetPasswordError(err: unknown): string {
  if (!(err instanceof ApiError)) return 'Failed to change password.'
  const msg = err.message
  if (/code 53/i.test(msg) && /verify old password/i.test(msg)) {
    return (
      'Your current password may be incorrect — double check it and try again. ' +
      "(If current-password verification isn't enabled on this server, this message " +
      'can also appear even when it was correct; ask an administrator if it persists.)'
    )
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
      setError('New password and confirmation do not match.')
      return
    }
    setBusy(true)
    try {
      await api.setPassword(dn, newPassword, currentPassword)
      notify('success', 'Password changed. Use your new password next time you sign in.')
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
    } catch (err) {
      // Show the directory's own rejection reason (e.g. a ppolicy quality
      // or history violation) rather than a generic message — the
      // server's policy is the actual source of truth for what's
      // allowed. One case gets reworded; see describeSetPasswordError.
      setError(describeSetPasswordError(err))
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
            Change password
          </CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-3.5">
            <p className="font-mono text-[12.5px] text-muted-foreground">{dn}</p>
            {policy && (
              <div className="space-y-1.5 rounded-console border border-border bg-muted/40 px-3 py-2.5 text-[12.5px]">
                <p className="font-medium text-foreground">Password requirements (from the directory server)</p>
                <ul className="list-disc space-y-0.5 pl-4 text-muted-foreground">
                  {policy.pwdMinLength != null && <li>At least {policy.pwdMinLength} characters</li>}
                  {!!policy.pwdInHistory && (
                    <li>
                      Can't reuse your last {policy.pwdInHistory} password{policy.pwdInHistory === 1 ? '' : 's'}
                    </li>
                  )}
                  {policy.pwdMaxAge != null && (
                    <li>
                      {policy.pwdMaxAge === 0 ? "Doesn't expire" : `Expires after ${formatDuration(policy.pwdMaxAge)}`}
                    </li>
                  )}
                  {policy.pwdSafeModify != null && (
                    <li>
                      {policy.pwdSafeModify
                        ? 'Your current password is required to change it'
                        : 'Your current password is not required to change it'}
                    </li>
                  )}
                </ul>
                {!!policy.pwdCheckQuality && (
                  <p className="text-muted-foreground">
                    The server may enforce additional quality checks beyond what's listed above.
                  </p>
                )}
              </div>
            )}
            {ambiguous && (
              <p className="text-[12px] text-muted-foreground">
                Multiple password policies are configured on this server, and it's not clear from here
                which one applies to your account. Ask an administrator if you're unsure of the
                requirements.
              </p>
            )}
            <div className="space-y-1.5">
              <Label htmlFor="current-password">Current password</Label>
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
              <Label htmlFor="new-password">New password</Label>
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
              <Label htmlFor="confirm-password">Confirm new password</Label>
              <Input
                id="confirm-password"
                type="password"
                autoComplete="new-password"
                required
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
              />
              {mismatch && <p className="text-[12px] text-danger">Passwords do not match.</p>}
            </div>
            <p className="text-[12px] text-muted-foreground">
              Password requirements are enforced by the directory server, not this page.
            </p>
            {error && (
              <div className="rounded-console border border-danger/30 bg-danger/10 px-3 py-2 text-[13px] text-danger">
                {error}
              </div>
            )}
            <Button type="submit" disabled={busy || mismatch} className="w-full">
              {busy ? 'Changing…' : 'Change password'}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
