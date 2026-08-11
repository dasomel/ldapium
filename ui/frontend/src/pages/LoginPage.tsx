import { useState, type FormEvent } from 'react'
import { Navigate } from 'react-router-dom'
import { LockKeyhole, TerminalSquare } from 'lucide-react'
import { useAuth } from '@/context/AuthContext'
import { ApiError } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

export function LoginPage() {
  const { dn, login } = useAuth()
  const [identity, setIdentity] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  if (dn) return <Navigate to="/tree" replace />

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      await login(identity, password)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not reach the server.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="mb-7 flex flex-col items-center gap-3 text-center">
          <div className="flex size-12 items-center justify-center rounded-console border border-border-strong bg-surface shadow-panel">
            <TerminalSquare className="size-6 text-accent" />
          </div>
          <div>
            <h1 className="text-lg font-semibold tracking-tight">Directory Console</h1>
            <p className="text-[13px] text-muted-foreground">Sign in with your directory credentials</p>
          </div>
        </div>

        <form
          onSubmit={handleSubmit}
          className="animate-console-in space-y-4 rounded-console border border-border bg-surface p-5 shadow-panel"
        >
          <div className="space-y-1.5">
            <Label htmlFor="identity">DN or uid</Label>
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
            <Label htmlFor="password">Password</Label>
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
            {busy ? 'Binding…' : 'Sign in'}
          </Button>
        </form>

        <p className="mt-4 text-center text-[12px] text-muted-foreground">
          Authenticated by an LDAP bind. Your permissions are whatever your directory account allows.
        </p>
      </div>
    </div>
  )
}
