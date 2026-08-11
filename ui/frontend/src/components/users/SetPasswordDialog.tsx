import { useState } from 'react'
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useT } from '@/context/LanguageContext'
import type { User } from '@/lib/types'

interface SetPasswordDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  user: User | null
  onSubmit: (dn: string, password: string) => Promise<string | undefined>
}

/** Changes a password via the RFC 3062 Password Modify extended operation
 * — never a raw userPassword write — so the directory's own hashing
 * scheme and password policy apply. */
export function SetPasswordDialog({ open, onOpenChange, user, onSubmit }: SetPasswordDialogProps) {
  const t = useT()
  const [password, setPassword] = useState('')
  const [generated, setGenerated] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  function reset() {
    setPassword('')
    setGenerated(null)
    setError(null)
  }

  async function handleSubmit() {
    if (!user) return
    setBusy(true)
    setError(null)
    try {
      const gen = await onSubmit(user.dn, password)
      if (gen) {
        setGenerated(gen)
      } else {
        onOpenChange(false)
        reset()
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : t('setPasswordDialog.genericError'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        onOpenChange(o)
        if (!o) reset()
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('setPasswordDialog.title')}</DialogTitle>
          <DialogDescription className="font-mono">{user?.dn}</DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-3">
          {generated ? (
            <div className="space-y-1.5">
              <Label>{t('setPasswordDialog.generatedLabel')}</Label>
              <Input readOnly value={generated} className="font-mono" onFocus={(e) => e.target.select()} />
              <p className="text-[12px] text-muted-foreground">{t('setPasswordDialog.copyNowHint')}</p>
            </div>
          ) : (
            <div className="space-y-1.5">
              <Label htmlFor="new-password">{t('common.newPasswordLabel')}</Label>
              <Input
                id="new-password"
                type="password"
                autoFocus
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
              <p className="text-[12px] text-muted-foreground">{t('setPasswordDialog.blankHint')}</p>
            </div>
          )}
          {error && (
            <div className="rounded-console border border-danger/30 bg-danger/10 px-3 py-2 text-[13px] text-danger">
              {error}
            </div>
          )}
        </DialogBody>
        <DialogFooter>
          {generated ? (
            <Button onClick={() => onOpenChange(false)}>{t('common.done')}</Button>
          ) : (
            <>
              <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
                {t('common.cancel')}
              </Button>
              <Button onClick={handleSubmit} disabled={busy}>
                {busy ? t('setPasswordDialog.settingBusy') : t('setPasswordDialog.title')}
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
