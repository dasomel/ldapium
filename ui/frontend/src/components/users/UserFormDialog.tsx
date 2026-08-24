import { useEffect, useState, type FormEvent } from 'react'
import { Dialog, DialogBody, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { GlossaryTerm } from '@/components/ldap/GlossaryTerm'
import { useT } from '@/context/LanguageContext'
import type { User, UserFormInput } from '@/lib/types'

interface UserFormDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  user: User | null
  onSubmit: (input: UserFormInput) => Promise<void>
}

const emptyForm: UserFormInput = {
  uid: '',
  cn: '',
  sn: '',
  givenName: '',
  mail: '',
  password: '',
  department: '',
  organization: '',
  organizationalUnit: '',
}

export function UserFormDialog({ open, onOpenChange, user, onSubmit }: UserFormDialogProps) {
  const t = useT()
  const [form, setForm] = useState<UserFormInput>(emptyForm)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const isEdit = Boolean(user)

  useEffect(() => {
    if (!open) return
    setError(null)
    setForm(
      user
        ? {
            dn: user.dn,
            uid: user.uid,
            cn: user.cn,
            sn: user.sn,
            // ?? '': an absent optional field (omitempty in the API
            // response) would otherwise seed the input as undefined,
            // making it start uncontrolled and then flip to controlled
            // the moment it's typed into — React warns on that switch.
            givenName: user.givenName ?? '',
            mail: user.mail ?? '',
            department: user.department ?? '',
            organization: user.organization ?? '',
            organizationalUnit: user.organizationalUnit ?? '',
          }
        : emptyForm,
    )
  }, [open, user])

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      await onSubmit(form)
      onOpenChange(false)
    } catch (err) {
      setError(err instanceof Error ? err.message : t('userForm.genericError'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle>{isEdit ? t('userForm.editTitle') : t('userForm.newTitle')}</DialogTitle>
          </DialogHeader>
          <DialogBody className="space-y-3.5">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label htmlFor="uid">
                  <GlossaryTerm term="uid">uid</GlossaryTerm>
                </Label>
                <Input
                  id="uid"
                  required
                  disabled={isEdit}
                  value={form.uid}
                  onChange={(e) => setForm((f) => ({ ...f, uid: e.target.value }))}
                  className="font-mono"
                  autoFocus={!isEdit}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="mail">mail</Label>
                <Input
                  id="mail"
                  type="email"
                  value={form.mail}
                  onChange={(e) => setForm((f) => ({ ...f, mail: e.target.value }))}
                />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label htmlFor="givenName">{t('userForm.givenNameLabel')}</Label>
                <Input
                  id="givenName"
                  value={form.givenName}
                  onChange={(e) => setForm((f) => ({ ...f, givenName: e.target.value }))}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="sn">
                  Surname (<GlossaryTerm term="sn">sn</GlossaryTerm>)
                </Label>
                <Input
                  id="sn"
                  required
                  value={form.sn}
                  onChange={(e) => setForm((f) => ({ ...f, sn: e.target.value }))}
                />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="cn">
                Common name (<GlossaryTerm term="cn">cn</GlossaryTerm>)
              </Label>
              <Input id="cn" required value={form.cn} onChange={(e) => setForm((f) => ({ ...f, cn: e.target.value }))} />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label htmlFor="organizationalUnit">{t('userForm.organizationalUnitLabel')}</Label>
                <Input
                  id="organizationalUnit"
                  value={form.organizationalUnit}
                  onChange={(e) => setForm((f) => ({ ...f, organizationalUnit: e.target.value }))}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="department">{t('userForm.departmentLabel')}</Label>
                <Input
                  id="department"
                  value={form.department}
                  onChange={(e) => setForm((f) => ({ ...f, department: e.target.value }))}
                />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="organization">{t('userForm.organizationLabel')}</Label>
              <Input
                id="organization"
                value={form.organization}
                onChange={(e) => setForm((f) => ({ ...f, organization: e.target.value }))}
              />
            </div>
            {!isEdit && (
              <div className="space-y-1.5">
                <Label htmlFor="password">{t('userForm.initialPasswordLabel')}</Label>
                <Input
                  id="password"
                  type="password"
                  autoComplete="new-password"
                  value={form.password}
                  onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))}
                />
                <p className="text-[12px] text-muted-foreground">{t('userForm.initialPasswordHint')}</p>
              </div>
            )}
            {error && (
              <div className="rounded-console border border-danger/30 bg-danger/10 px-3 py-2 text-[13px] text-danger">
                {error}
              </div>
            )}
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" disabled={busy}>
              {busy ? t('common.saving') : isEdit ? t('common.saveChanges') : t('userForm.createButton')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
