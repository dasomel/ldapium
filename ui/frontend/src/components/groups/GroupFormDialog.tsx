import { useEffect, useState, type FormEvent } from 'react'
import { Dialog, DialogBody, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import type { Group, GroupFormInput } from '@/lib/types'

interface GroupFormDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  group: Group | null
  onSubmit: (input: GroupFormInput) => Promise<void>
}

const emptyForm: GroupFormInput = { cn: '', description: '' }

export function GroupFormDialog({ open, onOpenChange, group, onSubmit }: GroupFormDialogProps) {
  const [form, setForm] = useState<GroupFormInput>(emptyForm)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const isEdit = Boolean(group)

  useEffect(() => {
    if (!open) return
    setError(null)
    setForm(group ? { dn: group.dn, cn: group.cn, description: group.description } : emptyForm)
  }, [open, group])

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      await onSubmit(form)
      onOpenChange(false)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save group')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle>{isEdit ? 'Edit group' : 'New group'}</DialogTitle>
          </DialogHeader>
          <DialogBody className="space-y-3.5">
            <div className="space-y-1.5">
              <Label htmlFor="group-cn">Common name (cn)</Label>
              <Input
                id="group-cn"
                required
                autoFocus
                value={form.cn}
                onChange={(e) => setForm((f) => ({ ...f, cn: e.target.value }))}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="group-description">Description</Label>
              <Input
                id="group-description"
                value={form.description}
                onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
              />
            </div>
            {!isEdit && (
              <p className="text-[12px] text-muted-foreground">
                groupOfNames requires at least one member, so the new group starts with you as its
                first member — add the real member(s) and remove yourself afterwards if needed.
              </p>
            )}
            {error && (
              <div className="rounded-console border border-danger/30 bg-danger/10 px-3 py-2 text-[13px] text-danger">
                {error}
              </div>
            )}
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
              Cancel
            </Button>
            <Button type="submit" disabled={busy}>
              {busy ? 'Saving…' : isEdit ? 'Save changes' : 'Create group'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
