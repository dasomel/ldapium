import { useState } from 'react'
import { AlertTriangle } from 'lucide-react'
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from './dialog'
import { Button } from './button'
import { Input } from './input'
import { Label } from './label'
import { useT } from '@/context/LanguageContext'

interface ConfirmDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  description: string
  /** Value the operator must retype to enable the confirm button — used
   * for irreversible deletes so a stray click can't destroy an entry. */
  requireText?: string
  confirmLabel?: string
  onConfirm: () => Promise<void> | void
}

/** Destructive-action confirmation used for every delete/remove flow in the
 * app. When requireText is set, the confirm button stays disabled until the
 * operator retypes that exact value. */
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  requireText,
  confirmLabel,
  onConfirm,
}: ConfirmDialogProps) {
  const t = useT()
  const [typed, setTyped] = useState('')
  const [busy, setBusy] = useState(false)

  const canConfirm = !requireText || typed === requireText

  async function handleConfirm() {
    setBusy(true)
    try {
      await onConfirm()
      onOpenChange(false)
    } finally {
      setBusy(false)
      setTyped('')
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!busy) {
          setTyped('')
          onOpenChange(o)
        }
      }}
    >
      <DialogContent>
        <DialogHeader>
          <div className="flex items-start gap-2.5">
            <AlertTriangle className="mt-0.5 size-4 shrink-0 text-danger" />
            <div>
              <DialogTitle>{title}</DialogTitle>
              <DialogDescription>{description}</DialogDescription>
            </div>
          </div>
        </DialogHeader>
        {requireText && (
          <DialogBody>
            <Label htmlFor="confirm-text">
              <span className="font-mono normal-case text-foreground">{requireText}</span>
              {t('confirmDialog.typeToConfirmSuffix')}
            </Label>
            <Input
              id="confirm-text"
              autoFocus
              autoComplete="off"
              spellCheck={false}
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              className="mt-1.5 font-mono"
            />
          </DialogBody>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button variant="danger" onClick={handleConfirm} disabled={!canConfirm || busy}>
            {busy ? t('common.working') : (confirmLabel ?? t('common.delete'))}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
