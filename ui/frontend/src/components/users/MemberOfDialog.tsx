import { Users2 } from 'lucide-react'
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { EmptyState } from '@/components/ui/empty-state'
import { GlossaryTerm } from '@/components/ldap/GlossaryTerm'
import type { User } from '@/lib/types'

interface MemberOfDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  user: User | null
}

// Read-only: memberOf is computed by the server's memberof overlay from
// each group's own member attribute, so it can't be edited here. Change
// membership from the Groups page's Members dialog instead.
export function MemberOfDialog({ open, onOpenChange, user }: MemberOfDialogProps) {
  const groups = user?.memberOf ?? []

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Users2 className="size-4 text-accent" />
            Group membership{' '}
            <span className="font-mono text-xs font-normal text-muted-foreground">
              (<GlossaryTerm term="memberOf">memberOf</GlossaryTerm>)
            </span>
          </DialogTitle>
          <DialogDescription className="font-mono">{user?.dn}</DialogDescription>
        </DialogHeader>
        <DialogBody>
          <div className="max-h-72 overflow-auto rounded-console border border-border">
            {groups.length === 0 ? (
              <EmptyState icon={Users2} title="No group membership" className="py-8" />
            ) : (
              <ul className="divide-y divide-border">
                {groups.map((dn) => (
                  <li key={dn} className="truncate px-3 py-2 font-mono text-[12.5px]" title={dn}>
                    {dn}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
