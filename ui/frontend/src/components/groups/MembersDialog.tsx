import { useEffect, useState, type FormEvent } from 'react'
import { UserMinus, UserPlus, Users2 } from 'lucide-react'
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { EmptyState } from '@/components/ui/empty-state'
import { GlossaryTerm } from '@/components/ldap/GlossaryTerm'
import type { Group } from '@/lib/types'

interface MembersDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  group: Group | null
  onAdd: (groupDn: string, memberDn: string) => Promise<void>
  onRemove: (groupDn: string, memberDn: string) => Promise<void>
}

export function MembersDialog({ open, onOpenChange, group, onAdd, onRemove }: MembersDialogProps) {
  const [members, setMembers] = useState<string[]>([])
  const [newMember, setNewMember] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busyDn, setBusyDn] = useState<string | null>(null)

  useEffect(() => {
    if (open && group) {
      setMembers(group.members)
      setError(null)
      setNewMember('')
    }
  }, [open, group])

  async function handleAdd(e: FormEvent) {
    e.preventDefault()
    if (!group || !newMember.trim()) return
    setError(null)
    setBusyDn('__new__')
    try {
      await onAdd(group.dn, newMember.trim())
      setMembers((m) => [...m, newMember.trim()])
      setNewMember('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add member')
    } finally {
      setBusyDn(null)
    }
  }

  async function handleRemove(memberDn: string) {
    if (!group) return
    setError(null)
    setBusyDn(memberDn)
    try {
      await onRemove(group.dn, memberDn)
      setMembers((m) => m.filter((d) => d !== memberDn))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to remove member')
    } finally {
      setBusyDn(null)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Users2 className="size-4 text-accent" />
            Members <span className="font-mono text-xs font-normal text-muted-foreground">(<GlossaryTerm term="member">member</GlossaryTerm>)</span>
          </DialogTitle>
          <DialogDescription className="font-mono">{group?.dn}</DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-3">
          <form onSubmit={handleAdd} className="flex gap-2">
            <Input
              placeholder="uid=jdoe,ou=people,dc=example,dc=com"
              value={newMember}
              onChange={(e) => setNewMember(e.target.value)}
              className="font-mono"
            />
            <Button type="submit" disabled={!newMember.trim() || busyDn === '__new__'}>
              <UserPlus className="size-4" />
              Add
            </Button>
          </form>

          {error && (
            <div className="rounded-console border border-danger/30 bg-danger/10 px-3 py-2 text-[13px] text-danger">
              {error}
            </div>
          )}

          <div className="max-h-72 overflow-auto rounded-console border border-border">
            {members.length === 0 ? (
              <EmptyState icon={Users2} title="No members" className="py-8" />
            ) : (
              <ul className="divide-y divide-border">
                {members.map((m) => (
                  <li key={m} className="flex items-center justify-between gap-2 px-3 py-2">
                    <span className="truncate font-mono text-[12.5px]" title={m}>
                      {m}
                    </span>
                    <Button
                      variant="ghost"
                      size="icon"
                      title="Remove member"
                      disabled={busyDn === m}
                      onClick={() => handleRemove(m)}
                      className="shrink-0 hover:bg-danger/10 hover:text-danger"
                    >
                      <UserMinus className="size-3.5" />
                    </Button>
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
