import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { UserMinus, UserPlus, UserRound, Users2 } from 'lucide-react'
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { EmptyState } from '@/components/ui/empty-state'
import { GlossaryTerm } from '@/components/ldap/GlossaryTerm'
import { useT } from '@/context/LanguageContext'
import { api } from '@/lib/api'
import type { Group } from '@/lib/types'

interface MembersDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  group: Group | null
  onAdd: (groupDn: string, memberDn: string) => Promise<void>
  onRemove: (groupDn: string, memberDn: string) => Promise<void>
}

interface Candidate {
  dn: string
  kind: 'user' | 'group'
  label: string
  detail?: string
  searchText: string
}

// Pasting a full DN ("=" present) is a deliberate escape hatch, not a
// search — don't try to match it against the pick list, just let the
// existing Add-by-DN path handle it. The same "=" heuristic is planned
// for the upcoming filter-vs-plain-search work, so it's worth keeping
// consistent here.
function looksLikeDN(input: string): boolean {
  return input.includes('=')
}

export function MembersDialog({ open, onOpenChange, group, onAdd, onRemove }: MembersDialogProps) {
  const t = useT()
  const [members, setMembers] = useState<string[]>([])
  const [query, setQuery] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busyDn, setBusyDn] = useState<string | null>(null)

  // The pick list is a plain client-side filter over the existing
  // /users and /groups listings, not a new search endpoint: those
  // listings already page past the server's size limit, and filtering
  // ~1200 entries client-side measured at ~0.03s, well within what a
  // type-ahead needs. candidates stays null while loading and becomes an
  // empty array either once loaded or if the fetch failed, so the UI can
  // tell "still loading" from "loaded, nothing to show" from "failed".
  const [candidates, setCandidates] = useState<Candidate[] | null>(null)
  const [candidatesError, setCandidatesError] = useState<string | null>(null)

  useEffect(() => {
    if (open && group) {
      setMembers(group.members)
      setError(null)
      setQuery('')
    }
  }, [open, group])

  useEffect(() => {
    if (!open) return
    setCandidates(null)
    setCandidatesError(null)
    Promise.all([api.listUsers(), api.listGroups()])
      .then(([users, groups]) => {
        setCandidates([
          ...users.items.map(
            (u): Candidate => ({
              dn: u.dn,
              kind: 'user',
              label: u.uid,
              detail: u.cn,
              searchText: [u.uid, u.cn, u.mail, u.displayName].filter(Boolean).join(' ').toLowerCase(),
            }),
          ),
          ...groups.items.map(
            (g): Candidate => ({
              dn: g.dn,
              kind: 'group',
              label: g.cn,
              detail: g.description,
              searchText: [g.cn, g.description].filter(Boolean).join(' ').toLowerCase(),
            }),
          ),
        ])
      })
      .catch((err) => {
        // A failed pick-list fetch must not block adding members — fall
        // back to the plain "paste a DN" path and say why the list isn't
        // there, same principle as the schema-editing fallback.
        setCandidates([])
        setCandidatesError(err instanceof Error ? err.message : t('membersDialog.loadCandidatesFailedGeneric'))
      })
  }, [open])

  const existing = useMemo(() => new Set(members.map((m) => m.trim().toLowerCase())), [members])

  const suggestions = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!candidates || !q || looksLikeDN(query)) return []
    return candidates
      .filter((c) => c.dn.toLowerCase() !== group?.dn.toLowerCase()) // a group can't be its own member
      .filter((c) => !existing.has(c.dn.toLowerCase()))
      .filter((c) => c.searchText.includes(q))
      .slice(0, 8)
  }, [candidates, query, existing, group])

  const hasGroupCandidates = !!candidates?.some((c) => c.kind === 'group')

  async function addMember(dn: string) {
    if (!group || !dn.trim()) return
    setError(null)
    setBusyDn(dn)
    try {
      await onAdd(group.dn, dn)
      setMembers((m) => [...m, dn])
      setQuery('')
    } catch (err) {
      setError(err instanceof Error ? err.message : t('membersDialog.addMemberFailed'))
    } finally {
      setBusyDn(null)
    }
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    addMember(query.trim())
  }

  async function handleRemove(memberDn: string) {
    if (!group) return
    setError(null)
    setBusyDn(memberDn)
    try {
      await onRemove(group.dn, memberDn)
      setMembers((m) => m.filter((d) => d !== memberDn))
    } catch (err) {
      setError(err instanceof Error ? err.message : t('membersDialog.removeMemberFailed'))
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
            {t('common.members')}{' '}
            <span className="font-mono text-xs font-normal text-muted-foreground">
              (<GlossaryTerm term="member">member</GlossaryTerm>)
            </span>
          </DialogTitle>
          <DialogDescription className="font-mono">{group?.dn}</DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-3">
          <div className="space-y-1.5">
            <form onSubmit={handleSubmit} className="flex gap-2">
              <Input
                placeholder={t('membersDialog.searchPlaceholder')}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                className="font-mono"
              />
              <Button type="submit" disabled={!query.trim() || busyDn === query.trim()}>
                <UserPlus className="size-4" />
                {t('common.add')}
              </Button>
            </form>

            {candidatesError && (
              <p className="text-[12px] text-muted-foreground">
                {t('membersDialog.pickListError', { error: candidatesError })}
              </p>
            )}

            {suggestions.length > 0 && (
              <ul className="max-h-48 overflow-auto rounded-console border border-border">
                {suggestions.map((c) => (
                  <li key={c.dn}>
                    <button
                      type="button"
                      disabled={busyDn === c.dn}
                      onClick={() => addMember(c.dn)}
                      className="flex w-full items-center justify-between gap-2 px-3 py-1.5 text-left text-[12.5px] hover:bg-muted disabled:opacity-50"
                    >
                      <span className="flex min-w-0 items-center gap-1.5">
                        {c.kind === 'group' ? (
                          <Users2 className="size-3.5 shrink-0 text-muted-foreground" />
                        ) : (
                          <UserRound className="size-3.5 shrink-0 text-muted-foreground" />
                        )}
                        <span className="truncate">{c.label}</span>
                        {c.detail && <span className="truncate text-muted-foreground">{c.detail}</span>}
                      </span>
                      <span className="shrink-0 truncate font-mono text-[11px] text-muted-foreground">{c.dn}</span>
                    </button>
                  </li>
                ))}
              </ul>
            )}

            {hasGroupCandidates && (
              <p className="text-[12px] text-muted-foreground">{t('membersDialog.nestedGroupsNote')}</p>
            )}
          </div>

          {error && (
            <div className="rounded-console border border-danger/30 bg-danger/10 px-3 py-2 text-[13px] text-danger">
              {error}
            </div>
          )}

          <div className="max-h-72 overflow-auto rounded-console border border-border">
            {members.length === 0 ? (
              <EmptyState icon={Users2} title={t('membersDialog.noMembers')} className="py-8" />
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
                      title={t('membersDialog.removeMemberTitle')}
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
            {t('common.close')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
