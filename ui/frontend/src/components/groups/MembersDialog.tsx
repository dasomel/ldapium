import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { ArrowLeft, ArrowRight, UserRound, Users2 } from 'lucide-react'
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
  onSave: (groupDn: string, members: string[]) => Promise<void>
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

// The scroll box both transfer panels share. Only the shell is common — the
// two row layouts genuinely differ (available rows are two-column and
// aria-pressed for multi-select; member rows stack label over DN for single
// select), so rows stay with their own list. Extracting the shell also fixes
// a drift: the boxes sit side by side but had grown different heights
// (h-72 vs h-[18.5rem]) while looking like they matched.
function MemberListBox({
  isEmpty,
  emptyTitle,
  children,
}: {
  isEmpty: boolean
  emptyTitle: string
  children: ReactNode
}) {
  return (
    <div className="h-72 overflow-auto rounded-console border border-border">
      {isEmpty ? (
        <EmptyState icon={Users2} title={emptyTitle} className="py-8" />
      ) : (
        <ul className="divide-y divide-border">{children}</ul>
      )}
    </div>
  )
}

export function MembersDialog({ open, onOpenChange, group, onSave }: MembersDialogProps) {
  const t = useT()
  const [members, setMembers] = useState<string[]>([])
  const [query, setQuery] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const [selectedCandidateDns, setSelectedCandidateDns] = useState<string[]>([])
  const [selectedMemberDn, setSelectedMemberDn] = useState<string | null>(null)

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
      setSelectedCandidateDns([])
      setSelectedMemberDn(null)
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

  const availableCandidates = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!candidates) return []
    return candidates
      .filter((c) => c.dn.toLowerCase() !== group?.dn.toLowerCase()) // a group can't be its own member
      .filter((c) => !existing.has(c.dn.toLowerCase()))
      .filter((c) => !q || c.searchText.includes(q) || c.dn.toLowerCase().includes(q))
  }, [candidates, query, existing, group])

  const candidatesByDn = useMemo(() => new Map(candidates?.map((candidate) => [candidate.dn, candidate])), [candidates])
  const hasGroupCandidates = !!candidates?.some((c) => c.kind === 'group')
  const canAddTypedDn = looksLikeDN(query) && !existing.has(query.trim().toLowerCase())
  const allAvailableSelected =
    availableCandidates.length > 0 && availableCandidates.every((candidate) => selectedCandidateDns.includes(candidate.dn))

  function moveToMembers(dns = selectedCandidateDns.length > 0 ? selectedCandidateDns : canAddTypedDn ? [query.trim()] : []) {
    if (!group || dns.length === 0) return
    setError(null)
    setMembers((m) => [...m, ...dns])
    setQuery('')
    setSelectedCandidateDns([])
  }

  function moveToAvailable(memberDn = selectedMemberDn) {
    if (!memberDn) return
    setError(null)
    setMembers((m) => m.filter((d) => d !== memberDn))
    setSelectedMemberDn(null)
  }

  function toggleCandidate(dn: string) {
    setSelectedCandidateDns((selected) => (selected.includes(dn) ? selected.filter((item) => item !== dn) : [...selected, dn]))
  }

  function toggleAllCandidates() {
    setSelectedCandidateDns(allAvailableSelected ? [] : availableCandidates.map((candidate) => candidate.dn))
  }

  async function handleSave() {
    if (!group) return
    setError(null)
    setSaving(true)
    try {
      await onSave(group.dn, members)
      onOpenChange(false)
    } catch (err) {
      setError(err instanceof Error ? err.message : t('membersDialog.saveMembersFailed'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl">
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
          <div className="grid gap-3 md:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)]">
            <section className="min-w-0 space-y-2">
              <div className="flex items-center justify-between">
                <h3 className="text-[13px] font-medium">{t('membersDialog.availableMembers')}</h3>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs text-muted-foreground">
                    {selectedCandidateDns.length > 0
                      ? t('membersDialog.selectedCount', { count: selectedCandidateDns.length })
                      : availableCandidates.length}
                  </span>
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    disabled={saving || availableCandidates.length === 0}
                    onClick={toggleAllCandidates}
                  >
                    {allAvailableSelected ? t('membersDialog.clearSelection') : t('membersDialog.selectAll')}
                  </Button>
                </div>
              </div>
              <Input
                placeholder={t('membersDialog.searchPlaceholder')}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                className="font-mono"
              />
              <p className="text-[12px] text-muted-foreground">{t('membersDialog.pasteDnHint')}</p>
              <p className="text-[12px] text-muted-foreground">{t('membersDialog.multiSelectHint')}</p>
              <MemberListBox isEmpty={availableCandidates.length === 0} emptyTitle={t('membersDialog.noAvailableMembers')}>
                    {availableCandidates.map((c) => (
                  <li key={c.dn}>
                    <button
                      type="button"
                      disabled={saving}
                      onClick={() => toggleCandidate(c.dn)}
                      onDoubleClick={() => moveToMembers([c.dn])}
                      aria-pressed={selectedCandidateDns.includes(c.dn)}
                      className={`flex w-full items-center justify-between gap-2 px-3 py-2 text-left text-[12.5px] hover:bg-muted disabled:opacity-50 ${
                        selectedCandidateDns.includes(c.dn) ? 'bg-muted' : ''
                      }`}
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
              </MemberListBox>
            </section>

            <div className="flex items-center justify-center gap-2 md:flex-col">
              <Button
                type="button"
                variant="outline"
                size="icon"
                title={t('membersDialog.addSelectedTitle')}
                disabled={saving || (selectedCandidateDns.length === 0 && !canAddTypedDn)}
                onClick={() => moveToMembers()}
              >
                <ArrowRight className="size-4" />
              </Button>
              <Button
                type="button"
                variant="outline"
                size="icon"
                title={t('membersDialog.removeSelectedTitle')}
                disabled={saving || !selectedMemberDn}
                onClick={() => moveToAvailable()}
              >
                <ArrowLeft className="size-4" />
              </Button>
            </div>

            <section className="min-w-0 space-y-2">
              <div className="flex items-center justify-between">
                <h3 className="text-[13px] font-medium">{t('membersDialog.selectedMembers')}</h3>
                <span className="font-mono text-xs text-muted-foreground">{members.length}</span>
              </div>
              <MemberListBox isEmpty={members.length === 0} emptyTitle={t('membersDialog.noMembers')}>
                    {members.map((memberDn) => {
                      const candidate = candidatesByDn.get(memberDn)
                      return (
                        <li key={memberDn}>
                          <button
                            type="button"
                            disabled={saving}
                            onClick={() => setSelectedMemberDn(memberDn)}
                            onDoubleClick={() => moveToAvailable(memberDn)}
                            className={`flex w-full items-center gap-2 px-3 py-2 text-left text-[12.5px] hover:bg-muted disabled:opacity-50 ${
                              selectedMemberDn === memberDn ? 'bg-muted' : ''
                            }`}
                          >
                            {candidate?.kind === 'group' ? (
                              <Users2 className="size-3.5 shrink-0 text-muted-foreground" />
                            ) : (
                              <UserRound className="size-3.5 shrink-0 text-muted-foreground" />
                            )}
                            <span className="min-w-0">
                              {candidate && <span className="block truncate">{candidate.label}</span>}
                              <span className="block truncate font-mono text-[11px] text-muted-foreground" title={memberDn}>
                                {memberDn}
                              </span>
                            </span>
                          </button>
                        </li>
                      )
                    })}
              </MemberListBox>
            </section>
          </div>

          {candidatesError && (
            <p className="text-[12px] text-muted-foreground">
              {t('membersDialog.pickListError', { error: candidatesError })}
            </p>
          )}
          {hasGroupCandidates && <p className="text-[12px] text-muted-foreground">{t('membersDialog.nestedGroupsNote')}</p>}
          {error && (
            <div className="rounded-console border border-danger/30 bg-danger/10 px-3 py-2 text-[13px] text-danger">
              {error}
            </div>
          )}
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" disabled={saving} onClick={() => onOpenChange(false)}>
            {t('common.cancel')}
          </Button>
          <Button onClick={handleSave} disabled={saving}>
            {saving ? t('common.saving') : t('common.saveChanges')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
