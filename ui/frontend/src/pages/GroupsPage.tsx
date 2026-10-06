import { useEffect, useMemo, useRef, useState } from 'react'
import { Pencil, Plus, Search, Trash2, Users2 } from 'lucide-react'
import { api, ApiError } from '@/lib/api'
import { useWriteAttempt } from '@/lib/useWriteAttempt'
import type { Group, GroupFormInput } from '@/lib/types'
import { useToast } from '@/context/ToastContext'
import { useT } from '@/context/LanguageContext'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeadCell, TableRow } from '@/components/ui/table'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { EmptyState, ErrorState, Spinner } from '@/components/ui/empty-state'
import { ConfirmDialog } from '@/components/ui/confirm-dialog'
import { GroupFormDialog } from '@/components/groups/GroupFormDialog'
import { GroupPagination } from '@/components/groups/GroupPagination'
import { MembersDialog } from '@/components/groups/MembersDialog'

function TruncatedText({ text, className = '' }: { text: string; className?: string }) {
  const ref = useRef<HTMLSpanElement>(null)
  const [isTruncated, setIsTruncated] = useState(false)

  useEffect(() => {
    const element = ref.current
    if (!element) return

    const update = () => setIsTruncated(element.scrollWidth > element.clientWidth)
    update()
    const observer = new ResizeObserver(update)
    observer.observe(element)
    return () => observer.disconnect()
  }, [isTruncated, text])

  const content = <span ref={ref} tabIndex={isTruncated ? 0 : undefined} className={`block truncate ${className}`}>{text}</span>
  if (!isTruncated) return content

  return (
    <Tooltip>
      <TooltipTrigger asChild>{content}</TooltipTrigger>
      <TooltipContent className="max-w-[min(32rem,90vw)] break-all">{text}</TooltipContent>
    </Tooltip>
  )
}

export function GroupsPage() {
  const { notify } = useToast()
  const t = useT()
  const write = useWriteAttempt()
  const [groups, setGroups] = useState<Group[] | null>(null)
  const [truncated, setTruncated] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [query, setQuery] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)

  const [formOpen, setFormOpen] = useState(false)
  const [editing, setEditing] = useState<Group | null>(null)
  const [membersGroup, setMembersGroup] = useState<Group | null>(null)
  const [deleting, setDeleting] = useState<Group | null>(null)

  const rowRefs = useRef<Array<HTMLTableRowElement | null>>([])

  function load() {
    setError(null)
    api
      .listGroups()
      .then(({ items, truncated }) => {
        setGroups(items)
        setTruncated(truncated)
      })
      .catch((err) => setError(err instanceof ApiError ? err.message : t('groups.loadFailed')))
  }

  useEffect(load, [])

  // Re-read after a conflict or a lost response (see UsersPage.reread).
  async function reread() {
    const { items, truncated } = await api.listGroups()
    setGroups(items)
    setTruncated(truncated)
    return items
  }

  const filtered = useMemo(() => {
    if (!groups) return []
    const q = query.trim().toLowerCase()
    if (!q) return groups
    return groups.filter((g) => g.cn.toLowerCase().includes(q) || g.description?.toLowerCase().includes(q))
  }, [groups, query])

  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize))
  const currentPage = Math.min(page, pageCount)
  const pageGroups = filtered.slice((currentPage - 1) * pageSize, currentPage * pageSize)

  async function handleCreateOrUpdate(input: GroupFormInput) {
    if (editing) {
      const target = editing
      await write(
        {
          fingerprint: ['update', target.dn, input],
          etag: target.etag,
          onStale: async () => {
            const fresh = (await reread()).find((g) => g.dn === target.dn)
            if (fresh) setEditing(fresh)
          },
        },
        (w) => api.updateGroup({ ...input, dn: target.dn }, w),
      )
      notify('success', t('groups.updatedToast', { cn: input.cn }))
    } else {
      await write({ fingerprint: ['create', input] }, (w) => api.createGroup(input, w))
      notify('success', t('groups.createdToast', { cn: input.cn }))
    }
    load()
  }

  async function handleDelete() {
    if (!deleting) return
    const target = deleting
    try {
      await write({ fingerprint: ['delete', target.dn], etag: target.etag, onStale: reread }, (w) =>
        api.deleteGroup(target.dn, w),
      )
    } catch (err) {
      // ConfirmDialog shows no error text; see UsersPage.handleDelete.
      if (!(err instanceof ApiError)) throw err
      notify('error', err.message)
      return
    }
    notify('success', t('groups.deletedToast', { cn: target.cn }))
    setDeleting(null)
    load()
  }

  async function handleSaveMembers(groupDn: string, members: string[]) {
    const group = groups?.find((candidate) => candidate.dn === groupDn)
    if (!group) return
    // No If-Match and no key here: these are many parallel single-member
    // writes, and each one moves the group's etag, so a tag would make them
    // conflict with each other.
    const previous = new Set(group.members)
    const next = new Set(members)

    await Promise.all([
      ...members.filter((memberDn) => !previous.has(memberDn)).map((memberDn) => api.addMember(groupDn, memberDn)),
      ...group.members.filter((memberDn) => !next.has(memberDn)).map((memberDn) => api.removeMember(groupDn, memberDn)),
    ])
    load()
  }

  function onRowKeyDown(e: React.KeyboardEvent<HTMLTableRowElement>, index: number) {
    if (e.target !== e.currentTarget) return
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      if (index + 1 < pageGroups.length) rowRefs.current[index + 1]?.focus()
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      rowRefs.current[index - 1]?.focus()
    } else if (e.key === 'Enter') {
      e.preventDefault()
      setEditing(pageGroups[index])
      setFormOpen(true)
    }
  }

  return (
    <div className="max-w-6xl space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="relative w-full sm:w-72">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            aria-label={t('groups.filterPlaceholder')} placeholder={t('groups.filterPlaceholder')}
            value={query}
            onChange={(e) => { setQuery(e.target.value); setPage(1) }}
            className="pl-8"
          />
        </div>
        <Button
          onClick={() => {
            setEditing(null)
            setFormOpen(true)
          }}
        >
          <Plus className="size-4" />
          {t('groups.newGroupButton')}
        </Button>
      </div>

      <Card className="overflow-hidden">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Users2 className="size-4 text-accent" />
            {t('nav.groups')}
            {groups && <span className="font-mono text-xs font-normal text-muted-foreground">{filtered.length}</span>}
          </CardTitle>
        </CardHeader>
        {truncated && (
          <div className="border-b border-border bg-accent-muted px-4 py-2 text-[12.5px] text-accent">
            {t('groups.truncatedBanner', { n: groups?.length ?? 0 })}
          </div>
        )}
        <CardContent className="p-0">
          {error && <ErrorState message={error} onRetry={load} />}
          {!error && groups === null && (
            <div className="flex items-center gap-2 px-4 py-6 text-[13px] text-muted-foreground">
              <Spinner /> {t('groups.loading')}
            </div>
          )}
          {groups?.length === 0 && (
            <EmptyState
              icon={Users2}
              title={t('groups.emptyTitle')}
              description={t('groups.emptyDescription')}
              action={
                <Button size="sm" onClick={() => setFormOpen(true)}>
                  <Plus className="size-4" /> {t('groups.newGroupButton')}
                </Button>
              }
            />
          )}
          {!!groups?.length && filtered.length === 0 && (
            <EmptyState icon={Search} title={t('common.noMatches')} description={t('common.noMatchesDescription', { query })} />
          )}
          {filtered.length > 0 && (
            <Table className="table-fixed">
              <TableHead>
                <tr>
                  <TableHeadCell className="w-[38%]">cn</TableHeadCell>
                  <TableHeadCell className="w-[40%]">{t('common.description')}</TableHeadCell>
                  <TableHeadCell className="w-[10%]">{t('common.members')}</TableHeadCell>
                  <TableHeadCell className="w-[12%] text-right">{t('common.actions')}</TableHeadCell>
                </tr>
              </TableHead>
              <TableBody>
                {pageGroups.map((g, i) => (
                  <TableRow
                    key={g.dn}
                    ref={(el) => {
                      rowRefs.current[i] = el
                    }}
                    tabIndex={0}
                    onKeyDown={(e) => onRowKeyDown(e, i)}
                    className="focus-visible:bg-muted focus-visible:outline-none"
                  >
                    <TableCell><TruncatedText text={g.cn} className="font-mono" /></TableCell>
                    <TableCell className="text-muted-foreground">
                      {g.description ? <TruncatedText text={g.description} /> : '—'}
                    </TableCell>
                    <TableCell>
                      <button
                        onClick={() => setMembersGroup(g)}
                        className="hover:underline"
                      >
                        <Badge variant="accent">{g.members.length}</Badge>
                      </button>
                    </TableCell>
                    <TableCell>
                      <div className="flex justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          title={t('groups.manageMembersTitle')}
                          onClick={() => setMembersGroup(g)}
                        >
                          <Users2 className="size-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          title={t('common.edit')}
                          onClick={() => {
                            setEditing(g)
                            setFormOpen(true)
                          }}
                        >
                          <Pencil className="size-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          title={t('common.delete')}
                          className="hover:bg-danger/10 hover:text-danger"
                          onClick={() => setDeleting(g)}
                        >
                          <Trash2 className="size-3.5" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
          {!error && filtered.length > 0 && <GroupPagination page={currentPage} pageSize={pageSize} total={filtered.length}
            onPage={setPage} onPageSize={(size) => { setPageSize(size); setPage(1) }} />}
        </CardContent>
      </Card>

      <GroupFormDialog open={formOpen} onOpenChange={setFormOpen} group={editing} onSubmit={handleCreateOrUpdate} />
      <MembersDialog
        open={!!membersGroup}
        onOpenChange={(o) => !o && setMembersGroup(null)}
        group={membersGroup}
        onSave={handleSaveMembers}
      />
      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title={t('groups.deleteTitle')}
        description={t('groups.deleteDescription', { dn: deleting?.dn ?? t('common.thisEntry') })}
        requireText={deleting?.cn}
        onConfirm={handleDelete}
      />
    </div>
  )
}
