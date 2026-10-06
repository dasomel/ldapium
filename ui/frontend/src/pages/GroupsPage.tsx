import { useEffect, useRef, useState } from 'react'
import { Pencil, Plus, Search, Trash2, Users2 } from 'lucide-react'
import { api, ApiError } from '@/lib/api'
import { describeChanges, useWriteAttempt } from '@/lib/useWriteAttempt'
import type { Group, GroupFormInput } from '@/lib/types'
import { useToast } from '@/context/ToastContext'
import { useAuth } from '@/context/AuthContext'
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
  const { dn } = useAuth()
  const t = useT()
  const write = useWriteAttempt()

  const [groups, setGroups] = useState<Group[] | null>(null)
  const [error, setError] = useState<{ message: string; code?: string } | null>(null)
  const [query, setQuery] = useState('')
  const [debouncedQuery, setDebouncedQuery] = useState('')
  const [cursor, setCursor] = useState<string | undefined>(undefined)
  const [cursorStack, setCursorStack] = useState<Array<string | undefined>>([])
  const [hasMore, setHasMore] = useState(false)
  const [nextCursor, setNextCursor] = useState<string | undefined>(undefined)
  const [pageSize, setPageSize] = useState(10)

  const [formOpen, setFormOpen] = useState(false)
  const [editing, setEditing] = useState<Group | null>(null)
  const [membersGroup, setMembersGroup] = useState<Group | null>(null)
  const [deleting, setDeleting] = useState<Group | null>(null)

  const autoAdvanceRef = useRef(0)
  const prevDnRef = useRef(dn)
  const isMountedRef = useRef(false)
  const rowRefs = useRef<Array<HTMLTableRowElement | null>>([])

  function loadPage(
    cursorParam?: string,
    stackParam: Array<string | undefined> = cursorStack,
    qParam = debouncedQuery,
    sizeParam = pageSize,
  ) {
    setError(null)
    api
      .listGroups({ limit: sizeParam, cursor: cursorParam, q: qParam || undefined })
      .then(({ items, hasMore: more, nextCursor: next }) => {
        const hasMoreBool = Boolean(more)
        setHasMore(hasMoreBool)
        setNextCursor(next)
        setCursor(cursorParam)
        setCursorStack(stackParam)

        // Empty page with hasMore: true -> auto-advance per CHANGE.md
        if (items.length === 0 && hasMoreBool && next && autoAdvanceRef.current < 5) {
          autoAdvanceRef.current += 1
          loadPage(next, stackParam, qParam, sizeParam)
          return
        }
        autoAdvanceRef.current = 0
        setGroups(items)
      })
      .catch((err) => {
        if (err instanceof ApiError) {
          // 400 cursor_invalid -> restart from first page if cursor was provided or stack was non-empty
          if (err.code === 'cursor_invalid' || (err.status === 400 && err.message.includes('cursor'))) {
            if (cursorParam || stackParam.length > 0) {
              notify('error', t('common.cursorInvalidNotice'))
              setCursor(undefined)
              setCursorStack([])
              loadPage(undefined, [], qParam, sizeParam)
              return
            }
          }
          setError({ message: err.message, code: err.code })
        } else {
          setError({ message: t('groups.loadFailed') })
        }
      })
  }

  useEffect(() => {
    const trimmed = query.trim()
    const timer = setTimeout(() => {
      setDebouncedQuery(trimmed)
    }, 200)
    return () => clearTimeout(timer)
  }, [query])

  useEffect(() => {
    if (!isMountedRef.current) {
      isMountedRef.current = true
      loadPage(undefined, [], debouncedQuery, pageSize)
      return
    }
    setCursor(undefined)
    setCursorStack([])
    loadPage(undefined, [], debouncedQuery, pageSize)
  }, [debouncedQuery])

  useEffect(() => {
    if (prevDnRef.current !== dn) {
      prevDnRef.current = dn
      setCursor(undefined)
      setCursorStack([])
      loadPage(undefined, [], debouncedQuery, pageSize)
    }
  }, [dn])

  // Re-read after a conflict or a lost response (keeps the current page).
  async function reread() {
    const { items } = await api.listGroups({
      limit: pageSize,
      cursor,
      q: debouncedQuery || undefined,
    })
    setGroups(items)
    return items
  }

  const handleNext = () => {
    if (!hasMore || !nextCursor) return
    const newStack = [...cursorStack, cursor]
    loadPage(nextCursor, newStack, debouncedQuery, pageSize)
  }

  const handlePrevious = () => {
    if (cursorStack.length === 0) return
    const prevCursor = cursorStack[cursorStack.length - 1]
    const newStack = cursorStack.slice(0, -1)
    loadPage(prevCursor, newStack, debouncedQuery, pageSize)
  }

  const handleFirst = () => {
    if (cursorStack.length === 0) return
    loadPage(undefined, [], debouncedQuery, pageSize)
  }

  const handlePageSizeChange = (newSize: number) => {
    setPageSize(newSize)
    setCursor(undefined)
    setCursorStack([])
    loadPage(undefined, [], debouncedQuery, newSize)
  }

  async function handleCreateOrUpdate(input: GroupFormInput) {
    if (editing) {
      const target = editing
      await write(
        {
          fingerprint: ['update', target.dn, input],
          etag: target.etag,
          discarded: describeChanges([
            ['cn', target.cn, input.cn],
            [t('common.description'), target.description, input.description],
          ]),
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
    setFormOpen(false)
    setEditing(null)
    loadPage(cursor, cursorStack, debouncedQuery, pageSize)
  }

  async function handleDelete() {
    if (!deleting) return
    const target = deleting
    await write(
      {
        fingerprint: ['delete', target.dn],
        etag: target.etag,
        onStale: reread,
      },
      (w) => api.deleteGroup(target.dn, w),
    )
    notify('success', t('groups.deletedToast', { cn: target.cn }))
    setDeleting(null)
    loadPage(cursor, cursorStack, debouncedQuery, pageSize)
  }

  async function handleSaveMembers(groupDn: string, members: string[]) {
    const group = groups?.find((g) => g.dn === groupDn)
    if (!group) return
    const previous = new Set(group.members)
    const next = new Set(members)
    await Promise.all([
      ...members.filter((memberDn) => !previous.has(memberDn)).map((memberDn) => api.addMember(groupDn, memberDn)),
      ...group.members.filter((memberDn) => !next.has(memberDn)).map((memberDn) => api.removeMember(groupDn, memberDn)),
    ])
    loadPage(cursor, cursorStack, debouncedQuery, pageSize)
  }

  function onRowKeyDown(e: React.KeyboardEvent<HTMLTableRowElement>, index: number) {
    if (e.target !== e.currentTarget || !groups) return
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      if (index + 1 < groups.length) rowRefs.current[index + 1]?.focus()
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      if (index - 1 >= 0) rowRefs.current[index - 1]?.focus()
    } else if (e.key === 'Enter') {
      e.preventDefault()
      setEditing(groups[index])
      setFormOpen(true)
    }
  }

  const currentPageNumber = cursorStack.length + 1
  const showPagination = !error && groups !== null && (groups.length > 0 || hasMore || cursorStack.length > 0)

  return (
    <div className="max-w-6xl space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="relative w-full sm:w-72">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            aria-label={t('groups.filterPlaceholder')}
            placeholder={t('groups.filterPlaceholder')}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
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
            {groups && <span className="font-mono text-xs font-normal text-muted-foreground">{groups.length}</span>}
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {error && (
            <ErrorState
              message={error.message}
              hint={error.code === 'size_limit_exceeded' ? t('common.sizeLimitHint') : undefined}
              onRetry={
                error.code === 'scan_timeout' || error.code === 'unavailable'
                  ? () => loadPage(cursor, cursorStack, debouncedQuery, pageSize)
                  : () => loadPage(undefined, [], debouncedQuery, pageSize)
              }
            />
          )}
          {!error && groups === null && (
            <div className="flex items-center gap-2 px-4 py-6 text-[13px] text-muted-foreground">
              <Spinner /> {t('groups.loading')}
            </div>
          )}
          {!error && groups?.length === 0 && !hasMore && cursorStack.length === 0 && (
            debouncedQuery ? (
              <EmptyState
                icon={Search}
                title={t('common.noMatches')}
                description={t('common.noMatchesDescription', { query: debouncedQuery })}
              />
            ) : (
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
            )
          )}
          {!error && groups && groups.length === 0 && (hasMore || cursorStack.length > 0) && (
            <div className="p-6 text-center text-[13px] text-muted-foreground">
              {t('common.emptyPageWithMore')}
            </div>
          )}
          {!error && groups && groups.length > 0 && (
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
                {groups.map((g, i) => (
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
          {showPagination && (
            <GroupPagination
              page={currentPageNumber}
              pageSize={pageSize}
              hasMore={hasMore}
              canPrevious={cursorStack.length > 0}
              onNext={handleNext}
              onPrevious={handlePrevious}
              onFirst={handleFirst}
              onPageSize={handlePageSizeChange}
              navAriaLabel={t('groups.paginationNavigation')}
            />
          )}
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
