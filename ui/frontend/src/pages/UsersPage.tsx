import { useEffect, useRef, useState } from 'react'
import { CircleAlert, KeyRound, Lock, Pencil, Plus, Search, Trash2, Unlock, UserRound, X } from 'lucide-react'
import { api, ApiError } from '@/lib/api'
import { describeChanges, useWriteAttempt } from '@/lib/useWriteAttempt'
import type { User, UserFormInput } from '@/lib/types'
import { useToast } from '@/context/ToastContext'
import { useAuth } from '@/context/AuthContext'
import { useLanguage } from '@/context/LanguageContext'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeadCell, TableRow } from '@/components/ui/table'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { EmptyState, ErrorState, Spinner } from '@/components/ui/empty-state'
import { ConfirmDialog } from '@/components/ui/confirm-dialog'
import { UserFormDialog } from '@/components/users/UserFormDialog'
import { SetPasswordDialog } from '@/components/users/SetPasswordDialog'
import { MemberOfDialog } from '@/components/users/MemberOfDialog'
import { GroupPagination } from '@/components/groups/GroupPagination'

const MAX_EMPTY_ADVANCES = 20

export function UsersPage() {
  const { notify } = useToast()
  const { dn } = useAuth()
  const { language, t } = useLanguage()
  const write = useWriteAttempt()

  const [users, setUsers] = useState<User[] | null>(null)
  const [error, setError] = useState<{ message: string; code?: string } | null>(null)
  const [query, setQuery] = useState('')
  const [debouncedQuery, setDebouncedQuery] = useState('')
  const [cursor, setCursor] = useState<string | undefined>(undefined)
  const [cursorStack, setCursorStack] = useState<Array<string | undefined>>([])
  const [hasMore, setHasMore] = useState(false)
  const [nextCursor, setNextCursor] = useState<string | undefined>(undefined)
  const [pageSize, setPageSize] = useState(10)
  const [scanCapped, setScanCapped] = useState(false)

  const [formOpen, setFormOpen] = useState(false)
  const [editing, setEditing] = useState<User | null>(null)
  const [passwordUser, setPasswordUser] = useState<User | null>(null)
  const [deleting, setDeleting] = useState<User | null>(null)
  const [memberOfUser, setMemberOfUser] = useState<User | null>(null)

  const requestGenRef = useRef(0)
  // False while unmounted: late write/retry callbacks must not start new requests.
  const aliveRef = useRef(true)
  const lastRequestRef = useRef<{
    cursorParam?: string
    stackParam: Array<string | undefined>
    qParam: string
    sizeParam: number
  } | null>(null)
  const prevDnRef = useRef(dn)
  const isMountedRef = useRef(false)
  const rowRefs = useRef<Array<HTMLTableRowElement | null>>([])
  // Latest view (cursor/stack/q/limit), refreshed every render: async write
  // callbacks close over stale state, so they read the view from here instead.
  const viewRef = useRef({ cursor, cursorStack, q: debouncedQuery, pageSize })
  viewRef.current = { cursor, cursorStack, q: debouncedQuery, pageSize }

  // Every request takes a generation; a response (or error) whose generation
  // is no longer current is dropped, so a slow older request cannot overwrite
  // newer rows or the cursor stack, and unmount invalidates everything.
  function loadPage(
    cursorParam?: string,
    stackParam: Array<string | undefined> = cursorStack,
    qParam = debouncedQuery,
    sizeParam = pageSize,
    advances = 0,
  ) {
    if (!aliveRef.current) return
    const gen = ++requestGenRef.current
    lastRequestRef.current = { cursorParam, stackParam, qParam, sizeParam }
    setError(null)
    if (advances === 0) setScanCapped(false)
    api
      .listUsers({ limit: sizeParam, cursor: cursorParam, q: qParam || undefined })
      .then(({ items, hasMore: more, nextCursor: next }) => {
        if (gen !== requestGenRef.current) return
        const hasMoreBool = Boolean(more)
        setHasMore(hasMoreBool)
        setNextCursor(next)
        setCursor(cursorParam)
        setCursorStack(stackParam)

        // Empty page with hasMore: true -> auto-advance per CHANGE.md, bounded
        if (items.length === 0 && hasMoreBool && next) {
          if (advances < MAX_EMPTY_ADVANCES) {
            loadPage(next, stackParam, qParam, sizeParam, advances + 1)
            return
          }
          setScanCapped(true)
        }
        setUsers(items)
      })
      .catch((err) => {
        if (gen !== requestGenRef.current) return
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
          setError({ message: t('users.loadFailed') })
        }
      })
  }

  // Retry re-issues the request that failed (same cursor, q, limit).
  function retryLast() {
    const r = lastRequestRef.current
    if (r) loadPage(r.cursorParam, r.stackParam, r.qParam, r.sizeParam)
  }

  useEffect(() => {
    aliveRef.current = true
    return () => {
      aliveRef.current = false
      requestGenRef.current++
    }
  }, [])

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

  // Re-read after a conflict or a lost response (keeps current page).
  async function reread() {
    if (!aliveRef.current) return []
    const gen = requestGenRef.current
    const startQ = viewRef.current.q
    const v = viewRef.current
    const { items } = await api.listUsers({
      limit: v.pageSize,
      cursor: v.cursor,
      q: startQ || undefined,
    })
    if (gen === requestGenRef.current && viewRef.current.q === startQ) setUsers(items)
    return items
  }

  // Post-write refresh: always the CURRENT view, and skipped entirely when the
  // query changed since the write began (the new query already loads its own page).
  function refreshAfterWrite(startQ: string) {
    const v = viewRef.current
    if (v.q !== startQ) return
    loadPage(v.cursor, v.cursorStack, v.q, v.pageSize)
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

  async function handleCreateOrUpdate(input: UserFormInput) {
    const startQ = viewRef.current.q
    if (editing) {
      const target = editing
      await write(
        {
          fingerprint: ['update', target.dn, input],
          etag: target.etag,
          discarded: describeChanges([
            ['cn', target.cn, input.cn],
            ['sn', target.sn, input.sn],
            ['mail', target.mail, input.mail],
            [t('userForm.givenNameLabel'), target.givenName, input.givenName],
            [t('userForm.organizationalUnitLabel'), target.organizationalUnit, input.organizationalUnit],
            [t('userForm.departmentLabel'), target.department, input.department],
            [t('userForm.organizationLabel'), target.organization, input.organization],
          ]),
          onStale: async () => {
            const fresh = (await reread()).find((u) => u.dn === target.dn)
            if (fresh) setEditing(fresh)
          },
        },
        (w) => api.updateUser({ ...input, dn: target.dn }, w),
      )
      notify('success', t('users.updatedToast', { name: input.uid || target.uid }))
    } else {
      await write({ fingerprint: ['create', input] }, (w) => api.createUser(input, w))
      notify('success', t('users.createdToast', { uid: input.uid }))
    }
    setFormOpen(false)
    setEditing(null)
    refreshAfterWrite(startQ)
  }

  async function handleSetPassword(dn: string, password: string) {
    const res = await api.setPassword(dn, password || undefined)
    notify('success', t('users.passwordUpdatedToast'))
    reread().catch(() => undefined)
    return res.generatedPassword
  }

  async function handleDelete() {
    const startQ = viewRef.current.q
    if (!deleting) return
    const target = deleting
    try {
      await write({ fingerprint: ['delete', target.dn], etag: target.etag, onStale: reread }, (w) =>
        api.deleteUser(target.dn, w),
      )
    } catch (err) {
      if (!(err instanceof ApiError)) throw err
      notify('error', err.message)
      return
    }
    notify('success', t('users.deletedToast', { uid: target.uid }))
    setDeleting(null)
    refreshAfterWrite(startQ)
  }

  async function handleUnlock(u: User) {
    const startQ = viewRef.current.q
    try {
      await api.unlockUser(u.dn)
      notify('success', t('users.unlockedToast', { uid: u.uid }))
      refreshAfterWrite(startQ)
    } catch (err) {
      notify('error', err instanceof ApiError ? err.message : t('users.unlockFailedToast', { uid: u.uid }))
    }
  }

  async function handleLock(u: User) {
    const startQ = viewRef.current.q
    try {
      await api.lockUser(u.dn)
      notify('success', t('users.lockedToast', { uid: u.uid }))
      refreshAfterWrite(startQ)
    } catch (err) {
      notify('error', err instanceof ApiError ? err.message : t('users.lockFailedToast', { uid: u.uid }))
    }
  }

  function onRowKeyDown(e: React.KeyboardEvent<HTMLTableRowElement>, index: number) {
    if (e.target !== e.currentTarget || !users) return
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      if (index + 1 < users.length) rowRefs.current[index + 1]?.focus()
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      if (index - 1 >= 0) rowRefs.current[index - 1]?.focus()
    } else if (e.key === 'Enter') {
      e.preventDefault()
      setEditing(users[index])
      setFormOpen(true)
    }
  }

  const currentPageNumber = cursorStack.length + 1
  const showPagination = !error && users !== null && (users.length > 0 || hasMore || cursorStack.length > 0)

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="relative w-full sm:w-72">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            aria-label={t('users.filterPlaceholder')}
            placeholder={t('users.filterPlaceholder')}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="pl-8 pr-8"
          />
          {query && (
            <button
              type="button"
              onClick={() => {
                setQuery('')
                setDebouncedQuery('')
              }}
              title={t('users.clearFilter')}
              className="absolute right-1.5 top-1/2 rounded-console p-1.5 -translate-y-1/2 text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              <X className="size-3.5" />
              <span className="sr-only">{t('users.clearFilter')}</span>
            </button>
          )}
        </div>
        <Button
          onClick={() => {
            setEditing(null)
            setFormOpen(true)
          }}
        >
          <Plus className="size-4" />
          {t('users.newUserButton')}
        </Button>
      </div>

      <Card className="overflow-hidden">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <UserRound className="size-4 text-accent" />
            {t('users.title')}
            {users && (
              <span className="font-mono text-xs font-normal text-muted-foreground">
                {users.length}
              </span>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {error && (
            <ErrorState
              message={error.message}
              hint={error.code === 'size_limit_exceeded' ? t('common.sizeLimitHint') : undefined}
              onRetry={
                error.code === 'scan_timeout' || error.code === 'unavailable'
                  ? retryLast
                  : () => loadPage(undefined, [], debouncedQuery, pageSize)
              }
            />
          )}
          {!error && users === null && (
            <div className="flex items-center gap-2 px-4 py-6 text-[13px] text-muted-foreground">
              <Spinner /> {t('users.loading')}
            </div>
          )}
          {!error && users?.length === 0 && !hasMore && cursorStack.length === 0 && (
            debouncedQuery ? (
              <EmptyState
                icon={Search}
                title={t('common.noMatches')}
                description={t('common.noMatchesDescription', { query: debouncedQuery })}
              />
            ) : (
              <EmptyState
                icon={UserRound}
                title={t('users.emptyTitle')}
                description={t('users.emptyDescription')}
                action={
                  <Button size="sm" onClick={() => setFormOpen(true)}>
                    <Plus className="size-4" /> {t('users.newUserButton')}
                  </Button>
                }
              />
            )
          )}
          {!error && users && users.length === 0 && (hasMore || cursorStack.length > 0) && (
            <div className="p-6 text-center text-[13px] text-muted-foreground">
              {scanCapped ? t('common.emptyScanCapped') : t('common.emptyPageWithMore')}
            </div>
          )}
          {!error && users && users.length > 0 && (
            <Table>
              <TableHead>
                <tr>
                  <TableHeadCell>uid</TableHeadCell>
                  <TableHeadCell>{t('users.colName')}</TableHeadCell>
                  <TableHeadCell>{t('users.colMail')}</TableHeadCell>
                  <TableHeadCell>{t('nav.groups')}</TableHeadCell>
                  <TableHeadCell>
                    <div className="flex items-center gap-1">
                      {t('users.colStatus')}
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <button
                            type="button"
                            aria-label={t('users.statusHelpLabel')}
                            className="inline-flex size-4 items-center justify-center rounded-full text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                          >
                            <CircleAlert className="size-3.5" />
                          </button>
                        </TooltipTrigger>
                        <TooltipContent className="max-w-sm">
                          <div className="space-y-2">
                            <p>
                              <strong>{t('users.statusUnlockedTitle')}</strong> — {t('users.statusUnlockedDescription')}
                            </p>
                            <p>
                              <strong>{t('users.lockedBadge')}</strong> — {t('users.statusLockedDescription')}
                            </p>
                          </div>
                        </TooltipContent>
                      </Tooltip>
                    </div>
                  </TableHeadCell>
                  <TableHeadCell className="text-right">{t('common.actions')}</TableHeadCell>
                </tr>
              </TableHead>
              <TableBody>
                {users.map((u, i) => (
                  <TableRow
                    key={u.dn}
                    ref={(el) => {
                      rowRefs.current[i] = el
                    }}
                    tabIndex={0}
                    onKeyDown={(e) => onRowKeyDown(e, i)}
                    className="focus-visible:bg-muted focus-visible:outline-none"
                  >
                    <TableCell className="font-mono">{u.uid}</TableCell>
                    <TableCell>{u.cn}</TableCell>
                    <TableCell className="text-muted-foreground">{u.mail || '—'}</TableCell>
                    <TableCell>
                      {u.memberOf?.length ? (
                        <button onClick={() => setMemberOfUser(u)} className="hover:underline">
                          <Badge variant="accent">{u.memberOf.length}</Badge>
                        </button>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell>
                      {u.locked ? (
                        <Badge variant="danger" className="gap-1">
                          <Lock className="size-3" />
                          {t('users.lockedBadge')}
                        </Badge>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <div className="flex justify-end gap-1">
                        {u.locked ? (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Button
                                variant="ghost"
                                size="icon"
                                aria-label={t('users.unlockTitle')}
                                onClick={() => handleUnlock(u)}
                              >
                                <Unlock className="size-3.5" />
                              </Button>
                            </TooltipTrigger>
                            <TooltipContent>
                              {t('users.unlockTitle')}
                              {u.lockedAt && ` · ${new Date(u.lockedAt).toLocaleString(language === 'ko' ? 'ko-KR' : 'en-US')}`}
                            </TooltipContent>
                          </Tooltip>
                        ) : (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Button
                                variant="ghost"
                                size="icon"
                                aria-label={t('users.lockTitle')}
                                onClick={() => handleLock(u)}
                              >
                                <Lock className="size-3.5" />
                              </Button>
                            </TooltipTrigger>
                            <TooltipContent>{t('users.lockTitle')}</TooltipContent>
                          </Tooltip>
                        )}
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button
                              variant="ghost"
                              size="icon"
                              aria-label={t('common.edit')}
                              onClick={() => {
                                setEditing(u)
                                setFormOpen(true)
                              }}
                            >
                              <Pencil className="size-3.5" />
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent>{t('common.edit')}</TooltipContent>
                        </Tooltip>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button
                              variant="ghost"
                              size="icon"
                              aria-label={t('setPasswordDialog.title')}
                              onClick={() => setPasswordUser(u)}
                            >
                              <KeyRound className="size-3.5" />
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent>{t('setPasswordDialog.title')}</TooltipContent>
                        </Tooltip>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button
                              variant="ghost"
                              size="icon"
                              aria-label={t('common.delete')}
                              className="hover:bg-danger/10 hover:text-danger"
                              onClick={() => setDeleting(u)}
                            >
                              <Trash2 className="size-3.5" />
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent>{t('common.delete')}</TooltipContent>
                        </Tooltip>
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
              navAriaLabel={t('users.paginationNavigation')}
            />
          )}
        </CardContent>
      </Card>

      <UserFormDialog open={formOpen} onOpenChange={setFormOpen} user={editing} onSubmit={handleCreateOrUpdate} />
      <MemberOfDialog open={!!memberOfUser} onOpenChange={(o) => !o && setMemberOfUser(null)} user={memberOfUser} />
      <SetPasswordDialog
        open={!!passwordUser}
        onOpenChange={(o) => !o && setPasswordUser(null)}
        user={passwordUser}
        onSubmit={handleSetPassword}
      />
      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title={t('users.deleteTitle')}
        description={t('users.deleteDescription', { dn: deleting?.dn ?? t('common.thisEntry') })}
        requireText={deleting?.uid}
        onConfirm={handleDelete}
      />
    </div>
  )
}
