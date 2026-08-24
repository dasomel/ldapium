import { useEffect, useMemo, useRef, useState } from 'react'
import { ChevronsLeft, ChevronsRight, KeyRound, Lock, Pencil, Plus, Search, Trash2, Unlock, UserRound, X } from 'lucide-react'
import { api, ApiError } from '@/lib/api'
import type { User, UserFormInput } from '@/lib/types'
import { useToast } from '@/context/ToastContext'
import { useLanguage } from '@/context/LanguageContext'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeadCell, TableRow } from '@/components/ui/table'
import { EmptyState, ErrorState, Spinner } from '@/components/ui/empty-state'
import { ConfirmDialog } from '@/components/ui/confirm-dialog'
import { UserFormDialog } from '@/components/users/UserFormDialog'
import { SetPasswordDialog } from '@/components/users/SetPasswordDialog'
import { MemberOfDialog } from '@/components/users/MemberOfDialog'

const PAGE_SIZES = [10, 20, 50, 100]
const PAGE_WINDOW_SIZE = 10

export function UsersPage() {
  const { notify } = useToast()
  const { language, t } = useLanguage()
  const [users, setUsers] = useState<User[] | null>(null)
  const [truncated, setTruncated] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [query, setQuery] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)

  const [formOpen, setFormOpen] = useState(false)
  const [editing, setEditing] = useState<User | null>(null)
  const [passwordUser, setPasswordUser] = useState<User | null>(null)
  const [deleting, setDeleting] = useState<User | null>(null)
  const [memberOfUser, setMemberOfUser] = useState<User | null>(null)

  const rowRefs = useRef<Array<HTMLTableRowElement | null>>([])

  function load() {
    setError(null)
    api
      .listUsers()
      .then(({ items, truncated }) => {
        setUsers(items)
        setTruncated(truncated)
        setPage(1)
      })
      .catch((err) => setError(err instanceof ApiError ? err.message : t('users.loadFailed')))
  }

  useEffect(load, [])

  const filtered = useMemo(() => {
    if (!users) return []
    const q = query.trim().toLowerCase()
    if (!q) return users
    return users.filter((u) =>
      [u.uid, u.cn, u.mail, u.displayName, u.department, u.organization, u.organizationalUnit].some((v) =>
        v?.toLowerCase().includes(q),
      ),
    )
  }, [users, query])

  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize))
  const currentPage = Math.min(page, pageCount)
  const pageUsers = filtered.slice((currentPage - 1) * pageSize, currentPage * pageSize)
  const pageNumbers = useMemo(() => {
    const visiblePages = Math.min(PAGE_WINDOW_SIZE, pageCount)
    const firstPage = Math.floor((currentPage - 1) / visiblePages) * visiblePages + 1
    return Array.from({ length: Math.min(visiblePages, pageCount - firstPage + 1) }, (_, index) => firstPage + index)
  }, [currentPage, pageCount])

  useEffect(() => {
    setPage(1)
  }, [query])

  async function handleCreateOrUpdate(input: UserFormInput) {
    if (editing) {
      await api.updateUser({ ...input, dn: editing.dn })
      notify('success', t('users.updatedToast', { name: input.uid || editing.uid }))
    } else {
      await api.createUser(input)
      notify('success', t('users.createdToast', { uid: input.uid }))
    }
    load()
  }

  async function handleSetPassword(dn: string, password: string) {
    const res = await api.setPassword(dn, password || undefined)
    notify('success', t('users.passwordUpdatedToast'))
    return res.generatedPassword
  }

  async function handleDelete() {
    if (!deleting) return
    await api.deleteUser(deleting.dn)
    notify('success', t('users.deletedToast', { uid: deleting.uid }))
    setDeleting(null)
    load()
  }

  // Not run through ConfirmDialog: unlocking isn't destructive (it can't
  // lose data — the account was working fine before it got locked out),
  // so it gets the same one-click treatment as Edit and Set password
  // rather than the retype-to-confirm flow reserved for deletes.
  async function handleUnlock(u: User) {
    try {
      await api.unlockUser(u.dn)
      notify('success', t('users.unlockedToast', { uid: u.uid }))
      load()
    } catch (err) {
      notify('error', err instanceof ApiError ? err.message : t('users.unlockFailedToast', { uid: u.uid }))
    }
  }

  function onRowKeyDown(e: React.KeyboardEvent<HTMLTableRowElement>, index: number) {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      rowRefs.current[index + 1]?.focus()
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      rowRefs.current[index - 1]?.focus()
    } else if (e.key === 'Enter') {
      setEditing(pageUsers[index])
      setFormOpen(true)
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <div className="relative w-72">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder={t('users.filterPlaceholder')}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="pl-8 pr-8"
          />
          {query && (
            <button
              type="button"
              onClick={() => setQuery('')}
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
                {t('users.totalCount', { count: filtered.length })}
              </span>
            )}
          </CardTitle>
        </CardHeader>
        {truncated && (
          <div className="border-b border-border bg-accent-muted px-4 py-2 text-[12.5px] text-accent">
            {t('users.truncatedBanner', { n: users?.length ?? 0 })}
          </div>
        )}
        <CardContent className="p-0">
          {error && <ErrorState message={error} onRetry={load} />}
          {!error && users === null && (
            <div className="flex items-center gap-2 px-4 py-6 text-[13px] text-muted-foreground">
              <Spinner /> {t('users.loading')}
            </div>
          )}
          {users?.length === 0 && (
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
          )}
          {!!users?.length && filtered.length === 0 && (
            <EmptyState icon={Search} title={t('common.noMatches')} description={t('common.noMatchesDescription', { query })} />
          )}
          {filtered.length > 0 && (
            <Table>
              <TableHead>
                <tr>
                  <TableHeadCell>uid</TableHeadCell>
                  <TableHeadCell>{t('users.colName')}</TableHeadCell>
                  <TableHeadCell>{t('users.colMail')}</TableHeadCell>
                  <TableHeadCell>{t('nav.groups')}</TableHeadCell>
                  <TableHeadCell>{t('users.colStatus')}</TableHeadCell>
                  <TableHeadCell className="text-right">{t('common.actions')}</TableHeadCell>
                </tr>
              </TableHead>
              <TableBody>
                {pageUsers.map((u, i) => (
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
                        <Badge
                          variant="danger"
                          className="gap-1"
                          title={
                            u.lockedAt
                              ? t('users.lockedSince', {
                                  date: new Date(u.lockedAt).toLocaleString(language === 'ko' ? 'ko-KR' : 'en-US'),
                                })
                              : t('users.lockedBadge')
                          }
                        >
                          <Lock className="size-3" />
                          {t('users.lockedBadge')}
                        </Badge>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <div className="flex justify-end gap-1">
                        {u.locked && (
                          <Button
                            variant="ghost"
                            size="icon"
                            title={t('users.unlockTitle')}
                            onClick={() => handleUnlock(u)}
                          >
                            <Unlock className="size-3.5" />
                          </Button>
                        )}
                        <Button
                          variant="ghost"
                          size="icon"
                          title={t('common.edit')}
                          onClick={() => {
                            setEditing(u)
                            setFormOpen(true)
                          }}
                        >
                          <Pencil className="size-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          title={t('setPasswordDialog.title')}
                          onClick={() => setPasswordUser(u)}
                        >
                          <KeyRound className="size-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          title={t('common.delete')}
                          className="hover:bg-danger/10 hover:text-danger"
                          onClick={() => setDeleting(u)}
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
          {filtered.length > 0 && (
            <div className="grid grid-cols-[1fr_auto_1fr] items-center gap-3 border-t border-border px-4 py-3">
              <div className="flex items-center gap-2">
                <label className="flex items-center gap-2 text-[12.5px] text-muted-foreground">
                  {t('users.rowsPerPage')}
                  <select
                    value={pageSize}
                    onChange={(e) => {
                      setPageSize(Number(e.target.value))
                      setPage(1)
                    }}
                    className="h-8 rounded-console border border-input bg-surface px-2 text-[12.5px] text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                  >
                    {PAGE_SIZES.map((size) => (
                      <option key={size} value={size}>
                        {size}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
              <nav className="flex items-center gap-2" aria-label={t('users.paginationNavigation')}>
                <Button
                  variant="outline"
                  size="icon"
                  disabled={currentPage === 1}
                  onClick={() => setPage(1)}
                  title={t('users.firstPage')}
                >
                  <ChevronsLeft className="size-4" />
                </Button>
                <Button
                  variant="outline"
                  size="icon"
                  disabled={currentPage === 1}
                  onClick={() => setPage(Math.max(1, pageNumbers[0] - 1))}
                  title={t('users.previousPage')}
                >
                  &lt;
                </Button>
                {pageNumbers.map((pageNumber) => (
                  <Button
                    key={pageNumber}
                    variant={pageNumber === currentPage ? 'subtle' : 'outline'}
                    size="icon"
                    onClick={() => setPage(pageNumber)}
                    aria-current={pageNumber === currentPage ? 'page' : undefined}
                    title={t('users.pageNumber', { page: pageNumber })}
                  >
                    {pageNumber}
                  </Button>
                ))}
                <Button
                  variant="outline"
                  size="icon"
                  disabled={currentPage === pageCount}
                  onClick={() => setPage(Math.min(pageCount, pageNumbers[pageNumbers.length - 1] + 1))}
                  title={t('users.nextPage')}
                >
                  &gt;
                </Button>
                <Button
                  variant="outline"
                  size="icon"
                  disabled={currentPage === pageCount}
                  onClick={() => setPage(pageCount)}
                  title={t('users.lastPage')}
                >
                  <ChevronsRight className="size-4" />
                </Button>
              </nav>
              <span className="justify-self-end text-[12.5px] text-muted-foreground">
                {t('users.paginationSummary', {
                  from: (currentPage - 1) * pageSize + 1,
                  to: Math.min(currentPage * pageSize, filtered.length),
                  total: filtered.length,
                })}
              </span>
            </div>
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
