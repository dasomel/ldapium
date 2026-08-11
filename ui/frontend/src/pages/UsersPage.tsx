import { useEffect, useMemo, useRef, useState } from 'react'
import { KeyRound, Pencil, Plus, Search, Trash2, UserRound } from 'lucide-react'
import { api, ApiError } from '@/lib/api'
import type { User, UserFormInput } from '@/lib/types'
import { useToast } from '@/context/ToastContext'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeadCell, TableRow } from '@/components/ui/table'
import { EmptyState, ErrorState, Spinner } from '@/components/ui/empty-state'
import { ConfirmDialog } from '@/components/ui/confirm-dialog'
import { UserFormDialog } from '@/components/users/UserFormDialog'
import { SetPasswordDialog } from '@/components/users/SetPasswordDialog'

export function UsersPage() {
  const { notify } = useToast()
  const [users, setUsers] = useState<User[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [query, setQuery] = useState('')

  const [formOpen, setFormOpen] = useState(false)
  const [editing, setEditing] = useState<User | null>(null)
  const [passwordUser, setPasswordUser] = useState<User | null>(null)
  const [deleting, setDeleting] = useState<User | null>(null)

  const rowRefs = useRef<Array<HTMLTableRowElement | null>>([])

  function load() {
    setError(null)
    api
      .listUsers()
      .then(setUsers)
      .catch((err) => setError(err instanceof ApiError ? err.message : 'Failed to load users'))
  }

  useEffect(load, [])

  const filtered = useMemo(() => {
    if (!users) return []
    const q = query.trim().toLowerCase()
    if (!q) return users
    return users.filter((u) =>
      [u.uid, u.cn, u.mail, u.displayName].some((v) => v?.toLowerCase().includes(q)),
    )
  }, [users, query])

  async function handleCreateOrUpdate(input: UserFormInput) {
    if (editing) {
      await api.updateUser({ ...input, dn: editing.dn })
      notify('success', `Updated ${input.uid || editing.uid}`)
    } else {
      await api.createUser(input)
      notify('success', `Created user ${input.uid}`)
    }
    load()
  }

  async function handleSetPassword(dn: string, password: string) {
    const res = await api.setPassword(dn, password || undefined)
    notify('success', 'Password updated')
    return res.generatedPassword
  }

  async function handleDelete() {
    if (!deleting) return
    await api.deleteUser(deleting.dn)
    notify('success', `Deleted ${deleting.uid}`)
    setDeleting(null)
    load()
  }

  function onRowKeyDown(e: React.KeyboardEvent<HTMLTableRowElement>, index: number) {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      rowRefs.current[index + 1]?.focus()
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      rowRefs.current[index - 1]?.focus()
    } else if (e.key === 'Enter') {
      setEditing(filtered[index])
      setFormOpen(true)
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <div className="relative w-72">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Filter users…"
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
          New user
        </Button>
      </div>

      <Card className="overflow-hidden">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <UserRound className="size-4 text-accent" />
            Users
            {users && <span className="font-mono text-xs font-normal text-muted-foreground">{filtered.length}</span>}
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {error && <ErrorState message={error} onRetry={load} />}
          {!error && users === null && (
            <div className="flex items-center gap-2 px-4 py-6 text-[13px] text-muted-foreground">
              <Spinner /> Loading users…
            </div>
          )}
          {users?.length === 0 && (
            <EmptyState
              icon={UserRound}
              title="No users yet"
              description="Create the first directory user to get started."
              action={
                <Button size="sm" onClick={() => setFormOpen(true)}>
                  <Plus className="size-4" /> New user
                </Button>
              }
            />
          )}
          {!!users?.length && filtered.length === 0 && (
            <EmptyState icon={Search} title="No matches" description={`Nothing matches "${query}".`} />
          )}
          {filtered.length > 0 && (
            <Table>
              <TableHead>
                <tr>
                  <TableHeadCell>uid</TableHeadCell>
                  <TableHeadCell>Name</TableHeadCell>
                  <TableHeadCell>Mail</TableHeadCell>
                  <TableHeadCell className="text-right">Actions</TableHeadCell>
                </tr>
              </TableHead>
              <TableBody>
                {filtered.map((u, i) => (
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
                      <div className="flex justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          title="Edit"
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
                          title="Set password"
                          onClick={() => setPasswordUser(u)}
                        >
                          <KeyRound className="size-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          title="Delete"
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
        </CardContent>
      </Card>

      <UserFormDialog open={formOpen} onOpenChange={setFormOpen} user={editing} onSubmit={handleCreateOrUpdate} />
      <SetPasswordDialog
        open={!!passwordUser}
        onOpenChange={(o) => !o && setPasswordUser(null)}
        user={passwordUser}
        onSubmit={handleSetPassword}
      />
      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title="Delete user"
        description={`This permanently removes ${deleting?.dn ?? 'this entry'} from the directory.`}
        requireText={deleting?.uid}
        onConfirm={handleDelete}
      />
    </div>
  )
}
