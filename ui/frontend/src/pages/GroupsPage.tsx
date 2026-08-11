import { useEffect, useMemo, useRef, useState } from 'react'
import { Pencil, Plus, Search, Trash2, Users2 } from 'lucide-react'
import { api, ApiError } from '@/lib/api'
import type { Group, GroupFormInput } from '@/lib/types'
import { useToast } from '@/context/ToastContext'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeadCell, TableRow } from '@/components/ui/table'
import { EmptyState, ErrorState, Spinner } from '@/components/ui/empty-state'
import { ConfirmDialog } from '@/components/ui/confirm-dialog'
import { GroupFormDialog } from '@/components/groups/GroupFormDialog'
import { MembersDialog } from '@/components/groups/MembersDialog'

export function GroupsPage() {
  const { notify } = useToast()
  const [groups, setGroups] = useState<Group[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [query, setQuery] = useState('')

  const [formOpen, setFormOpen] = useState(false)
  const [editing, setEditing] = useState<Group | null>(null)
  const [membersGroup, setMembersGroup] = useState<Group | null>(null)
  const [deleting, setDeleting] = useState<Group | null>(null)

  const rowRefs = useRef<Array<HTMLTableRowElement | null>>([])

  function load() {
    setError(null)
    api
      .listGroups()
      .then(setGroups)
      .catch((err) => setError(err instanceof ApiError ? err.message : 'Failed to load groups'))
  }

  useEffect(load, [])

  const filtered = useMemo(() => {
    if (!groups) return []
    const q = query.trim().toLowerCase()
    if (!q) return groups
    return groups.filter((g) => g.cn.toLowerCase().includes(q) || g.description?.toLowerCase().includes(q))
  }, [groups, query])

  async function handleCreateOrUpdate(input: GroupFormInput) {
    if (editing) {
      await api.updateGroup({ ...input, dn: editing.dn })
      notify('success', `Updated ${input.cn}`)
    } else {
      await api.createGroup(input)
      notify('success', `Created group ${input.cn}`)
    }
    load()
  }

  async function handleDelete() {
    if (!deleting) return
    await api.deleteGroup(deleting.dn)
    notify('success', `Deleted ${deleting.cn}`)
    setDeleting(null)
    load()
  }

  async function handleAddMember(groupDn: string, memberDn: string) {
    await api.addMember(groupDn, memberDn)
    load()
  }

  async function handleRemoveMember(groupDn: string, memberDn: string) {
    await api.removeMember(groupDn, memberDn)
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
            placeholder="Filter groups…"
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
          New group
        </Button>
      </div>

      <Card className="overflow-hidden">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Users2 className="size-4 text-accent" />
            Groups
            {groups && <span className="font-mono text-xs font-normal text-muted-foreground">{filtered.length}</span>}
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {error && <ErrorState message={error} onRetry={load} />}
          {!error && groups === null && (
            <div className="flex items-center gap-2 px-4 py-6 text-[13px] text-muted-foreground">
              <Spinner /> Loading groups…
            </div>
          )}
          {groups?.length === 0 && (
            <EmptyState
              icon={Users2}
              title="No groups yet"
              description="Create the first group to start organizing access."
              action={
                <Button size="sm" onClick={() => setFormOpen(true)}>
                  <Plus className="size-4" /> New group
                </Button>
              }
            />
          )}
          {!!groups?.length && filtered.length === 0 && (
            <EmptyState icon={Search} title="No matches" description={`Nothing matches "${query}".`} />
          )}
          {filtered.length > 0 && (
            <Table>
              <TableHead>
                <tr>
                  <TableHeadCell>cn</TableHeadCell>
                  <TableHeadCell>Description</TableHeadCell>
                  <TableHeadCell>Members</TableHeadCell>
                  <TableHeadCell className="text-right">Actions</TableHeadCell>
                </tr>
              </TableHead>
              <TableBody>
                {filtered.map((g, i) => (
                  <TableRow
                    key={g.dn}
                    ref={(el) => {
                      rowRefs.current[i] = el
                    }}
                    tabIndex={0}
                    onKeyDown={(e) => onRowKeyDown(e, i)}
                    className="focus-visible:bg-muted focus-visible:outline-none"
                  >
                    <TableCell className="font-mono">{g.cn}</TableCell>
                    <TableCell className="text-muted-foreground">{g.description || '—'}</TableCell>
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
                          title="Manage members"
                          onClick={() => setMembersGroup(g)}
                        >
                          <Users2 className="size-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          title="Edit"
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
                          title="Delete"
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
        </CardContent>
      </Card>

      <GroupFormDialog open={formOpen} onOpenChange={setFormOpen} group={editing} onSubmit={handleCreateOrUpdate} />
      <MembersDialog
        open={!!membersGroup}
        onOpenChange={(o) => !o && setMembersGroup(null)}
        group={membersGroup}
        onAdd={handleAddMember}
        onRemove={handleRemoveMember}
      />
      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title="Delete group"
        description={`This permanently removes ${deleting?.dn ?? 'this entry'} from the directory.`}
        requireText={deleting?.cn}
        onConfirm={handleDelete}
      />
    </div>
  )
}
