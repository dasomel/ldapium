import { useEffect, useState } from 'react'
import { FileSearch, FolderTree, Loader2 } from 'lucide-react'
import { api, ApiError } from '@/lib/api'
import type { Entry, TreeNode } from '@/lib/types'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { EmptyState, ErrorState, Spinner } from '@/components/ui/empty-state'
import { TreeNodeRow } from '@/components/tree/TreeNodeRow'

export function TreePage() {
  const [roots, setRoots] = useState<TreeNode[] | null>(null)
  const [rootError, setRootError] = useState<string | null>(null)
  const [selectedDn, setSelectedDn] = useState<string | null>(null)
  const [entry, setEntry] = useState<Entry | null>(null)
  const [entryLoading, setEntryLoading] = useState(false)
  const [entryError, setEntryError] = useState<string | null>(null)

  useEffect(() => {
    loadRoots()
  }, [])

  function loadRoots() {
    setRootError(null)
    setRoots(null)
    api
      .tree()
      .then(setRoots)
      .catch((err) => setRootError(err instanceof ApiError ? err.message : 'Failed to load the base DN'))
  }

  useEffect(() => {
    if (!selectedDn) {
      setEntry(null)
      return
    }
    let cancelled = false
    setEntryLoading(true)
    setEntryError(null)
    api
      .entry(selectedDn)
      .then((e) => {
        if (!cancelled) setEntry(e)
      })
      .catch((err) => {
        if (!cancelled) setEntryError(err instanceof ApiError ? err.message : 'Failed to load entry')
      })
      .finally(() => {
        if (!cancelled) setEntryLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [selectedDn])

  return (
    <div className="grid h-full grid-cols-[320px_1fr] gap-4">
      <Card className="flex flex-col overflow-hidden">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FolderTree className="size-4 text-accent" />
            DIT Browser
          </CardTitle>
        </CardHeader>
        <CardContent className="flex-1 overflow-auto p-2">
          {rootError && <ErrorState message={rootError} onRetry={loadRoots} />}
          {!rootError && roots === null && (
            <div className="flex items-center gap-2 px-2 py-3 text-[13px] text-muted-foreground">
              <Spinner /> Loading base DN…
            </div>
          )}
          {roots?.length === 0 && (
            <EmptyState icon={FolderTree} title="No entries under the base DN" />
          )}
          {roots?.map((node) => (
            <TreeNodeRow key={node.dn} node={node} depth={0} selectedDn={selectedDn} onSelect={setSelectedDn} />
          ))}
        </CardContent>
      </Card>

      <Card className="flex flex-col overflow-hidden">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileSearch className="size-4 text-accent" />
            {selectedDn ? 'Entry attributes' : 'Select an entry'}
          </CardTitle>
        </CardHeader>
        <CardContent className="flex-1 overflow-auto p-0">
          {!selectedDn && (
            <EmptyState
              icon={FileSearch}
              title="Nothing selected"
              description="Pick an entry from the tree on the left to inspect its attributes."
            />
          )}
          {selectedDn && entryLoading && (
            <div className="flex items-center gap-2 px-4 py-4 text-[13px] text-muted-foreground">
              <Loader2 className="size-3.5 animate-spin" /> Loading entry…
            </div>
          )}
          {entryError && <ErrorState message={entryError} />}
          {entry && !entryLoading && (
            <div className="divide-y divide-border">
              <div className="px-4 py-3">
                <p className="text-[11px] uppercase tracking-wide text-muted-foreground">Distinguished Name</p>
                <p className="mt-0.5 break-all font-mono text-[13px]">{entry.dn}</p>
              </div>
              {Object.entries(entry.attributes)
                .sort(([a], [b]) => a.localeCompare(b))
                .map(([name, values]) => (
                  <div key={name} className="grid grid-cols-[160px_1fr] gap-3 px-4 py-2.5">
                    <p className="font-mono text-[12.5px] text-muted-foreground">{name}</p>
                    <div className="flex flex-wrap gap-1.5">
                      {values.map((v, i) => (
                        <Badge key={i} variant="neutral" className="break-all font-mono">
                          {v}
                        </Badge>
                      ))}
                    </div>
                  </div>
                ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
