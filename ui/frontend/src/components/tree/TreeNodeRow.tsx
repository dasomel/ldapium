import { useState } from 'react'
import { ChevronRight, Loader2 } from 'lucide-react'
import { api, ApiError } from '@/lib/api'
import { useT } from '@/context/LanguageContext'
import type { TreeNode } from '@/lib/types'
import { cn } from '@/lib/utils'

interface TreeNodeRowProps {
  node: TreeNode
  depth: number
  selectedDn: string | null
  onSelect: (dn: string) => void
}

/** One expandable row in the DIT tree. Children are fetched lazily on
 * first expand, matching how sysadmins actually explore large directories
 * (never eagerly load the whole subtree). */
export function TreeNodeRow({ node, depth, selectedDn, onSelect }: TreeNodeRowProps) {
  const t = useT()
  const [expanded, setExpanded] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [children, setChildren] = useState<TreeNode[] | null>(null)

  async function toggle() {
    onSelect(node.dn)
    if (!node.hasChildren) return
    if (expanded) {
      setExpanded(false)
      return
    }
    setExpanded(true)
    if (children !== null) return
    setLoading(true)
    setError(null)
    try {
      setChildren(await api.tree(node.dn))
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('tree.loadChildrenFailed'))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <button
        type="button"
        onClick={toggle}
        onKeyDown={(e) => {
          if (e.key === 'ArrowRight' && !expanded) toggle()
          if (e.key === 'ArrowLeft' && expanded) toggle()
        }}
        style={{ paddingLeft: 8 + depth * 16 }}
        className={cn(
          'flex w-full items-center gap-1.5 rounded-console py-1.5 pr-2 text-left text-[13px] transition-colors',
          'hover:bg-muted focus-visible:bg-muted focus-visible:outline-none',
          selectedDn === node.dn && 'bg-accent-muted text-accent',
        )}
      >
        {node.hasChildren ? (
          <ChevronRight
            className={cn('size-3.5 shrink-0 text-muted-foreground transition-transform', expanded && 'rotate-90')}
          />
        ) : (
          <span className="size-3.5 shrink-0" />
        )}
        <span className="truncate font-mono text-[12.5px]">{node.rdn}</span>
      </button>

      {expanded && (
        <div>
          {loading && (
            <div
              style={{ paddingLeft: 8 + (depth + 1) * 16 }}
              className="flex items-center gap-1.5 py-1.5 text-[12px] text-muted-foreground"
            >
              <Loader2 className="size-3 animate-spin" /> {t('tree.loadingChildren')}
            </div>
          )}
          {error && (
            <div style={{ paddingLeft: 8 + (depth + 1) * 16 }} className="py-1.5 text-[12px] text-danger">
              {error}
            </div>
          )}
          {children?.length === 0 && !loading && (
            <div style={{ paddingLeft: 8 + (depth + 1) * 16 }} className="py-1.5 text-[12px] text-muted-foreground">
              {t('tree.noEntriesShort')}
            </div>
          )}
          {children?.map((child) => (
            <TreeNodeRow
              key={child.dn}
              node={child}
              depth={depth + 1}
              selectedDn={selectedDn}
              onSelect={onSelect}
            />
          ))}
        </div>
      )}
    </div>
  )
}
