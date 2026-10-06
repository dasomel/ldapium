import { ChevronsLeft } from 'lucide-react'
import { useT } from '@/context/LanguageContext'
import { Button } from '@/components/ui/button'

export interface GroupPaginationProps {
  page: number
  pageSize: number
  hasMore: boolean
  canPrevious: boolean
  onNext: () => void
  onPrevious: () => void
  onFirst?: () => void
  onPageSize: (size: number) => void
  navAriaLabel?: string
  total?: number
  onPage?: (page: number) => void
}

export function GroupPagination({
  page,
  pageSize,
  hasMore,
  canPrevious,
  onNext,
  onPrevious,
  onFirst,
  onPageSize,
  navAriaLabel,
}: GroupPaginationProps) {
  const t = useT()

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border px-4 py-3">
      <label className="flex items-center gap-2 text-[12.5px] text-muted-foreground">
        {t('users.rowsPerPage')}
        <select
          aria-label={t('users.rowsPerPage')}
          value={pageSize}
          onChange={(event) => onPageSize(Number(event.target.value))}
          className="h-8 rounded-console border border-border-strong bg-surface px-2 text-[12.5px] text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          {[10, 20, 50, 100].map((size) => (
            <option key={size} value={size}>
              {size}
            </option>
          ))}
        </select>
      </label>
      <nav className="flex flex-wrap items-center gap-1" aria-label={navAriaLabel ?? t('groups.paginationNavigation')}>
        {onFirst && (
          <Button
            variant="outline"
            size="icon"
            disabled={!canPrevious}
            onClick={onFirst}
            aria-label={t('users.firstPage')}
            title={t('users.firstPage')}
          >
            <ChevronsLeft className="size-4" />
          </Button>
        )}
        <Button
          variant="outline"
          size="icon"
          disabled={!canPrevious}
          onClick={onPrevious}
          aria-label={t('users.previousPage')}
          title={t('users.previousPage')}
        >
          &lt;
        </Button>
        <span
          className="inline-flex h-8 min-w-8 items-center justify-center rounded-console border border-border-strong bg-surface px-2 text-[12.5px] font-medium text-foreground"
          aria-current="page"
          aria-label={t('users.pageNumber', { page })}
        >
          {page}
        </span>
        <Button
          variant="outline"
          size="icon"
          disabled={!hasMore}
          onClick={onNext}
          aria-label={t('users.nextPage')}
          title={t('users.nextPage')}
        >
          &gt;
        </Button>
      </nav>
      <span role="status" className="text-[12.5px] text-muted-foreground">
        {t('users.cursorPaginationSummary', { page })}
      </span>
    </div>
  )
}
