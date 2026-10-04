import { ChevronsLeft, ChevronsRight } from 'lucide-react'
import { useT } from '@/context/LanguageContext'
import { Button } from '@/components/ui/button'

export function GroupPagination({ page, pageSize, total, onPage, onPageSize }: {
  page: number; pageSize: number; total: number
  onPage: (page: number) => void; onPageSize: (size: number) => void
}) {
  const t = useT()
  const pageCount = Math.max(1, Math.ceil(total / pageSize))
  const start = Math.max(1, Math.min(page - 2, pageCount - 4))
  const pages = Array.from({ length: Math.min(5, pageCount) }, (_, index) => start + index)
  return <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border px-4 py-3">
    <label className="flex items-center gap-2 text-[12.5px] text-muted-foreground">
      {t('users.rowsPerPage')}
      <select aria-label={t('users.rowsPerPage')} value={pageSize} onChange={(event) => onPageSize(Number(event.target.value))}
        className="h-8 rounded-console border border-border-strong bg-surface px-2 text-foreground">
        {[10, 20, 50, 100].map(size => <option key={size} value={size}>{size}</option>)}
      </select>
    </label>
    <nav className="flex flex-wrap items-center gap-1" aria-label={t('groups.paginationNavigation')}>
      <Button variant="outline" size="icon" disabled={page === 1} onClick={() => onPage(1)} aria-label={t('users.firstPage')}><ChevronsLeft /></Button>
      <Button variant="outline" size="icon" disabled={page === 1} onClick={() => onPage(page - 1)} aria-label={t('users.previousPage')}>&lt;</Button>
      {pages.map(number => <Button key={number} variant={number === page ? 'subtle' : 'outline'} size="icon"
        onClick={() => onPage(number)} aria-current={number === page ? 'page' : undefined}
        aria-label={t('users.pageNumber', { page: number })}>{number}</Button>)}
      <Button variant="outline" size="icon" disabled={page === pageCount} onClick={() => onPage(page + 1)} aria-label={t('users.nextPage')}>&gt;</Button>
      <Button variant="outline" size="icon" disabled={page === pageCount} onClick={() => onPage(pageCount)} aria-label={t('users.lastPage')}><ChevronsRight /></Button>
    </nav>
    <span role="status" className="text-[12.5px] text-muted-foreground">
      {t('users.paginationSummary', { from: (page - 1) * pageSize + 1, to: Math.min(page * pageSize, total), total })}
    </span>
  </div>
}
