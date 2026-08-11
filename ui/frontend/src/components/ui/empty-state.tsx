import type { ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'
import { useT } from '@/context/LanguageContext'
import { cn } from '@/lib/utils'

interface EmptyStateProps {
  icon: LucideIcon
  title: string
  description?: string
  action?: ReactNode
  className?: string
}

export function EmptyState({ icon: Icon, title, description, action, className }: EmptyStateProps) {
  return (
    <div className={cn('flex flex-col items-center justify-center gap-3 px-6 py-16 text-center', className)}>
      <div className="flex size-11 items-center justify-center rounded-full border border-dashed border-border-strong text-muted-foreground">
        <Icon className="size-5" />
      </div>
      <div className="space-y-1">
        <p className="text-sm font-medium text-foreground">{title}</p>
        {description && <p className="max-w-sm text-[13px] text-muted-foreground">{description}</p>}
      </div>
      {action}
    </div>
  )
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  const t = useT()
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-16 text-center">
      <div className="flex size-11 items-center justify-center rounded-full border border-danger/30 bg-danger/10 text-danger">
        !
      </div>
      <div className="space-y-1">
        <p className="text-sm font-medium text-foreground">{t('common.somethingWrong')}</p>
        {/* message is the server's/network's own error text — never
         * translated, see lib/i18n/en.ts's file-level comment. */}
        <p className="max-w-sm font-mono text-[12.5px] text-muted-foreground">{message}</p>
      </div>
      {onRetry && (
        <button onClick={onRetry} className="text-[13px] font-medium text-accent hover:underline">
          {t('common.retry')}
        </button>
      )}
    </div>
  )
}

export function Spinner({ className }: { className?: string }) {
  return (
    <div
      className={cn(
        'size-4 animate-spin rounded-full border-2 border-border-strong border-t-accent',
        className,
      )}
    />
  )
}
