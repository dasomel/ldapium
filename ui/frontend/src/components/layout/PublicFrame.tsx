import { Link, Outlet } from 'react-router-dom'
import { LogIn, TerminalSquare } from 'lucide-react'
import { useT } from '@/context/LanguageContext'

/** Minimal chrome for pages readable without a session (see App.tsx). */
export function PublicFrame() {
  const t = useT()
  return (
    <div className="flex min-h-dvh flex-col">
      <header className="flex items-center gap-2 border-b border-border bg-surface px-4 py-3">
        <TerminalSquare aria-hidden="true" className="size-5 text-accent" />
        <span className="flex-1 text-sm font-semibold">Directory Console</span>
        <Link to="/login" className="flex items-center gap-1.5 rounded-console px-2 py-1.5 text-[13px] text-muted-foreground hover:bg-muted"><LogIn aria-hidden="true" className="size-4" />{t('apiDocs.signIn')}</Link>
      </header>
      <main id="main-content" className="min-w-0 flex-1 p-3 sm:p-5"><Outlet /></main>
    </div>
  )
}
