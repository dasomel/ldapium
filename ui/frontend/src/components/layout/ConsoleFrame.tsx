import { useRef, useState } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { KeyRound, Languages, LogOut, Menu, Moon, Sun, TerminalSquare, type LucideIcon } from 'lucide-react'
import { useLanguage } from '@/context/LanguageContext'
import { useTheme } from '@/context/ThemeContext'
import { useToast } from '@/context/ToastContext'
import { Dialog, DialogContent, DialogTitle } from '@/components/ui/dialog'
import { cn } from '@/lib/utils'
import { arrangeNavigation } from '@/components/layout/navigation'
import packageInfo from '../../../package.json'

export interface NavigationItem { to: string; label: string; icon: LucideIcon }
export function ConsoleFrame({ dn, logout, navigation }: { dn: string | null; logout: () => Promise<string | null>; navigation: NavigationItem[] }) {
  const { language, setLanguage, t } = useLanguage()
  const { theme, toggle } = useTheme()
  const { notify } = useToast()
  const [menuOpen, setMenuOpen] = useState(false)
  const menuButton = useRef<HTMLButtonElement>(null)
  const ko = language === 'ko'
  async function logOut() { try { const url = await logout(); if (url) window.location.assign(url) } catch { notify('error', t('common.logoutFailed')) } }
  function sidebar() {
    return <>
      <div className="flex items-center gap-2 border-b border-border px-4 py-4"><TerminalSquare className="size-5 text-accent" /><span className="text-sm font-semibold">Directory Console</span></div>
      <nav aria-label={ko ? '주 메뉴' : 'Main navigation'} className="flex-1 space-y-1 overflow-y-auto px-2 py-3">
        {arrangeNavigation(navigation).map((item) => <NavLink key={item.to} to={item.to} onClick={() => setMenuOpen(false)} className={({ isActive }) => cn('flex items-center gap-2.5 rounded-console px-2.5 py-2 text-[13px] font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring', isActive ? 'bg-accent-muted text-accent' : 'text-muted-foreground hover:bg-muted hover:text-foreground')}><item.icon aria-hidden="true" className="size-4 shrink-0" />{item.label}</NavLink>)}
      </nav>
      <div className="space-y-1 border-t border-border p-3">
        <button type="button" onClick={() => setLanguage(ko ? 'en' : 'ko')} className="flex w-full items-center gap-2.5 rounded-console px-2.5 py-2 text-[13px] text-muted-foreground hover:bg-muted"><Languages className="size-4" />{ko ? 'English' : '한국어'}</button>
        <button type="button" onClick={toggle} className="flex w-full items-center gap-2.5 rounded-console px-2.5 py-2 text-[13px] text-muted-foreground hover:bg-muted">{theme === 'dark' ? <Sun className="size-4" /> : <Moon className="size-4" />}{theme === 'dark' ? t('common.themeToLight') : t('common.themeToDark')}</button>
      </div>
      <p className="border-t border-border px-4 py-2 text-[10px] text-muted-foreground">Version {packageInfo.version}</p>
    </>
  }
  return <div className="flex h-dvh overflow-hidden">
    <a href="#main-content" className="sr-only z-[100] focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:rounded-console focus:bg-surface focus:p-3 focus:text-accent">{ko ? '본문으로 이동' : 'Skip to content'}</a>
    <aside className="hidden w-56 shrink-0 flex-col border-r border-border bg-surface md:flex">{sidebar()}</aside>
    <Dialog open={menuOpen} onOpenChange={setMenuOpen}><DialogContent aria-describedby={undefined} onCloseAutoFocus={(event) => { event.preventDefault(); menuButton.current?.focus() }} className="left-0 top-0 flex h-dvh max-h-dvh w-72 max-w-[85vw] translate-x-0 translate-y-0 flex-col rounded-none p-0"><DialogTitle className="sr-only">{ko ? '탐색 메뉴' : 'Navigation menu'}</DialogTitle>{sidebar()}</DialogContent></Dialog>
    <div className="flex min-w-0 flex-1 flex-col">
      <header className="flex shrink-0 items-center gap-2 border-b border-border bg-surface px-3 py-2.5 sm:px-5">
        <button ref={menuButton} type="button" aria-label={ko ? '메뉴 열기' : 'Open navigation'} onClick={() => setMenuOpen(true)} className="rounded-console p-2 text-muted-foreground hover:bg-muted md:hidden"><Menu className="size-5" /></button>
        <div className="min-w-0 flex-1"><p className="text-[11px] text-muted-foreground">{t('common.boundAs')}</p><p className="truncate font-mono text-xs" title={dn ?? undefined}>{dn}</p></div>
        <NavLink to="/change-password" aria-label={t('changePassword.title')} className={({ isActive }) => cn('flex shrink-0 items-center gap-1.5 rounded-console p-2 text-[13px]', isActive ? 'bg-accent-muted text-accent' : 'text-muted-foreground hover:bg-muted')}><KeyRound className="size-4" /><span className="hidden sm:inline">{t('changePassword.title')}</span></NavLink>
        <button type="button" onClick={logOut} aria-label={t('common.logOut')} className="flex shrink-0 items-center gap-1.5 rounded-console p-2 text-[13px] text-muted-foreground hover:bg-muted"><LogOut className="size-4" /><span className="hidden sm:inline">{t('common.logOut')}</span></button>
      </header>
      <main id="main-content" tabIndex={-1} className="min-w-0 flex-1 overflow-auto p-3 focus:outline-none sm:p-5"><Outlet /></main>
    </div>
  </div>
}
