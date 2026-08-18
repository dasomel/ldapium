import { NavLink, Outlet } from 'react-router-dom'
import { FolderTree, KeyRound, Languages, LogOut, Moon, Server, Sun, TerminalSquare, UserRound, Users2 } from 'lucide-react'
import { useAuth } from '@/context/AuthContext'
import { useTheme } from '@/context/ThemeContext'
import { useToast } from '@/context/ToastContext'
import { useLanguage, type Language } from '@/context/LanguageContext'
import type { DictKey } from '@/lib/i18n/en'
import { cn } from '@/lib/utils'
import { StatusHud } from './StatusHud'

const nav: { to: string; labelKey: DictKey; icon: typeof FolderTree }[] = [
  { to: '/tree', labelKey: 'nav.tree', icon: FolderTree },
  { to: '/users', labelKey: 'nav.users', icon: UserRound },
  { to: '/groups', labelKey: 'nav.groups', icon: Users2 },
  { to: '/server-settings', labelKey: 'nav.serverSettings', icon: Server },
]

export function AppShell() {
  const { dn, logout } = useAuth()
  const { theme, toggle } = useTheme()
  const { notify } = useToast()
  const { language, setLanguage, t } = useLanguage()

  async function handleLogout() {
    try {
      const redirectURL = await logout()
      if (redirectURL) window.location.assign(redirectURL)
    } catch {
      notify('error', t('common.logoutFailed'))
    }
  }

  // Each option is always spelled in its own language, regardless of the
  // current UI language — that's how a picker stays usable to someone who
  // doesn't (yet) read the language currently on screen. So these two
  // labels are intentionally not looked up via t().
  function toggleLanguage() {
    setLanguage(language === 'ko' ? 'en' : 'ko')
  }
  const otherLanguage: Language = language === 'ko' ? 'en' : 'ko'
  const otherLanguageLabel = otherLanguage === 'ko' ? '한국어' : 'English'

  return (
    <div className="flex min-h-screen">
      <aside className="flex w-56 shrink-0 flex-col border-r border-border bg-surface">
        <div className="flex items-center gap-2 border-b border-border px-4 py-4">
          <TerminalSquare className="size-5 text-accent" />
          <span className="text-sm font-semibold tracking-tight">Directory Console</span>
        </div>
        <nav className="flex-1 space-y-0.5 px-2 py-3">
          {nav.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-2.5 rounded-console px-2.5 py-2 text-[13px] font-medium transition-colors',
                  isActive
                    ? 'bg-accent-muted text-accent'
                    : 'text-muted-foreground hover:bg-muted hover:text-foreground',
                )
              }
            >
              <item.icon className="size-4" />
              {t(item.labelKey)}
            </NavLink>
          ))}
        </nav>
        <div className="space-y-0.5 border-t border-border p-3">
          <button
            onClick={toggleLanguage}
            className="flex w-full items-center gap-2.5 rounded-console px-2.5 py-2 text-[13px] font-medium text-muted-foreground hover:bg-muted hover:text-foreground"
          >
            <Languages className="size-4" />
            {otherLanguageLabel}
          </button>
          <button
            onClick={toggle}
            className="flex w-full items-center gap-2.5 rounded-console px-2.5 py-2 text-[13px] font-medium text-muted-foreground hover:bg-muted hover:text-foreground"
          >
            {theme === 'dark' ? <Sun className="size-4" /> : <Moon className="size-4" />}
            {theme === 'dark' ? t('common.themeToLight') : t('common.themeToDark')}
          </button>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between border-b border-border bg-surface px-5 py-2.5">
          <div className="min-w-0">
            <p className="text-[11px] uppercase tracking-wide text-muted-foreground">{t('common.boundAs')}</p>
            <p className="truncate font-mono text-[12.5px] text-foreground" title={dn ?? undefined}>
              {dn}
            </p>
          </div>
          <div className="flex items-center gap-1">
            <NavLink
              to="/change-password"
              title={t('changePassword.title')}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-1.5 rounded-console px-2.5 py-1.5 text-[13px] font-medium',
                  isActive
                    ? 'bg-accent-muted text-accent'
                    : 'text-muted-foreground hover:bg-muted hover:text-foreground',
                )
              }
            >
              <KeyRound className="size-4" />
              {t('changePassword.title')}
            </NavLink>
            <button
              onClick={handleLogout}
              className="flex items-center gap-1.5 rounded-console px-2.5 py-1.5 text-[13px] font-medium text-muted-foreground hover:bg-muted hover:text-foreground"
            >
              <LogOut className="size-4" />
              {t('common.logOut')}
            </button>
          </div>
        </header>
        <main className="min-w-0 flex-1 overflow-auto p-5">
          <Outlet />
        </main>
        <StatusHud />
      </div>
    </div>
  )
}
