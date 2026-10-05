import { Activity, BookOpen, Archive, FolderTree, History, Settings2, ShieldCheck, UserRound, Users2 } from 'lucide-react'
import { useAuth } from '@/context/AuthContext'
import { useLanguage } from '@/context/LanguageContext'
import type { DictKey } from '@/lib/i18n/en'
import { ConsoleFrame } from '@/components/layout/ConsoleFrame'

const nav: { to: string; labelKey: DictKey; icon: typeof FolderTree }[] = [
  { to: '/tree', labelKey: 'nav.tree', icon: FolderTree },
  { to: '/users', labelKey: 'nav.users', icon: UserRound },
  { to: '/groups', labelKey: 'nav.groups', icon: Users2 },
  { to: '/history', labelKey: 'nav.history', icon: History },
  { to: '/health', labelKey: 'nav.health', icon: Activity },
  { to: '/server-settings', labelKey: 'nav.serverSettings', icon: Settings2 },
  { to: '/api-docs', labelKey: 'nav.apiDocs', icon: BookOpen },
]
export function AppShell() {
  const { dn, logout } = useAuth()
  const { language, t } = useLanguage()
  return <ConsoleFrame dn={dn} logout={logout} navigation={[...nav.map((item) => ({ ...item, label: t(item.labelKey) })), { to: '/backups', label: language === 'ko' ? '백업' : 'Backups', icon: Archive }, { to: '/applications', label: language === 'ko' ? '앱 SSO 권한' : 'App SSO permissions', icon: ShieldCheck }]} />
}
