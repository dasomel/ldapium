import { Activity, BookOpen, Archive, Fingerprint, FlaskConical, FolderTree, History, Network, Settings2, ShieldCheck, UserRound, Users2, type LucideIcon } from 'lucide-react'

// D39: keep the same functional order and distinct icons across desktop/mobile
// navigation and deployments that expose optional administration pages.
const routes: { to: string; icon: LucideIcon }[] = [
  { to: '/tree', icon: FolderTree },
  { to: '/users', icon: UserRound },
  { to: '/groups', icon: Users2 },
  { to: '/applications', icon: ShieldCheck },
  { to: '/keycloak', icon: Fingerprint },
  { to: '/health', icon: Activity },
  { to: '/history', icon: History },
  { to: '/backups', icon: Archive },
  { to: '/replication', icon: Network },
  { to: '/server-settings', icon: Settings2 },
  { to: '/test-data', icon: FlaskConical },
  { to: '/api-docs', icon: BookOpen },
]
export function arrangeNavigation<T extends { to: string; icon: LucideIcon }>(items: T[]): T[] {
  const order = (to: string) => { const index = routes.findIndex(route => route.to === to); return index < 0 ? routes.length : index }
  return items.map(item => ({ ...item, icon: routes.find(route => route.to === item.to)?.icon ?? item.icon }))
    .sort((a, b) => order(a.to) - order(b.to))
}
