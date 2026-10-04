import { Navigate, Route, Routes } from 'react-router-dom'
import { BackupsPage } from '@/pages/BackupsPage'
import { ApplicationsPage } from '@/pages/ApplicationsPage'
import { useAuth } from '@/context/AuthContext'
import { AppShell } from '@/components/layout/AppShell'
import { LoginPage } from '@/pages/LoginPage'
import { TreePage } from '@/pages/TreePage'
import { UsersPage } from '@/pages/UsersPage'
import { GroupsPage } from '@/pages/GroupsPage'
import { ChangePasswordPage } from '@/pages/ChangePasswordPage'
import { HealthPage } from '@/pages/HealthPage'
import { HistoryPage } from '@/pages/HistoryPage'
import { ServerSettingsPage } from '@/pages/ServerSettingsPage'
import { ApiDocsPage } from '@/pages/ApiDocsPage'
import { PublicFrame } from '@/components/layout/PublicFrame'
import { Spinner } from '@/components/ui/empty-state'

function RequireAuth({ children }: { children: React.ReactNode }) {
  const { dn, loading } = useAuth()
  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Spinner />
      </div>
    )
  }
  if (!dn) return <Navigate to="/login" replace />
  return <>{children}</>
}

// /api-docs is readable without a session (the spec endpoint is public):
// signed-in users get the normal console shell, everyone else a minimal frame.
function ShellOrPublic() {
  const { dn, loading } = useAuth()
  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Spinner />
      </div>
    )
  }
  return dn ? <AppShell /> : <PublicFrame />
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<ShellOrPublic />}>
        <Route path="/api-docs" element={<ApiDocsPage />} />
      </Route>
      <Route
        element={
          <RequireAuth>
            <AppShell />
          </RequireAuth>
        }
      >
        <Route path="/tree" element={<TreePage />} />
        <Route path="/backups" element={<BackupsPage />} />
        <Route path="/applications" element={<ApplicationsPage />} />
        <Route path="/users" element={<UsersPage />} />
        <Route path="/groups" element={<GroupsPage />} />
        <Route path="/change-password" element={<ChangePasswordPage />} />
        <Route path="/history" element={<HistoryPage />} />
        <Route path="/health" element={<HealthPage />} />
        <Route path="/server-settings" element={<ServerSettingsPage />} />
        <Route path="/" element={<Navigate to="/tree" replace />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
