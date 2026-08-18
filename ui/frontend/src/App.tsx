import { Navigate, Route, Routes } from 'react-router-dom'
import { useAuth } from '@/context/AuthContext'
import { AppShell } from '@/components/layout/AppShell'
import { LoginPage } from '@/pages/LoginPage'
import { TreePage } from '@/pages/TreePage'
import { UsersPage } from '@/pages/UsersPage'
import { GroupsPage } from '@/pages/GroupsPage'
import { ChangePasswordPage } from '@/pages/ChangePasswordPage'
import { ServerSettingsPage } from '@/pages/ServerSettingsPage'
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

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        element={
          <RequireAuth>
            <AppShell />
          </RequireAuth>
        }
      >
        <Route path="/tree" element={<TreePage />} />
        <Route path="/users" element={<UsersPage />} />
        <Route path="/groups" element={<GroupsPage />} />
        <Route path="/change-password" element={<ChangePasswordPage />} />
        <Route path="/server-settings" element={<ServerSettingsPage />} />
        <Route path="/" element={<Navigate to="/tree" replace />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
