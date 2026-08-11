import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react'
import { ApiError, api } from '@/lib/api'

interface AuthState {
  dn: string | null
  loading: boolean
  login: (identity: string, password: string) => Promise<void>
  logout: () => Promise<void>
}

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [dn, setDn] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    api
      .me()
      .then((me) => {
        if (!cancelled) setDn(me.dn)
      })
      .catch(() => {
        if (!cancelled) setDn(null)
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [])

  const login = useCallback(async (identity: string, password: string) => {
    const me = await api.login(identity, password)
    setDn(me.dn)
  }, [])

  const logout = useCallback(async () => {
    try {
      await api.logout()
    } catch (err) {
      // Logout should still clear local state even if the network call
      // failed (e.g. session already expired server-side).
      if (!(err instanceof ApiError)) throw err
    }
    setDn(null)
  }, [])

  return <AuthContext.Provider value={{ dn, loading, login, logout }}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
