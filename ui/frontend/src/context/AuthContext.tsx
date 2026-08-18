import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react'
import { ApiError, api } from '@/lib/api'
import type { AuthMode } from '@/lib/types'

interface AuthState {
  dn: string | null
  authMode: AuthMode | null
  loading: boolean
  login: (identity: string, password: string) => Promise<void>
  logout: () => Promise<string | null>
}

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [dn, setDn] = useState<string | null>(null)
  const [authMode, setAuthMode] = useState<AuthMode | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    Promise.allSettled([api.me(), api.authConfig()]).then(([me, authConfig]) => {
      if (cancelled) return
      setDn(me.status === 'fulfilled' ? me.value.dn : null)
      // Fail closed: while auth mode is unknown, LoginPage never offers
      // LDAP credentials that might bypass a configured SSO deployment.
      setAuthMode(authConfig.status === 'fulfilled' ? authConfig.value.mode : null)
      setLoading(false)
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
    let redirectURL: string | undefined
    try {
      redirectURL = (await api.logout())?.redirectURL
    } catch (err) {
      // Logout should still clear local state even if the network call
      // failed (e.g. session already expired server-side).
      if (!(err instanceof ApiError)) throw err
    }
    setDn(null)
    return redirectURL ?? null
  }, [])

  return <AuthContext.Provider value={{ dn, authMode, loading, login, logout }}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
