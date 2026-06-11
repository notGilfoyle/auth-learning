import { createContext, useContext, useState, useCallback, useEffect, useRef } from 'react'
import { configureClient } from '../api/client'

// ---------------------------------------------------------------------------
// Token storage strategy — trade-off commentary
// ---------------------------------------------------------------------------
//
// ACCESS TOKEN → React state (in-memory only)
//   PRO: Never written to the DOM or any Web Storage API, so a content-
//        injection XSS cannot read it via `localStorage.getItem`.
//   CON: Lost on page refresh.  We recover it silently using the refresh token.
//
// REFRESH TOKEN → localStorage
//   PRO: Survives page refreshes; the user stays logged in across sessions.
//   CON: Any XSS with script execution can call `localStorage.getItem` and
//        steal it.  This is the accepted trade-off for a client-side SPA demo.
//
// GOLD STANDARD (Phase 2): HttpOnly cookies for the refresh token.
//   The browser sends them automatically but JavaScript can never read them
//   (`document.cookie` does not expose HttpOnly cookies), eliminating the XSS
//   theft vector entirely.  Requires SameSite/CORS cookie config on the server.
//
// ---------------------------------------------------------------------------

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [accessToken, setAccessToken] = useState(null)
  const [user, setUser] = useState(null)

  // Ref stays in sync with state so the API client's getter closure always
  // returns the latest value without needing a re-render cycle.
  const accessTokenRef = useRef(null)
  useEffect(() => {
    accessTokenRef.current = accessToken
  }, [accessToken])

  // Wire the API client once on mount.  The getter reads the ref (always
  // current); the onRefreshed callback updates React state so the Dashboard
  // re-renders with the new token.
  useEffect(() => {
    configureClient({
      tokenGetter: () => accessTokenRef.current,
      onRefreshed: (newToken) => setAccessToken(newToken),
    })
  }, [])

  const register = useCallback(async (email, password) => {
    const res = await fetch('http://localhost:8000/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    })
    if (!res.ok) {
      const err = await res.json()
      throw new Error(err.detail || 'Registration failed')
    }
    return res.json()
  }, [])

  const login = useCallback(async (email, password) => {
    const res = await fetch('http://localhost:8000/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    })
    if (!res.ok) {
      const err = await res.json()
      throw new Error(err.detail || 'Login failed')
    }
    const data = await res.json()

    setAccessToken(data.access_token)
    accessTokenRef.current = data.access_token
    localStorage.setItem('refreshToken', data.refresh_token)

    const meRes = await fetch('http://localhost:8000/auth/me', {
      headers: { Authorization: `Bearer ${data.access_token}` },
    })
    const me = await meRes.json()
    setUser(me)
    return me
  }, [])

  const logout = useCallback(async () => {
    const refreshToken = localStorage.getItem('refreshToken')
    if (refreshToken) {
      try {
        await fetch('http://localhost:8000/auth/logout', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refresh_token: refreshToken }),
        })
      } catch {
        // Best-effort revocation — clear local state regardless.
      }
    }
    setAccessToken(null)
    accessTokenRef.current = null
    setUser(null)
    localStorage.removeItem('refreshToken')
  }, [])

  // Called by ProtectedRoute on page load when React state has been reset
  // (refresh) but a stored refresh token may still be valid.
  const recoverSession = useCallback(async () => {
    const stored = localStorage.getItem('refreshToken')
    if (!stored) return false

    const res = await fetch('http://localhost:8000/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: stored }),
    })
    if (!res.ok) {
      localStorage.removeItem('refreshToken')
      return false
    }

    const data = await res.json()
    setAccessToken(data.access_token)
    accessTokenRef.current = data.access_token
    localStorage.setItem('refreshToken', data.refresh_token)

    const meRes = await fetch('http://localhost:8000/auth/me', {
      headers: { Authorization: `Bearer ${data.access_token}` },
    })
    const me = await meRes.json()
    setUser(me)
    return true
  }, [])

  return (
    <AuthContext.Provider
      value={{ user, accessToken, login, logout, register, recoverSession }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>')
  return ctx
}
