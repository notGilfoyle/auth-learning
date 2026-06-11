import { useState, useEffect, useRef } from 'react'
import { Navigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

export default function ProtectedRoute({ children }) {
  const { user, accessToken, recoverSession } = useAuth()
  const [checking, setChecking] = useState(true)
  const [canAccess, setCanAccess] = useState(false)
  // Guard against running the recovery twice in React StrictMode (double-invoke).
  const attempted = useRef(false)

  useEffect(() => {
    if (attempted.current) return
    attempted.current = true

    // Fast path: context already has a valid session (user navigated here after
    // logging in without a page refresh).
    if (user && accessToken) {
      setCanAccess(true)
      setChecking(false)
      return
    }

    // Slow path: page was refreshed and React state was reset.  Try to silently
    // recover a session from the stored refresh token.
    recoverSession().then((ok) => {
      setCanAccess(ok)
      setChecking(false)
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  if (checking) {
    return (
      <div className="loading-screen">
        <div className="spinner" />
        <p>Checking session…</p>
      </div>
    )
  }

  if (!canAccess) return <Navigate to="/login" replace />

  return children
}
