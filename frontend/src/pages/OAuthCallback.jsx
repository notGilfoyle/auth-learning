import { useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

/**
 * Landing page for the Google OAuth redirect.
 *
 * The backend sends the browser here after a successful Google login:
 *   http://localhost:5173/auth/callback#access_token=...&refresh_token=...
 *
 * The tokens are in the URL *fragment* (after #), not the query string.
 * Fragments are never sent to the server, so the tokens don't appear in
 * our backend's access logs.  However, they are briefly visible in the
 * browser address bar, so we clear them from the URL immediately.
 *
 * After reading the tokens we hand them to AuthContext.loginWithTokens,
 * which stores them and fetches /auth/me — exactly the same state the app
 * would be in after a normal email/password login.
 */
export default function OAuthCallback() {
  const { loginWithTokens } = useAuth()
  const navigate = useNavigate()
  const attempted = useRef(false)

  useEffect(() => {
    // Guard against React StrictMode double-invoke.
    if (attempted.current) return
    attempted.current = true

    const hash = window.location.hash.slice(1) // strip leading #
    const params = new URLSearchParams(hash)
    const accessToken = params.get('access_token')
    const refreshToken = params.get('refresh_token')

    // Remove tokens from the URL immediately so they don't linger in
    // browser history.
    window.history.replaceState(null, '', window.location.pathname)

    if (!accessToken || !refreshToken) {
      navigate('/login', { state: { error: 'Google sign-in failed. Please try again.' } })
      return
    }

    loginWithTokens(accessToken, refreshToken)
      .then(() => navigate('/dashboard', { replace: true }))
      .catch(() =>
        navigate('/login', { state: { error: 'Could not complete sign-in. Please try again.' } })
      )
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <div className="loading-screen">
      <div className="spinner" />
      <p>Completing sign in…</p>
    </div>
  )
}
