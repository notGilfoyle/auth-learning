import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { apiRequest } from '../api/client'

// ---------------------------------------------------------------------------
// Client-side JWT decoding
// ---------------------------------------------------------------------------
// A JWT is three base64url-encoded segments: header.payload.signature
// We decode the payload (middle segment) purely to display its claims.
//
// IMPORTANT — this is DECODING, not VERIFYING.
//   • Decoding: base64url → JSON (anyone can do this, no key required).
//   • Verifying: check the HMAC-SHA256 signature using the server's secret key.
//
// This function demonstrates that JWT payloads are ENCODED, NOT ENCRYPTED.
// The claims (sub, exp, iat) are readable by anyone who holds the token —
// never put sensitive data (passwords, PII) inside a JWT payload.
// The server verifies the signature; the client just reads the claims.
function decodeJwtPayload(token) {
  try {
    const [, payloadB64] = token.split('.')
    // base64url → base64 (replace url-safe chars, add padding)
    const base64 = payloadB64.replace(/-/g, '+').replace(/_/g, '/')
    const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4)
    return JSON.parse(atob(padded))
  } catch {
    return null
  }
}

export default function Dashboard() {
  const { user, accessToken, logout } = useAuth()
  const navigate = useNavigate()
  const [secondsLeft, setSecondsLeft] = useState(null)
  const [tokenPayload, setTokenPayload] = useState(null)
  const [pingResult, setPingResult] = useState(null)
  const [pinging, setPinging] = useState(false)

  // Re-decode whenever the token changes (it rotates after auto-refresh).
  useEffect(() => {
    if (!accessToken) return
    const payload = decodeJwtPayload(accessToken)
    setTokenPayload(payload)

    if (!payload?.exp) return

    const tick = () => {
      const secs = Math.max(0, payload.exp - Math.floor(Date.now() / 1000))
      setSecondsLeft(secs)
    }
    tick()
    const id = setInterval(tick, 1000)
    return () => clearInterval(id)
  }, [accessToken])

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  // Demonstrate auto-refresh: calls /auth/me via the API client wrapper.
  // If the access token has expired, the client transparently refreshes it
  // and retries — the user sees the result with no manual intervention.
  const handlePing = async () => {
    setPinging(true)
    setPingResult(null)
    try {
      const res = await apiRequest('/auth/me')
      if (res.ok) {
        const data = await res.json()
        setPingResult({ ok: true, message: `✓ /auth/me → ${JSON.stringify(data)}` })
      } else {
        setPingResult({ ok: false, message: `✗ ${res.status} ${res.statusText}` })
      }
    } catch (err) {
      setPingResult({ ok: false, message: `Network error: ${err.message}` })
    } finally {
      setPinging(false)
    }
  }

  const fmt = (secs) => {
    if (secs === null) return '—'
    const m = Math.floor(secs / 60)
    const s = secs % 60
    return `${m}m ${String(s).padStart(2, '0')}s`
  }

  return (
    <div className="dashboard">
      <header className="dashboard-header">
        <div>
          <h1>Dashboard</h1>
          <span className="badge">Protected route</span>
        </div>
        <button onClick={handleLogout} className="btn-secondary">
          Sign out
        </button>
      </header>

      <div className="dashboard-grid">
        {/* Account info */}
        <section className="card">
          <h2>Your account</h2>
          <dl className="info-list">
            <dt>ID</dt>
            <dd>{user?.id}</dd>
            <dt>Email</dt>
            <dd>{user?.email}</dd>
            <dt>Signed in via</dt>
            <dd>
              <span className={`provider-badge provider-${user?.auth_provider}`}>
                {user?.auth_provider === 'google' ? 'Google OAuth' : 'Email / password'}
              </span>
            </dd>
          </dl>
        </section>

        {/* Auto-refresh demo */}
        <section className="card">
          <h2>Auto-refresh demo</h2>
          <p className="card-note">
            Click the button to call <code>/auth/me</code> through the API
            client wrapper. If the access token is expired the client will
            silently refresh it and retry — watch the token inspector update.
          </p>
          <button onClick={handlePing} className="btn-primary" disabled={pinging}>
            {pinging ? 'Calling…' : 'Ping /auth/me'}
          </button>
          {pingResult && (
            <div className={`alert ${pingResult.ok ? 'alert-success' : 'alert-error'}`}>
              {pingResult.message}
            </div>
          )}
        </section>

        {/* Token inspector */}
        <section className="card token-card">
          <h2>Access token inspector</h2>
          <p className="card-note">
            Decoded <strong>client-side</strong> — no network call, no key required.
            This shows that JWT payloads are <strong>encoded, not encrypted</strong>.
            The server verifies the signature; this panel only reads the claims.
          </p>

          <div className={`countdown ${secondsLeft !== null && secondsLeft < 60 ? 'expiring' : ''}`}>
            <span className="countdown-label">Expires in</span>
            <span className="countdown-value">{fmt(secondsLeft)}</span>
            {secondsLeft === 0 && (
              <span className="countdown-note">Next API call triggers auto-refresh</span>
            )}
          </div>

          {tokenPayload && (
            <table className="token-table">
              <thead>
                <tr>
                  <th>Claim</th>
                  <th>Value</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(tokenPayload).map(([k, v]) => (
                  <tr key={k}>
                    <td className="claim-key">{k}</td>
                    <td className="claim-val">
                      {k === 'exp' || k === 'iat'
                        ? `${v}  (${new Date(v * 1000).toLocaleTimeString()})`
                        : String(v)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          <details className="raw-token">
            <summary>Raw token</summary>
            <code className="token-text">{accessToken}</code>
          </details>
        </section>
      </div>
    </div>
  )
}
