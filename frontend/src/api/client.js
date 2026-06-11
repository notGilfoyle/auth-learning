const BASE_URL = 'http://localhost:8000'

// ---------------------------------------------------------------------------
// Token accessor wiring
// ---------------------------------------------------------------------------
// The API client needs the current access token, but it lives in React state
// (AuthContext).  We use a getter/setter pair injected from the context so
// there is no circular import between this module and AuthContext.

let getToken = () => null
let onTokenRefreshed = (_newToken) => {}

export function configureClient({ tokenGetter, onRefreshed }) {
  getToken = tokenGetter
  onTokenRefreshed = onRefreshed
}

// ---------------------------------------------------------------------------
// Refresh logic
// ---------------------------------------------------------------------------

// Deduplicate concurrent refresh attempts: if two requests fire while the
// access token is expired, only one refresh call goes to the server and both
// requests share the result.
let refreshPromise = null

async function attemptRefresh() {
  const stored = localStorage.getItem('refreshToken')
  if (!stored) return null

  const res = await fetch(`${BASE_URL}/auth/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: stored }),
  })

  if (!res.ok) {
    localStorage.removeItem('refreshToken')
    return null
  }

  const data = await res.json()
  // Persist the new (rotated) refresh token and notify the context so it can
  // update its accessToken state (which the Dashboard displays).
  localStorage.setItem('refreshToken', data.refresh_token)
  onTokenRefreshed(data.access_token)
  return data.access_token
}

// ---------------------------------------------------------------------------
// Main request wrapper
// ---------------------------------------------------------------------------

/**
 * Fetch wrapper that:
 *  1. Attaches `Authorization: Bearer <token>` to every request.
 *  2. On 401, attempts a single token refresh and retries the original request.
 *  3. If refresh fails (session truly expired), clears storage and redirects
 *     to /login.
 */
export async function apiRequest(path, options = {}) {
  const buildHeaders = (token) => ({
    'Content-Type': 'application/json',
    ...options.headers,
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  })

  const doFetch = (token) =>
    fetch(`${BASE_URL}${path}`, { ...options, headers: buildHeaders(token) })

  let res = await doFetch(getToken())

  if (res.status === 401) {
    if (!refreshPromise) {
      refreshPromise = attemptRefresh().finally(() => {
        refreshPromise = null
      })
    }

    const newToken = await refreshPromise

    if (!newToken) {
      // Refresh failed — the session is dead.  Send the user to login.
      localStorage.removeItem('refreshToken')
      window.location.href = '/login'
      return res
    }

    // Retry with the fresh token.
    res = await doFetch(newToken)
  }

  return res
}
