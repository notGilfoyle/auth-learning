# Auth Learning Demo

A production-quality full-stack authentication app built to demonstrate the core concepts behind modern web auth. Intended as a portfolio/learning reference — every non-obvious security decision has an inline comment explaining the *why*.

**Stack:** Python · FastAPI · SQLite · Argon2 · JWT · Authlib · React · Vite

---

## Concepts demonstrated

| Concept | Where |
|---|---|
| **Argon2id password hashing** | `backend/auth/security.py` → `hash_password` |
| **Adaptive rehashing on login** | `backend/main.py` → `check_needs_rehash` |
| **Stateless access tokens (JWT)** | `backend/auth/security.py` → `create_access_token` |
| **Stateful refresh tokens (opaque, revocable)** | `backend/models.py` → `RefreshToken` |
| **Refresh token rotation** | `backend/main.py` → `POST /auth/refresh` |
| **User enumeration defense** | `backend/main.py` → `login` (timing-normalized path) |
| **Algorithm-pinned JWT decode** | `backend/auth/security.py` → `decode_access_token` |
| **OAuth 2.0 + OIDC delegated login** | `backend/main.py` → `/auth/google/*` |
| **ID token validation (RS256, JWKS)** | Authlib inside `google_callback` |
| **App issues its own session after OAuth** | `backend/main.py` → `google_callback` |
| **Token storage trade-offs** | `frontend/src/context/AuthContext.jsx` (comment block) |
| **Auto-refresh on 401** | `frontend/src/api/client.js` → `apiRequest` |
| **JWT encoding ≠ encryption** | `frontend/src/pages/Dashboard.jsx` → `decodeJwtPayload` |
| **Protected route guard** | `frontend/src/components/ProtectedRoute.jsx` |

---

## Architecture

```
Browser (React + Vite :5173)
        │
        │  POST /auth/login  ──────────────────────────────►┐
        │  ◄── { access_token (JWT), refresh_token (opaque) }│
        │                                                    │
        │  GET /auth/me                                      │
        │  Authorization: Bearer <access_token>  ──────────►│
        │                                                    │  FastAPI :8000
        │  [access token expires → 401]                      │  SQLite (auth.db)
        │  POST /auth/refresh  ──────────────────────────────►│
        │  ◄── { new_access_token, new_refresh_token }       │
        │  [retry original request]                          │
        │                                                    │
        │  POST /auth/logout  ───────────────────────────────►│
        │  (revokes refresh token in DB)                     │
        └────────────────────────────────────────────────────┘

Google OAuth / OIDC flow:

  Browser ──GET /auth/google/login──► FastAPI
          ◄── 302 redirect ──────────── (Authlib generates state + nonce)
          │
          └──► accounts.google.com  (user logs in to Google, never to our app)
               ◄── user consents ──
               └──► GET /auth/google/callback?code=...&state=...──► FastAPI
                                        (Authlib validates state, exchanges
                                         code, validates ID token via JWKS)
                    ◄── 302 to /auth/callback#access_token=...
          │
  Browser reads tokens from fragment, clears URL
  Calls /auth/me → lands on Dashboard (same state as password login)
```

**Access token** — short-lived JWT (default 15 min). Verified stateless by the server. Cannot be revoked early — that's why the lifetime is short.

**Refresh token** — long-lived opaque random string (default 7 days) stored in the database. Can be individually revoked. Rotated on every use.

---

## Setup

### Prerequisites

- Python ≥ 3.11 with [uv](https://docs.astral.sh/uv/)
- Node.js ≥ 18

### Backend

```bash
cd backend

# Install dependencies
uv sync

# Create your .env from the example
cp .env.example .env
# Edit .env — at minimum set SECRET_KEY:
# python -c "import secrets; print(secrets.token_hex(32))"

# Start the API server
uv run uvicorn main:app --reload
# → http://localhost:8000
# → Interactive docs at http://localhost:8000/docs
```

### Frontend

```bash
cd frontend

npm install
npm run dev
# → http://localhost:5173
```

Open http://localhost:5173, register an account, log in, and watch the token inspector on the dashboard.

---

## Login with Google (OAuth 2.0 / OIDC)

### The flow, step by step

1. User clicks **"Continue with Google"** on the login page.
2. The browser navigates to `GET /auth/google/login` on the backend.
3. Authlib generates a random `state` (CSRF token) and OIDC `nonce`, stores them in a signed session cookie, and **redirects the browser to Google's consent screen**.
4. The user authenticates with Google (types their Google password into **Google's** login page — our app never sees it).
5. Google redirects back to `GET /auth/google/callback?code=...&state=...`.
6. Authlib validates `state` (CSRF check), then exchanges the authorization code for tokens via a **back-channel** POST to Google's token endpoint (the code never touches the frontend).
7. Authlib fetches Google's **public JWKS** and validates the ID token's RS256 signature, issuer, audience, expiry, and nonce. The ID token is a JWT signed by Google — verified using Google's public key.
8. We extract the verified `email` and `sub` (Google's stable user identifier) from the ID token claims.
9. We find or create the user in our own database.
10. We issue **our own** access token (15-min JWT) and refresh token (stored in DB) — reusing the same functions as password login.
11. We redirect the browser to `http://localhost:5173/auth/callback#access_token=...&refresh_token=...`. The frontend reads the tokens from the URL fragment, clears them from the address bar, and lands on the dashboard.

From step 10 onward, the session is completely identical to a password login — auto-refresh, ProtectedRoute, logout, all work the same way.

### Getting Google credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/) → **APIs & Services** → **Credentials**.
2. Click **Create Credentials** → **OAuth client ID**.
3. Application type: **Web application**.
4. Under **Authorized redirect URIs**, add exactly:
   ```
   http://localhost:8000/auth/google/callback
   ```
5. Copy the **Client ID** and **Client Secret** into your `.env`:
   ```
   GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
   GOOGLE_CLIENT_SECRET=your-client-secret
   ```
6. Restart the backend (`uv run uvicorn main:app --reload`).

> Leave `GOOGLE_CLIENT_ID` blank to disable the Google button entirely — email/password login continues to work.

---

## API endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/auth/register` | — | Create a new user |
| `POST` | `/auth/login` | — | Verify credentials, issue access + refresh tokens |
| `GET`  | `/auth/me` | Bearer | Return the current user's profile |
| `POST` | `/auth/refresh` | — | Exchange a refresh token for a new token pair |
| `POST` | `/auth/logout` | — | Revoke a refresh token |
| `GET`  | `/auth/google/login` | — | Start the Google OAuth flow (browser redirect) |
| `GET`  | `/auth/google/callback` | — | Google's redirect target; issues our own tokens |

---

## Security notes

**Argon2id** is the OWASP-recommended password hashing algorithm. Memory-hard (resists GPU brute-force), uses the "id" hybrid to resist side-channel attacks. `check_needs_rehash` silently upgrades hashes as cost parameters are tuned upward.

**User enumeration defense**: login returns "Invalid email or password" for both "email not found" and "wrong password". Runs the full Argon2 computation even on the not-found path so response time is identical in both cases.

**Algorithm pinning**: `jwt.decode` is called with `algorithms=["HS256"]` explicitly, preventing the algorithm-confusion attack (`"alg": "none"` or RS256 public key substitution).

**Refresh token rotation**: every successful refresh invalidates the old token and issues a new one. A stolen refresh token becomes invalid the next time the legitimate client rotates.

**OAuth: user never gives Google password to our app**: the entire point of OAuth 2.0 is that authentication is *delegated* — the user proves identity to Google, and Google vouches for them via a signed ID token. We verify that signature using Google's public JWKS, then issue our own session. Our server never handles Google credentials.

**ID token vs access token (Google's)**: we intentionally ignore Google's access token after the flow. We only use the *ID token* to learn who the user is, then create our own session. Using Google's access token to call our own API would tightly couple our security to Google's token lifetime and format.

---

## What's not here (Phase 3)

- HttpOnly cookie storage for refresh tokens
- Email verification
- Rate limiting / lockout
- GitHub / other OAuth providers
- HTTPS / production deployment
