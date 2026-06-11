# Auth Learning Demo

A production-quality full-stack authentication app built to demonstrate the core concepts behind modern web auth. Intended as a portfolio/learning reference — every non-obvious security decision has an inline comment explaining the *why*.

**Stack:** Python · FastAPI · SQLite · Argon2 · JWT · React · Vite

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
```

**Access token** — short-lived JWT (default 15 min). Verified stateless by the server (signature + exp claim, no DB lookup). Cannot be revoked early — that's why the lifetime is short.

**Refresh token** — long-lived opaque random string (default 7 days) stored in the database. Can be individually revoked. Rotated (old token invalidated, new one issued) on every use.

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
# Edit .env and set SECRET_KEY to a long random value:
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

## API endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/auth/register` | — | Create a new user |
| `POST` | `/auth/login` | — | Verify credentials, issue access + refresh tokens |
| `GET`  | `/auth/me` | Bearer | Return the current user's profile |
| `POST` | `/auth/refresh` | — | Exchange a refresh token for a new token pair |
| `POST` | `/auth/logout` | — | Revoke a refresh token |

---

## Security notes

**Argon2id** is the OWASP-recommended password hashing algorithm. It's memory-hard (resists GPU brute-force) and uses the "id" hybrid to resist side-channel attacks. The `check_needs_rehash` call on login silently upgrades hashes when the cost parameters are tuned upward over time.

**User enumeration defense**: the login endpoint returns the identical error ("Invalid email or password") for both "email not found" and "wrong password". It also runs the full Argon2 computation even on the not-found path (against a dummy hash) so the response time is the same in both cases.

**Algorithm pinning**: `jwt.decode` is called with `algorithms=["HS256"]` explicitly. Omitting this allows the algorithm-confusion attack where a malicious token uses `"alg": "none"` or substitutes an asymmetric public key for the HMAC secret.

**Refresh token rotation**: every successful refresh invalidates the presented token and issues a new one. If a refresh token is stolen, it becomes invalid the next time the legitimate client rotates — providing a signal that the session may be compromised.

---

## What's not here (Phase 2)

- OAuth 2.0 / social login (Google, GitHub)
- HttpOnly cookie storage for refresh tokens
- Email verification
- Rate limiting / lockout
- HTTPS / production deployment
