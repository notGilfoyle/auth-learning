from contextlib import asynccontextmanager
from datetime import datetime, timezone

from authlib.integrations.starlette_client import OAuth
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from sqlalchemy import text
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

import models
import schemas
from auth.dependencies import get_current_user
from auth.security import (
    DUMMY_HASH,
    check_needs_rehash,
    create_access_token,
    create_refresh_token,
    hash_password,
    verify_password,
)
from config import settings
from database import engine, get_db
from models import RefreshToken, User


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables that don't exist yet.
    models.Base.metadata.create_all(bind=engine)

    # Lightweight schema migration for databases that pre-date the Google OAuth
    # columns.  SQLite only supports ADD COLUMN (not MODIFY COLUMN), so we can
    # add new nullable columns but cannot relax the NOT NULL constraint on
    # hashed_password — that requires recreating the table (use Alembic in
    # production).  If you hit a NOT NULL error on hashed_password, delete
    # auth.db and restart; the fresh table will have the correct nullable schema.
    with engine.connect() as conn:
        for stmt in [
            "ALTER TABLE users ADD COLUMN auth_provider VARCHAR(32) NOT NULL DEFAULT 'local'",
            "ALTER TABLE users ADD COLUMN google_sub VARCHAR(256)",
        ]:
            try:
                conn.execute(text(stmt))
                conn.commit()
            except Exception:
                pass  # Column already exists — safe to ignore.

    yield


app = FastAPI(title="Auth Learning API", version="1.0.0", lifespan=lifespan)

# SessionMiddleware is required by Authlib's Starlette integration.
# It stores the OAuth 'state' (CSRF token) and OIDC 'nonce' in a signed
# cookie between the /auth/google/login redirect and the callback.
# The secret_key signs the cookie so clients cannot tamper with state.
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key)

# CORS: allow the Vite dev server to call this API from the browser.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Google OAuth / OIDC client
# ---------------------------------------------------------------------------
# Authlib reads Google's OIDC discovery document from server_metadata_url and
# automatically learns the authorization endpoint, token endpoint, and JWKS
# URI — no hardcoded Google URLs anywhere in our code.
oauth = OAuth()
oauth.register(
    name="google",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_id=settings.google_client_id,
    client_secret=settings.google_client_secret,
    client_kwargs={"scope": "openid email profile"},
)


# ---------------------------------------------------------------------------
# Email / password routes (unchanged)
# ---------------------------------------------------------------------------


@app.post("/auth/register", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED)
def register(body: schemas.UserRegister, db: Session = Depends(get_db)) -> User:
    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )
    user = User(
        email=body.email,
        hashed_password=hash_password(body.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/auth/login", response_model=schemas.TokenResponse)
def login(body: schemas.UserLogin, db: Session = Depends(get_db)) -> dict:
    user = db.query(User).filter(User.email == body.email).first()

    # User enumeration defense: always run the full Argon2 verification even
    # when the email is not found OR the account has no password (Google-only).
    # This keeps response time constant across all failure modes.
    if user is None or user.hashed_password is None:
        verify_password(body.password, DUMMY_HASH)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not verify_password(body.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    # Silently upgrade the stored hash if Argon2 parameters have changed.
    if check_needs_rehash(user.hashed_password):
        user.hashed_password = hash_password(body.password)
        db.commit()

    access_token = create_access_token(user.id)
    refresh_token_value, expires_at = create_refresh_token()
    db.add(RefreshToken(token=refresh_token_value, user_id=user.id, expires_at=expires_at))
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token_value,
        "token_type": "bearer",
    }


@app.get("/auth/me", response_model=schemas.UserOut)
def me(current_user: User = Depends(get_current_user)) -> User:
    return current_user


@app.post("/auth/refresh", response_model=schemas.TokenResponse)
def refresh(body: schemas.RefreshRequest, db: Session = Depends(get_db)) -> dict:
    db_token = (
        db.query(RefreshToken).filter(RefreshToken.token == body.refresh_token).first()
    )

    now = datetime.now(timezone.utc)
    token_valid = (
        db_token is not None
        and not db_token.revoked
        and db_token.expires_at.replace(tzinfo=timezone.utc) > now
    )

    if not token_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    # Refresh token rotation: revoke the old one and issue a new pair.
    db_token.revoked = True  # type: ignore[union-attr]

    new_access = create_access_token(db_token.user_id)  # type: ignore[union-attr]
    new_refresh_value, new_expires = create_refresh_token()
    db.add(
        RefreshToken(
            token=new_refresh_value,
            user_id=db_token.user_id,  # type: ignore[union-attr]
            expires_at=new_expires,
        )
    )
    db.commit()

    return {
        "access_token": new_access,
        "refresh_token": new_refresh_value,
        "token_type": "bearer",
    }


@app.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(body: schemas.LogoutRequest, db: Session = Depends(get_db)) -> None:
    db_token = (
        db.query(RefreshToken).filter(RefreshToken.token == body.refresh_token).first()
    )
    if db_token:
        db_token.revoked = True
        db.commit()
    # Always return 204 whether or not the token existed — no information leak.


# ---------------------------------------------------------------------------
# Google OAuth / OIDC routes
# ---------------------------------------------------------------------------


@app.get("/auth/google/login")
async def google_login(request: Request):
    """
    Step 1 — Redirect the browser to Google's consent screen.

    Authlib generates a random 'state' (CSRF token) and an OIDC 'nonce',
    stores both in the signed session cookie, then returns a 302 to Google's
    authorization endpoint.

    SECURITY: The user types their Google password into Google's login page,
    never into our app.  We never see it.  That is the core security benefit
    of OAuth 2.0: delegated authentication.  We are just asking Google to
    vouch for the user's identity.
    """
    if not settings.google_client_id:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=(
                "Google OAuth is not configured. "
                "Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env"
            ),
        )
    redirect_uri = "http://localhost:8000/auth/google/callback"
    return await oauth.google.authorize_redirect(request, redirect_uri)


@app.get("/auth/google/callback")
async def google_callback(request: Request, db: Session = Depends(get_db)):
    """
    Step 2 — Google redirects back here with an authorization code.

    What Authlib does automatically:
    1. Validates the 'state' query param against the session cookie — CSRF check.
    2. Exchanges the code for tokens via a back-channel POST to Google's token
       endpoint (the code never reaches the frontend, preventing interception).
    3. Fetches Google's public JWKS and validates the ID token's RS256 signature
       and claims (iss, aud, exp, nonce).  The ID token is a JWT signed by
       Google — Authlib verifies it using Google's *public key*, just as our
       own middleware verifies our HS256 JWTs using our *secret key*.

    What we do after:
    4. Extract the validated email and Google 'sub' (a stable, unique identifier
       for the Google account that never changes even if the user renames their
       Google account).
    5. Find or create the user in our own database.
    6. Issue OUR OWN access + refresh tokens — reusing the exact same functions
       as password login.  From here on, the session is identical regardless of
       how the user authenticated.
    """
    try:
        token = await oauth.google.authorize_access_token(request)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OAuth authorization failed. Please try signing in again.",
        )

    userinfo = token.get("userinfo")
    if not userinfo or not userinfo.get("email"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google did not return an email address.",
        )

    email: str = userinfo["email"]
    google_sub: str = userinfo["sub"]

    # Find or create the user.
    user = db.query(User).filter(User.email == email).first()

    if user is None:
        # First-ever sign-in: create an account with no password.
        user = User(
            email=email,
            hashed_password=None,
            auth_provider="google",
            google_sub=google_sub,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    elif user.google_sub is None:
        # Existing local user signing in with Google for the first time —
        # link their Google sub so future Google sign-ins find this account.
        user.google_sub = google_sub
        db.commit()

    # Issue our own tokens — identical to the password login path.
    access_token = create_access_token(user.id)
    refresh_token_value, expires_at = create_refresh_token()
    db.add(RefreshToken(token=refresh_token_value, user_id=user.id, expires_at=expires_at))
    db.commit()

    # Redirect to the frontend callback page with tokens in the URL fragment.
    #
    # WHY THE FRAGMENT (#) and not query params (?):
    #   Fragments are not sent to any server — they live only in the browser —
    #   so the tokens won't appear in our backend access logs or Google's
    #   referrer headers.
    #
    # REMAINING RISK: tokens are briefly visible in the address bar and may
    # be persisted in browser history.
    #
    # PRODUCTION ALTERNATIVES (more secure):
    #   1. HttpOnly cookie — set Set-Cookie on this response; JS can't read it,
    #      eliminating XSS theft entirely.
    #   2. One-time code exchange — redirect with a short-lived opaque code;
    #      the frontend POSTs it to /auth/token-exchange to get the real tokens,
    #      so they never appear in any URL.
    frontend_callback = (
        "http://localhost:5173/auth/callback"
        f"#access_token={access_token}&refresh_token={refresh_token_value}"
    )
    return RedirectResponse(url=frontend_callback)
