from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

import models
import schemas
from database import engine, get_db
from models import RefreshToken, User
from auth.dependencies import get_current_user
from auth.security import (
    DUMMY_HASH,
    check_needs_rehash,
    create_access_token,
    create_refresh_token,
    hash_password,
    verify_password,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create all tables on startup.  Replace with Alembic migrations for
    # a production project where schema changes must be tracked.
    models.Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title="Auth Learning API", version="1.0.0", lifespan=lifespan)

# CORS: allow the Vite dev server to call this API from the browser.
# In production, lock this down to your actual frontend origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Auth routes
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
    # when the email is not found.  Without this, an attacker could distinguish
    # "email unknown" (fast path, no hash work) from "wrong password" (slow
    # path, full hash computation) purely by response timing.  The DUMMY_HASH
    # makes both code paths take the same ~100 ms.
    if user is None:
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

    # Silently upgrade the stored hash if the Argon2 parameters have been
    # strengthened since the password was last set — no user action required.
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

    # Refresh token rotation: revoke the presented token immediately and issue
    # a fresh pair.  This limits the blast radius if a refresh token is ever
    # stolen — each token is single-use, so a leaked token becomes invalid the
    # next time the legitimate client rotates.
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
