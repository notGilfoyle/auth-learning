from datetime import datetime
from sqlalchemy import String, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship
from database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    # Nullable: Google-authenticated users have no password.
    # Local (email/password) users always have a non-null hash.
    hashed_password: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    # "local" = email/password login; "google" = created via Google OAuth.
    # A user whose account was created locally but later signs in with Google
    # keeps auth_provider="local"; we just link their google_sub.
    auth_provider: Mapped[str] = mapped_column(
        String(32), nullable=False, default="local"
    )
    # Google's stable identifier for the user (the 'sub' claim in the ID token).
    # Stored so we can recognise a returning Google user without relying solely
    # on email (which users can change on Google's side).
    google_sub: Mapped[str | None] = mapped_column(
        String(256), nullable=True, unique=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    # Opaque random token (not a JWT) — stored so it can be explicitly revoked.
    token: Mapped[str] = mapped_column(String(512), unique=True, index=True, nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)

    user: Mapped["User"] = relationship(back_populates="refresh_tokens")
