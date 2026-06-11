import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

from config import settings

# ---------------------------------------------------------------------------
# Argon2id password hashing
# ---------------------------------------------------------------------------
# Argon2id is the OWASP-recommended variant: it resists both GPU-accelerated
# dictionary attacks (via memory-hardness) and side-channel attacks (via the
# 'i' component).  argon2-cffi's defaults are deliberately conservative
# (time_cost=3 iterations, memory_cost=64 MB, parallelism=4 threads).
# Increase time_cost or memory_cost as hardware improves to keep up with
# attacker capability — without requiring users to reset passwords (see
# check_needs_rehash below).
ph = PasswordHasher()

# Pre-computed dummy hash used in the login timing-attack defense (see main.py).
# Running verify_password against this when the email is not found makes the
# response time identical to a wrong-password attempt.
DUMMY_HASH: str = ph.hash("__unused_dummy_for_timing_normalization__")

ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    """Hash a plaintext password with Argon2id. Never store the return value's input."""
    return ph.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plaintext password against its Argon2 hash.

    Returns False (never raises) on any mismatch or malformed hash, so callers
    always receive a boolean — no exception-path timing difference.
    """
    try:
        return ph.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def check_needs_rehash(hashed_password: str) -> bool:
    """
    Return True if the stored hash used weaker parameters than the current defaults.

    Call this on every successful login and silently re-hash with up-to-date
    settings.  Users automatically get stronger hashes over time without any
    password-reset flow.
    """
    return ph.check_needs_rehash(hashed_password)


# ---------------------------------------------------------------------------
# JWT access tokens
# ---------------------------------------------------------------------------


def create_access_token(subject: str | int) -> str:
    """
    Create a short-lived, signed JWT access token.

    Access tokens are STATELESS — the server validates them by checking the
    HMAC-SHA256 signature and the 'exp' claim, with no database lookup.
    This is fast, but means revocation is impossible before expiry.  That is
    why access tokens must be short-lived (default: 15 minutes).
    """
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": str(subject),
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    """
    Decode and cryptographically verify a JWT access token.

    Passing algorithms=["HS256"] explicitly prevents the 'algorithm confusion'
    attack (CVE-class): an attacker could craft a token signed with 'none' or
    an RS256 public key if the server accepted any algorithm.
    """
    return jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])


# ---------------------------------------------------------------------------
# Opaque refresh tokens
# ---------------------------------------------------------------------------


def create_refresh_token() -> tuple[str, datetime]:
    """
    Generate a cryptographically random refresh token and its expiry timestamp.

    Refresh tokens are intentionally NOT JWTs.  Using an opaque random string
    (256 bits of entropy from secrets.token_urlsafe) stored in the database
    means they can be individually revoked on logout or after rotation — unlike
    a stateless JWT, which cannot be invalidated before its 'exp' claim.
    """
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)
    return token, expires_at
