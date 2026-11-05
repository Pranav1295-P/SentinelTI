"""Password hashing and session tokens."""

import secrets
from datetime import UTC, datetime, timedelta

import jwt
from pwdlib import PasswordHash

from app.core.config import settings

ALGORITHM = "HS256"
COOKIE_NAME = "sentinelti_session"

_hasher = PasswordHash.recommended()
# Verified against when the email is unknown, so login timing does not reveal accounts.
_decoy_hash = _hasher.hash(secrets.token_urlsafe(16))
_dev_secret = secrets.token_urlsafe(48)


def signing_key() -> str:
    configured = settings.secret_key.get_secret_value()
    if configured:
        return configured
    if settings.environment == "production":
        raise RuntimeError("SECRET_KEY must be set in production")
    return _dev_secret


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, stored_hash: str | None) -> bool:
    return _hasher.verify(password, stored_hash or _decoy_hash) and stored_hash is not None


def create_access_token(user_id: str) -> str:
    now = datetime.now(UTC)
    claims = {
        "sub": user_id,
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_minutes),
    }
    return jwt.encode(claims, signing_key(), algorithm=ALGORITHM)


def decode_access_token(token: str) -> str | None:
    """Return the user id, or None for any invalid or expired token."""
    try:
        return jwt.decode(token, signing_key(), algorithms=[ALGORITHM]).get("sub")
    except jwt.PyJWTError:
        return None
