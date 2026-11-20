"""Password hashing (argon2id), session token generation, and login throttling."""

from __future__ import annotations

import hashlib
import secrets
import time
from collections import defaultdict, deque

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

_password_hasher = PasswordHasher()

# Sliding-window login attempt tracker keyed by (ip, email)
_attempts: dict[str, deque[float]] = defaultdict(deque)


def hash_password(password: str) -> str:
    return _password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def generate_session_token() -> str:
    return secrets.token_urlsafe(32)


def hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def check_and_record_login_attempt(
    key: str,
    *,
    max_attempts: int,
    window_seconds: int,
) -> bool:
    """Return True if attempt is allowed, False if rate-limited."""
    now = time.monotonic()
    q = _attempts[key]
    cutoff = now - window_seconds
    while q and q[0] < cutoff:
        q.popleft()
    if len(q) >= max_attempts:
        return False
    q.append(now)
    return True


def clear_login_attempts(key: str) -> None:
    _attempts.pop(key, None)


def validate_password_strength(password: str) -> None:
    """Enforce baseline password complexity for admin-created and reset passwords."""
    if len(password) < 12 or len(password) > 128:
        raise ValueError("Password must be between 12 and 128 characters.")
    if not any(ch.isupper() for ch in password):
        raise ValueError("Password must include at least one uppercase letter.")
    if not any(ch.islower() for ch in password):
        raise ValueError("Password must include at least one lowercase letter.")
    if not any(ch.isdigit() or not ch.isalnum() for ch in password):
        raise ValueError("Password must include at least one digit or symbol.")


def reset_rate_limiter() -> None:
    """Clear all rate-limiter state (intended for tests)."""
    _attempts.clear()
