import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple
import jwt

from sqlalchemy.orm import Session
from app.config import settings
from app.models.audit_log import AuditLog
from app.models.user import User

ALGORITHM = "HS256"
DEFAULT_EXPIRE_MINUTES = 60 * 24  # 24 hours
PBKDF2_ITERATIONS = int(os.getenv("PBKDF2_ITERATIONS", "100000"))

# Optional Argon2 support if argon2-cffi is installed
try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    _argon2_hasher: Optional[PasswordHasher] = PasswordHasher(
        time_cost=2,
        memory_cost=32768,  # 32 MB
        parallelism=2,
        hash_len=32,
        salt_len=16,
    )
except ImportError:
    _argon2_hasher = None


def hash_password(password: str) -> str:
    """
    Hashes a password using Argon2id if available, or PBKDF2-HMAC-SHA256.
    Format:
      - Argon2id: Starts with '$argon2id$'
      - PBKDF2: 'pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>'
    """
    if not password:
        raise ValueError("Password cannot be empty")

    if _argon2_hasher is not None:
        return _argon2_hasher.hash(password)

    salt = secrets.token_bytes(16)
    salt_hex = salt.hex()
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERATIONS)
    hash_hex = dk.hex()
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt_hex}${hash_hex}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plaintext password against a stored hash (supporting Argon2id and PBKDF2-HMAC-SHA256).
    Uses constant-time comparison to prevent timing side-channel attacks.
    """
    if not plain_password or not hashed_password:
        return False

    try:
        # Check Argon2id hash
        if hashed_password.startswith("$argon2"):
            if _argon2_hasher is not None:
                try:
                    return _argon2_hasher.verify(hashed_password, plain_password)
                except VerifyMismatchError:
                    return False
            return False

        # Check PBKDF2-HMAC-SHA256 hash
        parts = hashed_password.split('$')
        if len(parts) != 4 or parts[0] != 'pbkdf2_sha256':
            return False

        iterations = int(parts[1])
        salt = bytes.fromhex(parts[2])
        expected_hash = bytes.fromhex(parts[3])

        candidate_hash = hashlib.pbkdf2_hmac('sha256', plain_password.encode('utf-8'), salt, iterations)
        return hmac.compare_digest(candidate_hash, expected_hash)
    except Exception:
        return False


import uuid
from sqlalchemy import select
from app.models.user_session import UserSession


def hash_jti(jti: str) -> str:
    """
    Returns SHA256 hex digest of a session JTI to avoid storing raw tokens.
    """
    return hashlib.sha256(jti.encode("utf-8")).hexdigest()


def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None,
    db: Optional[Session] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> str:
    """
    Generates a cryptographically signed JWT access token containing a unique jti identifier.
    Persists a server-side UserSession record if db session is provided.
    """
    to_encode = data.copy()
    now = datetime.utcnow()
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=DEFAULT_EXPIRE_MINUTES)

    jti = to_encode.get("jti") or uuid.uuid4().hex

    to_encode.update({
        "exp": expire,
        "iat": now,
        "sub": str(data.get("user_id", "")),
        "jti": jti,
    })
    secret_key = settings.SECRET_KEY or "kyptic-production-secure-key-32-bytes"
    token = jwt.encode(to_encode, secret_key, algorithm=ALGORITHM)

    if db is not None and "user_id" in data and data["user_id"]:
        try:
            user_id = int(data["user_id"])
            jti_hashed = hash_jti(jti)
            session = UserSession(
                user_id=user_id,
                jti=jti_hashed,
                is_active=True,
                created_at=now,
                expires_at=expire,
                ip_address=ip_address,
                user_agent=user_agent,
            )
            db.add(session)
            db.commit()
        except Exception:
            db.rollback()

    return token


def revoke_user_session(db: Session, jti: str) -> bool:
    """
    Revokes an active server-side user session by its JTI identifier.
    """
    if not jti:
        return False
    jti_hashed = hash_jti(jti)
    session = db.scalar(select(UserSession).where(UserSession.jti == jti_hashed))
    if session and session.is_active:
        session.is_active = False
        session.revoked_at = datetime.utcnow()
        db.commit()
        return True
    return False


def is_session_active(db: Session, jti: str, user_id: int) -> bool:
    """
    Verifies if a server-side session identified by jti and user_id is active and not expired.
    """
    if not jti or not user_id:
        return False
    jti_hashed = hash_jti(jti)
    session = db.scalar(
        select(UserSession).where(
            UserSession.jti == jti_hashed,
            UserSession.user_id == user_id,
        )
    )
    if not session:
        return False
    if not session.is_active:
        return False
    if session.expires_at <= datetime.utcnow():
        return False
    return True


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Decodes and validates a JWT access token. Returns None if invalid, expired, or malformed.
    """
    try:
        secret_key = settings.SECRET_KEY or "kyptic-production-secure-key-32-bytes"
        payload = jwt.decode(token, secret_key, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None


def log_audit_event(
    db: Session,
    action: str,
    resource_type: str,
    user_id: Optional[int] = None,
    organization_id: Optional[int] = None,
    resource_id: Optional[str] = None,
    details: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> AuditLog:
    """
    Helper function to persist audit events to the audit_logs table.
    Never logs passwords, tokens, hashes, or secrets.
    """
    audit = AuditLog(
        user_id=user_id,
        organization_id=organization_id,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        details=details,
        ip_address=ip_address,
        created_at=datetime.utcnow(),
    )
    db.add(audit)
    db.commit()
    db.refresh(audit)
    return audit
