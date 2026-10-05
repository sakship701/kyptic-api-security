import os
import re
from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import settings

DATABASE_URL = settings.DATABASE_URL


def get_secret_safe_url(url: str) -> str:
    """Mask password credentials in database URL for safe logging."""
    if not url:
        return ""
    # Mask password in postgresql://user:pass@host/db or similar
    return re.sub(r"://([^:]+):([^@]+)@", r"://\1:****@", url)


def create_db_engine(db_url: str):
    """Create engine configured appropriately for SQLite or PostgreSQL."""
    if db_url.startswith("sqlite"):
        return create_engine(
            db_url,
            connect_args={"check_same_thread": False},
        )
    else:
        return create_engine(
            db_url,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20,
        )


engine = create_db_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


class Base(DeclarativeBase):
    pass


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_test_db_isolation(test_db_url: str) -> None:
    """
    Safety check ensuring tests do NOT execute against the production/dev database.
    Prevents accidental database wiping or mutation.
    """
    prod_url = settings.DATABASE_URL
    if not test_db_url:
        raise ValueError("TEST_DATABASE_URL is not configured.")

    if test_db_url == prod_url:
        raise RuntimeError(
            f"SECURITY ERROR: TEST_DATABASE_URL matches production DATABASE_URL ({get_secret_safe_url(prod_url)}). "
            "Tests must be executed against a separate test database!"
        )


def validate_db_connection() -> bool:
    """Validate database connectivity on application startup."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as e:
        safe_url = get_secret_safe_url(DATABASE_URL)
        print(f"Database connection check failed for {safe_url}: {e}")
        return False
