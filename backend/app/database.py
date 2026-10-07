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


LIVE_DB_NAMES = {"kyptic_db", "kyptic.db"}


def is_live_database_url(url: str) -> bool:
    """Check if a database URL targets the live application database (kyptic_db or kyptic.db)."""
    if not url:
        return False
    cleaned = url.split("?")[0].rstrip("/\\")
    if "sqlite" in cleaned:
        db_name = Path(cleaned).name.lower()
        return db_name == "kyptic.db"
    else:
        db_name = cleaned.split("/")[-1].lower()
        return db_name in LIVE_DB_NAMES


def verify_test_db_isolation(test_db_url: str) -> None:
    """
    Safety check ensuring tests do NOT execute against the production/dev database.
    Prevents accidental database wiping or mutation.
    """
    if not test_db_url:
        raise ValueError("Database URL for test is not configured.")

    if is_live_database_url(test_db_url):
        raise RuntimeError(
            f"SECURITY ISOLATION ERROR: Refusing to execute tests against live/production application database ({get_secret_safe_url(test_db_url)}). "
            "Tests MUST use an isolated test database (e.g. TEST_DATABASE_URL=postgresql+psycopg2://kyptic:kyptic_dev_pass@localhost:5432/kyptic_test_db)!"
        )


def create_db_engine(db_url: str):
    """Create engine configured appropriately for SQLite or PostgreSQL."""
    if "PYTEST_CURRENT_TEST" in os.environ or os.getenv("TESTING", "").lower() in ("true", "1", "yes"):
        verify_test_db_isolation(db_url)

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
