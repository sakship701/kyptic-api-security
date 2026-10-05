import os
from pathlib import Path
import pytest

# Set DATABASE_URL to an isolated test database BEFORE app imports
TEST_DB_PATH = Path(__file__).resolve().parents[1] / "test_kyptic.db"
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB_PATH}"

from app.database import Base, engine, SessionLocal, DATABASE_URL


@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    """Ensure test database is isolated and initialized before running any tests."""
    print(f"\n[PYTEST DATABASE ISOLATION] Test DB URL: {DATABASE_URL}")
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
    engine.dispose()
    if TEST_DB_PATH.exists():
        try:
            TEST_DB_PATH.unlink()
        except Exception:
            pass
