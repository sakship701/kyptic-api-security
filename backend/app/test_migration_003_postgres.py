import os
import pytest
from sqlalchemy import create_engine, text, inspect
from alembic import command
from alembic.config import Config
from pathlib import Path


from app.database import verify_test_db_isolation


POSTGRES_TEST_URL = os.getenv(
    "TEST_DATABASE_URL",
    "postgresql+psycopg2://kyptic:kyptic_dev_pass@localhost:5432/kyptic_test_db"
)


def get_alembic_config(db_url: str) -> Config:
    backend_dir = Path(__file__).resolve().parents[1]
    ini_path = backend_dir / "alembic.ini"
    cfg = Config(str(ini_path))
    cfg.set_main_option("sqlalchemy.url", db_url)
    cfg.set_main_option("script_location", str(backend_dir / "alembic"))
    return cfg


def ensure_test_db_exists(db_url: str):
    if "postgresql" in db_url and "kyptic_test_db" in db_url:
        base_url = db_url.rsplit("/", 1)[0] + "/postgres"
        try:
            root_engine = create_engine(base_url, isolation_level="AUTOCOMMIT")
            with root_engine.connect() as conn:
                res = conn.execute(text("SELECT 1 FROM pg_database WHERE datname='kyptic_test_db'")).scalar()
                if not res:
                    conn.execute(text("CREATE DATABASE kyptic_test_db"))
            root_engine.dispose()
        except Exception:
            pass


def test_migration_003_postgres_boolean_semantics(monkeypatch):
    """
    Regression Test for Migration 003:
    Proves that migration 003 executes cleanly against PostgreSQL BOOLEAN column semantics,
    normalizes NULL and True superuser values to False, and preserves BOOLEAN data type.
    """
    verify_test_db_isolation(POSTGRES_TEST_URL)
    ensure_test_db_exists(POSTGRES_TEST_URL)

    from app.config import settings
    monkeypatch.setenv("DATABASE_URL", POSTGRES_TEST_URL)
    monkeypatch.setattr(settings, "DATABASE_URL", POSTGRES_TEST_URL)

    engine = create_engine(POSTGRES_TEST_URL, pool_pre_ping=True)
    
    # 1. Reset database schema to clean state
    with engine.connect() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public;"))
        conn.commit()

    cfg = get_alembic_config(POSTGRES_TEST_URL)

    # 2. Upgrade to migration 002
    command.upgrade(cfg, "002_add_user_project_ownership")

    # 3. Seed users with True, False, and NULL for is_superuser before running migration 003
    with engine.connect() as conn:
        # Drop NOT NULL constraint on is_superuser temporarily to test NULL handling
        conn.execute(text("ALTER TABLE users ALTER COLUMN is_superuser DROP NOT NULL"))
        conn.execute(
            text("""
                INSERT INTO users (email, password_hash, full_name, is_active, is_superuser, created_at, updated_at)
                VALUES 
                    ('user_true@kyptic.test', 'hash1', 'User True', true, true, NOW(), NOW()),
                    ('user_false@kyptic.test', 'hash2', 'User False', true, false, NOW(), NOW()),
                    ('user_null@kyptic.test', 'hash3', 'User Null', true, NULL, NOW(), NOW())
            """)
        )
        conn.commit()

    # 4. Upgrade through migration 003 (and head)
    command.upgrade(cfg, "003_enforce_single_user_role")

    # 5. Verify data normalization
    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT email, is_superuser FROM users ORDER BY email")
        ).fetchall()
        
        user_map = {row[0]: row[1] for row in rows}
        assert user_map['user_false@kyptic.test'] is False
        assert user_map['user_null@kyptic.test'] is False
        assert user_map['user_true@kyptic.test'] is False

    # 6. Verify column remains PostgreSQL BOOLEAN
    inspector = inspect(engine)
    columns = inspector.get_columns("users")
    is_superuser_col = next(c for c in columns if c["name"] == "is_superuser")
    col_type_name = str(is_superuser_col["type"]).upper()
    assert "BOOLEAN" in col_type_name

    # 7. Complete upgrade to head
    command.upgrade(cfg, "head")

    engine.dispose()
