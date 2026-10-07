import os
import pytest
from pathlib import Path
from sqlalchemy import create_engine, select, text, inspect
from sqlalchemy.orm import Session
from alembic import command
from alembic.config import Config

from app.models.project import Project
from app.models.scan import Scan, ScanStatus


from app.database import verify_test_db_isolation

POSTGRES_TEST_URL = os.getenv(
    "TEST_DATABASE_URL",
    "postgresql+psycopg2://kyptic:kyptic_dev_pass@localhost:5432/kyptic_test_db"
)

# Disposable database URL for fresh migration verification
DISPOSABLE_POSTGRES_BASE_URL = os.getenv(
    "DISPOSABLE_POSTGRES_BASE_URL",
    "postgresql+psycopg2://kyptic:kyptic_dev_pass@localhost:5432/"
)
FRESH_MIGRATION_DB_NAME = "kyptic_test_fresh_migration_005"
FRESH_MIGRATION_DB_URL = f"{DISPOSABLE_POSTGRES_BASE_URL}{FRESH_MIGRATION_DB_NAME}"


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


def test_scan_metadata_long_string_persistence(monkeypatch):
    """
    Regression Test:
    Proves that storing scanner and scanner_version strings longer than 50 characters
    (such as aggregated multi-scanner strings) succeeds without StringDataRightTruncation error.
    """
    verify_test_db_isolation(POSTGRES_TEST_URL)
    ensure_test_db_exists(POSTGRES_TEST_URL)
    from app.config import settings
    monkeypatch.setenv("DATABASE_URL", POSTGRES_TEST_URL)
    monkeypatch.setattr(settings, "DATABASE_URL", POSTGRES_TEST_URL)

    engine = create_engine(POSTGRES_TEST_URL, pool_pre_ping=True)
    cfg = get_alembic_config(POSTGRES_TEST_URL)
    command.upgrade(cfg, "head")

    # Real failing strings from production UI scan
    failing_scanner = "semgrep, detect-secrets, sca-dependency, dast-web, kyptic-browser-dast, api-security"
    failing_scanner_version = "semgrep 1.174.0, detect-secrets 1.5.0, sca-dependency sca-dependency 1.0.0, dast-web 1.0.0"

    assert len(failing_scanner) > 50
    assert len(failing_scanner_version) > 50

    with Session(engine) as session:
        # Fetch or create sentinel project
        project = session.scalars(select(Project)).first()
        if not project:
            project = Project(name="Sentinel Metadata Project", technology="Python")
            session.add(project)
            session.commit()

        # Create scan with long scanner metadata strings
        scan = Scan(
            project_id=project.id,
            status=ScanStatus.COMPLETED,
            progress=100,
            current_phase="Completed",
            scanner=failing_scanner,
            scanner_version=failing_scanner_version,
            result_count=24,
            duration=91.79,
        )
        session.add(scan)
        session.commit()
        scan_id = scan.id

        # Re-fetch and verify exact persistence
        retrieved_scan = session.get(Scan, scan_id)
        assert retrieved_scan is not None
        assert retrieved_scan.scanner == failing_scanner
        assert retrieved_scan.scanner_version == failing_scanner_version
        assert retrieved_scan.result_count == 24
        assert retrieved_scan.duration == 91.79

        # Clean up sentinel scan
        session.delete(retrieved_scan)
        session.commit()

    # Column type verification via SQLAlchemy Inspector
    inspector = inspect(engine)
    columns = inspector.get_columns("scans")
    scanner_col = next(c for c in columns if c["name"] == "scanner")
    scanner_ver_col = next(c for c in columns if c["name"] == "scanner_version")

    assert scanner_col["type"].length == 255
    assert scanner_ver_col["type"].length == 255

    engine.dispose()


def test_fresh_postgresql_migration_path_reaches_head(monkeypatch):
    """
    Verification Test:
    Applies all Alembic migrations from scratch on a fresh PostgreSQL database
    and verifies revision 005_widen_scan_scanner_metadata is reached cleanly.
    """
    verify_test_db_isolation(FRESH_MIGRATION_DB_URL)
    from app.config import settings
    monkeypatch.setenv("DATABASE_URL", FRESH_MIGRATION_DB_URL)
    monkeypatch.setattr(settings, "DATABASE_URL", FRESH_MIGRATION_DB_URL)

    # Create temporary fresh DB
    root_engine = create_engine(f"{DISPOSABLE_POSTGRES_BASE_URL}postgres", isolation_level="AUTOCOMMIT")
    with root_engine.connect() as conn:
        conn.execute(text(f"DROP DATABASE IF EXISTS {FRESH_MIGRATION_DB_NAME}"))
        conn.execute(text(f"CREATE DATABASE {FRESH_MIGRATION_DB_NAME}"))
    root_engine.dispose()

    try:
        fresh_engine = create_engine(FRESH_MIGRATION_DB_URL, pool_pre_ping=True)
        cfg = get_alembic_config(FRESH_MIGRATION_DB_URL)

        # Run alembic upgrade head on fresh database
        command.upgrade(cfg, "head")

        # Verify current revision
        with fresh_engine.connect() as conn:
            result = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
            assert result == "005_widen_scan_scanner_metadata"

        # Verify scans table schema on fresh database
        inspector = inspect(fresh_engine)
        columns = inspector.get_columns("scans")
        scanner_col = next(c for c in columns if c["name"] == "scanner")
        scanner_ver_col = next(c for c in columns if c["name"] == "scanner_version")

        assert scanner_col["type"].length == 255
        assert scanner_ver_col["type"].length == 255

        fresh_engine.dispose()
    finally:
        # Clean up temporary database
        root_engine = create_engine(f"{DISPOSABLE_POSTGRES_BASE_URL}postgres", isolation_level="AUTOCOMMIT")
        with root_engine.connect() as conn:
            conn.execute(text(f"DROP DATABASE IF EXISTS {FRESH_MIGRATION_DB_NAME}"))
        root_engine.dispose()
