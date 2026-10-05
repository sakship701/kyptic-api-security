import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.database import Base, get_db, get_secret_safe_url, verify_test_db_isolation
from app.dependencies.auth import get_current_user
from app.main import app
from app.migrations.migrate_sqlite_to_postgres import run_sqlite_to_postgres_migration
from app.models.api_endpoint import ApiEndpoint
from app.models.finding import Finding, FindingSeverity
from app.models.organization import Organization, OrganizationMember
from app.models.project import Project
from app.models.scan import Scan
from app.models.user import User
from app.services.storage_service import storage_service


@pytest.fixture(scope="module")
def test_engine():
    """Create an isolated in-memory test database engine with StaticPool for Phase 1 tests."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="module")
def migrated_test_engine():
    """Create an in-memory database engine populated from the real kyptic.db baseline."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    backend_dir = Path(__file__).resolve().parents[1]
    sqlite_db_path = backend_dir / "kyptic.db"
    if not sqlite_db_path.exists():
        sqlite_db_path = backend_dir / "kyptic.db.bak"

    run_sqlite_to_postgres_migration(sqlite_db_path, engine, verbose=False)

    # Create demo owner user and bind Project 1 for authenticated API tests
    with Session(engine) as session:
        demo_user = User(
            id=1,
            email=settings.BOOTSTRAP_OWNER_EMAIL,
            password_hash="pbkdf2_sha256$600000$demo$hash",
            full_name="Demo Owner",
            is_active=True,
            is_superuser=False,
        )
        session.add(demo_user)
        project = session.get(Project, 1)
        if project:
            project.user_id = 1
        session.commit()

    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client(migrated_test_engine):
    """FastAPI TestClient overriding get_db and get_current_user to connect to the migrated test engine."""
    def _override_get_db():
        with Session(migrated_test_engine) as session:
            yield session

    def _override_get_current_user():
        with Session(migrated_test_engine) as session:
            return session.get(User, 1)

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_current_user] = _override_get_current_user
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


# 1. Test database URL credential masking
def test_get_secret_safe_url():
    url_with_pass = "postgresql+psycopg2://kyptic_user:super_secret_password@localhost:5432/kyptic_db"
    safe = get_secret_safe_url(url_with_pass)
    assert "super_secret_password" not in safe
    assert "kyptic_user:****@" in safe


# 2. Test production database protection check
def test_verify_test_db_isolation():
    with pytest.raises(RuntimeError, match="SECURITY ERROR"):
        verify_test_db_isolation(settings.DATABASE_URL)

    # Isolated test database URL should pass
    verify_test_db_isolation("sqlite:///:memory:")


# 3. Test storage abstraction cross-platform key resolution
def test_storage_abstraction():
    legacy_win_path = r"C:\kyptic-api-security\backend\data\projects\1\openapi_spec.raw"
    resolved = storage_service.get_file_path(legacy_win_path)
    assert str(resolved).endswith(os.path.join("projects", "1", "openapi_spec.raw"))

    logical_key = "projects/1/source/main.py"
    key_resolved = storage_service.get_file_path(logical_key)
    assert str(key_resolved).endswith(os.path.join("projects", "1", "source", "main.py"))


# 4. Test SQLite to PostgreSQL / target database migration and data integrity
def test_sqlite_to_postgres_migration_integrity(migrated_test_engine):
    with Session(migrated_test_engine) as session:
        projects = session.scalars(select(Project)).all()
        scans = session.scalars(select(Scan)).all()
        findings = session.scalars(select(Finding)).all()
        endpoints = session.scalars(select(ApiEndpoint)).all()

        assert len(projects) == 1
        assert projects[0].name == "Kyptic Demo Vulnerable App"
        assert len(scans) >= 1
        assert len(findings) == 17

        # Severity breakdown verification: 1 Critical, 5 High, 11 Medium, 0 Low
        severities = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity).lower()
            if sev in severities:
                severities[sev] += 1

        assert severities["critical"] == 1
        assert severities["high"] == 5
        assert severities["medium"] == 11
        assert severities["low"] == 0


# 5. Test API backward compatibility against migrated database
def test_api_compatibility_projects(client):
    response = client.get("/api/projects")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    p = data[0]
    assert p["id"] == 1
    assert p["name"] == "Kyptic Demo Vulnerable App"
    assert p["score"] == 12
    assert p["critical"] == 1
    assert p["high"] == 5
    assert p["medium"] == 11
    assert p["total_findings"] == 17
    assert p["has_data"] is True


def test_api_compatibility_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_api_compatibility_posture(client):
    response = client.get("/api/projects/1/posture")
    assert response.status_code == 200
    posture = response.json()
    assert posture["project_id"] == 1
    assert posture["score"] == 12
    assert posture["total_findings"] == 17
    assert posture["has_data"] is True
