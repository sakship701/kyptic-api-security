import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.finding import Finding, FindingSeverity, FindingStatus, FindingSource
from app.services.posture_service import calculate_risk_score, get_project_posture, get_global_posture

# Setup isolated in-memory SQLite database with StaticPool for thread-safe test sharing
SQLALCHEMY_TEST_DATABASE_URL = "sqlite:///:memory:"
test_engine = create_engine(
    SQLALCHEMY_TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_db():
    app.dependency_overrides[get_db] = override_get_db
    Base.metadata.create_all(bind=test_engine)
    db = TestingSessionLocal()
    db.query(Finding).delete()
    db.query(Scan).delete()
    db.query(Project).delete()
    db.commit()
    db.close()
    yield
    Base.metadata.drop_all(bind=test_engine)
    app.dependency_overrides.clear()


def test_posture_calculation_empty_data():
    db = TestingSessionLocal()
    score, grade, counts = calculate_risk_score([])
    assert score == 100
    assert grade == "A (Excellent)"

    global_posture = get_global_posture(db)
    assert global_posture["has_data"] is False
    assert global_posture["score"] is None
    assert global_posture["grade"] == "No assessment data"
    db.close()


def test_posture_calculation_with_findings():
    db = TestingSessionLocal()
    project = Project(name="Test App", status="READY")
    db.add(project)
    db.commit()

    finding1 = Finding(
        project_id=project.id,
        scan_id=1,
        title="SQL Injection",
        description="SQL injection vulnerability detected in auth module.",
        severity=FindingSeverity.CRITICAL,
        status=FindingStatus.OPEN,
        file_path="/app/auth.py",
        category="Injection",
        source=FindingSource.SAST,
    )
    finding2 = Finding(
        project_id=project.id,
        scan_id=1,
        title="XSS Risk",
        description="Reflected XSS vulnerability detected in view template.",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
        file_path="/app/views.py",
        category="XSS",
        source=FindingSource.SAST,
    )

    db.add_all([finding1, finding2])
    db.commit()

    project_posture = get_project_posture(db, project.id)
    assert project_posture["has_data"] is True
    # 100 - (15 + 8) = 77
    assert project_posture["score"] == 77
    assert project_posture["counts"]["critical"] == 1
    assert project_posture["counts"]["high"] == 1
    db.close()


def test_posture_endpoints_via_client():
    # Test zero-data global posture
    res = client.get("/api/projects/global/posture")
    assert res.status_code == 200
    data = res.json()
    assert data["has_data"] is False
    assert data["score"] is None
    assert data["grade"] == "No assessment data"

    # Create project and test project posture
    proj_res = client.post("/api/projects", json={"name": "Demo Project", "technology": "Python", "description": "Test"})
    assert proj_res.status_code == 201
    proj_id = proj_res.json()["id"]

    posture_res = client.get(f"/api/projects/{proj_id}/posture")
    assert posture_res.status_code == 200
    pdata = posture_res.json()
    assert pdata["has_data"] is False
    assert pdata["score"] is None


def test_scan_activity_endpoint():
    res = client.get("/api/scans/activity")
    assert res.status_code == 200
    activity_data = res.json()
    assert isinstance(activity_data, list)
    assert len(activity_data) == 30
    assert all("date" in item and "count" in item for item in activity_data)


def test_activity_feed_endpoint():
    res = client.get("/api/activity")
    assert res.status_code == 200
    feed = res.json()
    assert isinstance(feed, list)


def test_project_list_real_posture_and_isolation():
    db = TestingSessionLocal()
    proj1 = Project(name="Project One", technology="Python")
    proj2 = Project(name="Project Two", technology="Node")
    db.add_all([proj1, proj2])
    db.commit()

    f1 = Finding(
        project_id=proj1.id,
        scan_id=1,
        title="Critical Vulnerability",
        description="Critical injection vulnerability",
        severity=FindingSeverity.CRITICAL,
        status=FindingStatus.OPEN,
        file_path="app.py",
        category="Injection",
        source=FindingSource.SAST,
    )
    f2 = Finding(
        project_id=proj1.id,
        scan_id=1,
        title="High Vulnerability",
        description="High XSS vulnerability",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
        file_path="app.py",
        category="XSS",
        source=FindingSource.SAST,
    )
    db.add_all([f1, f2])
    db.commit()

    res = client.get("/api/projects")
    assert res.status_code == 200
    projects_data = res.json()
    assert len(projects_data) >= 2

    p1_data = next(p for p in projects_data if p["id"] == proj1.id)
    p2_data = next(p for p in projects_data if p["id"] == proj2.id)

    # Project 1 has findings
    assert p1_data["has_data"] is True
    assert p1_data["score"] == 77
    assert p1_data["critical"] == 1
    assert p1_data["high"] == 1
    assert p1_data["medium"] == 0
    assert p1_data["low"] == 0

    # Project 2 has NO findings (isolation & no-assessment test)
    assert p2_data["has_data"] is False
    assert p2_data["score"] is None
    assert p2_data["critical"] == 0
    assert p2_data["high"] == 0
    assert p2_data["medium"] == 0
    assert p2_data["low"] == 0
    db.close()
