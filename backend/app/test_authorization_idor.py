from datetime import datetime
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models.api_endpoint import ApiEndpoint
from app.models.audit_log import AuditLog
from app.models.finding import Finding, FindingSeverity, FindingSource, FindingStatus
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.user import User


@pytest.fixture(scope="module")
def authz_engine():
    """Isolated in-memory test database engine for authorization and IDOR tests."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture(scope="module")
def client(authz_engine):
    """FastAPI TestClient with overridden database session."""
    def _override_get_db():
        with Session(authz_engine) as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture(scope="module")
def two_users_and_projects(client, authz_engine):
    """
    Creates two distinct users (User A, User B) and two distinct projects (Project A, Project B).
    """
    # 1. Register User A
    res_a = client.post("/api/auth/register", json={
        "email": "user_a@kyptic.security",
        "password": "Password123!",
        "full_name": "User A",
    })
    assert res_a.status_code == 201, f"Register User A failed: {res_a.text}"
    token_a = res_a.json()["access_token"]
    user_a_id = res_a.json()["user"]["id"]

    # 2. Register User B
    res_b = client.post("/api/auth/register", json={
        "email": "user_b@kyptic.security",
        "password": "Password123!",
        "full_name": "User B",
    })
    assert res_b.status_code == 201, f"Register User B failed: {res_b.text}"
    token_b = res_b.json()["access_token"]
    user_b_id = res_b.json()["user"]["id"]

    # 3. User A creates Project A
    res_proj_a = client.post("/api/projects", json={
        "name": "Project Alpha (User A)",
        "technology": "Python",
    }, headers={"Authorization": f"Bearer {token_a}"})
    assert res_proj_a.status_code == 201
    proj_a_id = res_proj_a.json()["id"]

    # 4. User B creates Project B
    res_proj_b = client.post("/api/projects", json={
        "name": "Project Beta (User B)",
        "technology": "Node.js",
    }, headers={"Authorization": f"Bearer {token_b}"})
    assert res_proj_b.status_code == 201
    proj_b_id = res_proj_b.json()["id"]

    # Populate Project B with scan, finding, and endpoint for indirect IDOR testing
    with Session(authz_engine) as session:
        scan_b = Scan(
            project_id=proj_b_id,
            status=ScanStatus.RUNNING,
            progress=25,
            current_phase="Testing Probes",
            started_at=datetime.utcnow(),
        )
        session.add(scan_b)
        session.commit()
        session.refresh(scan_b)
        scan_b_id = scan_b.id

        finding_b = Finding(
            project_id=proj_b_id,
            scan_id=scan_b_id,
            title="SQL Injection in Login Endpoint",
            description="Vulnerable SQL query",
            severity=FindingSeverity.CRITICAL,
            category="Injection",
            file_path="app/auth.py",
            status=FindingStatus.OPEN,
            source=FindingSource.SAST,
            fingerprint="fp-user-b-sql-123",
        )
        session.add(finding_b)

        endpoint_b = ApiEndpoint(
            project_id=proj_b_id,
            path="/api/v1/users",
            method="GET",
            summary="List Users",
            risk_score=85,
            risk_level="HIGH",
        )
        session.add(endpoint_b)
        session.commit()
        session.refresh(finding_b)
        session.refresh(endpoint_b)
        finding_b_id = finding_b.id
        endpoint_b_id = endpoint_b.id

    return {
        "token_a": token_a,
        "token_b": token_b,
        "user_a_id": user_a_id,
        "user_b_id": user_b_id,
        "proj_a_id": proj_a_id,
        "proj_b_id": proj_b_id,
        "scan_b_id": scan_b_id,
        "finding_b_id": finding_b_id,
        "endpoint_b_id": endpoint_b_id,
    }


# 1. Direct Project Authorization & List Isolation
def test_project_isolation(client, two_users_and_projects):
    d = two_users_and_projects
    headers_a = {"Authorization": f"Bearer {d['token_a']}"}
    headers_b = {"Authorization": f"Bearer {d['token_b']}"}

    # User A -> Project A = 200
    res = client.get(f"/api/projects/{d['proj_a_id']}", headers=headers_a)
    assert res.status_code == 200

    # User B -> Project B = 200
    res = client.get(f"/api/projects/{d['proj_b_id']}", headers=headers_b)
    assert res.status_code == 200

    # User A -> Project B = 403 Forbidden (Blocked)
    res = client.get(f"/api/projects/{d['proj_b_id']}", headers=headers_a)
    assert res.status_code == 403

    # User B -> Project A = 403 Forbidden (Blocked)
    res = client.get(f"/api/projects/{d['proj_a_id']}", headers=headers_b)
    assert res.status_code == 403

    # Project list returns only caller's own projects
    list_a = client.get("/api/projects", headers=headers_a).json()
    assert len(list_a) == 1
    assert list_a[0]["id"] == d["proj_a_id"]

    list_b = client.get("/api/projects", headers=headers_b).json()
    assert len(list_b) == 1
    assert list_b[0]["id"] == d["proj_b_id"]


# 2. Scans Authorization & Indirect IDOR Protection
def test_scan_authorization_and_indirect_idor(client, two_users_and_projects):
    d = two_users_and_projects
    headers_a = {"Authorization": f"Bearer {d['token_a']}"}
    headers_b = {"Authorization": f"Bearer {d['token_b']}"}

    # User B can view their own scan
    res_b = client.get(f"/api/scans/{d['scan_b_id']}", headers=headers_b)
    assert res_b.status_code == 200

    # User A attempting to access User B's scan directly by scan_id -> 403 Forbidden
    res_a_get = client.get(f"/api/scans/{d['scan_b_id']}", headers=headers_a)
    assert res_a_get.status_code == 403

    # User A attempting to pause/stop User B's scan -> 403 Forbidden
    res_a_pause = client.post(f"/api/scans/{d['scan_b_id']}/pause", headers=headers_a)
    assert res_a_pause.status_code == 403

    res_a_stop = client.post(f"/api/scans/{d['scan_b_id']}/stop", headers=headers_a)
    assert res_a_stop.status_code == 403


# 3. Findings Authorization & Indirect IDOR Protection
def test_finding_authorization_and_indirect_idor(client, two_users_and_projects):
    d = two_users_and_projects
    headers_a = {"Authorization": f"Bearer {d['token_a']}"}
    headers_b = {"Authorization": f"Bearer {d['token_b']}"}

    # User B can access their own finding
    res_b = client.get(f"/api/findings/{d['finding_b_id']}", headers=headers_b)
    assert res_b.status_code == 200

    # User A attempting to read User B's finding by finding_id -> 403 Forbidden
    res_a_get = client.get(f"/api/findings/{d['finding_b_id']}", headers=headers_a)
    assert res_a_get.status_code == 403

    # User A attempting to triage/update User B's finding -> 403 Forbidden
    res_a_patch = client.patch(
        f"/api/findings/{d['finding_b_id']}",
        json={"status": "resolved", "resolution_comment": "Hacked status"},
        headers=headers_a
    )
    assert res_a_patch.status_code == 403

    # User A listing findings: must not see finding B
    list_a = client.get("/api/findings", headers=headers_a).json()
    assert len(list_a) == 0


# 4. API Security Endpoints Authorization & IDOR Protection
def test_api_security_authorization_and_idor(client, two_users_and_projects):
    d = two_users_and_projects
    headers_a = {"Authorization": f"Bearer {d['token_a']}"}
    headers_b = {"Authorization": f"Bearer {d['token_b']}"}

    # User B can fetch and update DAST config for Project B
    res_b_config = client.get(f"/api/projects/{d['proj_b_id']}/api-security/dast-config", headers=headers_b)
    assert res_b_config.status_code == 200

    # User A accessing Project B's DAST config -> 403 Forbidden
    res_a_get_cfg = client.get(f"/api/projects/{d['proj_b_id']}/api-security/dast-config", headers=headers_a)
    assert res_a_get_cfg.status_code == 403

    res_a_put_cfg = client.put(
        f"/api/projects/{d['proj_b_id']}/api-security/dast-config",
        json={"api_target_url": "http://localhost:8001", "api_dast_enabled": True},
        headers=headers_a
    )
    assert res_a_put_cfg.status_code == 403

    # User A accessing Project B's endpoints & summary -> 403 Forbidden
    res_a_endpoints = client.get(f"/api/projects/{d['proj_b_id']}/api-security/endpoints", headers=headers_a)
    assert res_a_endpoints.status_code == 403

    res_a_ep_detail = client.get(f"/api/projects/{d['proj_b_id']}/api-security/endpoints/{d['endpoint_b_id']}", headers=headers_a)
    assert res_a_ep_detail.status_code == 403

    res_a_summary = client.get(f"/api/projects/{d['proj_b_id']}/api-security/summary", headers=headers_a)
    assert res_a_summary.status_code == 403

    res_a_greybox = client.get(f"/api/projects/{d['proj_b_id']}/greybox-context", headers=headers_a)
    assert res_a_greybox.status_code == 403


# 5. Targeted Verification Authorization & IDOR Protection
def test_targeted_verification_authorization(client, two_users_and_projects):
    d = two_users_and_projects
    headers_a = {"Authorization": f"Bearer {d['token_a']}"}

    # User A attempting to verify User B's finding -> 403 Forbidden / 404 Not Found
    res_a_verify = client.post(
        f"/api/projects/{d['proj_b_id']}/findings/{d['finding_b_id']}/verify",
        headers=headers_a
    )
    assert res_a_verify.status_code in (403, 404)


# 6. Reports Authorization & IDOR Protection
def test_reports_authorization_and_idor(client, two_users_and_projects):
    d = two_users_and_projects
    headers_a = {"Authorization": f"Bearer {d['token_a']}"}

    # User A attempting to generate report for Project B -> 403 Forbidden
    res_a_gen = client.post(
        "/api/reports/generate",
        json={"project_id": d["proj_b_id"], "report_type": "executive", "format": "json"},
        headers=headers_a
    )
    assert res_a_gen.status_code == 403

    # User A attempting to download report for Project B -> 403 Forbidden
    res_a_dl = client.get(
        f"/api/reports/download?project_id={d['proj_b_id']}&report_type=executive&format=pdf",
        headers=headers_a
    )
    assert res_a_dl.status_code == 403


# 7. Risk Map & Compliance Authorization
def test_risk_map_and_compliance_authorization(client, two_users_and_projects):
    d = two_users_and_projects
    headers_a = {"Authorization": f"Bearer {d['token_a']}"}

    # Risk Map
    res_a_risk = client.get(f"/api/projects/{d['proj_b_id']}/risk-map", headers=headers_a)
    assert res_a_risk.status_code == 403

    # Compliance
    res_a_comp = client.get(f"/api/projects/{d['proj_b_id']}/compliance", headers=headers_a)
    assert res_a_comp.status_code == 403


# 8. Activity Log Cross-Tenant Isolation
def test_activity_cross_tenant_isolation(client, two_users_and_projects):
    d = two_users_and_projects
    headers_a = {"Authorization": f"Bearer {d['token_a']}"}
    headers_b = {"Authorization": f"Bearer {d['token_b']}"}

    # User A activity feed must only contain User A's project events
    feed_a = client.get("/api/activity", headers=headers_a).json()
    for ev in feed_a:
        assert f"proj-{d['proj_b_id']}" not in ev["id"]
        assert f"scan-start-{d['scan_b_id']}" not in ev["id"]

    # User A querying project_id of User B -> 403 Forbidden
    res_filtered = client.get(f"/api/activity?project_id={d['proj_b_id']}", headers=headers_a)
    assert res_filtered.status_code == 403


# 9. Unauthenticated Access Rejection (401 across endpoints)
def test_unauthenticated_access_returns_401(client, two_users_and_projects):
    d = two_users_and_projects

    # Ensure client session cookie is cleared for unauthenticated tests
    client.cookies.clear()

    # Projects
    assert client.get("/api/projects").status_code == 401
    assert client.get(f"/api/projects/{d['proj_a_id']}").status_code == 401

    # Scans
    assert client.get("/api/scans").status_code == 401
    assert client.get(f"/api/scans/{d['scan_b_id']}").status_code == 401

    # Findings
    assert client.get("/api/findings").status_code == 401
    assert client.get(f"/api/findings/{d['finding_b_id']}").status_code == 401

    # API Security
    assert client.get(f"/api/projects/{d['proj_a_id']}/api-security/dast-config").status_code == 401
    assert client.get(f"/api/projects/{d['proj_a_id']}/api-security/endpoints").status_code == 401
    assert client.get(f"/api/projects/{d['proj_a_id']}/api-security/summary").status_code == 401

    # Reports
    assert client.post("/api/reports/generate", json={"project_id": d["proj_a_id"]}).status_code == 401
    assert client.get(f"/api/reports/download?project_id={d['proj_a_id']}").status_code == 401

    # Risk Map & Compliance
    assert client.get(f"/api/projects/{d['proj_a_id']}/risk-map").status_code == 401
    assert client.get(f"/api/projects/{d['proj_a_id']}/compliance").status_code == 401


# 10. Audit Log of Unauthorized Access Attempts
def test_unauthorized_access_is_audited(client, two_users_and_projects, authz_engine):
    d = two_users_and_projects
    headers_a = {"Authorization": f"Bearer {d['token_a']}"}

    # Attempt cross-tenant access
    client.get(f"/api/projects/{d['proj_b_id']}", headers=headers_a)

    # Verify audit log entry
    with Session(authz_engine) as session:
        unauthorized_logs = list(
            session.scalars(
                select(AuditLog).where(
                    AuditLog.action == "UNAUTHORIZED_ACCESS_ATTEMPT",
                    AuditLog.user_id == d["user_a_id"],
                    AuditLog.resource_id == str(d["proj_b_id"])
                )
            ).all()
        )
        assert len(unauthorized_logs) >= 1
        assert "attempted to access" in unauthorized_logs[0].details.lower()
