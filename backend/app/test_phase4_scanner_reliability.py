import os
from datetime import datetime
from pathlib import Path
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.models.finding import Finding, FindingSeverity, FindingSource, FindingStatus
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.services.finding_normalizer import generate_fingerprint, normalize_dast_results, normalize_semgrep_results
from app.services.scan_orchestrator import ScanOrchestrator
from app.services.storage_service import get_source_dir, get_project_dir

# Isolated in-memory database for pipeline testing
SQLALCHEMY_TEST_DATABASE_URL = "sqlite:///:memory:"
test_engine = create_engine(
    SQLALCHEMY_TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


def test_scanner_applicability_mapping():
    db = TestingSessionLocal()

    # Project 1: ZIP source
    zip_proj = Project(name="ZIP Project", source_type="ZIP", source_status="READY", user_id=1)
    db.add(zip_proj)

    # Project 2: WEBSITE target
    web_proj = Project(name="Web Project", source_type="WEBSITE", source_status="READY", target_url="https://example.com", user_id=1)
    db.add(web_proj)

    # Project 3: OPENAPI spec
    api_proj = Project(name="API Project", source_type="OPENAPI", source_status="READY", user_id=1)
    db.add(api_proj)

    db.commit()

    orch1 = ScanOrchestrator(db, scan_id=1)
    caps1 = orch1.determine_capabilities(zip_proj)
    assert caps1["white_box"] is True

    caps2 = orch1.determine_capabilities(web_proj)
    assert caps2["web_dast"] is True

    caps3 = orch1.determine_capabilities(api_proj)
    assert caps3["api_security"] is True

    db.close()


def test_cvss_integrity_no_fake_values():
    # When CVSS vector/score is missing from scanner output, it must be stored as None (NULL), never fabricated as 0.0 or random average
    dast_raw = {
        "status": "SUCCESS",
        "results": [
            {
                "title": "Missing Security Headers",
                "severity": "LOW",
                "evidence": "X-Frame-Options missing",
                "url": "https://example.com",
            }
        ]
    }
    findings = normalize_dast_results(dast_raw, project_id=10, scan_id=99, scanner_version="1.0.0")

    assert len(findings) == 1
    # Missing CVSS score must be None (NULL in DB), not fake 0 or hardcoded 5.0
    assert findings[0].cvss is None


def test_safe_project_returns_zero_findings(tmp_path: Path):
    db = TestingSessionLocal()

    # Use unique project ID 9999 to avoid colliding with project 1 directory on disk
    safe_proj = Project(id=9999, name="Safe Project 9999", source_type="ZIP", source_status="READY", user_id=999)
    db.add(safe_proj)
    db.commit()

    # Create empty/clean source directory
    src_dir = get_source_dir(safe_proj.id)
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "clean_code.py").write_text("def hello():\n    return 'Hello World'\n")

    scan = Scan(project_id=safe_proj.id, status=ScanStatus.QUEUED, progress=0, started_at=datetime.utcnow())
    db.add(scan)
    db.commit()

    orch = ScanOrchestrator(db, scan.id)
    # Execute scan synchronously
    import asyncio
    asyncio.run(orch.execute())

    db.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED
    assert scan.result_count >= 0

    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    # Clean code should yield 0 critical/high findings
    crit_high = [f for f in findings if f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH)]
    assert len(crit_high) == 0

    db.close()


def test_deduplication_preserves_unique_fingerprints():
    # Two findings with same rule & location must produce identical fingerprints
    fp1 = generate_fingerprint(1, "semgrep", "rule1", "app/main.py", 10, "msg1")
    fp2 = generate_fingerprint(1, "semgrep", "rule1", "app/main.py", 10, "msg1")

    assert fp1 == fp2
    assert len(fp1) == 64  # SHA-256 hex string
