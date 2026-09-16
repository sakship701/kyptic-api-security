import asyncio
import shutil
import pytest
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from app.database import Base, engine, get_db
from app.models.api_endpoint import ApiEndpoint
from app.models.finding import Finding, FindingSeverity, FindingSource, FindingStatus
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.services.scan_orchestrator import ScanOrchestrator
from app.services.storage_service import PROJECTS_DIR, get_project_dir, get_source_dir
from sqlalchemy.orm import Session


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    if PROJECTS_DIR.exists():
        shutil.rmtree(PROJECTS_DIR, ignore_errors=True)
    yield
    Base.metadata.drop_all(bind=engine)
    if PROJECTS_DIR.exists():
        shutil.rmtree(PROJECTS_DIR, ignore_errors=True)


def test_orchestrator_determine_capabilities_zip_project(tmp_path):
    db = next(get_db())
    project = Project(
        name="Zip Code Project",
        source_type="ZIP",
        source_status="READY",
    )
    db.add(project)
    db.commit()

    source_dir = get_source_dir(project.id)
    (source_dir / "app.py").write_text("print('hello')", encoding="utf-8")

    orchestrator = ScanOrchestrator(db, scan_id=1)
    caps = orchestrator.determine_capabilities(project)

    assert caps["white_box"] is True
    assert caps["web_dast"] is False
    assert caps["api_security"] is False


def test_orchestrator_determine_capabilities_website_project():
    db = next(get_db())
    project = Project(
        name="Web Target Project",
        source_type="WEBSITE",
        source_status="READY",
        target_url="http://example.com",
    )
    db.add(project)
    db.commit()

    orchestrator = ScanOrchestrator(db, scan_id=1)
    caps = orchestrator.determine_capabilities(project)

    assert caps["white_box"] is False
    assert caps["web_dast"] is True
    assert caps["api_security"] is False


def test_orchestrator_determine_capabilities_openapi_project():
    db = next(get_db())
    project = Project(
        name="OpenAPI Project",
        source_type="OPENAPI",
        source_status="READY",
    )
    db.add(project)
    db.commit()

    project_dir = get_project_dir(project.id)
    (project_dir / "openapi_spec.raw").write_text("openapi: 3.0.0", encoding="utf-8")

    orchestrator = ScanOrchestrator(db, scan_id=1)
    caps = orchestrator.determine_capabilities(project)

    assert caps["white_box"] is False
    assert caps["web_dast"] is False
    assert caps["api_security"] is True


def test_orchestrator_determine_capabilities_multi_capability():
    db = next(get_db())
    project = Project(
        name="Multi Capability Project",
        source_type="ZIP",
        source_status="READY",
        target_url="http://example.com",
        api_target_url="http://example.com/api",
        api_dast_enabled=True,
    )
    db.add(project)
    db.commit()

    source_dir = get_source_dir(project.id)
    (source_dir / "index.js").write_text("console.log('test');", encoding="utf-8")

    project_dir = get_project_dir(project.id)
    (project_dir / "openapi_spec.raw").write_text("openapi: 3.0.0", encoding="utf-8")

    orchestrator = ScanOrchestrator(db, scan_id=1)
    caps = orchestrator.determine_capabilities(project)

    assert caps["white_box"] is True
    assert caps["web_dast"] is True
    assert caps["api_security"] is True


def test_orchestrator_zero_findings_results_in_completed():
    db = next(get_db())
    project = Project(name="Zero Finding Project", source_type="ZIP", source_status="READY")
    db.add(project)
    db.commit()

    scan = Scan(project_id=project.id, status=ScanStatus.RUNNING)
    db.add(scan)
    db.commit()

    source_dir = get_source_dir(project.id)
    (source_dir / "clean.py").write_text("x = 10\nprint(x)", encoding="utf-8")

    with patch("app.services.scan_orchestrator.SemgrepSASTScanner._resolve_semgrep_path", return_value="/usr/bin/semgrep"), \
         patch("app.services.scan_orchestrator.SemgrepSASTScanner.scan", new_callable=AsyncMock) as mock_sast, \
         patch("app.services.scan_orchestrator.DetectSecretsScanner.scan", new_callable=AsyncMock) as mock_sec, \
         patch("app.services.scan_orchestrator.SCADependencyScanner.scan", new_callable=AsyncMock) as mock_sca:

        mock_sast.return_value = {"version": "1.0.0", "results": []}
        mock_sec.return_value = {"version": "1.0.0", "results": []}
        mock_sca.return_value = {"status": "NO_VULNERABILITIES", "version": "1.0.0", "results": []}

        orchestrator = ScanOrchestrator(db, scan.id)
        asyncio.run(orchestrator.execute())

        updated_scan = db.get(Scan, scan.id)
        assert updated_scan.status == ScanStatus.COMPLETED
        assert updated_scan.result_count == 0
        assert updated_scan.progress == 100
        assert updated_scan.current_phase == "Completed"


def test_orchestrator_error_isolation_web_dast_failure_preserves_sast_findings():
    db = next(get_db())
    project = Project(
        name="Multi Failure Isolation",
        source_type="ZIP",
        source_status="READY",
        target_url="http://unreachable-target.local",
    )
    db.add(project)
    db.commit()

    scan = Scan(project_id=project.id, status=ScanStatus.RUNNING)
    db.add(scan)
    db.commit()

    source_dir = get_source_dir(project.id)
    (source_dir / "main.py").write_text("key = 'secret123'", encoding="utf-8")

    dummy_sast_result = {
        "check_id": "python-hardcoded-secret",
        "path": "main.py",
        "start": {"line": 1},
        "end": {"line": 1},
        "extra": {"message": "Hardcoded Secret", "severity": "HIGH", "lines": "key = 'secret123'"}
    }

    with patch("app.services.scan_orchestrator.SemgrepSASTScanner._resolve_semgrep_path", return_value="/usr/bin/semgrep"), \
         patch("app.services.scan_orchestrator.SemgrepSASTScanner.scan", new_callable=AsyncMock) as mock_sast, \
         patch("app.services.scan_orchestrator.DetectSecretsScanner.scan", new_callable=AsyncMock) as mock_sec, \
         patch("app.services.scan_orchestrator.SCADependencyScanner.scan", new_callable=AsyncMock) as mock_sca, \
         patch("app.services.scan_orchestrator.DASTWebScanner.scan", new_callable=AsyncMock) as mock_dast:

        mock_sast.return_value = {"version": "1.0.0", "results": [dummy_sast_result]}
        mock_sec.return_value = {"version": "1.0.0", "results": []}
        mock_sca.return_value = {"status": "NO_MANIFESTS", "results": []}
        mock_dast.side_effect = Exception("Target network timeout")

        orchestrator = ScanOrchestrator(db, scan.id)
        asyncio.run(orchestrator.execute())

        updated_scan = db.get(Scan, scan.id)
        assert updated_scan.status == ScanStatus.COMPLETED
        assert updated_scan.result_count == 1
        assert updated_scan.dast_status == "SCANNER_ERROR"

        findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
        assert len(findings) == 1


def test_orchestrator_triage_preservation_across_scans():
    db = next(get_db())
    project = Project(name="Triage Test Project", source_type="ZIP", source_status="READY")
    db.add(project)
    db.commit()

    prior_scan = Scan(project_id=project.id, status=ScanStatus.COMPLETED)
    db.add(prior_scan)
    db.commit()

    prior_finding = Finding(
        project_id=project.id,
        scan_id=prior_scan.id,
        title="Hardcoded Key",
        description="Test secret key",
        severity=FindingSeverity.HIGH,
        cvss=7.5,
        category="Security Scan",
        file_path="config.py",
        line_number=10,
        status=FindingStatus.FALSE_POSITIVE,
        source=FindingSource.SAST,
        fingerprint="fp-test-key-123",
        resolution_comment="Ignored test dummy credential",
        resolved_at=datetime.utcnow(),
    )
    db.add(prior_finding)
    db.commit()

    new_scan = Scan(project_id=project.id, status=ScanStatus.RUNNING)
    db.add(new_scan)
    db.commit()

    source_dir = get_source_dir(project.id)
    (source_dir / "config.py").write_text("SECRET = 'test'", encoding="utf-8")

    dummy_sast_result = {
        "check_id": "test-key",
        "path": "config.py",
        "start": {"line": 10},
        "end": {"line": 10},
        "extra": {"message": "Hardcoded Key", "severity": "HIGH", "lines": "SECRET = 'test'"}
    }

    with patch("app.services.scan_orchestrator.SemgrepSASTScanner._resolve_semgrep_path", return_value="/usr/bin/semgrep"), \
         patch("app.services.scan_orchestrator.SemgrepSASTScanner.scan", new_callable=AsyncMock) as mock_sast, \
         patch("app.services.scan_orchestrator.DetectSecretsScanner.scan", new_callable=AsyncMock) as mock_sec, \
         patch("app.services.scan_orchestrator.SCADependencyScanner.scan", new_callable=AsyncMock) as mock_sca, \
         patch("app.services.finding_normalizer.generate_fingerprint", return_value="fp-test-key-123"):

        mock_sast.return_value = {"version": "1.0.0", "results": [dummy_sast_result]}
        mock_sec.return_value = {"version": "1.0.0", "results": []}
        mock_sca.return_value = {"status": "NO_MANIFESTS", "results": []}

        orchestrator = ScanOrchestrator(db, new_scan.id)
        asyncio.run(orchestrator.execute())

        new_findings = db.query(Finding).filter(Finding.scan_id == new_scan.id).all()
        assert len(new_findings) == 1
        assert new_findings[0].status == FindingStatus.FALSE_POSITIVE
        assert new_findings[0].resolution_comment == "Ignored test dummy credential"
