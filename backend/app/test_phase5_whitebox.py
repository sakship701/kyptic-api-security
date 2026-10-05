import os
from pathlib import Path
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.models.finding import Finding, FindingSeverity, FindingSource
from app.services.detect_secrets_scanner import DetectSecretsScanner
from app.services.finding_normalizer import (
    normalize_detect_secrets_results,
    normalize_sca_results,
    normalize_semgrep_results,
)
from app.services.sca_scanner import SCADependencyScanner, SCAStatus

# Isolated test DB
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


def test_semgrep_sast_normalization():
    semgrep_raw = {
        "results": [
            {
                "check_id": "python.lang.security.sqli.hardcoded-sql-expression",
                "path": "app/db.py",
                "start": {"line": 15},
                "end": {"line": 15},
                "extra": {
                    "message": "Possible SQL injection detected in raw query",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-89"], "owasp": ["A03:2021-Injection"]},
                    "lines": "cursor.execute('SELECT * FROM users WHERE id = ' + user_id)",
                },
            }
        ]
    }

    findings = normalize_semgrep_results(semgrep_raw, project_id=1, scan_id=101, scanner_version="1.0.0")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == FindingSeverity.HIGH
    assert f.cwe == "CWE-89"
    assert f.owasp == "A03:2021-Injection"
    assert f.file_path == "app/db.py"
    assert f.line_number == 15
    assert f.source == FindingSource.SAST


def test_detect_secrets_redaction(tmp_path: Path):
    # Create test source file containing a hardcoded secret
    vuln_file = tmp_path / "config.py"
    secret_key_str = "AKIAIOSFODNN7EXAMPLE123"
    vuln_file.write_text(f"AWS_KEY = '{secret_key_str}'\n")

    raw_secrets = {
        "results": {
            "config.py": [
                {
                    "type": "AWS Access Key",
                    "line_number": 1,
                    "hashed_secret": "3bc72f5ef3a4b917d235...test",
                }
            ]
        }
    }

    findings = normalize_detect_secrets_results(
        raw_secrets, project_id=1, scan_id=102, scanner_version="1.4.0", target_dir=tmp_path
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.source == FindingSource.SECRETS
    # Raw secret MUST NEVER appear in finding title, description, or code snippet
    assert secret_key_str not in f.title
    assert secret_key_str not in f.description
    assert secret_key_str not in (f.code_snippet or "")


def test_sca_dependency_vulnerable_vs_safe_manifests(tmp_path: Path):
    scanner = SCADependencyScanner()

    # Safe manifest test
    safe_dir = tmp_path / "safe"
    safe_dir.mkdir()
    (safe_dir / "requirements.txt").write_text("# Safe dependencies\nrequests==2.31.0\n")

    manifests = scanner.detect_manifests(safe_dir)
    assert len(manifests["python"]) == 1

    # Test status differentiation
    no_manifest_dir = tmp_path / "empty"
    no_manifest_dir.mkdir()

    import asyncio
    res_empty = asyncio.run(scanner.scan(no_manifest_dir))
    assert res_empty["status"] == SCAStatus.NO_MANIFESTS
    assert len(res_empty["results"]) == 0


def test_cve_cwe_cvss_integrity():
    dast_raw = {
        "status": "SUCCESS",
        "results": [
            {
                "title": "Information Exposure Through HTTP Headers",
                "severity": "INFO",
                "evidence": "Server: gunicorn",
                "url": "http://127.0.0.1:8000",
            }
        ]
    }
    from app.services.finding_normalizer import normalize_dast_results
    findings = normalize_dast_results(dast_raw, project_id=1, scan_id=103)
    assert len(findings) == 1
    # Missing CVSS score must be None (NULL in DB), not fake 0 or hardcoded score
    assert findings[0].cvss is None
