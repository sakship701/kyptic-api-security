import io
import os
import zipfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.services.ssrf_protection import is_ssrf_safe_url, is_local_demo_target
from app.services.storage_service import extract_zip_safely, storage_service

# Isolated test database
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


@pytest.fixture(autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=test_engine)
    app.dependency_overrides[get_db] = override_get_db
    yield
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)


def test_ssrf_blocking_private_ips():
    # Loopback
    safe, msg = is_ssrf_safe_url("http://127.0.0.1/admin")
    assert not safe

    # AWS Cloud Metadata
    safe, msg = is_ssrf_safe_url("http://169.254.169.254/latest/meta-data/")
    assert not safe

    # Private RFC 1918 IPv4
    safe, msg = is_ssrf_safe_url("http://10.0.0.1:8080/secret")
    assert not safe

    # Public IP should be allowed
    safe, msg = is_ssrf_safe_url("https://example.com/api")
    assert safe


def test_ssrf_local_demo_exception():
    os.environ["KYPTIC_LOCAL_DEMO_URL"] = "http://127.0.0.1:8001"

    # Local demo exact match
    assert is_local_demo_target("http://127.0.0.1:8001/openapi.json")
    assert is_local_demo_target("http://localhost:8001/api/v1")

    # Arbitrary private ports or paths on localhost should be blocked by default SSRF check
    safe, _ = is_ssrf_safe_url("http://127.0.0.1:22")
    assert not safe


def test_zip_slip_and_traversal_rejection(tmp_path: Path):
    target_dir = tmp_path / "target"
    target_dir.mkdir()

    # Create malicious ZIP in memory with Zip Slip path
    zip_bytes = io.BytesIO()
    with zipfile.ZipFile(zip_bytes, "w") as zf:
        zf.writestr("../../evil.txt", "malicious payload")

    zip_file_path = tmp_path / "malicious.zip"
    zip_file_path.write_bytes(zip_bytes.getvalue())

    with pytest.raises(ValueError, match="Path traversal"):
        extract_zip_safely(zip_file_path, target_dir)

    # Verify no file extracted outside target_dir
    assert not (tmp_path / "evil.txt").exists()


def test_zip_invalid_magic_bytes_rejection(tmp_path: Path):
    target_dir = tmp_path / "target"
    target_dir.mkdir()

    fake_zip = tmp_path / "fake.zip"
    fake_zip.write_bytes(b"NOT_A_ZIP_HEADER_DATA")

    with pytest.raises(ValueError, match="Invalid ZIP file header magic bytes"):
        extract_zip_safely(fake_zip, target_dir)


def test_zip_entry_count_limit(tmp_path: Path):
    target_dir = tmp_path / "target"
    target_dir.mkdir()

    zip_bytes = io.BytesIO()
    with zipfile.ZipFile(zip_bytes, "w") as zf:
        for i in range(5001):
            zf.writestr(f"file_{i}.txt", "data")

    too_many_zip = tmp_path / "too_many.zip"
    too_many_zip.write_bytes(zip_bytes.getvalue())

    with pytest.raises(ValueError, match="too many files"):
        extract_zip_safely(too_many_zip, target_dir)


def test_security_headers(tmp_path: Path):
    client = TestClient(app)
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"


def test_request_body_size_limit():
    client = TestClient(app)
    # 51MB payload exceeds 50MB limit
    large_payload = "A" * (51 * 1024 * 1024)
    response = client.post(
        "/api/auth/register",
        content=large_payload,
        headers={"Content-Length": str(len(large_payload)), "Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert "exceeds maximum limit" in response.json()["detail"]
