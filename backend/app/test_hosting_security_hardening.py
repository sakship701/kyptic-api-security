import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.rate_limiter import SimpleRateLimiter
from app.services.storage_service import StorageService


def test_s3_production_safety_failure():
    # Test 1: Production mode with STORAGE_PROVIDER=local must raise ValueError
    class ProdLocalSettings:
        ENVIRONMENT = "production"
        STORAGE_PROVIDER = "local"
        STORAGE_LOCAL_DIR = "/tmp/data"

    with pytest.raises(ValueError, match="Production mode requires S3-compatible storage"):
        StorageService(settings_obj=ProdLocalSettings())

    # Test 2: STORAGE_PROVIDER=s3 with missing/empty bucket must raise ValueError
    class ProdMissingBucketSettings:
        ENVIRONMENT = "production"
        STORAGE_PROVIDER = "s3"
        S3_BUCKET_NAME = ""

    with pytest.raises(ValueError, match="S3_BUCKET_NAME must be explicitly configured"):
        StorageService(settings_obj=ProdMissingBucketSettings())


def test_s3_development_local_storage_works(tmp_path: Path):
    # Development mode with local storage works cleanly
    class DevSettings:
        ENVIRONMENT = "development"
        STORAGE_PROVIDER = "local"
        STORAGE_LOCAL_DIR = tmp_path / "data"

    svc = StorageService(settings_obj=DevSettings())
    assert svc.provider.__class__.__name__ == "LocalStorageProvider"


def test_rate_limiter_redis_missing_url_failure():
    # Distributed rate limiter backend set to redis without REDIS_URL must raise ValueError
    old_env = os.environ.get("REDIS_URL")
    if "REDIS_URL" in os.environ:
        del os.environ["REDIS_URL"]

    try:
        with pytest.raises(ValueError, match="REDIS_URL environment variable is missing"):
            SimpleRateLimiter(backend="redis")
    finally:
        if old_env is not None:
            os.environ["REDIS_URL"] = old_env


def test_security_headers_and_csp(tmp_path):
    client = TestClient(app)
    response = client.get("/api/health")

    assert response.status_code == 200
    assert "Content-Security-Policy" in response.headers
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"

    # HSTS should NOT be present on plain HTTP in development
    assert "Strict-Transport-Security" not in response.headers

    # HSTS SHOULD be present when HTTPS request is simulated
    https_response = client.get("/api/health", headers={"X-Forwarded-Proto": "https"})
    assert https_response.status_code == 200
    assert "Strict-Transport-Security" in https_response.headers
    assert "max-age=31536000" in https_response.headers["Strict-Transport-Security"]
