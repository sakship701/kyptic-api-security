import io
import unittest
import zipfile
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models.project import Project
from app.services.ingestion_service import (
    validate_git_url,
    validate_website_url,
    handle_website_ingestion,
    handle_zip_ingestion,
    handle_git_ingestion,
)
from app.services.storage_service import extract_zip_safely, get_source_dir, get_project_dir, clean_project_source


class TestProjectIngestion(unittest.TestCase):
    def setUp(self):
        # Set up a test SQLite database in memory
        self.engine = create_engine("sqlite:///:memory:")
        self.Session = sessionmaker(bind=self.engine)
        Base.metadata.create_all(self.engine)
        self.db = self.Session()

        # Create a dummy project in db
        self.project = Project(
            name="Test Ingestion Project",
            technology="Python",
            status="active"
        )
        self.db.add(self.project)
        self.db.commit()
        self.db.refresh(self.project)

    def tearDown(self):
        self.db.close()
        Base.metadata.drop_all(self.engine)

    def test_validate_git_url(self):
        # Only HTTPS is allowed
        self.assertTrue(validate_git_url("https://github.com/user/repo"))
        self.assertFalse(validate_git_url("http://gitlab.com/user/repo.git"))  # HTTP rejected
        self.assertFalse(validate_git_url("file:///etc/passwd"))  # file:// rejected
        self.assertFalse(validate_git_url("ssh://git@github.com/user/repo"))  # ssh:// rejected
        self.assertFalse(validate_git_url("/local/path/to/repo"))  # local filesystem path rejected
        self.assertFalse(validate_git_url("git://github.com/user/repo"))  # git:// rejected
        self.assertFalse(validate_git_url("git@github.com:user/repo.git"))  # git@ transport rejected
        self.assertFalse(validate_git_url("-oProxyCommand=abc"))  # Unsafe arguments

    def test_validate_website_url(self):
        # Syntactically valid HTTP/HTTPS URLs
        self.assertTrue(validate_website_url("https://example.com"))
        self.assertTrue(validate_website_url("http://127.0.0.1:8080/test"))
        self.assertFalse(validate_website_url("file:///usr/bin/local"))
        self.assertFalse(validate_website_url("ftp://example.com"))
        self.assertFalse(validate_website_url("invalid-url"))

    def test_website_registration(self):
        # Register a valid website target
        project = handle_website_ingestion(self.project.id, "https://example.com", self.db)
        self.assertEqual(project.source_type, "WEBSITE")
        self.assertEqual(project.source_status, "READY")
        self.assertEqual(project.target_url, "https://example.com")
        self.assertIsNone(project.local_source_reference)

        # Invalid URL schema check
        with self.assertRaises(ValueError):
            handle_website_ingestion(self.project.id, "file:///etc/passwd", self.db)

    def test_zip_slip_protection(self):
        # Create a malformed ZIP file in-memory attempting path traversal escape
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zip_ref:
            # Entry attempting path traversal
            zip_ref.writestr("../../../traversal.txt", "escaped content")
        
        zip_buffer.seek(0)
        
        # Target extraction folder
        target_dir = Path("./test_extract_sandbox").resolve()
        target_dir.mkdir(exist_ok=True)
        
        # Verify extraction fails and catches Zip Slip
        with self.assertRaises(ValueError) as context:
            extract_zip_safely(zip_buffer, target_dir)
            
        self.assertIn("escape detected", str(context.exception))
        
        # Cleanup test folder
        if target_dir.exists():
            import shutil
            shutil.rmtree(target_dir)

    def test_safe_zip_extraction(self):
        # Create a valid ZIP file in-memory
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zip_ref:
            zip_ref.writestr("src/main.py", "print('hello')")
            zip_ref.writestr("README.md", "# Readme")
        
        zip_buffer.seek(0)
        
        # Target extraction folder
        target_dir = Path("./test_extract_sandbox").resolve()
        target_dir.mkdir(exist_ok=True)
        
        # Extract successfully
        extract_zip_safely(zip_buffer, target_dir)
        
        self.assertTrue((target_dir / "src" / "main.py").exists())
        self.assertTrue((target_dir / "README.md").exists())
        
        # Cleanup test folder
        if target_dir.exists():
            import shutil
            shutil.rmtree(target_dir)

    def test_router_create_project_and_get_source(self):
        from app.routers.projects import get_project_source
        source = get_project_source(self.project.id, self.db)
        self.assertEqual(source["project_id"], self.project.id)
        self.assertEqual(source["status"], "NOT_INGESTED")
        self.assertIsNone(source["source_type"])

    def test_router_ingest_website(self):
        from app.routers.projects import ingest_website
        from app.schemas.project import WebsiteIngestRequest
        payload = WebsiteIngestRequest(target_url="http://127.0.0.1:8000")
        project = ingest_website(self.project.id, payload, self.db)
        self.assertEqual(project.source_type, "WEBSITE")
        self.assertEqual(project.source_status, "READY")
        self.assertEqual(project.target_url, "http://127.0.0.1:8000")


    def test_router_get_source_not_found(self):
        from app.routers.projects import get_project_source
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as context:
            get_project_source(9999, self.db)
        self.assertEqual(context.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
