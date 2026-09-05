import os
import subprocess
import urllib.parse
from datetime import datetime
from pathlib import Path
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models.project import Project
from app.services.storage_service import clean_project_source, get_project_dir, get_source_dir, extract_zip_safely

MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50MB

def validate_git_url(url: str) -> bool:
    if not url or not isinstance(url, str):
        return False
    url = url.strip()
    if url.startswith("-"):
        return False
    try:
        parsed = urllib.parse.urlparse(url)
        # Only HTTPS scheme is allowed
        if parsed.scheme != "https":
            return False
        # Ensure it has a netloc (hostname)
        if not parsed.netloc:
            return False
        return True
    except Exception:
        return False

from app.services.ssrf_protection import is_ssrf_safe_url


def validate_website_url(url: str, allow_localhost: bool = True) -> bool:
    safe, _ = is_ssrf_safe_url(url, allow_localhost=allow_localhost)
    return safe

def handle_zip_ingestion(project_id: int, temp_zip_path: str) -> None:
    """
    Background task to perform ZIP ingestion.
    1. Set status to INGESTING
    2. Safely extract archive
    3. Set status to READY, clean up temp archive
    4. On failure, set status to FAILED, clean up extracted files and temp archive
    """
    db = SessionLocal()
    try:
        project = db.get(Project, project_id)
        if not project:
            return
        
        project.source_status = "INGESTING"
        db.commit()

        # Clean and get source dir
        clean_project_source(project_id)
        source_dir = get_source_dir(project_id)

        # Extract
        extract_zip_safely(Path(temp_zip_path), source_dir)

        # Success
        project.source_type = "ZIP"
        project.source_status = "READY"
        project.local_source_reference = f"projects/{project_id}/source"
        project.last_ingested_at = datetime.utcnow()
        project.ingestion_error = None
        db.commit()

    except Exception as e:
        db.rollback()
        # Mark failed
        project = db.get(Project, project_id)
        if project:
            project.source_status = "FAILED"
            project.ingestion_error = str(e)
            db.commit()
        # Cleanup source dir
        try:
            clean_project_source(project_id)
        except Exception:
            pass
    finally:
        # Delete temp zip file
        try:
            p = Path(temp_zip_path)
            if p.exists():
                p.unlink()
        except Exception:
            pass
        db.close()

def handle_git_ingestion(project_id: int, repo_url: str) -> None:
    """
    Background task to perform Git ingestion.
    1. Validate Git URL
    2. Set status to INGESTING
    3. Clone using subprocess list arguments and shell=False
    4. Set status to READY on success, or FAILED on failure
    """
    db = SessionLocal()
    try:
        project = db.get(Project, project_id)
        if not project:
            return
        
        repo_url = repo_url.strip()
        if not validate_git_url(repo_url):
            raise ValueError("Invalid Git Repository URL. Only HTTP/HTTPS URLs are allowed.")

        project.source_status = "INGESTING"
        db.commit()

        # Clean source dir
        clean_project_source(project_id)
        source_dir = get_source_dir(project_id)

        # Run clone safely
        # Use subprocess list syntax to avoid shell injection
        result = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, "."],
            cwd=str(source_dir),
            capture_output=True,
            text=True,
            shell=False
        )

        if result.returncode != 0:
            err_msg = result.stderr.strip() if result.stderr else f"git clone failed with code {result.returncode}"
            raise RuntimeError(err_msg)

        # Success
        project.source_type = "GIT"
        project.source_status = "READY"
        project.repository_url = repo_url  # Ensure compatibility with existing fields
        project.local_source_reference = f"projects/{project_id}/source"
        project.last_ingested_at = datetime.utcnow()
        project.ingestion_error = None
        db.commit()

    except Exception as e:
        db.rollback()
        # Mark failed
        project = db.get(Project, project_id)
        if project:
            project.source_status = "FAILED"
            project.ingestion_error = str(e)
            db.commit()
        # Cleanup source dir
        try:
            clean_project_source(project_id)
        except Exception:
            pass
    finally:
        db.close()

def handle_website_ingestion(project_id: int, target_url: str, db: Session) -> Project:
    """
    Website target registration (synchronous since it's only database target persistence).
    """
    target_url = target_url.strip()
    if not validate_website_url(target_url):
        raise ValueError("Invalid Website URL. Only HTTP/HTTPS URLs are allowed.")

    project = db.get(Project, project_id)
    if not project:
        raise ValueError("Project not found")

    project.source_type = "WEBSITE"
    project.source_status = "READY"
    project.target_url = target_url
    project.local_source_reference = None
    project.last_ingested_at = datetime.utcnow()
    project.ingestion_error = None
    db.commit()
    db.refresh(project)
    return project
