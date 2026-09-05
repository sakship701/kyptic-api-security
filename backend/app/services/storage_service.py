import os
import shutil
import zipfile
from pathlib import Path

# backend/ directory
BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BASE_DIR / "data"
PROJECTS_DIR = DATA_DIR / "projects"

def get_project_dir(project_id: int) -> Path:
    """Get project-specific root directory under data/projects/<project_id>/."""
    path = PROJECTS_DIR / str(project_id)
    path.mkdir(parents=True, exist_ok=True)
    return path

def get_source_dir(project_id: int) -> Path:
    """Get the source code directory inside the project folder."""
    path = get_project_dir(project_id) / "source"
    path.mkdir(parents=True, exist_ok=True)
    return path

def clean_project_source(project_id: int) -> None:
    """Clean the project source directory to remove previous code."""
    source_dir = get_source_dir(project_id)
    if source_dir.exists():
        try:
            shutil.rmtree(source_dir)
        except Exception:
            # Fallback if directory deletion gets locked on Windows
            for root, dirs, files in os.walk(source_dir, topdown=False):
                for name in files:
                    try:
                        os.remove(os.path.join(root, name))
                    except Exception:
                        pass
                for name in dirs:
                    try:
                        os.rmdir(os.path.join(root, name))
                    except Exception:
                        pass
    source_dir.mkdir(parents=True, exist_ok=True)

def extract_zip_safely(zip_path: Path, target_dir: Path) -> None:
    """
    Safely extract a zip archive to the target directory.
    Protects against Zip Slip (path traversal) and unsafe symlink-related escapes.
    """
    target_dir = target_dir.resolve()
    
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        # 1. Perform Zip Slip checks on all archive entries first
        for member in zip_ref.infolist():
            # Construct proposed destination path
            member_path = target_dir / member.filename
            
            # Resolve to absolute path
            try:
                resolved_member_path = member_path.resolve()
            except Exception:
                resolved_member_path = member_path.absolute()
                
            # Verify resolved path is strictly within the target_dir boundary
            try:
                common = os.path.commonpath([target_dir, resolved_member_path])
            except Exception as e:
                raise ValueError(f"Path traversal detected: {member.filename} (cannot resolve common path)")
                
            if common != str(target_dir):
                raise ValueError(f"Path traversal escape detected: {member.filename} lies outside target directory")

        # 2. Extract files
        zip_ref.extractall(target_dir)

        # 3. Post-extraction safety validation:
        # Check if any symlink was created and verify it does not point outside the sandbox.
        for path in target_dir.rglob("*"):
            try:
                if path.is_symlink():
                    resolved_target = path.readlink()
                    # Resolve absolute symlink target
                    if not resolved_target.is_absolute():
                        resolved_target = (path.parent / resolved_target).resolve()
                    else:
                        resolved_target = resolved_target.resolve()
                    
                    # Verify target lies inside the target directory
                    try:
                        common = os.path.commonpath([target_dir, resolved_target])
                        if common != str(target_dir):
                            # Remove unsafe symlink
                            path.unlink()
                            raise ValueError(f"Unsafe symlink detected and blocked: {path} pointing outside sandbox")
                    except Exception:
                        path.unlink()
                        raise ValueError(f"Unsafe symlink pointing outside sandbox: {path}")
            except Exception as e:
                # If we cannot resolve symlink or read link, delete it for safety
                try:
                    if path.is_symlink():
                        path.unlink()
                except Exception:
                    pass
                raise ValueError(f"Symlink security check failed: {e}")
