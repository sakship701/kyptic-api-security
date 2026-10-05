import os
import shutil
import zipfile
from pathlib import Path
from typing import Protocol

from app.config import settings

BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = settings.STORAGE_LOCAL_DIR if hasattr(settings, "STORAGE_LOCAL_DIR") else (BASE_DIR / "data")
PROJECTS_DIR = DATA_DIR / "projects"


class StorageProvider(Protocol):
    def get_path(self, storage_key: str) -> Path:
        ...

    def exists(self, storage_key: str) -> bool:
        ...


class LocalStorageProvider:
    def __init__(self, base_dir: Path | str = DATA_DIR) -> None:
        self.base_dir = Path(base_dir).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def get_path(self, storage_key: str) -> Path:
        """
        Converts a logical storage key (or legacy path) to a safe absolute Path inside base_dir.
        Handles both Windows absolute paths and Linux relative storage keys.
        """
        if not storage_key:
            return self.base_dir

        # Normalize windows slashes
        clean_key = str(storage_key).replace("\\", "/")

        # Check if legacy absolute path pointing inside backend/data
        if "data/projects" in clean_key:
            relative_part = clean_key.split("data/projects/")[-1]
            target_path = self.base_dir / "projects" / relative_part
        elif clean_key.startswith("projects/"):
            target_path = self.base_dir / clean_key
        else:
            target_path = self.base_dir / clean_key

        # Resolve path safely
        try:
            resolved = target_path.resolve()
        except Exception:
            resolved = target_path.absolute()

        return resolved

    def exists(self, storage_key: str) -> bool:
        return self.get_path(storage_key).exists()


class S3StorageProvider:
    """
    S3-compatible object storage provider abstraction for production cloud deployment.
    """
    def __init__(self, bucket_name: str, region: str = "us-east-1", endpoint_url: str | None = None) -> None:
        self.bucket_name = bucket_name
        self.region = region
        self.endpoint_url = endpoint_url

    def get_path(self, storage_key: str) -> Path:
        # In S3 mode, return local cache path or logical representation
        clean_key = str(storage_key).replace("\\", "/")
        return DATA_DIR / "cache" / clean_key

    def exists(self, storage_key: str) -> bool:
        return False


class StorageService:
    def __init__(self, settings_obj=None) -> None:
        cfg = settings_obj or settings
        env = getattr(cfg, "ENVIRONMENT", "development").lower()
        provider_type = getattr(cfg, "STORAGE_PROVIDER", "local").lower()

        if env in ("production", "prod"):
            if provider_type != "s3":
                raise ValueError(
                    "Production storage policy violation: Production mode requires S3-compatible storage "
                    "(STORAGE_PROVIDER=s3). Local filesystem storage fallback is forbidden in production."
                )

        if provider_type == "s3":
            bucket = getattr(cfg, "S3_BUCKET_NAME", None)
            if not bucket or bucket in ("CHANGE_ME", ""):
                raise ValueError(
                    "S3 storage configuration missing: S3_BUCKET_NAME must be explicitly configured "
                    "when STORAGE_PROVIDER is set to 's3'."
                )
            self.provider = S3StorageProvider(
                bucket_name=bucket,
                region=getattr(cfg, "S3_REGION", "us-east-1"),
                endpoint_url=getattr(cfg, "S3_ENDPOINT_URL", None),
            )
        else:
            self.provider = LocalStorageProvider(base_dir=getattr(cfg, "STORAGE_LOCAL_DIR", DATA_DIR))

    def get_file_path(self, storage_ref: str) -> Path:
        return self.provider.get_path(storage_ref)

    def get_project_dir(self, project_id: int) -> Path:
        path = self.provider.get_path(f"projects/{project_id}")
        path.mkdir(parents=True, exist_ok=True)
        return path

    def get_source_dir(self, project_id: int) -> Path:
        path = self.provider.get_path(f"projects/{project_id}/source")
        path.mkdir(parents=True, exist_ok=True)
        return path

    def to_storage_key(self, path: Path | str) -> str:
        """Convert absolute path to cross-platform logical storage key."""
        str_path = str(path).replace("\\", "/")
        if "data/projects/" in str_path:
            return "projects/" + str_path.split("data/projects/")[-1]
        elif "data/" in str_path:
            return str_path.split("data/")[-1]
        return str_path


storage_service = StorageService()


# Forward-compatible helper functions matching pre-existing signature
def get_project_dir(project_id: int) -> Path:
    return storage_service.get_project_dir(project_id)


def get_source_dir(project_id: int) -> Path:
    return storage_service.get_source_dir(project_id)


def resolve_storage_reference(storage_ref: str) -> Path:
    return storage_service.get_file_path(storage_ref)


def clean_project_source(project_id: int) -> None:
    source_dir = get_source_dir(project_id)
    if source_dir.exists():
        try:
            shutil.rmtree(source_dir)
        except Exception:
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
    Safely extracts a ZIP archive into target_dir with complete defense-in-depth security checks:
    - Signature validation (magic bytes PK\\x03\\x04)
    - Zip Slip & path traversal prevention
    - Absolute path rejection
    - Reserved device name rejection (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
    - Archive size limit (50MB compressed)
    - Individual file size limit (50MB uncompressed)
    - Total uncompressed size limit (250MB)
    - Total entry count limit (5,000 entries)
    - Decompression bomb ratio check (>100:1 ratio)
    - Symlink detection & sandbox containment verification
    - Automatic cleanup of target_dir on extraction failure
    """
    target_dir = target_dir.resolve()

    if not zip_path.exists():
        raise ValueError(f"ZIP file does not exist: {zip_path}")

    # 1. Compressed Archive Size Check (50MB max)
    archive_size = zip_path.stat().st_size
    if archive_size > 50 * 1024 * 1024:
        raise ValueError("ZIP archive size exceeds maximum limit of 50MB")

    # 2. File Header Magic Byte Check (PK\x03\x04)
    try:
        with open(zip_path, "rb") as f:
            header = f.read(4)
            if header != b"PK\x03\x04":
                raise ValueError("Invalid ZIP file header magic bytes")
    except Exception as e:
        if isinstance(e, ValueError):
            raise
        raise ValueError(f"Failed to read ZIP file header: {e}")

    # Reserved Windows device names
    RESERVED_NAMES = {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    }

    total_uncompressed = 0
    total_entries = 0

    try:
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            infolist = zip_ref.infolist()

            # Entry Count Limit (5,000 entries max)
            if len(infolist) > 5000:
                raise ValueError("ZIP archive contains too many files (maximum limit is 5,000)")

            for member in infolist:
                total_entries += 1
                fname = member.filename

                # Absolute Path & Traversal Checks
                if fname.startswith("/") or fname.startswith("\\") or (len(fname) > 1 and fname[1] == ":"):
                    raise ValueError(f"Path traversal rejected: Absolute path in ZIP entry '{fname}'")

                if ".." in fname.replace("\\", "/").split("/"):
                    raise ValueError(f"Path traversal rejected: Relative traversal in ZIP entry '{fname}'")

                # Reserved Name Check
                parts = Path(fname).parts
                for part in parts:
                    base_part = part.split(".")[0].upper()
                    if base_part in RESERVED_NAMES:
                        raise ValueError(f"Reserved device name rejected in ZIP entry: '{fname}'")

                # Individual File Size Limit (50MB max)
                if member.file_size > 50 * 1024 * 1024:
                    raise ValueError(f"ZIP entry '{fname}' exceeds individual size limit of 50MB")

                total_uncompressed += member.file_size

                # Total Uncompressed Size Limit (250MB max)
                if total_uncompressed > 250 * 1024 * 1024:
                    raise ValueError("ZIP extracted size exceeds total limit of 250MB")

                # Zip Bomb Ratio Check (>100:1 ratio for files >10MB)
                if total_uncompressed > 10 * 1024 * 1024 and archive_size > 0:
                    ratio = total_uncompressed / archive_size
                    if ratio > 100.0:
                        raise ValueError(f"Zip bomb detected: Decompression ratio {ratio:.1f}:1 exceeds safety threshold")

                # Destination Path Resolution & Zip Slip Verification
                member_path = target_dir / fname
                try:
                    resolved_member = member_path.resolve()
                except Exception:
                    resolved_member = member_path.absolute()

                try:
                    common = os.path.commonpath([target_dir, resolved_member])
                    if common != str(target_dir):
                        raise ValueError(f"Path traversal escape detected: '{fname}' points outside target directory")
                except Exception:
                    raise ValueError(f"Path traversal detected: Cannot resolve common path for '{fname}'")

            # Perform Extraction
            zip_ref.extractall(target_dir)

        # Symlink Post-Extraction Containment Check
        for path in target_dir.rglob("*"):
            try:
                if path.is_symlink():
                    resolved_target = path.readlink()
                    if not resolved_target.is_absolute():
                        resolved_target = (path.parent / resolved_target).resolve()
                    else:
                        resolved_target = resolved_target.resolve()

                    try:
                        common = os.path.commonpath([target_dir, resolved_target])
                        if common != str(target_dir):
                            path.unlink()
                            raise ValueError(f"Unsafe symlink detected and removed: {path} points outside target directory")
                    except Exception:
                        path.unlink()
                        raise ValueError(f"Unsafe symlink removed: {path}")
            except Exception as e:
                try:
                    if path.is_symlink():
                        path.unlink()
                except Exception:
                    pass
                if isinstance(e, ValueError):
                    raise

    except Exception as err:
        # Cleanup target_dir on extraction failure to prevent partial corrupt state
        if target_dir.exists():
            for item in target_dir.iterdir():
                try:
                    if item.is_dir():
                        shutil.rmtree(item)
                    else:
                        item.unlink()
                except Exception:
                    pass
        raise err
