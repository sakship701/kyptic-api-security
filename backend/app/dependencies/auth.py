from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models.api_endpoint import ApiEndpoint
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.models.user import User
from app.services.auth_service import decode_access_token, is_session_active, log_audit_event

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


def get_current_user(
    request: Request,
    token_header: str | None = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """
    Retrieves the currently authenticated user from either:
    1. Authorization: Bearer <token> header
    2. HttpOnly 'kyptic_session' cookie
    """
    token = token_header
    if not token:
        token = request.cookies.get("kyptic_session")

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token is invalid or expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id_val = payload.get("user_id") or payload.get("sub")
    if not user_id_val:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token payload.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        user_id = int(user_id_val)
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user identifier in token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authenticated user account no longer exists.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    jti = payload.get("jti")
    if not jti:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token payload.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Validate active server-side session
    if not is_session_active(db, jti, user.id):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been revoked or expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    request.state.jti = jti
    return user


def verify_project_access(
    project_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Project:
    """
    Verifies that the authenticated user owns the specified project.
    Strict single-role authorization: User A can only access User A's projects.
    Protects against Insecure Direct Object Reference (IDOR) attacks across all endpoints.
    """
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project {project_id} not found."
        )

    # Legacy unowned project bootstrap: only assign to configured bootstrap owner if email matches
    if project.user_id is None:
        if settings.BOOTSTRAP_OWNER_EMAIL and user.email.lower() == settings.BOOTSTRAP_OWNER_EMAIL.lower():
            project.user_id = user.id
            db.commit()
            db.refresh(project)
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to access this project."
            )

    # Strict ownership check
    if project.user_id != user.id:
        ip = request.client.host if request.client else None
        log_audit_event(
            db=db,
            user_id=user.id,
            action="UNAUTHORIZED_ACCESS_ATTEMPT",
            resource_type="project",
            resource_id=str(project_id),
            details=f"User {user.email} (ID {user.id}) attempted to access Project {project_id} owned by User {project.user_id}",
            ip_address=ip,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to access this project."
        )

    return project


def get_scan_with_ownership_check(
    scan_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Scan:
    """
    Retrieves a Scan and validates that the authenticated user owns the scan's parent project.
    """
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    verify_project_access(project_id=scan.project_id, request=request, user=user, db=db)
    return scan


def get_finding_with_ownership_check(
    finding_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Finding:
    """
    Retrieves a Finding and validates that the authenticated user owns the finding's parent project.
    """
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")
    verify_project_access(project_id=finding.project_id, request=request, user=user, db=db)
    return finding


def get_endpoint_with_ownership_check(
    endpoint_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ApiEndpoint:
    """
    Retrieves an ApiEndpoint and validates that the authenticated user owns the endpoint's parent project.
    """
    endpoint = db.get(ApiEndpoint, endpoint_id)
    if endpoint is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API Endpoint not found.")
    verify_project_access(project_id=endpoint.project_id, request=request, user=user, db=db)
    return endpoint
