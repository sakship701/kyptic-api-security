from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.dependencies.auth import get_current_user
from app.models.project import Project
from app.models.user import User
from app.schemas.auth import TokenResponse, UserLoginRequest, UserRegisterRequest, UserResponse
from app.services.auth_service import create_access_token, hash_password, log_audit_event, revoke_user_session, verify_password
from app.services.rate_limiter import enforce_auth_rate_limit

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(enforce_auth_rate_limit)])
def register_user(
    req: UserRegisterRequest,
    response: Response,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    email_clean = req.email.lower().strip()
    if not email_clean:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email is required.")

    # Check for existing user
    existing_user = db.scalar(select(User).where(User.email == email_clean))
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email address already exists."
        )

    # Hash password securely (Argon2id / PBKDF2-HMAC-SHA256)
    hashed_pw = hash_password(req.password)

    user = User(
        email=email_clean,
        password_hash=hashed_pw,
        full_name=req.full_name.strip() if req.full_name else None,
        is_active=True,
        is_superuser=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # Controlled bootstrap project ownership: if this user matches the configured bootstrap owner email,
    # bind any legacy unowned projects (e.g. Project 1)
    if settings.BOOTSTRAP_OWNER_EMAIL and email_clean == settings.BOOTSTRAP_OWNER_EMAIL:
        unowned_projects = list(db.scalars(select(Project).where(Project.user_id.is_(None))).all())
        for proj in unowned_projects:
            proj.user_id = user.id
        if unowned_projects:
            db.commit()

    ip = request.client.host if request.client else None
    user_agent = request.headers.get("User-Agent")
    log_audit_event(
        db=db,
        user_id=user.id,
        action="USER_REGISTER",
        resource_type="user",
        resource_id=str(user.id),
        details=f"Registered new account for {user.email}",
        ip_address=ip,
    )

    # Create access token and server-side session
    access_token = create_access_token(
        {"user_id": user.id, "email": user.email},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        db=db,
        ip_address=ip,
        user_agent=user_agent,
    )

    # Set HttpOnly cookie for session security
    response.set_cookie(
        key="kyptic_session",
        value=access_token,
        httponly=True,
        samesite=settings.COOKIE_SAMESITE,
        secure=settings.COOKIE_SECURE,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
    )

    user_resp = UserResponse.model_validate(user)
    return TokenResponse(access_token=access_token, user=user_resp)


@router.post("/login", response_model=TokenResponse, dependencies=[Depends(enforce_auth_rate_limit)])
def login_user(
    req: UserLoginRequest,
    response: Response,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    email_clean = req.email.lower().strip()
    user = db.scalar(select(User).where(User.email == email_clean))

    ip = request.client.host if request.client else None
    user_agent = request.headers.get("User-Agent")

    if not user or not verify_password(req.password, user.password_hash):
        log_audit_event(
            db=db,
            user_id=user.id if user else None,
            action="LOGIN_FAILED",
            resource_type="user",
            resource_id=str(user.id) if user else email_clean,
            details=f"Failed login attempt for email {email_clean}",
            ip_address=ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is deactivated."
        )

    log_audit_event(
        db=db,
        user_id=user.id,
        action="LOGIN_SUCCESS",
        resource_type="user",
        resource_id=str(user.id),
        details=f"User {user.email} logged in successfully",
        ip_address=ip,
    )

    access_token = create_access_token(
        {"user_id": user.id, "email": user.email},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        db=db,
        ip_address=ip,
        user_agent=user_agent,
    )

    response.set_cookie(
        key="kyptic_session",
        value=access_token,
        httponly=True,
        samesite=settings.COOKIE_SAMESITE,
        secure=settings.COOKIE_SECURE,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
    )

    user_resp = UserResponse.model_validate(user)
    return TokenResponse(access_token=access_token, user=user_resp)


@router.post("/logout")
def logout_user(
    response: Response,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    ip = request.client.host if request.client else None
    jti = getattr(request.state, "jti", None)
    if jti:
        revoke_user_session(db=db, jti=jti)

    log_audit_event(
        db=db,
        user_id=user.id,
        action="LOGOUT",
        resource_type="user",
        resource_id=str(user.id),
        details=f"User {user.email} logged out",
        ip_address=ip,
    )
    response.delete_cookie(key="kyptic_session", path="/")
    return {"message": "Successfully logged out."}


@router.get("/me", response_model=UserResponse)
def get_me(user: User = Depends(get_current_user)) -> UserResponse:
    return UserResponse.model_validate(user)
