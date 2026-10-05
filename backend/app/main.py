import logging
from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.database import Base, engine, validate_db_connection
from app.models import ApiEndpoint, AuditLog, Finding, Organization, OrganizationMember, Project, Scan, User
from app.routers.activity import router as activity_router
from app.routers.api_security import router as api_security_router
from app.routers.auth import router as auth_router
from app.routers.compliance import router as compliance_router
from app.routers.copilot import router as copilot_router
from app.routers.findings import router as findings_router
from app.routers.projects import router as projects_router
from app.routers.reports import router as reports_router
from app.routers.risk_map import router as risk_map_router
from app.routers.scans import router as scans_router
from app.routers.targeted_verification import router as targeted_verification_router
from app.services.scan_service import resume_pending_scans

logger = logging.getLogger("kyptic.main")

# Ensure database tables exist safely
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Kyptic Backend", version="0.1.0")

# Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    # Enforce request body size limit (50MB max)
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > 50 * 1024 * 1024:
                return JSONResponse(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    content={"detail": "Request body size exceeds maximum limit of 50MB."}
                )
        except ValueError:
            pass

    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "connect-src 'self' http: https: ws: wss:; "
        "font-src 'self' data:; "
        "object-src 'none'; "
        "frame-ancestors 'none';"
    )

    # Conditionally set Strict-Transport-Security for HTTPS/production
    is_https = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    is_prod = getattr(settings, "ENVIRONMENT", "development").lower() in ("production", "prod")
    if is_https or (is_prod and getattr(settings, "COOKIE_SECURE", False)):
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    return response


# Global Exception Handler: Prevents leaking stack traces, SQL errors, or internal paths in production
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled Exception at %s: %s", request.url.path, exc, exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal server error occurred."}
    )


cors_origins = getattr(settings, "CORS_ORIGINS", ["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173"])
if isinstance(cors_origins, str):
    cors_origins = [o.strip() for o in cors_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(projects_router)
app.include_router(scans_router)
app.include_router(findings_router)
app.include_router(reports_router, prefix="/api/v1")
app.include_router(reports_router, prefix="/api")
app.include_router(api_security_router)
app.include_router(targeted_verification_router)
app.include_router(copilot_router)
app.include_router(risk_map_router)
app.include_router(compliance_router)
app.include_router(activity_router)


@app.on_event("startup")
async def on_startup() -> None:
    validate_db_connection()
    resume_pending_scans()


@app.get("/api/health", tags=["health"])
def health_check() -> dict[str, str]:
    return {"status": "ok", "message": "Kyptic backend is running"}
