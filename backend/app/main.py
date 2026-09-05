from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import Base, engine, update_db_schema
from app.models import Finding, Project, Scan
from app.routers.findings import router as findings_router
from app.routers.projects import router as projects_router
from app.routers.scans import router as scans_router
from app.routers.reports import router as reports_router
from app.routers.api_security import router as api_security_router
from app.services.scan_service import resume_pending_scans


Base.metadata.create_all(bind=engine)
update_db_schema()

app = FastAPI(title="Kyptic Backend", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(projects_router)
app.include_router(scans_router)
app.include_router(findings_router)
app.include_router(reports_router, prefix="/api/v1")
app.include_router(reports_router, prefix="/api")
app.include_router(api_security_router)



@app.on_event("startup")
async def resume_scans_after_restart() -> None:
    resume_pending_scans()


@app.get("/api/health", tags=["health"])
def health_check() -> dict[str, str]:
    return {"status": "ok", "message": "Kyptic backend is running"}