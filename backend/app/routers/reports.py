import html
import re
from typing import Any, Dict, List
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.responses import Response, HTMLResponse, JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.services.report_service import ReportService


router = APIRouter(prefix="/reports", tags=["Reports"])


class ReportGenerateRequest(BaseModel):
    project_id: int
    report_type: str = "executive"  # executive, developer, compliance, owasp
    format: str = "pdf"             # pdf, html, json


@router.get("/templates")
def get_report_templates() -> List[Dict[str, Any]]:
    return [
        {
            "id": "t-1",
            "key": "executive",
            "title": "Executive Summary",
            "subtitle": "High-level risk overview & security score",
            "description": "Tailored for leadership and CISOs. Summarizes overarching security posture, critical risk score (0-100), and severity trends.",
            "category": "Executive",
            "icon": "assignment_ind",
        },
        {
            "id": "t-2",
            "key": "developer",
            "title": "Developer Report",
            "subtitle": "Technical deep-dive & code snippets",
            "description": "Granular technical details including stack traces, affected code snippets, line numbers, and actionable remediation steps.",
            "category": "Technical",
            "icon": "code",
        },
        {
            "id": "t-3",
            "key": "compliance",
            "title": "Compliance Report",
            "subtitle": "PCI-DSS & SOC2 regulatory mapping",
            "description": "Maps discovered vulnerabilities directly to specific regulatory clauses within frameworks like PCI-DSS v4.0 and SOC2 Type II.",
            "category": "Compliance",
            "icon": "verified_user",
        },
        {
            "id": "t-4",
            "key": "owasp",
            "title": "OWASP Top 10",
            "subtitle": "Web security threat distribution",
            "description": "Categorizes findings against official OWASP Top 10 2021 categories for web application security baselines.",
            "category": "Technical",
            "icon": "bug_report",
        },
    ]


@router.post("/generate")
def generate_report(
    req: ReportGenerateRequest,
    db: Session = Depends(get_db)
):
    service = ReportService(db)
    try:
        report_type = req.report_type.lower()
        fmt = req.format.lower()

        if fmt == "json":
            res_data = service.generate_json_report(req.project_id, report_type)
            return JSONResponse(content=res_data)
        elif fmt == "html":
            html_content = service.generate_html_report(req.project_id, report_type)
            return HTMLResponse(content=html_content)
        elif fmt == "pdf":
            pdf_bytes = service.generate_pdf_report(req.project_id, report_type)
            filename = f"kyptic_report_{req.project_id}_{report_type}.pdf"
            # Sanitize filename for headers
            safe_filename = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", filename)
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f'attachment; filename="{safe_filename}"'
                }
            )
        else:
            raise HTTPException(status_code=400, detail="Unsupported format. Choose 'pdf', 'html', or 'json'.")

    except ValueError as val_err:
        raise HTTPException(status_code=404, detail=str(val_err))
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {err}")


@router.get("/download")
def download_report(
    project_id: int = Query(...),
    report_type: str = Query("executive"),
    format: str = Query("pdf"),
    db: Session = Depends(get_db)
):
    """GET endpoint for downloading reports directly from browser links."""
    req = ReportGenerateRequest(project_id=project_id, report_type=report_type, format=format)
    return generate_report(req, db)
