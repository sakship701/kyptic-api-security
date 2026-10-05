from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.models.finding import Finding, FindingSeverity
from app.models.project import Project


def calculate_risk_score(findings: List[Finding]) -> Tuple[int, str, Dict[str, int]]:
    """
    Deterministic risk-score formula based ONLY on actual findings:
    - Base Score = 100
    - CRITICAL: -15 pts
    - HIGH: -8 pts
    - MEDIUM: -3 pts
    - LOW: -1 pt
    - INFO: 0 pts
    Final Score = max(0, min(100, int(round(100 - deduction))))
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = str(f.severity.value if hasattr(f.severity, "value") else f.severity).lower()
        if sev in counts:
            counts[sev] += 1

    deduction = (
        (counts["critical"] * 15)
        + (counts["high"] * 8)
        + (counts["medium"] * 3)
        + (counts["low"] * 1)
    )

    score = max(0, min(100, int(round(100 - deduction))))

    if score >= 90:
        grade = "A (Excellent)"
    elif score >= 75:
        grade = "B (Good)"
    elif score >= 60:
        grade = "C (Needs Improvement)"
    elif score >= 40:
        grade = "D (Poor)"
    else:
        grade = "F (Critical Risk)"

    return score, grade, counts


def get_project_posture(db: Session, project_id: int) -> Dict[str, Any]:
    project = db.get(Project, project_id)
    if not project:
        return {
            "project_id": project_id,
            "project_name": None,
            "score": None,
            "grade": "No assessment data",
            "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "total_findings": 0,
            "has_data": False,
        }

    findings = db.query(Finding).filter(Finding.project_id == project_id).all()
    if not findings:
        return {
            "project_id": project.id,
            "project_name": project.name,
            "score": None,
            "grade": "No assessment data",
            "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "total_findings": 0,
            "has_data": False,
        }

    score, grade, counts = calculate_risk_score(findings)
    return {
        "project_id": project.id,
        "project_name": project.name,
        "score": score,
        "grade": grade,
        "counts": counts,
        "total_findings": len(findings),
        "has_data": True,
    }


def get_global_posture(db: Session) -> Dict[str, Any]:
    findings = db.query(Finding).all()
    if not findings:
        return {
            "project_id": None,
            "project_name": "All Projects",
            "score": None,
            "grade": "No assessment data",
            "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "total_findings": 0,
            "has_data": False,
        }

    score, grade, counts = calculate_risk_score(findings)
    return {
        "project_id": None,
        "project_name": "All Projects",
        "score": score,
        "grade": grade,
        "counts": counts,
        "total_findings": len(findings),
        "has_data": True,
    }
