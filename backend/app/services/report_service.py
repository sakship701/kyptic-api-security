import html
import io
import json
from datetime import datetime
from typing import Any, Dict, List, Tuple

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from sqlalchemy.orm import Session
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.finding import Finding, FindingSeverity, FindingSource
from app.models.api_endpoint import ApiEndpoint
from app.services.posture_service import calculate_risk_score
from app.services.compliance_service import ComplianceService


VALID_REPORT_TYPES = {"executive", "developer", "compliance", "owasp"}


def map_owasp_category(category: str, title: str) -> str:
    cat_upper = (category or "").upper()
    title_upper = (title or "").upper()

    # OWASP API Security Top 10 (2023)
    if "API1" in cat_upper or "BOLA" in cat_upper or "OBJECT LEVEL AUTHORIZATION" in cat_upper:
        return "API1:2023 - Broken Object Level Authorization"
    if "API2" in cat_upper or ("API" in cat_upper and "AUTH" in cat_upper and "API3" not in cat_upper):
        return "API2:2023 - Broken Authentication"
    if "API3" in cat_upper or "PROPERTY LEVEL" in cat_upper or "SENSITIVE DATA" in cat_upper:
        return "API3:2023 - Broken Object Property Level Authorization"
    if "API4" in cat_upper or "RESOURCE CONSUMPTION" in cat_upper or ("API" in cat_upper and "RATE" in cat_upper):
        return "API4:2023 - Unrestricted Resource Consumption"
    if "API5" in cat_upper or "FUNCTION LEVEL" in cat_upper:
        return "API5:2023 - Broken Function Level Authorization"
    if "API6" in cat_upper or "BUSINESS FLOW" in cat_upper or "MASS ASSIGNMENT" in cat_upper:
        return "API6:2023 - Unrestricted Access to Sensitive Business Flows"
    if "API7" in cat_upper or ("API" in cat_upper and "SSRF" in cat_upper):
        return "API7:2023 - Server Side Request Forgery"
    if "API8" in cat_upper or ("API" in cat_upper and "MISCONFIGURATION" in cat_upper):
        return "API8:2023 - Security Misconfiguration"
    if "API9" in cat_upper or "INVENTORY" in cat_upper:
        return "API9:2023 - Improper Inventory Management"
    if "API10" in cat_upper or "UNSAFE CONSUMPTION" in cat_upper:
        return "API10:2023 - Unsafe Consumption of APIs"

    # OWASP Web Top 10 (2021)
    if "A01" in cat_upper or "ACCESS CONTROL" in cat_upper or "IDOR" in cat_upper or "CORS" in cat_upper:
        return "A01:2021 - Broken Access Control"
    if "A02" in cat_upper or "CRYPTOGRAPHIC" in cat_upper or "TLS" in cat_upper or "HTTPS" in cat_upper or "SECRET" in cat_upper:
        return "A02:2021 - Cryptographic Failures"
    if "A03" in cat_upper or "INJECTION" in cat_upper or "SQL" in cat_upper or "XSS" in cat_upper or "COMMAND" in cat_upper:
        return "A03:2021 - Injection"
    if "A04" in cat_upper or "DESIGN" in cat_upper:
        return "A04:2021 - Insecure Design"
    if "A05" in cat_upper or "MISCONFIGURATION" in cat_upper or "HEADER" in cat_upper or "COOKIE" in cat_upper:
        return "A05:2021 - Security Misconfiguration"
    if "A06" in cat_upper or "VULNERABLE" in cat_upper or "DEPENDENCY" in cat_upper or "SCA" in cat_upper or "CVE" in cat_upper:
        return "A06:2021 - Vulnerable & Outdated Components"
    if "A07" in cat_upper or "AUTH" in cat_upper or "CREDENTIAL" in cat_upper:
        return "A07:2021 - Identification & Authentication Failures"
    if "A08" in cat_upper or "INTEGRITY" in cat_upper:
        return "A08:2021 - Software & Data Integrity Failures"
    if "A09" in cat_upper or "LOGGING" in cat_upper or "MONITORING" in cat_upper:
        return "A09:2021 - Security Logging & Monitoring Failures"
    if "A10" in cat_upper or "SSRF" in cat_upper:
        return "A10:2021 - Server-Side Request Forgery (SSRF)"

    return "A05:2021 - Security Misconfiguration"


class ReportService:
    def __init__(self, db: Session):
        self.db = db

    def _get_project_data(self, project_id: int) -> Tuple[Project, List[Scan], List[Finding]]:
        project = self.db.get(Project, project_id)
        if not project:
            raise ValueError(f"Project ID {project_id} not found.")

        scans = self.db.query(Scan).filter(Scan.project_id == project_id).all()
        findings = self.db.query(Finding).filter(Finding.project_id == project_id).all()

        return project, scans, findings

    def generate_json_report(self, project_id: int, report_type: str = "executive") -> Dict[str, Any]:
        rtype = (report_type or "executive").lower().strip()
        if rtype not in VALID_REPORT_TYPES:
            raise ValueError(f"Invalid report_type: '{report_type}'. Allowed types: {sorted(list(VALID_REPORT_TYPES))}")

        project, scans, findings = self._get_project_data(project_id)
        score, grade, counts = calculate_risk_score(findings)

        owasp_map: Dict[str, int] = {}
        for f in findings:
            cat = map_owasp_category(f.category, f.title)
            owasp_map[cat] = owasp_map.get(cat, 0) + 1

        formatted_findings = []
        for f in findings:
            formatted_findings.append({
                "id": f.id,
                "title": f.title,
                "description": f.description,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "cvss": float(f.cvss) if f.cvss is not None else None,
                "cvss_vector": getattr(f, "cvss_vector", None),
                "cvss_source": getattr(f, "cvss_source", None),
                "cvss_version": getattr(f, "cvss_version", None),
                "category": f.category,
                "owasp": map_owasp_category(f.category, f.title),
                "source": f.source.value if hasattr(f.source, "value") else str(f.source),
                "file_path": f.file_path,
                "line_number": f.line_number,
                "rule_id": f.rule_id,
                "code_snippet": f.code_snippet,
                "confidence_score": getattr(f, "confidence_score", 50),
                "confidence_level": getattr(f, "confidence_level", "MEDIUM"),
                "verification_status": getattr(f, "verification_status", "UNVERIFIED"),
                "verification_explanation": getattr(f, "verification_explanation", None),
                "evidence_sources": getattr(f, "evidence_sources", None),
                "correlation_count": getattr(f, "correlation_count", 0),
            })

        api_endpoints = self.db.query(ApiEndpoint).filter(ApiEndpoint.project_id == project_id).all()
        api_summary = None
        formatted_api_endpoints = []

        if api_endpoints:
            api_summary = {
                "total_api_endpoints": len(api_endpoints),
                "critical_endpoints": sum(1 for ep in api_endpoints if ep.risk_level == "CRITICAL"),
                "high_endpoints": sum(1 for ep in api_endpoints if ep.risk_level == "HIGH"),
                "medium_endpoints": sum(1 for ep in api_endpoints if ep.risk_level == "MEDIUM"),
                "low_endpoints": sum(1 for ep in api_endpoints if ep.risk_level == "LOW"),
                "info_endpoints": sum(1 for ep in api_endpoints if ep.risk_level == "INFO"),
                "unauthenticated_endpoints": sum(1 for ep in api_endpoints if ep.auth_status == "UNAUTHENTICATED"),
                "sensitive_data_endpoints": sum(1 for ep in api_endpoints if ep.sensitive_data_fields),
                "bola_risk_endpoints": sum(1 for ep in api_endpoints if ep.bola_status == "POTENTIAL_BOLA"),
                "mass_assignment_endpoints": sum(1 for ep in api_endpoints if ep.mass_assignment_status == "SUSPICIOUS_PROPERTIES_EXPOSED"),
                "rate_limit_risk_endpoints": sum(1 for ep in api_endpoints if ep.rate_limit_status == "MISSING"),
                "dast_verified_vulnerable_count": sum(1 for ep in api_endpoints if ep.dast_status == "VERIFIED_VULNERABLE"),
                "dast_verified_secure_count": sum(1 for ep in api_endpoints if ep.dast_status == "VERIFIED_SECURE"),
                "dast_inconclusive_count": sum(1 for ep in api_endpoints if ep.dast_status == "INCONCLUSIVE"),
                "dast_untested_count": sum(1 for ep in api_endpoints if not ep.dast_status or ep.dast_status == "UNTESTED"),
            }
            for ep in api_endpoints:
                formatted_api_endpoints.append({
                    "id": ep.id,
                    "path": ep.path,
                    "method": ep.method,
                    "summary": ep.summary,
                    "auth_status": ep.auth_status,
                    "risk_score": ep.risk_score,
                    "risk_level": ep.risk_level,
                    "bola_status": ep.bola_status,
                    "mass_assignment_status": ep.mass_assignment_status,
                    "rate_limit_status": ep.rate_limit_status,
                    "dast_status": ep.dast_status or "UNTESTED",
                })

        base_report = {
            "project_id": project.id,
            "project_name": project.name,
            "technology": project.technology,
            "source_type": project.source_type,
            "report_type": rtype,
            "generated_at": datetime.utcnow().isoformat(),
            "metrics": {
                "security_score": score,
                "security_grade": grade,
                "total_findings": len(findings),
                "severity_counts": counts,
                "scans_count": len(scans),
            },
            "owasp_breakdown": owasp_map,
            "api_security_summary": api_summary,
            "api_endpoints": formatted_api_endpoints,
            "findings": formatted_findings,
        }

        # Add report-type specific JSON sections
        if rtype == "executive":
            top_risks = [f for f in formatted_findings if f["severity"].lower() in ("critical", "high")]
            base_report["top_strategic_risks"] = [
                {
                    "title": f["title"],
                    "severity": f["severity"],
                    "category": f["category"],
                    "source": f["source"],
                    "description": f["description"]
                }
                for f in top_risks[:5]
            ]
            base_report["remediation_priorities"] = [
                f"Remediate {counts['critical']} Critical severity vulnerability immediately.",
                f"Address {counts['high']} High severity findings in the upcoming sprint cycle.",
                f"Review {len(formatted_api_endpoints)} API endpoints for authorization and rate-limiting controls."
            ]

        elif rtype == "developer":
            grouped_by_file: Dict[str, List[Dict[str, Any]]] = {}
            for f in formatted_findings:
                fp = f["file_path"] or "Unspecified Location"
                if fp not in grouped_by_file:
                    grouped_by_file[fp] = []
                grouped_by_file[fp].append(f)

            base_report["technical_details"] = {
                "grouped_by_file": grouped_by_file,
                "total_files_affected": len(grouped_by_file),
                "unverified_findings_count": sum(1 for f in formatted_findings if f["verification_status"] == "UNVERIFIED"),
            }

        elif rtype == "compliance":
            comp_eval = ComplianceService.evaluate_compliance(self.db, project_id, framework="PCI_DSS")
            base_report["compliance_summary"] = {
                "framework": comp_eval.framework,
                "framework_name": comp_eval.summary.framework_name,
                "coverage_percentage": comp_eval.summary.coverage_percentage,
                "total_controls": comp_eval.summary.total_controls,
                "affected_controls": comp_eval.summary.affected_controls,
                "unaffected_controls": comp_eval.summary.unaffected_controls,
                "insufficient_evidence_controls": comp_eval.summary.insufficient_evidence_controls,
                "total_mapped_findings": comp_eval.summary.total_mapped_findings,
                "disclaimer": comp_eval.summary.disclaimer,
            }
            base_report["controls"] = [
                {
                    "control_id": ctrl.control_id,
                    "control_name": ctrl.control_name,
                    "status": ctrl.status,
                    "affected_findings_count": ctrl.affected_findings_count,
                    "evidence_summary": ctrl.evidence_summary,
                    "remediation_reference": ctrl.remediation_reference,
                    "mapped_findings": [
                        {
                            "finding_id": mf.finding_id,
                            "title": mf.title,
                            "severity": mf.severity,
                            "cwe": mf.cwe,
                            "owasp": mf.owasp,
                            "verification_status": mf.verification_status,
                            "confidence_score": mf.confidence_score,
                            "file_path": mf.file_path,
                        }
                        for mf in ctrl.mapped_findings
                    ]
                }
                for ctrl in comp_eval.controls
            ]

        elif rtype == "owasp":
            grouped_by_owasp: Dict[str, List[Dict[str, Any]]] = {}
            for f in formatted_findings:
                owasp_cat = f["owasp"]
                if owasp_cat not in grouped_by_owasp:
                    grouped_by_owasp[owasp_cat] = []
                grouped_by_owasp[owasp_cat].append(f)

            base_report["owasp_summary"] = {
                "categories": [
                    {
                        "category_name": cat_name,
                        "count": len(f_list),
                        "findings": f_list
                    }
                    for cat_name, f_list in grouped_by_owasp.items()
                ]
            }

        return base_report

    def generate_html_report(self, project_id: int, report_type: str = "executive") -> str:
        data = self.generate_json_report(project_id, report_type)
        rtype = data["report_type"]
        proj_name = html.escape(data["project_name"])
        score = data["metrics"]["security_score"]
        grade = html.escape(data["metrics"]["security_grade"])
        counts = data["metrics"]["severity_counts"]

        if rtype == "executive":
            top_risks_html = ""
            for r in data.get("top_strategic_risks", []):
                top_risks_html += f"""
                <div style="border: 1px solid #374151; border-radius: 6px; padding: 12px; margin-bottom: 12px; background: #111827;">
                    <strong style="color: #f8fafc;">{html.escape(r['title'])}</strong> ({html.escape(r['severity']).upper()})
                    <p style="color: #94a3b8; font-size: 13px; margin: 4px 0 0 0;">{html.escape(r['description'])}</p>
                </div>
                """
            rem_html = "".join(f"<li>{html.escape(p)}</li>" for p in data.get("remediation_priorities", []))

            api_html = ""
            if data.get("api_security_summary"):
                api_sum = data["api_security_summary"]
                api_html = f"""
                <div class="card">
                    <h2 style="margin-top: 0; color: #38bdf8;">API Security Executive Summary</h2>
                    <div class="metric-grid">
                        <div class="metric-box"><div style="color: #94a3b8; font-size: 12px;">TOTAL ENDPOINTS</div><div class="metric-num">{api_sum['total_api_endpoints']}</div></div>
                        <div class="metric-box"><div style="color: #ef4444; font-size: 12px;">CRITICAL RISK</div><div class="metric-num" style="color: #ef4444;">{api_sum['critical_endpoints']}</div></div>
                        <div class="metric-box"><div style="color: #f97316; font-size: 12px;">HIGH RISK</div><div class="metric-num" style="color: #f97316;">{api_sum['high_endpoints']}</div></div>
                        <div class="metric-box"><div style="color: #eab308; font-size: 12px;">UNAUTHENTICATED</div><div class="metric-num" style="color: #eab308;">{api_sum['unauthenticated_endpoints']}</div></div>
                    </div>
                </div>
                """

            body_content = f"""
            <div class="card">
                <h2 style="color: #38bdf8; margin-top: 0;">Executive Summary & Risk Posture</h2>
                <p style="color: #cbd5e1;">Target Application: <strong>{proj_name}</strong> | Overall Security Score: <strong>{score}/100 ({grade})</strong></p>
                <div class="metric-grid">
                    <div class="metric-box"><div style="color: #ef4444; font-size: 12px;">CRITICAL</div><div class="metric-num" style="color: #ef4444;">{counts['critical']}</div></div>
                    <div class="metric-box"><div style="color: #f97316; font-size: 12px;">HIGH</div><div class="metric-num" style="color: #f97316;">{counts['high']}</div></div>
                    <div class="metric-box"><div style="color: #eab308; font-size: 12px;">MEDIUM</div><div class="metric-num" style="color: #eab308;">{counts['medium']}</div></div>
                    <div class="metric-box"><div style="color: #3b82f6; font-size: 12px;">LOW / INFO</div><div class="metric-num" style="color: #3b82f6;">{counts['low'] + counts['info']}</div></div>
                </div>
            </div>
            <div class="card">
                <h2 style="color: #f97316; margin-top: 0;">Top Strategic Risks</h2>
                {top_risks_html if top_risks_html else '<p style="color: #94a3b8;">No critical or high strategic risks detected.</p>'}
            </div>
            {api_html}
            <div class="card">
                <h2 style="color: #10b981; margin-top: 0;">Leadership Remediation Priorities</h2>
                <ul style="color: #cbd5e1; line-height: 1.6;">{rem_html}</ul>
            </div>
            """

        elif rtype == "developer":
            findings_html = ""
            for f in data["findings"]:
                title = html.escape(f["title"])
                sev = html.escape(f["severity"]).upper()
                src = html.escape(f["source"]).upper()
                path = html.escape(f["file_path"] or "N/A")
                line_str = f":L{f['line_number']}" if f.get("line_number") else ""
                snippet = html.escape(f["code_snippet"] or "No code snippet available")
                rule = html.escape(f.get("rule_id") or "N/A")
                cvss_str = f"CVSS: {f['cvss']}" if f.get("cvss") is not None else "CVSS: None"
                conf = f.get("confidence_score", 50)
                status = html.escape(f.get("verification_status", "UNVERIFIED"))

                sev_color = "#ef4444" if sev == "CRITICAL" else "#f97316" if sev == "HIGH" else "#eab308" if sev == "MEDIUM" else "#3b82f6"

                findings_html += f"""
                <div style="border: 1px solid #1f2937; border-radius: 8px; padding: 16px; margin-bottom: 16px; background: #0f172a;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <h3 style="margin: 0; color: #f8fafc;">{title}</h3>
                        <span style="background: {sev_color}; color: #ffffff; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold;">{sev}</span>
                    </div>
                    <p style="color: #94a3b8; font-size: 13px; margin: 8px 0;">
                        <strong>Location:</strong> <code>{path}{line_str}</code> | 
                        <strong>Source:</strong> {src} | <strong>Rule:</strong> {rule} | 
                        <strong>{cvss_str}</strong> | <strong>Conf:</strong> {conf}% | <strong>Status:</strong> {status}
                    </p>
                    <p style="color: #cbd5e1; font-size: 14px;">{html.escape(f['description'])}</p>
                    <pre style="background: #020617; color: #38bdf8; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 12px;"><code>{snippet}</code></pre>
                </div>
                """

            body_content = f"""
            <div class="card">
                <h2 style="color: #38bdf8; margin-top: 0;">Developer Technical Deep-Dive ({len(data['findings'])} Findings)</h2>
                <p style="color: #94a3b8; font-size: 13px;">Granular technical findings including source files, line numbers, rule IDs, and code snippets for engineering remediation.</p>
            </div>
            {findings_html}
            """

        elif rtype == "compliance":
            comp_sum = data.get("compliance_summary", {})
            ctrls = data.get("controls", [])
            ctrl_rows_html = ""
            for c in ctrls:
                st = c["status"]
                st_color = "#ef4444" if st == "AFFECTED" else "#10b981" if st == "NOT_AFFECTED" else "#eab308"
                ctrl_rows_html += f"""
                <div style="border: 1px solid #1f2937; border-radius: 6px; padding: 12px; margin-bottom: 12px; background: #0b0f19;">
                    <div style="display: flex; justify-content: space-between;">
                        <strong style="color: #f8fafc;">{html.escape(c['control_id'])}: {html.escape(c['control_name'])}</strong>
                        <span style="color: {st_color}; font-weight: bold; font-size: 12px;">{st}</span>
                    </div>
                    <p style="color: #94a3b8; font-size: 12px; margin: 4px 0;">{html.escape(c['evidence_summary'])}</p>
                </div>
                """

            body_content = f"""
            <div class="card">
                <h2 style="color: #38bdf8; margin-top: 0;">Regulatory Compliance Assessment - {html.escape(comp_sum.get('framework_name', 'PCI-DSS'))}</h2>
                <div class="metric-grid">
                    <div class="metric-box"><div style="color: #94a3b8; font-size: 12px;">COVERAGE</div><div class="metric-num">{comp_sum.get('coverage_percentage', 0)}%</div></div>
                    <div class="metric-box"><div style="color: #ef4444; font-size: 12px;">AFFECTED CONTROLS</div><div class="metric-num" style="color: #ef4444;">{comp_sum.get('affected_controls', 0)}</div></div>
                    <div class="metric-box"><div style="color: #10b981; font-size: 12px;">PASSED CONTROLS</div><div class="metric-num" style="color: #10b981;">{comp_sum.get('unaffected_controls', 0)}</div></div>
                    <div class="metric-box"><div style="color: #eab308; font-size: 12px;">INSUFFICIENT EVIDENCE</div><div class="metric-num" style="color: #eab308;">{comp_sum.get('insufficient_evidence_controls', 0)}</div></div>
                </div>
                <p style="color: #64748b; font-size: 11px; margin-top: 16px; font-style: italic;">{html.escape(comp_sum.get('disclaimer', ''))}</p>
            </div>
            <div class="card">
                <h3 style="color: #f8fafc; margin-top: 0;">Control Evaluation Trail</h3>
                {ctrl_rows_html}
            </div>
            """

        elif rtype == "owasp":
            owasp_cats_html = ""
            for cat in data.get("owasp_summary", {}).get("categories", []):
                cat_name = html.escape(cat["category_name"])
                findings_in_cat = cat["findings"]
                f_list_html = "".join(f"<li style='margin-bottom: 4px;'><strong>{html.escape(f['title'])}</strong> ({html.escape(f['severity']).upper()}) - <code>{html.escape(f['file_path'] or 'N/A')}</code></li>" for f in findings_in_cat)

                owasp_cats_html += f"""
                <div style="border: 1px solid #1f2937; border-radius: 8px; padding: 16px; margin-bottom: 16px; background: #0f172a;">
                    <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #374151; padding-bottom: 8px; margin-bottom: 12px;">
                        <h3 style="margin: 0; color: #38bdf8;">{cat_name}</h3>
                        <span style="background: #1e293b; color: #f8fafc; padding: 2px 8px; border-radius: 12px; font-size: 12px;">{len(findings_in_cat)} Finding(s)</span>
                    </div>
                    <ul style="color: #cbd5e1; font-size: 13px; padding-left: 20px;">{f_list_html}</ul>
                </div>
                """

            body_content = f"""
            <div class="card">
                <h2 style="color: #38bdf8; margin-top: 0;">OWASP Top 10 Security Threat Distribution</h2>
                <p style="color: #94a3b8; font-size: 13px;">Vulnerabilities categorized according to official OWASP Web Top 10 (2021) and OWASP API Security Top 10 (2023) standards.</p>
            </div>
            {owasp_cats_html if owasp_cats_html else '<div class="card"><p style="color: #94a3b8;">No findings mapped to OWASP categories.</p></div>'}
            """

        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Kyptic Security Report - {proj_name} ({rtype.upper()})</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #030712; color: #f8fafc; margin: 0; padding: 32px; }}
        .header {{ border-bottom: 2px solid #1e293b; padding-bottom: 16px; margin-bottom: 32px; display: flex; justify-content: space-between; align-items: center; }}
        .card {{ background: #0b0f19; border: 1px solid #1e293b; border-radius: 12px; padding: 24px; margin-bottom: 24px; }}
        .metric-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-top: 16px; }}
        .metric-box {{ background: #111827; padding: 16px; border-radius: 8px; text-align: center; border: 1px solid #1f2937; }}
        .metric-num {{ font-size: 28px; font-weight: bold; margin-top: 4px; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1 style="margin: 0; color: #38bdf8;">KYPTIC SECURITY REPORT</h1>
            <p style="margin: 4px 0 0 0; color: #94a3b8;">Target: {proj_name} | Type: {rtype.upper()}</p>
        </div>
        <div style="text-align: right;">
            <span style="font-size: 36px; font-weight: bold; color: #38bdf8;">{score}/100</span>
            <div style="color: #94a3b8; font-size: 12px;">Grade: {grade}</div>
        </div>
    </div>
    {body_content}
</body>
</html>"""

    def generate_pdf_report(self, project_id: int, report_type: str = "executive") -> bytes:
        data = self.generate_json_report(project_id, report_type)
        rtype = data["report_type"]

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#1e293b"),
        )
        subtitle_style = ParagraphStyle(
            "DocSubTitle",
            parent=styles["Normal"],
            fontSize=10,
            leading=13,
            textColor=colors.HexColor("#64748b"),
        )
        section_style = ParagraphStyle(
            "SectionHeader",
            parent=styles["Heading2"],
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#0f172a"),
            spaceBefore=12,
            spaceAfter=6,
        )
        body_style = ParagraphStyle(
            "BodyTextCustom",
            parent=styles["Normal"],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#334155"),
        )
        code_style = ParagraphStyle(
            "CodeCustom",
            parent=styles["Normal"],
            fontName="Courier",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#0284c7"),
        )

        style_dict = {
            "title": title_style,
            "subtitle": subtitle_style,
            "section": section_style,
            "body": body_style,
            "code": code_style,
        }

        story = []

        # Common Header
        proj_title = html.escape(data["project_name"])
        report_title = f"KYPTIC SECURITY REPORT - {rtype.upper()}"
        score = data["metrics"]["security_score"]
        grade = html.escape(data["metrics"]["security_grade"])

        header_data = [
            [
                Paragraph(f"<b>{report_title}</b><br/><font color='#64748b'>Target: {proj_title} | Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</font>", title_style),
                Paragraph(f"<font size=18 color='#0284c7'><b>{score} / 100</b></font><br/><font size=9 color='#475569'>Grade: {grade}</font>", subtitle_style)
            ]
        ]
        header_table = Table(header_data, colWidths=[380, 160])
        header_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (1, 0), (1, 0), "RIGHT"),
        ]))
        story.append(header_table)
        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceBefore=5, spaceAfter=15))

        # Delegate to specialized Story Builder
        if rtype == "executive":
            story.extend(self._build_executive_pdf_story(data, style_dict))
        elif rtype == "developer":
            story.extend(self._build_developer_pdf_story(data, style_dict))
        elif rtype == "compliance":
            story.extend(self._build_compliance_pdf_story(data, style_dict))
        elif rtype == "owasp":
            story.extend(self._build_owasp_pdf_story(data, style_dict))
        else:
            story.extend(self._build_executive_pdf_story(data, style_dict))

        doc.build(story)
        pdf_data = buffer.getvalue()
        buffer.close()
        return pdf_data

    def _build_executive_pdf_story(self, data: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> List[Any]:
        story = []
        counts = data["metrics"]["severity_counts"]

        # Executive Overview Table
        story.append(Paragraph("Executive Overview & Severity Breakdown", styles["section"]))
        metrics_table_data = [
            ["Critical", "High", "Medium", "Low / Info", "Total Findings"],
            [
                str(counts["critical"]),
                str(counts["high"]),
                str(counts["medium"]),
                str(counts["low"] + counts["info"]),
                str(data["metrics"]["total_findings"])
            ]
        ]
        metrics_table = Table(metrics_table_data, colWidths=[100, 100, 100, 120, 120])
        metrics_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("TEXTCOLOR", (0, 1), (0, 1), colors.HexColor("#dc2626")),
            ("TEXTCOLOR", (1, 1), (1, 1), colors.HexColor("#ea580c")),
            ("TEXTCOLOR", (2, 1), (2, 1), colors.HexColor("#d97706")),
            ("TEXTCOLOR", (3, 1), (3, 1), colors.HexColor("#2563eb")),
            ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ]))
        story.append(metrics_table)
        story.append(Spacer(1, 15))

        # Top Strategic Risks Section
        story.append(Paragraph("Top Strategic Vulnerability Risks", styles["section"]))
        top_risks = data.get("top_strategic_risks", [])
        if not top_risks:
            story.append(Paragraph("No Critical or High strategic risks identified in target application.", styles["body"]))
        else:
            risk_rows = [["Title", "Severity", "Category", "Source"]]
            for r in top_risks:
                risk_rows.append([
                    r["title"][:40],
                    r["severity"].upper(),
                    r["category"][:30],
                    r["source"].upper()
                ])
            risk_table = Table(risk_rows, colWidths=[200, 80, 160, 100])
            risk_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ]))
            story.append(risk_table)

        story.append(Spacer(1, 15))

        # API Security Summary (if present)
        if data.get("api_security_summary"):
            story.append(Paragraph("API Security Executive Summary", styles["section"]))
            api_sum = data["api_security_summary"]
            api_p = Paragraph(
                f"<b>Total Endpoints:</b> {api_sum['total_api_endpoints']} | "
                f"<b>Critical Risk:</b> {api_sum['critical_endpoints']} | "
                f"<b>Unauthenticated:</b> {api_sum['unauthenticated_endpoints']} | "
                f"<b>BOLA Exposure:</b> {api_sum['bola_risk_endpoints']}",
                styles["body"]
            )
            story.append(api_p)
            story.append(Spacer(1, 15))

        # Strategic Remediation Priorities
        story.append(Paragraph("Leadership Remediation Priorities", styles["section"]))
        for p in data.get("remediation_priorities", []):
            story.append(Paragraph(f"• {html.escape(p)}", styles["body"]))
            story.append(Spacer(1, 4))

        return story

    def _build_developer_pdf_story(self, data: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> List[Any]:
        story = []
        findings = data["findings"]

        story.append(Paragraph(f"Technical Findings & Code Evidence ({len(findings)})", styles["section"]))
        story.append(Paragraph("Detailed technical breakdown for engineering remediation teams.", styles["body"]))
        story.append(Spacer(1, 10))

        if not findings:
            story.append(Paragraph("No technical findings detected in application.", styles["body"]))
            return story

        for f in findings:
            f_title = html.escape(f["title"])
            f_sev = html.escape(f["severity"]).upper()
            f_src = html.escape(f["source"]).upper()
            f_path = html.escape(f["file_path"] or "N/A")
            f_line = f" (Line {f['line_number']})" if f.get("line_number") else ""
            f_desc = html.escape(f["description"])
            f_snippet = html.escape(f["code_snippet"] or "N/A")
            f_rule = html.escape(f.get("rule_id") or "N/A")
            f_cvss = f"CVSS {f['cvss']}" if f.get("cvss") is not None else "CVSS None"
            f_conf = f.get("confidence_score", 50)
            f_status = html.escape(f.get("verification_status", "UNVERIFIED"))

            sev_bg = "#fee2e2" if f_sev == "CRITICAL" else "#ffedd5" if f_sev == "HIGH" else "#fef3c7" if f_sev == "MEDIUM" else "#dbeafe"
            sev_fg = "#991b1b" if f_sev == "CRITICAL" else "#9a3412" if f_sev == "HIGH" else "#92400e" if f_sev == "MEDIUM" else "#1e40af"

            meta_str = f"<b>Location:</b> {f_path}{f_line} | <b>Rule ID:</b> {f_rule} | <b>Source:</b> {f_src} | <b>{f_cvss}</b> | <b>Confidence:</b> {f_conf}% ({f_status})"

            finding_content = [
                [Paragraph(f"<b>{f_title}</b>", styles["body"]), Paragraph(f"<font color='{sev_fg}'><b>{f_sev}</b></font>", styles["body"])],
                [Paragraph(meta_str, styles["body"]), Paragraph("", styles["body"])],
                [Paragraph(f"<b>Description:</b> {f_desc}", styles["body"]), Paragraph("", styles["body"])],
                [Paragraph(f"<font color='#0284c7'>Code / Proof Snippet:</font><br/><code>{f_snippet}</code>", styles["code"]), Paragraph("", styles["body"])],
            ]

            f_table = Table(finding_content, colWidths=[440, 100])
            f_table.setStyle(TableStyle([
                ("SPAN", (0, 1), (1, 1)),
                ("SPAN", (0, 2), (1, 2)),
                ("SPAN", (0, 3), (1, 3)),
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("BACKGROUND", (1, 0), (1, 0), colors.HexColor(sev_bg)),
                ("ALIGN", (1, 0), (1, 0), "CENTER"),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(f_table)
            story.append(Spacer(1, 10))

        return story

    def _build_compliance_pdf_story(self, data: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> List[Any]:
        story = []
        comp_sum = data.get("compliance_summary", {})
        controls = data.get("controls", [])

        story.append(Paragraph(f"Regulatory Compliance Assessment - {comp_sum.get('framework_name', 'PCI-DSS')}", styles["section"]))
        story.append(Spacer(1, 5))

        # Compliance Summary Table
        comp_table_data = [
            ["Framework", "Coverage %", "Affected Controls", "Passed Controls", "Insufficient Evidence"],
            [
                str(comp_sum.get("framework_name", "PCI-DSS")),
                f"{comp_sum.get('coverage_percentage', 0)}%",
                str(comp_sum.get("affected_controls", 0)),
                str(comp_sum.get("unaffected_controls", 0)),
                str(comp_sum.get("insufficient_evidence_controls", 0)),
            ]
        ]
        comp_table = Table(comp_table_data, colWidths=[140, 100, 100, 100, 100])
        comp_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ]))
        story.append(comp_table)
        story.append(Spacer(1, 15))

        # Control Mapping Table
        story.append(Paragraph("Security Control Mapping & Audit Trail", styles["section"]))
        ctrl_rows = [["Control ID", "Control Name", "Status", "Evidence Summary"]]
        for c in controls:
            ctrl_rows.append([
                c["control_id"],
                c["control_name"][:30],
                c["status"],
                c["evidence_summary"][:55]
            ])
        if len(ctrl_rows) == 1:
            ctrl_rows.append(["N/A", "No compliance controls evaluated", "NONE", "No data"])

        ctrl_table = Table(ctrl_rows, colWidths=[80, 160, 90, 210])
        ctrl_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ]))
        story.append(ctrl_table)
        story.append(Spacer(1, 15))

        # Disclaimer
        disclaimer_text = comp_sum.get("disclaimer", "Compliance coverage represents an automated assessment aid and does not constitute legal certification.")
        story.append(Paragraph(f"<b>Audit Disclaimer:</b> {html.escape(disclaimer_text)}", styles["body"]))

        return story

    def _build_owasp_pdf_story(self, data: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> List[Any]:
        story = []
        owasp_sum = data.get("owasp_summary", {})
        categories = owasp_sum.get("categories", [])

        story.append(Paragraph("OWASP Security Threat Distribution", styles["section"]))
        story.append(Paragraph("Findings grouped by OWASP Top 10 (2021) and OWASP API Security Top 10 (2023) standards.", styles["body"]))
        story.append(Spacer(1, 10))

        # Summary Breakdown Table
        breakdown_rows = [["OWASP Category", "Total Vulnerabilities"]]
        for cat in categories:
            breakdown_rows.append([cat["category_name"], str(len(cat["findings"]))])
        if len(breakdown_rows) == 1:
            breakdown_rows.append(["No OWASP category findings recorded", "0"])

        b_table = Table(breakdown_rows, colWidths=[380, 160])
        b_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ]))
        story.append(b_table)
        story.append(Spacer(1, 15))

        # Category Groupings
        story.append(Paragraph("Vulnerabilities Grouped by OWASP Category", styles["section"]))
        for cat in categories:
            cat_name = html.escape(cat["category_name"])
            story.append(Paragraph(f"<b>{cat_name}</b> ({len(cat['findings'])} findings)", styles["section"]))

            f_rows = [["Finding Title", "Severity", "File Path"]]
            for f in cat["findings"]:
                f_rows.append([
                    f["title"][:40],
                    f["severity"].upper(),
                    (f["file_path"] or "N/A")[:35]
                ])
            f_table = Table(f_rows, colWidths=[220, 80, 240])
            f_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ]))
            story.append(f_table)
            story.append(Spacer(1, 10))

        return story
