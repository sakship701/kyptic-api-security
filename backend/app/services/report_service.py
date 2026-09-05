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


def calculate_risk_score(findings: List[Finding]) -> Tuple[int, str, Dict[str, int]]:
    """
    Deterministic risk-score formula based ONLY on actual findings:
    - Base Score = 100
    - CRITICAL: -15 pts
    - HIGH: -8 pts
    - MEDIUM: -3 pts
    - LOW: -1 pt
    - INFO: 0 pts
    Final Score = max(0, min(100, int(round(100 - total_deduction))))
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


def map_owasp_category(category: str, title: str) -> str:
    cat_upper = category.upper()
    title_upper = title.upper()

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
        scan_ids = [s.id for s in scans]
        findings = self.db.query(Finding).filter(Finding.project_id == project_id).all()

        return project, scans, findings

    def generate_json_report(self, project_id: int, report_type: str = "executive") -> Dict[str, Any]:
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
                "category": f.category,
                "owasp": map_owasp_category(f.category, f.title),
                "source": f.source.value if hasattr(f.source, "value") else str(f.source),
                "file_path": f.file_path,
                "line_number": f.line_number,
                "rule_id": f.rule_id,
                "code_snippet": f.code_snippet,
            })

        return {
            "project_id": project.id,
            "project_name": project.name,
            "technology": project.technology,
            "source_type": project.source_type,
            "report_type": report_type,
            "generated_at": datetime.utcnow().isoformat(),
            "metrics": {
                "security_score": score,
                "security_grade": grade,
                "total_findings": len(findings),
                "severity_counts": counts,
                "scans_count": len(scans),
            },
            "owasp_breakdown": owasp_map,
            "findings": formatted_findings,
        }

    def generate_html_report(self, project_id: int, report_type: str = "executive") -> str:
        data = self.generate_json_report(project_id, report_type)
        proj_name = html.escape(data["project_name"])
        score = data["metrics"]["security_score"]
        grade = html.escape(data["metrics"]["security_grade"])
        counts = data["metrics"]["severity_counts"]

        findings_html = ""
        for f in data["findings"]:
            title = html.escape(f["title"])
            sev = html.escape(f["severity"]).upper()
            src = html.escape(f["source"]).upper()
            path = html.escape(f["file_path"])
            snippet = html.escape(f["code_snippet"] or "No snippet available")
            
            sev_color = "#ef4444" if sev == "CRITICAL" else "#f97316" if sev == "HIGH" else "#eab308" if sev == "MEDIUM" else "#3b82f6"

            findings_html += f"""
            <div style="border: 1px solid #1f2937; border-radius: 8px; padding: 16px; margin-bottom: 16px; background: #0f172a;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <h3 style="margin: 0; color: #f8fafc;">{title}</h3>
                    <span style="background: {sev_color}; color: #ffffff; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold;">{sev}</span>
                </div>
                <p style="color: #94a3b8; font-size: 14px; margin: 8px 0;"><strong>Source:</strong> {src} | <strong>Location:</strong> <code>{path}</code></p>
                <p style="color: #cbd5e1; font-size: 14px;">{html.escape(f['description'])}</p>
                <pre style="background: #020617; color: #38bdf8; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 12px;"><code>{snippet}</code></pre>
            </div>
            """

        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Kyptic Security Report - {proj_name}</title>
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
            <p style="margin: 4px 0 0 0; color: #94a3b8;">Target: {proj_name} | Type: {report_type.upper()}</p>
        </div>
        <div style="text-align: right;">
            <span style="font-size: 36px; font-weight: bold; color: #38bdf8;">{score}/100</span>
            <div style="color: #94a3b8; font-size: 12px;">Grade: {grade}</div>
        </div>
    </div>

    <div class="card">
        <h2 style="margin-top: 0;">Executive Summary & Metrics</h2>
        <div class="metric-grid">
            <div class="metric-box">
                <div style="color: #ef4444; font-size: 12px;">CRITICAL</div>
                <div class="metric-num" style="color: #ef4444;">{counts['critical']}</div>
            </div>
            <div class="metric-box">
                <div style="color: #f97316; font-size: 12px;">HIGH</div>
                <div class="metric-num" style="color: #f97316;">{counts['high']}</div>
            </div>
            <div class="metric-box">
                <div style="color: #eab308; font-size: 12px;">MEDIUM</div>
                <div class="metric-num" style="color: #eab308;">{counts['medium']}</div>
            </div>
            <div class="metric-box">
                <div style="color: #3b82f6; font-size: 12px;">LOW / INFO</div>
                <div class="metric-num" style="color: #3b82f6;">{counts['low'] + counts['info']}</div>
            </div>
        </div>
    </div>

    <div class="card">
        <h2 style="margin-top: 0;">Discovered Security Findings ({len(data['findings'])})</h2>
        {findings_html if findings_html else '<p style="color: #94a3b8;">No security findings detected.</p>'}
    </div>
</body>
</html>"""

    def generate_pdf_report(self, project_id: int, report_type: str = "executive") -> bytes:
        data = self.generate_json_report(project_id, report_type)

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
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#1e293b"),
        )
        subtitle_style = ParagraphStyle(
            "DocSubTitle",
            parent=styles["Normal"],
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#64748b"),
        )
        section_style = ParagraphStyle(
            "SectionHeader",
            parent=styles["Heading2"],
            fontSize=14,
            leading=18,
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

        story = []

        # Title & Header Table
        proj_title = html.escape(data["project_name"])
        report_title = f"KYPTIC APPLICATION SECURITY REPORT - {report_type.upper()}"
        score = data["metrics"]["security_score"]
        grade = html.escape(data["metrics"]["security_grade"])

        header_data = [
            [
                Paragraph(f"<b>{report_title}</b><br/><font color='#64748b'>Target: {proj_title} | Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</font>", title_style),
                Paragraph(f"<font size=20 color='#0284c7'><b>{score} / 100</b></font><br/><font size=9 color='#475569'>Grade: {grade}</font>", subtitle_style)
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

        # Severity Overview Table
        story.append(Paragraph("Executive Summary & Risk Metrics", section_style))
        counts = data["metrics"]["severity_counts"]
        
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

        # OWASP Top 10 Breakdown
        story.append(Paragraph("OWASP Top 10 Threat Distribution", section_style))
        owasp_rows = [["OWASP Category", "Vulnerability Count"]]
        for k, v in data["owasp_breakdown"].items():
            owasp_rows.append([k, str(v)])
        if len(owasp_rows) == 1:
            owasp_rows.append(["No OWASP category findings recorded", "0"])

        owasp_table = Table(owasp_rows, colWidths=[380, 160])
        owasp_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#334155")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ]))
        story.append(owasp_table)
        story.append(Spacer(1, 15))

        # Detailed Findings Section
        story.append(Paragraph(f"Discovered Findings ({len(data['findings'])})", section_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0"), spaceBefore=2, spaceAfter=10))

        if not data["findings"]:
            story.append(Paragraph("No vulnerabilities detected in target application.", body_style))
        else:
            for f in data["findings"]:
                f_title = html.escape(f["title"])
                f_sev = html.escape(f["severity"]).upper()
                f_src = html.escape(f["source"]).upper()
                f_path = html.escape(f["file_path"])
                f_desc = html.escape(f["description"])
                f_snippet = html.escape(f["code_snippet"] or "N/A")

                sev_bg = "#fee2e2" if f_sev == "CRITICAL" else "#ffedd5" if f_sev == "HIGH" else "#fef3c7" if f_sev == "MEDIUM" else "#dbeafe"
                sev_fg = "#991b1b" if f_sev == "CRITICAL" else "#9a3412" if f_sev == "HIGH" else "#92400e" if f_sev == "MEDIUM" else "#1e40af"

                finding_content = [
                    [Paragraph(f"<b>{f_title}</b>", body_style), Paragraph(f"<font color='{sev_fg}'><b>{f_sev}</b></font>", body_style)],
                    [Paragraph(f"<b>Source:</b> {f_src} | <b>Path:</b> {f_path}", body_style), Paragraph("", body_style)],
                    [Paragraph(f"<b>Details:</b> {f_desc}", body_style), Paragraph("", body_style)],
                    [Paragraph(f"<font color='#0284c7'>Snippet/Evidence:</font><br/><code>{f_snippet}</code>", code_style), Paragraph("", body_style)],
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
                story.append(Spacer(1, 8))

        doc.build(story)
        pdf_data = buffer.getvalue()
        buffer.close()
        return pdf_data
