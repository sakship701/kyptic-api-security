from typing import List, Optional
from sqlalchemy.orm import Session

from app.models.finding import Finding, FindingStatus
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.schemas.compliance import (
    ComplianceControl,
    ComplianceFrameworkSummary,
    ComplianceResponse,
    ControlMappedFinding,
)
from app.security.compliance_registry import ComplianceRegistry


class ComplianceService:
    DISCLAIMER = (
        "Compliance coverage represents an automated evidence-based security assessment aid "
        "and does NOT constitute legal compliance certification."
    )

    DAST_CWES = {"CWE-639", "CWE-284", "CWE-285", "CWE-307", "CWE-400", "CWE-770", "CWE-915", "CWE-213", "CWE-862"}
    DAST_OWASPS = {"API1:2023", "API2:2023", "API3:2023", "API4:2023", "API5:2023", "A01:2021", "A05:2021"}

    SCA_CWES = {"CWE-1104", "CWE-937"}
    SCA_OWASPS = {"A06:2021", "API6:2023"}

    SAST_CWES = {"CWE-89", "CWE-78", "CWE-79", "CWE-94", "CWE-327", "CWE-798", "CWE-311", "CWE-502"}
    SAST_OWASPS = {"A03:2021", "A02:2021", "A07:2021", "A08:2021"}

    @classmethod
    def _is_control_domain_assessed(
        cls,
        ctrl_def,
        completed_scans: List[Scan],
        all_findings: List[Finding],
    ) -> bool:
        if not completed_scans and not all_findings:
            return False

        cwes_set = set(ctrl_def.cwes or [])
        owasps_set = set(ctrl_def.owasps or [])

        requires_dast = bool(cwes_set & cls.DAST_CWES or owasps_set & cls.DAST_OWASPS)
        requires_sca = bool(cwes_set & cls.SCA_CWES or owasps_set & cls.SCA_OWASPS)
        requires_sast = bool(cwes_set & cls.SAST_CWES or owasps_set & cls.SAST_OWASPS)

        has_full_scan = any(
            s.scanner in [None, "", "full_scan", "orchestrator", "unified"]
            for s in completed_scans
        )

        has_dast = has_full_scan or any(
            (s.scanner and s.scanner.lower() in ["dast", "api_security", "browser_dast"]) or
            (s.dast_status and s.dast_status.lower() in ["completed", "success", "done"])
            for s in completed_scans
        ) or any(
            str(getattr(f, "source", "")).lower() in ["dast", "api_security", "greybox", "findingsource.dast", "findingsource.api_security"]
            for f in all_findings
        )

        has_sast = has_full_scan or any(
            (s.scanner and s.scanner.lower() in ["sast", "semgrep"])
            for s in completed_scans
        ) or any(
            str(getattr(f, "source", "")).lower() in ["sast", "secrets", "greybox", "findingsource.sast", "findingsource.secrets"]
            for f in all_findings
        )

        has_sca = has_full_scan or any(
            (s.scanner and s.scanner.lower() in ["sca"]) or
            (s.sca_status and s.sca_status.lower() in ["completed", "success", "done"])
            for s in completed_scans
        ) or any(
            str(getattr(f, "source", "")).lower() in ["sca", "findingsource.sca"]
            for f in all_findings
        )

        if not requires_dast and not requires_sca and not requires_sast:
            return len(completed_scans) > 0 or len(all_findings) > 0

        if requires_dast and not has_dast:
            return False
        if requires_sca and not has_sca:
            return False
        if requires_sast and not has_sast:
            return False

        return True

    @classmethod
    def evaluate_compliance(
        cls,
        db: Session,
        project_id: int,
        framework: str = "PCI_DSS",
    ) -> ComplianceResponse:
        project = db.get(Project, project_id)
        if not project:
            raise ValueError(f"Project {project_id} not found")

        framework_key = framework.upper()
        if framework_key not in ComplianceRegistry.FRAMEWORKS:
            framework_key = "PCI_DSS"

        framework_name = ComplianceRegistry.FRAMEWORKS[framework_key]
        control_defs = ComplianceRegistry.get_controls_for_framework(framework_key)

        scans = db.query(Scan).filter(Scan.project_id == project_id).all()
        completed_scans = [s for s in scans if s.status == ScanStatus.COMPLETED]

        findings = (
            db.query(Finding)
            .filter(Finding.project_id == project_id)
            .order_by(Finding.severity.desc(), Finding.created_at.desc())
            .all()
        )

        controls_result: List[ComplianceControl] = []
        affected_count = 0
        unaffected_count = 0
        insufficient_count = 0
        total_mapped_findings_count = 0

        for ctrl_def in control_defs:
            mapped_findings: List[ControlMappedFinding] = []
            
            for f in findings:
                f_cwe = f.cwe or ""
                f_owasp = f.owasp or ""
                
                # Check match against control CWEs or OWASPs
                cwe_match = any(c in f_cwe for c in ctrl_def.cwes) if ctrl_def.cwes else False
                owasp_match = any(o in f_owasp for o in ctrl_def.owasps) if ctrl_def.owasps else False

                if cwe_match or owasp_match:
                    sev_str = str(f.severity.value if hasattr(f.severity, "value") else f.severity).upper()
                    mapped_findings.append(
                        ControlMappedFinding(
                            finding_id=f.id,
                            title=f.title,
                            severity=sev_str,
                            cwe=f.cwe,
                            owasp=f.owasp,
                            verification_status=f.verification_status,
                            confidence_score=f.confidence_score,
                            file_path=f.file_path,
                        )
                    )

            total_mapped_findings_count += len(mapped_findings)
            open_mapped = [mf for mf in mapped_findings if mf.finding_id in [f.id for f in findings if f.status == FindingStatus.OPEN]]

            # Status determination logic
            if not ctrl_def.cwes and not ctrl_def.owasps:
                ctrl_status = "NO_DIRECT_MAPPING"
                evidence_str = "No direct automated scanner rules map to this compliance control vector."
            elif len(open_mapped) > 0:
                ctrl_status = "AFFECTED"
                affected_count += 1
                evidence_str = f"{len(open_mapped)} active finding(s) affect this security control."
            elif cls._is_control_domain_assessed(ctrl_def, completed_scans, findings):
                ctrl_status = "NOT_AFFECTED"
                unaffected_count += 1
                evidence_str = "Sufficient assessment completed with no active findings detected for this security control."
            else:
                ctrl_status = "INSUFFICIENT_EVIDENCE"
                insufficient_count += 1
                evidence_str = "Insufficient scan evidence available to evaluate this control domain."

            controls_result.append(
                ComplianceControl(
                    control_id=ctrl_def.control_id,
                    control_name=ctrl_def.control_name,
                    framework=ctrl_def.framework,
                    description=ctrl_def.description,
                    status=ctrl_status,
                    affected_findings_count=len(mapped_findings),
                    mapped_findings=mapped_findings,
                    evidence_summary=evidence_str,
                    remediation_reference=ctrl_def.remediation_reference,
                )
            )

        total_ctrls = len(controls_result)
        coverage_pct = round((unaffected_count / total_ctrls * 100.0), 1) if total_ctrls > 0 else 0.0

        summary = ComplianceFrameworkSummary(
            framework=framework_key,
            framework_name=framework_name,
            total_controls=total_ctrls,
            affected_controls=affected_count,
            unaffected_controls=unaffected_count,
            insufficient_evidence_controls=insufficient_count,
            total_mapped_findings=total_mapped_findings_count,
            coverage_percentage=coverage_pct,
            disclaimer=cls.DISCLAIMER,
        )

        return ComplianceResponse(
            project_id=project.id,
            project_name=project.name,
            framework=framework_key,
            summary=summary,
            controls=controls_result,
        )

