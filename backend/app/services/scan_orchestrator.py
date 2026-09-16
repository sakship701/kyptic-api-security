import asyncio
import time
from datetime import datetime
from typing import Any, Dict, List, Set, Tuple

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models.finding import Finding, FindingSeverity, FindingSource, FindingStatus
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.services.api_security_scanner import run_static_api_analysis
from app.services.cross_validation_engine import CrossValidationEngine
from app.services.dast_probes import run_active_dast_probes
from app.services.dast_scanner import DASTStatus, DASTWebScanner
from app.services.detect_secrets_scanner import DetectSecretsScanner
from app.services.finding_normalizer import (
    generate_fingerprint,
    normalize_dast_results,
    normalize_detect_secrets_results,
    normalize_sca_results,
    normalize_semgrep_results,
)
from app.services.sca_scanner import SCADependencyScanner
from app.services.semgrep_scanner import SemgrepSASTScanner
from app.services.ssrf_protection import is_ssrf_safe_url
from app.services.storage_service import get_project_dir, get_source_dir


class ScanOrchestrator:
    """
    Unified Scan Orchestrator for Kyptic API Security Platform.
    Sequences and executes all applicable security analysis modules
    (White-Box SAST/Secrets/SCA, Web DAST, OpenAPI Static & API DAST)
    with error isolation, finding normalization, and triage preservation.
    """

    def __init__(self, db: Session, scan_id: int):
        self.db = db
        self.scan_id = scan_id

    def determine_capabilities(self, project: Project) -> Dict[str, bool]:
        """
        Determines which scanning modules are applicable based on project assets and configuration.
        """
        source_dir = get_source_dir(project.id)
        has_source_files = source_dir.exists() and any(f.is_file() for f in source_dir.rglob("*"))
        is_source_type = project.source_type in ("ZIP", "GIT", "ZIP_ARCHIVE", "GIT_REPOSITORY")

        has_white_box = is_source_type or (has_source_files and project.source_type not in ("WEBSITE", "OPENAPI"))

        target_url = project.target_url or (project.api_target_url if project.source_type == "WEBSITE" else None)
        has_web_dast = bool(target_url) or project.source_type == "WEBSITE"

        project_dir = get_project_dir(project.id)
        spec_file = project_dir / "openapi_spec.raw"
        has_api_security = spec_file.exists() or project.source_type == "OPENAPI"

        return {
            "white_box": has_white_box,
            "web_dast": has_web_dast,
            "api_security": has_api_security,
        }

    async def execute(self) -> None:
        scan = self.db.get(Scan, self.scan_id)
        if scan is None or scan.status in {ScanStatus.PAUSED, ScanStatus.STOPPED, ScanStatus.FAILED}:
            return

        project = self.db.get(Project, scan.project_id)
        if project is None:
            scan.status = ScanStatus.FAILED
            scan.error_message = "Project not found"
            self.db.commit()
            return

        if not project.source_type or project.source_status != "READY":
            scan.status = ScanStatus.FAILED
            scan.error_message = "Project source code is missing or not ready. Please complete onboarding first."
            self.db.commit()
            return

        capabilities = self.determine_capabilities(project)

        # Start scan execution
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.utcnow()
        scan.current_phase = "Preparing scan"
        scan.progress = 5
        self.db.commit()

        start_time = time.time()
        combined_findings: List[Finding] = []
        executed_scanners: List[str] = []
        scanner_versions: List[str] = []
        sca_status: str | None = None
        dast_status: str | None = None

        # =====================================================================
        # STAGE 1: White-Box Analysis (SAST + Secrets + SCA)
        # =====================================================================
        if capabilities["white_box"]:
            source_dir = get_source_dir(project.id)

            # 1a. SAST (Semgrep)
            scan.current_phase = "Running SAST"
            scan.progress = 15
            self.db.commit()

            sast_scanner = SemgrepSASTScanner()
            semgrep_path = sast_scanner._resolve_semgrep_path()
            if semgrep_path:
                try:
                    sast_results = await sast_scanner.scan(source_dir)
                    sast_version = sast_results.get("version", "semgrep 1.0.0")
                    sast_findings = normalize_semgrep_results(
                        sast_results,
                        project_id=project.id,
                        scan_id=self.scan_id,
                        scanner_version=sast_version,
                        target_dir=source_dir,
                    )
                    combined_findings.extend(sast_findings)
                    executed_scanners.append("semgrep")
                    scanner_versions.append(f"semgrep {sast_version}")
                except Exception as sast_err:
                    pass

            # 1b. Secret Detection (detect-secrets)
            scan.current_phase = "Running Secret Detection"
            scan.progress = 25
            self.db.commit()

            try:
                secrets_scanner = DetectSecretsScanner()
                secrets_results = await secrets_scanner.scan(source_dir)
                secrets_version = secrets_results.get("version", "detect-secrets 1.4.0")
                secrets_findings = normalize_detect_secrets_results(
                    secrets_results,
                    project_id=project.id,
                    scan_id=self.scan_id,
                    scanner_version=secrets_version,
                    target_dir=source_dir,
                )
                combined_findings.extend(secrets_findings)
                executed_scanners.append("detect-secrets")
                scanner_versions.append(f"detect-secrets {secrets_version}")
            except Exception as sec_err:
                pass

            # 1c. SCA / Dependency Analysis
            scan.current_phase = "Running Dependency Analysis"
            scan.progress = 35
            self.db.commit()

            try:
                sca_scanner = SCADependencyScanner()
                sca_results = await sca_scanner.scan(source_dir)
                sca_status = sca_results.get("status")
                scan.sca_status = sca_status
                sca_version = sca_results.get("version", "1.0.0")
                sca_findings = normalize_sca_results(
                    sca_results,
                    project_id=project.id,
                    scan_id=self.scan_id,
                    scanner_version=sca_version,
                    target_dir=source_dir,
                )
                combined_findings.extend(sca_findings)
                executed_scanners.append("sca-dependency")
                scanner_versions.append(f"sca-dependency {sca_version}")
            except Exception as sca_err:
                sca_status = "SCANNER_ERROR"
                scan.sca_status = sca_status

        # =====================================================================
        # STAGE 2: Web DAST Scan
        # =====================================================================
        if capabilities["web_dast"]:
            target_url = project.target_url or (project.api_target_url if project.source_type == "WEBSITE" else None)
            if target_url:
                scan.current_phase = "Running DAST Web Scan"
                scan.progress = 50
                self.db.commit()

                dast_scanner = DASTWebScanner()
                try:
                    dast_results = await dast_scanner.scan(target_url)
                    dast_status = dast_results.get("status")
                    scan.dast_status = dast_status
                    dast_version = dast_results.get("version", "1.0.0")
                    dast_findings = normalize_dast_results(
                        dast_results,
                        project_id=project.id,
                        scan_id=self.scan_id,
                        scanner_version=dast_version,
                    )
                    combined_findings.extend(dast_findings)
                    executed_scanners.append("dast-web")
                    scanner_versions.append(f"dast-web {dast_version}")
                except Exception as dast_err:
                    dast_status = DASTStatus.SCANNER_ERROR
                    scan.dast_status = dast_status
            elif project.source_type == "WEBSITE" and not target_url:
                scan.status = ScanStatus.FAILED
                scan.error_message = "Website projects are DAST targets; target URL is missing."
                self.db.commit()
                return

        # =====================================================================
        # STAGE 3: API Security Analysis (Static Spec Audit + API DAST Probes)
        # =====================================================================
        if capabilities["api_security"]:
            project_dir = get_project_dir(project.id)
            spec_file = project_dir / "openapi_spec.raw"

            if project.source_type == "OPENAPI" and not spec_file.exists():
                scan.status = ScanStatus.FAILED
                scan.error_message = "OpenAPI specification source file not found for this project."
                self.db.commit()
                return

            if spec_file.exists():
                scan.current_phase = "Parsing OpenAPI Specification & Static Audit"
                scan.progress = 65
                self.db.commit()

                try:
                    created_endpoints, static_findings = run_static_api_analysis(
                        db=self.db, project_id=project.id, scan_id=self.scan_id
                    )
                    combined_findings.extend(static_findings)
                    executed_scanners.append("api-security")
                    scanner_versions.append("api-security 1.0.0")
                except Exception as static_err:
                    if project.source_type == "OPENAPI":
                        scan.status = ScanStatus.FAILED
                        scan.error_message = f"API security static analysis failed: {str(static_err)}"
                        self.db.commit()
                        return
                    created_endpoints = []

                # Dynamic API DAST Probes
                api_target = project.api_target_url or project.target_url
                if project.api_dast_enabled and api_target:
                    is_safe, ssrf_msg = is_ssrf_safe_url(api_target, allow_localhost=False)
                    if is_safe:
                        scan.current_phase = "Running Dynamic DAST Probes"
                        scan.progress = 75
                        scan.dast_status = "RUNNING"
                        self.db.commit()

                        existing_map = {f.fingerprint: f for f in combined_findings if f.fingerprint}

                        def dast_progress_cb(done_cnt, total_cnt):
                            scan.progress = 75 + int((done_cnt / total_cnt) * 10)
                            self.db.commit()

                        try:
                            dast_probe_findings = run_active_dast_probes(
                                db=self.db,
                                project=project,
                                scan_id=self.scan_id,
                                endpoints=created_endpoints,
                                existing_findings_map=existing_map,
                                progress_callback=dast_progress_cb,
                            )
                            combined_findings.extend(dast_probe_findings)
                            dast_status = "COMPLETED"
                            scan.dast_status = dast_status
                            executed_scanners.append("dast-active-probe")
                            scanner_versions.append("dast-active-probe 1.0.0")
                        except Exception as probe_err:
                            dast_status = "FAILED"
                            scan.dast_status = dast_status
                    else:
                        dast_status = "SKIPPED_SSRF_BLOCKED"
                        scan.dast_status = dast_status
                elif project.api_dast_enabled and not api_target:
                    dast_status = "SKIPPED_NO_TARGET"
                    scan.dast_status = dast_status

        # =====================================================================
        # STAGE 4: Finding Normalization, Deduplication & Triage Preservation
        # =====================================================================
        scan.current_phase = "Parsing findings"
        scan.progress = 85
        self.db.commit()

        # Remove duplicate findings within this scan
        unique_findings: List[Finding] = []
        seen_fingerprints: Set[str] = set()
        for f in combined_findings:
            if f.fingerprint not in seen_fingerprints:
                seen_fingerprints.add(f.fingerprint)
                unique_findings.append(f)

        # Inherit triage status (RESOLVED, FALSE_POSITIVE) from prior scans
        prior_findings = self.db.scalars(
            select(Finding).where(Finding.project_id == project.id, Finding.scan_id != self.scan_id)
        ).all()
        prev_triage_map = {}
        for pf in prior_findings:
            if pf.fingerprint and pf.status in (FindingStatus.RESOLVED, FindingStatus.FALSE_POSITIVE):
                prev_triage_map[pf.fingerprint] = pf

        for f in unique_findings:
            if f.fingerprint in prev_triage_map:
                prev_f = prev_triage_map[f.fingerprint]
                f.status = prev_f.status
                f.resolution_comment = prev_f.resolution_comment
                f.resolved_at = prev_f.resolved_at

        # =====================================================================
        # STAGE 4.5: Cross-Validation & Deterministic Confidence Assessment
        # =====================================================================
        scan.current_phase = "Cross-validating findings & assessing confidence"
        scan.progress = 90
        self.db.commit()

        cv_engine = CrossValidationEngine(db=self.db)
        cv_engine.process_findings(
            project_id=project.id,
            scan_id=self.scan_id,
            findings=unique_findings,
            dast_status=dast_status or scan.dast_status,
            sca_status=sca_status or scan.sca_status,
        )

        # =====================================================================
        # STAGE 5: Saving & Finalizing Scan State
        # =====================================================================
        scan.current_phase = "Saving findings"
        scan.progress = 95
        self.db.commit()

        # Replace findings in database
        self.db.execute(delete(Finding).where(Finding.scan_id == self.scan_id))
        self.db.add_all(unique_findings)

        duration = time.time() - start_time
        scanner_name_str = ", ".join(executed_scanners) if executed_scanners else "none"
        scanner_ver_str = ", ".join(scanner_versions) if scanner_versions else "1.0.0"

        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.utcnow()
        scan.progress = 100
        scan.current_phase = "Completed"
        scan.scanner = scanner_name_str
        scan.scanner_version = scanner_ver_str
        scan.duration = duration
        scan.result_count = len(unique_findings)

        self.db.commit()
