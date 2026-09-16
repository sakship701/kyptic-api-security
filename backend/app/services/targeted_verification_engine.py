import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.api_endpoint import ApiEndpoint
from app.models.finding import Finding, FindingStatus
from app.models.project import Project
from app.schemas.targeted_verification import (
    TargetedVerificationRequest,
    TargetedVerificationResult,
    TargetedVerificationStatus,
)
from app.security.base_verifier import BaseVulnerabilityVerifier
from app.security.verifiers.sqli_verifier import SqlInjectionVerifier
from app.security.verifiers.web_verifiers import (
    CommandInjectionVerifier,
    XssVerifier,
    CsrfVerifier,
    PathTraversalVerifier,
    CorsVerifier,
    SecurityHeadersVerifier,
)
from app.security.vulnerability_registry import VulnerabilityRegistry
from app.services.cross_validation_engine import CrossValidationEngine
from app.services.dast_http_client import DastAuthContext, DastHttpClient, redact_secrets
from app.services.dast_probes import DastProbeEngine, DastVerificationStatus
from app.services.ssrf_protection import is_ssrf_safe_url


@dataclass
class TargetedVerificationContext:
    finding_id: Optional[int]
    project_id: Optional[int]
    endpoint_id: Optional[int]
    target_url: str
    http_method: str
    path: str
    vulnerability_id: str
    vulnerability_family: str
    probe_type: Optional[str]
    hypothesis: str
    source: str
    mapping_confidence: str = "EXACT"
    priority_level: str = "HIGH"


class TargetedVerificationEngine:
    """
    Pluggable & Extensible Targeted Vulnerability Verification Engine for Kyptic.
    Executes exactly ONE vulnerability hypothesis against ONE target endpoint using
    the centralized VulnerabilityRegistry and safe DAST probes.
    """

    _active_verifications_lock = threading.Lock()
    _active_verifications: Set[Tuple[Optional[int], Optional[int], str, str, str]] = set()

    def __init__(self, db: Optional[Session] = None):
        self.db = db
        self.verifiers: Dict[str, BaseVulnerabilityVerifier] = {
            "SQL_INJECTION": SqlInjectionVerifier(),
            "COMMAND_INJECTION": CommandInjectionVerifier(),
            "XSS": XssVerifier(),
            "CSRF": CsrfVerifier(),
            "PATH_TRAVERSAL": PathTraversalVerifier(),
            "CORS_MISCONFIG": CorsVerifier(),
            "SECURITY_HEADERS": SecurityHeadersVerifier(),
        }

    def verify_finding(self, project_id: int, finding_id: int) -> TargetedVerificationResult:
        if not self.db:
            raise ValueError("Database session is required to verify existing finding.")

        finding = self.db.get(Finding, finding_id)
        if not finding or finding.project_id != project_id:
            return TargetedVerificationResult(
                finding_id=finding_id,
                project_id=project_id,
                target_url="UNKNOWN",
                http_method="GET",
                path="UNKNOWN",
                vulnerability_id="UNKNOWN",
                vulnerability_family="UNKNOWN",
                status=TargetedVerificationStatus.INCONCLUSIVE,
                explanation=f"Finding ID {finding_id} was not found or does not belong to Project {project_id}.",
                safe_to_execute=False,
            )

        project = self.db.get(Project, project_id)
        if not project:
            return TargetedVerificationResult(
                finding_id=finding_id,
                project_id=project_id,
                target_url="UNKNOWN",
                http_method="GET",
                path="UNKNOWN",
                vulnerability_id="UNKNOWN",
                vulnerability_family="UNKNOWN",
                status=TargetedVerificationStatus.INCONCLUSIVE,
                explanation=f"Project ID {project_id} not found.",
                safe_to_execute=False,
            )

        # Resolve endpoint from finding or project endpoints
        target_url = project.api_target_url or "http://localhost:8000"
        path = finding.file_path
        method = "GET"

        if path.startswith("API:"):
            parts = path.split(":")
            if len(parts) >= 3:
                method = parts[1].upper()
                path = parts[2]

        ep_id = None
        endpoints = list(self.db.scalars(select(ApiEndpoint).where(ApiEndpoint.project_id == project_id)).all())
        matching_ep = None
        for ep in endpoints:
            if ep.path.lower() == path.lower() and ep.method.upper() == method.upper():
                matching_ep = ep
                ep_id = ep.id
                break

        if not matching_ep and endpoints:
            for ep in endpoints:
                if ep.path.lower() in path.lower() or path.lower() in ep.path.lower():
                    matching_ep = ep
                    ep_id = ep.id
                    break

        if not matching_ep:
            matching_ep = ApiEndpoint(
                id=0,
                project_id=project_id,
                path=path if path.startswith("/") else f"/{path}",
                method=method,
                auth_status="UNKNOWN",
                risk_level="HIGH",
            )

        # Resolve vulnerability from registry
        vuln_def = VulnerabilityRegistry.get_vulnerability(finding.category) or VulnerabilityRegistry.get_vulnerability(finding.title)
        if not vuln_def:
            # Fallback heuristic mapping
            title_upper = (finding.title or "").upper() + " " + (finding.category or "").upper()
            if "BOLA" in title_upper or "IDOR" in title_upper or "API1" in title_upper:
                vuln_def = VulnerabilityRegistry.get_vulnerability("BOLA")
            elif "AUTH" in title_upper or "API2" in title_upper:
                vuln_def = VulnerabilityRegistry.get_vulnerability("BROKEN_AUTH")
            elif "MASS ASSIGNMENT" in title_upper or "API6" in title_upper:
                vuln_def = VulnerabilityRegistry.get_vulnerability("MASS_ASSIGNMENT")
            elif "RATE LIMIT" in title_upper or "API4" in title_upper:
                vuln_def = VulnerabilityRegistry.get_vulnerability("RATE_LIMIT")

        vuln_id = vuln_def.vulnerability_id if vuln_def else (finding.category or "GENERAL_SECURITY")

        ctx = TargetedVerificationContext(
            finding_id=finding_id,
            project_id=project_id,
            endpoint_id=ep_id,
            target_url=target_url,
            http_method=matching_ep.method,
            path=matching_ep.path,
            vulnerability_id=vuln_id,
            vulnerability_family=vuln_def.vulnerability_family if vuln_def else "GENERAL_SECURITY",
            probe_type=vuln_def.probe_type if vuln_def else None,
            hypothesis=f"Verify if finding '{finding.title}' on {matching_ep.method} {matching_ep.path} is vulnerable to {vuln_id}.",
            source="EXISTING_FINDING",
        )

        auth_ctx = DastAuthContext(
            auth_type=project.api_auth_type or "NONE",
            header_name=project.api_auth_header_name or "Authorization",
        )

        res = self.execute_targeted_verification(ctx, endpoint_model=matching_ep, auth_context=auth_ctx)

        # Phase 2 Integration & Finding Metadata Update (preserve user triage)
        if finding.status not in (FindingStatus.RESOLVED, FindingStatus.FALSE_POSITIVE):
            if res.status == TargetedVerificationStatus.CONFIRMED:
                finding.verification_status = "VERIFIED_VULNERABLE"
                finding.verification_explanation = f"Targeted verification confirmed vulnerability: {res.explanation}"
                if not finding.evidence_sources or "DYNAMIC_PROBE" not in finding.evidence_sources:
                    finding.evidence_sources = f"{finding.evidence_sources}, DYNAMIC_PROBE" if finding.evidence_sources else "DYNAMIC_PROBE"
            elif res.status == TargetedVerificationStatus.NOT_CONFIRMED:
                finding.verification_status = "VERIFIED_SECURE"
                finding.verification_explanation = f"Targeted verification tested hypothesis and found target secure: {res.explanation}"
            elif res.status == TargetedVerificationStatus.INCONCLUSIVE:
                finding.verification_status = "INCONCLUSIVE"
                finding.verification_explanation = f"Targeted verification inconclusive: {res.explanation}"
            self.db.commit()

        return res

    def verify_standalone(self, req: TargetedVerificationRequest) -> TargetedVerificationResult:
        vuln_def = VulnerabilityRegistry.get_vulnerability(req.vulnerability_id)
        vuln_id = vuln_def.vulnerability_id if vuln_def else req.vulnerability_id.upper()
        family = vuln_def.vulnerability_family if vuln_def else "GENERAL_SECURITY"
        probe_type = vuln_def.probe_type if vuln_def else None

        ctx = TargetedVerificationContext(
            finding_id=None,
            project_id=None,
            endpoint_id=None,
            target_url=req.target_url,
            http_method=req.http_method.upper(),
            path=req.path if req.path.startswith("/") else f"/{req.path}",
            vulnerability_id=vuln_id,
            vulnerability_family=family,
            probe_type=probe_type,
            hypothesis=f"Standalone verification of hypothesis {vuln_id} against {req.http_method.upper()} {req.path}.",
            source="STANDALONE",
        )

        ep_model = ApiEndpoint(
            id=0,
            project_id=0,
            path=ctx.path,
            method=ctx.http_method,
            auth_status="AUTHENTICATED" if req.auth_type and req.auth_type != "NONE" else "UNAUTHENTICATED",
            risk_level="HIGH",
        )

        secrets = [req.auth_token] if req.auth_token else []
        auth_ctx = DastAuthContext(
            auth_type=req.auth_type or "NONE",
            header_name=req.auth_header_name or "Authorization",
            token_or_key=req.auth_token,
        )

        return self.execute_targeted_verification(ctx, endpoint_model=ep_model, auth_context=auth_ctx)

    def execute_targeted_verification(
        self,
        ctx: TargetedVerificationContext,
        endpoint_model: ApiEndpoint,
        auth_context: DastAuthContext,
    ) -> TargetedVerificationResult:
        # 1. Validate Vulnerability Support via Registry
        vuln_def = VulnerabilityRegistry.get_vulnerability(ctx.vulnerability_id)
        if not vuln_def or not vuln_def.supported or not vuln_def.implemented or not vuln_def.probe_type:
            return TargetedVerificationResult(
                finding_id=ctx.finding_id,
                project_id=ctx.project_id,
                endpoint_id=ctx.endpoint_id,
                target_url=ctx.target_url,
                http_method=ctx.http_method,
                path=ctx.path,
                vulnerability_id=ctx.vulnerability_id,
                vulnerability_family=ctx.vulnerability_family,
                probe_type=ctx.probe_type,
                status=TargetedVerificationStatus.NOT_SUPPORTED,
                explanation=f"Targeted dynamic verification for vulnerability '{ctx.vulnerability_id}' is not currently implemented.",
                safe_to_execute=True,
            )

        # 2. Safety Controls: SSRF & Loopback Protection
        is_safe, ssrf_reason = is_ssrf_safe_url(ctx.target_url, allow_localhost=False)
        if not is_safe:
            return TargetedVerificationResult(
                finding_id=ctx.finding_id,
                project_id=ctx.project_id,
                endpoint_id=ctx.endpoint_id,
                target_url=ctx.target_url,
                http_method=ctx.http_method,
                path=ctx.path,
                vulnerability_id=ctx.vulnerability_id,
                vulnerability_family=ctx.vulnerability_family,
                probe_type=ctx.probe_type,
                status=TargetedVerificationStatus.INCONCLUSIVE,
                explanation=f"Target URL '{ctx.target_url}' failed security validation ({ssrf_reason}). Verification aborted.",
                safe_to_execute=False,
            )

        # 3. Concurrent Execution Guard
        lock_key = (ctx.project_id, ctx.finding_id, ctx.target_url, ctx.path, ctx.vulnerability_id)
        with self._active_verifications_lock:
            if lock_key in self._active_verifications:
                return TargetedVerificationResult(
                    finding_id=ctx.finding_id,
                    project_id=ctx.project_id,
                    endpoint_id=ctx.endpoint_id,
                    target_url=ctx.target_url,
                    http_method=ctx.http_method,
                    path=ctx.path,
                    vulnerability_id=ctx.vulnerability_id,
                    vulnerability_family=ctx.vulnerability_family,
                    probe_type=ctx.probe_type,
                    status=TargetedVerificationStatus.INCONCLUSIVE,
                    explanation="A targeted verification for this exact target and vulnerability hypothesis is already in progress.",
                    safe_to_execute=True,
                )
            self._active_verifications.add(lock_key)

        try:
            # 4. Instantiate Probe Engine & Execute ONLY the target probe
            client = DastHttpClient(allow_localhost=False)
            engine = DastProbeEngine(client=client, base_url=ctx.target_url, auth_context=auth_context)

            probe_type = vuln_def.probe_type
            probe_res = None

            if probe_type in self.verifiers:
                verifier = self.verifiers[probe_type]
                probe_res = verifier.verify(
                    endpoint=endpoint_model,
                    client=client,
                    base_url=ctx.target_url,
                    auth_context=auth_context,
                )
            elif ctx.vulnerability_id in self.verifiers:
                verifier = self.verifiers[ctx.vulnerability_id]
                probe_res = verifier.verify(
                    endpoint=endpoint_model,
                    client=client,
                    base_url=ctx.target_url,
                    auth_context=auth_context,
                )
            elif probe_type == "BOLA":
                probe_res = engine.probe_bola(endpoint_model)
            elif probe_type == "AUTH_ENFORCEMENT":
                probe_res = engine.probe_auth_enforcement(endpoint_model)
            elif probe_type == "MASS_ASSIGNMENT":
                probe_res = engine.probe_mass_assignment(endpoint_model)
            elif probe_type == "RATE_LIMITING":
                probe_res = engine.probe_rate_limiting(endpoint_model)

            if not probe_res:
                return TargetedVerificationResult(
                    finding_id=ctx.finding_id,
                    project_id=ctx.project_id,
                    endpoint_id=ctx.endpoint_id,
                    target_url=ctx.target_url,
                    http_method=ctx.http_method,
                    path=ctx.path,
                    vulnerability_id=ctx.vulnerability_id,
                    vulnerability_family=ctx.vulnerability_family,
                    probe_type=probe_type,
                    status=TargetedVerificationStatus.INCONCLUSIVE,
                    explanation="Probe execution returned empty result.",
                    safe_to_execute=True,
                )

            # 5. Classify Probe Result strictly according to Phase 4 rules
            if probe_res.status == DastVerificationStatus.VERIFIED_VULNERABLE:
                status = TargetedVerificationStatus.CONFIRMED
                expl = probe_res.evidence or f"Targeted probe confirmed {ctx.vulnerability_id} vulnerability."
            elif probe_res.status == DastVerificationStatus.VERIFIED_SECURE:
                status = TargetedVerificationStatus.NOT_CONFIRMED
                expl = probe_res.evidence or f"Targeted probe verified target is secure against {ctx.vulnerability_id}."
            else:
                status = TargetedVerificationStatus.INCONCLUSIVE
                expl = probe_res.evidence or f"Targeted probe yielded inconclusive results for {ctx.vulnerability_id}."

            obs = []
            if probe_res.response_status:
                obs.append({
                    "status_code": probe_res.response_status,
                    "headers": probe_res.response_headers,
                    "body_snippet": probe_res.response_snippet,
                })

            redacted_evidence = redact_secrets(expl, auth_context.get_secrets_to_redact())

            return TargetedVerificationResult(
                finding_id=ctx.finding_id,
                project_id=ctx.project_id,
                endpoint_id=ctx.endpoint_id,
                target_url=ctx.target_url,
                http_method=ctx.http_method,
                path=ctx.path,
                vulnerability_id=ctx.vulnerability_id,
                vulnerability_family=ctx.vulnerability_family,
                probe_type=probe_type,
                status=status,
                explanation=redacted_evidence,
                evidence=redacted_evidence,
                requests_attempted=len(obs) or 1,
                responses_observed=obs,
                safe_to_execute=True,
                execution_metadata={
                    "hypothesis": ctx.hypothesis,
                    "source": ctx.source,
                    "probe_confidence": probe_res.confidence,
                },
            )
        finally:
            with self._active_verifications_lock:
                self._active_verifications.discard(lock_key)
