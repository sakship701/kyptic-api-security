from typing import Dict, List, Optional
from sqlalchemy.orm import Session

from app.models.api_endpoint import ApiEndpoint
from app.models.finding import Finding, FindingSeverity
from app.models.project import Project
from app.schemas.risk_map import (
    RiskMapEdge,
    RiskMapGraphResponse,
    RiskMapNode,
    RiskMapNodeDetails,
    RiskMapSummary,
)
from app.services.report_service import calculate_risk_score


class RiskMapService:
    @classmethod
    def generate_graph(
        cls,
        db: Session,
        project_id: int,
        severity_filter: Optional[str] = None,
        verification_status_filter: Optional[str] = None,
        vuln_type_filter: Optional[str] = None,
        min_risk_score: Optional[int] = None,
    ) -> RiskMapGraphResponse:
        project = db.get(Project, project_id)
        if not project:
            raise ValueError(f"Project {project_id} not found")

        # Fetch endpoints and findings for project
        endpoints = db.query(ApiEndpoint).filter(ApiEndpoint.project_id == project_id).all()
        findings_query = db.query(Finding).filter(Finding.project_id == project_id)

        if severity_filter:
            findings_query = findings_query.filter(Finding.severity == severity_filter.lower())
        if verification_status_filter:
            findings_query = findings_query.filter(Finding.verification_status == verification_status_filter.upper())
        if vuln_type_filter:
            findings_query = findings_query.filter(
                (Finding.category.ilike(f"%{vuln_type_filter}%")) | (Finding.cwe.ilike(f"%{vuln_type_filter}%"))
            )

        findings = findings_query.order_by(Finding.created_at.desc()).all()

        if min_risk_score is not None:
            findings = [f for f in findings if (f.cvss or 0) * 10 >= min_risk_score]

        overall_score, overall_grade, counts = calculate_risk_score(findings)

        nodes: List[RiskMapNode] = []
        edges: List[RiskMapEdge] = []
        node_ids_set = set()

        # Layer Column X Positions
        X_PROJECT = 100
        X_API = 350
        X_ENDPOINT = 650
        X_FINDING = 950
        X_VULN_FILE = 1250

        # Layer 1: PROJECT Node
        proj_node_id = f"proj-{project.id}"
        proj_status = "critical" if counts["critical"] > 0 else "warning" if counts["high"] > 0 else "safe"
        nodes.append(
            RiskMapNode(
                id=proj_node_id,
                label=project.name,
                type="PROJECT",
                status=proj_status,
                icon="dns",
                x=X_PROJECT,
                y=370,
                score=overall_score,
                project_id=project.id,
                details=RiskMapNodeDetails(
                    vulnName="Project Root Asset",
                    description=f"Project {project.name}. Overall Grade: {overall_grade}. Total Findings: {len(findings)}.",
                    sastDesc=f"Critical: {counts['critical']}, High: {counts['high']}, Medium: {counts['medium']}",
                    dastDesc=f"Target URL: {project.target_url or project.api_target_url or 'N/A'}",
                ),
            )
        )
        node_ids_set.add(proj_node_id)

        # Layer 2: API / SERVICE Node
        api_node_id = f"api-{project.id}"
        api_label = f"{project.name} API Service"
        nodes.append(
            RiskMapNode(
                id=api_node_id,
                label=api_label,
                type="API",
                status=proj_status,
                icon="cloud",
                x=X_API,
                y=370,
                score=overall_score,
                project_id=project.id,
                details=RiskMapNodeDetails(
                    vulnName="API Gateway Service",
                    description=f"API Service for {project.name}. Tech Stack: {project.technology or 'REST API'}.",
                ),
            )
        )
        node_ids_set.add(api_node_id)
        edges.append(
            RiskMapEdge(
                id=f"edge-proj-api-{project.id}",
                source=proj_node_id,
                target=api_node_id,
                type="PROJECT_API",
                status=proj_status,
            )
        )

        # Layer 3: ENDPOINT Nodes
        endpoint_node_map: Dict[str, str] = {}
        y_endpoint = 150
        if not endpoints:
            # Create synthetic default endpoint node if no OpenAPI spec uploaded yet but findings exist
            endpoints_data = [
                {"id": 0, "method": "POST", "path": "/api/v1/target", "risk_score": overall_score, "risk_level": "HIGH"}
            ]
        else:
            endpoints_data = [
                {"id": ep.id, "method": ep.method, "path": ep.path, "risk_score": ep.risk_score, "risk_level": ep.risk_level}
                for ep in endpoints
            ]

        for ep_idx, ep_data in enumerate(endpoints_data):
            ep_node_id = f"ep-{ep_data['id']}"
            ep_label = f"{ep_data['method']} {ep_data['path']}"
            is_crit = ep_data["risk_level"] in ("CRITICAL", "HIGH")
            ep_status = "critical" if is_crit else "warning" if ep_data["risk_level"] == "MEDIUM" else "safe"
            
            nodes.append(
                RiskMapNode(
                    id=ep_node_id,
                    label=ep_label,
                    type="ENDPOINT",
                    status=ep_status,
                    icon="api",
                    x=X_ENDPOINT,
                    y=y_endpoint,
                    score=ep_data["risk_score"],
                    method=ep_data["method"],
                    path=ep_data["path"],
                    project_id=project.id,
                    details=RiskMapNodeDetails(
                        vulnName=f"Endpoint: {ep_label}",
                        method=ep_data["method"],
                        path=ep_data["path"],
                        cvss=ep_data["risk_score"],
                        description=f"API Endpoint {ep_label}. Risk Level: {ep_data['risk_level']}.",
                    ),
                )
            )
            node_ids_set.add(ep_node_id)
            endpoint_node_map[ep_data["path"]] = ep_node_id
            edges.append(
                RiskMapEdge(
                    id=f"edge-api-ep-{ep_data['id']}",
                    source=api_node_id,
                    target=ep_node_id,
                    type="API_ENDPOINT",
                    status=ep_status,
                )
            )
            y_endpoint += 90

        # Layer 4 & 5: FINDING, VULNERABILITY, and FILE Nodes
        y_finding = 150
        file_nodes_created = set()
        vuln_nodes_created = set()

        for idx, finding in enumerate(findings):
            finding_node_id = f"finding-{finding.id}"
            sev_str = str(finding.severity.value if hasattr(finding.severity, "value") else finding.severity).lower()
            finding_status = "critical" if sev_str in ("critical", "high") else "warning" if sev_str == "medium" else "safe"
            cvss_score = float(finding.cvss) if finding.cvss is not None else 5.0

            nodes.append(
                RiskMapNode(
                    id=finding_node_id,
                    label=finding.title,
                    type="FINDING",
                    status=finding_status,
                    icon="bug_report",
                    x=X_FINDING,
                    y=y_finding,
                    score=cvss_score * 10,
                    severity=sev_str.upper(),
                    confidence_score=finding.confidence_score,
                    confidence_level=finding.confidence_level,
                    verification_status=finding.verification_status,
                    source=finding.source.value if hasattr(finding.source, "value") else finding.source,
                    project_id=project.id,
                    details=RiskMapNodeDetails(
                        vulnName=finding.title,
                        owasp=finding.owasp or "N/A",
                        cwe=finding.cwe or "N/A",
                        cvss=cvss_score,
                        description=finding.description,
                        sastDesc=f"File: {finding.file_path}:{finding.line_number or 'N/A'}. Scanner: {finding.scanner_name or 'Kyptic'}.",
                        sastCode=finding.code_snippet,
                        dastDesc=f"Verification Status: {finding.verification_status}. Confidence: {finding.confidence_score}%.",
                        source_file=finding.file_path,
                        line_number=finding.line_number,
                    ),
                )
            )
            node_ids_set.add(finding_node_id)

            # Link FINDING to matching ENDPOINT or API node
            target_ep_id = None
            if finding.file_path in endpoint_node_map:
                target_ep_id = endpoint_node_map[finding.file_path]
            elif len(endpoint_node_map) > 0:
                # Pick first endpoint
                target_ep_id = list(endpoint_node_map.values())[idx % len(endpoint_node_map)]
            else:
                target_ep_id = api_node_id

            edges.append(
                RiskMapEdge(
                    id=f"edge-ep-finding-{finding.id}",
                    source=target_ep_id,
                    target=finding_node_id,
                    type="ENDPOINT_FINDING",
                    status=finding_status,
                )
            )

            # Layer 5: VULNERABILITY node (CWE/OWASP)
            if finding.cwe and finding.cwe not in vuln_nodes_created:
                vuln_node_id = f"vuln-{finding.cwe}"
                nodes.append(
                    RiskMapNode(
                        id=vuln_node_id,
                        label=f"{finding.cwe}",
                        type="VULNERABILITY",
                        status=finding_status,
                        icon="shield",
                        x=X_VULN_FILE,
                        y=y_finding,
                        score=cvss_score * 10,
                        project_id=project.id,
                        details=RiskMapNodeDetails(
                            vulnName=finding.cwe,
                            owasp=finding.owasp or "N/A",
                            cwe=finding.cwe,
                            description=f"Taxonomy Weakness: {finding.cwe}. OWASP Mapping: {finding.owasp or 'N/A'}.",
                        ),
                    )
                )
                node_ids_set.add(vuln_node_id)
                vuln_nodes_created.add(finding.cwe)

            if finding.cwe:
                edges.append(
                    RiskMapEdge(
                        id=f"edge-finding-vuln-{finding.id}",
                        source=finding_node_id,
                        target=f"vuln-{finding.cwe}",
                        type="FINDING_VULN",
                        status=finding_status,
                    )
                )

            # Layer 5: SOURCE FILE node
            if finding.file_path and finding.file_path not in file_nodes_created:
                file_node_id = f"file-{finding.file_path}"
                nodes.append(
                    RiskMapNode(
                        id=file_node_id,
                        label=finding.file_path.split("/")[-1] or finding.file_path,
                        type="FILE",
                        status=finding_status,
                        icon="code",
                        x=X_VULN_FILE,
                        y=y_finding + 45,
                        score=cvss_score * 10,
                        project_id=project.id,
                        details=RiskMapNodeDetails(
                            vulnName=f"Source File: {finding.file_path}",
                            source_file=finding.file_path,
                            description=f"Source Code Asset: {finding.file_path}.",
                        ),
                    )
                )
                node_ids_set.add(file_node_id)
                file_nodes_created.add(finding.file_path)

            if finding.file_path:
                edges.append(
                    RiskMapEdge(
                        id=f"edge-finding-file-{finding.id}",
                        source=finding_node_id,
                        target=f"file-{finding.file_path}",
                        type="FINDING_FILE",
                        status=finding_status,
                    )
                )

            y_finding += 80

        summary = RiskMapSummary(
            total_nodes=len(nodes),
            total_edges=len(edges),
            critical_findings=counts["critical"],
            high_findings=counts["high"],
            medium_findings=counts["medium"],
            low_findings=counts["low"],
            info_findings=counts["info"],
            overall_risk_score=overall_score,
            overall_risk_grade=overall_grade,
        )

        return RiskMapGraphResponse(
            project_id=project.id,
            project_name=project.name,
            nodes=nodes,
            edges=edges,
            summary=summary,
        )
