export interface ControlMappedFindingData {
  finding_id: number;
  title: string;
  severity: string;
  cwe?: string | null;
  owasp?: string | null;
  verification_status: string;
  confidence_score: number;
  file_path: string;
}

export interface ComplianceControlData {
  control_id: string;
  control_name: string;
  framework: string;
  description: string;
  status: 'AFFECTED' | 'NOT_AFFECTED' | 'INSUFFICIENT_EVIDENCE' | 'NO_DIRECT_MAPPING';
  affected_findings_count: number;
  mapped_findings: ControlMappedFindingData[];
  evidence_summary: string;
  remediation_reference: string;
}

export interface ComplianceFrameworkSummaryData {
  framework: string;
  framework_name: string;
  total_controls: number;
  affected_controls: number;
  unaffected_controls: number;
  insufficient_evidence_controls: number;
  total_mapped_findings: number;
  coverage_percentage: number;
  disclaimer: string;
}

export interface ComplianceResponseData {
  project_id: number;
  project_name: string;
  framework: string;
  summary: ComplianceFrameworkSummaryData;
  controls: ComplianceControlData[];
}

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '');

export const fetchProjectCompliance = async (
  projectId: number,
  framework: string = 'PCI_DSS'
): Promise<ComplianceResponseData> => {
  const query = new URLSearchParams({ framework });
  const response = await fetch(`${API_BASE_URL}/api/projects/${projectId}/compliance?${query.toString()}`);
  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`Failed to load Compliance data (${response.status}): ${errText}`);
  }
  return response.json();
};
