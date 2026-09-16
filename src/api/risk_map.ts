export interface RiskMapNodeDetailsData {
  vulnName?: string | null;
  owasp?: string | null;
  cwe?: string | null;
  cvss?: number | null;
  description?: string | null;
  sastDesc?: string | null;
  sastCode?: string | null;
  dastDesc?: string | null;
  method?: string | null;
  path?: string | null;
  source_file?: string | null;
  line_number?: number | null;
}

export interface RiskMapNodeData {
  id: string;
  label: string;
  type: string;
  status: 'safe' | 'warning' | 'critical' | 'info';
  icon: string;
  x: number;
  y: number;
  score: number;
  severity?: string | null;
  confidence_score?: number | null;
  confidence_level?: string | null;
  verification_status?: string | null;
  source?: string | null;
  project_id: number;
  details?: RiskMapNodeDetailsData | null;
}

export interface RiskMapEdgeData {
  id: string;
  source: string;
  target: string;
  type: string;
  status: 'safe' | 'warning' | 'critical';
  label?: string | null;
}

export interface RiskMapSummaryData {
  total_nodes: number;
  total_edges: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  info_findings: number;
  overall_risk_score: number;
  overall_risk_grade: string;
}

export interface RiskMapGraphResponseData {
  project_id: number;
  project_name: string;
  nodes: RiskMapNodeData[];
  edges: RiskMapEdgeData[];
  summary: RiskMapSummaryData;
}

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '');

export const fetchProjectRiskMap = async (
  projectId: number,
  params?: {
    severity?: string;
    verification_status?: string;
    vulnerability_type?: string;
    min_risk_score?: number;
  }
): Promise<RiskMapGraphResponseData> => {
  const query = new URLSearchParams();
  if (params?.severity) query.append('severity', params.severity);
  if (params?.verification_status) query.append('verification_status', params.verification_status);
  if (params?.vulnerability_type) query.append('vulnerability_type', params.vulnerability_type);
  if (params?.min_risk_score !== undefined) query.append('min_risk_score', String(params.min_risk_score));

  const queryString = query.toString() ? `?${query.toString()}` : '';
  const response = await fetch(`${API_BASE_URL}/api/projects/${projectId}/risk-map${queryString}`);
  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`Failed to load Risk Map (${response.status}): ${errText}`);
  }
  return response.json();
};
