export interface ApiEndpointData {
  id: number;
  project_id: number;
  path: string;
  method: string;
  summary: string | null;
  operation_id: string | null;
  auth_status: string;
  auth_type: string | null;
  rate_limit_status: string;
  request_validation_status: string;
  sensitive_data_fields: string | null;
  bola_status?: string | null;
  mass_assignment_status?: string | null;
  risk_score: number;
  risk_level: string;
  discovered_via: string;
  created_at: string;
  updated_at: string;
}

export interface ApiSecuritySummaryData {
  total_endpoints: number;
  critical_endpoints: number;
  high_endpoints: number;
  medium_endpoints: number;
  low_endpoints: number;
  info_endpoints: number;
  unauthenticated_endpoints: number;
  sensitive_data_endpoints: number;
  unconstrained_validation_endpoints: number;
  bola_risk_endpoints?: number;
  mass_assignment_endpoints?: number;
  missing_rate_limit_endpoints?: number;
  total_api_findings: number;
  open_api_findings: number;
}

export interface OpenApiIngestResponseData {
  project_id: number;
  source_type: string;
  status: string;
  endpoints_count: number;
  message: string;
}

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '');

const getErrorMessage = (response: Response) => {
  if (response.status === 0) {
    return 'The Kyptic backend is unavailable. Start it on http://localhost:8000 and try again.';
  }
  return `The Kyptic backend returned an error (${response.status}). Please try again.`;
};

export const ingestOpenApi = async (projectId: number, file: File): Promise<OpenApiIngestResponseData> => {
  const formData = new FormData();
  formData.append('file', file);

  const response = await fetch(`${API_BASE_URL}/api/projects/${projectId}/ingest/openapi`, {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    const errorText = await response.text();
    try {
      const errorJson = JSON.parse(errorText);
      throw new Error(errorJson.detail || getErrorMessage(response));
    } catch {
      throw new Error(errorText || getErrorMessage(response));
    }
  }

  return response.json() as Promise<OpenApiIngestResponseData>;
};

export const analyzeApiSecurity = async (projectId: number): Promise<any> => {
  const response = await fetch(`${API_BASE_URL}/api/projects/${projectId}/api-security/analyze`, {
    method: 'POST',
  });

  if (!response.ok) {
    const errorText = await response.text();
    try {
      const errorJson = JSON.parse(errorText);
      throw new Error(errorJson.detail || getErrorMessage(response));
    } catch {
      throw new Error(errorText || getErrorMessage(response));
    }
  }

  return response.json();
};

export const fetchApiEndpoints = async (projectId: number): Promise<ApiEndpointData[]> => {
  const response = await fetch(`${API_BASE_URL}/api/projects/${projectId}/api-security/endpoints`);
  if (!response.ok) {
    throw new Error(getErrorMessage(response));
  }
  return response.json() as Promise<ApiEndpointData[]>;
};

export const fetchApiEndpointDetail = async (projectId: number, endpointId: number): Promise<ApiEndpointData> => {
  const response = await fetch(`${API_BASE_URL}/api/projects/${projectId}/api-security/endpoints/${endpointId}`);
  if (!response.ok) {
    throw new Error(getErrorMessage(response));
  }
  return response.json() as Promise<ApiEndpointData>;
};

export const fetchApiSecuritySummary = async (projectId: number): Promise<ApiSecuritySummaryData> => {
  const response = await fetch(`${API_BASE_URL}/api/projects/${projectId}/api-security/summary`);
  if (!response.ok) {
    throw new Error(getErrorMessage(response));
  }
  return response.json() as Promise<ApiSecuritySummaryData>;
};
