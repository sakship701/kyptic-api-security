export interface FindingApiData {
  id: number;
  project_id: number;
  scan_id: number;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cvss: number;
  category: string;
  file_path: string;
  line_number: number | null;
  status: 'open' | 'resolved' | 'false_positive';
  source: 'sast' | 'dast' | 'greybox' | 'correlation' | 'manual' | 'secrets' | 'sca';
  created_at: string;

  // SAST Specific Evidence & Metadata
  rule_id?: string | null;
  cwe?: string | null;
  owasp?: string | null;
  end_line_number?: number | null;
  code_snippet?: string | null;
  scanner_name?: string | null;
  scanner_version?: string | null;
  // Triage & Lifecycle Metadata
  resolution_comment?: string | null;
  resolved_at?: string | null;
}

export interface FindingSummaryApiData {
  open: number;
  resolved: number;
  false_positive: number;
  total: number;
  new: number;
  recurring: number;
  fixed: number;
}

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '');

const request = async <T>(path: string, options?: RequestInit): Promise<T> => {
  try {
    const response = await fetch(`${API_BASE_URL}${path}`, options);
    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`The Kyptic backend returned an error (${response.status}): ${errText}`);
    }
    return response.json() as Promise<T>;
  } catch (error) {
    if (error instanceof TypeError) {
      throw new Error('The Kyptic backend is unavailable. Start it on http://localhost:8000 and try again.');
    }
    throw error;
  }
};

export const fetchFindings = (severity?: string, status?: string) => {
  const params = new URLSearchParams();
  if (severity) params.append('severity', severity);
  if (status) params.append('finding_status', status);
  const query = params.toString() ? `?${params.toString()}` : '';
  return request<FindingApiData[]>(`/api/findings${query}`);
};

export const fetchFinding = (findingId: string | number) => request<FindingApiData>(`/api/findings/${findingId}`);

export const updateFindingStatus = (
  findingId: string | number,
  status: 'open' | 'resolved' | 'false_positive',
  resolutionComment?: string
) => request<FindingApiData>(`/api/findings/${findingId}`, {
  method: 'PATCH',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    status,
    resolution_comment: resolutionComment || undefined,
  }),
});

export interface GlobalFindingSummaryApiData {
  total: number;
  open: number;
  resolved: number;
  false_positive: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export const fetchGlobalFindingsSummary = () =>
  request<GlobalFindingSummaryApiData>('/api/v1/findings/summary');

export const fetchProjectFindingsSummary = (projectId: number | string) =>
  request<FindingSummaryApiData>(`/api/projects/${projectId}/findings/summary`);