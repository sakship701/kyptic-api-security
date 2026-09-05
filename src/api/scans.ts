export type ScanStatus = 'queued' | 'running' | 'paused' | 'completed' | 'stopped' | 'failed';

export interface ScanApiData {
  id: number;
  project_id: number;
  status: ScanStatus;
  progress: number;
  current_phase: string;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  error_message: string | null;
  sca_status?: 'SUCCESS' | 'NO_VULNERABILITIES' | 'DATABASE_UNAVAILABLE' | 'SCANNER_ERROR' | 'NO_MANIFESTS' | null;
}

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '');

const request = async <T>(path: string, options?: RequestInit): Promise<T> => {
  try {
    const response = await fetch(`${API_BASE_URL}${path}`, options);
    if (!response.ok) {
      let detail = `The Kyptic backend returned an error (${response.status}).`;
      try {
        const body = await response.json() as { detail?: string };
        detail = body.detail || detail;
      } catch {
        // Keep the status-based message when the response is not JSON.
      }
      throw new Error(detail);
    }
    return response.json() as Promise<T>;
  } catch (error) {
    if (error instanceof TypeError) {
      throw new Error('The Kyptic backend is unavailable. Start it on http://localhost:8000 and try again.');
    }
    throw error;
  }
};

export const createScan = (projectId: string) => request<ScanApiData>('/api/scans', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ project_id: Number(projectId) }),
});

export const fetchScans = () => request<ScanApiData[]>('/api/scans');
export const fetchScan = (scanId: number) => request<ScanApiData>(`/api/scans/${scanId}`);
export const pauseScan = (scanId: number) => request<ScanApiData>(`/api/scans/${scanId}/pause`, { method: 'POST' });
export const resumeScan = (scanId: number) => request<ScanApiData>(`/api/scans/${scanId}/resume`, { method: 'POST' });
export const stopScan = (scanId: number) => request<ScanApiData>(`/api/scans/${scanId}/stop`, { method: 'POST' });