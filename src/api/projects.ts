import { getAuthHeaders } from './auth';

export interface ProjectApiData {
  id: number;
  name: string;
  description: string | null;
  repository_url: string | null;
  technology: string | null;
  status: string;
  created_at: string;
  source_type?: string | null;
  source_status?: string;
  local_source_reference?: string | null;
  target_url?: string | null;
  last_ingested_at?: string | null;
  ingestion_error?: string | null;
  score?: number | null;
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  total_findings?: number;
  has_data?: boolean;
}

export interface CreateProjectPayload {
  name: string;
  description: string | null;
  repository_url: string | null;
  technology: string;
  source_type?: string | null;
  target_url?: string | null;
}

export interface ProjectSourceDetails {
  project_id: number;
  source_type: string | null;
  status: string;
  target_url: string | null;
  last_ingested_at: string | null;
  error_message: string | null;
}

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '');

const getErrorMessage = (response: Response) => {
  if (response.status === 0) {
    return 'The Kyptic backend is unavailable. Start it on http://localhost:8000 and try again.';
  }
  if (response.status === 401) {
    return 'Authentication required. Please log in.';
  }
  if (response.status === 403) {
    return 'Access denied. You do not have permission to view this project.';
  }
  return `The Kyptic backend returned an error (${response.status}). Please try again.`;
};

export const fetchProjects = async (): Promise<ProjectApiData[]> => {
  try {
    const response = await fetch(`${API_BASE_URL}/api/projects`, {
      method: 'GET',
      headers: getAuthHeaders(),
      credentials: 'include',
    });
    if (!response.ok) {
      throw new Error(getErrorMessage(response));
    }
    return response.json() as Promise<ProjectApiData[]>;
  } catch (error) {
    if (error instanceof TypeError) {
      throw new Error('The Kyptic backend is unavailable. Start it on http://localhost:8000 and try again.');
    }
    throw error;
  }
};

export const createProject = async (payload: CreateProjectPayload): Promise<ProjectApiData> => {
  try {
    const response = await fetch(`${API_BASE_URL}/api/projects`, {
      method: 'POST',
      headers: getAuthHeaders({ 'Content-Type': 'application/json' }),
      credentials: 'include',
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      throw new Error(getErrorMessage(response));
    }
    return response.json() as Promise<ProjectApiData>;
  } catch (error) {
    if (error instanceof TypeError) {
      throw new Error('The Kyptic backend is unavailable. Start it on http://localhost:8000 and try again.');
    }
    throw error;
  }
};

export const ingestZip = async (projectId: number, file: File): Promise<ProjectApiData> => {
  try {
    const formData = new FormData();
    formData.append('file', file);

    const headers = getAuthHeaders() as Record<string, string>;
    delete headers['Content-Type'];

    const response = await fetch(`${API_BASE_URL}/api/projects/${projectId}/ingest/zip`, {
      method: 'POST',
      headers,
      credentials: 'include',
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
    return response.json() as Promise<ProjectApiData>;
  } catch (error) {
    if (error instanceof TypeError) {
      throw new Error('The Kyptic backend is unavailable. Start it on http://localhost:8000 and try again.');
    }
    throw error;
  }
};

export const ingestGit = async (projectId: number, repositoryUrl: string): Promise<ProjectApiData> => {
  try {
    const response = await fetch(`${API_BASE_URL}/api/projects/${projectId}/ingest/git`, {
      method: 'POST',
      headers: getAuthHeaders({ 'Content-Type': 'application/json' }),
      credentials: 'include',
      body: JSON.stringify({ repository_url: repositoryUrl }),
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
    return response.json() as Promise<ProjectApiData>;
  } catch (error) {
    if (error instanceof TypeError) {
      throw new Error('The Kyptic backend is unavailable. Start it on http://localhost:8000 and try again.');
    }
    throw error;
  }
};

export const ingestWebsite = async (projectId: number, targetUrl: string): Promise<ProjectApiData> => {
  try {
    const response = await fetch(`${API_BASE_URL}/api/projects/${projectId}/ingest/website`, {
      method: 'POST',
      headers: getAuthHeaders({ 'Content-Type': 'application/json' }),
      credentials: 'include',
      body: JSON.stringify({ target_url: targetUrl }),
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
    return response.json() as Promise<ProjectApiData>;
  } catch (error) {
    if (error instanceof TypeError) {
      throw new Error('The Kyptic backend is unavailable. Start it on http://localhost:8000 and try again.');
    }
    throw error;
  }
};

export const ingestOpenApi = async (projectId: number, file: File): Promise<ProjectApiData> => {
  try {
    const formData = new FormData();
    formData.append('file', file);

    const headers = getAuthHeaders() as Record<string, string>;
    delete headers['Content-Type'];

    const response = await fetch(`${API_BASE_URL}/api/projects/${projectId}/ingest/openapi`, {
      method: 'POST',
      headers,
      credentials: 'include',
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
    return response.json() as Promise<ProjectApiData>;
  } catch (error) {
    if (error instanceof TypeError) {
      throw new Error('The Kyptic backend is unavailable. Start it on http://localhost:8000 and try again.');
    }
    throw error;
  }
};

export const fetchProjectSource = async (projectId: number): Promise<ProjectSourceDetails> => {
  try {
    const response = await fetch(`${API_BASE_URL}/api/projects/${projectId}/source`, {
      method: 'GET',
      headers: getAuthHeaders(),
      credentials: 'include',
    });
    if (!response.ok) {
      throw new Error(getErrorMessage(response));
    }
    return response.json() as Promise<ProjectSourceDetails>;
  } catch (error) {
    if (error instanceof TypeError) {
      throw new Error('The Kyptic backend is unavailable. Start it on http://localhost:8000 and try again.');
    }
    throw error;
  }
};

export const fetchProject = async (projectId: number): Promise<ProjectApiData> => {
  try {
    const response = await fetch(`${API_BASE_URL}/api/projects/${projectId}`, {
      method: 'GET',
      headers: getAuthHeaders(),
      credentials: 'include',
    });
    if (!response.ok) {
      throw new Error(getErrorMessage(response));
    }
    return response.json() as Promise<ProjectApiData>;
  } catch (error) {
    if (error instanceof TypeError) {
      throw new Error('The Kyptic backend is unavailable. Start it on http://localhost:8000 and try again.');
    }
    throw error;
  }
};

export interface ProjectPostureData {
  project_id: number | null;
  project_name: string | null;
  score: number | null;
  grade: string;
  counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  total_findings: number;
  has_data: boolean;
}

export const fetchProjectPosture = async (projectId?: string | number): Promise<ProjectPostureData> => {
  try {
    const url = projectId
      ? `${API_BASE_URL}/api/projects/${projectId}/posture`
      : `${API_BASE_URL}/api/projects/global/posture`;
    const response = await fetch(url, {
      method: 'GET',
      headers: getAuthHeaders(),
      credentials: 'include',
    });
    if (!response.ok) {
      throw new Error(getErrorMessage(response));
    }
    return response.json() as Promise<ProjectPostureData>;
  } catch (error) {
    if (error instanceof TypeError) {
      throw new Error('The Kyptic backend is unavailable. Start it on http://localhost:8000 and try again.');
    }
    throw error;
  }
};
