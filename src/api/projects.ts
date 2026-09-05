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
  return `The Kyptic backend returned an error (${response.status}). Please try again.`;
};

export const fetchProjects = async (): Promise<ProjectApiData[]> => {
  try {
    const response = await fetch(`${API_BASE_URL}/api/projects`);
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
      headers: { 'Content-Type': 'application/json' },
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

    const response = await fetch(`${API_BASE_URL}/api/projects/${projectId}/ingest/zip`, {
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
      headers: { 'Content-Type': 'application/json' },
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
      headers: { 'Content-Type': 'application/json' },
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

export const fetchProjectSource = async (projectId: number): Promise<ProjectSourceDetails> => {
  try {
    const response = await fetch(`${API_BASE_URL}/api/projects/${projectId}/source`);
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