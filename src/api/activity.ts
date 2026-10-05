import { getAuthHeaders } from './auth';

export interface ActivityEventData {
  id: string;
  type: string;
  title: string;
  description: string;
  timestamp: string;
  icon: string;
  status: 'info' | 'success' | 'warning' | 'error' | 'primary';
}

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '');

export const fetchActivityEvents = async (projectId?: number | string, limit = 10): Promise<ActivityEventData[]> => {
  const params = new URLSearchParams();
  if (projectId) params.append('project_id', String(projectId));
  params.append('limit', String(limit));
  const query = params.toString() ? `?${params.toString()}` : '';

  try {
    const response = await fetch(`${API_BASE_URL}/api/activity${query}`, {
      headers: getAuthHeaders(),
      credentials: 'include',
    });
    if (!response.ok) {
      return [];
    }
    return response.json() as Promise<ActivityEventData[]>;
  } catch {
    return [];
  }
};
