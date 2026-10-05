export interface User {
  id: number;
  email: string;
  full_name: string | null;
  is_active: boolean;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  user: User;
}

export interface LoginPayload {
  email: string;
  password: string;
}

export interface RegisterPayload {
  email: string;
  password: string;
  full_name?: string;
}

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '');

let authToken: string | null = null;

export const setAuthToken = (token: string | null) => {
  authToken = token;
  if (token) {
    sessionStorage.setItem('kyptic_token', token);
  } else {
    sessionStorage.removeItem('kyptic_token');
  }
};

export const getAuthToken = (): string | null => {
  if (!authToken) {
    authToken = sessionStorage.getItem('kyptic_token');
  }
  return authToken;
};

export const getAuthHeaders = (extraHeaders?: Record<string, string>): HeadersInit => {
  const headers: Record<string, string> = {
    ...extraHeaders,
  };
  const token = getAuthToken();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
};

export const loginUser = async (email: string, password: string): Promise<TokenResponse> => {
  const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ email, password }),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: 'Invalid email or password' }));
    throw new Error(errorData.detail || `Login failed with status ${response.status}`);
  }

  const data: TokenResponse = await response.json();
  setAuthToken(data.access_token);
  return data;
};

export const registerUser = async (email: string, password: string, fullName?: string): Promise<TokenResponse> => {
  const response = await fetch(`${API_BASE_URL}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ email, password, full_name: fullName || null }),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: 'Registration failed' }));
    throw new Error(errorData.detail || `Registration failed with status ${response.status}`);
  }

  const data: TokenResponse = await response.json();
  setAuthToken(data.access_token);
  return data;
};

export const logoutUser = async (): Promise<void> => {
  try {
    await fetch(`${API_BASE_URL}/api/auth/logout`, {
      method: 'POST',
      headers: getAuthHeaders(),
      credentials: 'include',
    });
  } catch (err) {
    console.error('Logout error:', err);
  } finally {
    setAuthToken(null);
  }
};

export const getCurrentUser = async (): Promise<User> => {
  const response = await fetch(`${API_BASE_URL}/api/auth/me`, {
    method: 'GET',
    headers: getAuthHeaders(),
    credentials: 'include',
  });

  if (!response.ok) {
    setAuthToken(null);
    throw new Error(`Authentication required (${response.status})`);
  }

  return response.json();
};
