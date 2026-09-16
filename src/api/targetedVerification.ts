import type { TargetedVerificationResultApiData } from './findings';

export interface VulnerabilityDefinitionApiData {
  vulnerability_id: string;
  display_name: string;
  vulnerability_family: string;
  aliases: string[];
  owasp?: string | null;
  cwe?: string | null;
  supported_execution_modes: string[];
  probe_type?: string | null;
  registered: boolean;
  implemented: boolean;
  supported: boolean;
  white_box_supported?: boolean;
  black_box_supported?: boolean;
  grey_box_supported?: boolean;
  targeted_verification_supported?: boolean;
  required_target_type: string;
  auth_required: boolean;
  description: string;
  remediation_category?: string | null;
}

export interface StandaloneVerificationRequest {
  target_url: string;
  http_method: string;
  path: string;
  vulnerability_id: string;
  auth_type?: string;
  auth_header_name?: string;
  auth_token?: string;
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

export const fetchVulnerabilities = () =>
  request<VulnerabilityDefinitionApiData[]>('/api/vulnerabilities');

export const runStandaloneTargetedVerification = (data: StandaloneVerificationRequest) =>
  request<TargetedVerificationResultApiData>('/api/targeted-verification', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
