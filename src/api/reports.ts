const API_BASE_URL = 'http://localhost:8000/api/v1';

export interface ReportTemplateApiData {
  id: string;
  key: string;
  title: string;
  subtitle: string;
  description: string;
  category: 'Executive' | 'Technical' | 'Compliance';
  icon: string;
}

export interface ReportGeneratePayload {
  project_id: number;
  report_type: string;
  format: 'pdf' | 'html' | 'json';
}

export const fetchReportTemplates = async (): Promise<ReportTemplateApiData[]> => {
  const response = await fetch(`${API_BASE_URL}/reports/templates`);
  if (!response.ok) {
    throw new Error('Failed to fetch report templates');
  }
  return response.json();
};

export const generateReportJson = async (projectId: number, reportType: string): Promise<any> => {
  const response = await fetch(`${API_BASE_URL}/reports/generate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      project_id: projectId,
      report_type: reportType,
      format: 'json',
    }),
  });

  if (!response.ok) {
    throw new Error('Failed to generate report data');
  }
  return response.json();
};

export const generateReportHtml = async (projectId: number, reportType: string): Promise<string> => {
  const response = await fetch(`${API_BASE_URL}/reports/generate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      project_id: projectId,
      report_type: reportType,
      format: 'html',
    }),
  });

  if (!response.ok) {
    throw new Error('Failed to generate HTML report');
  }
  return response.text();
};

export const downloadReportPdf = async (projectId: number, reportType: string): Promise<void> => {
  const response = await fetch(`${API_BASE_URL}/reports/generate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      project_id: projectId,
      report_type: reportType,
      format: 'pdf',
    }),
  });

  if (!response.ok) {
    throw new Error('Failed to generate PDF report');
  }

  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.style.display = 'none';
  a.href = url;
  a.download = `kyptic_report_proj${projectId}_${reportType}.pdf`;
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(url);
  document.body.removeChild(a);
};
