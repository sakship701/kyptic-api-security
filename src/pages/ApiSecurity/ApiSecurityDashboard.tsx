import React, { useEffect, useState } from 'react';
import { useApp } from '../../context/AppContext';
import GlassPanel from '../../components/ui/GlassPanel';
import Badge from '../../components/ui/Badge';
import Button from '../../components/ui/Button';
import {
  fetchApiEndpoints,
  fetchApiSecuritySummary,
  ingestOpenApi,
  analyzeApiSecurity,
  type ApiEndpointData,
  type ApiSecuritySummaryData,
} from '../../api/api_security';

export const ApiSecurityDashboard: React.FC = () => {
  const { projects, activeProjectId, setActiveProjectId } = useApp();

  const [summary, setSummary] = useState<ApiSecuritySummaryData | null>(null);
  const [endpoints, setEndpoints] = useState<ApiEndpointData[]>([]);
  const [selectedEndpoint, setSelectedEndpoint] = useState<ApiEndpointData | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Upload modal state
  const [isUploadOpen, setIsUploadOpen] = useState<boolean>(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState<boolean>(false);

  // Filters
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedMethod, setSelectedMethod] = useState<string>('ALL');
  const [selectedAuthFilter, setSelectedAuthFilter] = useState<string>('ALL');
  const [selectedRiskFilter, setSelectedRiskFilter] = useState<string>('ALL');

  const activeNumId = activeProjectId ? Number(activeProjectId) : 0;

  const loadApiData = async (projId: number) => {
    if (!projId) return;
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const [summaryRes, endpointsRes] = await Promise.all([
        fetchApiSecuritySummary(projId).catch(() => null),
        fetchApiEndpoints(projId).catch(() => []),
      ]);
      setSummary(summaryRes);
      setEndpoints(endpointsRes);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to load API security data.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (activeNumId) {
      void loadApiData(activeNumId);
    }
  }, [activeProjectId]);

  const handleIngestOpenApi = async () => {
    if (!activeNumId || !selectedFile) return;
    setIsUploading(true);
    setErrorMsg(null);
    setSuccessMsg(null);
    try {
      const res = await ingestOpenApi(activeNumId, selectedFile);
      setSuccessMsg(res.message);
      setIsUploadOpen(false);
      setSelectedFile(null);
      await loadApiData(activeNumId);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to ingest OpenAPI spec.');
    } finally {
      setIsUploading(false);
    }
  };

  const handleRunAnalysis = async () => {
    if (!activeNumId) return;
    setIsAnalyzing(true);
    setErrorMsg(null);
    setSuccessMsg(null);
    try {
      await analyzeApiSecurity(activeNumId);
      setSuccessMsg('API security analysis completed successfully.');
      await loadApiData(activeNumId);
    } catch (err: any) {
      setErrorMsg(err.message || 'API security analysis failed.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  // Filter endpoints
  const filteredEndpoints = endpoints.filter((ep) => {
    const matchesPath = ep.path.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (ep.summary && ep.summary.toLowerCase().includes(searchQuery.toLowerCase()));
    const matchesMethod = selectedMethod === 'ALL' || ep.method.toUpperCase() === selectedMethod;
    const matchesAuth = selectedAuthFilter === 'ALL' ||
      (selectedAuthFilter === 'UNAUTHENTICATED' && ep.auth_status === 'UNAUTHENTICATED') ||
      (selectedAuthFilter === 'AUTHENTICATED' && ep.auth_status === 'AUTHENTICATED');
    const matchesRisk = selectedRiskFilter === 'ALL' || ep.risk_level === selectedRiskFilter;

    return matchesPath && matchesMethod && matchesAuth && matchesRisk;
  });

  const getMethodBadgeVariant = (method: string): 'critical' | 'high' | 'medium' | 'low' | 'primary' | 'success' | 'neutral' => {
    switch (method.toUpperCase()) {
      case 'GET': return 'low';
      case 'POST': return 'primary';
      case 'PUT': return 'medium';
      case 'DELETE': return 'critical';
      case 'PATCH': return 'high';
      default: return 'neutral';
    }
  };


  const getRiskBadgeVariant = (level: string): 'critical' | 'high' | 'medium' | 'low' | 'neutral' => {
    switch (level.toUpperCase()) {
      case 'CRITICAL': return 'critical';
      case 'HIGH': return 'high';
      case 'MEDIUM': return 'medium';
      case 'LOW': return 'low';
      default: return 'neutral';
    }
  };

  return (
    <div className="p-4 md:p-container-padding max-w-[1600px] mx-auto w-full flex flex-col gap-stack-lg pb-24 text-on-surface">
      {/* Header & Controls */}
      <GlassPanel variant="low" className="p-8 rounded-2xl relative overflow-hidden bg-gradient-to-br from-[#11151D]/80 to-[#0f2438]/50 border-l-4 border-l-primary">
        <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-6 relative z-10">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <span className="material-symbols-outlined text-primary text-3xl">api</span>
              <h1 className="font-display-lg text-[32px] text-white">API Security Decision Dashboard</h1>
              <Badge variant="primary">Milestone 1</Badge>
            </div>
            <p className="text-on-surface-variant text-body-md max-w-3xl">
              Automated API endpoint discovery, OpenAPI specification analysis, authentication weakness detection, and excessive data exposure auditing.
            </p>
          </div>

          {/* Action Bar */}
          <div className="flex flex-wrap items-center gap-4">
            {/* Project Selector */}
            <div className="flex items-center gap-2 bg-surface-container-high px-4 py-2 rounded-xl border border-outline-variant">
              <span className="material-symbols-outlined text-on-surface-variant text-sm">folder</span>
              <select
                value={activeProjectId || ''}
                onChange={(e) => setActiveProjectId(e.target.value)}
                className="bg-transparent text-white font-medium focus:outline-none cursor-pointer"
              >
                {projects.map((p) => (
                  <option key={p.id} value={p.id} className="bg-surface-container text-white">
                    {p.name} ({p.sourceType || 'No Source'})
                  </option>
                ))}
              </select>
            </div>

            <Button
              variant="secondary"
              onClick={() => setIsUploadOpen(true)}
              className="flex items-center gap-2"
            >
              <span className="material-symbols-outlined text-sm">upload_file</span>
              Ingest OpenAPI Spec
            </Button>

            <Button
              variant="primary"
              onClick={handleRunAnalysis}
              disabled={isAnalyzing || !activeNumId}
              className="flex items-center gap-2"
            >
              <span className={`material-symbols-outlined text-sm ${isAnalyzing ? 'animate-spin' : ''}`}>
                {isAnalyzing ? 'sync' : 'security'}
              </span>
              {isAnalyzing ? 'Analyzing API...' : 'Run API Analysis'}
            </Button>
          </div>
        </div>
      </GlassPanel>

      {/* Messages */}
      {errorMsg && (
        <div className="p-4 rounded-xl bg-error/10 border border-error/30 text-error flex items-center gap-3">
          <span className="material-symbols-outlined text-xl">error</span>
          <span>{errorMsg}</span>
        </div>
      )}

      {successMsg && (
        <div className="p-4 rounded-xl bg-success/10 border border-success/30 text-success flex items-center gap-3">
          <span className="material-symbols-outlined text-xl">check_circle</span>
          <span>{successMsg}</span>
        </div>
      )}

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        <GlassPanel variant="high" className="p-6 rounded-xl flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
            <span className="material-symbols-outlined text-2xl">grid_view</span>
          </div>
          <div>
            <div className="text-display-md text-3xl font-bold text-white">{summary?.total_endpoints ?? 0}</div>
            <div className="text-on-surface-variant text-sm font-medium">Total API Endpoints</div>
          </div>
        </GlassPanel>

        <GlassPanel variant="high" className="p-6 rounded-xl flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-error/10 border border-error/20 flex items-center justify-center text-error">
            <span className="material-symbols-outlined text-2xl">warning</span>
          </div>
          <div>
            <div className="text-display-md text-3xl font-bold text-error">
              {(summary?.critical_endpoints ?? 0) + (summary?.high_endpoints ?? 0)}
            </div>
            <div className="text-on-surface-variant text-sm font-medium">High / Critical Risk Routes</div>
          </div>
        </GlassPanel>

        <GlassPanel variant="high" className="p-6 rounded-xl flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-warning/10 border border-warning/20 flex items-center justify-center text-warning">
            <span className="material-symbols-outlined text-2xl">lock_open</span>
          </div>
          <div>
            <div className="text-display-md text-3xl font-bold text-warning">{summary?.unauthenticated_endpoints ?? 0}</div>
            <div className="text-on-surface-variant text-sm font-medium">Missing Authentication</div>
          </div>
        </GlassPanel>

        <GlassPanel variant="high" className="p-6 rounded-xl flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-tertiary/10 border border-tertiary/20 flex items-center justify-center text-tertiary">
            <span className="material-symbols-outlined text-2xl">visibility</span>
          </div>
          <div>
            <div className="text-display-md text-3xl font-bold text-tertiary">{summary?.sensitive_data_endpoints ?? 0}</div>
            <div className="text-on-surface-variant text-sm font-medium">Sensitive Data Exposures</div>
          </div>
        </GlassPanel>
      </div>

      {/* Filter & Search Toolbar */}
      <GlassPanel variant="low" className="p-6 rounded-xl flex flex-col md:flex-row gap-4 justify-between items-center">
        <div className="flex flex-wrap items-center gap-3 w-full md:w-auto">
          {/* Search Box */}
          <div className="relative flex-1 md:w-80">
            <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant text-sm">search</span>
            <input
              type="text"
              placeholder="Search path or summary..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-surface-container-high pl-9 pr-4 py-2 rounded-lg border border-outline-variant/60 text-white placeholder-on-surface-variant text-sm focus:outline-none focus:border-primary"
            />
          </div>

          {/* HTTP Method Filter */}
          <select
            value={selectedMethod}
            onChange={(e) => setSelectedMethod(e.target.value)}
            className="bg-surface-container-high text-white px-3 py-2 rounded-lg border border-outline-variant/60 text-sm focus:outline-none cursor-pointer"
          >
            <option value="ALL">All Methods</option>
            <option value="GET">GET</option>
            <option value="POST">POST</option>
            <option value="PUT">PUT</option>
            <option value="DELETE">DELETE</option>
            <option value="PATCH">PATCH</option>
          </select>

          {/* Auth Filter */}
          <select
            value={selectedAuthFilter}
            onChange={(e) => setSelectedAuthFilter(e.target.value)}
            className="bg-surface-container-high text-white px-3 py-2 rounded-lg border border-outline-variant/60 text-sm focus:outline-none cursor-pointer"
          >
            <option value="ALL">All Auth States</option>
            <option value="UNAUTHENTICATED">Unauthenticated</option>
            <option value="AUTHENTICATED">Authenticated</option>
          </select>

          {/* Risk Level Filter */}
          <select
            value={selectedRiskFilter}
            onChange={(e) => setSelectedRiskFilter(e.target.value)}
            className="bg-surface-container-high text-white px-3 py-2 rounded-lg border border-outline-variant/60 text-sm focus:outline-none cursor-pointer"
          >
            <option value="ALL">All Risk Levels</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>
        </div>

        <div className="text-on-surface-variant text-sm font-medium self-end md:self-auto">
          Showing <strong className="text-white">{filteredEndpoints.length}</strong> of {endpoints.length} endpoints
        </div>
      </GlassPanel>

      {/* Endpoint Inventory Table */}
      <GlassPanel variant="high" className="rounded-xl overflow-hidden border border-outline-variant/40">
        {isLoading ? (
          <div className="p-12 text-center text-on-surface-variant flex flex-col items-center gap-3">
            <span className="material-symbols-outlined text-4xl animate-spin text-primary">sync</span>
            <span>Loading API Endpoint Inventory...</span>
          </div>
        ) : filteredEndpoints.length === 0 ? (
          <div className="p-12 text-center text-on-surface-variant flex flex-col items-center gap-3">
            <span className="material-symbols-outlined text-4xl text-outline">find_in_page</span>
            <span className="text-lg font-medium text-white">No API Endpoints Found</span>
            <p className="text-sm max-w-md">
              Ingest an OpenAPI specification (JSON/YAML) or run an API security analysis to discover endpoints.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-sm">
              <thead>
                <tr className="bg-surface-container-low border-b border-outline-variant/60 text-on-surface-variant font-medium">
                  <th className="p-4 pl-6">Method</th>
                  <th className="p-4">Endpoint Path</th>
                  <th className="p-4">Auth Requirement</th>
                  <th className="p-4">Input Validation</th>
                  <th className="p-4">Sensitive Fields Exposed</th>
                  <th className="p-4">Risk Score</th>
                  <th className="p-4 pr-6 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-outline-variant/30 text-on-surface">
                {filteredEndpoints.map((ep) => (
                  <tr
                    key={ep.id}
                    onClick={() => setSelectedEndpoint(ep)}
                    className="hover:bg-surface-container-high/60 cursor-pointer transition-colors"
                  >
                    {/* Method */}
                    <td className="p-4 pl-6 font-mono font-bold">
                      <Badge variant={getMethodBadgeVariant(ep.method)}>
                        {ep.method}
                      </Badge>
                    </td>

                    {/* Path & Summary */}
                    <td className="p-4">
                      <div className="font-mono text-white font-semibold">{ep.path}</div>
                      {ep.summary && <div className="text-xs text-on-surface-variant truncate max-w-xs">{ep.summary}</div>}
                    </td>

                    {/* Auth Status */}
                    <td className="p-4">
                      {ep.auth_status === 'UNAUTHENTICATED' ? (
                        <span className="inline-flex items-center gap-1.5 text-xs text-error font-medium bg-error/10 px-2.5 py-1 rounded-full border border-error/30">
                          <span className="material-symbols-outlined text-xs">lock_open</span>
                          Unauthenticated
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-xs text-success font-medium bg-success/10 px-2.5 py-1 rounded-full border border-success/30">
                          <span className="material-symbols-outlined text-xs">lock</span>
                          {ep.auth_type || 'Authenticated'}
                        </span>
                      )}
                    </td>

                    {/* Input Validation */}
                    <td className="p-4">
                      {ep.request_validation_status === 'UNCONSTRAINED' ? (
                        <span className="text-xs text-warning bg-warning/10 px-2.5 py-1 rounded-full border border-warning/30">
                          Unconstrained
                        </span>
                      ) : (
                        <span className="text-xs text-on-surface-variant bg-surface-container px-2.5 py-1 rounded-full">
                          Validated
                        </span>
                      )}
                    </td>

                    {/* Sensitive Fields */}
                    <td className="p-4">
                      {ep.sensitive_data_fields ? (
                        <span className="text-xs text-tertiary font-mono bg-tertiary/10 px-2.5 py-1 rounded-md border border-tertiary/30 truncate max-w-xs inline-block">
                          {ep.sensitive_data_fields}
                        </span>
                      ) : (
                        <span className="text-xs text-outline font-mono">None</span>
                      )}
                    </td>

                    {/* Risk Score */}
                    <td className="p-4">
                      <div className="flex items-center gap-3">
                        <div className="w-16 bg-surface-container rounded-full h-2 overflow-hidden">
                          <div
                            className={`h-full ${
                              ep.risk_score >= 75
                                ? 'bg-error'
                                : ep.risk_score >= 50
                                ? 'bg-error/80'
                                : ep.risk_score >= 25
                                ? 'bg-warning'
                                : 'bg-success'
                            }`}
                            style={{ width: `${Math.max(5, ep.risk_score)}%` }}
                          />
                        </div>
                        <Badge variant={getRiskBadgeVariant(ep.risk_level)}>
                          {ep.risk_score} ({ep.risk_level})
                        </Badge>
                      </div>
                    </td>

                    {/* Details Action */}
                    <td className="p-4 pr-6 text-right">
                      <Button variant="secondary">
                        View Details
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </GlassPanel>

      {/* OpenAPI Spec Ingestion Modal */}
      {isUploadOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <GlassPanel variant="high" className="w-full max-w-lg p-6 rounded-2xl border border-outline-variant flex flex-col gap-6">
            <div className="flex justify-between items-center border-b border-outline-variant/60 pb-4">
              <h3 className="text-xl font-bold text-white flex items-center gap-2">
                <span className="material-symbols-outlined text-primary">upload_file</span>
                Ingest OpenAPI Specification
              </h3>
              <button
                onClick={() => setIsUploadOpen(false)}
                className="text-on-surface-variant hover:text-white transition-colors"
              >
                <span className="material-symbols-outlined">close</span>
              </button>
            </div>

            <p className="text-sm text-on-surface-variant">
              Upload an OpenAPI 2.0 (Swagger) or OpenAPI 3.0/3.1 specification file in <strong>JSON</strong> or <strong>YAML</strong> format.
            </p>

            {/* Dropzone */}
            <div className="border-2 border-dashed border-outline-variant hover:border-primary/60 rounded-xl p-8 text-center flex flex-col items-center gap-3 transition-colors bg-surface-container-low">
              <span className="material-symbols-outlined text-4xl text-primary">description</span>
              <div>
                <label className="text-primary font-semibold cursor-pointer hover:underline">
                  Choose OpenAPI File
                  <input
                    type="file"
                    accept=".json,.yaml,.yml"
                    onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
                    className="hidden"
                  />
                </label>
                <p className="text-xs text-on-surface-variant mt-1">JSON or YAML up to 50MB</p>
              </div>

              {selectedFile && (
                <div className="mt-3 px-3 py-1.5 bg-primary/10 text-primary border border-primary/30 rounded-lg text-xs font-mono">
                  {selectedFile.name} ({(selectedFile.size / 1024).toFixed(1)} KB)
                </div>
              )}
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <Button variant="secondary" onClick={() => setIsUploadOpen(false)}>
                Cancel
              </Button>
              <Button
                variant="primary"
                onClick={handleIngestOpenApi}
                disabled={!selectedFile || isUploading}
                className="flex items-center gap-2"
              >
                {isUploading && <span className="material-symbols-outlined text-sm animate-spin">sync</span>}
                {isUploading ? 'Ingesting...' : 'Ingest Specification'}
              </Button>
            </div>
          </GlassPanel>
        </div>
      )}

      {/* Endpoint Detail Modal */}
      {selectedEndpoint && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm">
          <GlassPanel variant="high" className="w-full max-w-3xl p-6 rounded-2xl border border-outline-variant flex flex-col gap-6 max-h-[90vh] overflow-y-auto">
            <div className="flex justify-between items-start border-b border-outline-variant/60 pb-4">
              <div>
                <div className="flex items-center gap-3 mb-1">
                  <Badge variant={getMethodBadgeVariant(selectedEndpoint.method)}>
                    {selectedEndpoint.method}
                  </Badge>
                  <h3 className="text-xl font-mono font-bold text-white">{selectedEndpoint.path}</h3>
                </div>
                {selectedEndpoint.summary && (
                  <p className="text-sm text-on-surface-variant">{selectedEndpoint.summary}</p>
                )}
              </div>
              <button
                onClick={() => setSelectedEndpoint(null)}
                className="text-on-surface-variant hover:text-white transition-colors"
              >
                <span className="material-symbols-outlined">close</span>
              </button>
            </div>

            {/* Risk Assessment Section */}
            <div className="p-4 rounded-xl bg-surface-container-low border border-outline-variant flex justify-between items-center">
              <div>
                <div className="text-xs text-on-surface-variant uppercase tracking-wider font-semibold">Deterministic Risk Level</div>
                <div className="text-2xl font-bold text-white mt-0.5">{selectedEndpoint.risk_level}</div>
              </div>
              <div className="text-right">
                <div className="text-xs text-on-surface-variant uppercase tracking-wider font-semibold">Calculated Score</div>
                <div className="text-2xl font-bold text-primary mt-0.5">{selectedEndpoint.risk_score} / 100</div>
              </div>
            </div>

            {/* Endpoint Security Attributes Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 rounded-xl bg-surface-container-high/50 border border-outline-variant/50">
                <div className="text-xs text-on-surface-variant font-semibold uppercase mb-1">Authentication Requirements</div>
                <div className="flex items-center gap-2">
                  <span className={`material-symbols-outlined text-sm ${selectedEndpoint.auth_status === 'UNAUTHENTICATED' ? 'text-error' : 'text-success'}`}>
                    {selectedEndpoint.auth_status === 'UNAUTHENTICATED' ? 'lock_open' : 'lock'}
                  </span>
                  <span className="text-white font-medium">{selectedEndpoint.auth_status} ({selectedEndpoint.auth_type || 'NONE'})</span>
                </div>
              </div>

              <div className="p-4 rounded-xl bg-surface-container-high/50 border border-outline-variant/50">
                <div className="text-xs text-on-surface-variant font-semibold uppercase mb-1">Input Validation Boundary</div>
                <div className="flex items-center gap-2">
                  <span className="material-symbols-outlined text-sm text-warning">verified</span>
                  <span className="text-white font-medium">{selectedEndpoint.request_validation_status}</span>
                </div>
              </div>

              <div className="p-4 rounded-xl bg-surface-container-high/50 border border-outline-variant/50 md:col-span-2">
                <div className="text-xs text-on-surface-variant font-semibold uppercase mb-1">Exposed Sensitive Response Properties</div>
                {selectedEndpoint.sensitive_data_fields ? (
                  <div className="text-tertiary font-mono text-xs bg-tertiary/10 p-2.5 rounded-lg border border-tertiary/30 mt-1">
                    {selectedEndpoint.sensitive_data_fields}
                  </div>
                ) : (
                  <div className="text-on-surface-variant text-xs italic mt-1">No sensitive credentials or PII fields detected in response schema.</div>
                )}
              </div>
            </div>

            {/* Explanations & Actionable Remediations */}
            <div className="flex flex-col gap-3">
              <h4 className="text-sm font-bold text-white uppercase tracking-wider">Security Recommendations</h4>
              <div className="p-4 rounded-xl bg-primary/5 border border-primary/20 text-sm text-on-surface space-y-2">
                {selectedEndpoint.auth_status === 'UNAUTHENTICATED' && (
                  <div className="flex items-start gap-2">
                    <span className="material-symbols-outlined text-error text-base shrink-0 mt-0.5">priority_high</span>
                    <div>
                      <strong className="text-white">Authentication Gap:</strong> Enforce OAuth 2.0 or Bearer JWT security scheme on this endpoint in your API gateway or framework router.
                    </div>
                  </div>
                )}

                {selectedEndpoint.sensitive_data_fields && (
                  <div className="flex items-start gap-2">
                    <span className="material-symbols-outlined text-warning text-base shrink-0 mt-0.5">warning</span>
                    <div>
                      <strong className="text-white">Data Exposure Mitigation:</strong> Mask or omit sensitive response fields (`{selectedEndpoint.sensitive_data_fields}`) from DTO response serializations.
                    </div>
                  </div>
                )}

                {selectedEndpoint.request_validation_status === 'UNCONSTRAINED' && (
                  <div className="flex items-start gap-2">
                    <span className="material-symbols-outlined text-info text-base shrink-0 mt-0.5">info</span>
                    <div>
                      <strong className="text-white">Input Constraint Enforcement:</strong> Add explicit `maxLength`, `pattern`, or `enum` boundaries to all string parameters in the schema.
                    </div>
                  </div>
                )}
              </div>
            </div>

            <div className="flex justify-end pt-2 border-t border-outline-variant/60">
              <Button variant="primary" onClick={() => setSelectedEndpoint(null)}>
                Close Overview
              </Button>
            </div>
          </GlassPanel>
        </div>
      )}
    </div>
  );
};

export default ApiSecurityDashboard;
