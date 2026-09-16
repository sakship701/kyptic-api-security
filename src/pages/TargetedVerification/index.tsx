import React, { useEffect, useState } from 'react';
import GlassPanel from '../../components/ui/GlassPanel';
import {
  fetchVulnerabilities,
  runStandaloneTargetedVerification,
} from '../../api/targetedVerification';
import type { VulnerabilityDefinitionApiData } from '../../api/targetedVerification';
import type { TargetedVerificationResultApiData } from '../../api/findings';

export const TargetedVerificationPage: React.FC = () => {
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilityDefinitionApiData[]>([]);
  const [loadingVulns, setLoadingVulns] = useState(true);

  const [targetUrl, setTargetUrl] = useState('http://localhost:8000');
  const [httpMethod, setHttpMethod] = useState('GET');
  const [path, setPath] = useState('/api/v1/users/{id}');
  const [selectedVulnId, setSelectedVulnId] = useState('BOLA');

  const [authType, setAuthType] = useState('NONE');
  const [authHeaderName, setAuthHeaderName] = useState('Authorization');
  const [authToken, setAuthToken] = useState('');

  const [executing, setExecuting] = useState(false);
  const [result, setResult] = useState<TargetedVerificationResultApiData | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    fetchVulnerabilities()
      .then((data) => {
        setVulnerabilities(data);
        setLoadingVulns(false);
      })
      .catch((err) => {
        console.error('Failed to fetch vulnerability registry:', err);
        setLoadingVulns(false);
      });
  }, []);

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setExecuting(true);
    setErrorMsg(null);
    setResult(null);

    try {
      const res = await runStandaloneTargetedVerification({
        target_url: targetUrl,
        http_method: httpMethod,
        path: path,
        vulnerability_id: selectedVulnId,
        auth_type: authType,
        auth_header_name: authHeaderName,
        auth_token: authToken || undefined,
      });
      setResult(res);
    } catch (err: any) {
      setErrorMsg(err.message || 'Targeted verification execution failed.');
    } finally {
      setExecuting(false);
    }
  };

  const selectedDef = vulnerabilities.find((v) => v.vulnerability_id === selectedVulnId);

  return (
    <div className="p-stack-lg max-w-6xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="font-heading-lg text-heading-lg text-on-surface">Targeted Vulnerability Verification</h1>
        <p className="font-body-md text-on-surface-variant mt-1">
          Execute a focused, single-hypothesis dynamic security probe against any API target without running a full project scan.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Verification Control Form */}
        <div className="lg:col-span-6 space-y-6">
          <GlassPanel className="p-6">
            <form onSubmit={handleVerify} className="space-y-4">
              <h2 className="font-heading-md text-heading-md text-on-surface mb-4">Target Parameters</h2>

              <div>
                <label className="block text-xs font-semibold text-on-surface-variant uppercase tracking-wider mb-1">
                  Target Base URL
                </label>
                <input
                  type="text"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  placeholder="https://example.com"
                  required
                  className="w-full px-3 py-2 bg-surface-container-high border border-outline-variant rounded-lg text-on-surface font-mono text-sm focus:outline-none focus:border-primary"
                />
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-1">
                  <label className="block text-xs font-semibold text-on-surface-variant uppercase tracking-wider mb-1">
                    Method
                  </label>
                  <select
                    value={httpMethod}
                    onChange={(e) => setHttpMethod(e.target.value)}
                    className="w-full px-3 py-2 bg-surface-container-high border border-outline-variant rounded-lg text-on-surface font-mono text-sm focus:outline-none focus:border-primary"
                  >
                    <option value="GET">GET</option>
                    <option value="POST">POST</option>
                    <option value="PUT">PUT</option>
                    <option value="DELETE">DELETE</option>
                    <option value="PATCH">PATCH</option>
                  </select>
                </div>

                <div className="col-span-2">
                  <label className="block text-xs font-semibold text-on-surface-variant uppercase tracking-wider mb-1">
                    Path / Route
                  </label>
                  <input
                    type="text"
                    value={path}
                    onChange={(e) => setPath(e.target.value)}
                    placeholder="/api/v1/users/{id}"
                    required
                    className="w-full px-3 py-2 bg-surface-container-high border border-outline-variant rounded-lg text-on-surface font-mono text-sm focus:outline-none focus:border-primary"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-on-surface-variant uppercase tracking-wider mb-1">
                  Vulnerability Hypothesis
                </label>
                <select
                  value={selectedVulnId}
                  onChange={(e) => setSelectedVulnId(e.target.value)}
                  disabled={loadingVulns}
                  className="w-full px-3 py-2 bg-surface-container-high border border-outline-variant rounded-lg text-on-surface font-body-md text-sm focus:outline-none focus:border-primary"
                >
                  {vulnerabilities.map((v) => (
                    <option key={v.vulnerability_id} value={v.vulnerability_id}>
                      {v.supported ? '✓ Supported' : '⚡ Planned'} — {v.display_name}
                    </option>
                  ))}
                </select>
              </div>

              {selectedDef && (
                <div className="p-3 rounded-lg bg-surface-container-high border border-outline-variant text-xs space-y-1">
                  <div className="font-semibold text-on-surface flex items-center justify-between">
                    <span>{selectedDef.display_name}</span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        selectedDef.supported ? 'bg-primary/20 text-primary' : 'bg-surface-variant text-on-surface-variant'
                      }`}
                    >
                      {selectedDef.supported ? 'DYNAMIC PROBE READY' : 'PLANNED / STATIC ONLY'}
                    </span>
                  </div>
                  <p className="text-on-surface-variant">{selectedDef.description}</p>
                </div>
              )}

              {/* Auth Context Accordion/Section */}
              <div className="pt-2 border-t border-outline-variant space-y-3">
                <label className="block text-xs font-semibold text-on-surface-variant uppercase tracking-wider">
                  Authentication Context
                </label>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <select
                      value={authType}
                      onChange={(e) => setAuthType(e.target.value)}
                      className="w-full px-3 py-2 bg-surface-container-high border border-outline-variant rounded-lg text-on-surface text-sm"
                    >
                      <option value="NONE">No Authentication</option>
                      <option value="BEARER">Bearer Token</option>
                      <option value="API_KEY">API Key Header</option>
                    </select>
                  </div>
                  {authType !== 'NONE' && (
                    <div>
                      <input
                        type="text"
                        value={authHeaderName}
                        onChange={(e) => setAuthHeaderName(e.target.value)}
                        placeholder="Authorization"
                        className="w-full px-3 py-2 bg-surface-container-high border border-outline-variant rounded-lg text-on-surface text-sm"
                      />
                    </div>
                  )}
                </div>
                {authType !== 'NONE' && (
                  <div>
                    <input
                      type="password"
                      value={authToken}
                      onChange={(e) => setAuthToken(e.target.value)}
                      placeholder="Secret token / credential"
                      className="w-full px-3 py-2 bg-surface-container-high border border-outline-variant rounded-lg text-on-surface text-sm"
                    />
                  </div>
                )}
              </div>

              <button
                type="submit"
                disabled={executing}
                className="w-full mt-4 py-3 px-4 bg-primary text-on-primary font-bold rounded-lg hover:bg-primary-hover transition-all duration-200 active:scale-95 disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {executing ? (
                  <>
                    <span className="material-symbols-outlined animate-spin">sync</span>
                    Executing Focused Probe...
                  </>
                ) : (
                  <>
                    <span className="material-symbols-outlined">bolt</span>
                    Verify Targeted Vulnerability
                  </>
                )}
              </button>
            </form>
          </GlassPanel>
        </div>

        {/* Results Panel */}
        <div className="lg:col-span-6">
          <GlassPanel className="p-6 h-full flex flex-col">
            <h2 className="font-heading-md text-heading-md text-on-surface mb-4">Verification Results</h2>

            {errorMsg && (
              <div className="p-4 rounded-lg bg-error-container text-on-error-container text-sm flex items-start gap-2">
                <span className="material-symbols-outlined">error</span>
                <div>{errorMsg}</div>
              </div>
            )}

            {!result && !errorMsg && !executing && (
              <div className="flex-1 flex flex-col items-center justify-center text-center p-8 text-on-surface-variant space-y-3">
                <span className="material-symbols-outlined text-[48px] text-outline">verified</span>
                <p className="font-body-md">Configure target parameters and launch targeted verification to inspect dynamic evidence.</p>
              </div>
            )}

            {executing && (
              <div className="flex-1 flex flex-col items-center justify-center text-center p-8 text-primary space-y-3">
                <span className="material-symbols-outlined text-[48px] animate-spin">sync</span>
                <p className="font-body-md font-semibold">Executing safe probe against target endpoint...</p>
              </div>
            )}

            {result && (
              <div className="space-y-4">
                <div
                  className={`p-4 rounded-xl border flex items-center justify-between ${
                    result.status === 'CONFIRMED'
                      ? 'bg-error/10 border-error text-error'
                      : result.status === 'NOT_CONFIRMED'
                      ? 'bg-primary/10 border-primary text-primary'
                      : result.status === 'NOT_SUPPORTED'
                      ? 'bg-surface-variant border-outline text-on-surface-variant'
                      : 'bg-tertiary/10 border-tertiary text-tertiary'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <span className="material-symbols-outlined text-[28px]">
                      {result.status === 'CONFIRMED'
                        ? 'warning'
                        : result.status === 'NOT_CONFIRMED'
                        ? 'verified'
                        : result.status === 'NOT_SUPPORTED'
                        ? 'block'
                        : 'help_outline'}
                    </span>
                    <div>
                      <div className="font-heading-sm text-heading-sm font-bold">{result.status}</div>
                      <div className="text-xs opacity-90">{result.vulnerability_id} — {result.vulnerability_family}</div>
                    </div>
                  </div>
                  <span className="font-mono text-xs font-bold px-2.5 py-1 rounded bg-surface/50 border border-current">
                    {result.http_method} {result.path}
                  </span>
                </div>

                <div>
                  <h3 className="text-xs font-semibold text-on-surface-variant uppercase tracking-wider mb-1">
                    Explanation
                  </h3>
                  <div className="p-3 bg-surface-container-high rounded-lg text-sm text-on-surface font-body-md leading-relaxed border border-outline-variant">
                    {result.explanation}
                  </div>
                </div>

                {result.evidence && (
                  <div>
                    <h3 className="text-xs font-semibold text-on-surface-variant uppercase tracking-wider mb-1">
                      Sanitized Evidence
                    </h3>
                    <pre className="p-3 bg-surface-container-lowest rounded-lg text-xs font-mono text-on-surface text-wrap break-all border border-outline-variant max-h-60 overflow-y-auto">
                      {result.evidence}
                    </pre>
                  </div>
                )}

                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div className="p-2.5 bg-surface-container-high rounded-lg">
                    <span className="text-on-surface-variant block">Requests Attempted</span>
                    <span className="font-bold text-on-surface text-sm">{result.requests_attempted}</span>
                  </div>
                  <div className="p-2.5 bg-surface-container-high rounded-lg">
                    <span className="text-on-surface-variant block">Probe Type</span>
                    <span className="font-bold text-on-surface text-sm">{result.probe_type || 'N/A'}</span>
                  </div>
                </div>
              </div>
            )}
          </GlassPanel>
        </div>
      </div>
    </div>
  );
};

export default TargetedVerificationPage;
