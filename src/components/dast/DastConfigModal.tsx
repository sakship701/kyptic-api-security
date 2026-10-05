import React, { useEffect, useState } from 'react';
import GlassPanel from '../ui/GlassPanel';
import Button from '../ui/Button';
import { fetchDastConfig, updateDastConfig, testDastConnection, type DastTargetConfigData } from '../../api/api_security';

interface DastConfigModalProps {
  isOpen: boolean;
  projectId: number;
  onClose: () => void;
  onSaved?: () => void;
}

export const DastConfigModal: React.FC<DastConfigModalProps> = ({
  isOpen,
  projectId,
  onClose,
  onSaved,
}) => {
  const [targetUrl, setTargetUrl] = useState<string>('');
  const [dastEnabled, setDastEnabled] = useState<boolean>(false);
  const [authType, setAuthType] = useState<string>('NONE');
  const [authHeaderName, setAuthHeaderName] = useState<string>('Authorization');

  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isSaving, setIsSaving] = useState<boolean>(false);
  const [isTesting, setIsTesting] = useState<boolean>(false);

  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ status: string; message: string } | null>(null);

  const loadConfig = async () => {
    if (!projectId) return;
    setIsLoading(true);
    setErrorMsg(null);
    setSuccessMsg(null);
    setTestResult(null);

    try {
      const config: DastTargetConfigData = await fetchDastConfig(projectId);
      setDastEnabled(config.api_dast_enabled ?? false);
      setTargetUrl(config.api_target_url || '');
      setAuthType(config.api_auth_type || 'NONE');
      setAuthHeaderName(config.api_auth_header_name || 'Authorization');
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to load DAST target configuration.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen && projectId) {
      void loadConfig();
    }
  }, [isOpen, projectId]);

  if (!isOpen) return null;

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    setErrorMsg(null);
    setSuccessMsg(null);
    setTestResult(null);

    try {
      const updated = await updateDastConfig(projectId, {
        api_target_url: targetUrl.trim(),
        api_dast_enabled: dastEnabled,
        api_auth_type: authType,
        api_auth_header_name: authHeaderName,
      });

      // Confirm persisted state from response / refresh
      setDastEnabled(updated.api_dast_enabled);
      setTargetUrl(updated.api_target_url || '');
      setSuccessMsg(updated.message || 'DAST target configuration saved successfully.');

      if (onSaved) {
        onSaved();
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to save DAST configuration.');
    } finally {
      setIsSaving(false);
    }
  };

  const handleTestConnection = async () => {
    setIsTesting(true);
    setErrorMsg(null);
    setTestResult(null);

    try {
      const res = await testDastConnection(projectId);
      setTestResult({
        status: res.status,
        message: res.message,
      });
    } catch (err: any) {
      setErrorMsg(err.message || 'DAST target connection test failed.');
    } finally {
      setIsTesting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm">
      <GlassPanel variant="high" className="w-full max-w-xl p-6 rounded-2xl border border-outline-variant flex flex-col gap-6 max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex justify-between items-center border-b border-outline-variant/60 pb-4">
          <div className="flex items-center gap-3">
            <span className="material-symbols-outlined text-tertiary text-2xl">bolt</span>
            <h3 className="text-xl font-bold text-white">Project DAST Configuration</h3>
          </div>
          <button
            onClick={onClose}
            className="text-on-surface-variant hover:text-white transition-colors"
          >
            <span className="material-symbols-outlined">close</span>
          </button>
        </div>

        {/* Informational Warning Banner */}
        <div className="p-4 rounded-xl bg-tertiary/10 border border-tertiary/30 text-sm text-on-surface-variant space-y-1.5">
          <div className="flex items-center gap-2 font-semibold text-tertiary">
            <span className="material-symbols-outlined text-base">info</span>
            <span>DAST Security & Compliance Notice</span>
          </div>
          <ul className="list-disc list-inside space-y-1 text-xs text-on-surface-variant/90 pl-1">
            <li>DAST performs active HTTP security testing against configured endpoints.</li>
            <li>Only authorized targets owned or permitted for scanning should be configured.</li>
            <li>Target URL is subject to strict server-side SSRF and safety validation.</li>
          </ul>
        </div>

        {isLoading ? (
          <div className="p-8 text-center text-on-surface-variant flex flex-col items-center gap-3">
            <span className="material-symbols-outlined text-3xl animate-spin text-primary">sync</span>
            <span>Loading DAST Configuration...</span>
          </div>
        ) : (
          <form onSubmit={handleSave} className="flex flex-col gap-5">
            {/* Feedback Messages */}
            {errorMsg && (
              <div className="p-3.5 rounded-xl bg-error/10 border border-error/30 text-error text-xs flex items-center gap-2.5">
                <span className="material-symbols-outlined text-base shrink-0">error</span>
                <span>{errorMsg}</span>
              </div>
            )}

            {successMsg && (
              <div className="p-3.5 rounded-xl bg-success/10 border border-success/30 text-success text-xs flex items-center gap-2.5">
                <span className="material-symbols-outlined text-base shrink-0">check_circle</span>
                <span>{successMsg}</span>
              </div>
            )}

            {testResult && (
              <div className={`p-3.5 rounded-xl text-xs flex items-center gap-2.5 ${
                testResult.status === 'SUCCESS'
                  ? 'bg-success/10 border border-success/30 text-success'
                  : 'bg-warning/10 border border-warning/30 text-warning'
              }`}>
                <span className="material-symbols-outlined text-base shrink-0">
                  {testResult.status === 'SUCCESS' ? 'sensors' : 'signal_cellular_off'}
                </span>
                <span>[{testResult.status}] {testResult.message}</span>
              </div>
            )}

            {/* DAST Dynamic Testing Switch */}
            <div className="flex items-center justify-between p-4 rounded-xl bg-surface-container-high/60 border border-outline-variant/60">
              <div>
                <label htmlFor="dast-toggle-switch" className="font-semibold text-white block cursor-pointer">
                  DAST Dynamic Testing
                </label>
                <span className="text-xs text-on-surface-variant">
                  {dastEnabled ? 'Active vulnerability probing enabled for this project' : 'Active DAST probing disabled'}
                </span>
              </div>
              <div className="flex items-center gap-3">
                <span className={`text-xs font-bold font-mono ${dastEnabled ? 'text-success' : 'text-on-surface-variant'}`}>
                  {dastEnabled ? 'ON' : 'OFF'}
                </span>
                <button
                  type="button"
                  id="dast-toggle-switch"
                  role="switch"
                  aria-checked={dastEnabled}
                  onClick={() => setDastEnabled(!dastEnabled)}
                  className={`relative inline-flex h-7 w-12 items-center rounded-full transition-colors focus:outline-none ${
                    dastEnabled ? 'bg-primary' : 'bg-surface-container'
                  }`}
                >
                  <span
                    className={`inline-block h-5 w-5 transform rounded-full bg-white transition-transform ${
                      dastEnabled ? 'translate-x-6' : 'translate-x-1'
                    }`}
                  />
                </button>
              </div>
            </div>

            {/* Target URL Input */}
            <div className="flex flex-col gap-1.5">
              <label htmlFor="dast-target-url-input" className="text-xs font-semibold text-white uppercase tracking-wider">
                Target URL
              </label>
              <input
                id="dast-target-url-input"
                type="text"
                placeholder="e.g. http://127.0.0.1:8001 or https://api.example.com"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                className="w-full bg-surface-container-high px-4 py-2.5 rounded-xl border border-outline-variant text-white font-mono text-sm placeholder-on-surface-variant/60 focus:outline-none focus:border-primary"
              />
              <span className="text-[11px] text-on-surface-variant">
                Enter target base URL (e.g., <code className="text-tertiary">http://127.0.0.1:8001</code> for local demo target).
              </span>
            </div>

            {/* Actions */}
            <div className="flex items-center justify-between pt-3 border-t border-outline-variant/60">
              <Button
                type="button"
                variant="secondary"
                onClick={handleTestConnection}
                disabled={isTesting || !targetUrl.trim() || isSaving}
                className="flex items-center gap-1.5 text-xs"
              >
                <span className={`material-symbols-outlined text-sm ${isTesting ? 'animate-spin' : ''}`}>
                  {isTesting ? 'sync' : 'network_ping'}
                </span>
                {isTesting ? 'Testing...' : 'Test Connection'}
              </Button>

              <div className="flex gap-3">
                <Button type="button" variant="secondary" onClick={onClose} disabled={isSaving}>
                  Cancel
                </Button>
                <Button
                  type="submit"
                  variant="primary"
                  disabled={isSaving}
                  className="flex items-center gap-2"
                >
                  {isSaving && <span className="material-symbols-outlined text-sm animate-spin">sync</span>}
                  {isSaving ? 'Saving...' : 'Save DAST Configuration'}
                </Button>
              </div>
            </div>
          </form>
        )}
      </GlassPanel>
    </div>
  );
};

export default DastConfigModal;
