import React, { useEffect, useState } from 'react';
import { useApp } from '../../context/AppContext';
import GlassPanel from '../../components/ui/GlassPanel';
import Badge from '../../components/ui/Badge';

import {
  fetchGlobalFindingsSummary,
  fetchFindings,
  type GlobalFindingSummaryApiData,
  type FindingApiData,
} from '../../api/findings';

import {
  fetchApiSecuritySummary,
  type ApiSecuritySummaryData,
} from '../../api/api_security';

import {
  fetchProjectPosture,
  type ProjectPostureData,
} from '../../api/projects';

import {
  fetchProjectCompliance,
  type ComplianceResponseData,
} from '../../api/compliance';

import {
  fetchProjectRiskMap,
  type RiskMapGraphResponseData,
} from '../../api/risk_map';

import {
  fetchScanActivity,
  type ScanActivityData,
} from '../../api/scans';

import {
  fetchActivityEvents,
  type ActivityEventData,
} from '../../api/activity';

export const Dashboard: React.FC = () => {
  const {
    isScanning,
    scanProgress,
    scanStatus,
    scanPhase,
    startScan,
    pauseScan,
    resumeScan,
    stopScan,
    activeProjectId,
    setActiveProjectId,
    scanError,
    projects,
    activeScanId,
  } = useApp();

  const activeProject = projects.find((p) => p.id === activeProjectId) || projects[0];

  const [summaryData, setSummaryData] = useState<GlobalFindingSummaryApiData | null>(null);
  const [apiSummaryData, setApiSummaryData] = useState<ApiSecuritySummaryData | null>(null);
  const [postureData, setPostureData] = useState<ProjectPostureData | null>(null);
  const [recentFindings, setRecentFindings] = useState<FindingApiData[]>([]);
  const [complianceData, setComplianceData] = useState<ComplianceResponseData | null>(null);
  const [riskMapData, setRiskMapData] = useState<RiskMapGraphResponseData | null>(null);
  const [scanActivityData, setScanActivityData] = useState<ScanActivityData[]>([]);
  const [activityFeed, setActivityFeed] = useState<ActivityEventData[]>([]);

  useEffect(() => {
    void fetchGlobalFindingsSummary()
      .then(setSummaryData)
      .catch(() => setSummaryData(null));
  }, [isScanning]);

  useEffect(() => {
    if (activeProjectId && !isNaN(Number(activeProjectId))) {
      void fetchApiSecuritySummary(Number(activeProjectId))
        .then(setApiSummaryData)
        .catch(() => setApiSummaryData(null));

      void fetchProjectCompliance(Number(activeProjectId), 'PCI_DSS')
        .then(setComplianceData)
        .catch(() => setComplianceData(null));

      void fetchProjectRiskMap(Number(activeProjectId))
        .then(setRiskMapData)
        .catch(() => setRiskMapData(null));
    } else {
      setApiSummaryData(null);
      setComplianceData(null);
      setRiskMapData(null);
    }
  }, [activeProjectId, isScanning]);

  useEffect(() => {
    void fetchProjectPosture(activeProjectId)
      .then(setPostureData)
      .catch(() => setPostureData(null));
  }, [activeProjectId, isScanning]);

  useEffect(() => {
    void fetchFindings()
      .then((findings) => {
        const filtered = findings.filter(
          (f) => !activeProjectId || String(f.project_id) === activeProjectId
        );
        setRecentFindings(filtered);
      })
      .catch(() => setRecentFindings([]));
  }, [activeProjectId, isScanning]);

  useEffect(() => {
    void fetchScanActivity()
      .then(setScanActivityData)
      .catch(() => setScanActivityData([]));
  }, [isScanning]);

  useEffect(() => {
    void fetchActivityEvents(activeProjectId)
      .then(setActivityFeed)
      .catch(() => setActivityFeed([]));
  }, [activeProjectId, isScanning]);

  const handleStartScan = () => {
    void startScan(activeProjectId).catch(() => undefined);
  };

  // Compute Security Insights Count (cross-validated / correlated / verified findings)
  const securityInsightsCount = recentFindings.filter(
    (f) => f.source === 'correlation' || f.verification_status === 'CONFIRMED' || (f.confidence_score && f.confidence_score >= 80)
  ).length;

  // Compute Donut Slices
  const totalFindings = summaryData?.total ?? 0;
  const critCount = summaryData?.critical ?? 0;
  const highCount = summaryData?.high ?? 0;
  const medCount = summaryData?.medium ?? 0;

  const critPct = totalFindings > 0 ? (critCount / totalFindings) * 100 : 0;
  const highPct = totalFindings > 0 ? (highCount / totalFindings) * 100 : 0;
  const medPct = totalFindings > 0 ? (medCount / totalFindings) * 100 : 0;

  const donutGradient = totalFindings > 0
    ? `conic-gradient(#ffb4ab 0% ${critPct}%, #ffb782 ${critPct}% ${critPct + highPct}%, #a6c8ff ${critPct + highPct}% ${critPct + highPct + medPct}%, #4ade80 ${critPct + highPct + medPct}% 100%)`
    : 'conic-gradient(#1f242d 0% 100%)';

  // Compute 30d Scan Activity Chart SVG Path
  const maxScanCount = Math.max(...scanActivityData.map((d) => d.count), 0);
  const chartPoints = scanActivityData.map((item, idx) => {
    const x = (idx / Math.max(scanActivityData.length - 1, 1)) * 100;
    const y = maxScanCount > 0 ? 45 - (item.count / maxScanCount) * 35 : 45;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  const pathString = scanActivityData.length > 0 ? `M0,45 L${chartPoints.join(' L')}` : 'M0,45 L100,45';
  const areaString = `${pathString} L100,50 L0,50 Z`;

  // Compute Most Critical Asset from Risk Map or Endpoints
  const mostCriticalNode = riskMapData?.nodes
    ?.filter((n) => n.type === 'ENDPOINT' || n.type === 'API' || n.type === 'PROJECT')
    ?.sort((a, b) => (b.score || 0) - (a.score || 0))[0];
  const mostCriticalAssetLabel = mostCriticalNode?.label || (activeProject?.name ? activeProject.name : 'No active targets');

  // Compute Open Findings for Table (Critical & High)
  const openCriticalFindings = recentFindings
    .filter((f) => f.status === 'open')
    .sort((a, b) => {
      const sevOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
      return (sevOrder[b.severity] || 0) - (sevOrder[a.severity] || 0);
    })
    .slice(0, 5);

  // Posture Score State
  const postureScore = postureData?.has_data ? postureData.score : null;
  const postureGrade = postureData?.has_data ? postureData.grade : 'No assessment data';
  const dashOffset = postureScore !== null ? 282.7 - (282.7 * postureScore) / 100 : 282.7;

  return (
    <div className="p-4 md:p-container-padding max-w-[1600px] mx-auto w-full flex flex-col gap-stack-lg pb-24 relative text-on-surface">

      {/* Header & Project Selector */}
      <GlassPanel variant="low" className="p-8 rounded-2xl relative overflow-hidden bg-gradient-to-br from-[#11151D]/80 to-[#001c3b]/40 border-l-4 border-l-primary">
        <div className="absolute top-0 left-0 right-0 h-1 shimmer"></div>
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-6 relative z-10">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <h2 className="font-display-lg text-[32px] text-white font-bold">
                Kyptic Security Console
              </h2>
              {projects.length > 0 && (
                <select
                  value={activeProjectId}
                  onChange={(e) => setActiveProjectId(e.target.value)}
                  className="bg-surface-container border border-outline-variant text-white text-xs px-3 py-1.5 rounded-lg font-mono cursor-pointer outline-none focus:border-primary"
                >
                  <option value="">All Projects Scope</option>
                  {projects.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                    </option>
                  ))}
                </select>
              )}
            </div>
            <div className="flex flex-col sm:flex-row gap-4 mt-4">
              <div className="flex items-center gap-2 text-on-surface-variant bg-surface/50 px-4 py-2 rounded-lg border border-outline-variant/50">
                <span className="material-symbols-outlined text-primary text-sm">verified_user</span>
                <span className="text-sm">Protecting <strong className="text-white">{projects.length}</strong> registered applications.</span>
              </div>
              <div className="flex items-center gap-2 text-on-surface-variant bg-surface/50 px-4 py-2 rounded-lg border border-error/30">
                <span className="material-symbols-outlined text-error text-sm">warning</span>
                <span className="text-sm"><strong className="text-error">{summaryData?.critical ?? 0}</strong> critical vulnerabilities detected.</span>
              </div>
              <div className="flex items-center gap-2 text-on-surface-variant bg-surface/50 px-4 py-2 rounded-lg border border-outline-variant/50">
                <span className="material-symbols-outlined text-tertiary text-sm">history</span>
                <span className="text-sm">Scan status: <strong className="text-white">{isScanning ? 'Running...' : 'Idle'}</strong>.</span>
              </div>
            </div>
          </div>
        </div>
        <div className="absolute -right-20 -top-20 w-64 h-64 bg-primary/10 rounded-full blur-3xl pointer-events-none"></div>
      </GlassPanel>

      {/* Bento Grid Structure */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-gutter">
        {/* Main Score & Top KPIs (Left Column) */}
        <div className="md:col-span-8 flex flex-col gap-gutter">
          {/* KPI Row */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-gutter">
            {/* KPI Card 1 */}
            <div className="card-base p-6 rounded-xl relative overflow-hidden group bg-gradient-to-br from-[#11151D] to-[#1a1414]">
              <div className="absolute top-0 right-0 w-24 h-24 bg-error/5 rounded-full blur-2xl -mr-10 -mt-10 transition-transform group-hover:scale-110"></div>
              <div className="flex justify-between items-start mb-4">
                <span className="font-label-mono text-label-mono text-on-surface-variant uppercase">Critical Vulns</span>
                <span className="material-symbols-outlined text-error">warning</span>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="font-display-lg text-display-lg text-on-surface">{summaryData?.critical ?? 0}</span>
                <span className="text-sm text-error bg-error/10 px-2 py-0.5 rounded flex items-center">
                  Active
                </span>
              </div>
            </div>

            {/* KPI Card 2 */}
            <div className="card-base p-6 rounded-xl relative overflow-hidden group bg-gradient-to-br from-[#11151D] to-[#0d141e]">
              <div className="absolute top-0 right-0 w-24 h-24 bg-primary/5 rounded-full blur-2xl -mr-10 -mt-10 transition-transform group-hover:scale-110"></div>
              <div className="flex justify-between items-start mb-4">
                <span className="font-label-mono text-label-mono text-on-surface-variant uppercase">Active Projects</span>
                <span className="material-symbols-outlined text-primary">inventory_2</span>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="font-display-lg text-display-lg text-on-surface">{projects.length}</span>
              </div>
            </div>

            {/* KPI Card 3 */}
            <div className="card-base p-6 rounded-xl relative overflow-hidden group bg-gradient-to-br from-[#11151D] to-[#1e150d]">
              <div className="absolute top-0 right-0 w-24 h-24 bg-tertiary/5 rounded-full blur-2xl -mr-10 -mt-10 transition-transform group-hover:scale-110"></div>
              <div className="flex justify-between items-start mb-4">
                <span className="font-label-mono text-label-mono text-on-surface-variant uppercase">Scans Running</span>
                <span className="material-symbols-outlined text-tertiary">radar</span>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="font-display-lg text-display-lg text-on-surface">
                  {isScanning ? '1' : '0'}
                </span>
                <span className={`text-sm text-tertiary bg-tertiary/10 px-2 py-0.5 rounded ${isScanning ? 'animate-pulse' : ''}`}>
                  {isScanning ? 'Active' : 'Idle'}
                </span>
              </div>
            </div>

            {/* KPI Card 4: Security Insights */}
            <div className="card-base p-6 rounded-xl relative overflow-hidden group bg-gradient-to-br from-[#11151D] to-[#0d1c22]">
              <div className="absolute top-0 right-0 w-24 h-24 bg-[#a3defe]/5 rounded-full blur-2xl -mr-10 -mt-10 transition-transform group-hover:scale-110"></div>
              <div className="flex justify-between items-start mb-4">
                <span className="font-label-mono text-label-mono text-on-surface-variant uppercase">Security Insights</span>
                <span className="material-symbols-outlined text-[#a3defe]">tips_and_updates</span>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="font-display-lg text-display-lg text-on-surface">{securityInsightsCount}</span>
                <span className="text-sm text-[#a3defe] bg-[#a3defe]/10 px-2 py-0.5 rounded">
                  {securityInsightsCount > 0 ? 'Verified' : 'Idle'}
                </span>
              </div>
            </div>
          </div>

          {/* Attack Surface Overview & Live Scan Status Row */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-gutter">
            {/* Attack Surface & API Security Overview */}
            <div className="card-base p-6 rounded-xl bg-gradient-to-br from-[#11151D] to-[#0A0D12]">
              <div className="flex justify-between items-center mb-4">
                <h3 className="font-headline-md text-headline-md text-on-surface">API Security Surface</h3>
                <span className="text-xs text-primary font-mono bg-primary/10 px-2 py-0.5 rounded border border-primary/20">
                  {apiSummaryData ? `${apiSummaryData.total_endpoints} Endpoints` : 'No API Data'}
                </span>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-surface-container/50 p-4 rounded-lg border border-outline-variant/50 flex flex-col justify-center">
                  <span className="text-on-surface-variant text-sm mb-1">API Endpoints</span>
                  <span className="text-white font-display-lg text-2xl">{apiSummaryData?.total_endpoints ?? 0}</span>
                </div>
                <div className="bg-surface-container/50 p-4 rounded-lg border border-error/30 flex flex-col justify-center relative overflow-hidden">
                  <span className="text-on-surface-variant text-sm mb-1 relative z-10">High/Critical Routes</span>
                  <span className="text-error font-display-lg text-2xl relative z-10">
                    {(apiSummaryData?.critical_endpoints ?? 0) + (apiSummaryData?.high_endpoints ?? 0)}
                  </span>
                </div>
                <div className="bg-surface-container/50 p-4 rounded-lg border border-[#ff9800]/30 flex flex-col justify-center">
                  <span className="text-on-surface-variant text-sm mb-1">Unauthenticated</span>
                  <span className="text-[#ff9800] font-display-lg text-2xl">
                    {apiSummaryData?.unauthenticated_endpoints ?? 0}
                  </span>
                </div>
                <div className="bg-surface-container/50 p-4 rounded-lg border border-primary/30 flex flex-col justify-center">
                  <span className="text-on-surface-variant text-sm mb-1">DAST Verified Vuln</span>
                  <span className="text-primary font-display-lg text-2xl">
                    {apiSummaryData?.verified_vulnerable_endpoints ?? 0}
                  </span>
                </div>
              </div>
            </div>

            {/* Live Scan Status */}
            <div className="card-base p-6 rounded-xl bg-gradient-to-br from-[#11151D] to-[#0A0D12] border-primary-container/20 border flex flex-col justify-between min-h-[300px]">
              <div>
                <div className="flex justify-between items-center mb-4">
                  <h3 className="font-headline-md text-headline-md text-white flex items-center gap-2">
                    <span className={`material-symbols-outlined text-primary ${scanStatus === 'running' ? 'animate-spin' : ''}`} style={{ animationDuration: '1.5s' }}>
                      {scanStatus === 'completed' ? 'verified_user' : 'radar'}
                    </span>
                    <span>Active Scan Status</span>
                  </h3>
                  <span className="bg-primary/20 text-primary text-xs px-2 py-1 rounded border border-primary/30 font-mono">
                    {scanStatus === 'running' || scanStatus === 'paused' ? `Scan #${activeScanId || 'Active'}` : 'Engine: Idle'}
                  </span>
                </div>

                {scanStatus === 'idle' || scanStatus === 'stopped' || scanStatus === 'failed' ? (
                  <div className="flex flex-col gap-4 py-2">
                    <p className="text-sm text-on-surface-variant">
                      No scan currently running. Select an action below to start analyzing project source repositories or API endpoints.
                    </p>
                    <div className="flex flex-col sm:flex-row gap-3 mt-2">
                      <button
                        type="button"
                        onClick={handleStartScan}
                        disabled={projects.length === 0}
                        className="flex items-center justify-center gap-2 px-5 py-2.5 rounded-lg bg-primary text-on-primary font-bold hover:brightness-110 active:scale-95 transition-all shadow-[0_4px_15px_rgba(166,200,255,0.2)] text-sm cursor-pointer border-none disabled:opacity-50"
                      >
                        <span className="material-symbols-outlined text-sm">rocket_launch</span>
                        <span>Start Security Scan</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => window.location.href = '/projects'}
                        className="flex items-center justify-center gap-2 px-5 py-2.5 rounded-lg bg-surface-container border border-outline-variant text-on-surface font-semibold hover:border-primary/50 hover:text-primary active:scale-95 transition-all text-sm cursor-pointer"
                      >
                        <span className="material-symbols-outlined text-sm">folder</span>
                        <span>Manage Projects</span>
                      </button>
                    </div>
                  </div>
                ) : scanStatus === 'completed' ? (
                  <div className="flex flex-col gap-4 py-2">
                    <div className="flex items-center gap-2 text-green-400 bg-green-950/20 border border-green-500/30 rounded-lg p-3">
                      <span className="material-symbols-outlined">check_circle</span>
                      <span className="text-sm font-semibold">Scan Completed Successfully</span>
                    </div>
                    <p className="text-sm text-on-surface-variant">
                      Analysis finished. {summaryData?.critical ?? 0} critical findings identified in project results.
                    </p>
                    <div className="flex gap-3">
                      <button
                        type="button"
                        onClick={() => window.location.href = '/findings'}
                        className="flex items-center justify-center gap-2 px-5 py-2.5 rounded-lg bg-primary text-on-primary font-bold hover:brightness-110 active:scale-95 transition-all text-sm cursor-pointer border-none"
                      >
                        <span className="material-symbols-outlined text-sm">security</span>
                        <span>View Findings</span>
                      </button>
                      <button
                        type="button"
                        onClick={handleStartScan}
                        className="flex items-center justify-center gap-2 px-5 py-2.5 rounded-lg bg-surface-container border border-outline-variant text-on-surface font-semibold hover:border-primary/50 hover:text-primary active:scale-95 transition-all text-sm cursor-pointer"
                      >
                        <span className="material-symbols-outlined text-sm">replay</span>
                        <span>Scan Again</span>
                      </button>
                    </div>
                  </div>
                ) : (
                  /* running or paused */
                  <div className="space-y-4 py-1">
                    <p className="text-sm text-on-surface-variant">
                      Analyzing target: <code className="text-primary bg-primary/10 px-1 rounded">{activeProject?.name || 'Selected Project'}</code>
                    </p>
                    <div>
                      <div className="mb-1.5 flex justify-between items-end">
                        <span className="text-xs font-semibold text-white">Execution Pipeline</span>
                        <span className="text-xl font-bold text-primary">
                          {scanProgress}%
                        </span>
                      </div>
                      <div className="w-full h-2.5 bg-surface-container-highest rounded-full overflow-hidden mb-3 border border-outline-variant/30">
                        <div
                          className={`h-full bg-gradient-to-r from-[#2E90FA] to-[#005fb0] rounded-full relative transition-all duration-300 ${scanStatus === 'paused' ? 'brightness-50' : ''}`}
                          style={{ width: `${scanProgress}%` }}
                        >
                          {scanStatus === 'running' && <div className="absolute inset-0 shimmer opacity-50"></div>}
                        </div>
                      </div>
                      <div className="flex justify-between text-[11px] text-on-surface-variant">
                        <span>Phase: {scanPhase || (scanStatus === 'paused' ? 'Paused' : 'Running Scanners')}</span>
                        <span>Status: {scanStatus}</span>
                      </div>
                    </div>

                    {/* Controls */}
                    <div className="flex items-center gap-3 pt-2">
                      {scanStatus === 'running' ? (
                        <button
                          type="button"
                          onClick={() => void pauseScan().catch(() => undefined)}
                          className="flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg bg-surface-container border border-outline-variant text-on-surface hover:text-primary hover:border-primary/50 transition-colors text-xs font-semibold cursor-pointer active:scale-95"
                        >
                          <span className="material-symbols-outlined text-[16px]">pause</span>
                          <span>Pause</span>
                        </button>
                      ) : scanStatus === 'paused' ? (
                        <button
                          type="button"
                          onClick={() => void resumeScan().catch(() => undefined)}
                          className="flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg bg-primary text-on-primary hover:brightness-110 transition-all text-xs font-bold cursor-pointer active:scale-95 border-none"
                        >
                          <span className="material-symbols-outlined text-[16px]">play_arrow</span>
                          <span>Resume</span>
                        </button>
                      ) : null}

                      <button
                        type="button"
                        onClick={() => void stopScan().catch(() => undefined)}
                        className="flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg bg-transparent border border-error/40 text-error hover:bg-error/10 transition-colors text-xs font-semibold cursor-pointer active:scale-95"
                      >
                        <span className="material-symbols-outlined text-[16px]">stop</span>
                        <span>Stop</span>
                      </button>
                    </div>
                  </div>
                )}
                {scanError && <p className="mt-3 text-sm text-error">{scanError}</p>}
              </div>
            </div>
          </div>

          {/* Charts Row */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-gutter">
            {/* Chart 1: Donut Severity Distribution */}
            <div className="card-base p-6 rounded-xl bg-gradient-to-br from-[#11151D] to-[#0A0D12]">
              <h3 className="font-headline-md text-headline-md text-on-surface mb-6">Severity Distribution</h3>
              <div className="flex justify-center items-center h-48 relative">
                {/* Dynamic Donut Chart */}
                <div
                  className="w-40 h-40 rounded-full relative flex items-center justify-center shadow-[0_0_30px_rgba(0,0,0,0.5)] transition-all duration-500"
                  style={{ background: donutGradient }}
                >
                  <div className="w-28 h-28 bg-[#11151D] rounded-full flex flex-col items-center justify-center">
                    <span className="font-display-lg text-[24px] text-on-surface font-bold">{totalFindings}</span>
                    <span className="font-label-mono text-[10px] text-on-surface-variant">TOTAL</span>
                  </div>
                </div>
              </div>
              <div className="flex justify-center gap-4 mt-6 flex-wrap">
                <div className="flex items-center gap-1.5">
                  <div className="w-3 h-3 rounded-sm bg-error shadow-[0_0_5px_#ffb4ab]"></div>
                  <span className="text-xs text-on-surface-variant">Critical ({summaryData?.critical ?? 0})</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <div className="w-3 h-3 rounded-sm bg-tertiary shadow-[0_0_5px_#ffb782]"></div>
                  <span className="text-xs text-on-surface-variant">High ({summaryData?.high ?? 0})</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <div className="w-3 h-3 rounded-sm bg-primary shadow-[0_0_5px_#a6c8ff]"></div>
                  <span className="text-xs text-on-surface-variant">Med ({summaryData?.medium ?? 0})</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <div className="w-3 h-3 rounded-sm bg-emerald-400 shadow-[0_0_5px_#4ade80]"></div>
                  <span className="text-xs text-on-surface-variant">Low ({summaryData?.low ?? 0})</span>
                </div>
              </div>
            </div>

            {/* Chart 2: Scan Activity (30d) Area Chart */}
            <div className="card-base p-6 rounded-xl bg-gradient-to-br from-[#11151D] to-[#0A0D12]">
              <h3 className="font-headline-md text-headline-md text-on-surface mb-6">Scan Activity (30d)</h3>
              <div className="h-48 relative w-full flex items-end pt-4 pb-2">
                <svg className="w-full h-full overflow-visible" preserveAspectRatio="none" viewBox="0 0 100 50">
                  <defs>
                    <linearGradient id="chartGrad" x1="0" x2="0" y1="0" y2="1">
                      <stop offset="0%" stopColor="#3192fc" stopOpacity="0.4"></stop>
                      <stop offset="100%" stopColor="#3192fc" stopOpacity="0.0"></stop>
                    </linearGradient>
                  </defs>
                  <line stroke="#1F242D" strokeDasharray="2,2" strokeWidth="0.5" x1="0" x2="100" y1="10" y2="10"></line>
                  <line stroke="#1F242D" strokeDasharray="2,2" strokeWidth="0.5" x1="0" x2="100" y1="30" y2="30"></line>
                  <line stroke="#1F242D" strokeWidth="0.5" x1="0" x2="100" y1="50" y2="50"></line>
                  <path d={areaString} fill="url(#chartGrad)"></path>
                  <path d={pathString} fill="none" stroke="#3192fc" strokeWidth="2" vectorEffect="non-scaling-stroke"></path>
                </svg>
                <div className="absolute right-4 top-2 bg-surface-container border border-outline-variant px-2 py-1 rounded text-xs text-on-surface z-10 shadow-lg">
                  Peak: {maxScanCount} Scans
                </div>
              </div>
            </div>
          </div>

          {/* Risk Topology / Map Overview */}
          <div className="card-base p-6 rounded-xl bg-gradient-to-br from-[#11151D] to-[#0A0D12]">
            <div className="flex justify-between items-center mb-6">
              <h3 className="font-headline-md text-headline-md text-on-surface">Risk Topology Breakdown</h3>
              <button
                type="button"
                onClick={() => window.location.href = '/risk-map'}
                className="text-primary text-sm hover:underline flex items-center gap-1 bg-transparent border-none cursor-pointer"
              >
                <span>Explore Full Risk Map</span>
                <span className="material-symbols-outlined text-[16px]">arrow_forward</span>
              </button>
            </div>

            {riskMapData && riskMapData.nodes.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-surface-container/40 p-4 rounded-lg border border-outline-variant/30">
                  <span className="text-xs text-on-surface-variant block mb-1">Total Topology Nodes</span>
                  <span className="text-2xl font-bold text-white">{riskMapData.summary.total_nodes}</span>
                  <span className="text-xs text-outline block mt-1">{riskMapData.summary.total_edges} connections</span>
                </div>
                <div className="bg-surface-container/40 p-4 rounded-lg border border-outline-variant/30">
                  <span className="text-xs text-on-surface-variant block mb-1">Critical & High Nodes</span>
                  <span className="text-2xl font-bold text-error">
                    {riskMapData.summary.critical_findings + riskMapData.summary.high_findings}
                  </span>
                  <span className="text-xs text-outline block mt-1">{riskMapData.summary.critical_findings} critical / {riskMapData.summary.high_findings} high</span>
                </div>
                <div className="bg-surface-container/40 p-4 rounded-lg border border-outline-variant/30">
                  <span className="text-xs text-on-surface-variant block mb-1">Highest Risk Target</span>
                  <span className="text-sm text-white font-mono bg-surface px-2 py-1 rounded inline-block truncate max-w-full">
                    {mostCriticalAssetLabel}
                  </span>
                </div>
              </div>
            ) : (
              <div className="p-8 text-center bg-surface-container/20 rounded-lg border border-outline-variant/20">
                <span className="material-symbols-outlined text-outline text-3xl mb-2">bubble_chart</span>
                <p className="text-sm text-on-surface-variant">No risk topology data available. Ingest an OpenAPI spec or run a scan to map project assets.</p>
              </div>
            )}
          </div>

          {/* Recent Open Findings Table */}
          <div className="card-base rounded-xl overflow-hidden bg-gradient-to-br from-[#11151D] to-[#0A0D12]">
            <div className="p-6 border-b border-outline-variant flex justify-between items-center bg-surface-container-low/50">
              <h3 className="font-headline-md text-headline-md text-on-surface">Recent Open Findings</h3>
              <button
                type="button"
                onClick={() => window.location.href = '/findings'}
                className="text-primary font-medium text-sm hover:underline bg-transparent border-none cursor-pointer"
              >
                View All
              </button>
            </div>
            <div className="overflow-x-auto">
              {openCriticalFindings.length > 0 ? (
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-[#11151D]/50 border-b border-outline-variant">
                      <th className="px-6 py-4 font-label-mono text-label-mono text-on-surface-variant uppercase font-medium">Severity</th>
                      <th className="px-6 py-4 font-label-mono text-label-mono text-on-surface-variant uppercase font-medium">Title</th>
                      <th className="px-6 py-4 font-label-mono text-label-mono text-on-surface-variant uppercase font-medium">Category / CWE</th>
                      <th className="px-6 py-4 font-label-mono text-label-mono text-on-surface-variant uppercase font-medium text-center">Confidence</th>
                      <th className="px-6 py-4 font-label-mono text-label-mono text-on-surface-variant uppercase font-medium">Status</th>
                    </tr>
                  </thead>
                  <tbody className="font-body-md text-body-md">
                    {openCriticalFindings.map((finding) => (
                      <tr
                        key={finding.id}
                        onClick={() => window.location.href = '/findings'}
                        className="border-b border-outline-variant hover:bg-surface-container/50 transition-colors group cursor-pointer"
                      >
                        <td className="px-6 py-4">
                          <Badge variant={finding.severity === 'critical' ? 'critical' : finding.severity === 'high' ? 'high' : 'medium'}>
                            {finding.severity.toUpperCase()}
                          </Badge>
                        </td>
                        <td className="px-6 py-4 text-on-surface font-medium">{finding.title}</td>
                        <td className="px-6 py-4 text-on-surface-variant text-sm">
                          {finding.cwe || finding.category || 'Security Finding'}
                        </td>
                        <td className="px-6 py-4 text-center text-sm text-[#a3defe]">
                          {finding.confidence_score !== undefined ? `${finding.confidence_score}%` : (finding.confidence_level || 'N/A')}
                        </td>
                        <td className="px-6 py-4">
                          <span className="text-on-surface-variant text-xs border border-outline-variant px-2 py-1 rounded bg-surface/50 uppercase">
                            {finding.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="p-8 text-center text-on-surface-variant text-sm">
                  No critical findings detected.
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Right Column (Posture Score & AI Copilot Insights) */}
        <div className="md:col-span-4 flex flex-col gap-gutter">
          {/* Main Security Posture Gauge */}
          <div className="card-base p-8 rounded-xl flex flex-col items-center justify-center relative glow-box-primary bg-gradient-to-b from-[#11151D] to-[#0A0D12]">
            <h3 className="font-label-mono text-label-mono text-on-surface-variant uppercase absolute top-6 left-6 tracking-wider">Overall Posture</h3>
            <div className="absolute top-6 right-6 text-xs font-semibold px-2.5 py-1 rounded border bg-surface/50 text-on-surface-variant border-outline-variant">
              {postureGrade}
            </div>
            <div className="mt-8 mb-4 relative w-48 h-48 flex items-center justify-center">
              {/* SVG Gauge */}
              <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                <circle cx="50" cy="50" fill="none" r="45" stroke="#1F242D" strokeLinecap="round" strokeWidth="8"></circle>
                {postureScore !== null && (
                  <circle
                    className="drop-shadow-[0_0_12px_rgba(49,146,252,0.8)] transition-all duration-1000"
                    cx="50" cy="50" fill="none" r="45" stroke="url(#blueGrad)"
                    strokeDasharray="282.7"
                    strokeDashoffset={dashOffset}
                    strokeLinecap="round" strokeWidth="8"
                  ></circle>
                )}
                <defs>
                  <linearGradient id="blueGrad" x1="0%" x2="100%" y1="0%" y2="100%">
                    <stop offset="0%" stopColor="#a6c8ff"></stop>
                    <stop offset="100%" stopColor="#3192fc"></stop>
                  </linearGradient>
                </defs>
              </svg>
              <div className="absolute flex flex-col items-center justify-center text-center">
                <span className="font-display-lg text-[48px] font-bold text-white glow-text leading-none">
                  {postureScore !== null ? postureScore : 'N/A'}
                </span>
                <span className="text-on-surface-variant text-xs mt-1">
                  {postureScore !== null ? '/ 100' : 'No assessment data'}
                </span>
              </div>
            </div>
            <div className="flex items-center gap-2 mt-2 bg-surface px-4 py-1.5 rounded-full border border-outline-variant text-xs text-on-surface-variant">
              <span className="material-symbols-outlined text-sm text-primary">analytics</span>
              <span>Based on authoritative findings calculation</span>
            </div>
          </div>

          {/* AI Copilot Insights Panel */}
          <div className="glass-panel rounded-xl p-6 relative overflow-hidden bg-gradient-to-b from-[#11151D]/90 to-[#0A0D12]/90 border border-[#2E90FA]/30 shadow-[0_0_15px_rgba(46,144,250,0.1)]">
            <div className="absolute top-0 left-0 right-0 h-1 shimmer"></div>
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-gradient-to-br from-[#2E90FA]/20 to-transparent border border-[#2E90FA]/30">
                  <span className="material-symbols-outlined text-[#a3defe] animate-pulse">psychology</span>
                </div>
                <h3 className="font-headline-md text-headline-md text-white">AI Copilot Insights</h3>
              </div>
            </div>

            <div className="flex flex-col gap-4">
              {openCriticalFindings.length > 0 ? (
                openCriticalFindings.slice(0, 2).map((finding, idx) => (
                  <div
                    key={finding.id}
                    onClick={() => window.location.href = '/copilot'}
                    className="bg-[#0A0D12]/80 border border-[#1F242D] hover:border-primary/50 transition-all duration-300 rounded-lg p-4 cursor-pointer group shadow-md"
                  >
                    <div className="flex justify-between items-start mb-2">
                      <div className="flex items-center gap-2">
                        <span className={`w-2 h-2 rounded-full ${idx === 0 ? 'bg-error animate-ping' : 'bg-tertiary'}`}></span>
                        <span className="text-sm font-semibold text-white">
                          {idx === 0 ? 'Recommended Remediation' : 'Security Finding Insight'}
                        </span>
                      </div>
                      <span className="material-symbols-outlined text-on-surface-variant text-sm group-hover:text-primary transition-colors">auto_fix_high</span>
                    </div>
                    <p className="text-xs text-on-surface-variant leading-relaxed line-clamp-2">
                      {finding.description || `Remediate ${finding.title} in ${finding.file_path}`}
                    </p>
                    <div className="mt-3 flex items-center justify-between text-xs text-on-surface-variant">
                      <span className="font-mono text-primary bg-primary/10 px-1.5 py-0.5 rounded">{finding.cwe || finding.category}</span>
                      <span>Severity: {finding.severity.toUpperCase()}</span>
                    </div>
                  </div>
                ))
              ) : (
                <div className="p-6 bg-[#0A0D12]/80 border border-[#1F242D] rounded-lg text-center">
                  <p className="text-xs text-on-surface-variant mb-2">
                    Ask Copilot about a finding to get security guidance.
                  </p>
                </div>
              )}

              <button
                type="button"
                onClick={() => window.location.href = '/copilot'}
                className="mt-2 w-full flex justify-center items-center gap-2 py-3 rounded-lg bg-[#11151D] border border-primary/50 text-primary hover:bg-primary/10 transition-colors font-medium cursor-pointer"
              >
                <span className="material-symbols-outlined">forum</span> Open AI Chat
              </button>
            </div>
          </div>

          {/* Compliance Mini Widget */}
          <div className="card-base p-6 rounded-xl bg-gradient-to-br from-[#11151D] to-[#0A0D12]">
            <h3 className="font-label-mono text-label-mono text-on-surface-variant uppercase mb-4 tracking-wider">Compliance Summary</h3>
            {complianceData?.summary ? (
              <div className="flex flex-col gap-4">
                <div>
                  <div className="flex justify-between text-sm mb-1.5">
                    <span className="text-white font-medium">{complianceData.summary.framework_name}</span>
                    <span className="text-primary font-code-sm">{complianceData.summary.coverage_percentage}%</span>
                  </div>
                  <div className="w-full h-1.5 bg-surface-container-highest rounded-full overflow-hidden">
                    <div className="h-full bg-primary rounded-full" style={{ width: `${complianceData.summary.coverage_percentage}%` }}></div>
                  </div>
                </div>
                <div className="grid grid-cols-3 gap-2 text-center text-xs pt-2">
                  <div className="bg-surface-container/40 p-2 rounded border border-outline-variant/30">
                    <span className="block text-error font-bold">{complianceData.summary.affected_controls}</span>
                    <span className="text-[10px] text-on-surface-variant uppercase">Affected</span>
                  </div>
                  <div className="bg-surface-container/40 p-2 rounded border border-outline-variant/30">
                    <span className="block text-emerald-400 font-bold">{complianceData.summary.unaffected_controls}</span>
                    <span className="text-[10px] text-on-surface-variant uppercase">Passed</span>
                  </div>
                  <div className="bg-surface-container/40 p-2 rounded border border-outline-variant/30">
                    <span className="block text-amber-400 font-bold">{complianceData.summary.insufficient_evidence_controls}</span>
                    <span className="text-[10px] text-on-surface-variant uppercase">No Evidence</span>
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-xs text-on-surface-variant p-4 text-center bg-surface-container/20 rounded border border-outline-variant/20">
                {activeProjectId ? 'Insufficient scan evidence available to evaluate controls.' : 'Select a project to view compliance assessment.'}
              </div>
            )}
          </div>

          {/* Recent Activity Timeline */}
          <div className="card-base p-6 rounded-xl bg-gradient-to-br from-[#11151D] to-[#0A0D12]">
            <h3 className="font-label-mono text-label-mono text-on-surface-variant uppercase mb-4 tracking-wider">Recent Activity</h3>
            {activityFeed.length > 0 ? (
              <div className="relative border-l border-outline-variant/50 ml-3 space-y-6">
                {activityFeed.slice(0, 4).map((event) => (
                  <div key={event.id} className="relative pl-6">
                    <span className={`absolute -left-1.5 top-1 w-3 h-3 rounded-full ring-4 ring-[#11151D] ${event.status === 'error' ? 'bg-error' : event.status === 'success' ? 'bg-emerald-400' : 'bg-primary'}`}></span>
                    <div className="text-[10px] text-on-surface-variant mb-0.5">
                      {new Date(event.timestamp).toLocaleString()}
                    </div>
                    <p className="text-xs text-white font-medium">{event.title}</p>
                    <p className="text-[11px] text-on-surface-variant mt-0.5">{event.description}</p>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-xs text-on-surface-variant p-4 text-center bg-surface-container/20 rounded border border-outline-variant/20">
                No recent activity events recorded.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
