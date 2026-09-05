import React, { useEffect, useState } from 'react';
import { useApp } from '../../context/AppContext';
import GlassPanel from '../../components/ui/GlassPanel';
import Badge from '../../components/ui/Badge';
import { fetchGlobalFindingsSummary, type GlobalFindingSummaryApiData } from '../../api/findings';
import { fetchApiSecuritySummary, type ApiSecuritySummaryData } from '../../api/api_security';

export const Dashboard: React.FC = () => {
  const { 
    isScanning, 
    scanProgress, 
    scanStatus, 
    startScan, 
    pauseScan, 
    resumeScan, 
    stopScan, 
    activeProjectId,
    scanError,
    projects,
  } = useApp();

  const [summaryData, setSummaryData] = useState<GlobalFindingSummaryApiData | null>(null);
  const [apiSummaryData, setApiSummaryData] = useState<ApiSecuritySummaryData | null>(null);

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
    } else {
      setApiSummaryData(null);
    }
  }, [activeProjectId, isScanning]);

  const handleStartScan = () => {
    void startScan(activeProjectId).catch(() => undefined);
  };

  return (
    <div className="p-4 md:p-container-padding max-w-[1600px] mx-auto w-full flex flex-col gap-stack-lg pb-24 relative text-on-surface">

      {/* Personalized Hero Section */}
      <GlassPanel variant="low" className="p-8 rounded-2xl relative overflow-hidden bg-gradient-to-br from-[#11151D]/80 to-[#001c3b]/40 border-l-4 border-l-primary">
        <div className="absolute top-0 left-0 right-0 h-1 shimmer"></div>
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-6 relative z-10">
          <div>
            <h2 className="font-display-lg text-[36px] text-white mb-2 flex items-center gap-3">
              Welcome back, Security Admin
              <span className="material-symbols-outlined text-primary text-3xl animate-bounce">waving_hand</span>
            </h2>
            <div className="flex flex-col sm:flex-row gap-4 mt-4">
              <div className="flex items-center gap-2 text-on-surface-variant bg-surface/50 px-4 py-2 rounded-lg border border-outline-variant/50">
                <span className="material-symbols-outlined text-primary text-sm">verified_user</span>
                <span className="text-sm">Kyptic protecting <strong className="text-white">{projects.length}</strong> registered applications.</span>
              </div>
              <div className="flex items-center gap-2 text-on-surface-variant bg-surface/50 px-4 py-2 rounded-lg border border-error/30">
                <span className="material-symbols-outlined text-error text-sm">warning</span>
                <span className="text-sm"><strong className="text-error">{summaryData?.critical ?? 0}</strong> critical vulnerabilities detected across projects.</span>
              </div>
              <div className="flex items-center gap-2 text-on-surface-variant bg-surface/50 px-4 py-2 rounded-lg border border-outline-variant/50">
                <span className="material-symbols-outlined text-tertiary text-sm">history</span>
                <span className="text-sm">Scan status: <strong className="text-white">{isScanning ? 'running...' : 'Idle'}</strong>.</span>
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

            {/* KPI Card 4 */}
            <div className="card-base p-6 rounded-xl relative overflow-hidden group bg-gradient-to-br from-[#11151D] to-[#0d1c22]">
              <div className="absolute top-0 right-0 w-24 h-24 bg-[#a3defe]/5 rounded-full blur-2xl -mr-10 -mt-10 transition-transform group-hover:scale-110"></div>
              <div className="flex justify-between items-start mb-4">
                <span className="font-label-mono text-label-mono text-on-surface-variant uppercase">AI Insights</span>
                <span className="material-symbols-outlined text-[#a3defe]">tips_and_updates</span>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="font-display-lg text-display-lg text-on-surface">8</span>
                <span className="text-sm text-[#a3defe] bg-[#a3defe]/10 px-2 py-0.5 rounded">Ready</span>
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
                    {scanStatus === 'running' || scanStatus === 'paused' ? 'PID: 8892' : 'Engine: Idle'}
                  </span>
                </div>

                {scanStatus === 'idle' || scanStatus === 'stopped' || scanStatus === 'failed' ? (
                  <div className="flex flex-col gap-4 py-2">
                    <p className="text-sm text-on-surface-variant">
                      No scan is currently running. Select an action below to start analyzing source repositories.
                    </p>
                    <div className="flex flex-col sm:flex-row gap-3 mt-2">
                      <button
                        type="button"
                        onClick={handleStartScan}
                        className="flex items-center justify-center gap-2 px-5 py-2.5 rounded-lg bg-primary text-on-primary font-bold hover:brightness-110 active:scale-95 transition-all shadow-[0_4px_15px_rgba(166,200,255,0.2)] text-sm cursor-pointer border-none"
                      >
                        <span className="material-symbols-outlined text-sm">rocket_launch</span>
                        <span>Start Intelligent Scan</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => alert('Upload Project is not connected to the backend yet.')}
                        className="flex items-center justify-center gap-2 px-5 py-2.5 rounded-lg bg-surface-container border border-outline-variant text-on-surface font-semibold hover:border-primary/50 hover:text-primary active:scale-95 transition-all text-sm cursor-pointer"
                      >
                        <span className="material-symbols-outlined text-sm">upload_file</span>
                        <span>Upload Project</span>
                      </button>
                    </div>
                    <div className="mt-2">
                      <button
                        type="button"
                        onClick={() => alert('Generate Report is not connected to the backend yet.')}
                        className="text-xs text-on-surface-variant hover:text-primary transition-colors flex items-center gap-1 bg-transparent border-none cursor-pointer p-0"
                      >
                        <span className="material-symbols-outlined text-sm">summarize</span>
                        <span>Generate Report</span>
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
                      Analysis finished. 14 critical findings were verified by the local RAG engine.
                    </p>
                    <div className="flex gap-3">
                      <button
                        type="button"
                        onClick={() => window.location.href = '/findings'}
                        className="flex items-center justify-center gap-2 px-5 py-2.5 rounded-lg bg-primary text-on-primary font-bold hover:brightness-110 active:scale-95 transition-all text-sm cursor-pointer border-none"
                      >
                        <span className="material-symbols-outlined text-sm">security</span>
                        <span>View Security Findings</span>
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
                      Analyzing <code className="text-primary bg-primary/10 px-1 rounded">auth-microservice-v2</code> repository.
                    </p>
                    <div>
                      <div className="mb-1.5 flex justify-between items-end">
                        <span className="text-xs font-semibold text-white">Deep SAST Pipeline</span>
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
                        <span>Phase: {scanStatus === 'paused' ? 'Paused' : scanProgress <= 20 ? 'Static Analysis' : scanProgress <= 50 ? 'Taint Analysis' : 'RAG Verification'}</span>
                        <span>Est. time remaining: {scanStatus === 'paused' ? 'Paused' : `${Math.ceil((100 - scanProgress) * 0.2)}s`}</span>
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
                          <span>Pause Scan</span>
                        </button>
                      ) : scanStatus === 'paused' ? (
                        <button
                          type="button"
                          onClick={() => void resumeScan().catch(() => undefined)}
                          className="flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg bg-primary text-on-primary hover:brightness-110 transition-all text-xs font-bold cursor-pointer active:scale-95 border-none shadow-[0_0_10px_rgba(166,200,255,0.2)]"
                        >
                          <span className="material-symbols-outlined text-[16px]">play_arrow</span>
                          <span>Resume Scan</span>
                        </button>
                      ) : (
                        <span className="text-xs text-on-surface-variant">Starting scan...</span>
                      )}
                      
                      <button
                        type="button"
                        onClick={() => void stopScan().catch(() => undefined)}
                        className="flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg bg-transparent border border-error/40 text-error hover:bg-error/10 transition-colors text-xs font-semibold cursor-pointer active:scale-95"
                      >
                        <span className="material-symbols-outlined text-[16px]">stop</span>
                        <span>Stop Scan</span>
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
            {/* Chart 1: Donut */}
            <div className="card-base p-6 rounded-xl bg-gradient-to-br from-[#11151D] to-[#0A0D12]">
              <h3 className="font-headline-md text-headline-md text-on-surface mb-6">Severity Distribution</h3>
              <div className="flex justify-center items-center h-48 relative">
                {/* Simulated Donut Chart using clean styling */}
                <div className="w-40 h-40 rounded-full border-[12px] border-surface-container relative shadow-[0_0_30px_rgba(0,0,0,0.5)]">
                  <div className="absolute inset-0 rounded-full border-[12px] border-error transition-all duration-500 hover:scale-105 cursor-pointer" style={{ clipPath: 'polygon(50% 50%, 50% 0, 100% 0, 100% 50%, 50% 50%)', borderColor: '#ffb4ab', zIndex: 3 }}></div>
                  <div className="absolute inset-0 rounded-full border-[12px] border-tertiary transition-all duration-500 hover:scale-105 cursor-pointer" style={{ clipPath: 'polygon(50% 50%, 100% 50%, 100% 100%, 0 100%, 0 80%, 50% 50%)', borderColor: '#ffb782', zIndex: 2 }}></div>
                  <div className="absolute inset-0 rounded-full border-[12px] border-primary transition-all duration-500 hover:scale-105 cursor-pointer" style={{ clipPath: 'polygon(50% 50%, 0 80%, 0 0, 50% 0, 50% 50%)', borderColor: '#a6c8ff', zIndex: 1 }}></div>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className="font-display-lg text-[24px] text-on-surface font-bold">246</span>
                    <span className="font-label-mono text-[10px] text-on-surface-variant">TOTAL</span>
                  </div>
                </div>
              </div>
              <div className="flex justify-center gap-4 mt-6 flex-wrap">
                <div className="flex items-center gap-1.5">
                  <div className="w-3 h-3 rounded-sm bg-error shadow-[0_0_5px_#ffb4ab]"></div>
                  <span className="text-xs text-on-surface-variant">Critical (14)</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <div className="w-3 h-3 rounded-sm bg-tertiary shadow-[0_0_5px_#ffb782]"></div>
                  <span className="text-xs text-on-surface-variant">High (48)</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <div className="w-3 h-3 rounded-sm bg-primary shadow-[0_0_5px_#a6c8ff]"></div>
                  <span className="text-xs text-on-surface-variant">Med (184)</span>
                </div>
              </div>
            </div>

            {/* Chart 2: Area Activity */}
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
                  <path d="M0,45 L10,35 L20,40 L30,20 L40,25 L50,15 L60,30 L70,10 L80,20 L90,5 L100,15 L100,50 L0,50 Z" fill="url(#chartGrad)"></path>
                  <path d="M0,45 L10,35 L20,40 L30,20 L40,25 L50,15 L60,30 L70,10 L80,20 L90,5 L100,15" fill="none" stroke="#3192fc" strokeWidth="2" vectorEffect="non-scaling-stroke"></path>
                  <circle className="animate-pulse" cx="70" cy="10" fill="#10141a" r="2" stroke="#3192fc" strokeWidth="1.5"></circle>
                  <circle className="animate-pulse" cx="90" cy="5" fill="#10141a" r="2" stroke="#3192fc" stroke-width="1.5"></circle>
                </svg>
                <div className="absolute right-4 top-2 bg-surface-container border border-outline-variant px-2 py-1 rounded text-xs text-on-surface z-10 shadow-lg">
                  Peak: 42 Scans
                </div>
              </div>
            </div>
          </div>

          {/* Risk Heat Map Section */}
          <div className="card-base p-6 rounded-xl bg-gradient-to-br from-[#11151D] to-[#0A0D12]">
            <div className="flex justify-between items-center mb-6">
              <h3 className="font-headline-md text-headline-md text-on-surface">Risk Heat Map</h3>
              <button className="text-primary text-sm hover:underline flex items-center gap-1">
                <span>Explore Details</span>
                <span className="material-symbols-outlined text-[16px]">arrow_forward</span>
              </button>
            </div>
            <div className="flex gap-6 h-64">
              <div className="flex-1 grid grid-cols-5 grid-rows-5 gap-1 bg-surface-container/30 p-2 rounded-lg border border-outline-variant/30">
                <div className="bg-error/80 rounded cursor-pointer hover:opacity-80 transition-opacity flex items-center justify-center text-xs text-white/90 font-bold">3</div>
                <div className="bg-error/90 rounded cursor-pointer hover:opacity-80 transition-opacity flex items-center justify-center text-xs text-white/90 font-bold">5</div>
                <div className="bg-error/60 rounded cursor-pointer hover:opacity-80 transition-opacity flex items-center justify-center text-xs text-white/90 font-bold">1</div>
                <div className="bg-tertiary/70 rounded cursor-pointer hover:opacity-80 transition-opacity"></div>
                <div className="bg-tertiary/40 rounded cursor-pointer hover:opacity-80 transition-opacity"></div>

                <div className="bg-error/70 rounded cursor-pointer hover:opacity-80 transition-opacity flex items-center justify-center text-xs text-white/90 font-bold">2</div>
                <div className="bg-tertiary/80 rounded cursor-pointer hover:opacity-80 transition-opacity flex items-center justify-center text-xs text-white/90 font-bold">4</div>
                <div className="bg-tertiary/60 rounded cursor-pointer hover:opacity-80 transition-opacity"></div>
                <div className="bg-primary/50 rounded cursor-pointer hover:opacity-80 transition-opacity"></div>
                <div className="bg-primary/20 rounded cursor-pointer hover:opacity-80 transition-opacity"></div>

                <div className="bg-tertiary/70 rounded cursor-pointer hover:opacity-80 transition-opacity flex items-center justify-center text-xs text-white/90 font-bold">1</div>
                <div className="bg-tertiary/50 rounded cursor-pointer hover:opacity-80 transition-opacity"></div>
                <div className="bg-primary/70 rounded cursor-pointer hover:opacity-80 transition-opacity flex items-center justify-center text-xs text-white/90 font-bold">8</div>
                <div className="bg-primary/40 rounded cursor-pointer hover:opacity-80 transition-opacity"></div>
                <div className="bg-surface-variant rounded cursor-pointer hover:opacity-80 transition-opacity"></div>

                <div className="bg-tertiary/40 rounded cursor-pointer hover:opacity-80 transition-opacity"></div>
                <div className="bg-primary/60 rounded cursor-pointer hover:opacity-80 transition-opacity flex items-center justify-center text-xs text-white/90 font-bold">3</div>
                <div className="bg-primary/30 rounded cursor-pointer hover:opacity-80 transition-opacity"></div>
                <div className="bg-surface-variant rounded cursor-pointer hover:opacity-80 transition-opacity"></div>
                <div className="bg-surface-variant rounded cursor-pointer hover:opacity-80 transition-opacity"></div>

                <div className="bg-primary/30 rounded cursor-pointer hover:opacity-80 transition-opacity"></div>
                <div className="bg-surface-variant rounded cursor-pointer hover:opacity-80 transition-opacity"></div>
                <div className="bg-surface-variant rounded cursor-pointer hover:opacity-80 transition-opacity"></div>
                <div className="bg-surface-variant rounded cursor-pointer hover:opacity-80 transition-opacity"></div>
                <div className="bg-surface-variant rounded cursor-pointer hover:opacity-80 transition-opacity"></div>
              </div>
              <div className="w-1/3 flex flex-col justify-between">
                <div>
                  <h4 className="text-sm font-medium text-on-surface mb-2">Exposure Trend</h4>
                  <div className="h-20 w-full relative">
                    <svg className="w-full h-full" preserveAspectRatio="none" viewBox="0 0 100 30">
                      <path d="M0,25 L20,15 L40,20 L60,10 L80,15 L100,5" fill="none" stroke="#ffb4ab" strokeWidth="2"></path>
                    </svg>
                  </div>
                </div>
                <div className="bg-surface-container/50 p-3 rounded-lg border border-outline-variant/30">
                  <span className="text-xs text-on-surface-variant block mb-1">Most Critical Asset</span>
                  <span className="text-sm text-white font-mono bg-surface px-2 py-1 rounded inline-block">Payment-Gateway-API</span>
                </div>
              </div>
            </div>
          </div>

          {/* Recent Critical Findings Table */}
          <div className="card-base rounded-xl overflow-hidden bg-gradient-to-br from-[#11151D] to-[#0A0D12]">
            <div className="p-6 border-b border-outline-variant flex justify-between items-center bg-surface-container-low/50">
              <h3 className="font-headline-md text-headline-md text-on-surface">Recent Critical Findings</h3>
              <button className="text-primary font-medium text-sm hover:underline">View All</button>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-[#11151D]/50 border-b border-outline-variant">
                    <th className="px-6 py-4 font-label-mono text-label-mono text-on-surface-variant uppercase font-medium">Severity</th>
                    <th className="px-6 py-4 font-label-mono text-label-mono text-on-surface-variant uppercase font-medium">Title</th>
                    <th className="px-6 py-4 font-label-mono text-label-mono text-on-surface-variant uppercase font-medium">CWE / Category</th>
                    <th className="px-6 py-4 font-label-mono text-label-mono text-on-surface-variant uppercase font-medium text-center">AI Conf.</th>
                    <th className="px-6 py-4 font-label-mono text-label-mono text-on-surface-variant uppercase font-medium">Status</th>
                  </tr>
                </thead>
                <tbody className="font-body-md text-body-md">
                  <tr className="border-b border-outline-variant hover:bg-surface-container/50 transition-colors group cursor-pointer">
                    <td className="px-6 py-4">
                      <Badge variant="critical" pulse={true}>Critical</Badge>
                    </td>
                    <td className="px-6 py-4 text-on-surface font-medium">SQL Injection in Auth Module</td>
                    <td className="px-6 py-4 text-on-surface-variant text-sm">CWE-89 <span className="text-outline">|</span> Injection</td>
                    <td className="px-6 py-4 text-center">
                      <span className="inline-flex items-center gap-1 text-[#a3defe] text-sm">
                        <span className="material-symbols-outlined text-[16px]">psychology</span> 98%
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <span className="text-on-surface-variant text-sm border border-outline-variant px-2 py-1 rounded bg-surface/50">Open</span>
                    </td>
                  </tr>
                  <tr className="border-b border-outline-variant hover:bg-surface-container/50 transition-colors group cursor-pointer">
                    <td className="px-6 py-4">
                      <Badge variant="critical" pulse={true}>Critical</Badge>
                    </td>
                    <td className="px-6 py-4 text-on-surface font-medium">RCE via Deserialization</td>
                    <td className="px-6 py-4 text-on-surface-variant text-sm">CWE-502 <span className="text-outline">|</span> Insecure Deser.</td>
                    <td className="px-6 py-4 text-center">
                      <span className="inline-flex items-center gap-1 text-[#a3defe] text-sm">
                        <span className="material-symbols-outlined text-[16px]">psychology</span> 94%
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <Badge variant="high">Investigating</Badge>
                    </td>
                  </tr>
                  <tr className="hover:bg-surface-container/50 transition-colors group cursor-pointer">
                    <td className="px-6 py-4">
                      <Badge variant="high" pulse={false}>High</Badge>
                    </td>
                    <td className="px-6 py-4 text-on-surface font-medium">Stored XSS in User Profile</td>
                    <td className="px-6 py-4 text-on-surface-variant text-sm">CWE-79 <span className="text-outline">|</span> XSS</td>
                    <td className="px-6 py-4 text-center">
                      <span className="inline-flex items-center gap-1 text-[#a3defe] text-sm">
                        <span className="material-symbols-outlined text-[16px]">psychology</span> 87%
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <span className="text-on-surface-variant text-sm border border-outline-variant px-2 py-1 rounded bg-surface/50">Open</span>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Right Column (Score & AI) */}
        <div className="md:col-span-4 flex flex-col gap-gutter">
          {/* Main Score Gauge */}
          <div className="card-base p-8 rounded-xl flex flex-col items-center justify-center relative glow-box-primary bg-gradient-to-b from-[#11151D] to-[#0A0D12]">
            <h3 className="font-label-mono text-label-mono text-on-surface-variant uppercase absolute top-6 left-6 tracking-wider">Overall Posture</h3>
            <div className="absolute top-6 right-6 text-[#a3defe] bg-[#a3defe]/10 px-2.5 py-1 rounded border border-[#a3defe]/20 text-xs font-semibold flex items-center gap-1">
              <span className="material-symbols-outlined text-[14px]">shield_locked</span> Low Risk
            </div>
            <div className="mt-8 mb-4 relative w-48 h-48 flex items-center justify-center">
              {/* SVG Gauge */}
              <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                <circle cx="50" cy="50" fill="none" r="45" stroke="#1F242D" strokeLinecap="round" strokeWidth="8"></circle>
                <circle 
                  className="drop-shadow-[0_0_12px_rgba(49,146,252,0.8)] transition-all duration-1000" 
                  cx="50" cy="50" fill="none" r="45" stroke="url(#blueGrad)" 
                  strokeDasharray="282.7" 
                  strokeDashoffset={282.7 - (282.7 * 87) / 100} 
                  strokeLinecap="round" strokeWidth="8"
                ></circle>
                <defs>
                  <linearGradient id="blueGrad" x1="0%" x2="100%" y1="0%" y2="100%">
                    <stop offset="0%" stopColor="#a6c8ff"></stop>
                    <stop offset="100%" stopColor="#3192fc"></stop>
                  </linearGradient>
                </defs>
              </svg>
              <div className="absolute flex flex-col items-center justify-center text-center">
                <span className="font-display-lg text-[56px] font-bold text-white glow-text leading-none">87</span>
                <span className="text-on-surface-variant text-sm mt-1">/ 100</span>
              </div>
            </div>
            <div className="flex items-center gap-2 mt-2 bg-surface px-4 py-2 rounded-full border border-outline-variant shadow-inner">
              <span className="material-symbols-outlined text-[16px] text-[#4ade80]">trending_up</span>
              <span className="text-sm font-medium text-[#4ade80]">+2.4%</span>
              <span className="text-xs text-on-surface-variant">vs last month</span>
            </div>
          </div>

          {/* Advanced AI Recommendation Panel */}
          <div className="glass-panel rounded-xl p-6 relative overflow-hidden bg-gradient-to-b from-[#11151D]/90 to-[#0A0D12]/90 border border-[#2E90FA]/30 shadow-[0_0_15px_rgba(46,144,250,0.1)]">
            {/* Shimmer decoration */}
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
              {/* Action Card 1 */}
              <div className="bg-[#0A0D12]/80 border border-[#1F242D] hover:border-error/50 transition-all duration-300 rounded-lg p-4 cursor-pointer group shadow-md hover:shadow-[0_0_10px_rgba(255,180,171,0.2)]">
                <div className="flex justify-between items-start mb-2">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-error animate-ping"></span>
                    <span className="text-sm font-semibold text-white">Recommended Fix</span>
                  </div>
                  <span className="material-symbols-outlined text-on-surface-variant text-sm group-hover:text-error transition-colors">auto_fix_high</span>
                </div>
                <p className="text-sm text-on-surface-variant leading-relaxed">
                  Rotate compromised API keys for <code className="font-code-sm text-error bg-error/10 px-1 py-0.5 rounded border border-error/20">Prod-DB-01</code> immediately.
                </p>
                <div className="mt-3 flex items-center gap-2 text-xs text-on-surface-variant mb-3">
                  <span className="material-symbols-outlined text-[14px]">timer</span> Est. remediation: ~5 mins
                </div>
                <button 
                  onClick={() => alert('Rotating API keys playbook initiated...')}
                  className="text-xs font-medium text-black bg-gradient-to-r from-error to-[#ffdad6] px-3 py-1.5 rounded hover:opacity-90 transition-opacity w-full shadow-md cursor-pointer"
                >
                  Execute Rotation Playbook
                </button>
              </div>

              {/* Action Card 2 */}
              <div className="bg-[#0A0D12]/80 border border-[#1F242D] hover:border-tertiary/50 transition-all duration-300 rounded-lg p-4 cursor-pointer group shadow-md hover:shadow-[0_0_10px_rgba(255,183,130,0.2)]">
                <div className="flex justify-between items-start mb-2">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-tertiary"></span>
                    <span className="text-sm font-semibold text-white">AI Insight</span>
                  </div>
                  <span className="material-symbols-outlined text-on-surface-variant text-sm group-hover:text-tertiary transition-colors">lightbulb</span>
                </div>
                <p className="text-sm text-on-surface-variant leading-relaxed">
                  Patch <code className="font-code-sm text-on-surface bg-surface px-1 py-0.5 rounded border border-outline-variant">CVE-2023-45678</code> in <code className="font-code-sm text-on-surface bg-surface px-1 py-0.5 rounded border border-outline-variant">Gateway-Service</code>.
                </p>
                <div className="mt-3 flex items-center gap-2 text-xs text-on-surface-variant mb-3">
                  <span className="material-symbols-outlined text-[14px]">timer</span> Est. remediation: ~15 mins
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-outline">Confidence: 94%</span>
                  <div className="flex-1 h-1 bg-surface-container rounded-full overflow-hidden">
                    <div className="h-full bg-tertiary w-[94%]"></div>
                  </div>
                </div>
              </div>

              <button 
                onClick={() => alert('Redirecting to AI Copilot...')}
                className="mt-2 w-full flex justify-center items-center gap-2 py-3 rounded-lg bg-[#11151D] border border-primary/50 text-primary hover:bg-primary/10 transition-colors font-medium cursor-pointer"
              >
                <span className="material-symbols-outlined">forum</span> Open AI Chat
              </button>
            </div>
          </div>

          {/* Expanded Compliance Mini Widget */}
          <div className="card-base p-6 rounded-xl bg-gradient-to-br from-[#11151D] to-[#0A0D12]">
            <h3 className="font-label-mono text-label-mono text-on-surface-variant uppercase mb-4 tracking-wider">Compliance Overview</h3>
            <div className="flex flex-col gap-4">
              <div>
                <div className="flex justify-between text-sm mb-1.5">
                  <span className="text-white font-medium">OWASP Top 10</span>
                  <span className="text-primary font-code-sm">95%</span>
                </div>
                <div className="w-full h-1.5 bg-surface-container-highest rounded-full overflow-hidden">
                  <div className="h-full bg-primary rounded-full shadow-[0_0_5px_#a6c8ff]" style={{ width: '95%' }}></div>
                </div>
              </div>
              <div>
                <div className="flex justify-between text-sm mb-1.5">
                  <span className="text-white font-medium">SOC 2 Type II</span>
                  <span className="text-primary font-code-sm">92%</span>
                </div>
                <div className="w-full h-1.5 bg-surface-container-highest rounded-full overflow-hidden">
                  <div className="h-full bg-primary rounded-full shadow-[0_0_5px_#a6c8ff]" style={{ width: '92%' }}></div>
                </div>
              </div>
              <div>
                <div className="flex justify-between text-sm mb-1.5">
                  <span className="text-white font-medium">ISO 27001</span>
                  <span className="text-primary font-code-sm">85%</span>
                </div>
                <div className="w-full h-1.5 bg-surface-container-highest rounded-full overflow-hidden">
                  <div className="h-full bg-primary rounded-full shadow-[0_0_5px_#a6c8ff]" style={{ width: '85%' }}></div>
                </div>
              </div>
              <div>
                <div className="flex justify-between text-sm mb-1.5">
                  <span className="text-white font-medium">PCI DSS</span>
                  <span className="text-tertiary font-code-sm">68%</span>
                </div>
                <div className="w-full h-1.5 bg-surface-container-highest rounded-full overflow-hidden">
                  <div className="h-full bg-tertiary rounded-full shadow-[0_0_5px_#ffb782]" style={{ width: '68%' }}></div>
                </div>
              </div>
              <div className="mt-2 pt-4 border-t border-outline-variant/30 flex justify-between text-xs text-on-surface-variant">
                <span>CWE Coverage: <strong className="text-white">89%</strong></span>
                <span>Avg CVSS: <strong className="text-white">4.2</strong></span>
              </div>
            </div>
          </div>

          {/* Recent Activity Timeline */}
          <div className="card-base p-6 rounded-xl bg-gradient-to-br from-[#11151D] to-[#0A0D12]">
            <h3 className="font-label-mono text-label-mono text-on-surface-variant uppercase mb-4 tracking-wider">Recent Activity</h3>
            <div className="relative border-l border-outline-variant/50 ml-3 space-y-6">
              <div className="relative pl-6">
                <span className="absolute -left-1.5 top-1 w-3 h-3 rounded-full bg-primary ring-4 ring-[#11151D]"></span>
                <div className="text-xs text-on-surface-variant mb-1">3 mins ago</div>
                <p className="text-sm text-white font-medium">Scheduled SAST Scan Completed</p>
                <p className="text-xs text-on-surface-variant mt-1">Found 2 new vulnerabilities in core-api.</p>
              </div>
              <div className="relative pl-6">
                <span className="absolute -left-1.5 top-1 w-3 h-3 rounded-full bg-tertiary ring-4 ring-[#11151D]"></span>
                <div className="text-xs text-on-surface-variant mb-1">1 hour ago</div>
                <p className="text-sm text-white font-medium">AI Playbook Executed</p>
                <p className="text-xs text-on-surface-variant mt-1">Automated patch applied to frontend-repo.</p>
              </div>
              <div className="relative pl-6">
                <span className="absolute -left-1.5 top-1 w-3 h-3 rounded-full bg-surface-variant ring-4 ring-[#11151D]"></span>
                <div className="text-xs text-on-surface-variant mb-1">Yesterday, 14:30</div>
                <p className="text-sm text-white font-medium">New Project Onboarded</p>
                <p className="text-xs text-on-surface-variant mt-1">payment-gateway-v3 added to scope.</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
