import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useApp } from '../../context/AppContext';
import { fetchApiEndpoints, type ApiEndpointData } from '../../api/api_security';

interface GraphNode {
  id: string;
  label: string;
  type: 'root' | 'module' | 'controller' | 'endpoint' | 'db';
  status: 'safe' | 'warning' | 'critical';
  icon: string;
  x: number;
  y: number;
  score?: number;
  details?: {
    vulnName?: string;
    owasp?: string;
    cwe?: string;
    cvss?: number;
    description?: string;
    sastDesc?: string;
    sastCode?: string;
    dastDesc?: string;
  };
}

export const RiskMap: React.FC = () => {
  const navigate = useNavigate();
  const { activeProjectId } = useApp();

  // Graph state: active node, zoom factor, explorer expanded state
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>('node-endpoint-login');
  const [zoomScale, setZoomScale] = useState<number>(0.9);
  const [isExplorerExpanded, setIsExplorerExpanded] = useState<boolean>(true);
  const [apiEndpoints, setApiEndpoints] = useState<ApiEndpointData[]>([]);

  useEffect(() => {
    if (activeProjectId && !isNaN(Number(activeProjectId))) {
      void fetchApiEndpoints(Number(activeProjectId))
        .then(setApiEndpoints)
        .catch(() => setApiEndpoints([]));
    }
  }, [activeProjectId]);

  // Nodes database
  const staticNodes: GraphNode[] = [
    {
      id: 'node-root',
      label: 'Core Backend',
      type: 'root',
      status: 'safe',
      icon: 'dns',
      x: 100,
      y: 370,
      score: 92,
      details: {
        vulnName: 'No Vulnerabilities',
        owasp: 'N/A',
        cwe: 'N/A',
        cvss: 0,
        description: 'Core Backend routing hub. Provisoned correctly and validated by AI gateway agent checks.',
        sastDesc: 'All dynamic models pass core SAST code checks.',
        dastDesc: 'No endpoint fuzz failures detected.'
      }
    },
    {
      id: 'node-auth-mod',
      label: 'Auth Module',
      type: 'module',
      status: 'warning',
      icon: 'folder',
      x: 350,
      y: 270,
      score: 68,
      details: {
        vulnName: 'Authentication Issues',
        owasp: 'A07:2021',
        cwe: 'CWE-287',
        cvss: 7.2,
        description: 'Auth sub-module controls keys, tokens, and credentials session management logic.',
        sastDesc: 'AWS secret key leak detected in deployment.yaml configuration.',
        dastDesc: 'Weak JWT signature validated.'
      }
    },
    {
      id: 'node-user-mod',
      label: 'User Mgmt',
      type: 'module',
      status: 'safe',
      icon: 'folder',
      x: 350,
      y: 470,
      score: 95,
      details: {
        vulnName: 'No Vulnerabilities',
        owasp: 'N/A',
        cwe: 'N/A',
        cvss: 0,
        description: 'User registration, roles, and profiles administrative module.',
        sastDesc: 'No SQL injection or authorization bypasses detected.',
        dastDesc: 'All profile endpoints returned 200 OK without errors.'
      }
    },
    {
      id: 'node-controller-auth',
      label: 'authController',
      type: 'controller',
      status: 'critical',
      icon: 'code',
      x: 600,
      y: 270,
      score: 9.8,
      details: {
        vulnName: 'SQL Injection',
        owasp: 'A03:2021',
        cwe: 'CWE-89',
        cvss: 9.8,
        description: 'Controller methods process login, logout, session refresh, and token sign procedures.',
        sastDesc: 'Raw dynamic query builder handles unescaped username inputs.',
        sastCode: "const query = `SELECT * FROM users WHERE username = '${username}'`;",
        dastDesc: 'Dynamic fuzz injection bypasses verification check.'
      }
    },
    {
      id: 'node-endpoint-login',
      label: '/api/v1/auth/login',
      type: 'endpoint',
      status: 'critical',
      icon: 'api',
      x: 850,
      y: 170,
      score: 9.8,
      details: {
        vulnName: 'SQL Injection (Blind)',
        owasp: 'A03:2021',
        cwe: 'CWE-89',
        cvss: 9.8,
        description: 'Vulnerable authentication login gateway processing unvalidated database select calls.',
        sastDesc: "Unsanitized input 'req.body.username' passed directly to query builder in authController.js:42.",
        sastCode: "const user = await db.query(`SELECT * FROM users WHERE username = '${req.body.username}'`);",
        dastDesc: 'Vulnerability confirmed exploitable via Blind SQL Injection technique during active scan.'
      }
    },
    {
      id: 'node-endpoint-refresh',
      label: '/api/v1/auth/refresh',
      type: 'endpoint',
      status: 'safe',
      icon: 'api',
      x: 850,
      y: 370,
      score: 100,
      details: {
        vulnName: 'No Vulnerabilities',
        owasp: 'N/A',
        cwe: 'N/A',
        cvss: 0,
        description: 'Refreshes JWT access tokens based on valid HTTP session cookies check.',
        sastDesc: 'Validation logic cryptographically secure.',
        dastDesc: 'Fuzzing did not disclose any timing anomalies.'
      }
    }
  ];

  const dynamicApiNodes: GraphNode[] = apiEndpoints.map((ep, idx) => {
    const isCrit = ep.risk_level === 'CRITICAL' || ep.risk_level === 'HIGH';
    const isWarn = ep.risk_level === 'MEDIUM';
    return {
      id: `dynamic-api-${ep.id}`,
      label: `${ep.method} ${ep.path}`,
      type: 'endpoint',
      status: isCrit ? 'critical' : isWarn ? 'warning' : 'safe',
      icon: 'api',
      x: 850 + (idx % 2 === 0 ? 0 : 40),
      y: 450 + (idx + 1) * 90,
      score: ep.risk_score,
      details: {
        vulnName: ep.summary || `API Asset: ${ep.method} ${ep.path}`,
        owasp: `Auth: ${ep.auth_status} | BOLA: ${ep.bola_status || 'N/A'}`,
        cwe: `OWASP API Security Top 10`,
        cvss: ep.risk_score,
        description: `API Endpoint ${ep.method} ${ep.path}. Auth Status: ${ep.auth_status}. Validation: ${ep.request_validation_status}. Rate Limit: ${ep.rate_limit_status}.`,
        sastDesc: `Sensitive Data Fields: ${ep.sensitive_data_fields || 'None'}. Mass Assignment: ${ep.mass_assignment_status || 'NOT_EVALUATED'}.`,
        dastDesc: `DAST Active Verification Status: ${ep.dast_status || 'UNTESTED'}`,
      },
    };
  });

  const nodes: GraphNode[] = [...staticNodes, ...dynamicApiNodes];

  // Resolve active detail matching
  const selectedNode = selectedNodeId ? nodes.find(n => n.id === selectedNodeId) : null;

  const handleZoomIn = () => setZoomScale(prev => Math.min(1.5, prev + 0.1));
  const handleZoomOut = () => setZoomScale(prev => Math.max(0.5, prev - 0.1));
  const handleResetZoom = () => setZoomScale(0.9);

  return (
    <div className="flex-1 flex h-[calc(100vh-64px)] overflow-hidden text-on-surface select-none">
      
      {/* Left Panel: File Explorer */}
      {isExplorerExpanded ? (
        <aside className="w-80 flex-shrink-0 border-r border-outline-variant/30 bg-surface-container-lowest flex flex-col h-full transition-all duration-300">
          <div className="p-4 border-b border-outline-variant/30 flex items-center justify-between">
            <h2 className="font-label-mono text-label-mono text-on-surface-variant uppercase tracking-wider">File Explorer</h2>
            <button 
              onClick={() => setIsExplorerExpanded(false)}
              className="text-on-surface-variant hover:text-on-surface cursor-pointer bg-transparent border-none"
              title="Collapse Panel"
            >
              <span className="material-symbols-outlined text-[18px]">menu_open</span>
            </button>
          </div>
          
          <div className="p-4 border-b border-outline-variant/20 flex flex-col gap-2 shrink-0">
            <div className="relative">
              <span className="material-symbols-outlined absolute left-2.5 top-1/2 -translate-y-1/2 text-on-surface-variant text-[16px]">search</span>
              <input
                type="text"
                placeholder="Search application files..."
                className="w-full bg-[#0A0D12] border border-[#1F242D] rounded pl-8 pr-3 py-1 text-xs text-on-surface focus:outline-none"
              />
            </div>
            
            <div className="flex gap-2 mb-2 overflow-x-auto pb-2 scrollbar-hide">
              <span className="px-3 py-1 rounded-full bg-error/10 border border-error/20 text-error text-[10px] whitespace-nowrap flex items-center gap-1">
                <span className="w-1 h-1 rounded-full bg-error"></span> Critical
              </span>
              <span className="px-3 py-1 rounded-full bg-[#1c2026] border border-[#1F242D] text-on-surface-variant text-[10px] whitespace-nowrap">REST API</span>
              <span className="px-3 py-1 rounded-full bg-[#1c2026] border border-[#1F242D] text-on-surface-variant text-[10px] whitespace-nowrap">OWASP A01</span>
            </div>
          </div>

          {/* Tree View list */}
          <div className="flex-1 overflow-y-auto p-2 space-y-1 text-sm font-label-mono">
            <div className="flex flex-col">
              <div 
                onClick={() => setSelectedNodeId('node-root')}
                className={`flex items-center gap-2 p-2 hover:bg-surface-container-high rounded cursor-pointer ${
                  selectedNodeId === 'node-root' ? 'bg-surface-container-high text-primary font-bold' : 'text-on-surface'
                }`}
              >
                <span className="material-symbols-outlined text-sm text-primary">keyboard_arrow_down</span>
                <span className="material-symbols-outlined text-sm text-primary">dns</span>
                <span className="truncate">Core Backend (v2.4.1)</span>
              </div>

              <div className="pl-6 space-y-1 border-l border-[#1F242D] ml-4 mt-1">
                {/* Auth Module */}
                <div className="flex flex-col">
                  <div 
                    onClick={() => setSelectedNodeId('node-auth-mod')}
                    className={`flex items-center gap-2 p-2 hover:bg-surface-container-high rounded cursor-pointer ${
                      selectedNodeId === 'node-auth-mod' ? 'bg-surface-container-high text-primary font-bold' : 'text-on-surface'
                    }`}
                  >
                    <span className="material-symbols-outlined text-sm text-primary">keyboard_arrow_down</span>
                    <span className="material-symbols-outlined text-sm text-tertiary">folder</span>
                    <span className="truncate">Auth Module</span>
                  </div>

                  <div className="pl-6 space-y-1 border-l border-[#1F242D] ml-4 mt-1">
                    <div className="flex flex-col">
                      <div 
                        onClick={() => setSelectedNodeId('node-controller-auth')}
                        className={`flex items-center gap-2 p-2 hover:bg-surface-container-high rounded cursor-pointer ${
                          selectedNodeId === 'node-controller-auth' ? 'bg-surface-container-high text-primary font-bold' : 'text-on-surface'
                        }`}
                      >
                        <span className="material-symbols-outlined text-sm text-primary">keyboard_arrow_down</span>
                        <span className="material-symbols-outlined text-sm text-outline">code</span>
                        <span className="truncate">authController.js</span>
                      </div>

                      <div className="pl-6 space-y-1 border-l border-[#1F242D] ml-4 mt-1">
                        {/* /api/v1/auth/login */}
                        <div 
                          onClick={() => setSelectedNodeId('node-endpoint-login')}
                          className={`flex items-center justify-between p-2 rounded cursor-pointer border ${
                            selectedNodeId === 'node-endpoint-login'
                              ? 'bg-error/20 border-error/50 text-error font-bold'
                              : 'bg-error/10 border-error/20 text-error/85 hover:bg-error/15'
                          }`}
                        >
                          <div className="flex items-center gap-2">
                            <span className="px-1.5 py-0.5 rounded bg-error/20 text-[9px] font-bold">POST</span>
                            <span className="text-[12px] truncate">/api/v1/auth/login</span>
                          </div>
                          <span className="material-symbols-outlined text-sm">warning</span>
                        </div>

                        {/* /api/v1/auth/refresh */}
                        <div 
                          onClick={() => setSelectedNodeId('node-endpoint-refresh')}
                          className={`flex items-center gap-2 p-2 hover:bg-surface-container-high rounded cursor-pointer ${
                            selectedNodeId === 'node-endpoint-refresh' ? 'bg-surface-container-high text-primary font-bold' : 'text-on-surface-variant'
                          }`}
                        >
                          <span className="px-1.5 py-0.5 rounded bg-surface-container-high border border-outline-variant text-[9px] font-bold">POST</span>
                          <span className="text-[12px] truncate">/api/v1/auth/refresh</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* User management */}
                <div 
                  onClick={() => setSelectedNodeId('node-user-mod')}
                  className="flex items-center gap-2 p-2 hover:bg-surface-container-high rounded cursor-pointer text-on-surface-variant"
                >
                  <span className="material-symbols-outlined text-sm">keyboard_arrow_right</span>
                  <span className="material-symbols-outlined text-sm text-outline">folder</span>
                  <span className="truncate">User Management</span>
                </div>
              </div>
            </div>
          </div>
        </aside>
      ) : (
        <div className="w-12 border-r border-outline-variant/30 bg-surface-container-lowest flex flex-col items-center py-4 select-none shrink-0">
          <button 
            onClick={() => setIsExplorerExpanded(true)}
            className="text-on-surface-variant hover:text-on-surface cursor-pointer bg-transparent border-none"
            title="Expand File Explorer"
          >
            <span className="material-symbols-outlined text-[20px]">menu</span>
          </button>
        </div>
      )}

      {/* Center Canvas: The Graph Visualization */}
      <div 
        onClick={() => setSelectedNodeId(null)}
        className="flex-1 relative bg-[#06070A] overflow-hidden"
      >
        {/* Background Grid */}
        <div 
          className="absolute inset-0 opacity-20" 
          style={{ 
            backgroundImage: 'radial-gradient(#1F242D 1px, transparent 1px)', 
            backgroundSize: '32px 32px' 
          }}
        />

        {/* Central Graph Render */}
        <div 
          className="absolute inset-0 z-10 transition-transform duration-300 transform origin-center"
          style={{ transform: `scale(${zoomScale}) translate(60px, 0px)` }}
        >
          {/* SVG Connection Lines */}
          <svg className="absolute inset-0 w-full h-full pointer-events-none z-0">
            {/* Backend to Auth Module */}
            <path d="M 150 400 L 400 300" fill="none" stroke={selectedNodeId === 'node-root' || selectedNodeId === 'node-auth-mod' ? '#2E90FA' : '#1F242D'} strokeWidth="2" />
            {/* Backend to User Module */}
            <path d="M 150 400 L 400 500" fill="none" stroke={selectedNodeId === 'node-root' || selectedNodeId === 'node-user-mod' ? '#2E90FA' : '#1F242D'} strokeWidth="2" />
            {/* Auth Module to authController */}
            <path d="M 400 300 L 650 300" fill="none" stroke={selectedNodeId === 'node-auth-mod' || selectedNodeId === 'node-controller-auth' ? '#2E90FA' : '#1F242D'} strokeWidth="2" />
            {/* authController to /api/v1/auth/login (Critical) */}
            <path 
              className="animate-pulse" 
              d="M 650 300 L 900 200" 
              fill="none" 
              stroke={selectedNodeId === 'node-controller-auth' || selectedNodeId === 'node-endpoint-login' ? '#ff4d4d' : '#8a1f1f'} 
              strokeDasharray="4" 
              strokeWidth="2.5" 
            />
            {/* authController to /api/v1/auth/refresh */}
            <path d="M 650 300 L 900 400" fill="none" stroke={selectedNodeId === 'node-controller-auth' || selectedNodeId === 'node-endpoint-refresh' ? '#2E90FA' : '#1F242D'} strokeWidth="2" />
          </svg>

          {/* Nodes list */}
          {nodes.map((node) => {
            const isSelected = selectedNodeId === node.id;
            const isNodeCritical = node.status === 'critical';
            const isNodeWarning = node.status === 'warning';
            
            // Positioning variables
            const style = {
              top: `${node.y}px`,
              left: `${node.x}px`
            };

            return (
              <div 
                key={node.id}
                onClick={(e) => {
                  e.stopPropagation();
                  setSelectedNodeId(node.id);
                }}
                style={style}
                className={`absolute flex flex-col items-center gap-2 group cursor-pointer z-10 select-none ${
                  node.status === 'critical' ? 'pulse-critical' : ''
                }`}
              >
                {node.type === 'endpoint' ? (
                  <div className={`px-4 py-2 rounded-lg border transition-all ${
                    isNodeCritical 
                      ? isSelected 
                        ? 'bg-error/30 border-error shadow-[0_0_15px_rgba(255,77,77,0.3)] scale-105' 
                        : 'bg-error/15 border-error/50 group-hover:scale-105'
                      : isSelected 
                        ? 'bg-primary/20 border-primary scale-105' 
                        : 'bg-surface-container-low border-outline-variant hover:border-primary/50 group-hover:scale-105'
                  }`}>
                    <div className="flex items-center gap-2 font-label-mono text-xs">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${isNodeCritical ? 'bg-error/20 text-error' : 'bg-surface-container-highest text-outline'}`}>
                        POST
                      </span>
                      <span className="text-on-surface font-semibold">{node.label}</span>
                      {isNodeCritical && (
                        <span className="material-symbols-outlined text-error text-xs animate-ping">warning</span>
                      )}
                    </div>

                    {isNodeCritical && (
                      <div className="absolute top-14 left-1/2 transform -translate-x-1/2 w-48 bg-[#11151D] border border-error/50 rounded p-2 shadow-[0_0_20px_rgba(255,77,77,0.15)] flex flex-col gap-1 z-30">
                        <div className="text-xs text-error font-bold flex items-center gap-1">
                          <span className="material-symbols-outlined text-sm">bug_report</span> 
                          SQL Injection
                        </div>
                        <div className="text-[10px] text-on-surface-variant font-label-mono">Risk Score: 9.8 (CRITICAL)</div>
                      </div>
                    )}
                  </div>
                ) : (
                  <>
                    <div className={`w-14 h-14 rounded-2xl border transition-all flex items-center justify-center ${
                      isSelected 
                        ? 'bg-primary-container/20 border-primary shadow-[0_0_15px_rgba(46,144,250,0.3)] scale-110'
                        : isNodeCritical 
                          ? 'bg-error/10 border-error/50 group-hover:scale-110' 
                          : isNodeWarning 
                            ? 'bg-[#ff9800]/10 border-[#ff9800]/50 group-hover:scale-110' 
                            : 'bg-surface-container border-outline-variant group-hover:scale-110'
                    }`}>
                      <span className={`material-symbols-outlined text-2xl ${
                        isNodeCritical ? 'text-error' : isNodeWarning ? 'text-[#ff9800]' : 'text-primary'
                      }`}>
                        {node.icon}
                      </span>
                    </div>
                    <span className={`text-xs font-label-mono bg-[#0A0D12]/80 px-2 py-0.5 rounded border ${
                      isSelected ? 'text-primary border-primary/30' : 'text-on-surface-variant border-[#1F242D]'
                    }`}>
                      {node.label}
                    </span>
                  </>
                )}
              </div>
            );
          })}
        </div>

        {/* Zoom Controls */}
        <div className="absolute bottom-6 right-6 flex flex-col gap-2 z-30 select-none">
          <button 
            onClick={handleZoomIn}
            className="w-10 h-10 rounded-full glass-panel flex items-center justify-center text-on-surface hover:text-primary hover:border-primary/50 transition-all cursor-pointer"
          >
            <span className="material-symbols-outlined">add</span>
          </button>
          <button 
            onClick={handleZoomOut}
            className="w-10 h-10 rounded-full glass-panel flex items-center justify-center text-on-surface hover:text-primary hover:border-primary/50 transition-all cursor-pointer"
          >
            <span className="material-symbols-outlined">remove</span>
          </button>
          <button 
            onClick={handleResetZoom}
            className="w-10 h-10 rounded-full glass-panel flex items-center justify-center text-on-surface hover:text-primary hover:border-primary/50 transition-all cursor-pointer"
          >
            <span className="material-symbols-outlined">fit_screen</span>
          </button>
        </div>
      </div>

      {/* Right Sidebar: Selected Node Details */}
      <aside className="w-96 border-l border-outline-variant/30 bg-surface-container-lowest flex flex-col z-10 shrink-0 relative glass-panel shadow-[-10px_0_30px_rgba(0,0,0,0.5)]">
        {selectedNode ? (
          <>
            {/* Detail Header */}
            <div className="p-4 border-b border-outline-variant/30 flex justify-between items-start select-none">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-label-mono font-bold border uppercase ${
                    selectedNode.status === 'critical' ? 'bg-error/20 text-error border-error/30' : 'bg-surface-container-high text-outline border-outline-variant/40'
                  }`}>
                    {selectedNode.type}
                  </span>
                  <span className="text-xs text-outline font-label-mono">Asset Details</span>
                </div>
                <h2 className="font-label-mono text-on-surface text-sm break-all font-semibold select-all" title={selectedNode.label}>
                  {selectedNode.label}
                </h2>
              </div>
              <button 
                onClick={(e) => {
                  e.stopPropagation();
                  setSelectedNodeId(null);
                }}
                className="text-outline hover:text-on-surface transition-colors cursor-pointer bg-transparent border-none"
                title="Deselect node"
              >
                <span className="material-symbols-outlined">close</span>
              </button>
            </div>

            {/* Detail Content */}
            <div className="flex-grow overflow-y-auto p-4 space-y-6">
              
              {/* Score Header */}
              {selectedNode.status === 'critical' ? (
                <div className="flex items-center gap-4 p-4 rounded-xl bg-gradient-to-r from-error/10 to-transparent border border-error/20">
                  <div className="text-4xl font-display-lg text-error font-bold select-all">9.8</div>
                  <div className="flex flex-col">
                    <span className="text-sm font-bold text-error uppercase tracking-wider">Critical Risk</span>
                    <span className="text-xs text-on-surface-variant">Immediate action required</span>
                  </div>
                </div>
              ) : selectedNode.status === 'warning' ? (
                <div className="flex items-center gap-4 p-4 rounded-xl bg-gradient-to-r from-[#ff9800]/10 to-transparent border border-[#ff9800]/20">
                  <div className="text-4xl font-display-lg text-[#ff9800] font-bold select-all">7.2</div>
                  <div className="flex flex-col">
                    <span className="text-sm font-bold text-[#ff9800] uppercase tracking-wider">High Risk</span>
                    <span className="text-xs text-on-surface-variant">Needs attention</span>
                  </div>
                </div>
              ) : (
                <div className="flex items-center gap-4 p-4 rounded-xl bg-gradient-to-r from-[#10b981]/10 to-transparent border border-[#10b981]/20">
                  <div className="text-4xl font-display-lg text-[#10b981] font-bold select-all">100</div>
                  <div className="flex flex-col">
                    <span className="text-sm font-bold text-[#10b981] uppercase tracking-wider">Healthy Node</span>
                    <span className="text-xs text-on-surface-variant">No findings detected</span>
                  </div>
                </div>
              )}

              {/* Details Metadata grid */}
              <div className="grid grid-cols-2 gap-3 select-all">
                <div className="p-3 rounded-lg bg-[#11151D] border border-[#1F242D]">
                  <div className="text-xs text-outline mb-1 font-label-mono">Vulnerability</div>
                  <div className="text-sm text-on-surface font-semibold">{selectedNode.details?.vulnName}</div>
                </div>
                <div className="p-3 rounded-lg bg-[#11151D] border border-[#1F242D]">
                  <div className="text-xs text-outline mb-1 font-label-mono">OWASP Category</div>
                  <div className="text-sm text-on-surface font-semibold">{selectedNode.details?.owasp}</div>
                </div>
                <div className="p-3 rounded-lg bg-[#11151D] border border-[#1F242D]">
                  <div className="text-xs text-outline mb-1 font-label-mono">CWE</div>
                  <div className="text-sm text-on-surface font-semibold">{selectedNode.details?.cwe}</div>
                </div>
                <div className="p-3 rounded-lg bg-[#11151D] border border-[#1F242D]">
                  <div className="text-xs text-outline mb-1 font-label-mono">CVSS v3.1</div>
                  <div className="text-sm text-on-surface font-semibold">{selectedNode.details?.cvss || 'N/A'}</div>
                </div>
              </div>

              {/* Findings details */}
              <div className="space-y-3">
                <h3 className="text-sm font-bold text-on-surface uppercase tracking-wider select-none">Analysis Findings</h3>
                
                {/* Static findings */}
                <div className="p-3 rounded-lg border border-[#1F242D] bg-[#11151D] relative overflow-hidden">
                  <div className="absolute top-0 left-0 w-1 h-full bg-primary"></div>
                  <div className="flex items-center gap-2 mb-2 select-none">
                    <span className="material-symbols-outlined text-sm text-primary">find_in_page</span>
                    <span className="text-sm font-bold text-on-surface">Static Analysis (SAST)</span>
                  </div>
                  <p className="text-sm text-on-surface-variant leading-relaxed select-all">
                    {selectedNode.details?.sastDesc}
                  </p>
                  {selectedNode.details?.sastCode && (
                    <div className="bg-[#06070A] p-2 rounded border border-[#1F242D] font-code-sm text-xs text-outline overflow-x-auto whitespace-pre font-mono mt-2 select-all">
                      {selectedNode.details.sastCode}
                    </div>
                  )}
                </div>

                {/* Dynamic validation */}
                <div className="p-3 rounded-lg border border-[#1F242D] bg-[#11151D] relative overflow-hidden">
                  <div className="absolute top-0 left-0 w-1 h-full bg-error"></div>
                  <div className="flex items-center gap-2 mb-2 select-none">
                    <span className="material-symbols-outlined text-sm text-error">language</span>
                    <span className="text-sm font-bold text-on-surface">Dynamic Validation (DAST)</span>
                  </div>
                  <p className="text-sm text-on-surface-variant leading-relaxed select-all">
                    {selectedNode.details?.dastDesc}
                  </p>
                </div>
              </div>

              {/* AI Explanation glass card */}
              {selectedNode.status !== 'safe' && (
                <div className="p-4 rounded-xl border border-primary/30 bg-primary/5 backdrop-blur-md relative overflow-hidden select-all">
                  <div className="absolute inset-0 bg-gradient-to-r from-transparent via-primary/10 to-transparent -translate-x-full animate-[shimmer_3s_infinite]" />
                  <div className="flex items-center gap-2 mb-2 select-none">
                    <span className="material-symbols-outlined text-primary">psychology</span>
                    <span className="text-sm font-bold text-primary">Kyptic AI Analysis</span>
                  </div>
                  <p className="text-sm text-on-surface-variant leading-relaxed">
                    {selectedNode.details?.description}
                  </p>
                </div>
              )}

            </div>

            {/* Footer Actions */}
            <div className="p-4 border-t border-outline-variant/30 bg-surface-container-low flex gap-3 shrink-0 select-none">
              <button 
                onClick={() => navigate(selectedNode.status === 'critical' ? '/findings/finding-1' : '/findings')}
                className="flex-1 px-4 py-2 rounded-lg bg-surface-container-high border border-outline-variant text-on-surface text-sm font-semibold hover:bg-surface-bright transition-colors flex justify-center items-center gap-2 cursor-pointer"
              >
                <span className="material-symbols-outlined text-sm">open_in_new</span> Details
              </button>
              
              {selectedNode.status !== 'safe' && (
                <button 
                  onClick={() => navigate('/copilot', { state: { finding: { 
                    id: 'finding-1',
                    title: selectedNode.details?.vulnName || 'SQL Injection',
                    component: selectedNode.label,
                    file: 'controllers/authController.js',
                    cvss: selectedNode.details?.cvss || 9.8,
                    severity: selectedNode.status === 'critical' ? 'Critical' : 'High',
                    cwe: selectedNode.details?.cwe || 'CWE-89',
                    owasp: selectedNode.details?.owasp || 'A03:2021',
                    vulnerableCode: `const query = "SELECT * FROM users WHERE username = '" + req.body.username + "'";`
                  }} })}
                  className="flex-1 px-4 py-2 rounded-lg bg-primary text-on-primary text-sm font-semibold hover:bg-primary-fixed transition-colors shadow-[0_0_15px_rgba(166,200,255,0.3)] flex justify-center items-center gap-2 cursor-pointer border-none"
                >
                  <span className="material-symbols-outlined text-sm">auto_fix</span> Fix Issue
                </button>
              )}
            </div>
          </>
        ) : (
          <div className="flex-grow flex flex-col items-center justify-center p-8 text-center text-on-surface-variant select-none">
            <span className="material-symbols-outlined text-4xl text-outline mb-3">hub</span>
            <h3 className="text-sm font-bold text-on-surface uppercase tracking-wider mb-2">Asset Inspector</h3>
            <p className="text-xs text-on-surface-variant leading-relaxed max-w-[220px]">
              Select any component node on the graph canvas or File Explorer to analyze code structures and scanner logs.
            </p>
          </div>
        )}
      </aside>

      {/* Bottom Timeline Stepper Overlay */}
      <div className="absolute bottom-0 left-80 right-96 h-20 bg-gradient-to-t from-[#06070A] to-transparent z-20 flex items-end justify-center pb-6 pointer-events-none select-none">
        <div className="glass-panel px-8 py-3 rounded-full flex items-center justify-between w-full max-w-2xl pointer-events-auto relative shadow-2xl bg-surface-container/60 backdrop-blur-md border border-[#1F242D]">
          
          <div className="relative z-10 flex flex-col items-center gap-1 group cursor-help">
            <div className="w-6 h-6 rounded-full bg-primary border-2 border-[#0A0D12] flex items-center justify-center">
              <span className="material-symbols-outlined text-[12px] text-on-primary font-bold">check</span>
            </div>
            <span className="text-[10px] font-label-mono text-primary uppercase tracking-wider absolute -bottom-5 whitespace-nowrap">White-Box</span>
          </div>

          <div className="relative z-10 flex flex-col items-center gap-1 group cursor-help">
            <div className="w-6 h-6 rounded-full bg-primary border-2 border-[#0A0D12] flex items-center justify-center">
              <span className="material-symbols-outlined text-[12px] text-on-primary font-bold">check</span>
            </div>
            <span className="text-[10px] font-label-mono text-primary uppercase tracking-wider absolute -bottom-5 whitespace-nowrap">Mapping</span>
          </div>

          <div className="relative z-10 flex flex-col items-center gap-1 group cursor-help">
            <div className="w-6 h-6 rounded-full bg-[#11151D] border-2 border-primary flex items-center justify-center shadow-[0_0_10px_rgba(166,200,255,0.5)]">
              <span className="w-2 h-2 rounded-full bg-primary animate-pulse"></span>
            </div>
            <span className="text-[10px] font-label-mono text-on-surface uppercase tracking-wider absolute -bottom-5 whitespace-nowrap">Black-Box (In Progress)</span>
          </div>

          <div className="relative z-10 flex flex-col items-center gap-1 group cursor-help">
            <div className="w-6 h-6 rounded-full bg-[#11151D] border-2 border-[#1F242D] flex items-center justify-center">
            </div>
            <span className="text-[10px] font-label-mono text-outline uppercase tracking-wider absolute -bottom-5 whitespace-nowrap">Validation</span>
          </div>

          <div className="relative z-10 flex flex-col items-center gap-1 group cursor-help">
            <div className="w-6 h-6 rounded-full bg-[#11151D] border-2 border-[#1F242D] flex items-center justify-center">
              <span className="material-symbols-outlined text-[12px] text-outline">psychology</span>
            </div>
            <span className="text-[10px] font-label-mono text-outline uppercase tracking-wider absolute -bottom-5 whitespace-nowrap">AI Analysis</span>
          </div>

        </div>
      </div>

    </div>
  );
};

export default RiskMap;
