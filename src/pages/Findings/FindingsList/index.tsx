import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useApp } from '../../../context/AppContext';
import GlassPanel from '../../../components/ui/GlassPanel';
import { fetchFindings, type FindingApiData } from '../../../api/findings';

interface FindingItem {
  id: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  title: string;
  component: string;
  componentType: 'api' | 'code' | 'security' | 'description';
  sourceLabel: string;
  sourceType: string;
  cwe: string;
  owasp: string;
  cvss: number;
  confidence: number;
  status: 'Open' | 'Resolved' | 'False Positive';
  aiValidated: boolean;
  exploitable: boolean;
  projectId: number;
}

export const FindingsList: React.FC = () => {
  const navigate = useNavigate();
  const { activeProjectId, projects } = useApp();

  // Find active project metrics
  const activeProject = projects.find(p => p.id === activeProjectId) || projects[0] || {
    id: '',
    name: 'Select Project',
    technology: 'Unknown technology',
    repository: 'No repository connected',
    score: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    lastScan: 'Not scanned',
    status: 'Protected' as const,
  };

  const [findingsData, setFindingsData] = useState<FindingItem[]>([]);
  const [findingsLoading, setFindingsLoading] = useState(true);
  const [findingsError, setFindingsError] = useState<string | null>(null);

  const mapFinding = (finding: FindingApiData): FindingItem => {
    let sourceLabel = 'SAST';
    if (finding.source === 'api_security') sourceLabel = 'API SECURITY';
    else if (finding.source === 'dast') sourceLabel = 'DAST ACTIVE PROBE';
    else if (finding.source === 'secrets') sourceLabel = 'SECRETS';
    else if (finding.source === 'sca') sourceLabel = 'SCA';
    else if (finding.source === 'sast') sourceLabel = 'SAST';
    else sourceLabel = (finding.source || 'SAST').toUpperCase();

    return {
      id: String(finding.id),
      severity: finding.severity === 'critical' ? 'Critical' : finding.severity === 'high' ? 'High' : finding.severity === 'medium' ? 'Medium' : 'Low',
      title: finding.title,
      component: finding.file_path,
      componentType: (finding.source === 'dast' || finding.source === 'api_security') ? 'api' : finding.source === 'sca' ? 'security' : 'code',
      sourceLabel,
      sourceType: finding.source,
      cwe: finding.source === 'sca' ? (finding.rule_id || 'SCA Vulnerability') : finding.cwe || 'Security Finding',
      owasp: finding.source === 'sca' ? 'Dependency Vulnerability' : finding.owasp || finding.category,
      cvss: finding.cvss ?? 0,
      confidence: 100,
      status: finding.status === 'open' ? 'Open' : finding.status === 'resolved' ? 'Resolved' : 'False Positive',
      aiValidated: finding.source === 'correlation',
      exploitable: finding.severity === 'critical',
      projectId: finding.project_id,
    };
  };

  useEffect(() => {
    setFindingsLoading(true);
    void fetchFindings()
      .then((findings) => setFindingsData(findings.filter((finding) => !activeProjectId || String(finding.project_id) === activeProjectId).map(mapFinding)))
      .catch((error: unknown) => setFindingsError(error instanceof Error ? error.message : 'Unable to load findings.'))
      .finally(() => setFindingsLoading(false));
  }, [activeProjectId]);

  // Filters State
  const [searchQuery, setSearchQuery] = useState('');
  const [filterSeverity, setFilterSeverity] = useState({
    Critical: true,
    High: true,
    Medium: true,
    Low: true
  });
  const [owaspFilter, setOwaspFilter] = useState('All Categories');
  const [statusFilter, setStatusFilter] = useState<'All' | 'Confirmed' | 'Investigating'>('All');

  const handleResetFilters = () => {
    setSearchQuery('');
    setFilterSeverity({
      Critical: true,
      High: true,
      Medium: true,
      Low: true
    });
    setOwaspFilter('All Categories');
    setStatusFilter('All');
  };

  // Filter & Search Logic
  const filteredFindings = findingsData.filter((item) => {
    // Search filter
    const matchesSearch = 
      item.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.component.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.cwe.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.owasp.toLowerCase().includes(searchQuery.toLowerCase());

    // Severity Filter
    const matchesSeverity = filterSeverity[item.severity];

    // OWASP Filter
    const matchesOwasp = owaspFilter === 'All Categories' || item.owasp.startsWith(owaspFilter.split(':')[0]);

    // Validation Status Filter
    const matchesStatus = 
      statusFilter === 'All' ||
      (statusFilter === 'Confirmed' && item.status === 'Open') ||
      (statusFilter === 'Investigating' && item.status === 'False Positive');

    return matchesSearch && matchesSeverity && matchesOwasp && matchesStatus;
  });

  return (
    <div className="p-4 md:p-container-padding max-w-[1600px] mx-auto w-full text-on-surface">
      
      {/* Page Header */}
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4 mb-stack-lg">
        <div>
          <h2 className="font-headline-md text-display-lg-mobile md:text-display-lg text-on-surface font-bold tracking-tighter glow-text">
            Security Findings
          </h2>
          <p className="text-on-surface-variant mt-2 max-w-2xl text-body-md">
            Review, prioritize, validate, and remediate vulnerabilities detected during the latest intelligent security assessment.
          </p>
        </div>
        <div className="flex gap-3">
          <button 
            onClick={() => alert('Exporting findings report...')}
            className="px-4 py-2 rounded border border-[#1F242D] text-on-surface font-label-mono text-[12px] uppercase tracking-wider hover:bg-surface-container transition-colors flex items-center gap-2 cursor-pointer bg-transparent"
          >
            <span className="material-symbols-outlined text-[18px]">download</span> Export Report
          </button>
          <button 
            onClick={() => navigate('/copilot')}
            className="px-4 py-2 rounded bg-gradient-to-r from-[#2E90FA] to-[#005fb0] text-white font-label-mono text-[12px] uppercase tracking-wider hover:shadow-[0_0_15px_rgba(46,144,250,0.4)] transition-all flex items-center gap-2 cursor-pointer border-none"
          >
            <span className="material-symbols-outlined text-[18px]">auto_awesome</span> Open AI Analysis
          </button>
        </div>
      </div>

      {/* Top Summary Cards Row */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-stack-lg">
        
        {/* Score */}
        <GlassPanel className="rounded-lg p-4 flex flex-col justify-between relative overflow-hidden group">
          <div className="absolute inset-0 bg-primary/5 opacity-0 group-hover:opacity-100 transition-opacity"></div>
          <span className="text-on-surface-variant font-label-mono text-[11px] uppercase tracking-widest z-10">Security Score</span>
          <div className="mt-2 flex items-baseline gap-1 z-10">
            <span className="text-3xl font-headline-md font-bold text-on-surface">{activeProject.score}</span>
            <span className="text-on-surface-variant text-sm">/100</span>
          </div>
          <div className="w-full bg-surface-container h-1 mt-3 rounded-full overflow-hidden z-10">
            <div className="bg-primary h-full rounded-full" style={{ width: `${activeProject.score}%` }}></div>
          </div>
        </GlassPanel>

        {/* Risk Level */}
        <GlassPanel className="rounded-lg p-4 flex flex-col justify-between relative overflow-hidden group">
          <div className="absolute inset-0 bg-[#ff9800]/5 opacity-0 group-hover:opacity-100 transition-opacity"></div>
          <span className="text-on-surface-variant font-label-mono text-[11px] uppercase tracking-widest z-10">Overall Risk</span>
          <div className="mt-2 flex items-center gap-2 z-10">
            <span className="material-symbols-outlined text-[#ff9800] text-[28px]">warning</span>
            <span className="text-2xl font-headline-md font-bold text-on-surface">
              {activeProject.score < 60 ? 'Critical' : activeProject.score < 80 ? 'High' : 'Low'}
            </span>
          </div>
        </GlassPanel>

        {/* Confirmed */}
        <GlassPanel className="rounded-lg p-4 flex flex-col justify-between group">
          <span className="text-on-surface-variant font-label-mono text-[11px] uppercase tracking-widest">Confirmed Vulns</span>
          <div className="mt-2 z-10">
            <span className="text-3xl font-headline-md font-bold text-on-surface">
              {activeProject.critical + activeProject.high}
            </span>
          </div>
          <span className="text-error text-xs flex items-center gap-1 mt-1">
            <span className="material-symbols-outlined text-[14px]">arrow_upward</span> +4 from last scan
          </span>
        </GlassPanel>

        {/* False Positives */}
        <GlassPanel className="rounded-lg p-4 flex flex-col justify-between group">
          <span className="text-on-surface-variant font-label-mono text-[11px] uppercase tracking-widest">False Positives</span>
          <div className="mt-2 z-10">
            <span className="text-3xl font-headline-md font-bold text-on-surface">142</span>
          </div>
          <span className="text-primary text-xs flex items-center gap-1 mt-1">
            <span className="material-symbols-outlined text-[14px]">smart_toy</span> AI Validated
          </span>
        </GlassPanel>

        {/* Scan Duration */}
        <GlassPanel className="rounded-lg p-4 flex flex-col justify-between group">
          <span className="text-on-surface-variant font-label-mono text-[11px] uppercase tracking-widest">Scan Duration</span>
          <div className="mt-2 z-10 flex items-center gap-2">
            <span className="material-symbols-outlined text-on-surface-variant">timer</span>
            <span className="text-2xl font-headline-md font-bold text-on-surface">14m 22s</span>
          </div>
        </GlassPanel>

        {/* Vuln Breakdown */}
        <GlassPanel className="rounded-lg p-4 flex flex-col justify-center gap-2">
          <div className="flex items-center justify-between text-xs">
            <span className="flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-[#ff4d4d]"></div> Critical</span>
            <span className="font-code-sm font-bold">{activeProject.critical}</span>
          </div>
          <div className="flex items-center justify-between text-xs">
            <span className="flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-[#ff9800]"></div> High</span>
            <span className="font-code-sm font-bold">{activeProject.high}</span>
          </div>
          <div className="flex items-center justify-between text-xs">
            <span className="flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-[#ffeb3b]"></div> Medium</span>
            <span className="font-code-sm font-bold text-on-surface-variant">{activeProject.medium}</span>
          </div>
          <div className="flex items-center justify-between text-xs">
            <span className="flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-[#9e9e9e]"></div> Low</span>
            <span className="font-code-sm font-bold text-on-surface-variant">{activeProject.low}</span>
          </div>
        </GlassPanel>

      </div>

      {/* Complex Layout: Left Filters + Center Table + Right Sidebar */}
      <div className="flex flex-col xl:flex-row gap-gutter">
        
        {/* Left Sidebar: Filters */}
        <div className="w-full xl:w-64 shrink-0 flex flex-col gap-4">
          <GlassPanel className="rounded-lg p-4">
            <div className="flex items-center justify-between border-b border-outline-variant/30 pb-3 mb-4">
              <span className="font-label-mono text-[12px] uppercase tracking-widest text-on-surface font-semibold">Filters</span>
              <button 
                onClick={handleResetFilters}
                className="text-primary text-xs hover:underline cursor-pointer bg-transparent border-none"
              >
                Reset
              </button>
            </div>
            
            <div className="space-y-6">
              {/* Search Box on Filter bar for responsive support */}
              <div className="block sm:hidden">
                <label className="text-on-surface-variant text-xs mb-2 block uppercase tracking-wider font-label-mono">Search</label>
                <input
                  type="text"
                  placeholder="Search finding details..."
                  className="w-full bg-[#0A0D12] border border-[#1F242D] rounded px-3 py-1.5 text-sm text-on-surface focus:outline-none focus:border-primary"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />
              </div>

              {/* Severity Filter */}
              <div>
                <label className="text-on-surface-variant text-xs mb-2 block uppercase tracking-wider font-label-mono">Severity</label>
                <div className="space-y-2">
                  {Object.keys(filterSeverity).map((sev) => {
                    const typedSev = sev as keyof typeof filterSeverity;
                    return (
                      <label key={sev} className="flex items-center gap-2 cursor-pointer group">
                        <input
                          type="checkbox"
                          className={`form-checkbox bg-surface-container border-outline-variant rounded focus:ring-offset-0 focus:ring-offset-transparent ${
                            typedSev === 'Critical' ? 'text-[#ff4d4d] focus:ring-[#ff4d4d]' : typedSev === 'High' ? 'text-[#ff9800] focus:ring-[#ff9800]' : 'text-[#ffeb3b] focus:ring-[#ffeb3b]'
                          }`}
                          checked={filterSeverity[typedSev]}
                          onChange={(e) => setFilterSeverity({ ...filterSeverity, [typedSev]: e.target.checked })}
                        />
                        <span className="text-sm text-on-surface group-hover:text-white transition-colors">{sev}</span>
                      </label>
                    );
                  })}
                </div>
              </div>

              {/* OWASP Top 10 */}
              <div>
                <label className="text-on-surface-variant text-xs mb-2 block uppercase tracking-wider font-label-mono">OWASP Category</label>
                <select 
                  className="w-full bg-surface-container-high border-outline-variant/50 rounded text-sm text-on-surface py-1.5 focus:border-primary focus:ring-1 focus:ring-primary cursor-pointer"
                  value={owaspFilter}
                  onChange={(e) => setOwaspFilter(e.target.value)}
                >
                  <option value="All Categories">All Categories</option>
                  <option value="A01: Broken Access Control">A01: Broken Access Control</option>
                  <option value="A02: Cryptographic Failures">A02: Cryptographic Failures</option>
                  <option value="A03: Injection">A03: Injection</option>
                  <option value="A07: Identification and Auth">A07: Identification and Auth</option>
                  <option value="A08: Software and Data Integrity Failures">A08: Software and Data Integrity Failures</option>
                </select>
              </div>

              {/* Validation Status */}
              <div>
                <label className="text-on-surface-variant text-xs mb-2 block uppercase tracking-wider font-label-mono">Validation Status</label>
                <div className="flex flex-wrap gap-2">
                  <span 
                    onClick={() => setStatusFilter(statusFilter === 'Confirmed' ? 'All' : 'Confirmed')}
                    className={`px-2 py-1 rounded text-xs cursor-pointer border transition-colors ${
                      statusFilter === 'Confirmed' 
                        ? 'bg-primary/20 text-primary border-primary/30 font-bold' 
                        : 'bg-surface-container text-on-surface-variant border-outline-variant/30 hover:bg-surface-variant'
                    }`}
                  >
                    Confirmed
                  </span>
                  <span 
                    onClick={() => setStatusFilter(statusFilter === 'Investigating' ? 'All' : 'Investigating')}
                    className={`px-2 py-1 rounded text-xs cursor-pointer border transition-colors ${
                      statusFilter === 'Investigating' 
                        ? 'bg-primary/20 text-primary border-primary/30 font-bold' 
                        : 'bg-surface-container text-on-surface-variant border-outline-variant/30 hover:bg-surface-variant'
                    }`}
                  >
                    Investigating
                  </span>
                </div>
              </div>
            </div>
          </GlassPanel>
        </div>

        {/* Center: Vulnerability Table */}
        <div className="flex-grow glass-panel rounded-lg flex flex-col min-w-0 overflow-hidden">
          <div className="p-4 border-b border-outline-variant/30 flex justify-between items-center bg-surface-container-low/50">
            <div className="flex items-center gap-3">
              <h3 className="font-headline-md text-lg text-on-surface">Active Findings</h3>
              <span className="bg-surface-variant text-on-surface-variant text-xs px-2 py-0.5 rounded-full font-code-sm">
                {filteredFindings.length} Total
              </span>
            </div>

            {/* Inline search bar */}
            <div className="relative w-60 hidden sm:block">
              <span className="material-symbols-outlined absolute left-2.5 top-1/2 -translate-y-1/2 text-on-surface-variant text-sm">search</span>
              <input
                type="text"
                placeholder="Search findings..."
                className="w-full bg-[#0A0D12] border border-[#1F242D] rounded pl-8 pr-3 py-1 text-xs text-on-surface placeholder:text-on-surface-variant focus:outline-none focus:border-primary"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse whitespace-nowrap">
              <thead>
                <tr className="border-b border-outline-variant/30 bg-surface-container-lowest/50">
                  <th className="py-3 px-4 text-xs font-label-mono uppercase tracking-widest text-on-surface-variant font-medium">Severity</th>
                  <th className="py-3 px-4 text-xs font-label-mono uppercase tracking-widest text-on-surface-variant font-medium">Title & Component</th>
                  <th className="py-3 px-4 text-xs font-label-mono uppercase tracking-widest text-on-surface-variant font-medium">CVSS / Confidence</th>
                  <th className="py-3 px-4 text-xs font-label-mono uppercase tracking-widest text-on-surface-variant font-medium">Status</th>
                  <th className="py-3 px-4 text-xs font-label-mono uppercase tracking-widest text-on-surface-variant font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-outline-variant/20 font-body-md text-sm">
                {findingsLoading ? (
                  <tr><td colSpan={5} className="py-10 text-center text-on-surface-variant italic text-xs">Loading findings...</td></tr>
                ) : findingsError ? (
                  <tr><td colSpan={5} className="py-10 text-center text-error italic text-xs">{findingsError}</td></tr>
                ) : filteredFindings.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-10 text-center text-on-surface-variant italic text-xs">
                      No security findings match the selected filters.
                    </td>
                  </tr>
                ) : (
                  filteredFindings.map((item) => {
                    const isCritical = item.severity === 'Critical';
                    const isHigh = item.severity === 'High';
                    const isMedium = item.severity === 'Medium';

                    let sevBadgeClass = 'badge-low';
                    let cvssColor = 'text-on-surface-variant';

                    if (isCritical) {
                      sevBadgeClass = 'badge-critical';
                      cvssColor = 'text-error';
                    } else if (isHigh) {
                      sevBadgeClass = 'badge-high';
                      cvssColor = 'text-[#ff9800]';
                    } else if (isMedium) {
                      sevBadgeClass = 'badge-medium';
                      cvssColor = 'text-[#ffeb3b]';
                    }

                    return (
                      <tr 
                        key={item.id} 
                        onClick={() => navigate(`/findings/${item.id}`)}
                        className={`table-row-hover transition-colors group cursor-pointer ${
                          item.exploitable ? 'bg-[#ff4d4d]/[0.02]' : ''
                        }`}
                      >
                        <td className="py-3 px-4 align-top pt-4">
                          <span className={`severity-badge ${sevBadgeClass}`}>{item.severity}</span>
                        </td>
                        <td className="py-3 px-4">
                          <div className="font-medium text-on-surface mb-1 flex items-center gap-2 flex-wrap">
                            <span className="text-[10px] px-1.5 py-0.5 rounded font-mono font-bold tracking-wider bg-surface-container-high border border-outline-variant/40 text-primary">
                              {item.sourceLabel}
                            </span>
                            <span>{item.title}</span>
                            {item.aiValidated && (
                              <span className="material-symbols-outlined text-primary text-[14px]" title="AI Validated">
                                auto_awesome
                              </span>
                            )}
                            {item.exploitable && (
                              <span className="bg-error/20 text-error border border-error/30 text-[9px] px-1.5 py-0.5 rounded uppercase font-bold tracking-wider">
                                Exploitable
                              </span>
                            )}
                          </div>
                          <div className="text-on-surface-variant text-xs font-code-sm font-mono flex items-center gap-1">
                            <span className="material-symbols-outlined text-[12px]">
                              {item.componentType === 'api' ? 'api' : item.componentType === 'code' ? 'description' : 'security'}
                            </span>
                            <span>{item.component}</span>
                          </div>
                          <div className="text-outline text-[10px] mt-1 uppercase tracking-wider">
                            {item.cwe} • {item.owasp}
                          </div>
                        </td>
                        <td className="py-3 px-4 align-top pt-4">
                          <div className="flex flex-col gap-1">
                            <span className={`font-code-sm ${cvssColor}`}>{item.cvss}</span>
                            <span className="text-xs text-on-surface-variant">{item.confidence}% Conf.</span>
                          </div>
                        </td>
                        <td className="py-3 px-4 align-top pt-4">
                          <span className="flex items-center gap-1.5 text-xs text-on-surface">
                            <span className={`w-2 h-2 rounded-full ${
                              item.status === 'Open' 
                                ? 'bg-error animate-pulse' 
                                : item.status === 'False Positive' 
                                  ? 'bg-[#ff9800]' 
                                  : 'bg-[#4CAF50]'
                            }`}></span>
                            <span>{item.status}</span>
                          </span>
                        </td>
                        <td className="py-3 px-4 align-top pt-4 text-right">
                          <button className="text-primary hover:text-white transition-colors cursor-pointer bg-transparent border-none">
                            <span className="material-symbols-outlined text-[20px] group-hover:translate-x-1 transition-transform">
                              chevron_right
                            </span>
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Table Footer */}
          <div className="p-4 border-t border-outline-variant/30 flex justify-between items-center bg-surface-container-low/30 text-xs">
            <span className="text-on-surface-variant">
              Showing 1-{filteredFindings.length} of {filteredFindings.length} active findings
            </span>
            <div className="flex gap-1">
              <button disabled className="p-1 text-on-surface-variant hover:text-white disabled:opacity-30 disabled:cursor-not-allowed bg-transparent border-none">
                <span className="material-symbols-outlined text-[18px]">chevron_left</span>
              </button>
              <button disabled className="p-1 text-on-surface-variant hover:text-white disabled:opacity-30 disabled:cursor-not-allowed bg-transparent border-none">
                <span className="material-symbols-outlined text-[18px]">chevron_right</span>
              </button>
            </div>
          </div>
        </div>

        {/* Right Sidebar: AI Assessment Summary */}
        <div className="w-full xl:w-80 shrink-0">
          <GlassPanel className="rounded-lg overflow-hidden border border-primary/20 relative">
            
            {/* AI Header Graphic */}
            <div className="h-24 bg-gradient-to-br from-primary/20 to-transparent relative border-b border-primary/20 shimmer">
              <div className="absolute inset-0 flex items-center px-4">
                <span className="material-symbols-outlined text-primary text-[32px] mr-3">
                  auto_awesome
                </span>
                <div>
                  <h4 className="font-headline-md text-white text-lg leading-tight">AI Copilot</h4>
                  <span className="text-primary font-label-mono text-[10px] uppercase tracking-widest">
                    Assessment Summary
                  </span>
                </div>
              </div>
            </div>

            <div className="p-4 space-y-6">
              
              {/* Most Exploitable */}
              <div>
                <h5 className="text-xs font-label-mono uppercase tracking-widest text-error mb-3 flex items-center gap-2">
                  <span className="material-symbols-outlined text-[16px]">warning</span> Most Exploitable
                </h5>
                <div className="bg-surface-container p-3 rounded border border-error/20 relative overflow-hidden">
                  <div className="absolute left-0 top-0 bottom-0 w-1 bg-error"></div>
                  <p className="text-sm font-medium text-white mb-1">RCE via Deserialization</p>
                  <p className="text-xs text-on-surface-variant mb-2 line-clamp-2 leading-relaxed">
                    Kyptic AI verified a publicly available exploit chain that allows unauthenticated remote code execution on the main application server.
                  </p>
                  <button 
                    onClick={() => navigate('/findings/finding-2')}
                    className="text-xs text-primary hover:underline font-medium cursor-pointer bg-transparent border-none"
                  >
                    View Attack Path →
                  </button>
                </div>
              </div>

              {/* Remediation Estimate */}
              <div>
                <h5 className="text-xs font-label-mono uppercase tracking-widest text-on-surface-variant mb-3">
                  Est. Remediation Effort
                </h5>
                <div className="flex items-end gap-2 mb-2">
                  <span className="text-3xl font-headline-md font-bold text-white">4.5</span>
                  <span className="text-on-surface-variant mb-1 text-sm">hours total</span>
                </div>
                <div className="flex h-1.5 rounded-full overflow-hidden w-full bg-surface-container">
                  <div className="bg-error w-[30%]" title="Critical"></div>
                  <div className="bg-[#ff9800] w-[50%]" title="High"></div>
                  <div className="bg-outline-variant w-[20%]" title="Medium/Low"></div>
                </div>
                <div className="flex justify-between text-[10px] text-on-surface-variant mt-1 font-label-mono uppercase">
                  <span>Dev: 3h</span>
                  <span>DevOps: 1.5h</span>
                </div>
              </div>

              {/* Recommended Actions */}
              <div className="border-t border-outline-variant/30 pt-4">
                <h5 className="text-xs font-label-mono uppercase tracking-widest text-on-surface-variant mb-3">
                  Suggested Priority
                </h5>
                <ol className="space-y-3">
                  <li className="flex items-start gap-2">
                    <span className="bg-primary/20 text-primary w-5 h-5 rounded flex items-center justify-center text-xs font-bold shrink-0 mt-0.5">
                      1
                    </span>
                    <div>
                      <p className="text-sm text-white">Patch Deserialization Flaw</p>
                      <p className="text-[11px] text-on-surface-variant">Update core/utils/DataParser.java</p>
                    </div>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="bg-surface-container text-on-surface-variant w-5 h-5 rounded flex items-center justify-center text-xs font-bold shrink-0 mt-0.5">
                      2
                    </span>
                    <div>
                      <p className="text-sm text-white">Rotate AWS Credentials</p>
                      <p className="text-[11px] text-on-surface-variant">Found in deployment.yaml</p>
                    </div>
                  </li>
                </ol>
              </div>

              {/* Generate Secure Patches Action Button */}
              <button 
                onClick={() => alert('Generating secure patch playbooks...')}
                className="w-full bg-primary/10 border border-primary/30 text-primary py-2.5 rounded font-label-mono text-[11px] uppercase tracking-wider hover:bg-primary/20 hover:text-white transition-all flex items-center justify-center gap-2 cursor-pointer"
              >
                <span className="material-symbols-outlined text-[16px]">code_blocks</span> Generate Secure Patches
              </button>

            </div>
          </GlassPanel>
        </div>

      </div>

    </div>
  );
};

export default FindingsList;
