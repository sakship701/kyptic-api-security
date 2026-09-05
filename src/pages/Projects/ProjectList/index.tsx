import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useApp } from '../../../context/AppContext';
import GlassPanel from '../../../components/ui/GlassPanel';
import Badge from '../../../components/ui/Badge';

export const ProjectList: React.FC = () => {
  const navigate = useNavigate();
  const { projects, projectsLoading, projectsError, refreshProjects, isScanning, startScan } = useApp();

  // Filter & Sort States
  const [filterText, setFilterText] = useState('');
  const [sortBy, setSortBy] = useState('Risk Level');
  const [techFilter, setTechFilter] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string | null>(null);

  // Active Scan state check
  const getProjectStatus = (p: any) => {
    return p.status;
  };

  const getProjectScore = (p: any) => {
    return p.score;
  };

  const gitReposCount = projects.filter(p => p.sourceType === 'GIT' || (p.repository && p.repository !== 'No repository connected')).length;
  const websiteTargetsCount = projects.filter(p => p.sourceType === 'WEBSITE' || p.targetUrl).length;

  // Filter & Sort Logic
  const filteredProjects = projects
    .filter((p) => {
      const matchesSearch =
        p.name.toLowerCase().includes(filterText.toLowerCase()) ||
        p.technology.toLowerCase().includes(filterText.toLowerCase()) ||
        p.repository.toLowerCase().includes(filterText.toLowerCase());

      const matchesTech = techFilter ? p.technology.toLowerCase().includes(techFilter.toLowerCase()) : true;
      const matchesStatus = statusFilter ? p.status.toLowerCase() === statusFilter.toLowerCase() : true;

      return matchesSearch && matchesTech && matchesStatus;
    })
    .sort((a, b) => {
      if (sortBy === 'Name A-Z') {
        return a.name.localeCompare(b.name);
      }
      if (sortBy === 'Last Scanned') {
        return a.lastScan.localeCompare(b.lastScan);
      }
      // Default: Risk Level (lowest score first)
      const scoreA = getProjectScore(a);
      const scoreB = getProjectScore(b);
      return scoreA - scoreB;
    });

  const handleStartScan = (id: string) => {
    startScan(id);
  };

  return (
    <div className="p-4 md:p-container-padding max-w-[1600px] mx-auto w-full flex flex-col gap-stack-lg pb-24 relative text-on-surface">
      {/* Header Section */}
      <div>
        <h1 className="font-display-lg text-display-lg text-on-surface mb-2 glow-text">Projects</h1>
        <p className="font-body-lg text-body-lg text-on-surface-variant max-w-2xl">
          Manage, monitor, and secure all your applications from a single workspace.
        </p>
      </div>

      {/* KPI Bar */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <GlassPanel className="rounded-xl p-4 flex flex-col justify-between">
          <span className="font-label-mono text-label-mono text-on-surface-variant uppercase">Total Projects</span>
          <div className="font-headline-md text-headline-md text-on-surface mt-2">{projects.length}</div>
        </GlassPanel>
        <GlassPanel className="rounded-xl p-4 flex flex-col justify-between">
          <span className="font-label-mono text-label-mono text-on-surface-variant uppercase">Website Targets</span>
          <div className="font-headline-md text-headline-md text-on-surface mt-2">{websiteTargetsCount}</div>
        </GlassPanel>
        <GlassPanel className="rounded-xl p-4 flex flex-col justify-between">
          <span className="font-label-mono text-label-mono text-on-surface-variant uppercase">Git Repositories</span>
          <div className="font-headline-md text-headline-md text-on-surface mt-2">{gitReposCount}</div>
        </GlassPanel>
        <GlassPanel className="rounded-xl p-4 flex flex-col justify-between">
          <span className="font-label-mono text-label-mono text-on-surface-variant uppercase">Last Scan Status</span>
          <div className="font-body-lg text-body-lg text-primary mt-2">{isScanning ? 'Scanning...' : 'Idle'}</div>
        </GlassPanel>
        <GlassPanel className="rounded-xl p-4 flex flex-col justify-between border-l-2 border-l-error">
          <span className="font-label-mono text-label-mono text-on-surface-variant uppercase">Needs Attention</span>
          <div className="font-headline-md text-headline-md text-error mt-2">
            {projects.filter(p => p.status === 'Needs Attention').length}
          </div>
        </GlassPanel>
      </div>

      {projectsError && (
        <div className="p-4 rounded-xl border border-error/40 bg-error/10 text-error flex items-center justify-between gap-4">
          <span>{projectsError}</span>
          <button onClick={() => void refreshProjects()} className="px-3 py-2 rounded-lg border border-error/50 hover:bg-error/10 cursor-pointer">
            Retry
          </button>
        </div>
      )}

      {/* Toolbar */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-surface-container p-4 rounded-xl border border-outline-variant/30">
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative w-64">
            <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant text-sm">
              search
            </span>
            <input
              className="w-full bg-[#0A0D12] border border-[#1F242D] rounded-lg py-2 pl-9 pr-4 font-body-md text-sm text-on-surface focus:border-primary focus:ring-1 focus:ring-primary focus:outline-none transition-all placeholder:text-outline"
              placeholder="Filter projects..."
              type="text"
              value={filterText}
              onChange={(e) => setFilterText(e.target.value)}
            />
          </div>
          
          {/* Interactive Technology Filter */}
          <div className="relative">
            <button
              onClick={() => {
                setTechFilter(techFilter ? null : 'node');
                setStatusFilter(null);
              }}
              className={`px-3 py-2 rounded-lg border text-sm flex items-center gap-2 transition-colors cursor-pointer ${
                techFilter ? 'bg-primary-container/20 border-primary text-primary' : 'bg-[#0A0D12] border-[#1F242D] text-on-surface hover:border-primary'
              }`}
            >
              <span className="material-symbols-outlined text-[18px]">terminal</span>
              <span>{techFilter ? 'Node.js Only' : 'Technology'}</span>
            </button>
          </div>

          {/* Interactive Status Filter */}
          <div className="relative">
            <button
              onClick={() => {
                setStatusFilter(statusFilter ? null : 'scanning');
                setTechFilter(null);
              }}
              className={`px-3 py-2 rounded-lg border text-sm flex items-center gap-2 transition-colors cursor-pointer ${
                statusFilter ? 'bg-tertiary-container/20 border-tertiary text-tertiary' : 'bg-[#0A0D12] border-[#1F242D] text-on-surface hover:border-primary'
              }`}
            >
              <span className="material-symbols-outlined text-[18px]">task_alt</span>
              <span>{statusFilter ? 'Scanning Only' : 'Status'}</span>
            </button>
          </div>
        </div>

        <div className="flex items-center gap-4 w-full sm:w-auto">
          {/* Sorting Selector */}
          <div className="relative flex-1 sm:flex-none">
            <select
              className="w-full sm:w-auto appearance-none bg-[#0A0D12] border border-[#1F242D] rounded-lg py-2 pl-4 pr-10 font-body-md text-sm text-on-surface focus:border-primary focus:outline-none cursor-pointer"
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
            >
              <option value="Risk Level">Sort By: Risk Level</option>
              <option value="Name A-Z">Sort By: Name A-Z</option>
              <option value="Last Scanned">Sort By: Last Scanned</option>
            </select>
            <span className="material-symbols-outlined absolute right-3 top-1/2 -translate-y-1/2 text-on-surface-variant pointer-events-none">
              expand_more
            </span>
          </div>

          <button
            onClick={() => navigate('/projects/new')}
            className="btn-primary px-5 py-2 rounded-lg text-white font-body-md font-medium flex items-center gap-2 whitespace-nowrap cursor-pointer hover:shadow-[0_0_15px_rgba(46,144,250,0.4)]"
          >
            <span className="material-symbols-outlined text-[20px]">add</span>
            <span>Create New Project</span>
          </button>
        </div>
      </div>

      {/* Project Grid */}
      {projectsLoading ? (
        <div className="glass-panel rounded-xl p-10 text-center text-on-surface-variant animate-pulse">
          Loading projects...
        </div>
      ) : !projectsError && filteredProjects.length === 0 ? (
        <div className="glass-panel rounded-xl p-10 text-center text-on-surface-variant">
          No projects match the current filters.
        </div>
      ) : (
      <div className="grid grid-cols-1 lg:grid-cols-2 2xl:grid-cols-3 gap-gutter">
        {filteredProjects.map((p) => {
          const currentStatus = getProjectStatus(p);
          const currentScore = getProjectScore(p);

          const isCardScanning = currentStatus === 'Scanning';
          const isVulnerable = currentStatus === 'Needs Attention' || currentScore < 60;

          // Status Badge Variant
          let badgeVariant: 'primary' | 'critical' | 'high' | 'neutral' = 'neutral';
          let badgeLabel = 'Protected';

          if (isCardScanning) {
            badgeVariant = 'high'; // Uses tertiary orange color scheme
            badgeLabel = 'Scanning';
          } else if (isVulnerable) {
            badgeVariant = 'critical'; // Uses error red color scheme
            badgeLabel = 'Vulnerable';
          } else {
            badgeVariant = 'primary'; // Uses primary blue color scheme
          }

          return (
            <div 
              key={p.id} 
              className={`glass-panel rounded-xl overflow-hidden group hover:border-outline-variant transition-all duration-300 ${
                isVulnerable ? 'border-error/25' : ''
              }`}
            >
              <div className="p-6">
                <div className="flex justify-between items-start mb-4">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <h3 className="font-headline-md text-headline-md text-on-surface group-hover:text-primary transition-colors">
                        {p.name}
                      </h3>
                      <Badge variant={badgeVariant} pulse={isCardScanning}>
                        {badgeLabel}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-2 text-on-surface-variant text-sm font-code-sm">
                      <span className="material-symbols-outlined text-[16px]">
                        {p.technology.toLowerCase().includes('java') ? 'code' : 'terminal'}
                      </span>
                      <span>{p.technology}</span>
                      <span className="w-1 h-1 rounded-full bg-outline-variant"></span>
                      <span className="truncate max-w-[200px]" title={p.repository}>
                        {p.repository}
                      </span>
                    </div>
                    {p.sourceType && (
                      <div className="mt-2 flex items-center gap-2 text-xs font-label-mono">
                        <span className="text-on-surface-variant uppercase">Source:</span>
                        <span className="text-[#a3defe]">{p.sourceType}</span>
                        <span className="w-1 h-1 rounded-full bg-outline-variant"></span>
                        <span className="text-on-surface-variant uppercase">Status:</span>
                        <span className={`font-semibold ${
                          p.sourceStatus === 'READY' 
                            ? 'text-success' 
                            : p.sourceStatus === 'FAILED' 
                              ? 'text-error' 
                              : 'text-tertiary animate-pulse'
                        }`}>{p.sourceStatus}</span>
                      </div>
                    )}
                  </div>

                  {/* Circular Score Gauge */}
                  <div className="relative w-12 h-12 flex items-center justify-center">
                    <svg className={`w-full h-full transform -rotate-90 ${isCardScanning ? 'animate-spin' : ''}`} style={{ animationDuration: '3s' }} viewBox="0 0 36 36">
                      <path 
                        className="text-surface-container-high" 
                        d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" 
                        fill="none" 
                        stroke="currentColor" 
                        strokeWidth="3"
                      ></path>
                      <path 
                        className={isVulnerable ? 'text-error' : isCardScanning ? 'text-tertiary' : 'text-primary'}
                        d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" 
                        fill="none" 
                        stroke="currentColor" 
                        strokeDasharray={`${isCardScanning ? 75 : currentScore}, 100`} 
                        strokeWidth="3"
                      ></path>
                    </svg>
                    <span className={`absolute ${isCardScanning ? 'text-[10px]' : 'text-xs'} font-bold text-on-surface`}>
                      {isCardScanning ? '...' : currentScore}
                    </span>
                  </div>
                </div>

                <div className="flex items-center justify-between mt-6">
                  {/* Vulnerability Counts */}
                  {isCardScanning ? (
                    <div className="flex gap-2 opacity-50">
                      <div className="flex items-center gap-1 bg-surface-container-high px-2 py-1 rounded border border-error/20">
                        <span className="w-2 h-2 rounded-full bg-error"></span>
                        <span className="text-xs font-label-mono text-on-surface">0</span>
                      </div>
                      <div className="flex items-center gap-1 bg-surface-container-high px-2 py-1 rounded border border-tertiary-container/20">
                        <span className="w-2 h-2 rounded-full bg-tertiary-container"></span>
                        <span className="text-xs font-label-mono text-on-surface">2</span>
                      </div>
                    </div>
                  ) : (
                    <div className="flex gap-2">
                      <div className={`flex items-center gap-1 px-2 py-1 rounded border ${isVulnerable ? 'bg-error/10 border-error/30' : 'bg-surface-container-high border-error/20'}`}>
                        <span className="w-2 h-2 rounded-full bg-error"></span>
                        <span className={`text-xs font-label-mono ${isVulnerable ? 'text-error font-bold' : 'text-on-surface'}`}>
                          {p.critical}
                        </span>
                      </div>
                      <div className="flex items-center gap-1 bg-surface-container-high px-2 py-1 rounded border border-tertiary-container/20">
                        <span className="w-2 h-2 rounded-full bg-tertiary-container"></span>
                        <span className="text-xs font-label-mono text-on-surface">{p.high}</span>
                      </div>
                      <div className="flex items-center gap-1 bg-surface-container-high px-2 py-1 rounded border border-tertiary/20">
                        <span className="w-2 h-2 rounded-full bg-tertiary"></span>
                        <span className="text-xs font-label-mono text-on-surface">{p.medium}</span>
                      </div>
                      <div className="flex items-center gap-1 bg-surface-container-high px-2 py-1 rounded border border-[#10b981]/20">
                        <span className="w-2 h-2 rounded-full bg-[#10b981]"></span>
                        <span className="text-xs font-label-mono text-on-surface">{p.low}</span>
                      </div>
                    </div>
                  )}

                  {/* Scanned/Status Time */}
                  <div className={`text-xs flex items-center gap-1 ${isCardScanning ? 'text-tertiary animate-pulse' : 'text-on-surface-variant'}`}>
                    <span className="material-symbols-outlined text-[14px]">
                      {isCardScanning ? 'sync' : 'schedule'}
                    </span>
                    <span>{isCardScanning ? 'Analyzing dependencies...' : p.lastScan}</span>
                  </div>
                </div>
              </div>

              {/* Card Footer Actions */}
              <div className="bg-surface-container-high/50 px-6 py-3 border-t border-[#1F242D] flex items-center justify-between">
                {isCardScanning ? (
                  <button 
                    onClick={() => alert('Scan stopped manually.')}
                    className="text-sm font-medium text-on-surface-variant hover:text-on-surface transition-colors flex items-center gap-2 cursor-pointer"
                  >
                    Stop Scan
                  </button>
                ) : (
                  <button 
                    onClick={() => navigate(isVulnerable ? '/findings' : '/dashboard')}
                    className={`text-sm font-medium transition-colors flex items-center gap-2 cursor-pointer ${
                      isVulnerable ? 'text-error hover:text-error-container' : 'text-on-surface hover:text-primary'
                    }`}
                  >
                    <span>{isVulnerable ? 'View Critical Findings' : 'Open Dashboard'}</span>
                    <span className="material-symbols-outlined text-[16px]">
                      {isVulnerable ? 'warning' : 'arrow_forward'}
                    </span>
                  </button>
                )}

                <div className="flex items-center gap-1">
                  {!isCardScanning && (
                    <>
                      <button 
                        onClick={() => handleStartScan(p.id)}
                        disabled={isScanning}
                        className="p-1.5 text-on-surface-variant hover:text-primary hover:bg-surface-container rounded transition-colors cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed"
                        title="Run AI Scan"
                      >
                        <span className="material-symbols-outlined text-[18px]">memory</span>
                      </button>
                      <button 
                        onClick={() => alert('Generating report for ' + p.name)}
                        className="p-1.5 text-on-surface-variant hover:text-on-surface hover:bg-surface-container rounded transition-colors cursor-pointer"
                        title="Generate Report"
                      >
                        <span className="material-symbols-outlined text-[18px]">description</span>
                      </button>
                    </>
                  )}
                  <button 
                    onClick={() => navigate('/settings')}
                    className="p-1.5 text-on-surface-variant hover:text-on-surface hover:bg-surface-container rounded transition-colors cursor-pointer"
                    title="Settings"
                  >
                    <span className="material-symbols-outlined text-[18px]">settings</span>
                  </button>
                </div>
              </div>
            </div>
          );
        })}
      </div>
      )}
    </div>
  );
};

export default ProjectList;
