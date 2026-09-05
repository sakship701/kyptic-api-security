import React, { useState } from 'react';
import GlassPanel from '../../components/ui/GlassPanel';
import { fetchProjects, type ProjectApiData } from '../../api/projects';
import { downloadReportPdf, generateReportJson } from '../../api/reports';

interface ReportTemplate {
  id: string;
  title: string;
  subtitle: string;
  timeAgo: string;
  description: string;
  category: 'Executive' | 'Technical' | 'Compliance';
  icon: string;
  iconBg: string;
  iconColor: string;
}

interface HistoryItem {
  id: string;
  title: string;
  time: string;
  generator: string;
  type: 'PDF' | 'HTML';
}

interface ScheduledItem {
  id: string;
  title: string;
  schedule: string;
  recipientsCount: number;
  authorInitials?: string[];
}

export const Reports: React.FC = () => {
  // Projects state
  const [projectsList, setProjectsList] = useState<ProjectApiData[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null);

  // Modals state
  const [isPreviewOpen, setIsPreviewOpen] = useState(false);
  const [activePreviewTemplate, setActivePreviewTemplate] = useState<ReportTemplate | null>(null);
  const [previewData, setPreviewData] = useState<any>(null);
  
  const [isScheduleModalOpen, setIsScheduleModalOpen] = useState(false);
  const [newScheduleTitle, setNewScheduleTitle] = useState('');
  const [newScheduleFreq, setNewScheduleFreq] = useState('Weekly');
  const [newScheduleTime, setNewScheduleTime] = useState('08:00 AM');
  const [newScheduleRecipients, setNewScheduleRecipients] = useState('3 Recipients');

  // Loading spinner overlays
  const [isActionLoading, setIsActionLoading] = useState(false);
  const [loadingText, setLoadingText] = useState('');

  // Filtering templates
  const [filterCategory, setFilterCategory] = useState<'All' | 'Executive' | 'Technical' | 'Compliance'>('All');
  const [isFilterDropdownOpen, setIsFilterDropdownOpen] = useState(false);

  // Fetch projects on mount
  React.useEffect(() => {
    fetchProjects().then(projs => {
      setProjectsList(projs);
      if (projs.length > 0) {
        setSelectedProjectId(projs[0].id);
      }
    }).catch(() => {});
  }, []);

  // Dynamic states
  const [historyList, setHistoryList] = useState<HistoryItem[]>([
    {
      id: 'h-1',
      title: 'Executive Summary Digest',
      time: '14:30 Today',
      generator: 'Generated on-demand',
      type: 'PDF'
    },
    {
      id: 'h-2',
      title: 'Compliance Report (SOC2/PCI-DSS)',
      time: 'Yesterday',
      generator: 'Generated on-demand',
      type: 'PDF'
    }
  ]);

  const [scheduledList, setScheduledList] = useState<ScheduledItem[]>([
    {
      id: 's-1',
      title: 'Weekly Executive Digest',
      schedule: 'Every Monday at 08:00 AM (EST)',
      recipientsCount: 2,
      authorInitials: ['SJ', 'MR']
    }
  ]);

  const templates: ReportTemplate[] = [
    {
      id: 't-1',
      title: 'Executive Summary',
      subtitle: 'High-level risk overview',
      timeAgo: '2h ago',
      description: 'Tailored for leadership and stakeholders. Summarizes overarching security posture, critical risks, and trend analysis without dense technical jargon.',
      category: 'Executive',
      icon: 'assignment_ind',
      iconBg: 'bg-primary-container/20',
      iconColor: 'text-primary'
    },
    {
      id: 't-2',
      title: 'Developer Report',
      subtitle: 'Technical deep-dive',
      timeAgo: '1d ago',
      description: 'Granular technical details including stack traces, affected code snippets, and specific remediation steps designed for engineering teams.',
      category: 'Technical',
      icon: 'code',
      iconBg: 'bg-secondary-container/30',
      iconColor: 'text-secondary-fixed'
    },
    {
      id: 't-3',
      title: 'Compliance Report',
      subtitle: 'Regulatory mapping',
      timeAgo: '3d ago',
      description: 'Maps discovered vulnerabilities directly to specific clauses within frameworks like PCI-DSS, HIPAA, and SOC2.',
      category: 'Compliance',
      icon: 'verified_user',
      iconBg: 'bg-tertiary-container/20',
      iconColor: 'text-tertiary'
    },
    {
      id: 't-4',
      title: 'OWASP Top 10',
      subtitle: 'Web security focus',
      timeAgo: '1w ago',
      description: 'Categorizes findings specifically against the latest OWASP Top 10 categories, essential for web application security baselines.',
      category: 'Technical',
      icon: 'bug_report',
      iconBg: 'bg-error-container/20',
      iconColor: 'text-error'
    }
  ];

  const filteredTemplates = filterCategory === 'All' 
    ? templates 
    : templates.filter(t => t.category === filterCategory);

  const handleDownloadPdf = async (templateKey: string, reportTitle: string) => {
    const projId = selectedProjectId || (projectsList.length > 0 ? projectsList[0].id : 1);
    setLoadingText(`Compiling ${reportTitle} PDF report...`);
    setIsActionLoading(true);
    try {
      await downloadReportPdf(projId, templateKey);
      const newItem: HistoryItem = {
        id: `h-${Date.now()}`,
        title: `${reportTitle} (Proj ${projId})`,
        time: 'Just now',
        generator: 'Downloaded On-Demand',
        type: 'PDF'
      };
      setHistoryList(prev => [newItem, ...prev]);
    } catch (err: any) {
      alert(`Failed to download report PDF: ${err.message || err}`);
    } finally {
      setIsActionLoading(false);
    }
  };

  const handleOpenPreview = async (template: ReportTemplate) => {
    setActivePreviewTemplate(template);
    setIsPreviewOpen(true);
    const projId = selectedProjectId || (projectsList.length > 0 ? projectsList[0].id : 1);
    const keyMap: Record<string, string> = {
      't-1': 'executive',
      't-2': 'developer',
      't-3': 'compliance',
      't-4': 'owasp',
    };
    const reportKey = keyMap[template.id] || 'executive';
    try {
      const data = await generateReportJson(projId, reportKey);
      setPreviewData(data);
    } catch (err) {
      setPreviewData(null);
    }
  };

  const handleCreateSchedule = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newScheduleTitle.trim()) return;

    const newItem: ScheduledItem = {
      id: `s-${Date.now()}`,
      title: newScheduleTitle,
      schedule: `${newScheduleFreq === 'Daily' ? 'Every day' : newScheduleFreq === 'Weekly' ? 'Every Monday' : '1st of every month'} at ${newScheduleTime} (EST)`,
      recipientsCount: parseInt(newScheduleRecipients.split(' ')[0]) || 2
    };

    setScheduledList(prev => [...prev, newItem]);
    setIsScheduleModalOpen(false);
    setNewScheduleTitle('');
  };

  const handleDeleteSchedule = (id: string) => {
    if (confirm('Are you sure you want to remove this scheduled report?')) {
      setScheduledList(prev => prev.filter(item => item.id !== id));
    }
  };

  return (
    <div className="p-4 md:p-container-padding max-w-[1600px] mx-auto w-full flex flex-col gap-stack-lg text-on-surface relative">
      
      {/* Header */}
      <header className="flex flex-col gap-stack-sm select-none">
        <h1 className="font-display-lg-mobile md:font-display-lg text-display-lg-mobile md:text-display-lg text-on-surface font-bold">
          Security Reports
        </h1>
        <p className="font-body-lg text-body-lg text-on-surface-variant max-w-3xl">
          Generate, preview, and export comprehensive security reports for applications scanned by Kyptic.
        </p>
      </header>

      {/* Summary Cards Bento Grid */}
      <section className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-stack-md select-none">
        
        <GlassPanel className="p-stack-md flex flex-col gap-stack-sm col-span-1">
          <span className="font-label-mono text-label-mono text-on-surface-variant uppercase">Apps Scanned</span>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-headline-md text-on-surface font-bold">42</span>
          </div>
        </GlassPanel>

        <GlassPanel className="p-stack-md flex flex-col gap-stack-sm col-span-1">
          <span className="font-label-mono text-label-mono text-on-surface-variant uppercase">Reports Gen</span>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-headline-md text-on-surface font-bold">128</span>
            <span className="text-primary text-sm flex items-center font-bold">
              <span className="material-symbols-outlined text-[16px]">arrow_upward</span> 12%
            </span>
          </div>
        </GlassPanel>

        <GlassPanel className="p-stack-md flex flex-col gap-stack-sm col-span-2 relative overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-br from-primary/10 to-transparent z-0" />
          <div className="relative z-10 flex justify-between items-center h-full">
            <div className="flex flex-col gap-stack-sm">
              <span className="font-label-mono text-label-mono text-primary uppercase">Overall Security Score</span>
              <div className="flex items-baseline gap-2">
                <span className="text-4xl font-headline-md text-on-surface font-bold">68</span>
                <span className="text-on-surface-variant font-body-md">/ 100</span>
              </div>
            </div>
            {/* Minimal circular progress representation */}
            <div className="w-16 h-16 rounded-full border-4 border-outline-variant flex items-center justify-center relative">
              <svg className="absolute inset-0 w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                <circle className="text-surface-variant/20" cx="50" cy="50" fill="transparent" r="45" stroke="currentColor" strokeWidth="8" />
                <circle className="text-tertiary" cx="50" cy="50" fill="transparent" r="45" stroke="currentColor" strokeDasharray="283" strokeDashoffset="90" strokeWidth="8" />
              </svg>
              <span className="material-symbols-outlined text-tertiary">format_image_left</span>
            </div>
          </div>
        </GlassPanel>

        <GlassPanel className="p-stack-md flex flex-col gap-stack-sm col-span-2">
          <div className="flex justify-between items-start">
            <span className="font-label-mono text-label-mono text-on-surface-variant uppercase">Compliance Status</span>
            <span className="px-2 py-0.5 rounded bg-primary-container/20 text-primary font-label-mono text-[10px] border border-primary-container/30">
              PCI-DSS, SOC2
            </span>
          </div>
          <div className="flex flex-col mt-auto gap-2">
            <div className="flex justify-between font-label-mono text-xs">
              <span className="text-on-surface-variant">Overall Readiness</span>
              <span className="text-primary font-bold">85%</span>
            </div>
            <div className="w-full bg-[#1C2026] h-1.5 rounded-full overflow-hidden">
              <div className="bg-primary h-full rounded-full" style={{ width: '85%' }} />
            </div>
          </div>
        </GlassPanel>

        <GlassPanel className="p-stack-md flex flex-col gap-stack-sm col-span-1 border-l-2 border-l-error">
          <span className="font-label-mono text-label-mono text-error uppercase">Critical Findings</span>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-headline-md text-error font-bold">12</span>
          </div>
        </GlassPanel>

        <GlassPanel className="p-stack-md flex flex-col gap-stack-sm col-span-1">
          <span className="font-label-mono text-label-mono text-on-surface-variant uppercase">Avg Fix Time</span>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-headline-md text-on-surface font-bold">4.2</span>
            <span className="text-on-surface-variant text-sm">Days</span>
          </div>
        </GlassPanel>

      </section>

      {/* Main Layout: Reports Grid + Right Panel */}
      <div className="flex flex-col lg:flex-row gap-stack-lg items-start">
        
        {/* Left Area: Report Templates */}
        <div className="flex-1 flex flex-col gap-stack-md w-full">
          
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between border-b border-outline-variant/30 pb-2 relative z-20 gap-4">
            <div className="flex items-center gap-4">
              <h2 className="font-headline-md text-lg text-on-surface font-semibold">Available Report Templates</h2>
              {projectsList.length > 0 && (
                <div className="flex items-center gap-2">
                  <span className="text-xs font-label-mono text-on-surface-variant uppercase">Target Project:</span>
                  <select 
                    value={selectedProjectId || projectsList[0].id}
                    onChange={(e) => setSelectedProjectId(Number(e.target.value))}
                    className="bg-[#05070A] border border-outline-variant/60 rounded px-2 py-1 text-xs text-on-surface focus:outline-none focus:border-primary"
                  >
                    {projectsList.map(p => (
                      <option key={p.id} value={p.id}>{p.name} (ID: {p.id})</option>
                    ))}
                  </select>
                </div>
              )}
            </div>

            <div className="relative">
              <button 
                onClick={() => setIsFilterDropdownOpen(!isFilterDropdownOpen)}
                className="text-primary hover:text-primary-fixed flex items-center gap-1 text-sm font-medium transition-colors bg-transparent border-none cursor-pointer"
              >
                <span className="material-symbols-outlined text-[18px]">filter_list</span> 
                Filter: {filterCategory}
              </button>
              
              {isFilterDropdownOpen && (
                <div className="absolute right-0 mt-2 w-48 bg-[#0F131A] border border-outline-variant/50 rounded-lg shadow-xl py-1 z-30 font-label-mono text-xs">
                  {['All', 'Executive', 'Technical', 'Compliance'].map(cat => (
                    <button
                      key={cat}
                      onClick={() => {
                        setFilterCategory(cat as any);
                        setIsFilterDropdownOpen(false);
                      }}
                      className={`w-full text-left px-4 py-2 hover:bg-surface-container-high transition-colors ${
                        filterCategory === cat ? 'text-primary font-bold' : 'text-on-surface-variant'
                      }`}
                    >
                      {cat}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-stack-md">
            
            {filteredTemplates.map((template) => {
              const keyMap: Record<string, string> = {
                't-1': 'executive',
                't-2': 'developer',
                't-3': 'compliance',
                't-4': 'owasp',
              };
              const templateKey = keyMap[template.id] || 'executive';

              return (
                <div 
                  key={template.id}
                  className="bg-surface-container rounded-xl border border-outline-variant/30 p-stack-md flex flex-col h-full hover:border-primary/50 transition-colors duration-300 relative group"
                >
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <div className={`w-10 h-10 rounded flex items-center justify-center ${template.iconBg} ${template.iconColor}`}>
                        <span className="material-symbols-outlined">{template.icon}</span>
                      </div>
                      <div>
                        <h3 className="font-bold text-on-surface">{template.title}</h3>
                        <p className="text-xs text-on-surface-variant font-label-mono mt-1">{template.subtitle}</p>
                      </div>
                    </div>
                    <span className="px-2 py-0.5 rounded bg-surface-variant text-on-surface-variant text-[10px] font-label-mono flex items-center gap-1 border border-outline-variant/20">
                      <span className="material-symbols-outlined text-[12px]">schedule</span> 
                      {template.timeAgo}
                    </span>
                  </div>
                  
                  <p className="text-sm text-on-surface-variant mb-6 flex-grow leading-relaxed">
                    {template.description}
                  </p>
                  
                  <div className="flex items-center gap-3 mt-auto pt-4 border-t border-outline-variant/20">
                    <button 
                      onClick={() => handleOpenPreview(template)}
                      className="flex-1 py-2 rounded-md bg-primary text-on-primary font-semibold text-sm hover:brightness-110 active:scale-95 transition-all flex justify-center items-center gap-2 cursor-pointer border-none shadow-[0_0_15px_rgba(166,200,255,0.2)]"
                    >
                      <span className="material-symbols-outlined text-[18px]">visibility</span> Preview
                    </button>
                    
                    <button 
                      onClick={() => handleDownloadPdf(templateKey, template.title)}
                      className="w-10 h-10 rounded-md bg-surface-container-high border border-outline-variant/40 text-on-surface flex items-center justify-center hover:text-primary transition-colors cursor-pointer active:scale-95" 
                      title="Download PDF"
                    >
                      <span className="material-symbols-outlined text-[18px]">picture_as_pdf</span>
                    </button>
                  </div>
                </div>
              );
            })}

          </div>
        </div>

        {/* Right Area: AI Assistant Panel */}
        <div className="w-full lg:w-80 shrink-0">
          <div className="glass-panel rounded-xl p-stack-md flex flex-col gap-stack-md border border-primary/20 relative overflow-hidden">
            
            <div className="flex items-center gap-2 pb-2 border-b border-outline-variant/30">
              <span className="material-symbols-outlined text-primary">smart_toy</span>
              <h3 className="text-sm font-bold text-on-surface">AI Report Assistant</h3>
            </div>
            
            <div className="text-sm text-on-surface-variant leading-relaxed">
              <p className="mb-4">Kyptic AI has analyzed the latest scan results across all applications and generated strategic insights.</p>
              
              <div className="bg-surface-container-highest p-3 rounded-lg border border-outline-variant/40 mb-4 relative overflow-hidden">
                <div className="absolute top-0 left-0 w-1 h-full bg-error" />
                <div className="flex items-center gap-2 mb-2 select-none">
                  <span className="material-symbols-outlined text-error text-[16px]">warning</span>
                  <span className="font-bold text-on-surface text-xs uppercase tracking-wider">Business Impact</span>
                </div>
                <p className="text-xs text-on-surface-variant">
                  Unpatched critical vulnerabilities in the Payment Gateway module present an estimated <span className="text-error font-mono font-bold">$1.2M</span> financial risk exposure.
                </p>
              </div>
            </div>

            <div className="flex flex-col gap-2">
              <span className="font-label-mono text-[10px] text-on-surface-variant uppercase tracking-wider mb-1">Quick Actions</span>
              
              <button 
                onClick={() => handleDownloadPdf('executive', 'Executive Summary')}
                className="flex items-center justify-between p-2 rounded bg-surface-variant hover:bg-surface-bright border border-transparent hover:border-outline-variant/40 transition-colors group cursor-pointer text-left"
              >
                <span className="text-sm text-on-surface group-hover:text-primary transition-colors">Generate Executive Summary</span>
                <span className="material-symbols-outlined text-[16px] text-on-surface-variant group-hover:text-primary">arrow_forward</span>
              </button>
              
              <button 
                onClick={() => handleDownloadPdf('developer', 'Developer Deep-Dive')}
                className="flex items-center justify-between p-2 rounded bg-surface-variant hover:bg-surface-bright border border-transparent hover:border-outline-variant/40 transition-colors group cursor-pointer text-left"
              >
                <span className="text-sm text-on-surface group-hover:text-primary transition-colors">Summarize Findings</span>
                <span className="material-symbols-outlined text-[16px] text-on-surface-variant group-hover:text-primary">arrow_forward</span>
              </button>

              <button 
                onClick={() => handleDownloadPdf('compliance', 'Compliance Review')}
                className="flex items-center justify-between p-2 rounded bg-surface-variant hover:bg-surface-bright border border-transparent hover:border-outline-variant/40 transition-colors group cursor-pointer text-left"
              >
                <span className="text-sm text-on-surface group-hover:text-primary transition-colors">Business Risk Analysis</span>
                <span className="material-symbols-outlined text-[16px] text-on-surface-variant group-hover:text-primary">arrow_forward</span>
              </button>
            </div>

            <button 
              onClick={() => handleDownloadPdf('executive', 'Executive Board Presentation')}
              className="w-full py-3 rounded-lg bg-primary text-on-primary font-bold text-sm hover:brightness-110 active:scale-95 transition-all flex justify-center items-center gap-2 mt-2 shadow-[0_0_20px_rgba(49,146,252,0.3)] border-none cursor-pointer"
            >
              <span className="material-symbols-outlined">present_to_all</span> Create Board Presentation
            </button>

          </div>
        </div>

      </div>

      {/* Bottom Section: Timelines & Schedules */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-stack-lg mt-stack-md pt-stack-lg border-t border-outline-variant/20">
        
        {/* Recent Reports Timeline */}
        <div className="flex flex-col gap-stack-md w-full">
          <h3 className="font-headline-md text-lg text-on-surface font-semibold select-none">Recent Reports History</h3>
          
          <div className="bg-surface-container rounded-xl border border-outline-variant/30 p-stack-md">
            <div className="relative border-l border-outline-variant ml-3 space-y-6">
              
              {historyList.map((hist) => (
                <div key={hist.id} className="relative pl-6">
                  <div className="absolute w-3 h-3 bg-primary rounded-full -left-[6.5px] top-1.5 shadow-[0_0_8px_rgba(49,146,252,0.6)]" />
                  <div className="flex flex-col gap-1">
                    <div className="flex justify-between items-start">
                      <h4 className="text-sm font-bold text-on-surface select-all">{hist.title}</h4>
                      <span className="text-xs text-on-surface-variant font-label-mono">{hist.time}</span>
                    </div>
                    <p className="text-xs text-on-surface-variant">{hist.generator}</p>
                    <div className="flex gap-2 mt-2 select-none">
                      <button 
                        onClick={() => alert(`Downloading ${hist.type}...`)}
                        className="text-primary text-xs hover:underline flex items-center gap-1 bg-transparent border-none cursor-pointer"
                      >
                        <span className="material-symbols-outlined text-[14px]">download</span> {hist.type}
                      </button>
                    </div>
                  </div>
                </div>
              ))}

            </div>
            
            <button 
              onClick={() => alert('All archives are loaded!')}
              className="w-full text-center mt-6 text-sm text-on-surface-variant hover:text-primary transition-colors cursor-pointer bg-transparent border-none"
            >
              View All History
            </button>
          </div>
        </div>

        {/* Scheduled Reports */}
        <div className="flex flex-col gap-stack-md w-full">
          
          <div className="flex justify-between items-center select-none">
            <h3 className="font-headline-md text-lg text-on-surface font-semibold">Scheduled Reports</h3>
            <button 
              onClick={() => setIsScheduleModalOpen(true)}
              className="bg-surface-container-high border border-outline-variant text-on-surface hover:text-primary transition-colors text-xs px-3 py-1.5 rounded flex items-center gap-1 cursor-pointer font-bold"
            >
              <span className="material-symbols-outlined text-[14px]">add</span> New Schedule
            </button>
          </div>

          <div className="flex flex-col gap-3">
            
            {scheduledList.map((item) => (
              <div 
                key={item.id}
                className="bg-surface-container rounded-lg border border-outline-variant/30 p-4 flex items-center justify-between hover:border-outline-variant transition-colors group"
              >
                <div className="flex items-center gap-4">
                  <div className="w-10 h-10 rounded-full bg-surface-variant flex items-center justify-center border border-outline-variant/50">
                    <span className="material-symbols-outlined text-on-surface-variant text-[18px]">calendar_month</span>
                  </div>
                  <div>
                    <h4 className="text-sm font-bold text-on-surface select-all">{item.title}</h4>
                    <p className="text-xs text-on-surface-variant mt-0.5 select-all">{item.schedule}</p>
                  </div>
                </div>
                
                <div className="flex items-center gap-4 select-none">
                  {item.authorInitials ? (
                    <div className="flex -space-x-2">
                      {item.authorInitials.map((ini, i) => (
                        <div key={i} className="w-6 h-6 rounded-full bg-secondary-container border border-surface text-[10px] flex items-center justify-center text-on-surface">
                          {ini}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <span className="text-xs text-on-surface-variant px-2 py-1 bg-surface-variant rounded">
                      {item.recipientsCount} Recipients
                    </span>
                  )}
                  
                  <button 
                    onClick={() => handleDeleteSchedule(item.id)}
                    className="text-on-surface-variant hover:text-error transition-colors bg-transparent border-none cursor-pointer"
                    title="Remove Schedule"
                  >
                    <span className="material-symbols-outlined text-[18px]">delete</span>
                  </button>
                </div>
              </div>
            ))}

          </div>
        </div>

      </div>

      {/* Modal: New Schedule overlay */}
      {isScheduleModalOpen && (
        <div className="fixed inset-0 bg-[#000]/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#0D1016] border border-[#1F242D] rounded-xl w-full max-w-md p-6 relative">
            <h3 className="text-lg font-bold text-on-surface mb-4">Create New Report Schedule</h3>
            
            <form onSubmit={handleCreateSchedule} className="space-y-4">
              <div>
                <label className="block text-xs font-label-mono text-on-surface-variant uppercase mb-1">Schedule Name</label>
                <input 
                  type="text" 
                  required
                  placeholder="e.g. Weekly CISO Risk Brief"
                  value={newScheduleTitle}
                  onChange={e => setNewScheduleTitle(e.target.value)}
                  className="w-full bg-[#05070A] border border-outline-variant/60 rounded px-3 py-2 text-sm focus:outline-none focus:border-primary text-on-surface"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-label-mono text-on-surface-variant uppercase mb-1">Frequency</label>
                  <select 
                    value={newScheduleFreq}
                    onChange={e => setNewScheduleFreq(e.target.value)}
                    className="w-full bg-[#05070A] border border-outline-variant/60 rounded px-2 py-2 text-sm focus:outline-none focus:border-primary text-on-surface"
                  >
                    <option value="Daily">Daily</option>
                    <option value="Weekly">Weekly</option>
                    <option value="Monthly">Monthly</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-label-mono text-on-surface-variant uppercase mb-1">Time (EST)</label>
                  <input 
                    type="text" 
                    placeholder="e.g. 08:00 AM"
                    value={newScheduleTime}
                    onChange={e => setNewScheduleTime(e.target.value)}
                    className="w-full bg-[#05070A] border border-outline-variant/60 rounded px-3 py-2 text-sm focus:outline-none focus:border-primary text-on-surface"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-label-mono text-on-surface-variant uppercase mb-1">Recipients Count</label>
                <input 
                  type="text" 
                  placeholder="e.g. 4 Recipients"
                  value={newScheduleRecipients}
                  onChange={e => setNewScheduleRecipients(e.target.value)}
                  className="w-full bg-[#05070A] border border-outline-variant/60 rounded px-3 py-2 text-sm focus:outline-none focus:border-primary text-on-surface"
                />
              </div>

              <div className="flex gap-3 justify-end pt-4">
                <button 
                  type="button"
                  onClick={() => setIsScheduleModalOpen(false)}
                  className="px-4 py-2 rounded bg-surface-container hover:bg-surface-container-high transition-colors cursor-pointer border-none text-sm"
                >
                  Cancel
                </button>
                <button 
                  type="submit"
                  className="px-4 py-2 rounded bg-primary text-on-primary font-bold hover:brightness-110 transition-all cursor-pointer border-none text-sm"
                >
                  Save Schedule
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Report Preview overlay */}
      {isPreviewOpen && activePreviewTemplate && (
        <div className="fixed inset-0 bg-[#000]/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#0D1016] border border-[#1F242D] rounded-xl w-full max-w-4xl max-h-[85vh] flex flex-col relative">
            
            {/* Modal Header */}
            <div className="p-4 border-b border-[#1F242D] flex justify-between items-center shrink-0">
              <div>
                <span className="text-xs text-outline font-label-mono font-bold uppercase">{activePreviewTemplate.category} REPORT PREVIEW</span>
                <h3 className="text-lg font-bold text-on-surface">{activePreviewTemplate.title}</h3>
              </div>
              <button 
                onClick={() => setIsPreviewOpen(false)}
                className="text-outline hover:text-on-surface transition-colors cursor-pointer bg-transparent border-none"
              >
                <span className="material-symbols-outlined">close</span>
              </button>
            </div>

            {/* Modal Content Scroll */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6 font-body-md text-sm leading-relaxed text-on-surface-variant">
              
              {previewData && (
                <div className="space-y-4">
                  <div className="flex justify-between items-center p-4 bg-primary/5 border border-primary/20 rounded-lg">
                    <div>
                      <h4 className="font-bold text-on-surface text-base">{previewData.project_name} - Security Posture Report</h4>
                      <p className="text-xs mt-1">Generated on-demand for Project ID: {previewData.project_id} | Total Findings: {previewData.metrics?.total_findings}</p>
                    </div>
                    <div className="text-right">
                      <span className="text-3xl font-bold text-primary">{previewData.metrics?.security_score}</span>
                      <span className="text-xs block text-on-surface-variant">Grade: {previewData.metrics?.security_grade}</span>
                    </div>
                  </div>

                  <div className="grid grid-cols-4 gap-3 text-center my-4">
                    <div className="bg-[#111827] p-3 rounded border border-error/30">
                      <div className="text-xs font-bold text-error">CRITICAL</div>
                      <div className="text-xl font-bold text-error">{previewData.metrics?.severity_counts?.critical || 0}</div>
                    </div>
                    <div className="bg-[#111827] p-3 rounded border border-orange-500/30">
                      <div className="text-xs font-bold text-orange-400">HIGH</div>
                      <div className="text-xl font-bold text-orange-400">{previewData.metrics?.severity_counts?.high || 0}</div>
                    </div>
                    <div className="bg-[#111827] p-3 rounded border border-yellow-500/30">
                      <div className="text-xs font-bold text-yellow-400">MEDIUM</div>
                      <div className="text-xl font-bold text-yellow-400">{previewData.metrics?.severity_counts?.medium || 0}</div>
                    </div>
                    <div className="bg-[#111827] p-3 rounded border border-blue-500/30">
                      <div className="text-xs font-bold text-blue-400">LOW / INFO</div>
                      <div className="text-xl font-bold text-blue-400">{(previewData.metrics?.severity_counts?.low || 0) + (previewData.metrics?.severity_counts?.info || 0)}</div>
                    </div>
                  </div>

                  <h5 className="font-bold text-on-surface pt-2">Discovered Vulnerabilities & Findings</h5>
                  {previewData.findings && previewData.findings.length > 0 ? (
                    <div className="space-y-3">
                      {previewData.findings.map((f: any) => (
                        <div key={f.id} className="p-3 bg-[#0b0f19] border border-outline-variant/30 rounded">
                          <div className="flex justify-between items-center mb-1">
                            <span className="font-bold text-on-surface text-sm">{f.title}</span>
                            <span className="text-xs uppercase px-2 py-0.5 rounded font-mono font-bold bg-error/10 text-error border border-error/20">{f.severity}</span>
                          </div>
                          <p className="text-xs text-on-surface-variant mb-2">{f.description}</p>
                          <div className="text-xs font-mono text-primary bg-[#050608] p-2 rounded truncate">{f.code_snippet || f.file_path}</div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-on-surface-variant italic">No findings reported for this target project.</p>
                  )}
                </div>
              )}

              {!previewData && (
                <div className="flex items-center justify-center p-8">
                  <span className="text-on-surface-variant animate-pulse font-mono">Compiling live report data...</span>
                </div>
              )}

            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-[#1F242D] flex gap-3 justify-end shrink-0 select-none bg-[#0D1016]">
              <button 
                onClick={() => setIsPreviewOpen(false)}
                className="px-4 py-2 rounded bg-surface-container hover:bg-surface-container-high transition-colors cursor-pointer border-none text-sm"
              >
                Close Preview
              </button>
              
              <button 
                onClick={() => {
                  setIsPreviewOpen(false);
                  const keyMap: Record<string, string> = {
                    't-1': 'executive',
                    't-2': 'developer',
                    't-3': 'compliance',
                    't-4': 'owasp',
                  };
                  const reportKey = keyMap[activePreviewTemplate.id] || 'executive';
                  handleDownloadPdf(reportKey, activePreviewTemplate.title);
                }}
                className="px-4 py-2 rounded bg-primary text-on-primary font-bold hover:brightness-110 transition-all cursor-pointer border-none text-sm flex items-center gap-1"
              >
                <span className="material-symbols-outlined text-[16px]">picture_as_pdf</span>
                Download Report PDF
              </button>
            </div>

          </div>
        </div>
      )}

      {/* Loading Action Spinner Overlay */}
      {isActionLoading && (
        <div className="fixed inset-0 bg-[#000]/80 backdrop-blur-md z-[60] flex flex-col items-center justify-center gap-4 select-none">
          <span className="material-symbols-outlined text-4xl text-primary animate-spin">sync</span>
          <span className="text-primary text-sm font-label-mono font-bold tracking-wider animate-pulse">{loadingText}</span>
        </div>
      )}

    </div>
  );
};

export default Reports;
