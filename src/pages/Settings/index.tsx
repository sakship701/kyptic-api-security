import React, { useState } from 'react';

export const Settings: React.FC = () => {
  // Navigation active tab
  const [activeTab, setActiveTab] = useState<'general' | 'ai-config' | 'scanners' | 'system'>('general');

  // Input states
  const [orgName, setOrgName] = useState('Acme Corp Security');
  const [timezone, setTimezone] = useState('EST (Eastern Standard Time)');
  const [aiModel, setAiModel] = useState('Kyptic-Pro-v1 (Recommended)');
  const [temperature, setTemperature] = useState(0.2);

  // Scanner status toggles
  const [scanners, setScanners] = useState({
    semgrep: true,
    dast: true,
    secret: false
  });

  // Action states
  const [isUpdating, setIsUpdating] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [isDirty, setIsDirty] = useState(false);

  const handleToggleScanner = (key: 'semgrep' | 'dast' | 'secret') => {
    setScanners(prev => ({
      ...prev,
      [key]: !prev[key]
    }));
    setIsDirty(true);
  };

  const handleFieldChange = (setter: (val: any) => void, val: any) => {
    setter(val);
    setIsDirty(true);
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    // Simulate save duration
    await new Promise(resolve => setTimeout(resolve, 1200));
    setIsSaving(false);
    setIsDirty(false);
    alert('Kyptic platform configurations updated successfully!');
  };

  const handleCheckUpdates = async () => {
    setIsUpdating(true);
    await new Promise(resolve => setTimeout(resolve, 1500));
    setIsUpdating(false);
    alert('Your Kyptic instance is up to date! (Current version: v2.4.1)');
  };

  const scrollToSection = (id: 'general' | 'ai-config' | 'scanners' | 'system') => {
    setActiveTab(id);
    const element = document.getElementById(id);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  };

  return (
    <div className="p-4 md:p-container-padding max-w-[1600px] mx-auto w-full flex flex-col gap-stack-lg text-on-surface select-none relative">
      
      {/* Header */}
      <header className="flex flex-col gap-stack-sm">
        <h2 className="font-headline-md text-headline-md text-on-surface mb-2 font-bold">Settings</h2>
        <p className="text-on-surface-variant font-body-md max-w-3xl">
          Manage platform configuration, AI services, scanners, integrations, and security preferences.
        </p>
      </header>

      <form onSubmit={handleSave} className="flex flex-col lg:flex-row gap-gutter items-start">
        
        {/* Settings Navigation (In-page Sidebar) */}
        <aside className="lg:w-64 shrink-0 hidden lg:block sticky top-24 self-start">
          <nav className="flex flex-col gap-2 font-label-mono text-label-mono">
            <button
              type="button"
              onClick={() => scrollToSection('general')}
              className={`text-left px-4 py-2 rounded-lg transition-colors border-none cursor-pointer ${
                activeTab === 'general' 
                  ? 'bg-surface-variant text-on-surface font-semibold' 
                  : 'text-on-surface-variant hover:bg-surface-variant/40'
              }`}
            >
              General
            </button>
            <button
              type="button"
              onClick={() => scrollToSection('ai-config')}
              className={`text-left px-4 py-2 rounded-lg transition-colors border-none cursor-pointer ${
                activeTab === 'ai-config' 
                  ? 'bg-surface-variant text-on-surface font-semibold' 
                  : 'text-on-surface-variant hover:bg-surface-variant/40'
              }`}
            >
              AI Configuration
            </button>
            <button
              type="button"
              onClick={() => scrollToSection('scanners')}
              className={`text-left px-4 py-2 rounded-lg transition-colors border-none cursor-pointer ${
                activeTab === 'scanners' 
                  ? 'bg-surface-variant text-on-surface font-semibold' 
                  : 'text-on-surface-variant hover:bg-surface-variant/40'
              }`}
            >
              Scanner Configuration
            </button>
            <button
              type="button"
              onClick={() => scrollToSection('system')}
              className={`text-left px-4 py-2 rounded-lg transition-colors border-none cursor-pointer ${
                activeTab === 'system' 
                  ? 'bg-surface-variant text-on-surface font-semibold' 
                  : 'text-on-surface-variant hover:bg-surface-variant/40'
              }`}
            >
              Security &amp; System
            </button>
          </nav>
        </aside>

        {/* Settings Content Panels */}
        <div className="flex-1 flex flex-col gap-stack-lg w-full">
          
          {/* General Section */}
          <section className="glass-panel rounded-xl p-6 scroll-mt-24" id="general">
            <h3 className="font-body-lg text-body-lg text-on-surface mb-6 border-b border-outline-variant/30 pb-2 flex items-center gap-2 font-bold">
              <span className="material-symbols-outlined text-primary">tune</span> General
            </h3>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="flex flex-col gap-2">
                <label className="font-label-mono text-xs text-on-surface-variant uppercase">Organization Name</label>
                <input 
                  type="text" 
                  value={orgName}
                  onChange={e => handleFieldChange(setOrgName, e.target.value)}
                  className="bg-[#05070A] border border-outline-variant/50 rounded-lg px-4 py-2.5 text-on-surface focus:outline-none focus:border-primary transition-all font-sans text-sm select-text"
                />
              </div>

              <div className="flex flex-col gap-2">
                <label className="font-label-mono text-xs text-on-surface-variant uppercase">Timezone</label>
                <select 
                  value={timezone}
                  onChange={e => handleFieldChange(setTimezone, e.target.value)}
                  className="bg-[#05070A] border border-outline-variant/50 rounded-lg px-4 py-2.5 text-on-surface focus:outline-none focus:border-primary transition-all font-sans text-sm"
                >
                  <option value="UTC (Coordinated Universal Time)">UTC (Coordinated Universal Time)</option>
                  <option value="EST (Eastern Standard Time)">EST (Eastern Standard Time)</option>
                  <option value="PST (Pacific Standard Time)">PST (Pacific Standard Time)</option>
                </select>
              </div>
            </div>
          </section>

          {/* AI Configuration Section */}
          <section className="glass-panel rounded-xl p-6 scroll-mt-24" id="ai-config">
            <h3 className="font-body-lg text-body-lg text-on-surface mb-6 border-b border-outline-variant/30 pb-2 flex items-center gap-2 font-bold">
              <span className="material-symbols-outlined text-primary">smart_toy</span> AI Configuration
            </h3>

            <div className="space-y-6">
              <div className="flex items-center justify-between p-4 bg-surface-container-low rounded-lg border border-outline-variant/30">
                <div>
                  <h4 className="font-semibold text-on-surface text-sm">Local LLM Status</h4>
                  <p className="text-xs text-on-surface-variant mt-1 font-label-mono">Kyptic-Pro-v1 Engine</p>
                </div>
                <div className="flex items-center gap-2 px-3 py-1 bg-surface-container-highest rounded-full border border-outline-variant/50">
                  <div className="w-2 h-2 rounded-full bg-primary animate-pulse shadow-[0_0_8px_rgba(49,146,252,0.8)]" />
                  <span className="font-label-mono text-[10px] text-primary uppercase font-bold">Active</span>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="flex flex-col gap-2">
                  <label className="font-label-mono text-xs text-on-surface-variant uppercase">Model Selection</label>
                  <select 
                    value={aiModel}
                    onChange={e => handleFieldChange(setAiModel, e.target.value)}
                    className="bg-[#05070A] border border-outline-variant/50 rounded-lg px-4 py-2.5 text-on-surface focus:outline-none focus:border-primary transition-all font-sans text-sm"
                  >
                    <option value="Kyptic-Pro-v1 (Recommended)">Kyptic-Pro-v1 (Recommended)</option>
                    <option value="Kyptic-Fast-v2">Kyptic-Fast-v2</option>
                    <option value="Custom ONNX Model">Custom ONNX Model</option>
                  </select>
                </div>

                <div className="flex flex-col gap-2">
                  <div className="flex justify-between items-center">
                    <label className="font-label-mono text-xs text-on-surface-variant uppercase">Temperature</label>
                    <span className="font-mono text-sm text-primary font-bold">{temperature}</span>
                  </div>
                  <input 
                    type="range" 
                    min="0"
                    max="1"
                    step="0.1"
                    value={temperature}
                    onChange={e => handleFieldChange(setTemperature, parseFloat(e.target.value))}
                    className="w-full accent-primary mt-3 cursor-pointer"
                  />
                </div>
              </div>
            </div>
          </section>

          {/* Scanner Configuration Section */}
          <section className="glass-panel rounded-xl p-6 scroll-mt-24" id="scanners">
            <h3 className="font-body-lg text-body-lg text-on-surface mb-6 border-b border-outline-variant/30 pb-2 flex items-center gap-2 font-bold">
              <span className="material-symbols-outlined text-primary">radar</span> Scanner Configuration
            </h3>

            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4">
              
              {/* Semgrep */}
              <div className="flex items-center justify-between p-4 bg-[#0A0D12] rounded-lg border border-outline-variant/30 hover:border-primary/50 transition-colors group">
                <div className="flex items-center gap-3">
                  <span className="material-symbols-outlined text-on-surface-variant group-hover:text-primary transition-colors">code_blocks</span>
                  <div>
                    <h4 className="font-bold text-sm text-on-surface">Semgrep</h4>
                    <p className="text-xs text-on-surface-variant mt-0.5">Code analysis</p>
                  </div>
                </div>
                
                <button
                  type="button"
                  onClick={() => handleToggleScanner('semgrep')}
                  className={`w-9 h-5 rounded-full relative transition-colors border-none cursor-pointer ${
                    scanners.semgrep ? 'bg-primary shadow-[0_0_10px_rgba(49,146,252,0.3)]' : 'bg-surface-variant'
                  }`}
                >
                  <div className={`w-4 h-4 rounded-full bg-white absolute top-0.5 transition-all ${
                    scanners.semgrep ? 'left-[18px]' : 'left-0.5'
                  }`} />
                </button>
              </div>

              {/* DAST */}
              <div className="flex items-center justify-between p-4 bg-[#0A0D12] rounded-lg border border-outline-variant/30 hover:border-primary/50 transition-colors group">
                <div className="flex items-center gap-3">
                  <span className="material-symbols-outlined text-on-surface-variant group-hover:text-primary transition-colors">bug_report</span>
                  <div>
                    <h4 className="font-bold text-sm text-on-surface">DAST Engine</h4>
                    <p className="text-xs text-on-surface-variant mt-0.5">Dynamic testing</p>
                  </div>
                </div>
                
                <button
                  type="button"
                  onClick={() => handleToggleScanner('dast')}
                  className={`w-9 h-5 rounded-full relative transition-colors border-none cursor-pointer ${
                    scanners.dast ? 'bg-primary shadow-[0_0_10px_rgba(49,146,252,0.3)]' : 'bg-surface-variant'
                  }`}
                >
                  <div className={`w-4 h-4 rounded-full bg-white absolute top-0.5 transition-all ${
                    scanners.dast ? 'left-[18px]' : 'left-0.5'
                  }`} />
                </button>
              </div>

              {/* Secret Scanner */}
              <div className="flex items-center justify-between p-4 bg-[#0A0D12] rounded-lg border border-outline-variant/30 hover:border-primary/50 transition-colors group">
                <div className="flex items-center gap-3">
                  <span className={`material-symbols-outlined ${scanners.secret ? 'text-on-surface-variant group-hover:text-primary' : 'text-outline'} transition-colors`}>verified</span>
                  <div>
                    <h4 className={`font-bold text-sm ${scanners.secret ? 'text-on-surface' : 'text-on-surface-variant'}`}>Secret Scanner</h4>
                    <p className={`text-xs ${scanners.secret ? 'text-on-surface-variant' : 'text-outline'} mt-0.5`}>Credential detection</p>
                  </div>
                </div>
                
                <button
                  type="button"
                  onClick={() => handleToggleScanner('secret')}
                  className={`w-9 h-5 rounded-full relative transition-colors border-none cursor-pointer ${
                    scanners.secret ? 'bg-primary shadow-[0_0_10px_rgba(49,146,252,0.3)]' : 'bg-surface-variant'
                  }`}
                >
                  <div className={`w-4 h-4 rounded-full bg-white absolute top-0.5 transition-all ${
                    scanners.secret ? 'left-[18px]' : 'left-0.5'
                  }`} />
                </button>
              </div>

            </div>
          </section>

          {/* Security & System Section */}
          <section className="glass-panel rounded-xl p-6 scroll-mt-24 mb-16" id="system">
            <h3 className="font-body-lg text-body-lg text-on-surface mb-6 border-b border-outline-variant/30 pb-2 flex items-center gap-2 font-bold">
              <span className="material-symbols-outlined text-primary">dns</span> Security &amp; System
            </h3>

            <div className="bg-surface-container-low rounded-lg p-4 border border-outline-variant/30 flex flex-col md:flex-row justify-between items-center gap-4">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-surface-variant rounded-lg text-primary">
                  <span className="material-symbols-outlined">memory</span>
                </div>
                <div>
                  <h4 className="text-sm font-semibold text-on-surface">System Health</h4>
                  <p className="text-xs font-mono text-on-surface-variant mt-1">CPU: 12% | RAM: 34GB/64GB</p>
                </div>
              </div>
              
              <div className="text-right flex flex-col items-center md:items-end gap-2">
                <span className="text-xs text-on-surface-variant font-label-mono">Version v2.4.1</span>
                
                <button 
                  type="button"
                  onClick={handleCheckUpdates}
                  className="text-xs px-4 py-2 border border-outline-variant/50 rounded-lg hover:bg-surface-variant transition-colors cursor-pointer bg-transparent text-on-surface font-semibold"
                >
                  Check Updates
                </button>
              </div>
            </div>
          </section>

        </div>
      </form>

      {/* Floating Save Actions bar */}
      {isDirty && (
        <div className="fixed bottom-6 right-6 z-40 bg-[#0D1016] border border-[#1F242D] rounded-xl p-4 shadow-2xl flex items-center gap-4 animate-[slideIn_0.3s_ease-out]">
          <span className="text-xs text-on-surface-variant">You have unsaved configuration changes</span>
          
          <div className="flex gap-2">
            <button 
              type="button"
              onClick={() => {
                setOrgName('Acme Corp Security');
                setTimezone('EST (Eastern Standard Time)');
                setAiModel('Kyptic-Pro-v1 (Recommended)');
                setTemperature(0.2);
                setScanners({ semgrep: true, dast: true, secret: false });
                setIsDirty(false);
              }}
              className="px-3 py-1.5 rounded bg-surface-container hover:bg-surface-container-high transition-colors cursor-pointer border-none text-xs font-semibold"
            >
              Discard
            </button>
            <button 
              type="button"
              onClick={handleSave}
              className="px-4 py-1.5 rounded bg-primary text-on-primary hover:brightness-110 transition-all cursor-pointer border-none text-xs font-bold flex items-center gap-1 shadow-[0_0_15px_rgba(166,200,255,0.2)]"
            >
              Save Settings
            </button>
          </div>
        </div>
      )}

      {/* Saving and updating Spinners */}
      {(isSaving || isUpdating) && (
        <div className="fixed inset-0 bg-[#000]/80 backdrop-blur-md z-50 flex flex-col items-center justify-center gap-4">
          <span className="material-symbols-outlined text-4xl text-primary animate-spin">sync</span>
          <span className="text-primary text-sm font-label-mono font-bold tracking-wider animate-pulse">
            {isSaving ? 'Applying enterprise settings rules...' : 'Contacting mirror servers...'}
          </span>
        </div>
      )}

    </div>
  );
};

export default Settings;
