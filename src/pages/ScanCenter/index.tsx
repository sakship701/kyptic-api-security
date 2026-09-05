import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useApp } from '../../context/AppContext';
import GlassPanel from '../../components/ui/GlassPanel';

interface LogLine {
  time: string;
  text: string;
  type: 'info' | 'warn' | 'ai' | 'success';
}

export const ScanCenter: React.FC = () => {
  const navigate = useNavigate();
  const { isScanning, scanProgress, scanStatus, startScan, activeProjectId, projects } = useApp();
  
  const activeProject = projects.find(p => p.id === activeProjectId) || projects[0];

  // Logs state
  const [logs, setLogs] = useState<LogLine[]>([
    { time: '07:33:21', text: '[INFO] Initializing scan environment...', type: 'info' }
  ]);

  // Insights state
  const [insights, setInsights] = useState<{ text: string; type: 'error' | 'warning' }[]>([]);

  // Local scanning state for timeline card metrics
  const [phaseProgress, setPhaseProgress] = useState({
    sast: 0,
    risk: 0,
    dast: 0,
    validation: 0,
    ai: 0,
    report: 0
  });

  const consoleEndRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  // Trigger scan from local action
  const handleStartScan = () => {
    setLogs([{ time: new Date().toTimeString().split(' ')[0], text: '[INFO] Starting Intelligent Scan...', type: 'info' }]);
    setInsights([]);
    void startScan(activeProjectId).catch(() => undefined);
  };

  // Particles Backdrop effect (luxury constellation node shader simulation)
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const particles: { x: number; y: number; vx: number; vy: number; radius: number }[] = [];
    const particleCount = 40;

    for (let i = 0; i < particleCount; i++) {
      particles.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.4,
        vy: (Math.random() - 0.5) * 0.4,
        radius: Math.random() * 2 + 1,
      });
    }

    const draw = () => {
      ctx.clearRect(0, 0, width, height);
      ctx.fillStyle = '#06070A';
      ctx.fillRect(0, 0, width, height);

      // Lines connecting nodes
      ctx.strokeStyle = 'rgba(49, 146, 252, 0.05)';
      ctx.lineWidth = 0.8;
      for (let i = 0; i < particleCount; i++) {
        for (let j = i + 1; j < particleCount; j++) {
          const dx = particles[i].x - particles[j].x;
          const dy = particles[i].y - particles[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < 150) {
            ctx.beginPath();
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y);
            ctx.stroke();
          }
        }
      }

      // Draw nodes
      ctx.fillStyle = 'rgba(49, 146, 252, 0.2)';
      for (let i = 0; i < particleCount; i++) {
        const p = particles[i];
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
        ctx.fill();

        // Move particle
        p.x += p.vx;
        p.y += p.vy;

        // Bounce borders
        if (p.x < 0 || p.x > width) p.vx *= -1;
        if (p.y < 0 || p.y > height) p.vy *= -1;
      }

      animationFrameId = requestAnimationFrame(draw);
    };

    draw();

    const handleResize = () => {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };
    window.addEventListener('resize', handleResize);

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener('resize', handleResize);
    };
  }, []);

  // Monitor Scan progress and update console logs, timeline cards, and insights dynamically
  useEffect(() => {
    if (!isScanning) {
      if (scanProgress === 100) {
        // Finalize completed scan
        setPhaseProgress({
          sast: 100,
          risk: 100,
          dast: 100,
          validation: 100,
          ai: 100,
          report: 100
        });
      }
      return;
    }

    const timeString = () => new Date().toTimeString().split(' ')[0];

    // SAST Phase (0% - 20%)
    if (scanProgress > 0 && scanProgress <= 20) {
      const sastVal = Math.min(100, scanProgress * 5);
      setPhaseProgress(prev => ({ ...prev, sast: sastVal }));
      if (scanProgress === 5) {
        setLogs(prev => [...prev, { time: timeString(), text: '[SAST] Launching Semgrep Static Analyzer...', type: 'info' }]);
      }
      if (scanProgress === 15) {
        setLogs(prev => [...prev, { time: timeString(), text: '[SAST] Source code AST analysis completed.', type: 'info' }]);
      }
    }

    // Secret Detection (20% - 40%)
    if (scanProgress > 20 && scanProgress <= 40) {
      const riskVal = Math.min(100, (scanProgress - 20) * 5);
      setPhaseProgress(prev => ({ ...prev, sast: 100, risk: riskVal }));
      if (scanProgress === 25) {
        setLogs(prev => [...prev, { time: timeString(), text: '[SECRETS] Launching detect-secrets Scanner...', type: 'info' }]);
      }
      if (scanProgress === 35) {
        setLogs(prev => [...prev, { time: timeString(), text: '[SECRETS] Scanned source files for hardcoded secrets.', type: 'success' }]);
      }
    }

    // SCA / Dependency Analysis (40% - 60%)
    if (scanProgress > 40 && scanProgress <= 60) {
      const dastVal = Math.min(100, (scanProgress - 40) * 5);
      setPhaseProgress(prev => ({ ...prev, sast: 100, risk: 100, dast: dastVal }));
      if (scanProgress === 45) {
        setLogs(prev => [...prev, { time: timeString(), text: '[SCA] Launching Software Composition Analysis...', type: 'info' }]);
        setLogs(prev => [...prev, { time: timeString(), text: '[SCA] Auditing Python & Node.js manifests...', type: 'warn' }]);
      }
      if (scanProgress === 55) {
        setLogs(prev => [...prev, { time: timeString(), text: '[SCA] Dependency vulnerability lookup completed.', type: 'info' }]);
      }
    }

    // Findings Parsing (60% - 80%)
    if (scanProgress > 60 && scanProgress <= 80) {
      const valVal = Math.min(100, (scanProgress - 60) * 5);
      setPhaseProgress(prev => ({ ...prev, sast: 100, risk: 100, dast: 100, validation: valVal }));
      if (scanProgress === 65) {
        setLogs(prev => [...prev, { time: timeString(), text: '[INFO] Normalizing & deduplicating security findings...', type: 'info' }]);
      }
      if (scanProgress === 75) {
        setLogs(prev => [...prev, { time: timeString(), text: '[INFO] Unified finding fingerprints calculated.', type: 'success' }]);
      }
    }

    // AI Analysis (80% - 95%)
    if (scanProgress > 80 && scanProgress <= 95) {
      const aiVal = Math.min(100, (scanProgress - 80) * 6.6);
      setPhaseProgress(prev => ({ ...prev, sast: 100, risk: 100, dast: 100, validation: 100, ai: aiVal }));
      if (scanProgress === 85) {
        setLogs(prev => [...prev, { time: timeString(), text: '[AI] Querying LLM security context patterns...', type: 'ai' }]);
      }
      if (scanProgress === 90) {
        setLogs(prev => [...prev, { time: timeString(), text: '[AI] Generated 2 patch files for auth modules.', type: 'ai' }]);
      }
    }

    // Report (95% - 100%)
    if (scanProgress > 95 && scanProgress <= 100) {
      const repVal = Math.min(100, (scanProgress - 95) * 20);
      setPhaseProgress(prev => ({ ...prev, sast: 100, risk: 100, dast: 100, validation: 100, ai: 100, report: repVal }));
      if (scanProgress === 98) {
        setLogs(prev => [...prev, { time: timeString(), text: '[INFO] Compiling final security scorecard report...', type: 'info' }]);
      }
    }

  }, [scanProgress, isScanning, activeProjectId]);

  // Auto-scroll console
  useEffect(() => {
    consoleEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  return (
    <div className="flex-1 flex flex-col h-full overflow-hidden relative">
      {/* Constellation Particle Backdrop Canvas */}
      <canvas ref={canvasRef} className="absolute inset-0 z-0 pointer-events-none w-full h-full" />

      {/* Main Content Area */}
      <main className="flex-grow flex flex-col relative z-10 overflow-hidden text-on-surface">
        
        {/* Header & Meta Bar */}
        <header className="px-container-padding py-stack-md border-b border-outline-variant/20 bg-surface-container-lowest/50 backdrop-blur-sm shrink-0">
          <div className="flex justify-between items-end flex-wrap gap-4">
            <div>
              <h2 className="font-headline-md text-headline-md text-on-surface mb-1 glow-text">
                Intelligent Security Scan
              </h2>
              <p className="text-on-surface-variant font-body-md text-[14px]">
                Kyptic is performing a comprehensive AI-powered security assessment.
              </p>
            </div>
            
            <div className="flex items-center gap-6 glass-panel rounded-lg px-4 py-2 bg-surface-container-low/50">
              <div className="flex flex-col">
                <span className="font-label-mono text-[11px] text-on-surface-variant">PROJECT</span>
                <span className="font-body-md text-[14px] text-on-surface font-medium">{activeProject?.name || 'Select Project'}</span>
              </div>
              
              <div className="w-px h-8 bg-outline-variant/40"></div>
              
              <div className="flex items-center gap-3">
                <div className="relative w-8 h-8 flex items-center justify-center">
                  <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                    <path 
                      className="text-surface-variant" 
                      d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" 
                      fill="none" 
                      stroke="currentColor" 
                      strokeWidth="3"
                    ></path>
                    <path 
                      className="text-primary-container" 
                      d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" 
                      fill="none" 
                      stroke="currentColor" 
                      strokeDasharray={`${isScanning ? scanProgress : scanProgress === 100 ? 100 : 0}, 100`} 
                      strokeLinecap="round" 
                      strokeWidth="3"
                    ></path>
                  </svg>
                  <span className="absolute font-label-mono text-[9px] text-primary">
                    {isScanning ? `${scanProgress}%` : scanProgress === 100 ? '100%' : '0%'}
                  </span>
                </div>
                
                <div className="flex flex-col">
                  {isScanning ? (
                    <>
                      <span className="font-label-mono text-primary text-[11px] flex items-center gap-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-primary animate-ping"></span> Scanning...
                      </span>
                      <span className="font-body-md text-[12px] text-on-surface-variant">
                        Est. {Math.ceil((100 - scanProgress) * 0.2)}s remaining
                      </span>
                    </>
                  ) : scanStatus === 'paused' ? (
                    <>
                      <span className="font-label-mono text-tertiary text-[11px] flex items-center gap-1 font-bold">
                        <span className="material-symbols-outlined text-xs">pause_circle</span> Paused
                      </span>
                      <span className="font-body-md text-[12px] text-on-surface-variant">Resume from {scanProgress}%</span>
                    </>
                  ) : scanStatus === 'stopped' ? (
                    <>
                      <span className="font-label-mono text-error text-[11px] flex items-center gap-1 font-bold">
                        <span className="material-symbols-outlined text-xs">stop_circle</span> Stopped
                      </span>
                      <span className="font-body-md text-[12px] text-on-surface-variant">Ready to scan again</span>
                    </>
                  ) : scanProgress === 100 ? (
                    <>
                      <span className="font-label-mono text-[#10b981] text-[11px] flex items-center gap-1 font-bold">
                        <span className="material-symbols-outlined text-xs">check_circle</span> Completed
                      </span>
                      <span className="font-body-md text-[12px] text-on-surface-variant">Ready for review</span>
                    </>
                  ) : (
                    <>
                      <span className="font-label-mono text-on-surface-variant text-[11px]">System Idle</span>
                      <span className="font-body-md text-[12px] text-on-surface-variant">Ready to scan</span>
                    </>
                  )}
                </div>
              </div>
            </div>
          </div>
        </header>

        {/* Split Layout */}
        <div className="flex-1 flex overflow-hidden">
          
          {/* Left: Workflow Timeline Canvas */}
          <div className="flex-[3] p-container-padding overflow-y-auto relative custom-scrollbar">
            
            {/* Center Timeline Connector Line */}
            <div className="absolute left-[44px] top-[48px] bottom-[100px] w-px bg-gradient-to-b from-primary/50 via-outline-variant/30 to-transparent z-0"></div>
            
            <div className="flex flex-col gap-stack-md relative z-10 pl-8 max-w-3xl">
              
              {/* Card 1: SAST */}
              <GlassPanel 
                variant="low" 
                className={`rounded-xl p-4 flex items-center gap-4 border-l-4 relative transition-opacity duration-300 ${
                  phaseProgress.sast === 100 
                    ? 'border-l-[#10b981] opacity-90' 
                    : phaseProgress.sast > 0 
                      ? 'border-l-primary pulse-border shadow-[0_0_10px_rgba(46,144,250,0.15)]' 
                      : 'border-l-outline-variant opacity-50'
                }`}
              >
                <div className={`absolute -left-[41px] top-1/2 -translate-y-1/2 w-3 h-3 rounded-full border-2 border-background z-20 ${
                  phaseProgress.sast === 100 ? 'bg-[#10b981]' : phaseProgress.sast > 0 ? 'bg-primary animate-pulse' : 'bg-outline-variant'
                }`}></div>
                <div className="w-12 h-12 rounded-lg bg-surface-container flex items-center justify-center shrink-0">
                  <span className={`material-symbols-outlined ${phaseProgress.sast === 100 ? 'text-[#10b981]' : phaseProgress.sast > 0 ? 'text-primary' : 'text-outline'}`}>
                    code
                  </span>
                </div>
                <div className="flex-1">
                  <div className="flex justify-between items-center mb-1">
                    <h3 className="font-body-md font-semibold text-on-surface">White-Box (SAST)</h3>
                    <span className={`font-label-mono text-[12px] ${phaseProgress.sast === 100 ? 'text-[#10b981]' : 'text-primary'}`}>
                      {phaseProgress.sast === 100 ? '100% Complete' : phaseProgress.sast > 0 ? `${phaseProgress.sast}% Running...` : 'Queued'}
                    </span>
                  </div>
                  <p className="text-[13px] text-on-surface-variant">
                    {phaseProgress.sast === 100 ? '12 findings identified across 4,592 lines of code.' : phaseProgress.sast > 0 ? 'Analyzing syntax tree nodes...' : 'Awaiting dependency resolution.'}
                  </p>
                </div>
              </GlassPanel>

              {/* Card 2: Risk Map */}
              <GlassPanel 
                variant="low" 
                className={`rounded-xl p-4 flex items-center gap-4 border-l-4 relative transition-opacity duration-300 ${
                  phaseProgress.risk === 100 
                    ? 'border-l-[#10b981] opacity-90' 
                    : phaseProgress.risk > 0 
                      ? 'border-l-primary pulse-border shadow-[0_0_10px_rgba(46,144,250,0.15)]' 
                      : 'border-l-outline-variant opacity-50'
                }`}
              >
                <div className={`absolute -left-[41px] top-1/2 -translate-y-1/2 w-3 h-3 rounded-full border-2 border-background z-20 ${
                  phaseProgress.risk === 100 ? 'bg-[#10b981]' : phaseProgress.risk > 0 ? 'bg-primary animate-pulse' : 'bg-outline-variant'
                }`}></div>
                <div className="w-12 h-12 rounded-lg bg-surface-container flex items-center justify-center shrink-0">
                  <span className={`material-symbols-outlined ${phaseProgress.risk === 100 ? 'text-[#10b981]' : phaseProgress.risk > 0 ? 'text-primary' : 'text-outline'}`}>
                    hub
                  </span>
                </div>
                <div className="flex-1">
                  <div className="flex justify-between items-center mb-1">
                    <h3 className="font-body-md font-semibold text-on-surface">Risk Map</h3>
                    <span className={`font-label-mono text-[12px] ${phaseProgress.risk === 100 ? 'text-[#10b981]' : 'text-primary'}`}>
                      {phaseProgress.risk === 100 ? '100% Generated' : phaseProgress.risk > 0 ? `${phaseProgress.risk}% Generating...` : 'Queued'}
                    </span>
                  </div>
                  <p className="text-[13px] text-on-surface-variant">
                    {phaseProgress.risk === 100 ? '42 complex routes mapped. Key assets classified.' : phaseProgress.risk > 0 ? 'Analyzing route controllers and access routes...' : 'Pending static code layout.'}
                  </p>
                </div>
              </GlassPanel>

              {/* Card 3: DAST */}
              <GlassPanel 
                variant="low" 
                className={`rounded-xl p-4 flex items-center gap-4 border-l-4 relative transition-opacity duration-300 ${
                  phaseProgress.dast === 100 
                    ? 'border-l-[#10b981] opacity-90' 
                    : phaseProgress.dast > 0 
                      ? 'border-l-primary pulse-border shadow-[0_0_10px_rgba(46,144,250,0.15)]' 
                      : 'border-l-outline-variant opacity-50'
                }`}
              >
                <div className={`absolute -left-[41px] top-1/2 -translate-y-1/2 w-3 h-3 rounded-full border-2 border-background z-20 ${
                  phaseProgress.dast === 100 ? 'bg-[#10b981]' : phaseProgress.dast > 0 ? 'bg-primary animate-pulse' : 'bg-outline-variant'
                }`}></div>
                <div className="w-12 h-12 rounded-lg bg-surface-container flex items-center justify-center shrink-0">
                  <span className={`material-symbols-outlined ${phaseProgress.dast === 100 ? 'text-[#10b981]' : phaseProgress.dast > 0 ? 'text-primary' : 'text-outline'}`}>
                    language
                  </span>
                </div>
                <div className="flex-1">
                  <div className="flex justify-between items-center mb-1">
                    <h3 className="font-body-md font-semibold text-on-surface">Black-Box (DAST)</h3>
                    <span className={`font-label-mono text-[12px] ${phaseProgress.dast === 100 ? 'text-[#10b981]' : 'text-primary'}`}>
                      {phaseProgress.dast === 100 ? '100% Complete' : phaseProgress.dast > 0 ? `${phaseProgress.dast}% Running...` : 'Queued'}
                    </span>
                  </div>
                  <p className="text-[13px] text-on-surface-variant">
                    {phaseProgress.dast === 100 ? '150 endpoints tested. Core fuzz completed.' : phaseProgress.dast > 0 ? 'Actively injecting API payloads...' : 'Awaiting threat vectors.'}
                  </p>
                  {phaseProgress.dast > 0 && phaseProgress.dast < 100 && (
                    <div className="w-full bg-surface-container-high h-1.5 rounded-full mt-3 overflow-hidden">
                      <div className="bg-primary h-full rounded-full transition-all duration-300" style={{ width: `${phaseProgress.dast}%` }}></div>
                    </div>
                  )}
                </div>
              </GlassPanel>

              {/* Card 4: Cross Validation */}
              <GlassPanel 
                variant="low" 
                className={`rounded-xl p-4 flex items-center gap-4 border-l-4 relative transition-opacity duration-300 ${
                  phaseProgress.validation === 100 
                    ? 'border-l-[#10b981] opacity-90' 
                    : phaseProgress.validation > 0 
                      ? 'border-l-primary pulse-border shadow-[0_0_10px_rgba(46,144,250,0.15)]' 
                      : 'border-l-outline-variant opacity-50'
                }`}
              >
                <div className={`absolute -left-[41px] top-1/2 -translate-y-1/2 w-3 h-3 rounded-full border-2 border-background z-20 ${
                  phaseProgress.validation === 100 ? 'bg-[#10b981]' : phaseProgress.validation > 0 ? 'bg-primary animate-pulse' : 'bg-outline-variant'
                }`}></div>
                <div className="w-12 h-12 rounded-lg bg-surface-container flex items-center justify-center shrink-0">
                  <span className={`material-symbols-outlined ${phaseProgress.validation === 100 ? 'text-[#10b981]' : phaseProgress.validation > 0 ? 'text-primary' : 'text-outline'}`}>
                    join_inner
                  </span>
                </div>
                <div className="flex-1">
                  <div className="flex justify-between items-center mb-1">
                    <h3 className="font-body-md font-semibold text-on-surface">Cross Validation</h3>
                    <span className={`font-label-mono text-[12px] ${phaseProgress.validation === 100 ? 'text-[#10b981]' : 'text-primary'}`}>
                      {phaseProgress.validation === 100 ? '100% Validated' : phaseProgress.validation > 0 ? `${phaseProgress.validation}% Correlating...` : 'Queued'}
                    </span>
                  </div>
                  <p className="text-[13px] text-on-surface-variant">
                    {phaseProgress.validation === 100 ? 'Taint analysis verified critical injection sink.' : phaseProgress.validation > 0 ? 'Correlating SAST leaks to fuzzer findings...' : 'Pending dynamic outputs.'}
                  </p>
                </div>
              </GlassPanel>

              {/* Card 5: AI Security Copilot */}
              <GlassPanel 
                variant="low" 
                className={`rounded-xl p-4 flex items-center gap-4 border-l-4 relative transition-opacity duration-300 ${
                  phaseProgress.ai === 100 
                    ? 'border-l-[#10b981] opacity-90' 
                    : phaseProgress.ai > 0 
                      ? 'border-l-primary pulse-border shadow-[0_0_10px_rgba(46,144,250,0.15)]' 
                      : 'border-l-outline-variant opacity-50'
                }`}
              >
                <div className={`absolute -left-[41px] top-1/2 -translate-y-1/2 w-3 h-3 rounded-full border-2 border-background z-20 ${
                  phaseProgress.ai === 100 ? 'bg-[#10b981]' : phaseProgress.ai > 0 ? 'bg-primary animate-pulse' : 'bg-outline-variant'
                }`}></div>
                <div className="w-12 h-12 rounded-lg bg-surface-container flex items-center justify-center shrink-0">
                  <span className={`material-symbols-outlined ${phaseProgress.ai === 100 ? 'text-[#10b981]' : phaseProgress.ai > 0 ? 'text-primary' : 'text-outline'}`}>
                    smart_toy
                  </span>
                </div>
                <div className="flex-1">
                  <div className="flex justify-between items-center mb-1">
                    <h3 className="font-body-md font-semibold text-on-surface">AI Security Copilot</h3>
                    <span className={`font-label-mono text-[12px] ${phaseProgress.ai === 100 ? 'text-[#10b981]' : 'text-primary'}`}>
                      {phaseProgress.ai === 100 ? '100% Analyzed' : phaseProgress.ai > 0 ? `${phaseProgress.ai}% Generating Repairs...` : 'Queued'}
                    </span>
                  </div>
                  <p className="text-[13px] text-on-surface-variant">
                    {phaseProgress.ai === 100 ? 'AI patch playbooks created successfully.' : phaseProgress.ai > 0 ? 'Synthesizing remediation code templates...' : 'Pending validations.'}
                  </p>
                </div>
              </GlassPanel>

              {/* Card 6: Report Generation */}
              <GlassPanel 
                variant="low" 
                className={`rounded-xl p-4 flex items-center gap-4 border-l-4 relative transition-opacity duration-300 ${
                  phaseProgress.report === 100 
                    ? 'border-l-[#10b981] opacity-90' 
                    : phaseProgress.report > 0 
                      ? 'border-l-primary pulse-border shadow-[0_0_10px_rgba(46,144,250,0.15)]' 
                      : 'border-l-outline-variant opacity-50'
                }`}
              >
                <div className={`absolute -left-[41px] top-1/2 -translate-y-1/2 w-3 h-3 rounded-full border-2 border-background z-20 ${
                  phaseProgress.report === 100 ? 'bg-[#10b981]' : phaseProgress.report > 0 ? 'bg-primary animate-pulse' : 'bg-outline-variant'
                }`}></div>
                <div className="w-12 h-12 rounded-lg bg-surface-container flex items-center justify-center shrink-0">
                  <span className={`material-symbols-outlined ${phaseProgress.report === 100 ? 'text-[#10b981]' : phaseProgress.report > 0 ? 'text-primary' : 'text-outline'}`}>
                    description
                  </span>
                </div>
                <div className="flex-1">
                  <div className="flex justify-between items-center mb-1">
                    <h3 className="font-body-md font-semibold text-on-surface">Report Generation</h3>
                    <span className={`font-label-mono text-[12px] ${phaseProgress.report === 100 ? 'text-[#10b981]' : 'text-primary'}`}>
                      {phaseProgress.report === 100 ? '100% Generated' : phaseProgress.report > 0 ? 'Writing report...' : 'Pending'}
                    </span>
                  </div>
                  <p className="text-[13px] text-on-surface-variant">
                    {phaseProgress.report === 100 ? 'Security assessment compilation finalized.' : 'Awaiting AI telemetry compilation.'}
                  </p>
                </div>
              </GlassPanel>

            </div>
          </div>

          {/* Right: Live Console & Insights */}
          <div className="flex-[2] border-l border-outline-variant/20 bg-surface-container-lowest/80 backdrop-blur-md flex flex-col">
            
            {/* Console Area */}
            <div className="flex-1 p-4 flex flex-col overflow-hidden relative">
              <div className="flex items-center justify-between mb-2 shrink-0">
                <span className="font-label-mono text-[11px] text-on-surface-variant uppercase tracking-wider">
                  Live Execution Console
                </span>
                <div className="flex gap-1">
                  <div className="w-2 h-2 rounded-full bg-outline-variant"></div>
                  <div className="w-2 h-2 rounded-full bg-outline-variant"></div>
                  <div className="w-2 h-2 rounded-full bg-outline-variant"></div>
                </div>
              </div>

              {/* Console logs box */}
              <div className="bg-[#050608] rounded-lg border border-[#1a1f26] flex-1 p-3 font-code-sm text-code-sm overflow-y-auto relative min-h-[150px]">
                <div className="space-y-1 font-mono text-[12px] leading-relaxed">
                  {logs.map((log, index) => {
                    let color = 'text-primary/80';
                    if (log.type === 'warn') color = 'text-tertiary/90';
                    if (log.type === 'ai') color = 'text-secondary-fixed';
                    if (log.type === 'success') color = 'text-[#10b981]';

                    return (
                      <div key={index} className="flex">
                        <span className="opacity-50 text-[10px] mr-2 select-none">{log.time}</span>
                        <span className={color}>{log.text}</span>
                      </div>
                    );
                  })}
                  <div ref={consoleEndRef} />
                </div>
                <div className="absolute bottom-0 left-0 right-0 h-8 bg-gradient-to-t from-[#050608] to-transparent pointer-events-none"></div>
              </div>
            </div>

            {/* AI Insights Panel */}
            <div className="h-1/3 border-t border-outline-variant/20 p-4 bg-gradient-to-b from-transparent to-primary/5 flex flex-col gap-3">
              <span className="font-label-mono text-[11px] text-secondary-fixed uppercase tracking-wider flex items-center gap-2">
                <span className="material-symbols-outlined text-[14px]">auto_awesome</span> Active AI Insights
              </span>
              
              <div className="flex-1 overflow-y-auto pr-2 custom-scrollbar flex flex-col gap-2">
                {insights.length === 0 ? (
                  <div className="h-full flex items-center justify-center text-xs text-on-surface-variant italic">
                    Awaiting scan execution findings...
                  </div>
                ) : (
                  insights.map((insight, idx) => {
                    const isError = insight.type === 'error';
                    return (
                      <div 
                        key={idx} 
                        className={`glass-panel rounded-lg p-3 relative overflow-hidden group hover:opacity-90 transition-colors ${
                          isError ? 'border-error/30 bg-error/5' : 'border-tertiary/30 bg-tertiary/5'
                        }`}
                      >
                        <div className={`absolute left-0 top-0 bottom-0 w-1 ${isError ? 'bg-error' : 'bg-tertiary'}`}></div>
                        <p className="font-body-md text-[13px] text-on-surface leading-relaxed">
                          {insight.text}
                        </p>
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          </div>

        </div>

        {/* Footer / Status Bar */}
        <footer className="h-12 border-t border-outline-variant/20 bg-surface-container-lowest shrink-0 px-6 flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-2 text-on-surface-variant font-label-mono text-[12px]">
            {isScanning ? (
              <span className="material-symbols-outlined text-[16px] animate-spin text-primary">sync</span>
            ) : (
              <span className="material-symbols-outlined text-[16px] text-outline">check</span>
            )}
            <span>Engine: Kyptic-Core v4.2.1</span>
          </div>

          <div className="flex items-center gap-4">
            {scanProgress === 100 && (
              <button 
                onClick={() => navigate('/findings')}
                className="btn-primary text-xs px-3 py-1.5 rounded font-body-md font-semibold cursor-pointer animate-pulse hover:shadow-[0_0_10px_rgba(46,144,250,0.5)]"
              >
                View Security Findings
              </button>
            )}

            {!isScanning && (scanProgress === 0 || scanStatus === 'stopped') && (
              <button
                onClick={handleStartScan}
                className="btn-primary text-xs px-4 py-1.5 rounded font-body-md font-semibold cursor-pointer hover:shadow-[0_0_10px_rgba(46,144,250,0.5)]"
              >
                Start Intelligent Scan
              </button>
            )}

            <span className="font-label-mono text-[11px] text-on-surface-variant mr-2">REAL-TIME FINDINGS:</span>
            
            <div className="flex items-center gap-1.5 px-2 py-1 rounded bg-error/10 border border-error/20">
              <span className="w-2 h-2 rounded-full bg-error"></span>
              <span className="font-label-mono text-[12px] text-error">
                {scanProgress >= 45 ? '2 Crit' : '0 Crit'}
              </span>
            </div>
            
            <div className="flex items-center gap-1.5 px-2 py-1 rounded bg-tertiary-container/20 border border-tertiary-container/30">
              <span className="w-2 h-2 rounded-full bg-tertiary"></span>
              <span className="font-label-mono text-[12px] text-tertiary">
                {scanProgress >= 15 ? '5 High' : '0 High'}
              </span>
            </div>
            
            <div className="flex items-center gap-1.5 px-2 py-1 rounded bg-surface-variant border border-outline-variant/40">
              <span className="w-2 h-2 rounded-full bg-[#f1c40f]"></span>
              <span className="font-label-mono text-[12px] text-on-surface">
                {scanProgress >= 15 ? '12 Med' : '0 Med'}
              </span>
            </div>
            
            <div className="flex items-center gap-1.5 px-2 py-1 rounded bg-surface-variant border border-outline-variant/40">
              <span className="w-2 h-2 rounded-full bg-outline"></span>
              <span className="font-label-mono text-[12px] text-outline">
                {scanProgress >= 5 ? '4 Low' : '0 Low'}
              </span>
            </div>
          </div>
        </footer>

      </main>
    </div>
  );
};

export default ScanCenter;
