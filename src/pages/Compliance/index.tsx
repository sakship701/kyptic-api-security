import React, { useEffect, useState } from 'react';
import { useApp } from '../../context/AppContext';
import GlassPanel from '../../components/ui/GlassPanel';
import {
  fetchProjectCompliance,
  type ComplianceResponseData,
  type ComplianceControlData,
} from '../../api/compliance';

export const CompliancePage: React.FC = () => {
  const { activeProjectId } = useApp();

  const [selectedFramework, setSelectedFramework] = useState<string>('PCI_DSS');
  const [complianceData, setComplianceData] = useState<ComplianceResponseData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedControl, setSelectedControl] = useState<ComplianceControlData | null>(null);

  const frameworks = [
    { id: 'PCI_DSS', name: 'PCI DSS v4.0' },
    { id: 'SOC_2', name: 'SOC 2 Type II' },
    { id: 'ISO_27001', name: 'ISO/IEC 27001' },
    { id: 'OWASP_API_TOP_10', name: 'OWASP API Top 10' },
    { id: 'OWASP_TOP_10', name: 'OWASP Web Top 10' },
    { id: 'CWE', name: 'CWE Taxonomy' },
  ];

  useEffect(() => {
    if (activeProjectId && !isNaN(Number(activeProjectId))) {
      setLoading(true);
      fetchProjectCompliance(Number(activeProjectId), selectedFramework)
        .then((data) => {
          setComplianceData(data);
          if (data.controls.length > 0) {
            setSelectedControl(data.controls[0]);
          }
        })
        .catch(() => setComplianceData(null))
        .finally(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, [activeProjectId, selectedFramework]);

  const summary = complianceData?.summary;
  const controls = complianceData?.controls || [];

  return (
    <div className="p-4 md:p-container-padding max-w-[1600px] mx-auto w-full flex flex-col gap-stack-lg pb-24 text-on-surface">
      {/* Header */}
      <header className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-on-surface-variant mb-1 text-xs">
            <span className="font-label-mono text-label-mono uppercase">SECURITY ASSESSMENT</span>
            <span>/</span>
            <span className="text-primary font-bold">REGULATORY COMPLIANCE COVERAGE</span>
          </div>
          <h1 className="font-display-lg text-display-lg font-bold text-on-surface tracking-tight">
            Regulatory & Control Mapping
          </h1>
          <p className="text-on-surface-variant text-sm mt-1">
            Automated evidence-based mapping of vulnerability scan results to security controls.
          </p>
        </div>

        {/* Framework Selector */}
        <div className="flex items-center gap-2 bg-surface-container-low p-1.5 rounded-xl border border-outline-variant/40 overflow-x-auto">
          {frameworks.map((fw) => (
            <button
              key={fw.id}
              onClick={() => setSelectedFramework(fw.id)}
              className={`px-3 py-1.5 rounded-lg text-xs font-label-mono font-bold transition-all cursor-pointer border-none whitespace-nowrap ${
                selectedFramework === fw.id
                  ? 'bg-primary text-on-primary shadow-[0_0_15px_rgba(46,144,250,0.3)]'
                  : 'text-on-surface-variant hover:text-on-surface hover:bg-surface-container-high'
              }`}
            >
              {fw.name}
            </button>
          ))}
        </div>
      </header>

      {/* Statutory Disclaimer Banner */}
      <div className="p-4 rounded-xl bg-surface-container border border-outline-variant/30 flex items-start gap-3">
        <span className="material-symbols-outlined text-primary text-xl mt-0.5">verified_user</span>
        <div className="text-xs text-on-surface-variant leading-relaxed">
          <strong className="text-on-surface">Assessment Disclaimer:</strong>{' '}
          {summary?.disclaimer ||
            'Compliance coverage represents an automated evidence-based security assessment aid and does NOT constitute legal compliance certification.'}
        </div>
      </div>

      {loading ? (
        <div className="p-12 text-center text-on-surface-variant font-mono">
          Evaluating regulatory control coverage...
        </div>
      ) : summary ? (
        <>
          {/* Summary Metrics Row */}
          <section className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-gutter">
            <GlassPanel className="p-5 rounded-xl flex items-center justify-between">
              <div>
                <p className="text-sm text-on-surface-variant mb-1 font-medium">Control Coverage</p>
                <div className="flex items-baseline gap-2">
                  <span className="text-4xl font-bold text-primary">{summary.coverage_percentage}%</span>
                </div>
              </div>
              <div className="w-14 h-14 rounded-full border-4 border-primary text-primary flex items-center justify-center font-bold text-sm">
                {summary.unaffected_controls}/{summary.total_controls}
              </div>
            </GlassPanel>

            <GlassPanel className="p-5 rounded-xl flex items-center justify-between">
              <div>
                <p className="text-sm text-on-surface-variant mb-1 font-medium">Affected Controls</p>
                <div className="text-4xl font-bold text-error">{summary.affected_controls}</div>
              </div>
              <div className="w-12 h-12 rounded-full bg-error/10 text-error border border-error/20 flex items-center justify-center">
                <span className="material-symbols-outlined">warning</span>
              </div>
            </GlassPanel>

            <GlassPanel className="p-5 rounded-xl flex items-center justify-between">
              <div>
                <p className="text-sm text-on-surface-variant mb-1 font-medium">Unaffected Controls</p>
                <div className="text-4xl font-bold text-[#10b981]">{summary.unaffected_controls}</div>
              </div>
              <div className="w-12 h-12 rounded-full bg-[#10b981]/10 text-[#10b981] border border-[#10b981]/20 flex items-center justify-center">
                <span className="material-symbols-outlined">check_circle</span>
              </div>
            </GlassPanel>

            <GlassPanel className="p-5 rounded-xl flex items-center justify-between">
              <div>
                <p className="text-sm text-on-surface-variant mb-1 font-medium">Mapped Findings</p>
                <div className="text-4xl font-bold text-on-surface">{summary.total_mapped_findings}</div>
              </div>
              <div className="w-12 h-12 rounded-full bg-surface-container-high text-on-surface-variant flex items-center justify-center">
                <span className="material-symbols-outlined">fact_check</span>
              </div>
            </GlassPanel>
          </section>

          {/* Main Grid: Control List & Detail Inspector */}
          <section className="grid grid-cols-1 lg:grid-cols-12 gap-gutter items-start">
            {/* Control List */}
            <div className="lg:col-span-7 flex flex-col gap-3">
              {controls.map((ctrl) => {
                const isSelected = selectedControl?.control_id === ctrl.control_id;
                const isAffected = ctrl.status === 'AFFECTED';
                const isUnaffected = ctrl.status === 'NOT_AFFECTED';

                return (
                  <GlassPanel
                    key={ctrl.control_id}
                    onClick={() => setSelectedControl(ctrl)}
                    className={`p-4 rounded-xl cursor-pointer transition-all border ${
                      isSelected
                        ? 'border-primary shadow-[0_0_20px_rgba(46,144,250,0.2)]'
                        : 'border-outline-variant/30 hover:border-outline-variant'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div>
                        <div className="flex items-center gap-2 mb-1">
                          <span className="font-mono text-xs font-bold text-primary">{ctrl.control_id}</span>
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
                              isAffected
                                ? 'bg-error/20 text-error border-error/30'
                                : isUnaffected
                                ? 'bg-[#10b981]/20 text-[#10b981] border-[#10b981]/30'
                                : 'bg-surface-container-high text-on-surface-variant border-outline-variant'
                            }`}
                          >
                            {ctrl.status}
                          </span>
                        </div>
                        <h3 className="font-bold text-on-surface text-base">{ctrl.control_name}</h3>
                        <p className="text-xs text-on-surface-variant mt-1 line-clamp-2">{ctrl.description}</p>
                      </div>

                      {isAffected && (
                        <span className="px-2.5 py-1 rounded bg-error/10 text-error border border-error/30 text-xs font-bold shrink-0">
                          {ctrl.affected_findings_count} Finding(s)
                        </span>
                      )}
                    </div>
                  </GlassPanel>
                );
              })}
            </div>

            {/* Control Inspector */}
            <div className="lg:col-span-5">
              {selectedControl ? (
                <GlassPanel className="p-6 rounded-xl space-y-6">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-mono text-xs font-bold text-primary">{selectedControl.control_id}</span>
                      <span
                        className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold uppercase border ${
                          selectedControl.status === 'AFFECTED'
                            ? 'bg-error/20 text-error border-error/30'
                            : 'bg-[#10b981]/20 text-[#10b981] border-[#10b981]/30'
                        }`}
                      >
                        {selectedControl.status}
                      </span>
                    </div>
                    <h2 className="text-xl font-bold text-on-surface">{selectedControl.control_name}</h2>
                    <p className="text-xs text-on-surface-variant mt-2 leading-relaxed">
                      {selectedControl.description}
                    </p>
                  </div>

                  <div className="p-4 rounded-lg bg-[#11151D] border border-[#1F242D] space-y-2">
                    <h4 className="text-xs font-bold text-on-surface uppercase tracking-wider">Assessment Evidence</h4>
                    <p className="text-xs text-on-surface-variant leading-relaxed">{selectedControl.evidence_summary}</p>
                  </div>

                  {selectedControl.mapped_findings.length > 0 && (
                    <div className="space-y-3">
                      <h4 className="text-xs font-bold text-on-surface uppercase tracking-wider">Affecting Findings</h4>
                      <div className="space-y-2">
                        {selectedControl.mapped_findings.map((mf) => (
                          <div key={mf.finding_id} className="p-3 rounded bg-[#0A0D12] border border-[#1F242D] text-xs space-y-1">
                            <div className="flex justify-between font-semibold text-on-surface">
                              <span>{mf.title}</span>
                              <span className="text-error uppercase">{mf.severity}</span>
                            </div>
                            <div className="text-[11px] text-on-surface-variant font-mono">
                              File: {mf.file_path} | CWE: {mf.cwe || 'N/A'}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="p-4 rounded-lg bg-primary/5 border border-primary/20 space-y-2">
                    <h4 className="text-xs font-bold text-primary uppercase tracking-wider">Remediation Reference</h4>
                    <p className="text-xs text-on-surface-variant leading-relaxed">
                      {selectedControl.remediation_reference}
                    </p>
                  </div>
                </GlassPanel>
              ) : (
                <GlassPanel className="p-8 text-center text-on-surface-variant">
                  Select a control to view mapped security findings and evidence.
                </GlassPanel>
              )}
            </div>
          </section>
        </>
      ) : (
        <GlassPanel className="p-8 text-center text-on-surface-variant">
          Select a project to inspect regulatory control coverage.
        </GlassPanel>
      )}
    </div>
  );
};

export default CompliancePage;
