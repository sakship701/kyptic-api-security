import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useApp } from '../../../context/AppContext';
import GlassPanel from '../../../components/ui/GlassPanel';
import { ingestZip, ingestGit, ingestWebsite, fetchProjectSource } from '../../../api/projects';
import { ingestOpenApi } from '../../../api/api_security';

export const ProjectOnboard: React.FC = () => {
  const navigate = useNavigate();
  const { createProject } = useApp();

  const [step, setStep] = useState(2); // Start at step 2 as shown in the Stitch design default, but user can navigate.
  
  // Step 1: Info States
  const [projName, setProjName] = useState('Gateway Microservice');
  const [projTech, setProjTech] = useState('Java/Spring');
  const [projDesc, setProjDesc] = useState('Onboarding Java Gateway Microservice for core transaction routing.');

  // Step 2: Source States
  const [sourceType, setSourceType] = useState('Git Repository'); // 'Upload ZIP' | 'Git Repository' | 'Website URL'
  const [repoUrl, setRepoUrl] = useState('https://github.com/enterprise/gateway-service');
  const [websiteUrl, setWebsiteUrl] = useState('https://example.com');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  // Ingestion states (for Step 2 inline ingestion status)
  const [ingestStatus, setIngestStatus] = useState<'IDLE' | 'INGESTING' | 'READY' | 'FAILED'>('IDLE');
  const [ingestError, setIngestError] = useState<string | null>(null);
  const [createdProject, setCreatedProject] = useState<any | null>(null);
  
  // Step 3: Analysis States
  const [analysisMode, setAnalysisMode] = useState('Intelligent Scan'); // Intelligent Scan vs Custom Checklist

  // Step 4: Advanced States
  const [scanners, setScanners] = useState({
    whiteBox: true,
    blackBox: true,
    greyBox: true,
    riskMapping: true,
    crossValidation: true,
    aiAnalysis: true,
  });

  // Validation States
  const [errors, setErrors] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Connection Sources list
  const sources = [
    { name: 'Upload ZIP', desc: 'Upload your source code.', icon: 'folder_zip', color: 'text-on-surface' },
    { name: 'Git Repository', desc: 'Connect a Git repository.', icon: 'code', color: 'text-primary' },
    { name: 'Website URL', desc: 'Provide URL for DAST testing.', icon: 'language', color: 'text-on-surface' },
    { name: 'OpenAPI Specification', desc: 'Upload OpenAPI 2.0 / 3.0 / 3.1 spec.', icon: 'api', color: 'text-primary' },
  ];

  const handleIngestion = async () => {
    setErrors(null);
    setIngestError(null);
    setIngestStatus('INGESTING');
    try {
      // 1. Create project if not already created
      let project = createdProject;
      if (!project) {
        project = await createProject({
          name: projName.trim(),
          description: projDesc.trim() || null,
          repository_url: sourceType === 'Git Repository' ? repoUrl.trim() : null,
          technology: projTech,
        });
        setCreatedProject(project);
      }

      // 2. Trigger ingestion
      if (sourceType === 'Upload ZIP') {
        if (!selectedFile) {
          throw new Error('Please select a ZIP file to upload.');
        }
        await ingestZip(Number(project.id), selectedFile);
      } else if (sourceType === 'Git Repository') {
        if (!repoUrl.trim()) {
          throw new Error('Repository URL is required.');
        }
        await ingestGit(Number(project.id), repoUrl.trim());
      } else if (sourceType === 'OpenAPI Specification') {
        if (!selectedFile) {
          throw new Error('Please select an OpenAPI specification file (.json, .yaml, .yml).');
        }
        await ingestOpenApi(Number(project.id), selectedFile);
        setIngestStatus('READY');
      } else {
        if (!websiteUrl.trim()) {
          throw new Error('Website URL is required.');
        }
        await ingestWebsite(Number(project.id), websiteUrl.trim());
      }

      // 3. For ZIP and Git, poll status until READY or FAILED
      if (sourceType === 'Upload ZIP' || sourceType === 'Git Repository') {
        let isDone = false;
        let pollCount = 0;
        while (!isDone && pollCount < 120) { // Max 60 seconds polling (every 500ms)
          await new Promise((resolve) => setTimeout(resolve, 500));
          const sourceDetails = await fetchProjectSource(Number(project.id));
          if (sourceDetails.status === 'READY') {
            setIngestStatus('READY');
            isDone = true;
          } else if (sourceDetails.status === 'FAILED') {
            setIngestStatus('FAILED');
            setIngestError(sourceDetails.error_message || 'Ingestion failed.');
            isDone = true;
          }
          pollCount++;
        }
        if (!isDone) {
          throw new Error('Ingestion timed out. Please check the project list.');
        }
      } else {
        // Website is instant READY
        setIngestStatus('READY');
      }
    } catch (err) {
      setIngestStatus('FAILED');
      setIngestError(err instanceof Error ? err.message : 'Ingestion failed.');
    }
  };

  const handleNext = () => {
    setErrors(null);
    if (step === 1) {
      if (!projName.trim()) {
        setErrors('Project Name is required');
        return;
      }
      setStep(2);
    } else if (step === 2) {
      if (ingestStatus !== 'READY') {
        setErrors('You must successfully connect/upload your application source or target before proceeding.');
        return;
      }
      setStep(3);
    } else if (step === 3) {
      setStep(4);
    } else if (step === 4) {
      setStep(5);
    }
  };

  const handleBack = () => {
    setErrors(null);
    if (step > 1) {
      setStep(step - 1);
    } else {
      navigate('/projects');
    }
  };

  const handleCreate = async () => {
    setLoading(true);
    setErrors(null);
    try {
      navigate('/projects');
    } catch (error) {
      setErrors(error instanceof Error ? error.message : 'Unable to create project.');
    } finally {
      setLoading(false);
    }
  };

  // Render Stepper Badge Header helper
  const renderStepIcon = (index: number) => {
    if (step > index) {
      return (
        <div className="w-10 h-10 rounded-full bg-primary-container text-on-primary-container flex items-center justify-center shadow-[0_0_15px_rgba(49,146,252,0.3)]">
          <span className="material-symbols-outlined text-sm font-bold">check</span>
        </div>
      );
    }
    if (step === index) {
      return (
        <div className="w-10 h-10 rounded-full border-2 border-primary bg-surface text-primary flex items-center justify-center shadow-[0_0_15px_rgba(49,146,252,0.1)]">
          <span className="font-body-md font-bold">{index}</span>
        </div>
      );
    }
    return (
      <div className="w-10 h-10 rounded-full border border-outline-variant bg-surface text-on-surface-variant flex items-center justify-center">
        <span className="font-body-md">{index}</span>
      </div>
    );
  };

  return (
    <div className="flex-grow overflow-y-auto w-full relative bg-[#06070A] text-on-surface">
      <div className="max-w-[1200px] mx-auto px-gutter py-stack-lg w-full flex flex-col items-center">
        
        {/* Header */}
        <div className="text-center mb-12 max-w-2xl">
          <h2 className="font-display-lg text-display-lg text-on-surface mb-4">Create New Project</h2>
          <p className="font-body-lg text-body-lg text-on-surface-variant">
            Follow the steps to onboard your application and initiate the first security analysis.
          </p>
        </div>

        {/* Wizard Progress Stepper */}
        <div className="w-full max-w-4xl mb-16 px-4">
          <div className="flex items-center justify-between relative">
            <div className="flex flex-col items-center gap-3 relative z-10">
              {renderStepIcon(1)}
              <span className={`font-label-mono text-label-mono ${step >= 1 ? 'text-primary' : 'text-on-surface-variant'}`}>
                Project Info
              </span>
            </div>
            <div className={`step-line ${step > 1 ? 'active' : ''}`}></div>

            <div className="flex flex-col items-center gap-3 relative z-10">
              {renderStepIcon(2)}
              <span className={`font-label-mono text-label-mono ${step >= 2 ? 'text-primary' : 'text-on-surface-variant'}`}>
                Source
              </span>
            </div>
            <div className={`step-line ${step > 2 ? 'active' : ''}`}></div>

            <div className="flex flex-col items-center gap-3 relative z-10">
              {renderStepIcon(3)}
              <span className={`font-label-mono text-label-mono ${step >= 3 ? 'text-primary' : 'text-on-surface-variant'}`}>
                Analysis
              </span>
            </div>
            <div className={`step-line ${step > 3 ? 'active' : ''}`}></div>

            <div className="flex flex-col items-center gap-3 relative z-10">
              {renderStepIcon(4)}
              <span className={`font-label-mono text-label-mono ${step >= 4 ? 'text-primary' : 'text-on-surface-variant'}`}>
                Advanced
              </span>
            </div>
            <div className={`step-line ${step > 4 ? 'active' : ''}`}></div>

            <div className="flex flex-col items-center gap-3 relative z-10">
              {renderStepIcon(5)}
              <span className={`font-label-mono text-label-mono ${step >= 5 ? 'text-primary' : 'text-on-surface-variant'}`}>
                Review
              </span>
            </div>
          </div>
        </div>

        {/* Validation Message */}
        {errors && (
          <div className="w-full max-w-5xl p-3 mb-6 bg-error-container/10 border border-error-container text-error rounded-lg text-xs font-label-mono flex items-center gap-2">
            <span className="material-symbols-outlined text-sm">error</span>
            <span>{errors}</span>
          </div>
        )}

        {/* Step Content Container */}
        <GlassPanel variant="low" className="w-full max-w-5xl glass-panel rounded-xl p-8 mb-stack-lg">
          
          {/* STEP 1: Project Info */}
          {step === 1 && (
            <div className="space-y-6">
              <div className="mb-8">
                <h3 className="font-headline-md text-headline-md text-on-surface mb-2">Project Information</h3>
                <p className="text-on-surface-variant">Provide key identifiers for this enterprise security workspace.</p>
              </div>
              <div className="space-y-4">
                <div>
                  <label className="block font-label-mono text-label-mono text-on-surface-variant mb-2">
                    Project Name
                  </label>
                  <input
                    className="w-full bg-[#0A0D12] border border-[#1F242D] rounded-lg px-4 py-3 text-on-surface focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-colors"
                    placeholder="e.g. My Web App"
                    type="text"
                    value={projName}
                    onChange={(e) => setProjName(e.target.value)}
                  />
                </div>
                <div>
                  <label className="block font-label-mono text-label-mono text-on-surface-variant mb-2">
                    Technology Stack
                  </label>
                  <select
                    className="w-full bg-[#0A0D12] border border-[#1F242D] rounded-lg px-4 py-3 text-on-surface focus:outline-none focus:border-primary cursor-pointer"
                    value={projTech}
                    onChange={(e) => setProjTech(e.target.value)}
                  >
                    <option value="Node.js">Node.js</option>
                    <option value="Java/Spring">Java/Spring</option>
                    <option value="Python/Django">Python/Django</option>
                    <option value="Go">Go / Golang</option>
                  </select>
                </div>
                <div>
                  <label className="block font-label-mono text-label-mono text-on-surface-variant mb-2">
                    Description (Optional)
                  </label>
                  <textarea
                    className="w-full bg-[#0A0D12] border border-[#1F242D] rounded-lg px-4 py-3 text-on-surface focus:outline-none focus:border-primary transition-colors resize-none h-24"
                    placeholder="Short description of this service..."
                    value={projDesc}
                    onChange={(e) => setProjDesc(e.target.value)}
                  />
                </div>
              </div>
            </div>
          )}

          {/* STEP 2: Connection Source */}
          {step === 2 && (
            <div>
              <div className="mb-8">
                <h3 className="font-headline-md text-headline-md text-on-surface mb-2">How do you want to scan your application?</h3>
                <p className="text-on-surface-variant">Choose the repository or source type for your application code.</p>
              </div>

              {/* Grid for Sources */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                {sources.map((src) => {
                  const isSelected = sourceType === src.name;
                  return (
                    <button
                      key={src.name}
                      onClick={() => {
                        setSourceType(src.name);
                        setIngestStatus('IDLE');
                        setIngestError(null);
                      }}
                      className={`source-card rounded-lg p-6 flex flex-col items-start gap-4 text-left group relative overflow-hidden cursor-pointer ${
                        isSelected ? 'selected' : ''
                      }`}
                    >
                      {isSelected && (
                        <div className="absolute -top-10 -right-10 w-32 h-32 bg-primary/10 rounded-full blur-2xl"></div>
                      )}
                      <div className={`w-12 h-12 rounded-lg border flex items-center justify-center transition-colors ${
                        isSelected 
                          ? 'bg-primary-container/10 border-primary/30' 
                          : 'bg-surface-container-high border-outline-variant group-hover:border-on-surface-variant'
                      }`}>
                        <span className={`material-symbols-outlined text-2xl ${isSelected ? 'text-primary' : 'text-on-surface'}`}>
                          {src.icon}
                        </span>
                      </div>
                      <div>
                        <h4 className={`font-body-md font-semibold mb-1 ${isSelected ? 'text-primary' : 'text-on-surface'}`}>
                          {src.name}
                        </h4>
                        <p className={`font-code-sm text-code-sm ${isSelected ? 'text-primary/70' : 'text-on-surface-variant'}`}>
                          {src.desc}
                        </p>
                      </div>
                      {isSelected && (
                        <div className="absolute top-4 right-4 w-6 h-6 rounded-full bg-primary flex items-center justify-center shadow-md">
                          <span className="material-symbols-outlined text-on-primary text-sm font-bold">check</span>
                        </div>
                      )}
                    </button>
                  );
                })}
              </div>

              {/* Conditionally reveal details based on source selection */}
              {sourceType === 'Git Repository' && (
                <div className="mt-8 p-6 bg-surface-container-low border border-outline-variant rounded-lg">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <span className="material-symbols-outlined text-primary">link</span>
                      <h5 className="font-body-md font-medium text-on-surface">Git Connection Details</h5>
                    </div>
                    <span className="px-3 py-1 bg-surface-variant rounded-full text-xs font-label-mono text-on-surface-variant">
                      Required
                    </span>
                  </div>
                  <div className="space-y-4">
                    <div>
                      <label className="block font-label-mono text-label-mono text-on-surface-variant mb-2">Repository URL</label>
                      <input
                        className="w-full bg-surface-dim border border-outline-variant rounded-lg px-4 py-3 text-on-surface focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-colors"
                        placeholder="https://github.com/organization/repo"
                        type="text"
                        value={repoUrl}
                        onChange={(e) => setRepoUrl(e.target.value)}
                        disabled={ingestStatus === 'INGESTING' || ingestStatus === 'READY'}
                      />
                    </div>
                    
                    <div className="flex items-center justify-between p-4 border border-outline-variant rounded-lg bg-surface-dim">
                      <div>
                        <p className="font-body-md text-on-surface font-medium">Authentication</p>
                        <p className="font-code-sm text-code-sm text-on-surface-variant">Private repository authentication can be added later.</p>
                      </div>
                      <button 
                        type="button"
                        disabled
                        className="px-4 py-2 bg-surface-variant/50 text-on-surface/50 rounded-lg transition-colors font-medium text-sm cursor-not-allowed"
                      >
                        Configure Auth
                      </button>
                    </div>

                    <div className="flex items-center gap-4 pt-2">
                      <button
                        type="button"
                        onClick={handleIngestion}
                        disabled={ingestStatus === 'INGESTING' || ingestStatus === 'READY' || !repoUrl.trim()}
                        className="px-5 py-2.5 bg-primary text-white rounded-lg hover:opacity-90 disabled:opacity-50 transition-all font-medium text-sm cursor-pointer flex items-center gap-2"
                      >
                        {ingestStatus === 'INGESTING' ? (
                          <>
                            <span className="material-symbols-outlined text-sm animate-spin">sync</span>
                            <span>Cloning Repository...</span>
                          </>
                        ) : (
                          <>
                            <span className="material-symbols-outlined text-sm">cloud_download</span>
                            <span>Connect & Import Repository</span>
                          </>
                        )}
                      </button>
                      
                      {ingestStatus === 'READY' && (
                        <div className="flex items-center gap-1.5 text-success font-medium text-sm">
                          <span className="material-symbols-outlined text-sm font-bold">check_circle</span>
                          <span>Connected successfully</span>
                        </div>
                      )}

                      {ingestStatus === 'FAILED' && (
                        <div className="flex items-center gap-1.5 text-error font-medium text-sm max-w-md">
                          <span className="material-symbols-outlined text-sm">error</span>
                          <span className="truncate" title={ingestError || ''}>{ingestError || 'Connection failed'}</span>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {sourceType === 'Upload ZIP' && (
                <div className="mt-8 p-6 bg-surface-container-low border border-outline-variant rounded-lg">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <span className="material-symbols-outlined text-primary">folder_zip</span>
                      <h5 className="font-body-md font-medium text-on-surface">Source ZIP Upload</h5>
                    </div>
                    <span className="px-3 py-1 bg-surface-variant rounded-full text-xs font-label-mono text-on-surface-variant">
                      Required
                    </span>
                  </div>

                  <div className="flex flex-col items-center justify-center border-dashed border-2 border-outline-variant/60 rounded-lg py-10 bg-surface-dim relative">
                    <input
                      type="file"
                      accept=".zip"
                      onChange={(e) => {
                        const file = e.target.files?.[0] || null;
                        setSelectedFile(file);
                        setIngestStatus('IDLE');
                        setIngestError(null);
                      }}
                      className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                      disabled={ingestStatus === 'INGESTING' || ingestStatus === 'READY'}
                    />
                    <span className="material-symbols-outlined text-4xl text-outline mb-2">cloud_upload</span>
                    <p className="font-body-md text-on-surface mb-1">
                      {selectedFile ? selectedFile.name : 'Select or drag your project ZIP file here'}
                    </p>
                    <p className="text-xs text-on-surface-variant mb-4">Max size: 50MB</p>
                    <button 
                      type="button"
                      className="px-4 py-2 bg-surface-variant text-on-surface rounded-lg hover:bg-outline-variant transition-colors text-sm font-medium pointer-events-none"
                    >
                      {selectedFile ? 'Change File' : 'Browse File'}
                    </button>
                  </div>

                  {selectedFile && (
                    <div className="flex items-center gap-4 mt-6">
                      <button
                        type="button"
                        onClick={handleIngestion}
                        disabled={ingestStatus === 'INGESTING' || ingestStatus === 'READY'}
                        className="px-5 py-2.5 bg-primary text-white rounded-lg hover:opacity-90 disabled:opacity-50 transition-all font-medium text-sm cursor-pointer flex items-center gap-2"
                      >
                        {ingestStatus === 'INGESTING' ? (
                          <>
                            <span className="material-symbols-outlined text-sm animate-spin">sync</span>
                            <span>Uploading & Extracting...</span>
                          </>
                        ) : (
                          <>
                            <span className="material-symbols-outlined text-sm">upload</span>
                            <span>Upload ZIP File</span>
                          </>
                        )}
                      </button>

                      {ingestStatus === 'READY' && (
                        <div className="flex items-center gap-1.5 text-success font-medium text-sm">
                          <span className="material-symbols-outlined text-sm font-bold">check_circle</span>
                          <span>Uploaded and extracted successfully</span>
                        </div>
                      )}

                      {ingestStatus === 'FAILED' && (
                        <div className="flex items-center gap-1.5 text-error font-medium text-sm max-w-md">
                          <span className="material-symbols-outlined text-sm">error</span>
                          <span className="truncate" title={ingestError || ''}>{ingestError || 'Upload failed'}</span>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {sourceType === 'Website URL' && (
                <div className="mt-8 p-6 bg-surface-container-low border border-outline-variant rounded-lg">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <span className="material-symbols-outlined text-primary">language</span>
                      <h5 className="font-body-md font-medium text-on-surface">Website / Application Target</h5>
                    </div>
                    <span className="px-3 py-1 bg-surface-variant rounded-full text-xs font-label-mono text-on-surface-variant">
                      Required
                    </span>
                  </div>

                  <div className="space-y-4">
                    <div>
                      <label className="block font-label-mono text-label-mono text-on-surface-variant mb-2">Website URL</label>
                      <input
                        className="w-full bg-surface-dim border border-outline-variant rounded-lg px-4 py-3 text-on-surface focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-colors"
                        placeholder="https://example.com"
                        type="text"
                        value={websiteUrl}
                        onChange={(e) => setWebsiteUrl(e.target.value)}
                        disabled={ingestStatus === 'INGESTING' || ingestStatus === 'READY'}
                      />
                    </div>

                    <div className="flex items-center gap-4 pt-2">
                      <button
                        type="button"
                        onClick={handleIngestion}
                        disabled={ingestStatus === 'INGESTING' || ingestStatus === 'READY' || !websiteUrl.trim()}
                        className="px-5 py-2.5 bg-primary text-white rounded-lg hover:opacity-90 disabled:opacity-50 transition-all font-medium text-sm cursor-pointer flex items-center gap-2"
                      >
                        <span className="material-symbols-outlined text-sm">save</span>
                        <span>Save Target</span>
                      </button>

                      {ingestStatus === 'READY' && (
                        <div className="flex items-center gap-1.5 text-success font-medium text-sm">
                          <span className="material-symbols-outlined text-sm font-bold">check_circle</span>
                          <span>Target saved successfully</span>
                        </div>
                      )}

                      {ingestStatus === 'FAILED' && (
                        <div className="flex items-center gap-1.5 text-error font-medium text-sm">
                          <span className="material-symbols-outlined text-sm">error</span>
                          <span>{ingestError || 'Failed to save target'}</span>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {sourceType === 'OpenAPI Specification' && (
                <div className="mt-8 p-6 bg-surface-container-low border border-outline-variant rounded-lg">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <span className="material-symbols-outlined text-primary">api</span>
                      <h5 className="font-body-md font-medium text-on-surface">OpenAPI Specification Upload</h5>
                    </div>
                    <span className="px-3 py-1 bg-surface-variant rounded-full text-xs font-label-mono text-on-surface-variant">
                      Required
                    </span>
                  </div>

                  <div className="flex flex-col items-center justify-center border-dashed border-2 border-outline-variant/60 rounded-lg py-10 bg-surface-dim relative">
                    <input
                      type="file"
                      accept=".json,.yaml,.yml"
                      onChange={(e) => {
                        const file = e.target.files?.[0] || null;
                        setSelectedFile(file);
                        setIngestStatus('IDLE');
                        setIngestError(null);
                      }}
                      className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                      disabled={ingestStatus === 'INGESTING' || ingestStatus === 'READY'}
                    />
                    <span className="material-symbols-outlined text-4xl text-outline mb-2">upload_file</span>
                    <p className="font-body-md text-on-surface mb-1">
                      {selectedFile ? selectedFile.name : 'Select or drag your OpenAPI spec file (.json, .yaml, .yml)'}
                    </p>
                    <p className="text-xs text-on-surface-variant mb-4">Supported: OpenAPI 2.0, 3.0, 3.1 (Max 50MB)</p>
                    <button
                      type="button"
                      className="px-4 py-2 bg-surface-variant text-on-surface rounded-lg hover:bg-outline-variant transition-colors text-sm font-medium pointer-events-none"
                    >
                      {selectedFile ? 'Change Specification File' : 'Browse File'}
                    </button>
                  </div>

                  {selectedFile && (
                    <div className="flex items-center gap-4 mt-6">
                      <button
                        type="button"
                        onClick={handleIngestion}
                        disabled={ingestStatus === 'INGESTING' || ingestStatus === 'READY'}
                        className="px-5 py-2.5 bg-primary text-white rounded-lg hover:opacity-90 disabled:opacity-50 transition-all font-medium text-sm cursor-pointer flex items-center gap-2"
                      >
                        {ingestStatus === 'INGESTING' ? (
                          <>
                            <span className="material-symbols-outlined text-sm animate-spin">sync</span>
                            <span>Validating & Parsing Specification...</span>
                          </>
                        ) : (
                          <>
                            <span className="material-symbols-outlined text-sm">cloud_upload</span>
                            <span>Upload & Ingest OpenAPI Spec</span>
                          </>
                        )}
                      </button>

                      {ingestStatus === 'READY' && (
                        <div className="flex items-center gap-1.5 text-success font-medium text-sm">
                          <span className="material-symbols-outlined text-sm font-bold">check_circle</span>
                          <span>Specification ingested & endpoints parsed successfully</span>
                        </div>
                      )}

                      {ingestStatus === 'FAILED' && (
                        <div className="flex items-center gap-1.5 text-error font-medium text-sm max-w-md">
                          <span className="material-symbols-outlined text-sm">error</span>
                          <span className="truncate" title={ingestError || ''}>{ingestError || 'Ingestion failed'}</span>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* STEP 3: Analysis Config */}
          {step === 3 && (
            <div className="space-y-6">
              <div className="mb-8">
                <h3 className="font-headline-md text-headline-md text-on-surface mb-2">Select Analysis Mode</h3>
                <p className="text-on-surface-variant">Choose the default detection engine strategy for scanner telemetry.</p>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Mode 1: Intelligent Scan */}
                <button
                  type="button"
                  onClick={() => setAnalysisMode('Intelligent Scan')}
                  className={`flex flex-col items-start gap-4 p-6 rounded-lg text-left border relative overflow-hidden transition-all duration-300 cursor-pointer ${
                    analysisMode === 'Intelligent Scan'
                      ? 'bg-primary-container/10 border-primary shadow-[0_0_15px_rgba(49,146,252,0.15)]'
                      : 'bg-surface-container-low border-outline-variant hover:border-on-surface-variant'
                  }`}
                >
                  {analysisMode === 'Intelligent Scan' && (
                    <div className="absolute top-4 right-4 w-6 h-6 rounded-full bg-primary flex items-center justify-center shadow-md">
                      <span className="material-symbols-outlined text-on-primary text-sm font-bold">check</span>
                    </div>
                  )}
                  <div className={`p-3 rounded-lg border ${analysisMode === 'Intelligent Scan' ? 'bg-primary-container/10 border-primary/30 text-primary' : 'bg-surface-container-high border-outline-variant text-on-surface-variant'}`}>
                    <span className="material-symbols-outlined text-2xl">insights</span>
                  </div>
                  <div>
                    <h4 className={`font-body-md font-semibold mb-1 ${analysisMode === 'Intelligent Scan' ? 'text-primary' : 'text-on-surface'}`}>
                      Intelligent Scan (Recommended)
                    </h4>
                    <p className="text-xs text-on-surface-variant leading-relaxed">
                      Automatically runs static analysis, generates structural risk mapping, launches targeted dynamic checks, and outputs AI-engineered patch suggestions.
                    </p>
                  </div>
                </button>

                {/* Mode 2: Custom Checklist */}
                <button
                  type="button"
                  onClick={() => setAnalysisMode('Custom Checklist')}
                  className={`flex flex-col items-start gap-4 p-6 rounded-lg text-left border relative overflow-hidden transition-all duration-300 cursor-pointer ${
                    analysisMode === 'Custom Checklist'
                      ? 'bg-primary-container/10 border-primary shadow-[0_0_15px_rgba(49,146,252,0.15)]'
                      : 'bg-surface-container-low border-outline-variant hover:border-on-surface-variant'
                  }`}
                >
                  {analysisMode === 'Custom Checklist' && (
                    <div className="absolute top-4 right-4 w-6 h-6 rounded-full bg-primary flex items-center justify-center shadow-md">
                      <span className="material-symbols-outlined text-on-primary text-sm font-bold">check</span>
                    </div>
                  )}
                  <div className={`p-3 rounded-lg border ${analysisMode === 'Custom Checklist' ? 'bg-primary-container/10 border-primary/30 text-primary' : 'bg-surface-container-high border-outline-variant text-on-surface-variant'}`}>
                    <span className="material-symbols-outlined text-2xl">tune</span>
                  </div>
                  <div>
                    <h4 className={`font-body-md font-semibold mb-1 ${analysisMode === 'Custom Checklist' ? 'text-primary' : 'text-on-surface'}`}>
                      Custom Checklist Scan
                    </h4>
                    <p className="text-xs text-on-surface-variant leading-relaxed">
                      Manually select which scanners to run. Ideal for targeted audit scans or container-only evaluations. Exposes individual toggle scopes.
                    </p>
                  </div>
                </button>
              </div>
            </div>
          )}

          {/* STEP 4: Advanced Scanners */}
          {step === 4 && (
            <div className="space-y-6">
              <div className="mb-8">
                <h3 className="font-headline-md text-headline-md text-on-surface mb-2">Advanced Security Configuration</h3>
                <p className="text-on-surface-variant">Toggle individual analysis layers to customize scan coverage details.</p>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Scanner 1: White-Box Analysis */}
                <label className="flex items-center justify-between p-4 bg-surface-container-low border border-outline-variant rounded-lg cursor-pointer hover:border-on-surface-variant transition-colors">
                  <div className="flex items-center gap-3">
                    <span className="material-symbols-outlined text-primary">terminal</span>
                    <div>
                      <p className="font-body-md text-on-surface font-semibold">White-Box Analysis (SAST)</p>
                      <p className="text-xs text-on-surface-variant">Analyze source code line-by-line for injections</p>
                    </div>
                  </div>
                  <input
                    type="checkbox"
                    className="w-5 h-5 rounded border-outline-variant text-primary focus:ring-primary/30 cursor-pointer"
                    checked={scanners.whiteBox}
                    onChange={(e) => setScanners({ ...scanners, whiteBox: e.target.checked })}
                  />
                </label>

                {/* Scanner 2: Black-Box Analysis */}
                <label className="flex items-center justify-between p-4 bg-surface-container-low border border-outline-variant rounded-lg cursor-pointer hover:border-on-surface-variant transition-colors">
                  <div className="flex items-center gap-3">
                    <span className="material-symbols-outlined text-tertiary">language</span>
                    <div>
                      <p className="font-body-md text-on-surface font-semibold">Black-Box Analysis (DAST)</p>
                      <p className="text-xs text-on-surface-variant">Execute dynamic endpoint payload checks</p>
                    </div>
                  </div>
                  <input
                    type="checkbox"
                    className="w-5 h-5 rounded border-outline-variant text-primary focus:ring-primary/30 cursor-pointer"
                    checked={scanners.blackBox}
                    onChange={(e) => setScanners({ ...scanners, blackBox: e.target.checked })}
                  />
                </label>

                {/* Scanner 3: Grey-Box Analysis */}
                <label className="flex items-center justify-between p-4 bg-surface-container-low border border-outline-variant rounded-lg cursor-pointer hover:border-on-surface-variant transition-colors">
                  <div className="flex items-center gap-3">
                    <span className="material-symbols-outlined text-[#a3defe]">verified_user</span>
                    <div>
                      <p className="font-body-md text-on-surface font-semibold">Grey-Box Analysis (IAST)</p>
                      <p className="text-xs text-on-surface-variant">Analyze logic flow runtime vulnerabilities</p>
                    </div>
                  </div>
                  <input
                    type="checkbox"
                    className="w-5 h-5 rounded border-outline-variant text-primary focus:ring-primary/30 cursor-pointer"
                    checked={scanners.greyBox}
                    onChange={(e) => setScanners({ ...scanners, greyBox: e.target.checked })}
                  />
                </label>

                {/* Scanner 4: Risk Mapping */}
                <label className="flex items-center justify-between p-4 bg-surface-container-low border border-outline-variant rounded-lg cursor-pointer hover:border-on-surface-variant transition-colors">
                  <div className="flex items-center gap-3">
                    <span className="material-symbols-outlined text-primary">hub</span>
                    <div>
                      <p className="font-body-md text-on-surface font-semibold">Risk Mapping (Architecture)</p>
                      <p className="text-xs text-on-surface-variant">Reconstruct application flow diagram</p>
                    </div>
                  </div>
                  <input
                    type="checkbox"
                    className="w-5 h-5 rounded border-outline-variant text-primary focus:ring-primary/30 cursor-pointer"
                    checked={scanners.riskMapping}
                    onChange={(e) => setScanners({ ...scanners, riskMapping: e.target.checked })}
                  />
                </label>

                {/* Scanner 5: Cross-Validation */}
                <label className="flex items-center justify-between p-4 bg-surface-container-low border border-outline-variant rounded-lg cursor-pointer hover:border-on-surface-variant transition-colors">
                  <div className="flex items-center gap-3">
                    <span className="material-symbols-outlined text-primary">join_inner</span>
                    <div>
                      <p className="font-body-md text-on-surface font-semibold">Cross-Validation</p>
                      <p className="text-xs text-on-surface-variant">Correlate static and dynamic vulnerabilities</p>
                    </div>
                  </div>
                  <input
                    type="checkbox"
                    className="w-5 h-5 rounded border-outline-variant text-primary focus:ring-primary/30 cursor-pointer"
                    checked={scanners.crossValidation}
                    onChange={(e) => setScanners({ ...scanners, crossValidation: e.target.checked })}
                  />
                </label>

                {/* Scanner 6: AI Analysis */}
                <label className="flex items-center justify-between p-4 bg-surface-container-low border border-outline-variant rounded-lg cursor-pointer hover:border-on-surface-variant transition-colors">
                  <div className="flex items-center gap-3">
                    <span className="material-symbols-outlined text-primary">psychology</span>
                    <div>
                      <p className="font-body-md text-on-surface font-semibold">AI Analysis</p>
                      <p className="text-xs text-on-surface-variant">Generate code repair patch files</p>
                    </div>
                  </div>
                  <input
                    type="checkbox"
                    className="w-5 h-5 rounded border-outline-variant text-primary focus:ring-primary/30 cursor-pointer"
                    checked={scanners.aiAnalysis}
                    onChange={(e) => setScanners({ ...scanners, aiAnalysis: e.target.checked })}
                  />
                </label>
              </div>
            </div>
          )}

          {/* STEP 5: Review */}
          {step === 5 && (
            <div className="space-y-6">
              <div className="mb-8">
                <h3 className="font-headline-md text-headline-md text-on-surface mb-2">Review Project Configuration</h3>
                <p className="text-on-surface-variant">Verify details before initiating application provisioning.</p>
              </div>
              <div className="bg-surface-container-low border border-outline-variant rounded-lg p-6 space-y-4">
                <div className="grid grid-cols-3 border-b border-outline-variant/30 pb-3">
                  <span className="text-on-surface-variant text-sm font-label-mono uppercase">Project Name</span>
                  <span className="col-span-2 text-white font-medium text-body-md">{projName}</span>
                </div>
                <div className="grid grid-cols-3 border-b border-outline-variant/30 pb-3">
                  <span className="text-on-surface-variant text-sm font-label-mono uppercase">Stack</span>
                  <span className="col-span-2 text-white font-medium text-body-md">{projTech}</span>
                </div>
                <div className="grid grid-cols-3 border-b border-outline-variant/30 pb-3">
                  <span className="text-on-surface-variant text-sm font-label-mono uppercase">Source Type</span>
                  <span className="col-span-2 text-white font-medium text-body-md">{sourceType}</span>
                </div>
                {sourceType === 'Git Repository' && (
                  <div className="grid grid-cols-3 border-b border-outline-variant/30 pb-3">
                    <span className="text-on-surface-variant text-sm font-label-mono uppercase">Repository</span>
                    <span className="col-span-2 text-primary font-mono text-sm break-all">{repoUrl}</span>
                  </div>
                )}
                {sourceType === 'Website URL' && (
                  <div className="grid grid-cols-3 border-b border-outline-variant/30 pb-3">
                    <span className="text-on-surface-variant text-sm font-label-mono uppercase">Target URL</span>
                    <span className="col-span-2 text-primary font-mono text-sm break-all">{websiteUrl}</span>
                  </div>
                )}
                <div className="grid grid-cols-3 border-b border-outline-variant/30 pb-3">
                  <span className="text-on-surface-variant text-sm font-label-mono uppercase">Analysis Mode</span>
                  <span className="col-span-2 text-[#a3defe] font-medium text-body-md">{analysisMode}</span>
                </div>
                <div className="grid grid-cols-3">
                  <span className="text-on-surface-variant text-sm font-label-mono uppercase">Active Layers</span>
                  <span className="col-span-2 text-on-surface-variant text-sm">
                    {Object.entries(scanners)
                      .filter(([_, active]) => active)
                      .map(([key]) => key.replace(/([A-Z])/g, ' $1'))
                      .join(', ')}
                  </span>
                </div>
              </div>
            </div>
          )}

        </GlassPanel>

        {/* Navigation Action Buttons */}
        <div className="w-full max-w-5xl flex justify-between items-center pb-8">
          <button
            onClick={handleBack}
            className="px-6 py-3 rounded-lg font-medium text-on-surface-variant flex items-center gap-2 hover:text-on-surface transition-colors cursor-pointer bg-transparent border-none"
          >
            <span className="material-symbols-outlined text-sm">arrow_back</span>
            <span>Back</span>
          </button>

          {step < 5 ? (
            <button
              onClick={handleNext}
              className="btn-primary px-8 py-3 rounded-lg font-medium text-white flex items-center gap-2 cursor-pointer"
            >
              <span>Next</span>
              <span className="material-symbols-outlined text-sm">arrow_forward</span>
            </button>
          ) : (
            <button
              onClick={handleCreate}
              disabled={loading}
              className="btn-primary px-8 py-3 rounded-lg font-medium text-white flex items-center gap-2 cursor-pointer hover:shadow-[0_0_15px_rgba(49,146,252,0.4)] disabled:opacity-50"
            >
              {loading ? (
                <>
                  <span className="material-symbols-outlined text-sm animate-spin">sync</span>
                  <span>Creating...</span>
                </>
              ) : (
                <>
                  <span>Create Project</span>
                  <span className="material-symbols-outlined text-sm">done</span>
                </>
              )}
            </button>
          )}
        </div>

      </div>
    </div>
  );
};

export default ProjectOnboard;
