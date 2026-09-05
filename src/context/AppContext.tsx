import React, { createContext, useContext, useState, useEffect } from 'react';
import { createProject as createProjectApi, fetchProjects, type ProjectApiData } from '../api/projects';
import { createScan, fetchScan, fetchScans, pauseScan as pauseScanApi, resumeScan as resumeScanApi, stopScan as stopScanApi, type ScanApiData, type ScanStatus } from '../api/scans';

export interface ProjectData {
  id: string;
  name: string;
  technology: string;
  repository: string;
  score: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  lastScan: string;
  status: 'Protected' | 'Scanning' | 'Needs Attention';
  sourceType?: string | null;
  sourceStatus?: string;
  targetUrl?: string | null;
  ingestionError?: string | null;
}

const mapProject = (project: ProjectApiData): ProjectData => {
  const normalizedStatus = project.status.toLowerCase();
  const status: ProjectData['status'] = normalizedStatus.includes('scan')
    ? 'Scanning'
    : normalizedStatus.includes('attention') || normalizedStatus.includes('vulnerable')
      ? 'Needs Attention'
      : 'Protected';

  return {
    id: String(project.id),
    name: project.name,
    technology: project.technology || 'Unknown technology',
    repository: project.repository_url || 'No repository connected',
    score: status === 'Needs Attention' ? 45 : status === 'Scanning' ? 75 : 98,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    lastScan: project.created_at ? new Date(project.created_at).toLocaleDateString() : 'Not scanned',
    status,
    sourceType: project.source_type,
    sourceStatus: project.source_status,
    targetUrl: project.target_url,
    ingestionError: project.ingestion_error,
  };
};

interface AppContextType {
  orgName: string;
  setOrgName: (name: string) => void;
  activeProjectId: string;
  setActiveProjectId: (id: string) => void;
  projects: ProjectData[];
  setProjects: React.Dispatch<React.SetStateAction<ProjectData[]>>;
  projectsLoading: boolean;
  projectsError: string | null;
  refreshProjects: () => Promise<void>;
  createProject: (project: Parameters<typeof createProjectApi>[0]) => Promise<ProjectData>;
  isAuthenticated: boolean;
  login: (email: string) => Promise<boolean>;
  logout: () => void;
  activeScanId: number | null;
  scanError: string | null;
  isScanning: boolean;
  scanProgress: number;
  scanStatus: ScanStatus | 'idle';
  scanPhase: string;
  startScan: (projectId: string) => Promise<void>;
  pauseScan: () => Promise<void>;
  resumeScan: () => Promise<void>;
  stopScan: () => Promise<void>;
}

const AppContext = createContext<AppContextType | undefined>(undefined);

export const AppProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [orgName, setOrgName] = useState('Global Sec Ops');
  const [activeProjectId, setActiveProjectId] = useState('');
  const [isAuthenticated, setIsAuthenticated] = useState(() => {
    return localStorage.getItem('kyptic_auth') === 'true';
  });

  const [projects, setProjects] = useState<ProjectData[]>([]);
  const [projectsLoading, setProjectsLoading] = useState(true);
  const [projectsError, setProjectsError] = useState<string | null>(null);
  const [activeScanId, setActiveScanId] = useState<number | null>(null);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStatus, setScanStatus] = useState<ScanStatus | 'idle'>('idle');
  const [scanPhase, setScanPhase] = useState('Queued');
  const [scanError, setScanError] = useState<string | null>(null);

  const refreshProjects = async () => {
    setProjectsLoading(true);
    setProjectsError(null);
    try {
      const loadedProjects = (await fetchProjects()).map(mapProject);
      setProjects(loadedProjects);
      setActiveProjectId((currentId) => loadedProjects.some((project) => project.id === currentId)
        ? currentId
        : loadedProjects[0]?.id || '');
    } catch (error) {
      setProjects([]);
      setProjectsError(error instanceof Error ? error.message : 'Unable to load projects.');
    } finally {
      setProjectsLoading(false);
    }
  };

  const createProject = async (project: Parameters<typeof createProjectApi>[0]) => {
    const createdProject = mapProject(await createProjectApi(project));
    setProjects((currentProjects) => [...currentProjects, createdProject]);
    setActiveProjectId(createdProject.id);
    return createdProject;
  };

  useEffect(() => {
    void refreshProjects();
  }, []);

  const applyScan = (scan: ScanApiData | null) => {
    setActiveScanId(scan?.id ?? null);
    setScanProgress(scan?.progress ?? 0);
    setScanStatus(scan?.status ?? 'idle');
    setScanPhase(scan?.current_phase ?? 'Queued');
    if (scan?.project_id) {
      const displayStatus = scan.status === 'running' || scan.status === 'queued' || scan.status === 'paused'
        ? 'Scanning'
        : 'Protected';
      setProjects((currentProjects) => currentProjects.map((project) => (
        project.id === String(scan.project_id)
          ? { ...project, status: displayStatus, lastScan: scan.status === 'completed' ? 'Just now' : project.lastScan }
          : project
      )));
    }
  };

  const refreshScan = async (scanId: number) => {
    const scan = await fetchScan(scanId);
    applyScan(scan);
  };

  useEffect(() => {
    void fetchScans()
      .then((scans) => applyScan(scans[0] || null))
      .catch((error: unknown) => setScanError(error instanceof Error ? error.message : 'Unable to load scan state.'));
  }, []);

  useEffect(() => {
    if (activeScanId === null || !['queued', 'running'].includes(scanStatus)) {
      return undefined;
    }
    const interval = setInterval(() => {
      void refreshScan(activeScanId).catch((error: unknown) => {
        setScanError(error instanceof Error ? error.message : 'Unable to refresh scan state.');
      });
    }, 500);
    return () => clearInterval(interval);
  }, [activeScanId, scanStatus]);

  const isScanning = scanStatus === 'running' || scanStatus === 'queued';

  const login = async (_email: string) => {
    // Simple mock authentication delay
    await new Promise((r) => setTimeout(r, 600));
    setIsAuthenticated(true);
    localStorage.setItem('kyptic_auth', 'true');
    return true;
  };

  const logout = () => {
    setIsAuthenticated(false);
    localStorage.removeItem('kyptic_auth');
  };

  const startScan = async (projectId: string) => {
    setScanError(null);
    try {
      const scan = await createScan(projectId);
      applyScan(scan);
      setProjects(prev => prev.map(p => p.id === projectId ? { ...p, status: 'Scanning' } : p));
    } catch (error) {
      setScanError(error instanceof Error ? error.message : 'Unable to start scan.');
      throw error;
    }
  };

  const pauseScan = async () => {
    if (activeScanId === null) return;
    setScanError(null);
    try {
      applyScan(await pauseScanApi(activeScanId));
    } catch (error) {
      setScanError(error instanceof Error ? error.message : 'Unable to pause scan.');
      throw error;
    }
  };

  const resumeScan = async () => {
    if (activeScanId === null) return;
    setScanError(null);
    try {
      applyScan(await resumeScanApi(activeScanId));
    } catch (error) {
      setScanError(error instanceof Error ? error.message : 'Unable to resume scan.');
      throw error;
    }
  };

  const stopScan = async () => {
    if (activeScanId === null) return;
    setScanError(null);
    try {
      applyScan(await stopScanApi(activeScanId));
      setProjects(prev => prev.map(p => p.id === activeProjectId ? { ...p, status: 'Protected' } : p));
    } catch (error) {
      setScanError(error instanceof Error ? error.message : 'Unable to stop scan.');
      throw error;
    }
  };

  return (
    <AppContext.Provider
      value={{
        orgName,
        setOrgName,
        activeProjectId,
        setActiveProjectId,
        projects,
        setProjects,
        projectsLoading,
        projectsError,
        refreshProjects,
        createProject,
        isAuthenticated,
        login,
        logout,
        activeScanId,
        scanError,
        isScanning,
        scanProgress,
        scanStatus,
        scanPhase,
        startScan,
        pauseScan,
        resumeScan,
        stopScan,
      }}
    >
      {children}
    </AppContext.Provider>
  );
};

export const useApp = () => {
  const context = useContext(AppContext);
  if (!context) {
    throw new Error('useApp must be used within AppProvider');
  }
  return context;
};
