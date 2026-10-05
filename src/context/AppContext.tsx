import React, { createContext, useContext, useState, useEffect } from 'react';
import { getCurrentUser, loginUser, logoutUser, registerUser, type User } from '../api/auth';
import { createProject as createProjectApi, fetchProjects, type ProjectApiData } from '../api/projects';
import { createScan, fetchScan, fetchScans, pauseScan as pauseScanApi, resumeScan as resumeScanApi, stopScan as stopScanApi, type ScanApiData, type ScanStatus } from '../api/scans';

export interface ProjectData {
  id: string;
  name: string;
  technology: string;
  repository: string;
  score: number | null;
  critical: number;
  high: number;
  medium: number;
  low: number;
  totalFindings?: number;
  hasData?: boolean;
  lastScan: string;
  status: 'Protected' | 'Scanning' | 'Needs Attention';
  sourceType?: string | null;
  sourceStatus?: string;
  targetUrl?: string | null;
  ingestionError?: string | null;
}

const mapProject = (project: ProjectApiData): ProjectData => {
  const normalizedStatus = project.status.toLowerCase();
  const critical = project.critical ?? 0;
  const high = project.high ?? 0;
  const medium = project.medium ?? 0;
  const low = project.low ?? 0;
  const score = project.score ?? null;
  const hasData = project.has_data ?? ((project.total_findings ?? 0) > 0);

  let status: ProjectData['status'] = 'Protected';
  if (normalizedStatus.includes('scan')) {
    status = 'Scanning';
  } else if (
    normalizedStatus.includes('attention') ||
    normalizedStatus.includes('vulnerable') ||
    critical > 0 ||
    high > 0 ||
    (score !== null && score < 60)
  ) {
    status = 'Needs Attention';
  } else {
    status = 'Protected';
  }

  return {
    id: String(project.id),
    name: project.name,
    technology: project.technology || 'Unknown technology',
    repository: project.repository_url || 'No repository connected',
    score,
    critical,
    high,
    medium,
    low,
    totalFindings: project.total_findings ?? 0,
    hasData,
    lastScan: project.created_at ? new Date(project.created_at).toLocaleDateString() : 'Not scanned',
    status,
    sourceType: project.source_type,
    sourceStatus: project.source_status,
    targetUrl: project.target_url,
    ingestionError: project.ingestion_error,
  };
};

interface AppContextType {
  user: User | null;
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
  authLoading: boolean;
  login: (email: string, password: string) => Promise<boolean>;
  register: (email: string, password: string, fullName?: string) => Promise<boolean>;
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
  const [user, setUser] = useState<User | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [authLoading, setAuthLoading] = useState<boolean>(true);

  const [orgName, setOrgName] = useState('Global Sec Ops');
  const [activeProjectId, setActiveProjectId] = useState('');
  const [projects, setProjects] = useState<ProjectData[]>([]);
  const [projectsLoading, setProjectsLoading] = useState(false);
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

  // Bootstrap active authentication session on startup
  useEffect(() => {
    let isMounted = true;
    const checkAuth = async () => {
      try {
        const currentUser = await getCurrentUser();
        if (isMounted) {
          setUser(currentUser);
          setIsAuthenticated(true);
        }
      } catch {
        if (isMounted) {
          setUser(null);
          setIsAuthenticated(false);
        }
      } finally {
        if (isMounted) {
          setAuthLoading(false);
        }
      }
    };

    void checkAuth();
    return () => {
      isMounted = false;
    };
  }, []);

  // When authenticated, load projects
  useEffect(() => {
    if (isAuthenticated) {
      void refreshProjects();
    } else {
      setProjects([]);
      setActiveProjectId('');
    }
  }, [isAuthenticated]);

  const createProject = async (project: Parameters<typeof createProjectApi>[0]) => {
    const createdProject = mapProject(await createProjectApi(project));
    setProjects((currentProjects) => [...currentProjects, createdProject]);
    setActiveProjectId(createdProject.id);
    return createdProject;
  };

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
    if (!isAuthenticated) return;
    void fetchScans()
      .then((scans) => applyScan(scans[0] || null))
      .catch((error: unknown) => setScanError(error instanceof Error ? error.message : 'Unable to load scan state.'));
  }, [isAuthenticated]);

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

  const login = async (email: string, password: string): Promise<boolean> => {
    const tokenResp = await loginUser(email, password);
    setUser(tokenResp.user);
    setIsAuthenticated(true);
    return true;
  };

  const register = async (email: string, password: string, fullName?: string): Promise<boolean> => {
    const tokenResp = await registerUser(email, password, fullName);
    setUser(tokenResp.user);
    setIsAuthenticated(true);
    return true;
  };

  const logout = () => {
    void logoutUser();
    setUser(null);
    setIsAuthenticated(false);
    setProjects([]);
    setActiveProjectId('');
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
        user,
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
        authLoading,
        login,
        register,
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
