import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AppProvider } from './context/AppContext';
import AppShell from './components/layout/AppShell';

// Import Pages
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import ProjectList from './pages/Projects/ProjectList';
import ProjectOnboard from './pages/Projects/ProjectOnboard';
import ScanCenter from './pages/ScanCenter';
import FindingsList from './pages/Findings/FindingsList';
import FindingDetail from './pages/Findings/FindingDetail';
import Copilot from './pages/Copilot';
import RiskMap from './pages/RiskMap';
import Reports from './pages/Reports';
import Settings from './pages/Settings';
import UIKit from './pages/UIKit';

const App: React.FC = () => {
  return (
    <AppProvider>
      <BrowserRouter>
        <Routes>
          {/* Public Routes */}
          <Route path="/login" element={<Login />} />

          {/* Authenticated Routes with AppShell Layout */}
          <Route path="/" element={<AppShell />}>
            <Route index element={<Navigate to="/dashboard" replace />} />
            <Route path="dashboard" element={<Dashboard />} />
            <Route path="projects" element={<ProjectList />} />
            <Route path="projects/new" element={<ProjectOnboard />} />
            <Route path="scans" element={<ScanCenter />} />
            <Route path="findings" element={<FindingsList />} />
            <Route path="findings/:id" element={<FindingDetail />} />
            <Route path="copilot" element={<Copilot />} />
            <Route path="risk-map" element={<RiskMap />} />
            <Route path="reports" element={<Reports />} />
            <Route path="settings" element={<Settings />} />
            <Route path="ui-kit" element={<UIKit />} />
          </Route>

          {/* Fallback Catch-all Route */}
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </BrowserRouter>
    </AppProvider>
  );
};

export default App;
