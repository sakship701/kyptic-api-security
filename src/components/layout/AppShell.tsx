import React, { useState } from 'react';
import { Outlet, Navigate } from 'react-router-dom';
import SideNavBar from './SideNavBar';
import TopNavHeader from './TopNavHeader';
import { useApp } from '../../context/AppContext';
import Logo from '../ui/Logo';

export const AppShell: React.FC = () => {
  const { isAuthenticated, authLoading } = useApp();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // While checking active session
  if (authLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#06070A] text-on-surface">
        <div className="flex flex-col items-center gap-4">
          <Logo size="lg" />
          <div className="flex items-center gap-2 text-primary font-label-mono text-sm">
            <span className="material-symbols-outlined animate-spin text-lg">sync</span>
            <span>Verifying session...</span>
          </div>
        </div>
      </div>
    );
  }

  // Protect route
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return (
    <div className="min-h-screen flex flex-col md:flex-row bg-[#06070A] text-on-background selection:bg-primary-container selection:text-on-primary-container overflow-x-hidden">
      {/* Mobile Header */}
      <div className="md:hidden sticky top-0 z-50 w-full flex justify-between items-center px-4 h-16 bg-surface-container/80 backdrop-blur-xl border-b border-outline-variant shadow-sm">
        <Logo size="sm" withText={true} />
        <button
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          className="text-on-surface-variant hover:text-primary transition-colors duration-200"
        >
          <span className="material-symbols-outlined">{mobileMenuOpen ? 'close' : 'menu'}</span>
        </button>
      </div>

      {/* Mobile Drawer Navigation */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 top-16 bg-[#06070A] z-40 flex flex-col p-4 border-b border-outline-variant animate-fadeIn">
          {/* We reuse the sidebar list style here */}
          <ul className="flex flex-col gap-2">
            <li>
              <a
                href="/dashboard"
                onClick={() => setMobileMenuOpen(false)}
                className="flex items-center gap-3 px-4 py-3 rounded-lg text-primary bg-surface-container-high"
              >
                <span className="material-symbols-outlined">dashboard</span>
                <span>Dashboard</span>
              </a>
            </li>
            <li>
              <a
                href="/projects"
                onClick={() => setMobileMenuOpen(false)}
                className="flex items-center gap-3 px-4 py-3 rounded-lg text-on-surface-variant hover:bg-surface-container-high"
              >
                <span className="material-symbols-outlined">inventory_2</span>
                <span>Projects</span>
              </a>
            </li>
            <li>
              <a
                href="/scans"
                onClick={() => setMobileMenuOpen(false)}
                className="flex items-center gap-3 px-4 py-3 rounded-lg text-on-surface-variant hover:bg-surface-container-high"
              >
                <span className="material-symbols-outlined">rocket_launch</span>
                <span>New Scan</span>
              </a>
            </li>
            <li>
              <a
                href="/risk-map"
                onClick={() => setMobileMenuOpen(false)}
                className="flex items-center gap-3 px-4 py-3 rounded-lg text-on-surface-variant hover:bg-surface-container-high"
              >
                <span className="material-symbols-outlined">hub</span>
                <span>Risk Map</span>
              </a>
            </li>
            <li>
              <a
                href="/findings"
                onClick={() => setMobileMenuOpen(false)}
                className="flex items-center gap-3 px-4 py-3 rounded-lg text-on-surface-variant hover:bg-surface-container-high"
              >
                <span className="material-symbols-outlined">security</span>
                <span>Vulnerabilities</span>
              </a>
            </li>
            <li>
              <a
                href="/copilot"
                onClick={() => setMobileMenuOpen(false)}
                className="flex items-center gap-3 px-4 py-3 rounded-lg text-on-surface-variant hover:bg-surface-container-high"
              >
                <span className="material-symbols-outlined">psychology</span>
                <span>AI Security Copilot</span>
              </a>
            </li>
            <li>
              <a
                href="/reports"
                onClick={() => setMobileMenuOpen(false)}
                className="flex items-center gap-3 px-4 py-3 rounded-lg text-on-surface-variant hover:bg-surface-container-high"
              >
                <span className="material-symbols-outlined">assessment</span>
                <span>Reports</span>
              </a>
            </li>
          </ul>
        </div>
      )}

      {/* Desktop Left Nav Drawer */}
      <SideNavBar />

      {/* Main Workspace Frame */}
      <div className="flex-1 flex flex-col min-w-0 bg-[#06070A] h-screen overflow-y-auto">
        {/* Global Context Bar */}
        <TopNavHeader />

        {/* Dynamic Viewport Container */}
        <main className="flex-1 px-container-padding py-stack-lg max-w-content-width w-full mx-auto space-y-stack-xl">
          <Outlet />
        </main>
      </div>
    </div>
  );
};

export default AppShell;
