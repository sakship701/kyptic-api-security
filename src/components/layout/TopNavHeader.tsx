import React, { useState } from 'react';
import { useApp } from '../../context/AppContext';

export const TopNavHeader: React.FC = () => {
  const { orgName, setOrgName, activeProjectId, setActiveProjectId, projects } = useApp();
  const [showOrgDropdown, setShowOrgDropdown] = useState(false);
  const [showProjDropdown, setShowProjDropdown] = useState(false);

  const activeProject = projects.find(p => p.id === activeProjectId) || projects[0];

  const orgs = ['Global Sec Ops', 'Sentinel Global', 'DevSecOps Core'];

  return (
    <header className="hidden md:flex justify-between items-center px-container-padding h-20 w-full bg-surface-container/80 backdrop-blur-xl border-b border-outline-variant sticky top-0 z-30 shadow-sm shrink-0">
      {/* Org and Project Dropdowns */}
      <div className="flex items-center gap-4 text-on-surface-variant">
        {/* Org Selector */}
        <div className="relative">
          <button
            onClick={() => {
              setShowOrgDropdown(!showOrgDropdown);
              setShowProjDropdown(false);
            }}
            className="flex items-center gap-2 hover:text-primary transition-colors text-body-md font-medium"
          >
            <span>Org: {orgName}</span>
            <span className="material-symbols-outlined text-sm">keyboard_arrow_down</span>
          </button>
          {showOrgDropdown && (
            <ul className="absolute top-8 left-0 w-48 bg-[#0A0D12] border border-[#1F242D] rounded-lg p-1 shadow-2xl z-50">
              {orgs.map((org) => (
                <li key={org}>
                  <button
                    onClick={() => {
                      setOrgName(org);
                      setShowOrgDropdown(false);
                    }}
                    className={`w-full text-left px-3 py-2 rounded text-sm hover:bg-surface-container-high transition-colors ${
                      orgName === org ? 'text-primary font-semibold' : 'text-on-surface-variant'
                    }`}
                  >
                    {org}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>

        <span className="text-outline-variant">|</span>

        {/* Project Selector */}
        <div className="relative">
          <button
            onClick={() => {
              setShowProjDropdown(!showProjDropdown);
              setShowOrgDropdown(false);
            }}
            className="flex items-center gap-2 hover:text-primary transition-colors text-body-md font-medium"
          >
            <span>Project: {activeProject?.name || 'Select Project'}</span>
            <span className="material-symbols-outlined text-sm">keyboard_arrow_down</span>
          </button>
          {showProjDropdown && (
            <ul className="absolute top-8 left-0 w-48 bg-[#0A0D12] border border-[#1F242D] rounded-lg p-1 shadow-2xl z-50">
              {projects.map((proj) => (
                <li key={proj.id}>
                  <button
                    onClick={() => {
                      setActiveProjectId(proj.id);
                      setShowProjDropdown(false);
                    }}
                    className={`w-full text-left px-3 py-2 rounded text-sm hover:bg-surface-container-high transition-colors ${
                      activeProjectId === proj.id ? 'text-primary font-semibold' : 'text-on-surface-variant'
                    }`}
                  >
                    {proj.name}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      {/* Global Actions: Search, Notifications, Profile */}
      <div className="flex items-center gap-4">
        {/* Search */}
        <div className="relative">
          <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant">
            search
          </span>
          <input
            className="bg-[#0A0D12] border border-[#1F242D] rounded-full py-2 pl-10 pr-4 text-body-md text-on-surface focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary w-64 transition-all placeholder:text-outline"
            placeholder="Search vulnerabilities, projects..."
            type="text"
          />
        </div>

        {/* Notifications */}
        <button className="relative p-2 text-on-surface-variant hover:text-primary transition-colors opacity-90 hover:opacity-100">
          <span className="material-symbols-outlined">notifications</span>
          <span className="absolute top-1 right-1 w-2 h-2 bg-error rounded-full animate-pulse"></span>
        </button>

        {/* User Profile */}
        <button className="p-0.5 rounded-full border border-outline-variant hover:border-primary transition-colors opacity-90 hover:opacity-100 overflow-hidden">
          <img
            alt="User Profile"
            className="w-8 h-8 rounded-full object-cover"
            src="https://lh3.googleusercontent.com/aida-public/AB6AXuCiX_pxKcQLo_k8tWzRgp2MrXdqM8fLxQLwigPkxX6X6Ig0SZG1DfN2mVaIZxndvVQJZHt9lM6BXapUT9of-Mcv_zX6etmXdGSZOwDVzc6fUjg4AIizCIcptPu1ZSOcjauYMx09FKYcbfqZpB26SjH7JrAhFcKneBdKCr9-cJSXWw4kVDC38ZD2hVlLrlQgWmPwxxovyloRj0miget3n1Z5iTVRkooEskVaiFo6vviXViWCeDr2bQckPw"
          />
        </button>
      </div>
    </header>
  );
};

export default TopNavHeader;
