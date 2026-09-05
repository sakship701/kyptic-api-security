import React from 'react';
import { NavLink } from 'react-router-dom';
import Logo from '../ui/Logo';
import { useApp } from '../../context/AppContext';

export const SideNavBar: React.FC = () => {
  const { logout } = useApp();

  const navItems = [
    { name: 'Dashboard', path: '/dashboard', icon: 'dashboard' },
    { name: 'Projects', path: '/projects', icon: 'inventory_2' },
    { name: 'API Security', path: '/api-security', icon: 'api' },
    { name: 'New Scan', path: '/scans', icon: 'rocket_launch' },
    { name: 'Risk Map', path: '/risk-map', icon: 'hub' },
    { name: 'Vulnerabilities', path: '/findings', icon: 'security' },
    { name: 'AI Security Copilot', path: '/copilot', icon: 'psychology' },
    { name: 'Reports', path: '/reports', icon: 'assessment' },
  ];


  return (
    <nav className="hidden md:flex flex-col h-screen sticky left-0 top-0 w-64 border-r border-outline-variant bg-surface-container-low py-stack-lg z-40 shrink-0">
      {/* Branding */}
      <div className="px-6 mb-8">
        <Logo size="md" withText={true} />
      </div>

      {/* Nav Links */}
      <ul className="flex flex-col flex-1 px-4 gap-1">
        {navItems.map((item) => (
          <li key={item.name}>
            <NavLink
              to={item.path}
              className={({ isActive }) =>
                `flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200 active:scale-95 ${
                  isActive
                    ? 'text-primary font-bold border-r-2 border-primary bg-surface-container-high'
                    : 'text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface'
                }`
              }
            >
              <span className="material-symbols-outlined text-[20px]">{item.icon}</span>
              <span className="font-body-md text-body-md">{item.name}</span>
            </NavLink>
          </li>
        ))}

        {/* Settings at the bottom */}
        <li className="mt-auto">
          <NavLink
            to="/settings"
            className={({ isActive }) =>
              `flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200 active:scale-95 ${
                isActive
                  ? 'text-primary font-bold border-r-2 border-primary bg-surface-container-high'
                  : 'text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface'
              }`
            }
          >
            <span className="material-symbols-outlined text-[20px]">settings</span>
            <span className="font-body-md text-body-md">Settings</span>
          </NavLink>
        </li>

        {/* Log Out */}
        <li>
          <button
            onClick={logout}
            className="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface transition-all duration-200 active:scale-95 text-left"
          >
            <span className="material-symbols-outlined text-[20px]">logout</span>
            <span className="font-body-md text-body-md">Log Out</span>
          </button>
        </li>
      </ul>
    </nav>
  );
};

export default SideNavBar;
