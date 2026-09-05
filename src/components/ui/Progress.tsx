import React from 'react';

interface CircularProgressProps {
  value: number; // 0 to 100
  size?: number; // pixel size
  strokeWidth?: number;
  className?: string;
  variant?: 'primary' | 'error' | 'success' | 'tertiary';
  label?: string;
}

export const CircularProgress: React.FC<CircularProgressProps> = ({
  value,
  size = 64,
  strokeWidth = 4,
  className = '',
  variant = 'primary',
  label,
}) => {
  const colors = {
    primary: 'text-primary',
    error: 'text-error',
    success: 'text-[#10b981]',
    tertiary: 'text-tertiary',
  };

  return (
    <div className={`relative flex items-center justify-center ${className}`} style={{ width: size, height: size }}>
      <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
        <path
          className="text-surface-container-high"
          d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
          fill="none"
          stroke="currentColor"
          strokeWidth={strokeWidth}
        ></path>
        <path
          className={`${colors[variant]} transition-all duration-500`}
          d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
          fill="none"
          stroke="currentColor"
          strokeDasharray={`${value}, 100`}
          strokeLinecap="round"
          strokeWidth={strokeWidth}
        ></path>
      </svg>
      <span className="absolute text-xs font-bold text-on-surface">
        {label !== undefined ? label : value}
      </span>
    </div>
  );
};

interface ProgressBarProps {
  value: number; // 0 to 100
  className?: string;
  variant?: 'primary' | 'error' | 'success' | 'tertiary';
  glow?: boolean;
}

export const ProgressBar: React.FC<ProgressBarProps> = ({
  value,
  className = '',
  variant = 'primary',
  glow = false,
}) => {
  const bgColors = {
    primary: 'bg-primary',
    error: 'bg-error',
    success: 'bg-[#10b981]',
    tertiary: 'bg-tertiary',
  };

  const glowStyles = {
    primary: 'shadow-[0_0_10px_rgba(166,200,255,0.5)]',
    error: 'shadow-[0_0_10px_rgba(255,77,77,0.5)]',
    success: 'shadow-[0_0_10px_rgba(16,185,129,0.5)]',
    tertiary: 'shadow-[0_0_10px_rgba(255,183,130,0.5)]',
  };

  return (
    <div className={`h-1.5 w-full bg-surface-variant rounded-full overflow-hidden ${className}`}>
      <div
        className={`h-full rounded-full transition-all duration-500 ${bgColors[variant]} ${
          glow ? glowStyles[variant] : ''
        }`}
        style={{ width: `${value}%` }}
      ></div>
    </div>
  );
};
