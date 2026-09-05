import React from 'react';

interface BadgeProps {
  variant?: 'critical' | 'high' | 'medium' | 'low' | 'primary' | 'success' | 'neutral';
  children: React.ReactNode;
  icon?: string;
  className?: string;
  pulse?: boolean;
}

export const Badge: React.FC<BadgeProps> = ({
  variant = 'neutral',
  children,
  icon,
  className = '',
  pulse = false,
}) => {
  const baseClasses = 'px-2.5 py-1 rounded font-label-mono text-[11px] font-semibold uppercase tracking-wider inline-flex items-center gap-1.5 border';

  const variants = {
    critical: 'bg-error-container/10 text-error border-error-container/30',
    high: 'bg-tertiary-container/10 text-tertiary border-tertiary-container/30',
    medium: 'bg-[#ffeb3b]/10 text-[#ffeb3b] border-[#ffeb3b]/20',
    low: 'bg-surface-variant/50 text-on-surface-variant border-outline-variant/30',
    primary: 'bg-primary-container/10 text-primary border-primary-container/30',
    success: 'bg-[#10b981]/10 text-[#10b981] border-[#10b981]/20',
    neutral: 'bg-surface-container border-outline-variant/30 text-on-surface-variant',
  };

  const dotColors = {
    critical: 'bg-error',
    high: 'bg-tertiary',
    medium: 'bg-[#ffeb3b]',
    low: 'bg-outline',
    primary: 'bg-primary',
    success: 'bg-[#10b981]',
    neutral: 'bg-outline-variant',
  };

  return (
    <span className={`${baseClasses} ${variants[variant]} ${className}`}>
      {pulse && (
        <span className={`w-2 h-2 rounded-full ${dotColors[variant]} ${pulse ? 'animate-pulse' : ''}`}></span>
      )}
      {icon && !pulse && (
        <span className="material-symbols-outlined text-[13px]">{icon}</span>
      )}
      <span>{children}</span>
    </span>
  );
};

export default Badge;
