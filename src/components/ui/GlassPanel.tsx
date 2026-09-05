import React from 'react';

interface GlassPanelProps {
  children: React.ReactNode;
  className?: string;
  variant?: 'low' | 'high' | 'border-error';
}

export const GlassPanel: React.FC<GlassPanelProps> = ({
  children,
  className = '',
  variant = 'low',
}) => {
  const variantClasses = {
    low: 'glass-panel',
    high: 'glass-panel bg-surface-container-low/80 backdrop-blur-2xl shadow-[0_32px_64px_rgba(0,0,0,0.5)]',
    'border-error': 'glass-panel border-l-4 border-l-error',
  };

  return (
    <div className={`${variantClasses[variant]} ${className}`}>
      {children}
    </div>
  );
};

export default GlassPanel;
