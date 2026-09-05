import React from 'react';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'destructive' | 'ai' | 'ghost';
  children: React.ReactNode;
  icon?: string;
  className?: string;
}

export const Button: React.FC<ButtonProps> = ({
  variant = 'primary',
  children,
  icon,
  className = '',
  ...props
}) => {
  const baseClasses = 'px-4 py-2 rounded-lg font-body-md font-medium transition-all duration-200 flex items-center justify-center gap-2 active:scale-95';
  
  const variants = {
    primary: 'bg-gradient-to-r from-[#2E90FA] to-[#005fb0] text-white border border-transparent hover:shadow-[0_0_15px_rgba(46,144,250,0.4)]',
    secondary: 'bg-transparent border border-outline hover:border-primary text-on-surface hover:text-white',
    destructive: 'bg-error-container/10 border border-error-container/50 text-error hover:bg-error-container/30',
    ai: 'relative overflow-hidden bg-[#161B24] border border-primary-container/30 text-primary group',
    ghost: 'bg-transparent text-on-surface-variant hover:text-on-surface',
  };

  return (
    <button className={`${baseClasses} ${variants[variant]} ${className}`} {...props}>
      {variant === 'ai' && (
        <div className="absolute inset-0 ai-shimmer opacity-40 group-hover:opacity-100 transition-opacity"></div>
      )}
      {icon && (
        <span className="material-symbols-outlined text-[18px] relative z-10">{icon}</span>
      )}
      <span className="relative z-10">{children}</span>
    </button>
  );
};

export default Button;
