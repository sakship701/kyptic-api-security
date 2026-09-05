import React from 'react';
import logoImg from '../../assets/logo.png';

interface LogoProps {
  className?: string;
  size?: 'sm' | 'md' | 'lg' | 'xl';
  withText?: boolean;
}

export const Logo: React.FC<LogoProps> = ({ className = '', size = 'md', withText = false }) => {
  const logoUrl = logoImg;

  const sizeClasses = {
    sm: 'h-8 w-8',
    md: 'h-10 w-10',
    lg: 'h-16 w-16',
    xl: 'h-20 w-auto',
  };

  return (
    <div className={`flex items-center gap-3 ${className}`}>
      <img
        src={logoUrl}
        alt="Kyptic Logo"
        className={`${sizeClasses[size]} rounded-lg object-contain`}
      />
      {withText && (
        <div>
          <h1 className="font-headline-md text-headline-md font-bold text-primary tracking-tight leading-none">
            Kyptic
          </h1>
          <p className="font-label-mono text-[9px] text-on-surface-variant uppercase opacity-70 tracking-widest mt-1">
            Enterprise AI Security
          </p>
        </div>
      )}
    </div>
  );
};
export default Logo;
