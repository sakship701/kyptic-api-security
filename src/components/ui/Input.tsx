import React from 'react';

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  icon?: string;
  className?: string;
  label?: string;
}

export const Input: React.FC<InputProps> = ({
  icon,
  className = '',
  label,
  ...props
}) => {
  return (
    <div className="w-full">
      {label && (
        <label className="block font-label-mono text-[11px] text-on-surface-variant uppercase tracking-wider mb-2">
          {label}
        </label>
      )}
      <div className="relative">
        {icon && (
          <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant text-[20px] pointer-events-none">
            {icon}
          </span>
        )}
        <input
          className={`w-full bg-[#0A0D12] border border-[#1F242D] rounded-lg py-2.5 text-body-md text-on-surface placeholder:text-outline focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all duration-200 ${
            icon ? 'pl-10' : 'pl-4'
          } pr-4 ${className}`}
          {...props}
        />
      </div>
    </div>
  );
};

interface SelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
  label?: string;
  options: { label: string; value: string }[];
  className?: string;
}

export const Select: React.FC<SelectProps> = ({
  label,
  options,
  className = '',
  ...props
}) => {
  return (
    <div className="w-full">
      {label && (
        <label className="block font-label-mono text-[11px] text-on-surface-variant uppercase tracking-wider mb-2">
          {label}
        </label>
      )}
      <div className="relative">
        <select
          className={`w-full bg-[#0A0D12] border border-[#1F242D] rounded-lg py-2.5 pl-4 pr-10 text-body-md text-on-surface focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all duration-200 appearance-none cursor-pointer ${className}`}
          {...props}
        >
          {options.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
        <span className="material-symbols-outlined absolute right-3 top-1/2 -translate-y-1/2 text-on-surface-variant pointer-events-none">
          expand_more
        </span>
      </div>
    </div>
  );
};

interface TextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string;
  className?: string;
}

export const Textarea: React.FC<TextareaProps> = ({
  label,
  className = '',
  ...props
}) => {
  return (
    <div className="w-full">
      {label && (
        <label className="block font-label-mono text-[11px] text-on-surface-variant uppercase tracking-wider mb-2">
          {label}
        </label>
      )}
      <textarea
        className={`w-full bg-[#0A0D12] border border-[#1F242D] rounded-lg py-2.5 px-4 text-body-md text-on-surface placeholder:text-outline focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all duration-200 resize-none ${className}`}
        {...props}
      />
    </div>
  );
};
