import React from 'react';

interface CodeBlockProps {
  filename?: string;
  codeLines: { num: number; content: string; isHighlighted?: boolean }[];
  className?: string;
}

export const CodeBlock: React.FC<CodeBlockProps> = ({
  filename,
  codeLines,
  className = '',
}) => {
  const handleCopy = () => {
    const rawCode = codeLines.map((l) => l.content).join('\n');
    navigator.clipboard.writeText(rawCode);
  };

  return (
    <div className={`code-block rounded-lg overflow-hidden font-code-sm text-code-sm border border-[#1a1f26] ${className}`}>
      {filename && (
        <div className="bg-surface-container-low px-4 py-2 border-b border-[#1a1f26] flex justify-between items-center text-on-surface-variant text-xs">
          <span>{filename}</span>
          <button
            onClick={handleCopy}
            className="hover:text-primary transition-colors flex items-center gap-1"
            title="Copy Code"
          >
            <span className="material-symbols-outlined text-[16px]">content_copy</span>
          </button>
        </div>
      )}
      <div className="p-4 text-on-surface-variant overflow-x-auto whitespace-pre font-mono bg-[#050608]">
        {codeLines.map((line) => {
          if (line.isHighlighted) {
            return (
              <div key={line.num} className="highlight-line -mx-4 px-4 py-1 flex">
                <span className="text-error font-medium w-8 shrink-0 select-none">
                  {line.num} |
                </span>
                <span className="text-on-surface">{line.content}</span>
              </div>
            );
          }
          return (
            <div key={line.num} className="flex">
              <span className="text-outline w-8 shrink-0 select-none">
                {line.num} |
              </span>
              <span className="text-on-surface-variant">{line.content}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default CodeBlock;
