import React, { useState, useEffect, useRef } from 'react';
import { useLocation } from 'react-router-dom';
import { fetchCopilotStatus, sendCopilotChat, type CopilotStatusResponseData } from '../../api/copilot';

interface ChatMessage {
  sender: 'user' | 'ai';
  text: string;
  isFallback?: boolean;
  codeBlock?: {
    file: string;
    code: string;
    lang: string;
  };
}

export const Copilot: React.FC = () => {
  const location = useLocation();
  const chatEndRef = useRef<HTMLDivElement>(null);

  // Context from findings details page if navigated from a finding
  const passedFinding = location.state?.finding;
  const findingId = passedFinding?.id ? Number(passedFinding.id) : null;

  // Initialize focus details
  const focusTitle = passedFinding?.title || 'SQL Injection';
  const focusLocation = passedFinding?.file_path || passedFinding?.file || '/api/v1/login';
  const focusScore = passedFinding?.cvss ? `${passedFinding.cvss} (${passedFinding.severity})` : '9.8 (Critical)';

  const [copilotStatus, setCopilotStatus] = useState<CopilotStatusResponseData | null>(null);

  // Messages state
  const [messages, setMessages] = useState<ChatMessage[]>(() => {
    if (passedFinding) {
      return [
        {
          sender: 'user',
          text: `Can you analyze the vulnerability "${passedFinding.title}" found in ${passedFinding.file_path || 'the application'} and suggest a secure fix?`,
        },
        {
          sender: 'ai',
          text: `I've analyzed finding "${passedFinding.title}". This matches CWE classification **${passedFinding.cwe || 'CWE-89'}** (${passedFinding.owasp || 'A03:2021'}). Target file: \`${passedFinding.file_path || 'authController.js'}\`.`,
          codeBlock: passedFinding.code_snippet
            ? {
                file: passedFinding.file_path || 'authController.js',
                code: passedFinding.code_snippet,
                lang: 'javascript',
              }
            : undefined,
        },
      ];
    }
    return [
      {
        sender: 'user',
        text: "Can you analyze the SQL injection vulnerability found in the Banking API's login endpoint and suggest a fix?",
      },
      {
        sender: 'ai',
        text: "I've analyzed the SQL Injection vulnerability in the Banking API (`/api/v1/login`). The issue occurs because user input from the `username` field is concatenated into the SQL query in `authController.js`.",
        codeBlock: {
          file: 'controllers/authController.js',
          code: `const query = "SELECT * FROM users WHERE username = '" + req.body.username + "' AND password = '" + req.body.password + "'";\ndb.query(query);`,
          lang: 'javascript',
        },
      },
    ];
  });

  const [inputVal, setInputVal] = useState('');
  const [isTyping, setIsTyping] = useState(false);

  // Check Copilot status on load
  useEffect(() => {
    fetchCopilotStatus().then(setCopilotStatus);
  }, []);

  const handleSend = async () => {
    if (!inputVal.trim() || isTyping) return;

    const userMsg = inputVal;
    setMessages((prev) => [...prev, { sender: 'user', text: userMsg }]);
    setInputVal('');
    setIsTyping(true);

    try {
      const res = await sendCopilotChat(userMsg, findingId, false);
      setMessages((prev) => [
        ...prev,
        {
          sender: 'ai',
          text: res.message,
          isFallback: res.is_fallback,
          codeBlock: res.code_block ? { file: res.code_block.file, code: res.code_block.code, lang: res.code_block.lang } : undefined,
        },
      ]);
    } catch (err: any) {
      setMessages((prev) => [
        ...prev,
        {
          sender: 'ai',
          text: `Unable to connect to Kyptic Copilot service (${err.message || err}). Deterministic safety controls remain active.`,
          isFallback: true,
        },
      ]);
    } finally {
      setIsTyping(false);
    }
  };

  const handleSuggestClick = (promptText: string) => {
    setInputVal(promptText);
  };

  // Auto-scroll chat window
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isTyping]);

  return (
    <div className="flex-1 flex h-[calc(100vh-64px)] overflow-hidden text-on-surface">
      {/* Left Sidebar: Intelligence History */}
      <aside className="w-72 flex-shrink-0 border-r border-outline-variant/30 bg-surface-container-lowest flex flex-col h-full hidden lg:flex select-none">
        <div className="p-4 border-b border-outline-variant/30 flex items-center justify-between">
          <h2 className="font-label-mono text-label-mono text-on-surface-variant uppercase tracking-wider">Intelligence History</h2>
          <button
            onClick={() => {
              setMessages([]);
              setInputVal('');
            }}
            className="text-on-surface-variant hover:text-primary transition-colors cursor-pointer bg-transparent border-none"
            title="Clear Chat"
          >
            <span className="material-symbols-outlined text-[18px]">add</span>
          </button>
        </div>

        <div className="flex-grow overflow-y-auto p-4 space-y-6">
          <div>
            <h3 className="font-label-mono text-[11px] text-on-surface-variant mb-2 px-2 uppercase">Pinned Investigations</h3>
            <ul className="space-y-1">
              <li>
                <button
                  onClick={() => handleSuggestClick('Explain Auth Bypass timing attack scenario')}
                  className="w-full flex items-center gap-3 px-2 py-2 rounded-md hover:bg-surface-variant text-on-surface transition-colors group text-left cursor-pointer bg-transparent border-none"
                >
                  <span className="material-symbols-outlined text-[16px] text-tertiary">push_pin</span>
                  <span className="truncate text-sm group-hover:text-primary transition-colors">Auth Bypass in /api/v1/login</span>
                </button>
              </li>
              <li>
                <button
                  onClick={() => handleSuggestClick('Show data exfiltration patterns')}
                  className="w-full flex items-center gap-3 px-2 py-2 rounded-md hover:bg-surface-variant text-on-surface transition-colors group text-left cursor-pointer bg-transparent border-none"
                >
                  <span className="material-symbols-outlined text-[16px] text-tertiary">push_pin</span>
                  <span className="truncate text-sm group-hover:text-primary transition-colors">Data Exfiltration Patterns</span>
                </button>
              </li>
            </ul>
          </div>

          <div>
            <h3 className="font-label-mono text-[11px] text-on-surface-variant mb-2 px-2 uppercase">Recent Analyses</h3>
            <ul className="space-y-1">
              <li>
                <button
                  onClick={() => handleSuggestClick('Explain SQLi in Banking API')}
                  className="w-full flex items-center gap-3 px-2 py-2 rounded-md bg-surface-variant/50 text-primary border-l-2 border-primary transition-colors text-left cursor-pointer border-none"
                >
                  <span className="material-symbols-outlined text-[16px]">chat_bubble</span>
                  <span className="truncate text-sm font-medium">SQLi in Banking API</span>
                </button>
              </li>
              <li>
                <button
                  onClick={() => handleSuggestClick('How do I remediate this vulnerability safely?')}
                  className="w-full flex items-center gap-3 px-2 py-2 rounded-md hover:bg-surface-variant text-on-surface-variant transition-colors group text-left cursor-pointer bg-transparent border-none"
                >
                  <span className="material-symbols-outlined text-[16px]">chat_bubble</span>
                  <span className="truncate text-sm group-hover:text-on-surface transition-colors">Remediation Strategy</span>
                </button>
              </li>
            </ul>
          </div>
        </div>
      </aside>

      {/* Center Panel: AI Copilot conversation workspace */}
      <section className="flex-grow flex flex-col min-w-0 bg-[#06070A] relative overflow-hidden">
        {/* Top Status Banner */}
        {copilotStatus && (
          <div className="px-6 py-2 bg-surface-container-low/80 border-b border-outline-variant/30 flex items-center justify-between text-xs text-on-surface-variant">
            <div className="flex items-center gap-2 font-mono">
              <span className={`w-2 h-2 rounded-full ${copilotStatus.provider_available ? 'bg-green-500' : 'bg-amber-500'}`}></span>
              <span>Provider: <strong className="text-on-surface">{copilotStatus.configured_provider} ({copilotStatus.configured_model})</strong></span>
            </div>
            <div className="font-mono text-[11px]">
              {copilotStatus.provider_available ? (
                <span className="text-green-400 font-bold">ONLINE ({copilotStatus.latency_ms}ms)</span>
              ) : (
                <span className="text-amber-400 font-bold">FALLBACK ENGINE ACTIVE</span>
              )}
            </div>
          </div>
        )}

        {/* Chat Area */}
        <div className="flex-1 overflow-y-auto px-4 md:px-8 py-8 scroll-smooth h-full">
          <div className="max-w-4xl mx-auto space-y-8 pb-32">
            {messages.length === 0 && (
              <div className="text-center space-y-4 mb-12 mt-8">
                <div className="w-16 h-16 mx-auto bg-primary/10 rounded-full flex items-center justify-center border border-primary/20 shadow-[0_0_30px_rgba(166,200,255,0.1)]">
                  <span className="material-symbols-outlined text-3xl text-primary">robot_2</span>
                </div>
                <h1 className="font-headline-md text-headline-md text-on-background">Hello, Security Admin.</h1>
                <p className="text-on-surface-variant text-lg">How can I help secure your application today?</p>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-8 text-left">
                  <button
                    onClick={() => handleSuggestClick('Explain the mechanics of this vulnerability.')}
                    className="bg-surface-container border border-outline-variant p-4 rounded-xl hover:border-primary/50 hover:bg-surface-container-high transition-all duration-200 group flex flex-col gap-3 relative overflow-hidden text-left cursor-pointer bg-transparent"
                  >
                    <span className="material-symbols-outlined text-primary">code_blocks</span>
                    <span className="font-medium text-on-surface">Explain Vulnerability</span>
                    <span className="text-sm text-on-surface-variant">Break down the mechanics of the target vulnerability</span>
                  </button>
                  <button
                    onClick={() => handleSuggestClick('How do I fix it? Generate a secure patch.')}
                    className="bg-surface-container border border-outline-variant p-4 rounded-xl hover:border-primary/50 hover:bg-surface-container-high transition-all duration-200 group flex flex-col gap-3 relative overflow-hidden text-left cursor-pointer bg-transparent"
                  >
                    <span className="material-symbols-outlined text-tertiary">healing</span>
                    <span className="font-medium text-on-surface">Generate Secure Patch</span>
                    <span className="text-sm text-on-surface-variant">Create a parameterized query logic fix</span>
                  </button>
                  <button
                    onClick={() => handleSuggestClick('Explain CWE and OWASP mappings for this finding.')}
                    className="bg-surface-container border border-outline-variant p-4 rounded-xl hover:border-primary/50 hover:bg-surface-container-high transition-all duration-200 group flex flex-col gap-3 relative overflow-hidden text-left cursor-pointer bg-transparent"
                  >
                    <span className="material-symbols-outlined text-error">sort_by_alpha</span>
                    <span className="font-medium text-on-surface">Explain CWE & OWASP</span>
                    <span className="text-sm text-on-surface-variant">Analyze risk mappings and exploitability ratings</span>
                  </button>
                </div>
              </div>
            )}

            {messages.map((msg, idx) => {
              const isAi = msg.sender === 'ai';
              return (
                <div key={idx} className={`flex gap-4 ${isAi ? '' : 'justify-end'}`}>
                  {isAi && (
                    <div className="w-8 h-8 rounded-full bg-primary/20 border border-primary/30 flex-shrink-0 flex items-center justify-center mt-1">
                      <span className="material-symbols-outlined text-[18px] text-primary">robot_2</span>
                    </div>
                  )}

                  <div className={`flex-1 space-y-4 max-w-[80%] ${isAi ? '' : 'bg-surface-container-high border border-outline-variant rounded-2xl rounded-tr-sm px-5 py-3 ml-auto flex-initial'}`}>
                    {msg.isFallback && (
                      <div className="px-3 py-1 rounded bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs font-mono mb-2 inline-block">
                        Offline Fallback Advisory
                      </div>
                    )}
                    <div className="text-on-surface leading-relaxed text-[15px] whitespace-pre-wrap">
                      {msg.text}
                    </div>

                    {msg.codeBlock && (
                      <div className="rounded-lg overflow-hidden border border-[#1F242D] mt-3">
                        <div className="bg-surface-container-low px-4 py-2 border-b border-[#1F242D] flex justify-between items-center text-on-surface-variant text-xs">
                          <span>{msg.codeBlock.file}</span>
                          <button
                            onClick={() => alert('Code copied to clipboard!')}
                            className="hover:text-primary cursor-pointer bg-transparent border-none text-on-surface-variant"
                          >
                            <span className="material-symbols-outlined text-[16px]">content_copy</span>
                          </button>
                        </div>
                        <pre className="p-4 text-primary font-mono text-xs overflow-x-auto bg-[#0b0e14]">
                          <code>{msg.codeBlock.code}</code>
                        </pre>
                      </div>
                    )}

                    {isAi && (
                      <div className="flex gap-2 pt-2 text-xs font-label-mono">
                        <button
                          onClick={() => alert('Copy Patch logic')}
                          className="flex items-center gap-1.5 px-3 py-1.5 bg-surface-container border border-outline-variant rounded-full hover:bg-surface-container-high transition-colors text-on-surface-variant hover:text-on-surface cursor-pointer"
                        >
                          <span className="material-symbols-outlined text-[14px]">content_copy</span> Copy Patch
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}

            {isTyping && (
              <div className="flex gap-4 opacity-70">
                <div className="w-8 h-8 rounded-full bg-primary/20 border border-primary/30 flex-shrink-0 flex items-center justify-center mt-1">
                  <span className="material-symbols-outlined text-[18px] text-primary animate-pulse">robot_2</span>
                </div>
                <div className="flex-1 flex items-center">
                  <span className="text-on-surface-variant text-sm italic font-mono">Kyptic Copilot is analyzing findings...</span>
                </div>
              </div>
            )}

            <div ref={chatEndRef} />
          </div>
        </div>

        {/* Input Area */}
        <div className="absolute bottom-0 left-0 right-0 p-4 bg-gradient-to-t from-background via-background/90 to-transparent pt-12 shrink-0">
          <div className="max-w-4xl mx-auto">
            <div className="relative bg-surface-container/60 backdrop-blur-xl border border-outline-variant rounded-2xl shadow-[0_-10px_40px_rgba(0,0,0,0.5)] overflow-hidden focus-within:border-primary/50 transition-colors duration-300">
              <textarea
                className="w-full bg-transparent text-on-surface placeholder:text-on-surface-variant/50 border-none focus:ring-0 resize-none py-4 pl-4 pr-12 min-h-[60px] max-h-[200px] outline-none text-[15px]"
                placeholder="Ask Kyptic AI anything about your application's security..."
                rows={1}
                value={inputVal}
                onChange={(e) => setInputVal(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    handleSend();
                  }
                }}
              />
              <div className="flex items-center justify-between px-4 py-3 bg-surface-container-high/50 border-t border-outline-variant/50">
                <div className="flex gap-2">
                  <button
                    onClick={() => handleSuggestClick('Explain this vulnerability details')}
                    className="p-2 text-on-surface-variant hover:text-primary hover:bg-surface-variant rounded-lg transition-colors flex items-center gap-2 group cursor-pointer bg-transparent border-none"
                    title="Attach Context"
                  >
                    <span className="material-symbols-outlined text-[20px]">code</span>
                    <span className="text-xs font-label-mono opacity-0 group-hover:opacity-100 w-0 group-hover:w-auto overflow-hidden transition-all duration-200 whitespace-nowrap">Attach Context</span>
                  </button>
                </div>

                <button
                  onClick={handleSend}
                  disabled={isTyping}
                  className="bg-primary text-on-primary px-4 py-1.5 rounded-lg font-label-mono text-label-mono hover:bg-primary-fixed transition-colors flex items-center gap-2 shadow-[0_0_15px_rgba(166,200,255,0.2)] border-none cursor-pointer font-bold disabled:opacity-50"
                >
                  <span>Send</span>
                  <span className="material-symbols-outlined filled text-[18px]">send_spark</span>
                </button>
              </div>
            </div>

            <div className="text-center mt-2">
              <span className="text-[10px] font-label-mono text-on-surface-variant/50 uppercase tracking-widest">
                AI Security Copilot operates under evidence-grounded trust models. Verify fixes before deployment.
              </span>
            </div>
          </div>
        </div>
      </section>

      {/* Right Sidebar: Security Context */}
      <aside className="w-80 flex-shrink-0 border-l border-outline-variant/30 bg-surface-container-lowest flex flex-col h-full hidden xl:flex">
        <div className="p-4 border-b border-outline-variant/30">
          <h2 className="font-label-mono text-label-mono text-on-surface-variant uppercase tracking-wider">Security Context</h2>
        </div>

        <div className="flex-grow overflow-y-auto p-4 space-y-6 select-none">
          <div className="bg-surface-container border border-outline-variant/30 rounded-xl p-4">
            <div className="flex items-start justify-between mb-2">
              <div className="flex items-center gap-2">
                <span className="material-symbols-outlined text-primary text-[20px]">security</span>
                <span className="font-medium text-on-surface">Target Finding Context</span>
              </div>
            </div>
            <div className="text-sm text-on-surface-variant mb-2">{focusTitle}</div>
          </div>

          <div>
            <h3 className="font-label-mono text-[11px] text-on-surface-variant mb-3 uppercase tracking-wider">Current Focus</h3>
            <div className="space-y-3">
              <div className="flex justify-between items-center text-sm">
                <span className="text-on-surface-variant">Vulnerability</span>
                <span className="text-on-surface font-semibold text-error truncate max-w-[140px]">{focusTitle}</span>
              </div>
              <div className="flex justify-between items-center text-sm">
                <span className="text-on-surface-variant">Location</span>
                <span className="text-on-surface font-code-sm text-xs bg-surface-variant px-2 py-1 rounded border border-outline-variant/30 truncate max-w-[150px]" title={focusLocation}>
                  {focusLocation}
                </span>
              </div>
              <div className="flex justify-between items-center text-sm">
                <span className="text-on-surface-variant">Severity / Score</span>
                <span className="text-on-surface font-medium">{focusScore}</span>
              </div>
            </div>
          </div>
        </div>
      </aside>
    </div>
  );
};

export default Copilot;
