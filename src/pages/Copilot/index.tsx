import React, { useState, useEffect, useRef } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';

interface ChatMessage {
  sender: 'user' | 'ai';
  text: string;
  codeBlock?: {
    file: string;
    code: string;
    lang: string;
  };
}

export const Copilot: React.FC = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const chatEndRef = useRef<HTMLDivElement>(null);

  // Retrieve vulnerability context passed from findings details page if any
  const passedFinding = location.state?.finding;

  // Initialize focus details
  const focusTitle = passedFinding?.title || 'SQL Injection';
  const focusLocation = passedFinding?.component || passedFinding?.file || '/api/v1/login';
  const focusScore = passedFinding?.cvss ? `${passedFinding.cvss} (${passedFinding.severity})` : '9.8 (Critical)';

  // Initialize messages list
  const [messages, setMessages] = useState<ChatMessage[]>(() => {
    if (passedFinding) {
      return [
        {
          sender: 'user',
          text: `Can you analyze the recent vulnerability "${passedFinding.title}" found in ${passedFinding.component || passedFinding.file || 'the application'} and suggest a fix?`
        },
        {
          sender: 'ai',
          text: `I've analyzed the ${passedFinding.title} vulnerability. This matches **${passedFinding.cwe}** (${passedFinding.owasp}). The issue is located in the component file: \`${passedFinding.file || 'authController.js'}\`.`,
          codeBlock: {
            file: passedFinding.file || 'authController.js',
            code: passedFinding.vulnerableCode || `const query = "SELECT * FROM users WHERE username = '" + req.body.username + "'";\ndb.query(query);`,
            lang: passedFinding.file?.endsWith('.java') ? 'java' : 'javascript'
          }
        }
      ];
    }
    return [
      {
        sender: 'user',
        text: "Can you analyze the recent SQL injection vulnerability found in the Banking API's login endpoint and suggest a fix?"
      },
      {
        sender: 'ai',
        text: "I've analyzed the SQL Injection vulnerability in the Banking API (`/api/v1/login`). The issue occurs because user input from the `username` field is being directly concatenated into the SQL query string in `authController.js`.",
        codeBlock: {
          file: 'controllers/authController.js',
          code: `const query = "SELECT * FROM users WHERE username = '" + req.body.username + "' AND password = '" + req.body.password + "'";\ndb.query(query, (err, results) => { ... });`,
          lang: 'javascript'
        }
      }
    ];
  });

  const [inputVal, setInputVal] = useState('');
  const [isTyping, setIsTyping] = useState(false);

  const handleSend = () => {
    if (!inputVal.trim() || isTyping) return;

    const userMsg = inputVal;
    setMessages(prev => [...prev, { sender: 'user', text: userMsg }]);
    setInputVal('');
    setIsTyping(true);

    // Dynamic mock response timing
    setTimeout(() => {
      let aiText = "I've processed your query. Let me know if you would like me to generate secure parameterized query remediations or explain the OWASP mitigation checklist for this vector.";
      
      if (userMsg.toLowerCase().includes('fix') || userMsg.toLowerCase().includes('patch')) {
        aiText = "Here is the recommended mitigation patch. Parameterized inputs separate queries from variables, completely neutralizing injection payload triggers:";
      } else if (userMsg.toLowerCase().includes('explain') || userMsg.toLowerCase().includes('what is')) {
        aiText = "This vulnerability exposes database command contexts. By passing raw user input strings directly into dynamic concatenation blocks, query structures are manipulated to override checks.";
      }

      setMessages(prev => [
        ...prev, 
        { 
          sender: 'ai', 
          text: aiText,
          ...(userMsg.toLowerCase().includes('fix') || userMsg.toLowerCase().includes('patch') ? {
            codeBlock: {
              file: passedFinding?.file || 'authController.js',
              code: passedFinding?.correctCode || `const query = "SELECT * FROM users WHERE username = ? AND password = ?";\ndb.query(query, [username, password]);`,
              lang: passedFinding?.file?.endsWith('.java') ? 'java' : 'javascript'
            }
          } : {})
        }
      ]);
      setIsTyping(false);
    }, 1500);
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
          {/* Pinned Investigations */}
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

          {/* Recent Analyses */}
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
                  onClick={() => handleSuggestClick('Review dependency CVE list')}
                  className="w-full flex items-center gap-3 px-2 py-2 rounded-md hover:bg-surface-variant text-on-surface-variant transition-colors group text-left cursor-pointer bg-transparent border-none"
                >
                  <span className="material-symbols-outlined text-[16px]">chat_bubble</span>
                  <span className="truncate text-sm group-hover:text-on-surface transition-colors">Dependency CVE Review</span>
                </button>
              </li>
              <li>
                <button 
                  onClick={() => handleSuggestClick('Show patch instructions for Log4j vulnerability')}
                  className="w-full flex items-center gap-3 px-2 py-2 rounded-md hover:bg-surface-variant text-on-surface-variant transition-colors group text-left cursor-pointer bg-transparent border-none"
                >
                  <span className="material-symbols-outlined text-[16px]">chat_bubble</span>
                  <span className="truncate text-sm group-hover:text-on-surface transition-colors">Patching Guide for Log4j</span>
                </button>
              </li>
            </ul>
          </div>
        </div>
      </aside>

      {/* Center Panel: AI Copilot conversation workspace */}
      <section className="flex-grow flex flex-col min-w-0 bg-[#06070A] relative overflow-hidden">
        
        {/* Chat Area */}
        <div className="flex-1 overflow-y-auto px-4 md:px-8 py-8 scroll-smooth h-full">
          <div className="max-w-4xl mx-auto space-y-8 pb-32">
            
            {/* Welcome / Empty State */}
            {messages.length === 0 && (
              <div className="text-center space-y-4 mb-12 mt-8">
                <div className="w-16 h-16 mx-auto bg-primary/10 rounded-full flex items-center justify-center border border-primary/20 shadow-[0_0_30px_rgba(166,200,255,0.1)]">
                  <span className="material-symbols-outlined text-3xl text-primary">robot_2</span>
                </div>
                <h1 className="font-headline-md text-headline-md text-on-background">Hello, Security Admin.</h1>
                <p className="text-on-surface-variant text-lg">How can I help secure your application today?</p>
                
                {/* Quick Actions Grid */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-8 text-left">
                  <button 
                    onClick={() => handleSuggestClick('Explain the vulnerability detail mechanism')}
                    className="bg-surface-container border border-outline-variant p-4 rounded-xl hover:border-primary/50 hover:bg-surface-container-high transition-all duration-200 group flex flex-col gap-3 relative overflow-hidden text-left cursor-pointer bg-transparent"
                  >
                    <div className="absolute inset-0 bg-gradient-to-br from-primary/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity"></div>
                    <span className="material-symbols-outlined text-primary">code_blocks</span>
                    <span className="font-medium text-on-surface">Explain Vulnerability</span>
                    <span className="text-sm text-on-surface-variant">Break down the mechanics of the target vulnerability</span>
                  </button>
                  <button 
                    onClick={() => handleSuggestClick('How do I fix it? Generate a secure patch.')}
                    className="bg-surface-container border border-outline-variant p-4 rounded-xl hover:border-primary/50 hover:bg-surface-container-high transition-all duration-200 group flex flex-col gap-3 relative overflow-hidden text-left cursor-pointer bg-transparent"
                  >
                    <div className="absolute inset-0 bg-gradient-to-br from-tertiary/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity"></div>
                    <span className="material-symbols-outlined text-tertiary">healing</span>
                    <span className="font-medium text-on-surface">Generate Secure Patch</span>
                    <span className="text-sm text-on-surface-variant">Create a parameterized query logic fix</span>
                  </button>
                  <button 
                    onClick={() => handleSuggestClick('Explain the CVSS score criteria')}
                    className="bg-surface-container border border-outline-variant p-4 rounded-xl hover:border-primary/50 hover:bg-surface-container-high transition-all duration-200 group flex flex-col gap-3 relative overflow-hidden text-left cursor-pointer bg-transparent"
                  >
                    <div className="absolute inset-0 bg-gradient-to-br from-error/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity"></div>
                    <span className="material-symbols-outlined text-error">sort_by_alpha</span>
                    <span className="font-medium text-on-surface">Explain CVSS Score</span>
                    <span className="text-sm text-on-surface-variant">Analyze risk mappings and exploitability ratings</span>
                  </button>
                </div>
              </div>
            )}

            {/* Conversation Log */}
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
                    <div className="text-on-surface leading-relaxed text-[15px]">
                      {msg.text}
                    </div>

                    {msg.codeBlock && (
                      <div className="rounded-lg overflow-hidden border border-[#1F242D] mt-3">
                        <div className="bg-surface-container-low px-4 py-2 border-b border-[#1F242D] flex justify-between items-center text-on-surface-variant text-xs">
                          <span>{msg.codeBlock.file}</span>
                          <button 
                            onClick={() => alert('Code copied!')}
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
                        <button 
                          onClick={() => alert('Jira Ticket created!')}
                          className="flex items-center gap-1.5 px-3 py-1.5 bg-surface-container border border-outline-variant rounded-full hover:bg-surface-container-high transition-colors text-on-surface-variant hover:text-on-surface cursor-pointer"
                        >
                          <span className="material-symbols-outlined text-[14px]">add_task</span> Create Ticket
                        </button>
                        
                        <div className="flex-1"></div>
                        
                        <button className="text-on-surface-variant hover:text-primary p-1 bg-transparent border-none cursor-pointer">
                          <span className="material-symbols-outlined text-[18px]">thumb_up</span>
                        </button>
                        <button className="text-on-surface-variant hover:text-error p-1 bg-transparent border-none cursor-pointer">
                          <span className="material-symbols-outlined text-[18px]">thumb_down</span>
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}

            {/* Typing indicator */}
            {isTyping && (
              <div className="flex gap-4 opacity-70">
                <div className="w-8 h-8 rounded-full bg-primary/20 border border-primary/30 flex-shrink-0 flex items-center justify-center mt-1">
                  <span className="material-symbols-outlined text-[18px] text-primary animate-pulse">robot_2</span>
                </div>
                <div className="flex-1 flex items-center">
                  <span className="text-on-surface-variant text-sm italic">Kyptic is analyzing...</span>
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
                    title="Attach Code"
                  >
                    <span className="material-symbols-outlined text-[20px]">code</span>
                    <span className="text-xs font-label-mono opacity-0 group-hover:opacity-100 w-0 group-hover:w-auto overflow-hidden transition-all duration-200 whitespace-nowrap">Attach Code</span>
                  </button>
                  <button 
                    onClick={() => handleSuggestClick('Correlate recent security scan results')}
                    className="p-2 text-on-surface-variant hover:text-primary hover:bg-surface-variant rounded-lg transition-colors flex items-center gap-2 group cursor-pointer bg-transparent border-none" 
                    title="Attach Scan"
                  >
                    <span className="material-symbols-outlined text-[20px]">document_scanner</span>
                    <span className="text-xs font-label-mono opacity-0 group-hover:opacity-100 w-0 group-hover:w-auto overflow-hidden transition-all duration-200 whitespace-nowrap">Attach Scan</span>
                  </button>
                </div>
                
                <button 
                  onClick={handleSend}
                  className="bg-primary text-on-primary px-4 py-1.5 rounded-lg font-label-mono text-label-mono hover:bg-primary-fixed transition-colors flex items-center gap-2 shadow-[0_0_15px_rgba(166,200,255,0.2)] border-none cursor-pointer font-bold"
                >
                  <span>Send</span>
                  <span className="material-symbols-outlined filled text-[18px]">send_spark</span>
                </button>
              </div>
            </div>
            
            <div className="text-center mt-2">
              <span className="text-[10px] font-label-mono text-on-surface-variant/50 uppercase tracking-widest">
                AI can make mistakes. Verify critical fixes.
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
          {/* Active Entity Card */}
          <div className="bg-surface-container border border-outline-variant/30 rounded-xl p-4">
            <div className="flex items-start justify-between mb-2">
              <div className="flex items-center gap-2">
                <span className="material-symbols-outlined text-primary text-[20px]">api</span>
                <span className="font-medium text-on-surface">Banking API</span>
              </div>
              <span className="px-2 py-0.5 rounded text-[10px] font-label-mono uppercase bg-error/10 text-error border border-error/20 font-bold">
                Critical
              </span>
            </div>
            <div className="text-sm text-on-surface-variant mb-4">Node.js / Express Architecture</div>
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-full border-4 border-error/30 flex items-center justify-center relative">
                <svg className="absolute inset-0 w-full h-full -rotate-90" viewBox="0 0 36 36">
                  <path 
                    className="text-error" 
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" 
                    fill="none" 
                    stroke="currentColor" 
                    strokeDasharray="68, 100" 
                    strokeWidth="4"
                  ></path>
                </svg>
                <span className="font-bold text-error text-sm">68</span>
              </div>
              <div>
                <div className="text-xs text-on-surface-variant font-label-mono">SECURITY SCORE</div>
                <div className="text-sm font-medium text-on-surface">Needs Attention</div>
              </div>
            </div>
          </div>

          {/* Current Focus */}
          <div>
            <h3 className="font-label-mono text-[11px] text-on-surface-variant mb-3 uppercase tracking-wider">Current Focus</h3>
            <div className="space-y-3">
              <div className="flex justify-between items-center text-sm">
                <span className="text-on-surface-variant">Vulnerability</span>
                <span className="text-on-surface font-semibold text-error">{focusTitle}</span>
              </div>
              <div className="flex justify-between items-center text-sm">
                <span className="text-on-surface-variant">Location</span>
                <span className="text-on-surface font-code-sm text-xs bg-surface-variant px-2 py-1 rounded border border-outline-variant/30 truncate max-w-[150px]" title={focusLocation}>
                  {focusLocation}
                </span>
              </div>
              <div className="flex justify-between items-center text-sm">
                <span className="text-on-surface-variant">CVSS Score</span>
                <span className="text-on-surface font-medium">{focusScore}</span>
              </div>
            </div>
          </div>

          {/* AI Knowledge Base */}
          <div>
            <h3 className="font-label-mono text-[11px] text-on-surface-variant mb-3 uppercase tracking-wider">Knowledge Sources</h3>
            <div className="space-y-2">
              <div className="flex items-center justify-between p-2 rounded-lg bg-surface-variant/50 border border-outline-variant/30">
                <div className="flex items-center gap-2">
                  <span className="material-symbols-outlined text-[16px] text-primary">database</span>
                  <span className="text-sm text-on-surface">RAG Index</span>
                </div>
                <span className="w-2 h-2 rounded-full bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.5)]"></span>
              </div>
              <div className="flex items-center justify-between p-2 rounded-lg bg-surface-variant/50 border border-outline-variant/30">
                <div className="flex items-center gap-2">
                  <span className="material-symbols-outlined text-[16px] text-tertiary">memory</span>
                  <span className="text-sm text-on-surface">Local LLM</span>
                </div>
                <span className="w-2 h-2 rounded-full bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.5)]"></span>
              </div>
            </div>
          </div>

          {/* Suggested Actions */}
          <div className="mt-8">
            <h3 className="font-label-mono text-[11px] text-on-surface-variant mb-3 uppercase tracking-wider">Suggested Actions</h3>
            <div className="space-y-2">
              <button 
                onClick={() => handleSuggestClick('Generate parameterized query secure patch for focus issue')}
                className="w-full flex items-center justify-between p-3 rounded-lg border border-primary/30 bg-primary/5 hover:bg-primary/10 text-primary transition-colors group cursor-pointer"
              >
                <span className="text-sm font-semibold">Generate Secure Patch</span>
                <span className="material-symbols-outlined text-[18px] group-hover:translate-x-1 transition-transform">arrow_forward</span>
              </button>
              <button 
                onClick={() => navigate('/risk-map')}
                className="w-full flex items-center justify-between p-3 rounded-lg border border-outline-variant bg-transparent hover:bg-surface-variant text-on-surface transition-colors group cursor-pointer"
              >
                <span className="text-sm font-semibold">View Risk Map</span>
                <span className="material-symbols-outlined text-[18px] group-hover:translate-x-1 transition-transform">account_tree</span>
              </button>
            </div>
          </div>
        </div>
      </aside>

    </div>
  );
};

export default Copilot;
