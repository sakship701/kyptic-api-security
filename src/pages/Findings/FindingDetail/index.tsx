import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import GlassPanel from '../../../components/ui/GlassPanel';
import { fetchFinding, updateFindingStatus } from '../../../api/findings';

interface DetailData {
  title: string;
  vulnId: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  cvss: number;
  confidence: number;
  status: 'Open' | 'Resolved' | 'False Positive';
  owasp: string;
  cwe: string;
  remediationTime: string;
  impact: string;
  exploitability: string;
  endpoint: string;
  file: string;
  description: string;
  rootCause: string;
  vulnerableCode: string;
  correctCode: string;
  startLine: number;
  highlightedLines: number[];
  httpEvidence: string;
  pocExploit: string;
  resolutionComment?: string | null;
  resolvedAt?: string | null;
  source?: string;
  sourceLabel?: string;
  projectId?: number;
  endpointPath?: string | null;
}

export const FindingDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [activeTab, setActiveTab] = useState<'Description' | 'HTTP' | 'PoC'>('Description');
  const [patchGenerated, setPatchGenerated] = useState(false);
  const [generatingPatch, setGeneratingPatch] = useState(false);
  const [apiFinding, setApiFinding] = useState<DetailData | null>(null);
  const [loading, setLoading] = useState(Boolean(id && /^\d+$/.test(id)));
  const [loadError, setLoadError] = useState<string | null>(null);
  
  // Custom status state & Triage controls
  const [statusState, setStatusState] = useState<'Open' | 'Resolved' | 'False Positive'>('Open');
  const [statusInitialized, setStatusInitialized] = useState(false);
  const [isTriageModalOpen, setIsTriageModalOpen] = useState(false);
  const [targetTriageStatus, setTargetTriageStatus] = useState<'resolved' | 'false_positive' | 'open'>('resolved');
  const [triageComment, setTriageComment] = useState('');
  const [triageSubmitting, setTriageSubmitting] = useState(false);

  // Findings detailed database mapping
  const detailsDb: Record<string, DetailData> = {
    'finding-1': {
      vulnId: 'Vuln-4921',
      title: 'SQL Injection (Blind)',
      severity: 'Critical',
      cvss: 9.8,
      confidence: 99,
      status: 'Open',
      owasp: 'A03:2021-Injection',
      cwe: 'CWE-89',
      remediationTime: '45 Mins',
      impact: 'High',
      exploitability: 'Easy',
      endpoint: 'POST /api/v2/users/query',
      file: 'controllers/authController.js',
      description: 'The authentication module fails to properly sanitize user input in the username field before constructing a SQL query. This allows an attacker to inject arbitrary SQL commands, potentially bypassing authentication entirely or extracting sensitive data from the user database.',
      rootCause: 'String concatenation is used to build the SQL query dynamically instead of utilizing parameterized queries or an ORM that handles escaping automatically.',
      vulnerableCode: `40 |   const { username, password } = req.body;
41 |
42 |   const query = \`SELECT * FROM users WHERE username = '\${username}' AND password = '\${password}'\`;
43 |
44 |   db.query(query, (err, results) => {
45 |     if (err) return res.status(500).send("Database error");`,
      correctCode: `40 |   const { username, password } = req.body;
41 |
42 |   const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
43 |
44 |   db.query(query, [username, password], (err, results) => {
45 |     if (err) return res.status(500).send("Database error");`,
      startLine: 40,
      highlightedLines: [42],
      httpEvidence: `POST /api/v2/users/query HTTP/1.1
Host: api.sentinel.com
Content-Type: application/json

{
  "username": "admin' OR '1'='1",
  "password": "randompassword"
}

HTTP/1.1 200 OK
Content-Type: application/json
{
  "status": "authenticated",
  "user": { "id": 1, "username": "admin" }
}`,
      pocExploit: `curl -X POST https://api.sentinel.com/v2/users/query \\
  -H "Content-Type: application/json" \\
  -d '{"username": "admin\\x27 OR \\x271\\x27=\\x271", "password": "any"}'`
    },
    'finding-2': {
      vulnId: 'Vuln-1082',
      title: 'Remote Code Execution via Deserialization',
      severity: 'Critical',
      cvss: 10.0,
      confidence: 95,
      status: 'Open',
      owasp: 'A08:2021-Software and Data Integrity Failures',
      cwe: 'CWE-502',
      remediationTime: '1.5 Hours',
      impact: 'Critical',
      exploitability: 'Moderate',
      endpoint: 'POST /api/v1/parser/import',
      file: 'core/utils/DataParser.java',
      description: 'The import feature utilizes unsafe default ObjectInputStream deserialization on client-provided byte arrays, allowing remote code execution if parsed blocks contain payload gadgets.',
      rootCause: 'ObjectInputStream is instantiated and readObject() invoked directly without blacklists or white-listed target class matching definitions.',
      vulnerableCode: `50 |   public Object parseData(byte[] serializedBytes) throws Exception {
51 |     ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serializedBytes));
52 |     return ois.readObject(); // Unsafe deserialization of stream
53 |   }`,
      correctCode: `50 |   public Object parseData(byte[] serializedBytes) throws Exception {
51 |     // Use a safe deserializer or JSON mapper with class type checks
52 |     ObjectMapper mapper = new ObjectMapper();
53 |     return mapper.readValue(serializedBytes, SecureData.class);
54 |   }`,
      startLine: 50,
      highlightedLines: [52],
      httpEvidence: `POST /api/v1/parser/import HTTP/1.1
Host: api.sentinel.com
Content-Type: application/octet-stream

[Raw Hex Payload: AC ED 00 05 73 72 00 11 6A 61 76 61 2E 75 74 69 6C 2E 48 61 73 68 4D 61 70 ...]

HTTP/1.1 500 Internal Server Error
[Exploit Callback Detected]`,
      pocExploit: `# Generate ysoserial gadget payload and transmit
ysoserial CommonsCollections6 "ping collaborator.com" > payload.bin
curl -X POST https://api.sentinel.com/v1/parser/import --data-binary @payload.bin`
    },
    'finding-3': {
      vulnId: 'Vuln-3829',
      title: 'Broken Access Control (IDOR)',
      severity: 'High',
      cvss: 7.5,
      confidence: 88,
      status: 'Open',
      owasp: 'A01:2021-Broken Access Control',
      cwe: 'CWE-284',
      remediationTime: '30 Mins',
      impact: 'High',
      exploitability: 'Easy',
      endpoint: 'GET /api/v1/billing/{id}',
      file: 'api.sentinel.com/v1/billing',
      description: 'The billing route does not verify if the requesting user owns the invoice matching the provided URL parameter id, revealing arbitrary invoices to authenticated users.',
      rootCause: 'Invoices are queried only by document identifier ID without cross-referencing user context variables in the database lookup.',
      vulnerableCode: `12 |   const invoiceId = req.params.id;
13 |   const invoice = await Invoice.findById(invoiceId);
14 |   return res.json(invoice); // No ownership check`,
      correctCode: `12 |   const invoiceId = req.params.id;
13 |   const invoice = await Invoice.findOne({ _id: invoiceId, userId: req.user.id });
14 |   if (!invoice) return res.status(403).send("Unauthorized Access");
15 |   return res.json(invoice);`,
      startLine: 12,
      highlightedLines: [14],
      httpEvidence: `GET /api/v1/billing/9982 HTTP/1.1
Authorization: Bearer <Attacker_Token>

HTTP/1.1 200 OK
{
  "id": 9982,
  "userId": 4202, /* Different User ID */
  "amount": 25000.00
}`,
      pocExploit: `curl -H "Authorization: Bearer <Attacker_Token>" \\
  https://api.sentinel.com/v1/billing/9982`
    },
    'finding-4': {
      vulnId: 'Vuln-8910',
      title: 'Hardcoded AWS Access Key',
      severity: 'High',
      cvss: 7.2,
      confidence: 100,
      status: 'False Positive',
      owasp: 'A07:2021-Identification and Authentication Failures',
      cwe: 'CWE-798',
      remediationTime: '15 Mins',
      impact: 'High',
      exploitability: 'Easy',
      endpoint: 'config/deployment.yaml',
      file: 'config/deployment.yaml',
      description: 'Hardcoded AWS Access Key IDs and Secrets are embedded within the deployment configuration, exposing account authorization parameters to read repository users.',
      rootCause: 'Credentials are hardcoded in plaintext rather than referencing environment variable definitions or vaults.',
      vulnerableCode: `15 |   AWS_ACCESS_KEY_ID: "AKIAIOSFODNN7EXAMPLE"
16 |   AWS_SECRET_ACCESS_KEY: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
      correctCode: `15 |   AWS_ACCESS_KEY_ID: "\${AWS_ACCESS_KEY_ID}"
16 |   AWS_SECRET_ACCESS_KEY: "\${AWS_SECRET_ACCESS_KEY}"`,
      startLine: 15,
      highlightedLines: [15, 16],
      httpEvidence: `Static secret detection match in repository config:
Matched Pattern: AKIA[0-9A-Z]{16}
File: config/deployment.yaml`,
      pocExploit: `# Utilize awscli to confirm key is active
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws sts get-caller-identity`
    },
    'finding-5': {
      vulnId: 'Vuln-9982',
      title: 'JWT Misconfiguration (Weak Algorithm)',
      severity: 'Medium',
      cvss: 5.4,
      confidence: 82,
      status: 'Resolved',
      owasp: 'A02:2021-Cryptographic Failures',
      cwe: 'CWE-327',
      remediationTime: '15 Mins',
      impact: 'Medium',
      exploitability: 'Easy',
      endpoint: 'auth/TokenService.js',
      file: 'auth/TokenService.js',
      description: 'The authentication service signs JSON Web Tokens using the none algorithm value, allowing clients to forge valid authorization parameters.',
      rootCause: 'The library configuration accepts none values as a valid cryptographic algorithm check.',
      vulnerableCode: `21 |   const token = jwt.sign(payload, secret, { algorithm: 'none' });`,
      correctCode: `21 |   const token = jwt.sign(payload, secret, { algorithm: 'HS256' });`,
      startLine: 21,
      highlightedLines: [21],
      httpEvidence: `POST /api/v1/auth/session HTTP/1.1
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.

HTTP/1.1 200 OK
{
  "role": "admin"
}`,
      pocExploit: `# Craft base64 header indicating algorithm "none"
# Header: {"alg":"none","typ":"JWT"} -> eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
# Payload: {"user":"admin"} -> eyJ1c2VyIjoiYWRtaW4ifQ
curl -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ." \\
  https://api.sentinel.com/v1/dashboard`
    }
  };

  const legacyFinding = id ? detailsDb[id] : null;

  useEffect(() => {
    if (!id || !/^\d+$/.test(id)) {
      return;
    }
    setLoading(true);
    void fetchFinding(id)
      .then((finding) => {
        const severity = finding.severity === 'critical' ? 'Critical' : finding.severity === 'high' ? 'High' : finding.severity === 'medium' ? 'Medium' : 'Low';
        const status = finding.status === 'open' ? 'Open' : finding.status === 'resolved' ? 'Resolved' : 'False Positive';
        const scannerInfo = finding.scanner_name ? ` (Detected by ${finding.scanner_name}${finding.scanner_version ? ' v' + finding.scanner_version : ''})` : '';
        let sourceLabel = 'SAST';
        if (finding.source === 'api_security') sourceLabel = 'API SECURITY';
        else if (finding.source === 'dast') sourceLabel = 'DAST ACTIVE PROBE';
        else if (finding.source === 'secrets') sourceLabel = 'SECRETS';
        else if (finding.source === 'sca') sourceLabel = 'SCA';
        else if (finding.source === 'sast') sourceLabel = 'SAST';
        else sourceLabel = (finding.source || 'SAST').toUpperCase();

        setApiFinding({
          vulnId: finding.rule_id ? finding.rule_id : `Finding-${finding.id}`,
          title: finding.title,
          severity,
          cvss: finding.cvss ?? 0,
          confidence: 100,
          status,
          owasp: finding.source === 'sca' ? 'Dependency Vulnerability' : (finding.owasp || finding.category),
          cwe: finding.cwe || (finding.source === 'sca' ? (finding.rule_id || 'SCA-VULN') : 'CWE-000'),
          remediationTime: '30 Mins',
          impact: severity === 'Critical' ? 'Critical' : severity === 'High' ? 'High' : 'Medium',
          exploitability: severity === 'Critical' ? 'Easy' : 'Moderate',
          endpoint: sourceLabel,
          file: finding.file_path,
          description: finding.description + scannerInfo,
          rootCause: finding.source === 'sca' 
            ? `Software Composition Analysis (SCA) detected an unsafe dependency declaration in ${finding.file_path}. Update the package to the fixed version recommended.`
            : finding.rule_id ? `Rule / Advisory ID: ${finding.rule_id}` : 'Security finding detected during scan.',
          vulnerableCode: finding.code_snippet || `${finding.file_path}:${finding.line_number ?? 'n/a'}\nNo source code snippet available.`,
          correctCode: finding.source === 'sca' 
            ? `Update dependency in ${finding.file_path} to secure version.`
            : 'Remediation details will be supplied by a future security engine.',
          startLine: finding.line_number ?? 1,
          highlightedLines: finding.line_number ? [finding.line_number] : [],
          httpEvidence: finding.code_snippet || 'No HTTP evidence available.',
          pocExploit: 'No exploit payload required.',
          resolutionComment: finding.resolution_comment,
          resolvedAt: finding.resolved_at,
          source: finding.source,
          sourceLabel,
          projectId: finding.project_id,
          endpointPath: (finding.source === 'api_security' || finding.source === 'dast') ? finding.file_path : null,
        });
        setStatusState(status);
        setStatusInitialized(true);
        setLoadError(null);
      })
      .catch((error: unknown) => setLoadError(error instanceof Error ? error.message : 'Unable to load finding.'))
      .finally(() => setLoading(false));
  }, [id]);

  const currentFinding = apiFinding || legacyFinding;
  const isSAST = currentFinding?.endpoint === 'SAST';

  useEffect(() => {
    if (currentFinding && !statusInitialized) {
      setStatusState(currentFinding.status);
      setStatusInitialized(true);
    }
  }, [currentFinding, statusInitialized]);

  if (loading) {
    return <div className="p-8 text-on-surface text-center font-mono">Loading finding...</div>;
  }

  if (!currentFinding || loadError) {
    return (
      <div className="p-8 text-on-surface text-center">
        <h2 className="text-xl font-bold text-error">{loadError || 'Vulnerability Not Found'}</h2>
        <button 
          onClick={() => navigate('/findings')}
          className="mt-4 px-4 py-2 bg-primary text-on-primary rounded cursor-pointer border-none"
        >
          Return to Findings
        </button>
      </div>
    );
  }

  const handleGeneratePatch = async () => {
    setGeneratingPatch(true);
    await new Promise((resolve) => setTimeout(resolve, 1500));
    setGeneratingPatch(false);
    setPatchGenerated(true);
  };

  const handleOpenTriageModal = (newStatus: 'resolved' | 'false_positive' | 'open') => {
    setTargetTriageStatus(newStatus);
    setTriageComment(currentFinding?.resolutionComment || '');
    if (newStatus === 'open') {
      void handleSubmitTriageStatus('open', '');
    } else {
      setIsTriageModalOpen(true);
    }
  };

  const handleSubmitTriageStatus = async (statusVal: 'resolved' | 'false_positive' | 'open', commentVal: string) => {
    if (!id || !/^\d+$/.test(id)) return;
    setTriageSubmitting(true);
    try {
      const updated = await updateFindingStatus(id, statusVal, commentVal);
      const newStatus = updated.status === 'open' ? 'Open' : updated.status === 'resolved' ? 'Resolved' : 'False Positive';
      setStatusState(newStatus);
      if (apiFinding) {
        setApiFinding({
          ...apiFinding,
          status: newStatus,
          resolutionComment: updated.resolution_comment,
          resolvedAt: updated.resolved_at,
        });
      }
      setIsTriageModalOpen(false);
    } catch (err: any) {
      alert(`Failed to update finding triage status: ${err.message || err}`);
    } finally {
      setTriageSubmitting(false);
    }
  };

  // Exploitability Bolt styling
  const isCritical = currentFinding.severity === 'Critical';
  const isHigh = currentFinding.severity === 'High';

  return (
    <div className="p-4 md:p-container-padding max-w-[1600px] mx-auto w-full flex flex-col gap-stack-lg pb-24 text-on-surface relative">
      
      {/* Triage Comment Modal */}
      {isTriageModalOpen && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-[#111620] border border-[#232a3b] rounded-xl p-6 max-w-md w-full shadow-2xl space-y-4">
            <h3 className="text-lg font-bold text-on-surface flex items-center gap-2">
              <span className="material-symbols-outlined text-primary">rate_review</span>
              {targetTriageStatus === 'resolved' ? 'Mark Finding as Resolved' : 'Mark Finding as False Positive'}
            </h3>
            <p className="text-xs text-on-surface-variant">
              Provide an optional triage note explaining the resolution decision or reason for suppression:
            </p>
            <textarea
              value={triageComment}
              onChange={(e) => setTriageComment(e.target.value)}
              maxLength={1000}
              placeholder="e.g. Verified input sanitization in middleware / Test environment key false alarm..."
              rows={4}
              className="w-full bg-[#090d14] border border-[#232a3b] rounded p-3 text-sm text-on-surface font-body focus:outline-none focus:border-primary"
            />
            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => setIsTriageModalOpen(false)}
                className="px-4 py-2 rounded bg-surface-container text-on-surface hover:bg-surface-container-high cursor-pointer border-none text-sm"
              >
                Cancel
              </button>
              <button
                onClick={() => handleSubmitTriageStatus(targetTriageStatus, triageComment)}
                disabled={triageSubmitting}
                className="px-4 py-2 rounded bg-primary text-on-primary font-bold hover:brightness-110 cursor-pointer border-none text-sm disabled:opacity-50 flex items-center gap-1"
              >
                {triageSubmitting && <span className="material-symbols-outlined animate-spin text-sm">sync</span>}
                Confirm Triage
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Header Section */}
      <header className="flex flex-col md:flex-row md:items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-on-surface-variant mb-2 text-xs">
            <button 
              onClick={() => navigate('/findings')}
              className="hover:text-primary transition-colors flex items-center gap-1 bg-transparent border-none cursor-pointer text-xs"
            >
              <span className="material-symbols-outlined text-sm">arrow_back</span> Vulnerabilities
            </button>
            <span>/</span>
            <span className="font-label-mono text-label-mono uppercase">{currentFinding.vulnId}</span>
          </div>
          <h1 className="font-display-lg-mobile md:font-display-lg text-display-lg-mobile md:text-display-lg font-bold text-on-surface mb-3 tracking-tight">
            {currentFinding.title}
          </h1>
          
          <div className="flex flex-wrap items-center gap-3">
            {currentFinding.sourceLabel && (
              <span className="px-2.5 py-1 rounded font-mono font-bold text-xs tracking-wider bg-primary/10 border border-primary/30 text-primary uppercase">
                {currentFinding.sourceLabel}
              </span>
            )}
            <span className={`px-2 py-1 rounded border text-sm font-medium flex items-center gap-1 ${
              isCritical ? 'bg-error-container/20 border-error-container text-error' : isHigh ? 'bg-[#ff9800]/10 border-[#ff9800]/30 text-[#ff9800]' : 'bg-[#ffeb3b]/10 border-[#ffeb3b]/30 text-[#ffeb3b]'
            }`}>
              <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>error</span>
              {currentFinding.severity}
            </span>

            {/* Validation status badge */}
            <span 
              className={`px-2.5 py-1 rounded border text-sm font-bold flex items-center gap-1 ${
                statusState === 'Open' 
                  ? 'bg-error/10 border-error/30 text-error' 
                  : statusState === 'False Positive' 
                    ? 'bg-[#ff9800]/10 border-[#ff9800]/30 text-[#ff9800]' 
                    : 'bg-[#4CAF50]/10 border-[#4CAF50]/30 text-[#4CAF50]'
              }`}
            >
              <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>
                {statusState === 'Resolved' ? 'check_circle' : statusState === 'False Positive' ? 'gpp_bad' : 'warning'}
              </span>
              {statusState}
            </span>
            
            <div className="h-4 w-px bg-outline-variant mx-1"></div>
            
            <span className="text-sm text-on-surface-variant flex items-center gap-1">
              <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>psychology</span>
              Confidence: {currentFinding.confidence}%
            </span>
            <span className="text-sm text-on-surface-variant flex items-center gap-1">
              <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>fact_check</span>
              Cross-Validated
            </span>
          </div>
        </div>

        {/* Triage Action Buttons */}
        <div className="flex flex-wrap gap-2">
          {(currentFinding.source === 'api_security' || currentFinding.source === 'dast' || currentFinding.endpointPath || (currentFinding.file && (currentFinding.file.startsWith('/') || currentFinding.file.includes('/api/')))) && (
            <button
              onClick={() => {
                const projId = currentFinding.projectId || '';
                const targetPath = currentFinding.endpointPath || currentFinding.file;
                navigate(`/api-security?projectId=${projId}&endpointPath=${encodeURIComponent(targetPath)}`);
              }}
              className="px-3 py-2 rounded-lg bg-gradient-to-r from-[#2E90FA] to-[#005fb0] text-white hover:brightness-110 transition-all font-semibold flex items-center gap-1 text-xs shadow-lg cursor-pointer border-none"
            >
              <span className="material-symbols-outlined text-[16px]">api</span>
              View API Endpoint
            </button>
          )}

          {statusState === 'Open' ? (
            <>
              <button 
                onClick={() => handleOpenTriageModal('resolved')}
                className="px-3 py-2 rounded-lg bg-[#4CAF50]/20 text-[#4CAF50] border border-[#4CAF50]/40 hover:bg-[#4CAF50]/30 transition-all font-semibold flex items-center gap-1 text-xs cursor-pointer"
              >
                <span className="material-symbols-outlined text-[16px]">check_circle</span>
                Mark Resolved
              </button>
              <button 
                onClick={() => handleOpenTriageModal('false_positive')}
                className="px-3 py-2 rounded-lg bg-[#ff9800]/20 text-[#ff9800] border border-[#ff9800]/40 hover:bg-[#ff9800]/30 transition-all font-semibold flex items-center gap-1 text-xs cursor-pointer"
              >
                <span className="material-symbols-outlined text-[16px]">gpp_bad</span>
                Mark False Positive
              </button>
            </>
          ) : (
            <button 
              onClick={() => handleOpenTriageModal('open')}
              className="px-3 py-2 rounded-lg bg-surface-container text-on-surface border border-outline-variant hover:bg-surface-container-high transition-all font-semibold flex items-center gap-1 text-xs cursor-pointer"
            >
              <span className="material-symbols-outlined text-[16px]">lock_reset</span>
              Reopen Finding
            </button>
          )}

          <button 
            onClick={handleGeneratePatch}
            className="px-3 py-2 rounded-lg bg-primary-container text-on-primary-container hover:brightness-110 transition-all font-semibold flex items-center gap-1 text-xs shadow-lg shadow-primary-container/20 cursor-pointer border-none"
          >
            <span className="material-symbols-outlined text-[16px]">build</span>
            Fix Vulnerability
          </button>
        </div>
      </header>

      {/* Top Summary Row */}
      <section className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-gutter">
        
        {/* CVSS Score */}
        <GlassPanel className="p-5 rounded-xl flex items-center justify-between">
          <div>
            <p className="text-sm text-on-surface-variant mb-1 font-medium">CVSS v3.1 Score</p>
            <div className="flex items-baseline gap-2">
              <span className={`text-4xl font-bold ${isCritical ? 'text-error' : 'text-[#ff9800]'}`}>
                {currentFinding.cvss}
              </span>
              <span className={`text-sm uppercase font-bold ${isCritical ? 'text-error' : 'text-[#ff9800]'}`}>
                {currentFinding.severity}
              </span>
            </div>
          </div>
          <div className={`w-16 h-16 rounded-full border-4 flex items-center justify-center relative ${isCritical ? 'border-error text-error' : 'border-[#ff9800] text-[#ff9800]'}`}>
            <span className="material-symbols-outlined absolute opacity-20" style={{ fontSize: '48px' }}>warning</span>
            <span className="font-bold relative z-10">{currentFinding.cvss}</span>
          </div>
        </GlassPanel>

        {/* Impact & Exploitability */}
        <GlassPanel className="p-5 rounded-xl flex flex-col justify-center gap-3">
          <div className="flex justify-between items-center">
            <span className="text-sm text-on-surface-variant">Business Impact</span>
            <span className={`px-2 py-0.5 rounded text-xs font-medium border ${
              currentFinding.impact === 'Critical' || currentFinding.impact === 'High' ? 'bg-error-container/20 text-error border-error-container' : 'bg-surface-variant border-outline-variant'
            }`}>
              {currentFinding.impact}
            </span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-sm text-on-surface-variant">Exploitability</span>
            <span className="px-2 py-0.5 rounded text-xs font-medium bg-tertiary-container/20 text-tertiary border border-tertiary-container flex items-center gap-1">
              <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>bolt</span>
              {currentFinding.exploitability}
            </span>
          </div>
        </GlassPanel>

        {/* Affected Assets */}
        <GlassPanel className="p-5 rounded-xl flex flex-col justify-center gap-3 col-span-1 lg:col-span-2">
          <div className="flex gap-2 items-center">
            <span className="text-sm text-on-surface-variant w-24 shrink-0">Endpoint:</span>
            <span className="font-label-mono text-label-mono text-primary bg-primary/10 px-2 py-1 rounded truncate border border-primary/20 w-full" title={currentFinding.endpoint}>
              {currentFinding.endpoint}
            </span>
          </div>
          <div className="flex gap-2 items-center">
            <span className="text-sm text-on-surface-variant w-24 shrink-0">File:</span>
            <span className="font-label-mono text-label-mono text-on-surface bg-surface-container px-2 py-1 rounded truncate border border-[#1F242D] w-full" title={currentFinding.file}>
              {currentFinding.file}
            </span>
          </div>
        </GlassPanel>

      </section>

      {/* Main Grid Layout */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-gutter items-start">
        
        {/* Left Panel: Technical Evidence */}
        <div className="lg:col-span-7 flex flex-col gap-stack-md">
          <GlassPanel className="rounded-xl overflow-hidden">
            <div className="border-b border-[#1F242D] px-5 py-3 flex gap-6 bg-surface-container-low/50">
              <button 
                onClick={() => setActiveTab('Description')}
                className={`font-medium pb-3 -mb-3 px-1 transition-colors cursor-pointer bg-transparent border-none ${
                  activeTab === 'Description' ? 'text-primary border-b-2 border-primary' : 'text-on-surface-variant hover:text-on-surface'
                }`}
              >
                Description
              </button>
              {!isSAST && (
                <button 
                  onClick={() => setActiveTab('HTTP')}
                  className={`font-medium pb-3 -mb-3 px-1 transition-colors cursor-pointer bg-transparent border-none ${
                    activeTab === 'HTTP' ? 'text-primary border-b-2 border-primary' : 'text-on-surface-variant hover:text-on-surface'
                  }`}
                >
                  HTTP Evidence
                </button>
              )}
              {!isSAST && (
                <button 
                  onClick={() => setActiveTab('PoC')}
                  className={`font-medium pb-3 -mb-3 px-1 transition-colors cursor-pointer bg-transparent border-none ${
                    activeTab === 'PoC' ? 'text-primary border-b-2 border-primary' : 'text-on-surface-variant hover:text-on-surface'
                  }`}
                >
                  PoC Exploit
                </button>
              )}
            </div>

            <div className="p-5 space-y-6">
              
              {activeTab === 'Description' && (
                <>
                  {/* Tab 1 Description content */}
                  <div>
                    <h3 className="text-lg font-semibold text-on-surface mb-2">Technical Details</h3>
                    <p className="text-on-surface-variant text-sm leading-relaxed mb-4">
                      {currentFinding.description}
                    </p>
                    <h4 className="text-md font-semibold text-on-surface mt-4 mb-2">Root Cause</h4>
                    <p className="text-on-surface-variant text-sm leading-relaxed">
                      {currentFinding.rootCause}
                    </p>
                  </div>

                  {/* Code Snippet block */}
                  <div>
                    <h3 className="text-sm font-semibold text-on-surface mb-2 flex items-center gap-2">
                      <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>code</span> 
                      {patchGenerated ? 'Remediated Code (AI Patched)' : 'Vulnerable Code'}
                    </h3>
                    
                    <div className="code-block rounded-lg overflow-hidden font-code-sm text-code-sm">
                      <div className="bg-surface-container-low px-4 py-2 border-b border-[#1F242D] flex justify-between items-center text-on-surface-variant text-xs">
                        <span>{currentFinding.file}</span>
                        <button 
                          onClick={() => alert('Code copied to clipboard!')}
                          className="hover:text-primary cursor-pointer bg-transparent border-none"
                        >
                          <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>content_copy</span>
                        </button>
                      </div>
                      
                      <div className="p-4 text-on-surface-variant overflow-x-auto whitespace-pre font-mono text-xs leading-relaxed bg-[#0A0D12]">
                        {patchGenerated ? (
                          currentFinding.correctCode
                        ) : (
                          // Render lines with highlighting
                          currentFinding.vulnerableCode.split('\n').map((line, index) => {
                            const currentLineNum = currentFinding.startLine + index;
                            const isHighlighted = currentFinding.highlightedLines.includes(currentLineNum);
 
                            let lineContent = line;
                            const pipeIndex = line.indexOf('|');
                            if (pipeIndex !== -1) {
                              const leftPart = line.substring(0, pipeIndex).trim();
                              if (leftPart && !isNaN(Number(leftPart))) {
                                lineContent = line.substring(pipeIndex + 1);
                              }
                            }

                            return (
                              <div 
                                key={index} 
                                className={`-mx-4 px-4 ${isHighlighted ? 'bg-error-container/10 border-l-2 border-error text-on-surface' : ''}`}
                              >
                                <span className="text-outline select-none inline-block w-8 text-right pr-2 font-mono">
                                  {currentLineNum} |
                                </span>
                                <span>{lineContent}</span>
                              </div>
                            );
                          })
                        )}
                      </div>
                    </div>
                  </div>
                </>
              )}

              {activeTab === 'HTTP' && (
                <div>
                  <h3 className="text-lg font-semibold text-on-surface mb-2">HTTP Request / Response</h3>
                  <div className="bg-[#050608] rounded-lg border border-[#1a1f26] p-4 font-mono text-[12px] text-primary/80 overflow-x-auto whitespace-pre leading-relaxed">
                    {currentFinding.httpEvidence}
                  </div>
                </div>
              )}

              {activeTab === 'PoC' && (
                <div>
                  <h3 className="text-lg font-semibold text-on-surface mb-2">Proof of Concept</h3>
                  <p className="text-sm text-on-surface-variant mb-4">
                    Send the following payload vector command block to reproduce the finding:
                  </p>
                  <div className="bg-[#050608] rounded-lg border border-[#1a1f26] p-4 font-mono text-[12px] text-tertiary overflow-x-auto whitespace-pre leading-relaxed">
                    {currentFinding.pocExploit}
                  </div>
                </div>
              )}

            </div>
          </GlassPanel>
        </div>

        {/* Right Panel: Validation Timeline & AI Copilot */}
        <div className="lg:col-span-5 flex flex-col gap-stack-md">
          
          {/* AI Security Copilot Panel */}
          <GlassPanel className="rounded-xl overflow-hidden relative border-primary/30 shadow-[0_0_30px_rgba(49,146,252,0.1)]">
            <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-primary-container to-tertiary-container shimmer"></div>
            <div className="p-5">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 rounded-lg bg-primary-container/20 border border-primary/30 flex items-center justify-center text-primary">
                  <span className="material-symbols-outlined">smart_toy</span>
                </div>
                <div>
                  <h2 className="text-lg font-bold text-on-surface">AI Security Copilot</h2>
                  <p className="text-xs text-on-surface-variant">Automated Analysis & Remediation</p>
                </div>
              </div>

              <div className="bg-surface-container-low rounded-lg p-4 mb-5 border border-[#1F242D] relative">
                {patchGenerated ? (
                  <p className="text-sm text-on-surface leading-relaxed">
                    <span className="text-[#10b981] font-bold flex items-center gap-1 mb-2">
                      <span className="material-symbols-outlined text-sm">check_circle</span> Patch generated successfully!
                    </span>
                    I have rewritten the logic in <code className="bg-[#0A0D12] px-1 rounded text-primary">{currentFinding.file}</code> to use safe query parameterization, neutralizing injection vectors.
                  </p>
                ) : generatingPatch ? (
                  <div className="py-4 flex flex-col items-center justify-center gap-2">
                    <span className="material-symbols-outlined animate-spin text-primary text-2xl">sync</span>
                    <span className="text-sm text-primary font-medium font-label-mono">Synthesizing patch file...</span>
                  </div>
                ) : (
                  <p className="text-sm text-on-surface leading-relaxed">
                    I have analyzed this vulnerability. This is a classic <strong>{currentFinding.cwe}</strong>.
                    <br /><br />
                    I can generate a secure patch using parameterized queries for the <code className="bg-[#0A0D12] px-1 rounded text-primary">{currentFinding.file}</code> file.
                  </p>
                )}
              </div>

              <div className="flex flex-col gap-3">
                {!patchGenerated && (
                  <button 
                    onClick={handleGeneratePatch}
                    disabled={generatingPatch}
                    className="w-full py-2.5 rounded-lg bg-primary-container text-on-primary-container font-semibold hover:brightness-110 transition-all flex items-center justify-center gap-2 shadow-lg shadow-primary-container/20 cursor-pointer border-none disabled:opacity-50"
                  >
                    <span className="material-symbols-outlined text-[18px]">auto_fix_high</span> 
                    {generatingPatch ? 'Generating...' : 'Generate Secure Patch'}
                  </button>
                )}
                
                <button 
                  onClick={() => navigate('/copilot', { state: { finding: currentFinding } })}
                  className="w-full py-2.5 rounded-lg border border-outline-variant text-on-surface hover:bg-surface-container-high transition-colors font-medium flex items-center justify-center gap-2 cursor-pointer bg-transparent"
                >
                  <span className="material-symbols-outlined text-[18px]">chat</span> 
                  Explain Attack Scenario
                </button>
              </div>

              <div className="mt-6 pt-5 border-t border-[#1F242D] grid grid-cols-2 gap-4">
                <div>
                  <p className="text-xs text-on-surface-variant mb-1">OWASP Category</p>
                  <p className="text-sm font-medium text-on-surface">{currentFinding.owasp}</p>
                </div>
                <div>
                  <p className="text-xs text-on-surface-variant mb-1">CWE ID</p>
                  <a 
                    className="text-sm font-medium text-primary hover:underline flex items-center gap-1"
                    href={`https://cwe.mitre.org/data/definitions/${currentFinding.cwe.split('-')[1]}.html`}
                    target="_blank" 
                    rel="noopener noreferrer"
                  >
                    {currentFinding.cwe} 
                    <span className="material-symbols-outlined text-xs">open_in_new</span>
                  </a>
                </div>
                <div>
                  <p className="text-xs text-on-surface-variant mb-1">Estimated Fix Time</p>
                  <p className="text-sm font-medium text-on-surface flex items-center gap-1">
                    <span className="material-symbols-outlined text-xs text-secondary">timer</span> 
                    {currentFinding.remediationTime}
                  </p>
                </div>
              </div>
            </div>
          </GlassPanel>

          {/* Timeline Panel */}
          <GlassPanel className="p-5 rounded-xl">
            <h3 className="text-sm font-semibold text-on-surface mb-4">Detection Timeline</h3>
            <div className="relative pl-6 space-y-6 before:absolute before:inset-0 before:ml-[11px] before:-translate-x-px before:h-full before:w-0.5 before:bg-gradient-to-b before:from-transparent before:via-outline-variant/50 before:to-transparent">
              <div className="relative flex items-center gap-4">
                <div className="absolute left-0 w-3 h-3 rounded-full bg-outline-variant -ml-[19px] border-2 border-background z-20"></div>
                <div>
                  <p className="text-xs text-on-surface-variant">14:22</p>
                  <p className="text-sm font-medium text-on-surface">White-Box Detection</p>
                </div>
              </div>
              <div className="relative flex items-center gap-4">
                <div className="absolute left-0 w-3 h-3 rounded-full bg-primary -ml-[19px] border-2 border-background z-20 shadow-[0_0_10px_rgba(166,200,255,0.5)]"></div>
                <div>
                  <p className="text-xs text-on-surface-variant">14:23</p>
                  <p className="text-sm font-medium text-on-surface">Black-Box Validation</p>
                </div>
              </div>
              <div className="relative flex items-center gap-4">
                <div className="absolute left-0 w-3 h-3 rounded-full bg-primary -ml-[19px] border-2 border-background z-20 shadow-[0_0_10px_rgba(166,200,255,0.5)]"></div>
                <div>
                  <p className="text-xs text-on-surface-variant">14:24</p>
                  <p className="text-sm font-medium text-on-surface">AI Cross-Validation</p>
                </div>
              </div>
              <div className="relative flex items-center gap-4">
                <div className="absolute left-0 w-3 h-3 rounded-full bg-tertiary -ml-[19px] border-2 border-background z-20 shadow-[0_0_10px_rgba(255,183,130,0.5)]"></div>
                <div>
                  <p className="text-xs text-on-surface-variant">14:25</p>
                  <p className="text-sm font-medium text-tertiary">Report Generated</p>
                </div>
              </div>
            </div>
          </GlassPanel>

        </div>

      </section>

    </div>
  );
};

export default FindingDetail;
