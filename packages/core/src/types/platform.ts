export interface ASTMetrics {
  functions: Array<{ name: string; file: string; startLine: number; endLine: number; isAsync: boolean; params: string[] }>;
  classes: Array<{ name: string; file: string; methods: string[] }>;
  imports: Array<{ source: string; specifiers: string[] }>;
  exports: string[];
}

export interface CallGraphNode {
  caller: string;
  callee: string;
  file: string;
  line: number;
}

export interface TaintResult {
  source: string;
  sink: string;
  path: string[];
  confidence: number;
}

export interface CryptoSignature {
  type: string;
  mode: string;
  keySource: string;
  ivSource: string;
  outputFormat: string;
  destination: string;
  file: string;
}

export interface ValidationReport {
  ruleName: string;
  secretValue: string;
  exposure: 'CONFIRMED_EXPOSURE' | 'POTENTIAL_ATTACK_SURFACE' | 'INFORMATIONAL';
  details: string;
}

export interface RuntimeTelemetryEvent {
  layer: 'FETCH_INTERCEPT' | 'XHR_INTERCEPT' | 'WEBSOCKET_INTERCEPT' | 'EVENTSOURCE_INTERCEPT' | 'BEACON_INTERCEPT' | 'CRYPTO_ENCRYPT' | 'CRYPTO_DECRYPT' | 'CRYPTO_KEY' | 'STORAGE_MUTATION' | 'INDEXEDDB_MUTATION' | 'DOM_TAINT' | 'FORMDATA_APPEND';
  meta: string;
  payload: string;
  timestamp: number;
}

export interface DOMArtifactMetrics {
  elementType: string;
  elementHtml: string;
  attributes: Record<string, string>;
}

export interface FrameworkArchitectureMap {
  detectedFramework: 'Angular' | 'React' | 'Vue' | 'Unknown';
  components: string[];
  routes: string[];
  interceptors: string[];
}

export type FindingType = 'Secret Leak' | 'Hardcoded Credential' | 'IDOR' | 'XSS' | 'RCE' | 'Auth Bypass' | 'Info Disclosure' | 'Misconfiguration';
export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
export type Verdict = 'CONFIRMED' | 'LIKELY' | 'POSSIBLE' | 'NOT REPRODUCED' | 'INSUFFICIENT EVIDENCE';

export interface SourceLocation {
  filePath: string;
  lineStart: number;
  lineEnd: number;
  columnStart?: number;
  columnEnd?: number;
}

export interface ContextData {
  enclosingFunction?: string;
  enclosingClass?: string;
  variableName?: string;
  moduleName?: string;
  frameworkContext?: string;
  surroundingCode: string[];
}

export interface DecodedData {
  encodingType: string;
  isNested: boolean;
  cleartext: string;
}

export interface Evidence {
  type: 'Static' | 'Runtime' | 'Network' | 'Authentication' | 'Authorization' | 'Taint' | 'DOM' | 'Decoded' | 'Error' | 'Log';
  description: string;
  content: string;
}

export interface Finding {
  id: string;
  type: FindingType;
  title: string;
  category: string;
  owasp: string;
  cwe: string;
  raw: string;
  location: SourceLocation;
  context: ContextData;
  decoded?: DecodedData;
  entropy?: number;
  confidence: number;
  severity: SeverityLevel;
  cvssVector: string;
  cvssScore: number;
  verdict: Verdict;
  evidence: Evidence[];
  metadata: Record<string, unknown>;
}

export interface ProviderSessionState {
  conversationHistory: Array<{ role: 'user' | 'assistant' | 'system'; content: string }>;
  sessionMemory: Record<string, string>;
  runtimeTelemetry: Array<{ provider: string; latency: number; timestamp: number }>;
  collectedFindings: Finding[];
  assessmentContext: { targetUrl: string; assessmentId: string };
}

export interface IEnterpriseEngine {
  name: string;
  enabled: boolean;
  process(findings: Finding[], rawScripts: Array<{ url: string; content: string }>): Promise<Finding[]>;
}
