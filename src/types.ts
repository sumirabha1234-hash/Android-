export type VulnerabilitySeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface SecurityVulnerability {
  id: string;
  title: string;
  severity: VulnerabilitySeverity;
  category: 'manifest' | 'crypto' | 'network' | 'storage' | 'code' | 'permission' | 'secret';
  cwe?: string;
  masvsId?: string;
  description: string;
  impact: string;
  recommendation: string;
  location?: string;
  codeSnippet?: string;
  line?: number;
}

export interface AndroidPermission {
  name: string;
  shortName: string;
  protectionLevel: 'dangerous' | 'normal' | 'signature' | 'signatureOrSystem' | 'unknown';
  description: string;
  riskAssessment: string;
  isDangerous: boolean;
  category: 'Privacy' | 'Network' | 'Device' | 'Storage' | 'Hardware' | 'System' | 'Cost';
}

export interface ExtractedEndpoint {
  url: string;
  type: 'internal_api' | 'external_url' | 'ip_address' | 'cloud_bucket' | 'websocket' | 'deep_link';
  protocol: string;
  host?: string;
  path?: string;
  isInsecure: boolean;
  category: 'API / Backend' | 'Cloud Storage' | 'Analytics & Ads' | 'Auth Service' | 'CDN' | 'IP Host' | 'Custom Protocol';
  sourceFile?: string;
}

export interface SignatureDetails {
  schemeVersion: 'v1 (JAR)' | 'v2 (APK Signature)' | 'v3' | 'v1+v2+v3' | 'ELF Native Verification' | string;
  isValid: boolean;
  isSelfSigned: boolean;
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: string;
  validTo: string;
  algorithm: string;
  keySize: number;
  md5Fingerprint: string;
  sha1Fingerprint: string;
  sha256Fingerprint: string;
  warnings: string[];
}

export interface AndroidComponent {
  name: string;
  type: 'activity' | 'service' | 'receiver' | 'provider';
  exported: boolean;
  permission?: string;
  intentFilters: {
    actions: string[];
    categories: string[];
    dataSchemes?: string[];
  }[];
  isVulnerable: boolean;
  vulnerabilityReason?: string;
}

export interface SourceRecoveryStats {
  overallScore: number; // 0 to 100
  astRecovery: number; // 0 to 100
  typeInference: number; // 0 to 100
  controlFlowIntegrity: number; // 0 to 100
  symbolResolution: number; // 0 to 100
  deobfuscationFidelity: number; // 0 to 100
  resourceIdResolution: number; // 0 to 100
  reconstructedMethodsCount: number;
  totalMethodsCount: number;
  reconstructedClassesCount: number;
  totalClassesCount: number;
  recoveredVariablesCount: number;
  inlinedStringsCount: number;
  qualityGrade: 'PRISTINE_AST' | 'HIGH_FIDELITY' | 'SUBSTANTIAL' | 'PARTIAL' | 'LOW';
  appliedTechniques: string[];
}

export interface DecompiledFileItem {
  path: string;
  name: string;
  type: 'file' | 'directory';
  size?: number;
  language?: 'xml' | 'java' | 'smali' | 'json' | 'text' | 'binary' | 'kotlin' | 'c' | 'asm';
  content?: string;
  kotlinContent?: string;
  smaliContent?: string;
  deobfuscatedContent?: string;
  retrievalScore?: number; // 0 to 100%
  recoveryStats?: SourceRecoveryStats;
  children?: DecompiledFileItem[];
}

export interface HardcodedSecret {
  name: string;
  value: string;
  type: 'API Key' | 'AWS Secret' | 'Private Key' | 'JWT Token' | 'Firebase URL' | 'Database Password' | 'OAuth Client' | 'Hardcoded Encryption Key' | string;
  file: string;
  entropy: number;
  severity: VulnerabilitySeverity;
}

export type SandboxVerdict = 'CLEAN' | 'SUSPICIOUS_NETWORK' | 'DROPPER_DETECTED' | 'MALICIOUS_DOWNLOADER';

export interface InterceptedDownloadFile {
  id: string;
  url: string;
  destinationPath: string;
  fileName: string;
  fileSizeEstimate: string;
  mimeType: string;
  extension: string;
  sha256Estimate: string;
  downloadMethod: 'DownloadManager' | 'HttpURLConnection' | 'OkHttpClient' | 'DexClassLoader' | 'FileOutputStream' | 'WebViewDownload' | 'SocketStream';
  triggerComponent: string;
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  riskLabel: string;
  behaviorAnalysis: string;
  mitigation: string;
  isExecutedAfterDownload: boolean;
  isDynamicCodeLoading: boolean;
}

export interface SandboxNetworkTrace {
  id: string;
  timestamp: string;
  timeOffsetMs: number;
  protocol: 'HTTPS' | 'HTTP' | 'WSS' | 'TCP';
  method: 'GET' | 'POST' | 'CONNECT' | 'PUT' | 'HEAD';
  host: string;
  url: string;
  headers?: Record<string, string>;
  responseCode: number;
  responseStatus: string;
  contentType: string;
  bytesReceived: number;
  associatedFileDownload?: string;
  suspicionReasons: string[];
}

export interface SandboxLogEntry {
  id: string;
  timestamp: string;
  tag: 'AndroidRuntime' | 'DownloadManager' | 'ArtMethodHook' | 'VFS_Monitor' | 'NetFilter' | 'DexLoader' | 'SecuritySandbox' | 'EvasionDetector';
  level: 'INFO' | 'WARN' | 'ERROR' | 'DEBUG';
  message: string;
}

export interface DynamicSandboxResult {
  environment: {
    osVersion: string;
    deviceModel: string;
    runtime: string;
    securityLevel: string;
    macAddress: string;
    mockImei: string;
  };
  verdict: SandboxVerdict;
  verdictSummary: string;
  downloadedFiles: InterceptedDownloadFile[];
  networkTraces: SandboxNetworkTrace[];
  logs: SandboxLogEntry[];
  evasionTechniquesDetected: string[];
  dynamicCodeLoadingDetected: boolean;
  totalNetworkRequests: number;
  totalFilesDownloaded: number;
  executionDurationMs: number;
  simulationStatus: 'completed' | 'running' | 'idle';
}

export interface ApkAnalysisResult {
  fileName: string;
  fileSize: number;
  uploadTimestamp: number;
  md5: string;
  sha1: string;
  sha256: string;
  
  // Package Info
  packageName: string;
  versionName: string;
  versionCode: number;
  minSdkVersion: number;
  targetSdkVersion: number;
  compileSdkVersion?: number;
  appName?: string;
  appIcon?: string;
  
  // Security Scoring (0-100, 100 = safe)
  securityScore: number;
  securityRating: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  threatLevel: 'Safe' | 'Low Risk' | 'Medium Risk' | 'High Risk' | 'Critical';
  
  // Analysis Data
  rawManifestXml: string;
  formattedManifestXml: string;
  components: AndroidComponent[];
  permissions: AndroidPermission[];
  vulnerabilities: SecurityVulnerability[];
  endpoints: ExtractedEndpoint[];
  signature: SignatureDetails;
  secrets: HardcodedSecret[];
  nativeLibraries: string[];
  decompiledFiles: DecompiledFileItem[];
  
  // Isolated Fake Android Sandbox Simulation
  dynamicSandbox: DynamicSandboxResult;

  // 0-100% Decompile Source Code Retrieval Engine & Fidelity Metrics
  sourceCodeRecovery: SourceRecoveryStats;

  // Native Binary ELF Decompilation Results
  binaryAnalysis?: BinaryDecompileResult[];

  // High Level Stats
  stats: {
    totalFiles: number;
    totalDexFiles: number;
    totalClasses: number;
    totalMethods: number;
    totalStrings: number;
    criticalIssues: number;
    highIssues: number;
    mediumIssues: number;
    lowIssues: number;
    dangerousPermissionsCount: number;
    exportedComponentsCount: number;
    externalUrlsCount: number;
    apiEndpointsCount: number;
    downloadedFilesCount: number;
  };
}

export interface ElfHeaderInfo {
  magic: string;
  class: 'ELF32' | 'ELF64';
  data: 'Little Endian' | 'Big Endian';
  version: string;
  osAbi: string;
  type: 'Shared Object (.so)' | 'Executable (ELF)' | 'Relocatable (.o)' | 'Core';
  machine: 'AArch64 (ARM64)' | 'ARM (32-bit)' | 'x86_64 (AMD64)' | 'x86 (i386)' | 'MIPS' | 'RISC-V' | 'Unknown';
  entryPoint: string;
  programHeaderOffset: number;
  sectionHeaderOffset: number;
  flags: string;
  headerSize: number;
}

export interface BinaryMitigations {
  nx: boolean;
  pie: boolean;
  relro: 'Full RELRO' | 'Partial RELRO' | 'No RELRO';
  canary: boolean;
  fortify: boolean;
  stripped: boolean;
  rpath: boolean;
}

export interface ElfSection {
  name: string;
  type: string;
  flags: string;
  address: string;
  offset: number;
  size: number;
  entropy: number;
  description: string;
}

export interface BinarySymbol {
  name: string;
  demangledName?: string;
  type: 'FUNC' | 'OBJECT' | 'NOTYPE' | 'SECTION' | 'FILE';
  binding: 'GLOBAL' | 'LOCAL' | 'WEAK';
  visibility: 'DEFAULT' | 'HIDDEN' | 'PROTECTED';
  address: string;
  size: number;
  section: string;
  isJniExport: boolean;
  isImported: boolean;
  riskTag?: string;
}

export interface DisassembledInstruction {
  address: string;
  offset: number;
  bytes: string;
  mnemonic: string;
  operands: string;
  comment?: string;
  isBranch?: boolean;
  targetAddress?: string;
  isCall?: boolean;
  isJniCall?: boolean;
}

export interface DecompiledFunction {
  id: string;
  name: string;
  demangledName?: string;
  address: string;
  size: number;
  returnType: string;
  parameters: { name: string; type: string }[];
  isJniExport: boolean;
  assemblyInstructions: DisassembledInstruction[];
  cDecompiledCode: string;
  securityNotes: string[];
  complexity: number;
  cfgNodesCount: number;
}

export interface BinaryStringItem {
  offset: string;
  section: string;
  value: string;
  isSensitive: boolean;
  category?: 'URL' | 'Crypto Key' | 'System Command' | 'Path' | 'JNI Signature' | 'Log Tag' | 'General';
}

export interface BinaryDecompileResult {
  fileName: string;
  filePath: string;
  fileSize: number;
  architecture: string;
  sha256: string;
  md5: string;
  header: ElfHeaderInfo;
  mitigations: BinaryMitigations;
  sections: ElfSection[];
  symbols: BinarySymbol[];
  functions: DecompiledFunction[];
  strings: BinaryStringItem[];
  rawHexSnippet: string;
  decompilationScore: number; // 0-100%
  retrievalMetrics: {
    symbolRecoveryRate: number;
    cfgReconstructionRate: number;
    cCodeLiftingRate: number;
    stringCrossReferenceRate: number;
  };
  vulnerabilities: SecurityVulnerability[];
}

