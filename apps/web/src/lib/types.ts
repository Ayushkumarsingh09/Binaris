export type RiskLevel = "info" | "low" | "medium" | "high" | "critical";

export interface FileHashes {
  md5: string;
  sha1: string;
  sha256: string;
  sha3_256: string;
  blake3: string;
  imphash?: string | null;
  ssdeep?: string | null;
}

export interface BinaryIdentity {
  format: string;
  architecture: string;
  endianness: string;
  bits: number;
  os: string;
  is_dll: boolean;
  is_driver: boolean;
  is_shared_object: boolean;
  entry_point?: number | null;
  image_base?: number | null;
  compiler?: string | null;
  compiler_version?: string | null;
  language?: string | null;
  build_system?: string | null;
  framework?: string | null;
  packed: boolean;
  packer?: string | null;
  obfuscated: boolean;
  obfuscation: string[];
  encrypted_sections: string[];
  has_debug_symbols: boolean;
  has_signature: boolean;
}

export interface FunctionAnalysis {
  id: string;
  address: number;
  size: number;
  name: string;
  suggested_name?: string | null;
  description?: string | null;
  purpose?: string | null;
  complexity: number;
  possible_crypto: boolean;
  possible_networking: boolean;
  possible_anti_debug: boolean;
  possible_persistence: boolean;
  possible_injection: boolean;
  assembly_preview?: string | null;
  pseudocode_summary?: string | null;
  confidence: number;
  tags: string[];
}

export interface ImportEntry {
  module: string;
  symbol: string;
  risk: RiskLevel;
  tags: string[];
}

export interface ExtractedString {
  value: string;
  offset: number;
  encoding: string;
  category: string;
  score: number;
}

export interface SecurityFinding {
  id: string;
  title: string;
  category: string;
  severity: RiskLevel;
  confidence: number;
  description: string;
  location?: string | null;
}

export interface MalwareClassification {
  family: string;
  confidence: number;
  malware_probability: number;
  reasoning: string;
  suspicious_apis: string[];
  behaviors: string[];
}

export interface GraphPayload {
  nodes: { id: string; label: string; kind: string; address?: number | null }[];
  edges: { id: string; source: string; target: string; kind: string; label?: string | null }[];
}

export interface AnalysisReport {
  id: string;
  file_id: string;
  project_id: string;
  stage: string;
  progress: number;
  filename: string;
  size_bytes: number;
  hashes: FileHashes;
  identity: BinaryIdentity;
  sections: {
    name: string;
    virtual_address: number;
    raw_size: number;
    entropy: number;
    permissions: string;
  }[];
  imports: ImportEntry[];
  exports: { symbol: string; address: number }[];
  strings: ExtractedString[];
  network: { kind: string; value: string; suspicious: boolean }[];
  crypto: { algorithm: string; category: string; strength: string; confidence: number }[];
  packers: { name: string; confidence: number }[];
  functions: FunctionAnalysis[];
  security: SecurityFinding[];
  malware: MalwareClassification;
  call_graph: GraphPayload;
  cfg_summary: GraphPayload;
  import_graph: GraphPayload;
  dfg?: GraphPayload;
  memory_graph?: GraphPayload;
  network_graph?: GraphPayload;
  network_intel?: unknown;
  decomp_backends?: unknown;
  language_structures?: unknown;
  executive_summary: string;
  technical_summary: string;
  iocs: string[];
  created_at: string;
  completed_at?: string | null;
}

export interface Project {
  id: string;
  org_id: string;
  name: string;
  description?: string | null;
}

export interface AuthResponse {
  token: string;
  user: { id: string; email: string; name: string };
  org_id: string;
  role: string;
}

export interface ChatResponse {
  session_id: string;
  provider: string;
  message: {
    id: string;
    role: string;
    content: string;
    citations: unknown[];
  };
}
