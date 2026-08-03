use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::evidence::Evidence;
use crate::ids::*;
use crate::pipeline::PipelineStage;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryFormat {
    Pe,
    Elf,
    MachO,
    Apk,
    Aab,
    Jar,
    Msi,
    Firmware,
    Bootloader,
    KernelModule,
    Raw,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86,
    X64,
    Arm,
    Arm64,
    Mips,
    PowerPc,
    RiscV,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatingSystem {
    Windows,
    Linux,
    MacOs,
    Android,
    Ios,
    FreeBsd,
    Firmware,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub sha3_256: String,
    pub blake3: String,
    pub imphash: Option<String>,
    pub ssdeep: Option<String>,
    pub tlsh: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryIdentity {
    pub format: BinaryFormat,
    pub architecture: Architecture,
    pub endianness: String,
    pub bits: u8,
    pub os: OperatingSystem,
    pub is_dll: bool,
    pub is_driver: bool,
    pub is_shared_object: bool,
    pub entry_point: Option<u64>,
    pub image_base: Option<u64>,
    pub compiler: Option<String>,
    pub compiler_version: Option<String>,
    pub language: Option<String>,
    pub build_system: Option<String>,
    pub framework: Option<String>,
    pub linker: Option<String>,
    pub packed: bool,
    pub packer: Option<String>,
    pub obfuscated: bool,
    pub obfuscation: Vec<String>,
    pub encrypted_sections: Vec<String>,
    pub compressed: bool,
    pub has_debug_symbols: bool,
    pub has_signature: bool,
    pub mime: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_size: u64,
    pub entropy: f64,
    pub characteristics: Vec<String>,
    pub permissions: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportEntry {
    pub module: String,
    pub symbol: String,
    pub ordinal: Option<u16>,
    pub address: Option<u64>,
    pub risk: RiskLevel,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEntry {
    pub symbol: String,
    pub ordinal: Option<u16>,
    pub address: u64,
    pub forwarded: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedString {
    pub value: String,
    pub offset: u64,
    pub encoding: String,
    pub category: StringCategory,
    pub score: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StringCategory {
    Generic,
    Url,
    Domain,
    Ip,
    Email,
    Path,
    Registry,
    Mutex,
    Service,
    ApiKey,
    Credential,
    Jwt,
    Certificate,
    UserAgent,
    Command,
    Crypto,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIndicator {
    pub kind: NetworkKind,
    pub value: String,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub evidence: Vec<Evidence>,
    pub suspicious: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkKind {
    Url,
    Domain,
    Ip,
    Port,
    NamedPipe,
    Email,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoFinding {
    pub algorithm: String,
    pub category: String,
    pub mode: Option<String>,
    pub strength: String,
    pub weakness: Option<String>,
    pub confidence: f32,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerFinding {
    pub name: String,
    pub confidence: f32,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionAnalysis {
    pub id: FunctionId,
    pub address: u64,
    pub size: u64,
    pub name: String,
    pub suggested_name: Option<String>,
    pub description: Option<String>,
    pub purpose: Option<String>,
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
    pub complexity: f32,
    pub interesting_constants: Vec<String>,
    pub possible_vulnerabilities: Vec<String>,
    pub possible_crypto: bool,
    pub possible_networking: bool,
    pub possible_anti_debug: bool,
    pub possible_persistence: bool,
    pub possible_injection: bool,
    pub xrefs_from: Vec<u64>,
    pub xrefs_to: Vec<u64>,
    pub pseudocode_summary: Option<String>,
    pub assembly_preview: Option<String>,
    pub confidence: f32,
    pub evidence: Vec<Evidence>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub id: String,
    pub title: String,
    pub category: String,
    pub severity: RiskLevel,
    pub confidence: f32,
    pub description: String,
    pub cwe: Option<String>,
    pub location: Option<String>,
    pub evidence: Vec<Evidence>,
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MalwareFamily {
    Ransomware,
    Loader,
    Crypter,
    Trojan,
    Stealer,
    Miner,
    Rat,
    Botnet,
    Dropper,
    Rootkit,
    Worm,
    Keylogger,
    Banker,
    Spyware,
    Adware,
    Packer,
    Benign,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareClassification {
    pub family: MalwareFamily,
    pub confidence: f32,
    pub malware_probability: f32,
    pub reasoning: String,
    pub evidence: Vec<Evidence>,
    pub suspicious_apis: Vec<String>,
    pub suspicious_strings: Vec<String>,
    pub behaviors: Vec<String>,
    pub persistence: Vec<String>,
    pub privilege_escalation: Vec<String>,
    pub process_injection: Vec<String>,
    pub anti_analysis: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigitalSignatureInfo {
    pub present: bool,
    pub valid: Option<bool>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub serial: Option<String>,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub algorithm: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceEntry {
    pub name: String,
    pub kind: String,
    pub size: u64,
    pub language: Option<String>,
    pub entropy: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyInfo {
    pub name: String,
    pub version: Option<String>,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphPayload {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    pub kind: String,
    pub address: Option<u64>,
    pub meta: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub id: String,
    pub source: String,
    pub target: String,
    pub kind: String,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub id: AnalysisId,
    pub file_id: FileId,
    pub project_id: ProjectId,
    pub stage: PipelineStage,
    pub progress: u8,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
    pub filename: String,
    pub size_bytes: u64,
    pub hashes: FileHashes,
    pub identity: BinaryIdentity,
    pub sections: Vec<SectionInfo>,
    pub imports: Vec<ImportEntry>,
    pub exports: Vec<ExportEntry>,
    pub strings: Vec<ExtractedString>,
    pub network: Vec<NetworkIndicator>,
    pub crypto: Vec<CryptoFinding>,
    pub packers: Vec<PackerFinding>,
    pub functions: Vec<FunctionAnalysis>,
    pub security: Vec<SecurityFinding>,
    pub malware: MalwareClassification,
    pub signature: DigitalSignatureInfo,
    pub resources: Vec<ResourceEntry>,
    pub dependencies: Vec<DependencyInfo>,
    pub call_graph: GraphPayload,
    pub cfg_summary: GraphPayload,
    pub import_graph: GraphPayload,
    #[serde(default)]
    pub dfg: GraphPayload,
    #[serde(default)]
    pub memory_graph: GraphPayload,
    #[serde(default)]
    pub network_graph: GraphPayload,
    #[serde(default)]
    pub network_intel: Value,
    #[serde(default)]
    pub decomp_backends: Value,
    #[serde(default)]
    pub language_structures: Value,
    pub executive_summary: String,
    pub technical_summary: String,
    pub iocs: Vec<String>,
    pub yara_rules: Vec<String>,
    pub sbom: Value,
}

impl Default for GraphPayload {
    fn default() -> Self {
        Self {
            nodes: vec![],
            edges: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMeta {
    pub id: SnapshotId,
    pub analysis_id: AnalysisId,
    pub label: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: ProjectId,
    pub org_id: OrgId,
    pub name: String,
    pub description: Option<String>,
    pub created_by: UserId,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredFile {
    pub id: FileId,
    pub project_id: ProjectId,
    pub filename: String,
    pub size_bytes: u64,
    pub content_type: Option<String>,
    pub storage_key: String,
    pub hashes: FileHashes,
    pub uploaded_by: UserId,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub email: String,
    pub name: String,
    pub avatar_url: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: OrgId,
    pub name: String,
    pub slug: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Owner,
    Admin,
    Analyst,
    Viewer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    pub id: AnnotationId,
    pub analysis_id: AnalysisId,
    pub author_id: UserId,
    pub target_address: Option<u64>,
    pub target_kind: String,
    pub body: String,
    pub highlight_color: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub id: String,
    pub session_id: ChatSessionId,
    pub role: String,
    pub content: String,
    pub citations: Vec<Evidence>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatSession {
    pub id: ChatSessionId,
    pub analysis_id: AnalysisId,
    pub user_id: UserId,
    pub title: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportDocument {
    pub id: ReportId,
    pub analysis_id: AnalysisId,
    pub kind: ReportKind,
    pub format: ReportFormat,
    pub title: String,
    pub content: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportKind {
    Executive,
    Technical,
    ReverseEngineering,
    Malware,
    Dfir,
    ThreatIntelligence,
    Sbom,
    Ioc,
    Yara,
    Sigma,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportFormat {
    Markdown,
    Html,
    Pdf,
    Json,
    Sarif,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadRequestMeta {
    pub project_id: ProjectId,
    pub filename: String,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisJob {
    pub analysis_id: AnalysisId,
    pub file_id: FileId,
    pub project_id: ProjectId,
    pub storage_key: String,
    pub filename: String,
    pub enqueued_at: DateTime<Utc>,
    pub options: AnalysisOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisOptions {
    pub enable_ai: bool,
    pub enable_disassembly: bool,
    pub deep_unpack: bool,
    pub max_strings: usize,
    pub model_provider: Option<String>,
    pub model_name: Option<String>,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            enable_ai: true,
            enable_disassembly: true,
            deep_unpack: true,
            max_strings: 50_000,
            model_provider: None,
            model_name: None,
        }
    }
}
