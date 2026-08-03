use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ids::AnalysisId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineStage {
    Queued,
    Hashing,
    Identification,
    Unpacking,
    StaticAnalysis,
    Disassembly,
    GraphConstruction,
    FunctionExtraction,
    StringExtraction,
    ImportExportAnalysis,
    ResourceExtraction,
    AiSemantic,
    SecurityAnalysis,
    MalwareAnalysis,
    ReportGeneration,
    ChatIndexing,
    Completed,
    Failed,
}

impl PipelineStage {
    pub fn next(self) -> Option<Self> {
        use PipelineStage::*;
        match self {
            Queued => Some(Hashing),
            Hashing => Some(Identification),
            Identification => Some(Unpacking),
            Unpacking => Some(StaticAnalysis),
            StaticAnalysis => Some(Disassembly),
            Disassembly => Some(GraphConstruction),
            GraphConstruction => Some(FunctionExtraction),
            FunctionExtraction => Some(StringExtraction),
            StringExtraction => Some(ImportExportAnalysis),
            ImportExportAnalysis => Some(ResourceExtraction),
            ResourceExtraction => Some(AiSemantic),
            AiSemantic => Some(SecurityAnalysis),
            SecurityAnalysis => Some(MalwareAnalysis),
            MalwareAnalysis => Some(ReportGeneration),
            ReportGeneration => Some(ChatIndexing),
            ChatIndexing => Some(Completed),
            Completed | Failed => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Hashing => "hashing",
            Self::Identification => "identification",
            Self::Unpacking => "unpacking",
            Self::StaticAnalysis => "static_analysis",
            Self::Disassembly => "disassembly",
            Self::GraphConstruction => "graph_construction",
            Self::FunctionExtraction => "function_extraction",
            Self::StringExtraction => "string_extraction",
            Self::ImportExportAnalysis => "import_export_analysis",
            Self::ResourceExtraction => "resource_extraction",
            Self::AiSemantic => "ai_semantic",
            Self::SecurityAnalysis => "security_analysis",
            Self::MalwareAnalysis => "malware_analysis",
            Self::ReportGeneration => "report_generation",
            Self::ChatIndexing => "chat_indexing",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    pub fn progress_percent(self) -> u8 {
        match self {
            Self::Queued => 0,
            Self::Hashing => 5,
            Self::Identification => 10,
            Self::Unpacking => 15,
            Self::StaticAnalysis => 25,
            Self::Disassembly => 35,
            Self::GraphConstruction => 45,
            Self::FunctionExtraction => 52,
            Self::StringExtraction => 58,
            Self::ImportExportAnalysis => 64,
            Self::ResourceExtraction => 70,
            Self::AiSemantic => 80,
            Self::SecurityAnalysis => 86,
            Self::MalwareAnalysis => 90,
            Self::ReportGeneration => 95,
            Self::ChatIndexing => 98,
            Self::Completed => 100,
            Self::Failed => 100,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineEvent {
    pub analysis_id: AnalysisId,
    pub stage: PipelineStage,
    pub message: String,
    pub progress: u8,
    pub at: DateTime<Utc>,
    pub error: Option<String>,
}

impl PipelineEvent {
    pub fn new(analysis_id: AnalysisId, stage: PipelineStage, message: impl Into<String>) -> Self {
        Self {
            analysis_id,
            stage,
            message: message.into(),
            progress: stage.progress_percent(),
            at: Utc::now(),
            error: None,
        }
    }

    pub fn failed(analysis_id: AnalysisId, message: impl Into<String>) -> Self {
        Self {
            analysis_id,
            stage: PipelineStage::Failed,
            message: message.into(),
            progress: 100,
            at: Utc::now(),
            error: Some("pipeline_failed".into()),
        }
    }
}
