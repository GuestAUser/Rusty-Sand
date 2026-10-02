use serde::{Deserialize, Serialize};

pub const MAX_FILE_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_STRING_SCAN_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_STRINGS: usize = 1024;
pub const MAX_STRING_CHARS: usize = 512;
pub const MIN_STRING_CHARS: usize = 4;
pub const MAX_FINDINGS: usize = 256;
pub const MAX_SECTIONS: usize = 96;
pub const MAX_DIRECTORIES: usize = 16;
pub const MAX_IMPORT_LIBRARIES: usize = 128;
pub const MAX_IMPORTS: usize = 4096;
pub const MAX_EXPORTS: usize = 4096;
pub const MAX_EXPORT_NAMES: usize = 4096;
pub const MAX_NAME_BYTES: usize = 256;
pub const MAX_TLS_CALLBACKS: usize = 128;
pub const MAX_CERTIFICATES: usize = 64;
pub const MAX_REPORT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StaticReport {
    pub sha256: String,
    pub size_bytes: u64,
    /// Shannon entropy in bits per byte; zero for an empty input.
    pub entropy: f64,
    pub pe: Option<PeMetadata>,
    pub strings: Vec<ExtractedString>,
    pub findings: Vec<Finding>,
    pub coverage: Coverage,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Coverage {
    pub pe_status: PeStatus,
    pub string_scan_bytes: u64,
    pub strings_truncated: bool,
    pub findings_truncated: bool,
    pub limits: AnalysisLimits,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeStatus {
    NotPe,
    Parsed,
    Malformed,
    Limited,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisLimits {
    pub file_bytes: usize,
    pub string_scan_bytes: usize,
    pub strings: usize,
    pub string_chars: usize,
    pub findings: usize,
    pub sections: usize,
    pub directories: usize,
    pub import_libraries: usize,
    pub imports: usize,
    pub exports: usize,
    pub export_names: usize,
    pub name_bytes: usize,
    pub tls_callbacks: usize,
    pub certificates: usize,
    pub serialized_report_bytes: usize,
}

impl Default for AnalysisLimits {
    fn default() -> Self {
        Self {
            file_bytes: MAX_FILE_BYTES,
            string_scan_bytes: MAX_STRING_SCAN_BYTES,
            strings: MAX_STRINGS,
            string_chars: MAX_STRING_CHARS,
            findings: MAX_FINDINGS,
            sections: MAX_SECTIONS,
            directories: MAX_DIRECTORIES,
            import_libraries: MAX_IMPORT_LIBRARIES,
            imports: MAX_IMPORTS,
            exports: MAX_EXPORTS,
            export_names: MAX_EXPORT_NAMES,
            name_bytes: MAX_NAME_BYTES,
            tls_callbacks: MAX_TLS_CALLBACKS,
            certificates: MAX_CERTIFICATES,
            serialized_report_bytes: MAX_REPORT_BYTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedString {
    pub offset: u64,
    /// Full observed run length, including a suffix omitted from `value`.
    pub byte_length: u64,
    pub encoding: StringEncoding,
    pub value: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StringEncoding {
    Ascii,
    Utf16Le,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable machine-consumed identifier, independent of presentation text.
    pub id: String,
    pub category: FindingCategory,
    pub severity: Severity,
    /// Confidence in the stated observation, not confidence of malware.
    pub confidence: Confidence,
    pub summary: String,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    Structure,
    Packing,
    Capability,
    EmbeddedIndicator,
    TestSignature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Informational,
    Low,
    Medium,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub offset: Option<u64>,
    pub length: Option<u64>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeMetadata {
    pub kind: PeKind,
    pub machine: u16,
    pub timestamp: u32,
    pub characteristics: u16,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub image_base: u64,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub entry_point_rva: u32,
    pub entry_point_offset: Option<u64>,
    pub sections: Vec<Section>,
    pub directories: Vec<DataDirectory>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub tls: Option<TlsMetadata>,
    pub security: Option<SecurityMetadata>,
    /// Trailing file ranges excluding the certificate table.
    pub overlay: Vec<FileRange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeKind {
    Pe32,
    Pe32Plus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    pub header_offset: u64,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    /// None for sections with no file-backed content.
    pub entropy: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataDirectory {
    pub index: u8,
    /// RVA, except index 4, whose address is a file offset.
    pub address: u32,
    pub size: u32,
    pub is_file_offset: bool,
    pub file_offset: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Import {
    pub library: String,
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    pub hint: Option<u16>,
    pub thunk_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Export {
    pub ordinal: u32,
    pub rva: u32,
    pub names: Vec<String>,
    pub forwarder: Option<String>,
    pub file_offset: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsMetadata {
    pub raw_data_start_va: u64,
    pub raw_data_end_va: u64,
    pub index_va: u64,
    pub callbacks_va: u64,
    pub zero_fill_bytes: u32,
    pub characteristics: u32,
    pub callbacks: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityMetadata {
    pub offset: u64,
    pub size: u64,
    /// Structural WIN_CERTIFICATE records only; no trust verification.
    pub certificates: Vec<CertificateMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateMetadata {
    pub offset: u64,
    pub length: u32,
    pub revision: u16,
    pub certificate_type: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRange {
    pub offset: u64,
    pub size: u64,
}
