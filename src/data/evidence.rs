//! Evidence types that players can discover and analyze

use super::{Id, Severity, Confidence};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Categories of evidence
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EvidenceType {
    /// A suspicious file (malware, script, document)
    File(FileEvidence),
    /// Log entries from various sources
    LogEntry(LogEvidence),
    /// Network traffic or connection data
    NetworkCapture(NetworkEvidence),
    /// Interview notes from talking to employees
    Interview(InterviewEvidence),
    /// Alert from security tools
    Alert(AlertEvidence),
    /// Email (phishing, exfiltration, etc.)
    Email(EmailEvidence),
    /// Registry key or system configuration
    SystemConfig(ConfigEvidence),
    /// Process or memory artifact
    ProcessArtifact(ProcessEvidence),
}

/// Evidence about a suspicious file
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileEvidence {
    pub filename: String,
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub md5: String,
    pub file_type: String,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
    pub entropy: f32,
    pub strings_of_interest: Vec<String>,
    pub imports: Vec<String>,
    pub is_signed: bool,
    pub signer: Option<String>,
}

/// Evidence from log files
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogEvidence {
    pub source: String,      // "Windows Event Log", "Apache", "Syslog", etc.
    pub log_type: String,    // "Security", "Application", "Auth", etc.
    pub event_id: Option<u32>,
    pub timestamp: DateTime<Utc>,
    pub message: String,
    pub source_ip: Option<String>,
    pub user: Option<String>,
    pub process: Option<String>,
}

/// Network traffic evidence
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkEvidence {
    pub timestamp: DateTime<Utc>,
    pub source_ip: String,
    pub source_port: u16,
    pub dest_ip: String,
    pub dest_port: u16,
    pub protocol: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub dns_query: Option<String>,
    pub http_host: Option<String>,
    pub http_uri: Option<String>,
    pub tls_sni: Option<String>,
    pub is_encrypted: bool,
    pub suspicious_patterns: Vec<String>,
}

/// Interview evidence from talking to people
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InterviewEvidence {
    pub interviewee: String,
    pub role: String,
    pub department: String,
    pub timestamp: DateTime<Utc>,
    pub key_statements: Vec<String>,
    pub demeanor: String,          // "nervous", "cooperative", "defensive"
    pub credibility: Confidence,
    pub mentioned_names: Vec<String>,
    pub mentioned_systems: Vec<String>,
}

/// Alert from security tools (SIEM, EDR, etc.)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertEvidence {
    pub source_tool: String,       // "CrowdStrike", "Splunk", "Suricata"
    pub alert_name: String,
    pub alert_id: String,
    pub severity: Severity,
    pub timestamp: DateTime<Utc>,
    pub affected_host: String,
    pub description: String,
    pub iocs: Vec<String>,         // Indicators of Compromise
    pub mitre_techniques: Vec<String>,
    pub false_positive_rate: f32,
}

/// Email evidence
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmailEvidence {
    pub message_id: String,
    pub from: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub subject: String,
    pub timestamp: DateTime<Utc>,
    pub body_preview: String,
    pub has_attachments: bool,
    pub attachment_names: Vec<String>,
    pub headers: HashMap<String, String>,
    pub urls_in_body: Vec<String>,
    pub is_external: bool,
    pub spf_result: String,
    pub dkim_result: String,
}

/// System configuration evidence
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfigEvidence {
    pub system: String,
    pub config_type: String,       // "registry", "cron", "startup", "service"
    pub path: String,
    pub value: String,
    pub timestamp: DateTime<Utc>,
    pub is_persistence: bool,
    pub is_suspicious: bool,
}

/// Process or memory evidence
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessEvidence {
    pub hostname: String,
    pub process_name: String,
    pub pid: u32,
    pub ppid: u32,
    pub parent_name: String,
    pub command_line: String,
    pub user: String,
    pub start_time: DateTime<Utc>,
    pub executable_path: String,
    pub loaded_dlls: Vec<String>,
    pub network_connections: Vec<String>,
    pub child_processes: Vec<String>,
    pub is_suspicious: bool,
    pub suspicion_reasons: Vec<String>,
}

/// A piece of evidence the player has collected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: Id,
    pub evidence_type: EvidenceType,
    pub discovered_at: DateTime<Utc>,
    pub discovered_by: String,     // "player", "automated", "npc_name"
    pub analysis_notes: Vec<String>,
    pub is_analyzed: bool,
    pub linked_evidence: Vec<Id>,  // Related evidence IDs
    pub relevance: Confidence,
    pub tags: Vec<String>,
}

impl Evidence {
    pub fn new(evidence_type: EvidenceType) -> Self {
        Self {
            id: Id::new(),
            evidence_type,
            discovered_at: Utc::now(),
            discovered_by: "player".to_string(),
            analysis_notes: Vec::new(),
            is_analyzed: false,
            linked_evidence: Vec::new(),
            relevance: Confidence::Uncertain,
            tags: Vec::new(),
        }
    }

    /// Get a brief description of the evidence
    pub fn brief(&self) -> String {
        match &self.evidence_type {
            EvidenceType::File(f) => format!("File: {}", f.filename),
            EvidenceType::LogEntry(l) => format!("Log: {} - {}", l.source, &l.message[..50.min(l.message.len())]),
            EvidenceType::NetworkCapture(n) => format!("Network: {} -> {}:{}", n.source_ip, n.dest_ip, n.dest_port),
            EvidenceType::Interview(i) => format!("Interview: {} ({})", i.interviewee, i.role),
            EvidenceType::Alert(a) => format!("Alert: {} [{}]", a.alert_name, a.severity),
            EvidenceType::Email(e) => format!("Email: {} - {}", e.from, e.subject),
            EvidenceType::SystemConfig(c) => format!("Config: {} - {}", c.config_type, c.path),
            EvidenceType::ProcessArtifact(p) => format!("Process: {} (PID {})", p.process_name, p.pid),
        }
    }
}
