//! Investigation mechanics
//!
//! Handles evidence analysis, correlation, and deduction

use crate::data::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Result of analyzing evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub evidence_id: Id,
    pub findings: Vec<Finding>,
    pub iocs_extracted: Vec<IoC>,
    pub suggested_next_steps: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub confidence: Confidence,
}

/// A finding from analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub related_to: Vec<Id>,
}

/// Indicator of Compromise
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoC {
    pub ioc_type: IoCType,
    pub value: String,
    pub description: String,
    pub first_seen: Option<String>,
    pub related_evidence: Vec<Id>,
}

/// Types of IoCs
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IoCType {
    IPv4,
    IPv6,
    Domain,
    URL,
    Email,
    FileHash(HashType),
    FileName,
    FilePath,
    RegistryKey,
    Mutex,
    ProcessName,
    UserAgent,
    CertificateHash,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HashType {
    MD5,
    SHA1,
    SHA256,
}

impl std::fmt::Display for IoCType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IoCType::IPv4 => write!(f, "IPv4"),
            IoCType::IPv6 => write!(f, "IPv6"),
            IoCType::Domain => write!(f, "Domain"),
            IoCType::URL => write!(f, "URL"),
            IoCType::Email => write!(f, "Email"),
            IoCType::FileHash(h) => write!(f, "{:?} Hash", h),
            IoCType::FileName => write!(f, "Filename"),
            IoCType::FilePath => write!(f, "File Path"),
            IoCType::RegistryKey => write!(f, "Registry Key"),
            IoCType::Mutex => write!(f, "Mutex"),
            IoCType::ProcessName => write!(f, "Process"),
            IoCType::UserAgent => write!(f, "User Agent"),
            IoCType::CertificateHash => write!(f, "Cert Hash"),
        }
    }
}

/// Investigation state tracker
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationState {
    /// All discovered IoCs
    pub iocs: HashMap<String, IoC>,

    /// Correlation links between evidence
    pub correlations: Vec<Correlation>,

    /// Current hypotheses
    pub hypotheses: Vec<Hypothesis>,

    /// Investigation notes
    pub notes: Vec<InvestigationNote>,

    /// Key questions to answer
    pub open_questions: Vec<String>,

    /// Answered questions
    pub answered_questions: Vec<(String, String)>,
}

/// A correlation between pieces of evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Correlation {
    pub id: Id,
    pub evidence_a: Id,
    pub evidence_b: Id,
    pub correlation_type: CorrelationType,
    pub description: String,
    pub confidence: Confidence,
}

/// Types of correlations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CorrelationType {
    Temporal,          // Happened around the same time
    Causal,            // A likely caused B
    SharedIoC,         // Share an indicator
    SharedSystem,      // Same system involved
    SharedUser,        // Same user involved
    AttackChain,       // Part of the same attack sequence
}

/// A hypothesis about the incident
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hypothesis {
    pub id: Id,
    pub statement: String,
    pub supporting_evidence: Vec<Id>,
    pub contradicting_evidence: Vec<Id>,
    pub confidence: Confidence,
    pub is_confirmed: bool,
    pub is_refuted: bool,
}

/// An investigation note
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationNote {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub content: String,
    pub related_evidence: Vec<Id>,
    pub tags: Vec<String>,
}

impl InvestigationState {
    pub fn new() -> Self {
        Self {
            iocs: HashMap::new(),
            correlations: Vec::new(),
            hypotheses: Vec::new(),
            notes: Vec::new(),
            open_questions: vec![
                "What was the initial attack vector?".to_string(),
                "Which systems are compromised?".to_string(),
                "What data was accessed?".to_string(),
                "Is the threat still active?".to_string(),
                "Who is the threat actor?".to_string(),
            ],
            answered_questions: Vec::new(),
        }
    }

    /// Add an IoC
    pub fn add_ioc(&mut self, ioc: IoC) {
        self.iocs.insert(ioc.value.clone(), ioc);
    }

    /// Create a correlation between evidence
    pub fn correlate(&mut self, evidence_a: Id, evidence_b: Id,
                     corr_type: CorrelationType, description: &str) {
        let correlation = Correlation {
            id: Id::new(),
            evidence_a,
            evidence_b,
            correlation_type: corr_type,
            description: description.to_string(),
            confidence: Confidence::Possible,
        };
        self.correlations.push(correlation);
    }

    /// Add a hypothesis
    pub fn add_hypothesis(&mut self, statement: &str) -> Id {
        let hypothesis = Hypothesis {
            id: Id::new(),
            statement: statement.to_string(),
            supporting_evidence: Vec::new(),
            contradicting_evidence: Vec::new(),
            confidence: Confidence::Uncertain,
            is_confirmed: false,
            is_refuted: false,
        };
        let id = hypothesis.id;
        self.hypotheses.push(hypothesis);
        id
    }

    /// Add evidence to support or refute a hypothesis
    pub fn update_hypothesis(&mut self, hypothesis_id: Id, evidence_id: Id, supports: bool) {
        if let Some(h) = self.hypotheses.iter_mut().find(|h| h.id == hypothesis_id) {
            if supports {
                h.supporting_evidence.push(evidence_id);
            } else {
                h.contradicting_evidence.push(evidence_id);
            }

            // Update confidence based on evidence balance
            let support_count = h.supporting_evidence.len() as f32;
            let contradict_count = h.contradicting_evidence.len() as f32;
            let total = support_count + contradict_count;

            if total > 0.0 {
                let ratio = support_count / total;
                h.confidence = Confidence::from_percentage(ratio);
            }
        }
    }

    /// Answer a question
    pub fn answer_question(&mut self, question: &str, answer: &str) {
        if let Some(pos) = self.open_questions.iter().position(|q| q == question) {
            let q = self.open_questions.remove(pos);
            self.answered_questions.push((q, answer.to_string()));
        }
    }

    /// Get investigation progress percentage
    pub fn progress(&self) -> f32 {
        let total_questions = self.open_questions.len() + self.answered_questions.len();
        if total_questions == 0 {
            return 0.0;
        }
        self.answered_questions.len() as f32 / total_questions as f32 * 100.0
    }
}

/// Analyze a file evidence
pub fn analyze_file(evidence: &FileEvidence) -> AnalysisResult {
    let mut findings = Vec::new();
    let mut iocs = Vec::new();
    let mut techniques = Vec::new();
    let mut next_steps = Vec::new();

    // Check entropy (possible packing/encryption)
    if evidence.entropy > 7.0 {
        findings.push(Finding {
            title: "High Entropy Detected".to_string(),
            description: format!(
                "File has entropy of {:.2}, suggesting it may be packed or encrypted.",
                evidence.entropy
            ),
            severity: Severity::Medium,
            confidence: Confidence::Likely,
            related_to: vec![],
        });
        next_steps.push("Consider running file through sandbox".to_string());
    }

    // Check for suspicious strings
    for string in &evidence.strings_of_interest {
        if string.starts_with("http://") || string.starts_with("https://") {
            iocs.push(IoC {
                ioc_type: IoCType::URL,
                value: string.clone(),
                description: "URL found in file strings".to_string(),
                first_seen: None,
                related_evidence: vec![],
            });
        }
        if string.contains("powershell") || string.contains("cmd.exe") {
            findings.push(Finding {
                title: "Command Execution Reference".to_string(),
                description: format!("File contains reference to: {}", string),
                severity: Severity::High,
                confidence: Confidence::Confident,
                related_to: vec![],
            });
            techniques.push("T1059".to_string());
        }
    }

    // Add file hash as IoC
    iocs.push(IoC {
        ioc_type: IoCType::FileHash(HashType::SHA256),
        value: evidence.sha256.clone(),
        description: format!("SHA256 hash of {}", evidence.filename),
        first_seen: None,
        related_evidence: vec![],
    });

    // Check signing
    if !evidence.is_signed {
        findings.push(Finding {
            title: "Unsigned Executable".to_string(),
            description: "File is not digitally signed".to_string(),
            severity: Severity::Low,
            confidence: Confidence::Certain,
            related_to: vec![],
        });
    }

    // Suggest next steps
    next_steps.push("Check hash against VirusTotal".to_string());
    next_steps.push("Search for hash in other systems".to_string());
    if !evidence.imports.is_empty() {
        next_steps.push("Review imported functions for suspicious APIs".to_string());
    }

    AnalysisResult {
        evidence_id: Id::new(),  // Would use actual evidence ID
        findings,
        iocs_extracted: iocs,
        suggested_next_steps: next_steps,
        mitre_techniques: techniques,
        confidence: Confidence::Likely,
    }
}

/// Analyze network evidence
pub fn analyze_network(evidence: &NetworkEvidence) -> AnalysisResult {
    let mut findings = Vec::new();
    let mut iocs = Vec::new();
    let mut techniques = Vec::new();

    // Check for suspicious ports
    let suspicious_ports = vec![4444, 5555, 6666, 31337, 1337, 8080];
    if suspicious_ports.contains(&evidence.dest_port) {
        findings.push(Finding {
            title: "Connection to Suspicious Port".to_string(),
            description: format!("Outbound connection to port {}", evidence.dest_port),
            severity: Severity::High,
            confidence: Confidence::Likely,
            related_to: vec![],
        });
        techniques.push("T1571".to_string());
    }

    // Add IPs as IoCs
    iocs.push(IoC {
        ioc_type: IoCType::IPv4,
        value: evidence.dest_ip.clone(),
        description: "Destination IP from network capture".to_string(),
        first_seen: Some(evidence.timestamp.to_string()),
        related_evidence: vec![],
    });

    // Check for C2 patterns
    if let Some(ref host) = evidence.http_host {
        iocs.push(IoC {
            ioc_type: IoCType::Domain,
            value: host.clone(),
            description: "HTTP host from connection".to_string(),
            first_seen: None,
            related_evidence: vec![],
        });

        // Check for beaconing patterns (would need multiple data points)
        findings.push(Finding {
            title: "HTTP Connection to External Host".to_string(),
            description: format!("Connection to {}", host),
            severity: Severity::Medium,
            confidence: Confidence::Possible,
            related_to: vec![],
        });
    }

    // Large data transfer
    if evidence.bytes_sent > 10_000_000 {
        findings.push(Finding {
            title: "Large Outbound Data Transfer".to_string(),
            description: format!(
                "{}MB sent to {}",
                evidence.bytes_sent / 1_000_000,
                evidence.dest_ip
            ),
            severity: Severity::High,
            confidence: Confidence::Confident,
            related_to: vec![],
        });
        techniques.push("T1048".to_string());
    }

    AnalysisResult {
        evidence_id: Id::new(),
        findings,
        iocs_extracted: iocs,
        suggested_next_steps: vec![
            "Check destination IP reputation".to_string(),
            "Analyze payload if available".to_string(),
            "Search for other connections to this IP".to_string(),
        ],
        mitre_techniques: techniques,
        confidence: Confidence::Likely,
    }
}

impl Default for InvestigationState {
    fn default() -> Self {
        Self::new()
    }
}
