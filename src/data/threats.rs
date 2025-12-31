//! Threat actors and attack patterns
//!
//! Based on real-world TTPs (Tactics, Techniques, Procedures)
//! aligned with MITRE ATT&CK framework

use super::{Id, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Categories of threat actors
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatActorType {
    NationState,       // APT groups
    Cybercriminal,     // Financially motivated
    Hacktivist,        // Ideologically motivated
    Insider,           // Malicious or negligent employee
    ScriptKiddie,      // Low sophistication attacker
    Unknown,
}

/// A threat actor profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActor {
    pub id: Id,
    pub name: String,              // "APT28", "FIN7", "Unknown Actor"
    pub aliases: Vec<String>,
    pub actor_type: ThreatActorType,
    pub origin_country: Option<String>,
    pub motivation: String,
    pub sophistication: u8,        // 1-10
    pub typical_targets: Vec<String>,
    pub known_ttps: Vec<String>,   // MITRE ATT&CK IDs
    pub known_malware: Vec<String>,
    pub description: String,
}

/// MITRE ATT&CK Tactics (high-level attack phases)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttackTactic {
    Reconnaissance,
    ResourceDevelopment,
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    CommandAndControl,
    Exfiltration,
    Impact,
}

impl AttackTactic {
    pub fn description(&self) -> &'static str {
        match self {
            AttackTactic::Reconnaissance => "Gathering information about the target",
            AttackTactic::ResourceDevelopment => "Establishing resources for operations",
            AttackTactic::InitialAccess => "Gaining initial foothold in the network",
            AttackTactic::Execution => "Running malicious code",
            AttackTactic::Persistence => "Maintaining access across restarts",
            AttackTactic::PrivilegeEscalation => "Gaining higher-level permissions",
            AttackTactic::DefenseEvasion => "Avoiding detection",
            AttackTactic::CredentialAccess => "Stealing credentials",
            AttackTactic::Discovery => "Learning about the environment",
            AttackTactic::LateralMovement => "Moving through the network",
            AttackTactic::Collection => "Gathering target data",
            AttackTactic::CommandAndControl => "Communicating with compromised systems",
            AttackTactic::Exfiltration => "Stealing data from the network",
            AttackTactic::Impact => "Disrupting availability or integrity",
        }
    }

    pub fn color(&self) -> &'static str {
        match self {
            AttackTactic::Reconnaissance | AttackTactic::ResourceDevelopment => "blue",
            AttackTactic::InitialAccess | AttackTactic::Execution => "yellow",
            AttackTactic::Persistence | AttackTactic::PrivilegeEscalation => "orange",
            AttackTactic::DefenseEvasion | AttackTactic::CredentialAccess => "red",
            AttackTactic::Discovery | AttackTactic::LateralMovement => "purple",
            AttackTactic::Collection | AttackTactic::CommandAndControl => "magenta",
            AttackTactic::Exfiltration | AttackTactic::Impact => "red",
        }
    }
}

/// A specific attack technique
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackTechnique {
    pub id: String,                // "T1566.001" format
    pub name: String,
    pub tactic: AttackTactic,
    pub description: String,
    pub detection_hints: Vec<String>,
    pub mitigation_hints: Vec<String>,
    pub severity: Severity,
}

/// Known malware families
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareFamily {
    pub name: String,
    pub malware_type: MalwareType,
    pub capabilities: Vec<String>,
    pub indicators: Vec<String>,  // Known hashes, C2 domains, etc.
    pub associated_actors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MalwareType {
    Ransomware,
    Trojan,
    RAT,                 // Remote Access Trojan
    Backdoor,
    Rootkit,
    Keylogger,
    InfoStealer,
    Cryptominer,
    Wiper,
    Botnet,
    Dropper,
    Loader,
    Webshell,
    Unknown,
}

impl MalwareType {
    pub fn severity(&self) -> Severity {
        match self {
            MalwareType::Ransomware | MalwareType::Wiper => Severity::Critical,
            MalwareType::RAT | MalwareType::Backdoor | MalwareType::Rootkit => Severity::High,
            MalwareType::Trojan | MalwareType::InfoStealer | MalwareType::Keylogger => Severity::High,
            MalwareType::Botnet | MalwareType::Dropper | MalwareType::Loader => Severity::Medium,
            MalwareType::Cryptominer | MalwareType::Webshell => Severity::Medium,
            MalwareType::Unknown => Severity::Low,
        }
    }
}

/// Attack patterns used in scenarios
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackChain {
    pub id: Id,
    pub name: String,
    pub description: String,
    pub actor: Option<ThreatActor>,
    pub stages: Vec<AttackStage>,
    pub current_stage: usize,
    pub time_pressure: u32,        // Turns until escalation
    pub is_active: bool,
}

/// A stage in an attack chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStage {
    pub name: String,
    pub tactic: AttackTactic,
    pub technique_id: String,
    pub description: String,
    pub evidence_generated: Vec<String>,  // What evidence this stage creates
    pub detection_difficulty: u8,         // 1-10, how hard to spot
    pub time_to_next: u32,                // Turns until next stage if undetected
    pub impact_if_missed: String,
    pub is_detected: bool,
    pub is_contained: bool,
}

/// Pre-built threat library for realistic scenarios
pub fn create_threat_library() -> HashMap<String, AttackTechnique> {
    let mut techniques = HashMap::new();

    // Initial Access techniques
    techniques.insert("T1566.001".to_string(), AttackTechnique {
        id: "T1566.001".to_string(),
        name: "Spearphishing Attachment".to_string(),
        tactic: AttackTactic::InitialAccess,
        description: "Adversaries send malicious attachments via email to gain initial access".to_string(),
        detection_hints: vec![
            "Check email gateway logs for blocked attachments".to_string(),
            "Look for macro-enabled documents".to_string(),
            "Examine email headers for spoofing indicators".to_string(),
        ],
        mitigation_hints: vec![
            "Disable macros in Office documents".to_string(),
            "Implement email sandboxing".to_string(),
        ],
        severity: Severity::High,
    });

    techniques.insert("T1566.002".to_string(), AttackTechnique {
        id: "T1566.002".to_string(),
        name: "Spearphishing Link".to_string(),
        tactic: AttackTactic::InitialAccess,
        description: "Adversaries send links to malicious websites to gain access".to_string(),
        detection_hints: vec![
            "Check web proxy logs for credential harvesting sites".to_string(),
            "Look for newly registered domains in email links".to_string(),
            "Monitor for OAuth consent phishing".to_string(),
        ],
        mitigation_hints: vec![
            "Implement URL filtering".to_string(),
            "Enable MFA to reduce credential theft impact".to_string(),
        ],
        severity: Severity::High,
    });

    // Execution techniques
    techniques.insert("T1059.001".to_string(), AttackTechnique {
        id: "T1059.001".to_string(),
        name: "PowerShell".to_string(),
        tactic: AttackTactic::Execution,
        description: "Adversaries use PowerShell for execution and script-based attacks".to_string(),
        detection_hints: vec![
            "Enable PowerShell Script Block Logging".to_string(),
            "Look for encoded commands (-enc, -encodedcommand)".to_string(),
            "Monitor for suspicious cmdlets (IEX, Invoke-Expression)".to_string(),
        ],
        mitigation_hints: vec![
            "Enable Constrained Language Mode".to_string(),
            "Implement application whitelisting".to_string(),
        ],
        severity: Severity::High,
    });

    // Persistence
    techniques.insert("T1547.001".to_string(), AttackTechnique {
        id: "T1547.001".to_string(),
        name: "Registry Run Keys".to_string(),
        tactic: AttackTactic::Persistence,
        description: "Adversaries add programs to registry run keys for persistence".to_string(),
        detection_hints: vec![
            "Monitor HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
            "Check HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
            "Look for unsigned executables in startup paths".to_string(),
        ],
        mitigation_hints: vec![
            "Restrict registry permissions".to_string(),
            "Use application whitelisting".to_string(),
        ],
        severity: Severity::Medium,
    });

    // Credential Access
    techniques.insert("T1003.001".to_string(), AttackTechnique {
        id: "T1003.001".to_string(),
        name: "LSASS Memory".to_string(),
        tactic: AttackTactic::CredentialAccess,
        description: "Adversaries access LSASS process memory to extract credentials".to_string(),
        detection_hints: vec![
            "Monitor for processes accessing lsass.exe".to_string(),
            "Look for procdump, mimikatz, or similar tools".to_string(),
            "Check for LSASS crash dumps".to_string(),
        ],
        mitigation_hints: vec![
            "Enable Credential Guard".to_string(),
            "Restrict debug privileges".to_string(),
        ],
        severity: Severity::Critical,
    });

    // Lateral Movement
    techniques.insert("T1021.001".to_string(), AttackTechnique {
        id: "T1021.001".to_string(),
        name: "Remote Desktop Protocol".to_string(),
        tactic: AttackTactic::LateralMovement,
        description: "Adversaries use RDP to move laterally in the network".to_string(),
        detection_hints: vec![
            "Monitor for RDP connections from unusual sources".to_string(),
            "Check for RDP at unusual times".to_string(),
            "Look for authentication failures before success".to_string(),
        ],
        mitigation_hints: vec![
            "Require NLA for RDP".to_string(),
            "Limit RDP access via firewall rules".to_string(),
        ],
        severity: Severity::High,
    });

    // Command and Control
    techniques.insert("T1071.001".to_string(), AttackTechnique {
        id: "T1071.001".to_string(),
        name: "Web Protocols".to_string(),
        tactic: AttackTactic::CommandAndControl,
        description: "Adversaries communicate using HTTP/HTTPS to blend with normal traffic".to_string(),
        detection_hints: vec![
            "Look for beaconing patterns (regular intervals)".to_string(),
            "Check for unusual User-Agent strings".to_string(),
            "Monitor for high-entropy DNS queries".to_string(),
        ],
        mitigation_hints: vec![
            "Implement SSL/TLS inspection".to_string(),
            "Use network behavior analysis".to_string(),
        ],
        severity: Severity::High,
    });

    // Exfiltration
    techniques.insert("T1048".to_string(), AttackTechnique {
        id: "T1048".to_string(),
        name: "Exfiltration Over Alternative Protocol".to_string(),
        tactic: AttackTactic::Exfiltration,
        description: "Adversaries exfiltrate data over non-standard protocols".to_string(),
        detection_hints: vec![
            "Monitor for DNS tunneling (long queries, TXT records)".to_string(),
            "Check for unusual outbound protocols".to_string(),
            "Look for large data transfers to new destinations".to_string(),
        ],
        mitigation_hints: vec![
            "Implement DLP solutions".to_string(),
            "Restrict outbound protocols at firewall".to_string(),
        ],
        severity: Severity::Critical,
    });

    techniques
}
