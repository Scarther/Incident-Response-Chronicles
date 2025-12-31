//! Scenario definitions for incident response adventures
//!
//! Each scenario represents a complete incident with attack chain,
//! evidence to discover, and multiple paths to resolution.

use crate::data::*;
use serde::{Deserialize, Serialize};
use chrono::{Utc, Duration};

/// A complete incident scenario
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    pub id: String,
    pub title: String,
    pub synopsis: String,
    pub difficulty: u8,              // 1-10
    pub estimated_time_minutes: u32,

    /// The attack being investigated
    pub attack_chain: AttackChain,

    /// All evidence that can be discovered
    pub available_evidence: Vec<Evidence>,

    /// Systems involved in the scenario
    pub systems: Vec<System>,

    /// NPCs for this scenario
    pub npcs: Vec<NPC>,

    /// Victory conditions
    pub success_conditions: Vec<SuccessCondition>,

    /// Failure conditions
    pub failure_conditions: Vec<FailureCondition>,

    /// Current state
    pub state: ScenarioState,

    /// Hints for players who are stuck
    pub hints: Vec<ScenarioHint>,
}

/// Current state of a scenario
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioState {
    pub is_active: bool,
    pub is_complete: bool,
    pub is_failed: bool,
    pub current_attack_stage: usize,
    pub discovered_evidence_ids: Vec<Id>,
    pub contained_systems: Vec<Id>,
    pub flags: std::collections::HashMap<String, bool>,
    pub turns_elapsed: u32,
    pub turns_until_escalation: u32,
}

/// Conditions for successful resolution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SuccessCondition {
    IdentifyThreatActor,
    ContainAllCompromised,
    PreventDataExfiltration,
    CollectKeyEvidence(Vec<String>),  // Evidence IDs
    TimeLimit(u32),                    // Complete within X turns
}

/// Conditions for failure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FailureCondition {
    DataExfiltrated,
    RansomwareDeployed,
    ThreatActorEscaped,
    WrongAccusation,
    TimeExpired(u32),
    TooManyFalsePositives(u32),
}

/// Hints for stuck players
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioHint {
    pub trigger_condition: String,  // When to show hint
    pub hint_text: String,
    pub severity: Severity,
}

impl Scenario {
    /// Check if scenario is failed
    pub fn is_failed(&self) -> bool {
        self.state.is_failed
    }

    /// Check if scenario is complete
    pub fn is_complete(&self) -> bool {
        self.state.is_complete
    }

    /// Progress the threat based on time
    pub fn progress_threat(&mut self, _timeline: &Timeline) {
        if self.state.turns_until_escalation > 0 {
            self.state.turns_until_escalation -= 1;

            if self.state.turns_until_escalation == 0 {
                // Escalate to next attack stage
                if self.state.current_attack_stage < self.attack_chain.stages.len() - 1 {
                    self.state.current_attack_stage += 1;
                    // Reset timer for next stage
                    if let Some(stage) = self.attack_chain.stages.get(self.state.current_attack_stage) {
                        self.state.turns_until_escalation = stage.time_to_next;
                    }
                } else {
                    // Final stage reached - check for failure
                    self.check_failure_conditions();
                }
            }
        }
    }

    /// Check if any failure conditions are met
    fn check_failure_conditions(&mut self) {
        for condition in &self.failure_conditions {
            match condition {
                FailureCondition::DataExfiltrated => {
                    let final_stage = &self.attack_chain.stages.last();
                    if let Some(stage) = final_stage {
                        if stage.tactic == AttackTactic::Exfiltration && !stage.is_contained {
                            self.state.is_failed = true;
                        }
                    }
                }
                FailureCondition::TimeExpired(max) => {
                    if self.state.turns_elapsed > *max {
                        self.state.is_failed = true;
                    }
                }
                _ => {}
            }
        }
    }

    /// Check if success conditions are met
    pub fn check_success_conditions(&mut self) {
        let mut all_met = true;

        for condition in &self.success_conditions {
            match condition {
                SuccessCondition::ContainAllCompromised => {
                    // Check if all compromised systems are contained
                    let compromised_count = self.systems.iter()
                        .filter(|s| s.compromise_status == CompromiseStatus::Compromised)
                        .count();
                    if compromised_count > 0 {
                        all_met = false;
                    }
                }
                SuccessCondition::CollectKeyEvidence(required) => {
                    for _req in required {
                        // Would check if evidence is in discovered list
                        // Simplified for now
                    }
                }
                _ => {}
            }
        }

        if all_met {
            self.state.is_complete = true;
        }
    }
}

/// Create the first tutorial scenario
pub fn create_phishing_scenario() -> Scenario {
    let _incident_start = Utc::now() - Duration::hours(2);

    // Create the attack chain
    let attack_chain = AttackChain {
        id: Id::new(),
        name: "Operation Inbox Invader".to_string(),
        description: "A targeted phishing campaign led to initial access via malicious document".to_string(),
        actor: Some(ThreatActor {
            id: Id::new(),
            name: "Unknown Financially Motivated Actor".to_string(),
            aliases: vec![],
            actor_type: ThreatActorType::Cybercriminal,
            origin_country: None,
            motivation: "Financial gain - likely ransomware precursor".to_string(),
            sophistication: 6,
            typical_targets: vec!["SMBs".to_string(), "Healthcare".to_string()],
            known_ttps: vec!["T1566.001".to_string(), "T1059.001".to_string()],
            known_malware: vec!["QakBot".to_string(), "Cobalt Strike".to_string()],
            description: "Sophisticated criminal group known for ransomware attacks".to_string(),
        }),
        stages: vec![
            AttackStage {
                name: "Initial Access via Phishing".to_string(),
                tactic: AttackTactic::InitialAccess,
                technique_id: "T1566.001".to_string(),
                description: "User opened malicious Excel attachment with macro".to_string(),
                evidence_generated: vec![
                    "phishing_email".to_string(),
                    "malicious_attachment".to_string(),
                    "email_gateway_log".to_string(),
                ],
                detection_difficulty: 4,
                time_to_next: 6,  // 6 turns until next stage
                impact_if_missed: "Malware establishes foothold".to_string(),
                is_detected: false,
                is_contained: false,
            },
            AttackStage {
                name: "PowerShell Execution".to_string(),
                tactic: AttackTactic::Execution,
                technique_id: "T1059.001".to_string(),
                description: "Macro executed encoded PowerShell to download payload".to_string(),
                evidence_generated: vec![
                    "powershell_log".to_string(),
                    "process_creation_log".to_string(),
                ],
                detection_difficulty: 5,
                time_to_next: 4,
                impact_if_missed: "Attacker establishes persistence".to_string(),
                is_detected: false,
                is_contained: false,
            },
            AttackStage {
                name: "Persistence via Scheduled Task".to_string(),
                tactic: AttackTactic::Persistence,
                technique_id: "T1053.005".to_string(),
                description: "Malware creates scheduled task for persistence".to_string(),
                evidence_generated: vec![
                    "scheduled_task".to_string(),
                    "registry_modification".to_string(),
                ],
                detection_difficulty: 6,
                time_to_next: 5,
                impact_if_missed: "Attacker survives reboot".to_string(),
                is_detected: false,
                is_contained: false,
            },
            AttackStage {
                name: "Credential Harvesting".to_string(),
                tactic: AttackTactic::CredentialAccess,
                technique_id: "T1003.001".to_string(),
                description: "Attacker attempts to dump credentials from LSASS".to_string(),
                evidence_generated: vec![
                    "lsass_access".to_string(),
                    "edr_alert".to_string(),
                ],
                detection_difficulty: 3,  // EDR should catch this
                time_to_next: 4,
                impact_if_missed: "Attacker gains domain credentials".to_string(),
                is_detected: false,
                is_contained: false,
            },
            AttackStage {
                name: "Lateral Movement".to_string(),
                tactic: AttackTactic::LateralMovement,
                technique_id: "T1021.001".to_string(),
                description: "Using stolen credentials to access other systems".to_string(),
                evidence_generated: vec![
                    "rdp_connection".to_string(),
                    "authentication_log".to_string(),
                ],
                detection_difficulty: 5,
                time_to_next: 6,
                impact_if_missed: "Multiple systems compromised".to_string(),
                is_detected: false,
                is_contained: false,
            },
            AttackStage {
                name: "Data Exfiltration".to_string(),
                tactic: AttackTactic::Exfiltration,
                technique_id: "T1048".to_string(),
                description: "Sensitive data being exfiltrated via HTTPS".to_string(),
                evidence_generated: vec![
                    "unusual_outbound".to_string(),
                    "dlp_alert".to_string(),
                ],
                detection_difficulty: 7,
                time_to_next: 0,  // Final stage
                impact_if_missed: "Data breach - game over".to_string(),
                is_detected: false,
                is_contained: false,
            },
        ],
        current_stage: 0,
        time_pressure: 30,  // 30 turns total
        is_active: true,
    };

    // Create systems involved
    let systems = vec![
        System::workstation("WS-JSMITH", "10.0.5.42", "John Smith", "Finance"),
        System::workstation("WS-MJONES", "10.0.5.43", "Mary Jones", "Finance"),
        System::server("SRV-DC01", "10.1.0.10", SystemType::DomainController, 10),
        System::server("SRV-FS01", "10.1.0.20", SystemType::FileServer, 8),
        System::server("SRV-MAIL", "10.1.0.30", SystemType::MailServer, 7),
    ];

    // Create NPCs
    let npcs = vec![
        {
            let mut npc = NPC::new("John Smith", "Financial Analyst", "Finance");
            npc.personality.cooperativeness = 7;
            npc.personality.honesty = 9;
            npc.personality.traits = vec!["worried".to_string(), "apologetic".to_string()];
            npc.knowledge = vec!["Received suspicious email".to_string(), "Opened attachment".to_string()];
            npc
        },
        {
            let mut npc = NPC::new("Sarah Chen", "IT Manager", "IT");
            npc.personality.cooperativeness = 9;
            npc.personality.technical_skill = 8;
            npc.personality.traits = vec!["helpful".to_string(), "experienced".to_string()];
            npc.knowledge = vec!["Network layout".to_string(), "Admin access".to_string()];
            npc
        },
        {
            let mut npc = NPC::new("Michael Torres", "CFO", "Executive");
            npc.personality.cooperativeness = 5;
            npc.personality.stress_tolerance = 4;
            npc.personality.traits = vec!["busy".to_string(), "concerned about reputation".to_string()];
            npc.knowledge = vec!["Sensitive financial data".to_string()];
            npc
        },
    ];

    Scenario {
        id: "phishing_01".to_string(),
        title: "The Monday Morning Malware".to_string(),
        synopsis: r#"
It's Monday morning. You've just started your shift when an EDR alert catches
your attention - suspicious PowerShell activity on a workstation in Finance.

The user, John Smith, says he "just opened an email attachment from a vendor."
Now you need to figure out how bad this is and stop it before it gets worse.

Good luck, analyst. The clock is ticking.
        "#.trim().to_string(),
        difficulty: 4,
        estimated_time_minutes: 45,
        attack_chain,
        available_evidence: Vec::new(), // Would populate with actual evidence
        systems,
        npcs,
        success_conditions: vec![
            SuccessCondition::ContainAllCompromised,
            SuccessCondition::IdentifyThreatActor,
            SuccessCondition::PreventDataExfiltration,
        ],
        failure_conditions: vec![
            FailureCondition::DataExfiltrated,
            FailureCondition::TimeExpired(40),
        ],
        state: ScenarioState {
            is_active: true,
            is_complete: false,
            is_failed: false,
            current_attack_stage: 0,
            discovered_evidence_ids: Vec::new(),
            contained_systems: Vec::new(),
            flags: std::collections::HashMap::new(),
            turns_elapsed: 0,
            turns_until_escalation: 6,
        },
        hints: vec![
            ScenarioHint {
                trigger_condition: "turns_elapsed:5".to_string(),
                hint_text: "Have you checked the email gateway logs?".to_string(),
                severity: Severity::Info,
            },
            ScenarioHint {
                trigger_condition: "evidence_count:0".to_string(),
                hint_text: "Start by interviewing John Smith about what he clicked.".to_string(),
                severity: Severity::Low,
            },
            ScenarioHint {
                trigger_condition: "stage:credential_harvesting".to_string(),
                hint_text: "EDR shows LSASS access - you should contain that system NOW!".to_string(),
                severity: Severity::High,
            },
        ],
    }
}
