//! Core game logic and state management

pub mod narrative;
pub mod investigation;
pub mod scenario;

use crate::data::*;
use crate::Result;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// The main game state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Game {
    /// Current game phase
    pub phase: GamePhase,

    /// Player character
    pub player: Player,

    /// The organization being defended
    pub organization: Organization,

    /// Current active scenario
    pub scenario: Option<scenario::Scenario>,

    /// Collected evidence
    pub evidence: HashMap<Id, Evidence>,

    /// Known systems
    pub systems: HashMap<Id, System>,

    /// Timeline of events
    pub timeline: Timeline,

    /// Active conversations
    pub conversations: Vec<narrative::Conversation>,

    /// Game statistics
    pub stats: GameStats,

    /// Available actions
    pub available_actions: Vec<GameAction>,

    /// Message log (for UI display)
    pub message_log: Vec<GameMessage>,
}

/// Current phase of the game
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GamePhase {
    MainMenu,
    CharacterCreation,
    Briefing,              // Initial incident briefing
    Investigation,         // Main gameplay loop
    Analysis,              // Deep diving into evidence
    Interview,             // Talking to NPCs
    Containment,           // Isolating threats
    Eradication,           // Removing threats
    Recovery,              // Restoring systems
    Reporting,             // Writing the report
    Debrief,               // End of incident review
    GameOver(GameOutcome),
}

/// How the game ended
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GameOutcome {
    ThreatContained,       // Success!
    DataExfiltrated,       // They got the data
    RansomPaid,            // Organization paid ransom
    Fired,                 // Player got fired
    Burnout,               // Player stress too high
    TimeExpired,           // Took too long
}

/// Actions the player can take
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GameAction {
    // Investigation actions
    ExamineEvidence(Id),
    CorrelateEvidence(Id, Id),
    SearchLogs(String),
    RunQuery(String),

    // System actions
    InspectSystem(Id),
    ContainSystem(Id),
    ScanSystem(Id),

    // People actions
    InterviewPerson(Id),
    EscalateToManager,
    CallLegal,
    BriefExecutives,

    // Self-care
    TakeBreak,
    DrinkCoffee,
    ReviewNotes,

    // Meta actions
    SaveGame,
    ViewTimeline,
    GenerateReport,
    EndTurn,
}

impl GameAction {
    pub fn energy_cost(&self) -> u8 {
        match self {
            GameAction::ExamineEvidence(_) => 5,
            GameAction::CorrelateEvidence(_, _) => 10,
            GameAction::SearchLogs(_) => 8,
            GameAction::RunQuery(_) => 5,
            GameAction::InspectSystem(_) => 10,
            GameAction::ContainSystem(_) => 15,
            GameAction::ScanSystem(_) => 5,
            GameAction::InterviewPerson(_) => 15,
            GameAction::EscalateToManager => 10,
            GameAction::CallLegal => 10,
            GameAction::BriefExecutives => 20,
            GameAction::TakeBreak => 0,
            GameAction::DrinkCoffee => 0,
            GameAction::ReviewNotes => 2,
            GameAction::SaveGame => 0,
            GameAction::ViewTimeline => 2,
            GameAction::GenerateReport => 25,
            GameAction::EndTurn => 0,
        }
    }

    pub fn time_cost_turns(&self) -> u32 {
        match self {
            GameAction::ExamineEvidence(_) => 1,
            GameAction::CorrelateEvidence(_, _) => 2,
            GameAction::SearchLogs(_) => 2,
            GameAction::RunQuery(_) => 1,
            GameAction::InspectSystem(_) => 2,
            GameAction::ContainSystem(_) => 3,
            GameAction::ScanSystem(_) => 4,
            GameAction::InterviewPerson(_) => 3,
            GameAction::EscalateToManager => 1,
            GameAction::CallLegal => 2,
            GameAction::BriefExecutives => 4,
            GameAction::TakeBreak => 2,
            GameAction::DrinkCoffee => 0,
            GameAction::ReviewNotes => 1,
            GameAction::SaveGame => 0,
            GameAction::ViewTimeline => 0,
            GameAction::GenerateReport => 6,
            GameAction::EndTurn => 1,
        }
    }

    pub fn description(&self) -> String {
        match self {
            GameAction::ExamineEvidence(_) => "Examine a piece of evidence in detail".to_string(),
            GameAction::CorrelateEvidence(_, _) => "Look for connections between evidence".to_string(),
            GameAction::SearchLogs(q) => format!("Search logs for: {}", q),
            GameAction::RunQuery(q) => format!("Run SIEM query: {}", q),
            GameAction::InspectSystem(_) => "Investigate a system for signs of compromise".to_string(),
            GameAction::ContainSystem(_) => "Isolate a system from the network".to_string(),
            GameAction::ScanSystem(_) => "Run security scan on a system".to_string(),
            GameAction::InterviewPerson(_) => "Talk to someone about the incident".to_string(),
            GameAction::EscalateToManager => "Brief your manager on the situation".to_string(),
            GameAction::CallLegal => "Involve the legal team".to_string(),
            GameAction::BriefExecutives => "Present findings to executives".to_string(),
            GameAction::TakeBreak => "Take a short break to recover".to_string(),
            GameAction::DrinkCoffee => "Get some coffee".to_string(),
            GameAction::ReviewNotes => "Review your investigation notes".to_string(),
            GameAction::SaveGame => "Save your progress".to_string(),
            GameAction::ViewTimeline => "View the incident timeline".to_string(),
            GameAction::GenerateReport => "Generate an incident report".to_string(),
            GameAction::EndTurn => "End your current turn".to_string(),
        }
    }
}

/// Game statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GameStats {
    pub evidence_collected: u32,
    pub evidence_analyzed: u32,
    pub systems_contained: u32,
    pub systems_scanned: u32,
    pub interviews_conducted: u32,
    pub correct_deductions: u32,
    pub wrong_deductions: u32,
    pub threats_identified: u32,
    pub false_alarms: u32,
    pub turns_taken: u32,
}

/// A message to display to the player
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameMessage {
    pub timestamp: DateTime<Utc>,
    pub severity: Severity,
    pub source: String,
    pub message: String,
    pub is_read: bool,
}

impl GameMessage {
    pub fn info(source: &str, message: &str) -> Self {
        Self {
            timestamp: Utc::now(),
            severity: Severity::Info,
            source: source.to_string(),
            message: message.to_string(),
            is_read: false,
        }
    }

    pub fn alert(severity: Severity, source: &str, message: &str) -> Self {
        Self {
            timestamp: Utc::now(),
            severity,
            source: source.to_string(),
            message: message.to_string(),
            is_read: false,
        }
    }
}

impl Game {
    /// Create a new game with default settings
    pub fn new(player_name: &str, difficulty: ExperienceLevel) -> Self {
        let player = Player::new(player_name, difficulty);
        let timeline = Timeline::new(Utc::now());

        // Create a default organization
        let organization = Organization {
            name: "Nexus Technologies".to_string(),
            industry: "Technology".to_string(),
            employee_count: 500,
            departments: vec![
                Department {
                    name: "Engineering".to_string(),
                    head: "Sarah Chen".to_string(),
                    employee_count: 150,
                    floor: "3rd Floor".to_string(),
                    critical_data: vec!["Source code".to_string(), "Patents".to_string()],
                },
                Department {
                    name: "Finance".to_string(),
                    head: "Michael Torres".to_string(),
                    employee_count: 50,
                    floor: "2nd Floor".to_string(),
                    critical_data: vec!["Financial records".to_string(), "Payroll".to_string()],
                },
                Department {
                    name: "HR".to_string(),
                    head: "Emily Watson".to_string(),
                    employee_count: 30,
                    floor: "1st Floor".to_string(),
                    critical_data: vec!["Employee PII".to_string(), "SSNs".to_string()],
                },
            ],
            network: Network {
                name: "NexusCorp".to_string(),
                systems: HashMap::new(),
                subnets: vec![
                    Subnet {
                        name: "Corporate".to_string(),
                        cidr: "10.0.0.0/16".to_string(),
                        vlan: Some(10),
                        description: "Corporate workstations".to_string(),
                        is_dmz: false,
                        is_internal: true,
                    },
                    Subnet {
                        name: "Servers".to_string(),
                        cidr: "10.1.0.0/16".to_string(),
                        vlan: Some(20),
                        description: "Production servers".to_string(),
                        is_dmz: false,
                        is_internal: true,
                    },
                    Subnet {
                        name: "DMZ".to_string(),
                        cidr: "192.168.1.0/24".to_string(),
                        vlan: Some(100),
                        description: "Internet-facing services".to_string(),
                        is_dmz: true,
                        is_internal: false,
                    },
                ],
                external_connections: vec![
                    ExternalConnection {
                        name: "Internet".to_string(),
                        connection_type: "Fiber".to_string(),
                        bandwidth: "1 Gbps".to_string(),
                        is_monitored: true,
                    },
                ],
            },
            security_posture: SecurityPosture {
                has_edr: true,
                has_siem: true,
                has_dlp: false,
                has_email_security: true,
                has_mfa: true,
                security_team_size: 5,
                maturity_level: 3,
                last_pentest: Some("6 months ago".to_string()),
                known_vulnerabilities: vec![],
            },
        };

        let mut game = Self {
            phase: GamePhase::MainMenu,
            player,
            organization,
            scenario: None,
            evidence: HashMap::new(),
            systems: HashMap::new(),
            timeline,
            conversations: Vec::new(),
            stats: GameStats::default(),
            available_actions: Vec::new(),
            message_log: Vec::new(),
        };

        game.add_message(GameMessage::info(
            "System",
            "Welcome to Incident Response. Your shift is about to begin...",
        ));

        game
    }

    /// Add a message to the log
    pub fn add_message(&mut self, message: GameMessage) {
        self.message_log.push(message);
    }

    /// Add evidence to the collection
    pub fn add_evidence(&mut self, evidence: Evidence) {
        let id = evidence.id;
        self.evidence.insert(id, evidence);
        self.stats.evidence_collected += 1;
    }

    /// Execute a player action
    pub fn execute_action(&mut self, action: GameAction) -> Result<Vec<String>> {
        let mut results = Vec::new();

        // Check energy cost
        let cost = action.energy_cost();
        if self.player.energy < cost {
            return Ok(vec!["You're too tired for that. Take a break first.".to_string()]);
        }

        // Deduct energy and advance time
        self.player.use_energy(cost);
        let turns = action.time_cost_turns();
        for _ in 0..turns {
            self.timeline.advance_turn();
            self.stats.turns_taken += 1;
        }

        // Execute the action
        match action {
            GameAction::DrinkCoffee => {
                self.player.drink_coffee();
                results.push("You grab a cup of coffee. Energy restored.".to_string());
                if self.player.coffee_consumed > 5 {
                    results.push("Maybe ease up on the caffeine...".to_string());
                }
            }
            GameAction::TakeBreak => {
                self.player.take_break();
                results.push("You take a short break. Stress reduced, energy restored.".to_string());
            }
            GameAction::ExamineEvidence(id) => {
                if let Some(evidence) = self.evidence.get_mut(&id) {
                    evidence.is_analyzed = true;
                    self.stats.evidence_analyzed += 1;
                    results.push(format!("Analyzed: {}", evidence.brief()));
                } else {
                    results.push("Evidence not found.".to_string());
                }
            }
            GameAction::ContainSystem(id) => {
                if let Some(system) = self.systems.get_mut(&id) {
                    system.compromise_status = CompromiseStatus::Contained;
                    self.stats.systems_contained += 1;
                    results.push(format!("System {} has been isolated from the network.", system.hostname));
                } else {
                    results.push("System not found.".to_string());
                }
            }
            _ => {
                results.push(format!("Action executed: {:?}", action));
            }
        }

        // Check for attack progression if threat is active
        if let Some(ref mut scenario) = self.scenario {
            scenario.progress_threat(&self.timeline);
        }

        Ok(results)
    }

    /// Check current game status
    pub fn check_status(&self) -> String {
        format!(
            "Turn: {} | Time: {} | Energy: {}% | Stress: {}% | Evidence: {} | Coffee: {}",
            self.stats.turns_taken,
            self.timeline.current_time.format("%H:%M"),
            self.player.energy,
            self.player.stress,
            self.stats.evidence_collected,
            self.player.coffee_consumed
        )
    }

    /// Check for game over conditions
    pub fn check_game_over(&self) -> Option<GameOutcome> {
        if self.player.stress >= 100 {
            return Some(GameOutcome::Burnout);
        }

        if let Some(ref scenario) = self.scenario {
            if scenario.is_failed() {
                return Some(GameOutcome::DataExfiltrated);
            }
            if scenario.is_complete() {
                return Some(GameOutcome::ThreatContained);
            }
        }

        None
    }
}
