//! Timeline and event tracking
//!
//! Tracks the chronological order of events during an incident

use super::{Id, Severity};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Duration};

/// A single event in the incident timeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub id: Id,
    pub timestamp: DateTime<Utc>,
    pub event_type: TimelineEventType,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub source: String,           // What generated this event
    pub affected_systems: Vec<String>,
    pub related_evidence: Vec<Id>,
    pub is_player_action: bool,
    pub is_visible: bool,         // Some events only visible after discovery
    pub tags: Vec<String>,
}

/// Types of timeline events
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimelineEventType {
    // Attack events (from threat actor)
    AttackPhase(String),          // Attack stage progressed
    MalwareExecution,             // Malware ran
    DataAccess,                   // Sensitive data accessed
    LateralMovement,              // Attacker moved to new system
    Exfiltration,                 // Data leaving network

    // System events
    SystemAlert,                  // Security tool alert
    AuthenticationEvent,          // Login/logout
    FileModification,             // File changed
    NetworkConnection,            // New connection
    ProcessExecution,             // Process started
    ConfigChange,                 // System config modified

    // Player actions
    InvestigationStarted,
    EvidenceCollected,
    EvidenceAnalyzed,
    SystemContained,              // System isolated
    ThreatEradicated,             // Malware removed
    ReportGenerated,
    EscalationMade,               // Reported to management/legal

    // NPC events
    UserReport,                   // Employee reported something
    ManagerIntervention,          // Management got involved
    LegalNotification,            // Legal team involved

    // Meta events
    ShiftChange,                  // New shift starts
    BreakTime,                    // Player took a break
    GameSaved,
}

/// The complete incident timeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timeline {
    pub events: Vec<TimelineEvent>,
    pub current_time: DateTime<Utc>,
    pub incident_start: DateTime<Utc>,
    pub game_turn: u32,
    pub time_per_turn: Duration,
}

impl Timeline {
    pub fn new(start_time: DateTime<Utc>) -> Self {
        Self {
            events: Vec::new(),
            current_time: start_time,
            incident_start: start_time,
            game_turn: 0,
            time_per_turn: Duration::minutes(15), // Each turn = 15 min
        }
    }

    /// Add an event to the timeline
    pub fn add_event(&mut self, event: TimelineEvent) {
        // Insert in chronological order
        let pos = self.events
            .iter()
            .position(|e| e.timestamp > event.timestamp)
            .unwrap_or(self.events.len());
        self.events.insert(pos, event);
    }

    /// Advance game time by one turn
    pub fn advance_turn(&mut self) {
        self.game_turn += 1;
        self.current_time = self.current_time + self.time_per_turn;
    }

    /// Get elapsed time since incident start
    pub fn elapsed(&self) -> Duration {
        self.current_time - self.incident_start
    }

    /// Get visible events (those the player has discovered)
    pub fn visible_events(&self) -> Vec<&TimelineEvent> {
        self.events.iter().filter(|e| e.is_visible).collect()
    }

    /// Get events related to a specific system
    pub fn events_for_system(&self, hostname: &str) -> Vec<&TimelineEvent> {
        self.events
            .iter()
            .filter(|e| e.affected_systems.iter().any(|s| s == hostname))
            .collect()
    }

    /// Get events in a time range
    pub fn events_in_range(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> Vec<&TimelineEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .collect()
    }

    /// Get a summary of the timeline for reporting
    pub fn summary(&self) -> String {
        let total = self.events.len();
        let visible = self.visible_events().len();
        let critical = self.events.iter().filter(|e| e.severity == Severity::Critical).count();
        let high = self.events.iter().filter(|e| e.severity == Severity::High).count();

        format!(
            "Timeline: {} events ({} discovered), {} critical, {} high severity. Elapsed: {} hours {} minutes",
            total, visible, critical, high,
            self.elapsed().num_hours(),
            self.elapsed().num_minutes() % 60
        )
    }
}

/// Create a player action event
pub fn player_action(title: &str, description: &str, timestamp: DateTime<Utc>) -> TimelineEvent {
    TimelineEvent {
        id: Id::new(),
        timestamp,
        event_type: TimelineEventType::EvidenceCollected,
        title: title.to_string(),
        description: description.to_string(),
        severity: Severity::Info,
        source: "Player".to_string(),
        affected_systems: Vec::new(),
        related_evidence: Vec::new(),
        is_player_action: true,
        is_visible: true,
        tags: Vec::new(),
    }
}

/// Create an attack event (initially hidden)
pub fn attack_event(
    title: &str,
    description: &str,
    timestamp: DateTime<Utc>,
    severity: Severity,
    systems: Vec<String>,
) -> TimelineEvent {
    TimelineEvent {
        id: Id::new(),
        timestamp,
        event_type: TimelineEventType::AttackPhase("unknown".to_string()),
        title: title.to_string(),
        description: description.to_string(),
        severity,
        source: "Threat Actor".to_string(),
        affected_systems: systems,
        related_evidence: Vec::new(),
        is_player_action: false,
        is_visible: false, // Hidden until discovered
        tags: Vec::new(),
    }
}
