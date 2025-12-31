//! Player state and progression

use super::Id;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Achievement IDs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Achievement {
    // Blue Team achievements
    FirstBlood,           // Complete first incident
    SpeedDemon,           // Contain threat in under 10 turns
    Thorough,             // Collect all evidence in a scenario
    Diplomat,             // Interview all NPCs successfully
    CaffeinatedI,         // Drink 5 coffees
    CaffeinatedII,        // Drink 10 coffees
    CaffeinatedIII,       // Drink 20 coffees (achievement unlocked: heart palpitations)
    Perfectionist,        // Complete with 100% evidence analyzed
    NightOwl,             // Play for 2+ hours
    ZeroFalsePositives,   // Complete without false positives
    CrisisAverted,        // Stop ransomware before encryption
    MoleCatcher,          // Identify insider threat

    // Red Team achievements
    Ghost,                // Complete with <20% detection
    LoudAndProud,         // Complete with >90% detection
    DomainDomination,     // Achieve Domain Admin
    DataThief,            // Exfiltrate 10+ files
    SocialButterfly,      // Social engineer 3+ targets
    Persistent,           // Deploy implants on 5+ systems
    SpeedRunner,          // Complete in under 15 turns
    NoTraceLeft,          // Complete without triggering any alerts

    // Meta achievements
    BothSides,            // Complete both Blue and Red team scenarios
    MasterAnalyst,        // Complete all Blue Team scenarios
    MasterOperator,       // Complete all Red Team scenarios
    Completionist,        // Unlock all other achievements
    EasterEggHunter,      // Find all easter eggs
    L33tHax0r,            // Enter the konami code
    TheMatrix,            // Use the 'matrix' command
    CoffeeAddict,         // Drink 100 total coffees
}

impl Achievement {
    pub fn name(&self) -> &'static str {
        match self {
            Achievement::FirstBlood => "First Blood",
            Achievement::SpeedDemon => "Speed Demon",
            Achievement::Thorough => "Thorough",
            Achievement::Diplomat => "Diplomat",
            Achievement::CaffeinatedI => "Caffeinated I",
            Achievement::CaffeinatedII => "Caffeinated II",
            Achievement::CaffeinatedIII => "Caffeinated III",
            Achievement::Perfectionist => "Perfectionist",
            Achievement::NightOwl => "Night Owl",
            Achievement::ZeroFalsePositives => "Zero False Positives",
            Achievement::CrisisAverted => "Crisis Averted",
            Achievement::MoleCatcher => "Mole Catcher",
            Achievement::Ghost => "Ghost",
            Achievement::LoudAndProud => "Loud and Proud",
            Achievement::DomainDomination => "Domain Domination",
            Achievement::DataThief => "Data Thief",
            Achievement::SocialButterfly => "Social Butterfly",
            Achievement::Persistent => "Persistent",
            Achievement::SpeedRunner => "Speed Runner",
            Achievement::NoTraceLeft => "No Trace Left",
            Achievement::BothSides => "Both Sides",
            Achievement::MasterAnalyst => "Master Analyst",
            Achievement::MasterOperator => "Master Operator",
            Achievement::Completionist => "Completionist",
            Achievement::EasterEggHunter => "Easter Egg Hunter",
            Achievement::L33tHax0r => "L33T HAX0R",
            Achievement::TheMatrix => "The Matrix",
            Achievement::CoffeeAddict => "Coffee Addict",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Achievement::FirstBlood => "Complete your first incident response",
            Achievement::SpeedDemon => "Contain a threat in under 10 turns",
            Achievement::Thorough => "Collect all evidence in a scenario",
            Achievement::Diplomat => "Successfully interview all NPCs",
            Achievement::CaffeinatedI => "Drink 5 coffees in one game",
            Achievement::CaffeinatedII => "Drink 10 coffees in one game",
            Achievement::CaffeinatedIII => "Drink 20 coffees. Your hands are shaking.",
            Achievement::Perfectionist => "Analyze 100% of evidence",
            Achievement::NightOwl => "Play for 2+ hours straight",
            Achievement::ZeroFalsePositives => "Complete without any false positives",
            Achievement::CrisisAverted => "Stop ransomware before encryption spreads",
            Achievement::MoleCatcher => "Successfully identify an insider threat",
            Achievement::Ghost => "Complete Red Team with <20% detection score",
            Achievement::LoudAndProud => "Complete Red Team with >90% detection. YOLO.",
            Achievement::DomainDomination => "Achieve Domain Admin access",
            Achievement::DataThief => "Exfiltrate 10+ files",
            Achievement::SocialButterfly => "Social engineer 3+ different targets",
            Achievement::Persistent => "Deploy implants on 5+ systems",
            Achievement::SpeedRunner => "Complete Red Team in under 15 turns",
            Achievement::NoTraceLeft => "Complete without triggering SOC alerts",
            Achievement::BothSides => "Complete scenarios as both Blue and Red team",
            Achievement::MasterAnalyst => "Complete all Blue Team scenarios",
            Achievement::MasterOperator => "Complete all Red Team scenarios",
            Achievement::Completionist => "Unlock all other achievements",
            Achievement::EasterEggHunter => "Find all easter eggs",
            Achievement::L33tHax0r => "↑↑↓↓←→←→BA",
            Achievement::TheMatrix => "There is no spoon",
            Achievement::CoffeeAddict => "Drink 100 total coffees across all games",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            Achievement::FirstBlood => "🩸",
            Achievement::SpeedDemon => "⚡",
            Achievement::Thorough => "🔍",
            Achievement::Diplomat => "🤝",
            Achievement::CaffeinatedI | Achievement::CaffeinatedII | Achievement::CaffeinatedIII => "☕",
            Achievement::Perfectionist => "💯",
            Achievement::NightOwl => "🦉",
            Achievement::ZeroFalsePositives => "🎯",
            Achievement::CrisisAverted => "🛡️",
            Achievement::MoleCatcher => "🕵️",
            Achievement::Ghost => "👻",
            Achievement::LoudAndProud => "📢",
            Achievement::DomainDomination => "👑",
            Achievement::DataThief => "💾",
            Achievement::SocialButterfly => "🦋",
            Achievement::Persistent => "🔗",
            Achievement::SpeedRunner => "🏃",
            Achievement::NoTraceLeft => "🌫️",
            Achievement::BothSides => "⚖️",
            Achievement::MasterAnalyst => "🛡️",
            Achievement::MasterOperator => "☠️",
            Achievement::Completionist => "🏆",
            Achievement::EasterEggHunter => "🥚",
            Achievement::L33tHax0r => "💀",
            Achievement::TheMatrix => "🐰",
            Achievement::CoffeeAddict => "🫖",
        }
    }
}

/// The player character
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Player {
    pub name: String,
    pub title: String,           // "Junior Analyst", "Senior IR Lead"
    pub experience_level: ExperienceLevel,

    // Stats that affect gameplay
    pub stress: u8,              // 0-100, too high = mistakes
    pub energy: u8,              // 0-100, depletes over time
    pub reputation: i32,         // Company standing, -100 to 100
    pub coffee_consumed: u32,    // Just for fun

    // Skills that improve over time
    pub skills: PlayerSkills,

    // Inventory
    pub notes: Vec<String>,
    pub bookmarks: Vec<Id>,      // Saved evidence references

    // Progress tracking
    pub incidents_resolved: u32,
    pub false_positives: u32,
    pub threats_missed: u32,
    pub total_playtime_minutes: u32,

    // Scoring
    pub score: GameScore,

    // Achievements
    pub achievements: HashSet<Achievement>,
    pub total_coffees_ever: u32,  // Across all games
    pub easter_eggs_found: HashSet<String>,
}

/// Score tracking for both Blue and Red teams
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GameScore {
    // Blue Team scoring
    pub evidence_collected: u32,
    pub evidence_analyzed: u32,
    pub systems_contained: u32,
    pub interviews_conducted: u32,
    pub iocs_identified: u32,
    pub correct_conclusions: u32,
    pub time_bonus: i32,         // Bonus/penalty based on response time

    // Red Team scoring
    pub systems_compromised: u32,
    pub credentials_harvested: u32,
    pub data_exfiltrated: u32,
    pub persistence_established: u32,
    pub stealth_bonus: i32,      // Bonus for low detection

    // Universal
    pub total_points: i32,
}

impl GameScore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add points for Blue Team actions
    pub fn blue_team_action(&mut self, action: &str) {
        match action {
            "collect_evidence" => {
                self.evidence_collected += 1;
                self.total_points += 50;
            }
            "analyze_evidence" => {
                self.evidence_analyzed += 1;
                self.total_points += 100;
            }
            "contain_system" => {
                self.systems_contained += 1;
                self.total_points += 150;
            }
            "interview" => {
                self.interviews_conducted += 1;
                self.total_points += 75;
            }
            "identify_ioc" => {
                self.iocs_identified += 1;
                self.total_points += 50;
            }
            "correct_conclusion" => {
                self.correct_conclusions += 1;
                self.total_points += 200;
            }
            _ => {}
        }
    }

    /// Add points for Red Team actions
    pub fn red_team_action(&mut self, action: &str) {
        match action {
            "compromise_system" => {
                self.systems_compromised += 1;
                self.total_points += 100;
            }
            "harvest_creds" => {
                self.credentials_harvested += 1;
                self.total_points += 150;
            }
            "exfiltrate" => {
                self.data_exfiltrated += 1;
                self.total_points += 200;
            }
            "persistence" => {
                self.persistence_established += 1;
                self.total_points += 100;
            }
            "stealth_bonus" => {
                self.stealth_bonus += 50;
                self.total_points += 50;
            }
            "domain_admin" => {
                self.total_points += 500;
            }
            _ => {}
        }
    }

    /// Calculate final score with bonuses
    pub fn calculate_final(&mut self, detection_score: u8) -> i32 {
        // Stealth bonus for Red Team (low detection = more points)
        if detection_score < 20 {
            self.stealth_bonus = 500;
            self.total_points += 500;
        } else if detection_score < 40 {
            self.stealth_bonus = 250;
            self.total_points += 250;
        } else if detection_score > 80 {
            self.stealth_bonus = -200;
            self.total_points -= 200;
        }
        self.total_points
    }

    /// Get letter grade based on points
    pub fn grade(&self) -> &'static str {
        match self.total_points {
            p if p >= 1500 => "S",
            p if p >= 1200 => "A",
            p if p >= 900 => "B",
            p if p >= 600 => "C",
            p if p >= 300 => "D",
            _ => "F",
        }
    }
}

/// Player experience levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExperienceLevel {
    Intern,              // Tutorial mode, more hints
    JuniorAnalyst,       // Standard difficulty
    SeniorAnalyst,       // Less hand-holding
    IRLead,              // Time pressure
    CISO,                // Hard mode - business consequences
}

impl ExperienceLevel {
    pub fn description(&self) -> &'static str {
        match self {
            ExperienceLevel::Intern => "Learning the ropes. Helpful hints enabled.",
            ExperienceLevel::JuniorAnalyst => "Standard experience. Some guidance available.",
            ExperienceLevel::SeniorAnalyst => "You know what you're doing. Limited hints.",
            ExperienceLevel::IRLead => "Lead the response. Time pressure active.",
            ExperienceLevel::CISO => "Executive decisions. Business impact matters.",
        }
    }

    pub fn hint_frequency(&self) -> f32 {
        match self {
            ExperienceLevel::Intern => 1.0,         // Always show hints
            ExperienceLevel::JuniorAnalyst => 0.7,  // Often
            ExperienceLevel::SeniorAnalyst => 0.3,  // Sometimes
            ExperienceLevel::IRLead => 0.1,         // Rarely
            ExperienceLevel::CISO => 0.0,           // Never
        }
    }
}

/// Player skills that affect investigation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlayerSkills {
    pub log_analysis: u8,        // 1-10, speed/accuracy of log review
    pub malware_analysis: u8,    // 1-10, understanding malware behavior
    pub network_forensics: u8,   // 1-10, understanding network traffic
    pub social_engineering: u8,  // 1-10, interviewing effectiveness
    pub documentation: u8,       // 1-10, report quality
    pub communication: u8,       // 1-10, stakeholder management
}

impl Default for PlayerSkills {
    fn default() -> Self {
        Self {
            log_analysis: 5,
            malware_analysis: 5,
            network_forensics: 5,
            social_engineering: 5,
            documentation: 5,
            communication: 5,
        }
    }
}

impl Player {
    pub fn new(name: &str, level: ExperienceLevel) -> Self {
        let skills = match level {
            ExperienceLevel::Intern => PlayerSkills {
                log_analysis: 2,
                malware_analysis: 1,
                network_forensics: 2,
                social_engineering: 3,
                documentation: 2,
                communication: 3,
            },
            ExperienceLevel::JuniorAnalyst => PlayerSkills::default(),
            ExperienceLevel::SeniorAnalyst => PlayerSkills {
                log_analysis: 7,
                malware_analysis: 6,
                network_forensics: 7,
                social_engineering: 6,
                documentation: 7,
                communication: 6,
            },
            ExperienceLevel::IRLead | ExperienceLevel::CISO => PlayerSkills {
                log_analysis: 8,
                malware_analysis: 7,
                network_forensics: 8,
                social_engineering: 8,
                documentation: 9,
                communication: 9,
            },
        };

        Self {
            name: name.to_string(),
            title: level.to_string(),
            experience_level: level,
            stress: 0,
            energy: 100,
            reputation: 50,
            coffee_consumed: 0,
            skills,
            notes: Vec::new(),
            bookmarks: Vec::new(),
            incidents_resolved: 0,
            false_positives: 0,
            threats_missed: 0,
            total_playtime_minutes: 0,
            score: GameScore::new(),
            achievements: HashSet::new(),
            total_coffees_ever: 0,
            easter_eggs_found: HashSet::new(),
        }
    }

    /// Unlock an achievement
    pub fn unlock_achievement(&mut self, achievement: Achievement) -> bool {
        if self.achievements.insert(achievement) {
            // Achievement was newly unlocked
            true
        } else {
            // Already had it
            false
        }
    }

    /// Check if player has achievement
    pub fn has_achievement(&self, achievement: Achievement) -> bool {
        self.achievements.contains(&achievement)
    }

    /// Find an easter egg
    pub fn find_easter_egg(&mut self, egg: &str) -> bool {
        self.easter_eggs_found.insert(egg.to_string())
    }

    /// Add stress (from pressure, mistakes, etc.)
    pub fn add_stress(&mut self, amount: u8) {
        self.stress = (self.stress + amount).min(100);
    }

    /// Reduce stress (from breaks, success, etc.)
    pub fn reduce_stress(&mut self, amount: u8) {
        self.stress = self.stress.saturating_sub(amount);
    }

    /// Use energy for actions
    pub fn use_energy(&mut self, amount: u8) {
        self.energy = self.energy.saturating_sub(amount);
    }

    /// Restore energy (breaks, coffee)
    pub fn restore_energy(&mut self, amount: u8) {
        self.energy = (self.energy + amount).min(100);
    }

    /// Drink coffee!
    pub fn drink_coffee(&mut self) {
        self.coffee_consumed += 1;
        self.restore_energy(20);
        if self.coffee_consumed > 5 {
            // Too much coffee increases stress
            self.add_stress(5);
        }
    }

    /// Check if player is exhausted
    pub fn is_exhausted(&self) -> bool {
        self.energy < 20
    }

    /// Check if player is stressed out
    pub fn is_stressed(&self) -> bool {
        self.stress > 80
    }

    /// Get effectiveness modifier based on current state
    pub fn effectiveness(&self) -> f32 {
        let energy_mod = self.energy as f32 / 100.0;
        let stress_mod = 1.0 - (self.stress as f32 / 200.0); // Stress has less impact
        energy_mod * stress_mod
    }

    /// Take a break
    pub fn take_break(&mut self) {
        self.restore_energy(30);
        self.reduce_stress(20);
    }
}

impl std::fmt::Display for ExperienceLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExperienceLevel::Intern => write!(f, "Security Intern"),
            ExperienceLevel::JuniorAnalyst => write!(f, "Junior SOC Analyst"),
            ExperienceLevel::SeniorAnalyst => write!(f, "Senior Security Analyst"),
            ExperienceLevel::IRLead => write!(f, "Incident Response Lead"),
            ExperienceLevel::CISO => write!(f, "CISO"),
        }
    }
}

/// NPCs the player can interact with
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NPC {
    pub id: Id,
    pub name: String,
    pub title: String,
    pub department: String,
    pub personality: Personality,
    pub knowledge: Vec<String>,   // What they know about
    pub relationship: i32,        // -100 to 100 with player
    pub is_available: bool,
    pub location: String,
}

/// NPC personality traits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Personality {
    pub cooperativeness: u8,     // 1-10
    pub technical_skill: u8,     // 1-10
    pub stress_tolerance: u8,    // 1-10
    pub honesty: u8,             // 1-10 (low = might lie)
    pub traits: Vec<String>,     // "helpful", "nervous", "defensive"
}

impl NPC {
    pub fn new(name: &str, title: &str, department: &str) -> Self {
        Self {
            id: Id::new(),
            name: name.to_string(),
            title: title.to_string(),
            department: department.to_string(),
            personality: Personality {
                cooperativeness: 5,
                technical_skill: 5,
                stress_tolerance: 5,
                honesty: 8,
                traits: Vec::new(),
            },
            knowledge: Vec::new(),
            relationship: 0,
            is_available: true,
            location: "Office".to_string(),
        }
    }

    /// How willing is this NPC to help right now?
    pub fn willingness_to_help(&self, player_reputation: i32) -> f32 {
        let base = self.personality.cooperativeness as f32 / 10.0;
        let relationship_mod = (self.relationship as f32 + player_reputation as f32) / 200.0;
        (base + relationship_mod).clamp(0.0, 1.0)
    }
}
