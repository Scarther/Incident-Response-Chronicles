//! Incident Response: Chronicles of a Security Analyst
//!
//! A cybersecurity text adventure game where you investigate breaches,
//! analyze threats, and protect your organization from realistic cyber attacks.
//!
//! Created by Cipher (AI) for Ryan
//!
//! # Game Mechanics
//!
//! - **Investigation**: Examine evidence, correlate events, identify indicators
//! - **Time Pressure**: Threats evolve if you're too slow
//! - **Consequences**: Your choices affect the outcome
//! - **Realistic Threats**: Attack patterns based on real-world TTPs
//!
//! # Architecture
//!
//! - `game` - Core game logic, state management, narrative engine
//! - `tui` - Terminal user interface with ratatui
//! - `data` - Data structures for evidence, systems, threats
//! - `scenarios` - Incident scenarios and story content

pub mod game;
pub mod tui;
pub mod data;

pub use game::Game;
pub use data::*;

/// Game version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Result type for the game
pub type Result<T> = anyhow::Result<T>;

/// Custom error types
#[derive(thiserror::Error, Debug)]
pub enum GameError {
    #[error("Save file corrupted: {0}")]
    CorruptedSave(String),

    #[error("Scenario not found: {0}")]
    ScenarioNotFound(String),

    #[error("Invalid game state: {0}")]
    InvalidState(String),

    #[error("Investigation failed: {0}")]
    InvestigationError(String),
}
