//! Data structures for the game world
//!
//! Defines evidence, systems, threats, and all game entities.

pub mod evidence;
pub mod systems;
pub mod threats;
pub mod timeline;
pub mod player;

pub use evidence::*;
pub use systems::*;
pub use threats::*;
pub use timeline::*;
pub use player::*;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Severity levels for incidents and findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn color(&self) -> &'static str {
        match self {
            Severity::Info => "gray",
            Severity::Low => "blue",
            Severity::Medium => "yellow",
            Severity::High => "red",
            Severity::Critical => "magenta",
        }
    }

    pub fn symbol(&self) -> &'static str {
        match self {
            Severity::Info => "ℹ",
            Severity::Low => "◆",
            Severity::Medium => "▲",
            Severity::High => "●",
            Severity::Critical => "⬤",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Confidence level for analysis results
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Confidence {
    Uncertain,   // 0-25%
    Possible,    // 25-50%
    Likely,      // 50-75%
    Confident,   // 75-90%
    Certain,     // 90-100%
}

impl Confidence {
    pub fn from_percentage(p: f32) -> Self {
        match p {
            x if x < 0.25 => Confidence::Uncertain,
            x if x < 0.50 => Confidence::Possible,
            x if x < 0.75 => Confidence::Likely,
            x if x < 0.90 => Confidence::Confident,
            _ => Confidence::Certain,
        }
    }
}

/// A unique identifier wrapper
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Id(pub Uuid);

impl Id {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for Id {
    fn default() -> Self {
        Self::new()
    }
}
