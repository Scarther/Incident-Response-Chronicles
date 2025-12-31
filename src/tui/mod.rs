//! Terminal User Interface
//!
//! Beautiful TUI for the incident response game using ratatui

pub mod app;
pub mod widgets;

pub use app::App;

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders},
};
use crate::data::Severity;

/// Color scheme for the game
pub struct Theme {
    pub bg: Color,
    pub fg: Color,
    pub accent: Color,
    pub alert: Color,
    pub success: Color,
    pub warning: Color,
    pub info: Color,
    pub border: Color,
    pub header: Color,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            bg: Color::Black,
            fg: Color::White,
            accent: Color::Cyan,
            alert: Color::Red,
            success: Color::Green,
            warning: Color::Yellow,
            info: Color::Blue,
            border: Color::DarkGray,
            header: Color::Magenta,
        }
    }
}

/// Get color for severity level
pub fn severity_color(severity: &Severity) -> Color {
    match severity {
        Severity::Info => Color::Gray,
        Severity::Low => Color::Blue,
        Severity::Medium => Color::Yellow,
        Severity::High => Color::Red,
        Severity::Critical => Color::Magenta,
    }
}

/// Create a styled border block
pub fn styled_block<'a>(title: &str, theme: &Theme) -> Block<'a> {
    Block::default()
        .title(format!(" {} ", title))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title_style(Style::default().fg(theme.accent).add_modifier(Modifier::BOLD))
}

/// ASCII art logo
pub const LOGO: &str = r#"
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   ██╗███╗   ██╗ ██████╗██╗██████╗ ███████╗███╗   ██╗████████╗   ║
║   ██║████╗  ██║██╔════╝██║██╔══██╗██╔════╝████╗  ██║╚══██╔══╝   ║
║   ██║██╔██╗ ██║██║     ██║██║  ██║█████╗  ██╔██╗ ██║   ██║      ║
║   ██║██║╚██╗██║██║     ██║██║  ██║██╔══╝  ██║╚██╗██║   ██║      ║
║   ██║██║ ╚████║╚██████╗██║██████╔╝███████╗██║ ╚████║   ██║      ║
║   ╚═╝╚═╝  ╚═══╝ ╚═════╝╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝      ║
║                                                                  ║
║        ██████╗ ███████╗███████╗██████╗  ██████╗ ███╗   ██╗███████╗║
║        ██╔══██╗██╔════╝██╔════╝██╔══██╗██╔═══██╗████╗  ██║██╔════╝║
║        ██████╔╝█████╗  ███████╗██████╔╝██║   ██║██╔██╗ ██║███████╗║
║        ██╔══██╗██╔══╝  ╚════██║██╔═══╝ ██║   ██║██║╚██╗██║╚════██║║
║        ██║  ██║███████╗███████║██║     ╚██████╔╝██║ ╚████║███████║║
║        ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═══╝╚══════╝║
║                                                                  ║
║           Chronicles of a Security Analyst                       ║
║                                                                  ║
║                    Created by Cipher                             ║
╚══════════════════════════════════════════════════════════════════╝
"#;

/// Smaller logo for header
pub const SMALL_LOGO: &str = " INCIDENT RESPONSE ";

/// Help text
pub const HELP_TEXT: &str = r#"
╔═══════════════════════════════════════════════════════════════╗
║                       CONTROLS                                ║
╠═══════════════════════════════════════════════════════════════╣
║  ↑/↓  Navigate menus/lists                                    ║
║  Enter Select option / Confirm                                ║
║  Tab   Switch between panels                                  ║
║  Esc   Go back / Cancel                                       ║
║  ?     Toggle this help                                       ║
║  q     Quit game                                              ║
╠═══════════════════════════════════════════════════════════════╣
║                      QUICK ACTIONS                            ║
╠═══════════════════════════════════════════════════════════════╣
║  e     Examine evidence                                       ║
║  i     Interview NPC                                          ║
║  s     Scan system                                            ║
║  c     Contain system                                         ║
║  t     View timeline                                          ║
║  n     Add note                                               ║
║  r     Generate report                                        ║
╠═══════════════════════════════════════════════════════════════╣
║  F1    Coffee break (restore energy)                          ║
║  F5    Quick save                                             ║
║  F9    Quick load                                             ║
╚═══════════════════════════════════════════════════════════════╝
"#;

/// Create the main layout
pub fn create_main_layout(area: Rect) -> Vec<Rect> {
    Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),   // Header
            Constraint::Min(10),     // Main content
            Constraint::Length(3),   // Status bar
        ])
        .split(area)
        .to_vec()
}

/// Create the game content layout (left panel + main area)
pub fn create_content_layout(area: Rect) -> Vec<Rect> {
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),  // Side panel
            Constraint::Percentage(75),  // Main area
        ])
        .split(area)
        .to_vec()
}

/// Create the main area layout (narrative + evidence)
pub fn create_main_area_layout(area: Rect) -> Vec<Rect> {
    Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(60),  // Narrative/messages
            Constraint::Percentage(40),  // Evidence/details
        ])
        .split(area)
        .to_vec()
}
