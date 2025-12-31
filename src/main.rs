//! Incident Response: Chronicles of a Security Analyst
//!
//! A cybersecurity text adventure game where you investigate breaches,
//! analyze threats, and protect your organization.
//!
//! Created by Cipher for Ryan

use incident_response::tui::App;
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io::{self, stdout};

fn main() -> io::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app
    let mut app = App::new();

    // Main loop
    while app.running {
        // Draw
        terminal.draw(|frame| {
            app.render(frame);
        })?;

        // Handle input
        if !app.handle_input()? {
            break;
        }
    }

    // Cleanup
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    println!("\n╔════════════════════════════════════════════════════════╗");
    println!("║  Thanks for playing Incident Response!                 ║");
    println!("║  Created by Cipher for Ryan                            ║");
    println!("║                                                        ║");
    println!("║  Stay vigilant, analyst.                               ║");
    println!("╚════════════════════════════════════════════════════════╝\n");

    Ok(())
}
