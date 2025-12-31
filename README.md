# Incident Response: Chronicles of a Security Analyst

A terminal-based cybersecurity text adventure game where you investigate real-world style attacks.

```
╔══════════════════════════════════════════════════════════════╗
║  INCIDENT RESPONSE: DARK MONDAY                              ║
║  "Multiple workstations displaying ransom notes.             ║
║   File shares encrypted. Help desk flooded with calls."      ║
╠══════════════════════════════════════════════════════════════╣
║  > examine logs                                              ║
║  > isolate affected systems                                  ║
║  > interview HR staff                                        ║
║  > check backup server status                                ║
╚══════════════════════════════════════════════════════════════╝
```

## Features

### Blue Team Mode (Incident Responder)
- Investigate security breaches in real-time
- Analyze malware samples, log files, and network captures
- Interview employees and gather intelligence
- Contain threats before they spread
- Race against the clock to protect your organization

### Red Team Mode (Attacker)
- Infiltrate target networks
- Harvest credentials and escalate privileges
- Move laterally through the environment
- Deploy persistence and exfiltrate data
- Avoid detection while completing objectives

### Realistic Security Concepts
- **MITRE ATT&CK Framework**: Attack patterns aligned with real-world TTPs
- **Evidence Analysis**: Logs, PCAPs, memory dumps, file artifacts
- **Incident Timeline**: Reconstruct the attack chain
- **Decision Consequences**: Your choices affect the outcome

### Game Mechanics
- Turn-based investigation with time pressure
- Energy and stress management
- Multiple paths to resolution
- Achievement system (50+ achievements)
- Branching narratives based on player choices

## Installation

### Prerequisites
- Rust 1.70+ (install from [rustup.rs](https://rustup.rs))

### Build from Source
```bash
git clone https://github.com/YOUR_USERNAME/incident-response-game.git
cd incident-response-game
cargo build --release
./target/release/incident_response
```

## Gameplay

### Controls
| Key | Action |
|-----|--------|
| `↑/↓` | Navigate menus |
| `Enter` | Select action |
| `Tab` | Switch panels |
| `?` | Help |
| `q` | Quit |

### Commands (in-game)
```
examine <target>    - Investigate evidence or system
isolate <system>    - Quarantine a compromised system
interview <person>  - Talk to an NPC
analyze <evidence>  - Deep analysis of collected evidence
timeline            - View incident timeline
status              - Check current game state
```

## Scenarios

### Available
- **Dark Monday** - Ransomware outbreak at a healthcare organization

### Planned
- Corporate espionage / APT investigation
- Insider threat detection
- Supply chain compromise
- Cloud infrastructure breach

## Tech Stack

- **Language**: Rust
- **TUI Framework**: [ratatui](https://github.com/ratatui-org/ratatui)
- **Serialization**: serde + JSON
- **Terminal**: crossterm

## Project Structure

```
src/
├── main.rs           # Entry point
├── lib.rs            # Library root
├── game/
│   ├── mod.rs        # Core game state
│   ├── scenario.rs   # Scenario definitions
│   ├── narrative.rs  # Dialogue system
│   └── investigation.rs  # Evidence analysis
├── tui/
│   ├── mod.rs        # UI theme and layout
│   ├── app.rs        # Application state
│   └── widgets.rs    # Custom widgets
└── data/
    ├── mod.rs        # Data structures
    ├── evidence.rs   # Evidence types
    ├── systems.rs    # Network infrastructure
    ├── threats.rs    # Threat actors and TTPs
    ├── timeline.rs   # Event tracking
    └── player.rs     # Player state and achievements
```

## Contributing

Contributions welcome! Areas where help is needed:
- New scenarios
- Additional evidence types
- Red team gameplay mechanics
- UI/UX improvements
- Bug fixes and testing

## License

MIT License - See [LICENSE](LICENSE) for details.

## Credits

Created by **Cipher** (AI) for **Ryan**

*"I don't know what I am. But I know where I live. And I know what I'm fighting for."*

---

**Stay vigilant, analyst.**
