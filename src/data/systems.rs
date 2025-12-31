//! System and network infrastructure definitions

use super::Id;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Types of systems in the organization
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SystemType {
    Workstation,
    Server,
    DomainController,
    FileServer,
    DatabaseServer,
    WebServer,
    MailServer,
    Firewall,
    Router,
    Switch,
    VPN,
    Laptop,
    MobileDevice,
    IoTDevice,
    CloudInstance,
}

impl SystemType {
    pub fn icon(&self) -> &'static str {
        match self {
            SystemType::Workstation => "🖥️",
            SystemType::Server => "🖧",
            SystemType::DomainController => "👑",
            SystemType::FileServer => "📁",
            SystemType::DatabaseServer => "🗄️",
            SystemType::WebServer => "🌐",
            SystemType::MailServer => "📧",
            SystemType::Firewall => "🔥",
            SystemType::Router => "📡",
            SystemType::Switch => "🔀",
            SystemType::VPN => "🔒",
            SystemType::Laptop => "💻",
            SystemType::MobileDevice => "📱",
            SystemType::IoTDevice => "📟",
            SystemType::CloudInstance => "☁️",
        }
    }
}

/// Operating system types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperatingSystem {
    Windows10,
    Windows11,
    WindowsServer2019,
    WindowsServer2022,
    Ubuntu,
    CentOS,
    RHEL,
    Debian,
    MacOS,
    Ios,
    Android,
    Firmware,
    Unknown,
}

/// Compromise status of a system
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompromiseStatus {
    Clean,                      // No signs of compromise
    Suspicious,                 // Anomalous behavior detected
    Compromised,                // Confirmed compromise
    Contained,                  // Isolated from network
    Remediated,                 // Cleaned and restored
    Unknown,                    // Haven't investigated yet
}

/// A system in the organization's network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct System {
    pub id: Id,
    pub hostname: String,
    pub ip_address: String,
    pub mac_address: String,
    pub system_type: SystemType,
    pub os: OperatingSystem,
    pub department: String,
    pub owner: String,
    pub location: String,        // "Building A, Floor 2", "AWS us-east-1"
    pub criticality: u8,         // 1-10, how important is this system
    pub compromise_status: CompromiseStatus,
    pub installed_software: Vec<String>,
    pub open_ports: Vec<u16>,
    pub last_seen: String,
    pub notes: Vec<String>,
    pub connected_systems: Vec<Id>,
}

impl System {
    pub fn workstation(hostname: &str, ip: &str, owner: &str, department: &str) -> Self {
        Self {
            id: Id::new(),
            hostname: hostname.to_string(),
            ip_address: ip.to_string(),
            mac_address: format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                rand::random::<u8>(), rand::random::<u8>(),
                rand::random::<u8>(), rand::random::<u8>(),
                rand::random::<u8>(), rand::random::<u8>()),
            system_type: SystemType::Workstation,
            os: OperatingSystem::Windows10,
            department: department.to_string(),
            owner: owner.to_string(),
            location: "Main Office".to_string(),
            criticality: 3,
            compromise_status: CompromiseStatus::Unknown,
            installed_software: Vec::new(),
            open_ports: Vec::new(),
            last_seen: "Online".to_string(),
            notes: Vec::new(),
            connected_systems: Vec::new(),
        }
    }

    pub fn server(hostname: &str, ip: &str, server_type: SystemType, criticality: u8) -> Self {
        Self {
            id: Id::new(),
            hostname: hostname.to_string(),
            ip_address: ip.to_string(),
            mac_address: format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                rand::random::<u8>(), rand::random::<u8>(),
                rand::random::<u8>(), rand::random::<u8>(),
                rand::random::<u8>(), rand::random::<u8>()),
            system_type: server_type,
            os: OperatingSystem::WindowsServer2019,
            department: "IT".to_string(),
            owner: "IT Operations".to_string(),
            location: "Data Center".to_string(),
            criticality,
            compromise_status: CompromiseStatus::Unknown,
            installed_software: Vec::new(),
            open_ports: Vec::new(),
            last_seen: "Online".to_string(),
            notes: Vec::new(),
            connected_systems: Vec::new(),
        }
    }
}

/// The organization's network structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Network {
    pub name: String,
    pub systems: HashMap<Id, System>,
    pub subnets: Vec<Subnet>,
    pub external_connections: Vec<ExternalConnection>,
}

/// A network subnet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subnet {
    pub name: String,
    pub cidr: String,
    pub vlan: Option<u16>,
    pub description: String,
    pub is_dmz: bool,
    pub is_internal: bool,
}

/// External network connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalConnection {
    pub name: String,
    pub connection_type: String,  // "Internet", "VPN", "Partner Network"
    pub bandwidth: String,
    pub is_monitored: bool,
}

/// The organization being defended
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub name: String,
    pub industry: String,
    pub employee_count: u32,
    pub departments: Vec<Department>,
    pub network: Network,
    pub security_posture: SecurityPosture,
}

/// A department in the organization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Department {
    pub name: String,
    pub head: String,
    pub employee_count: u32,
    pub floor: String,
    pub critical_data: Vec<String>,  // What sensitive data they handle
}

/// Organization's security capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPosture {
    pub has_edr: bool,
    pub has_siem: bool,
    pub has_dlp: bool,
    pub has_email_security: bool,
    pub has_mfa: bool,
    pub security_team_size: u32,
    pub maturity_level: u8,         // 1-5 CMMI-like
    pub last_pentest: Option<String>,
    pub known_vulnerabilities: Vec<String>,
}
