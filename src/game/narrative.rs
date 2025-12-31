//! Narrative engine for dialogue and story
//!
//! Handles branching conversations, NPC interactions, and story events

use crate::data::{Id, NPC, Severity};
use serde::{Deserialize, Serialize};

/// A conversation with an NPC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conversation {
    pub id: Id,
    pub npc: NPC,
    pub history: Vec<DialogueLine>,
    pub current_node: Option<DialogueNode>,
    pub is_complete: bool,
    pub outcome: Option<ConversationOutcome>,
}

/// A single line of dialogue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DialogueLine {
    pub speaker: String,
    pub text: String,
    pub emotion: Option<String>,
}

/// A node in the dialogue tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DialogueNode {
    pub id: String,
    pub speaker: String,
    pub text: String,
    pub choices: Vec<DialogueChoice>,
    pub auto_advance: Option<String>,  // Next node if no choices
    pub on_enter: Vec<DialogueEffect>,
}

/// A choice the player can make
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DialogueChoice {
    pub text: String,
    pub next_node: String,
    pub requirements: Vec<DialogueRequirement>,
    pub effects: Vec<DialogueEffect>,
    pub is_visible: bool,
}

/// Requirements to see/select a choice
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DialogueRequirement {
    SkillCheck { skill: String, minimum: u8 },
    HasEvidence(Id),
    RelationshipMinimum(i32),
    StressMaximum(u8),
    PreviousChoice(String),
}

/// Effects of selecting a choice
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DialogueEffect {
    ChangeRelationship(i32),
    ChangeStress(i32),
    GainEvidence(String),        // Evidence ID to generate
    RevealInformation(String),
    UnlockDialogue(String),
    SetFlag(String, bool),
    TriggerEvent(String),
}

/// How a conversation ended
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConversationOutcome {
    Cooperative,      // NPC was helpful
    Uncooperative,    // NPC was unhelpful
    Hostile,          // NPC is now hostile
    Suspicious,       // NPC is now suspicious
    InformationGained(Vec<String>),
    EvidenceRevealed(Vec<Id>),
}

impl Conversation {
    pub fn new(npc: NPC, starting_node: DialogueNode) -> Self {
        Self {
            id: Id::new(),
            npc,
            history: Vec::new(),
            current_node: Some(starting_node),
            is_complete: false,
            outcome: None,
        }
    }

    /// Add a line to the conversation history
    pub fn add_line(&mut self, speaker: &str, text: &str, emotion: Option<&str>) {
        self.history.push(DialogueLine {
            speaker: speaker.to_string(),
            text: text.to_string(),
            emotion: emotion.map(String::from),
        });
    }

    /// Select a dialogue choice
    pub fn select_choice(&mut self, choice_index: usize) -> Vec<DialogueEffect> {
        if let Some(ref node) = self.current_node {
            if let Some(choice) = node.choices.get(choice_index) {
                let effects = choice.effects.clone();
                // Would need to look up next node here
                return effects;
            }
        }
        Vec::new()
    }
}

/// Pre-built dialogue trees for common situations
pub mod templates {
    use super::*;

    /// Create an interview dialogue for a suspicious employee
    pub fn suspicious_employee_interview(name: &str) -> DialogueNode {
        DialogueNode {
            id: "start".to_string(),
            speaker: name.to_string(),
            text: format!("*{} looks up from their desk nervously* Oh, Security? Is everything okay?", name),
            choices: vec![
                DialogueChoice {
                    text: "We're investigating a security incident. Can I ask you some questions?".to_string(),
                    next_node: "cooperative_path".to_string(),
                    requirements: vec![],
                    effects: vec![],
                    is_visible: true,
                },
                DialogueChoice {
                    text: "Your account shows unusual activity. Care to explain?".to_string(),
                    next_node: "defensive_path".to_string(),
                    requirements: vec![],
                    effects: vec![DialogueEffect::ChangeRelationship(-10)],
                    is_visible: true,
                },
                DialogueChoice {
                    text: "[Social Engineering] You seem stressed. Tough day?".to_string(),
                    next_node: "empathy_path".to_string(),
                    requirements: vec![DialogueRequirement::SkillCheck {
                        skill: "social_engineering".to_string(),
                        minimum: 6,
                    }],
                    effects: vec![DialogueEffect::ChangeRelationship(5)],
                    is_visible: true,
                },
            ],
            auto_advance: None,
            on_enter: vec![],
        }
    }

    /// IT admin being helpful
    pub fn helpful_it_admin_dialogue(name: &str) -> DialogueNode {
        DialogueNode {
            id: "start".to_string(),
            speaker: name.to_string(),
            text: format!("Hey! I heard we might have an incident. How can I help?"),
            choices: vec![
                DialogueChoice {
                    text: "Can you pull the logs from the mail server for the past 24 hours?".to_string(),
                    next_node: "logs_request".to_string(),
                    requirements: vec![],
                    effects: vec![
                        DialogueEffect::GainEvidence("mail_server_logs".to_string()),
                    ],
                    is_visible: true,
                },
                DialogueChoice {
                    text: "What systems have you noticed acting strange lately?".to_string(),
                    next_node: "observations".to_string(),
                    requirements: vec![],
                    effects: vec![
                        DialogueEffect::RevealInformation("suspicious_system_hint".to_string()),
                    ],
                    is_visible: true,
                },
                DialogueChoice {
                    text: "I need admin access to the EDR console.".to_string(),
                    next_node: "edr_access".to_string(),
                    requirements: vec![],
                    effects: vec![
                        DialogueEffect::SetFlag("has_edr_access".to_string(), true),
                    ],
                    is_visible: true,
                },
            ],
            auto_advance: None,
            on_enter: vec![],
        }
    }

    /// Nervous manager protecting their team
    pub fn protective_manager_dialogue(name: &str, department: &str) -> DialogueNode {
        DialogueNode {
            id: "start".to_string(),
            speaker: name.to_string(),
            text: format!(
                "*{} crosses their arms* My team in {} is very busy. What exactly do you need?",
                name, department
            ),
            choices: vec![
                DialogueChoice {
                    text: "I understand you're busy. I just need five minutes of someone's time.".to_string(),
                    next_node: "negotiate".to_string(),
                    requirements: vec![],
                    effects: vec![],
                    is_visible: true,
                },
                DialogueChoice {
                    text: "This is a security investigation. I need access to your team now.".to_string(),
                    next_node: "authority".to_string(),
                    requirements: vec![],
                    effects: vec![
                        DialogueEffect::ChangeRelationship(-15),
                        DialogueEffect::ChangeStress(5),
                    ],
                    is_visible: true,
                },
                DialogueChoice {
                    text: "[Communication] I'll escalate to the CISO if needed. Your call.".to_string(),
                    next_node: "escalation_threat".to_string(),
                    requirements: vec![DialogueRequirement::SkillCheck {
                        skill: "communication".to_string(),
                        minimum: 7,
                    }],
                    effects: vec![],
                    is_visible: true,
                },
            ],
            auto_advance: None,
            on_enter: vec![DialogueEffect::ChangeStress(3)],
        }
    }
}

/// Story events that can occur during gameplay
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoryEvent {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub trigger_conditions: Vec<String>,
    pub effects: Vec<DialogueEffect>,
    pub choices: Option<Vec<StoryChoice>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoryChoice {
    pub text: String,
    pub effects: Vec<DialogueEffect>,
    pub leads_to: Option<String>,  // Another event ID
}

/// Pre-built story events
pub fn create_story_events() -> Vec<StoryEvent> {
    vec![
        StoryEvent {
            id: "shift_handoff".to_string(),
            title: "Shift Change".to_string(),
            description: "Your colleague from the previous shift looks exhausted. 'Busy night. Check the queue - we've got a weird one.'".to_string(),
            severity: Severity::Info,
            trigger_conditions: vec!["game_start".to_string()],
            effects: vec![],
            choices: Some(vec![
                StoryChoice {
                    text: "What can you tell me about it?".to_string(),
                    effects: vec![DialogueEffect::RevealInformation("initial_alert".to_string())],
                    leads_to: None,
                },
                StoryChoice {
                    text: "Get some rest. I'll handle it.".to_string(),
                    effects: vec![DialogueEffect::ChangeRelationship(5)],
                    leads_to: None,
                },
            ]),
        },
        StoryEvent {
            id: "manager_check_in".to_string(),
            title: "Manager Checking In".to_string(),
            description: "Your manager stops by your desk. 'How's it going? Any updates I should know about?'".to_string(),
            severity: Severity::Info,
            trigger_conditions: vec!["turns_passed:10".to_string()],
            effects: vec![DialogueEffect::ChangeStress(5)],
            choices: Some(vec![
                StoryChoice {
                    text: "Still investigating. I'll have an update soon.".to_string(),
                    effects: vec![],
                    leads_to: None,
                },
                StoryChoice {
                    text: "We may have a serious problem. Let me show you what I've found.".to_string(),
                    effects: vec![DialogueEffect::TriggerEvent("escalation_briefing".to_string())],
                    leads_to: Some("escalation_briefing".to_string()),
                },
            ]),
        },
        StoryEvent {
            id: "coffee_machine_gossip".to_string(),
            title: "Overheard Conversation".to_string(),
            description: "At the coffee machine, you overhear two employees talking: 'Did you see that weird email from the CEO? Asking for gift cards?'".to_string(),
            severity: Severity::Medium,
            trigger_conditions: vec!["random_chance:0.3".to_string()],
            effects: vec![DialogueEffect::RevealInformation("bec_attempt".to_string())],
            choices: None,
        },
        StoryEvent {
            id: "threat_escalation".to_string(),
            title: "Alert: Threat Escalation".to_string(),
            description: "Your SIEM lights up. Multiple systems are now showing signs of compromise. The attacker is moving fast.".to_string(),
            severity: Severity::High,
            trigger_conditions: vec!["attack_stage:lateral_movement".to_string()],
            effects: vec![
                DialogueEffect::ChangeStress(15),
                DialogueEffect::TriggerEvent("mass_containment_decision".to_string()),
            ],
            choices: Some(vec![
                StoryChoice {
                    text: "Initiate emergency containment - isolate affected segment.".to_string(),
                    effects: vec![DialogueEffect::SetFlag("emergency_containment".to_string(), true)],
                    leads_to: None,
                },
                StoryChoice {
                    text: "Continue monitoring - we need more data before acting.".to_string(),
                    effects: vec![DialogueEffect::ChangeStress(10)],
                    leads_to: Some("threat_escalation_2".to_string()),
                },
            ]),
        },
    ]
}
