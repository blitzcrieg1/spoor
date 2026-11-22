//! Intent → action correlation.
//!
//! The LLM proxy records tool calls the model proposed; the broker records what
//! actually executed. If the executed tool was proposed shortly before, the
//! canonical event is annotated `intent_match=<tool>` so Agentmetry can sequence
//! "model proposed" → "host executed" without a separate join.

use std::collections::{HashMap, HashSet};

const ATTACK_TOOLS: &[&str] = &[
    "nmap", "naabu", "nuclei", "katana", "dalfox", "ffuf", "gobuster", "sqlmap", "nikto",
    "hydra", "masscan", "nc", "netcat", "ssh", "scp", "sftp", "msfconsole", "metasploit",
];

pub fn is_attack_tool(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ATTACK_TOOLS.iter().any(|tool| *tool == lower)
}

#[derive(Debug, PartialEq, Eq)]
pub enum IntentOutcome {
    Matched(String),
    Diverged { proposed: Vec<String>, executed: String },
}

#[derive(Default)]
pub struct IntentTracker {
    window_seconds: u64,
    by_session: HashMap<String, (HashSet<String>, u64)>,
    global: Option<(HashSet<String>, u64)>,
    model_api: Option<(String, u64)>,
}

impl IntentTracker {
    pub fn new(window_seconds: u64) -> Self {
        IntentTracker {
            window_seconds,
            by_session: HashMap::new(),
            global: None,
            model_api: None,
        }
    }

    /// Remember the upstream model endpoint observed for the latest LLM turn.
    pub fn note_model_api(&mut self, host: &str, now: u64) {
        if !host.is_empty() {
            self.model_api = Some((host.to_string(), now));
        }
    }

    /// The model endpoint that produced a turn within the matching window.
    pub fn recent_model_api(&self, now: u64) -> Option<String> {
        match &self.model_api {
            Some((host, at)) if now.saturating_sub(*at) <= self.window_seconds => {
                Some(host.clone())
            }
            _ => None,
        }
    }

    /// Remember attack tools proposed by one LLM turn.
    pub fn note_llm(&mut self, session: &str, tools: &[String], now: u64) {
        let proposed: HashSet<String> = tools
            .iter()
            .map(|tool| tool.to_ascii_lowercase())
            .filter(|tool| is_attack_tool(tool))
            .collect();
        if proposed.is_empty() {
            return;
        }
        self.by_session
            .insert(session.to_string(), (proposed.clone(), now));
        self.global = Some((proposed, now));
    }

    /// Compare one executed tool with the most recent proposal. The proposal is
    /// consumed on use: one model turn should explain one execution.
    pub fn evaluate_tool(&mut self, session: &str, tool: &str, now: u64) -> Option<IntentOutcome> {
        let tool = tool.to_ascii_lowercase();
        let entry = if let Some(entry) = self.by_session.remove(session) {
            // A session-specific proposal was consumed; the global fallback is
            // the same turn and must not fire again.
            self.global = None;
            entry
        } else {
            self.global.take()?
        };
        if now.saturating_sub(entry.1) > self.window_seconds {
            return None;
        }
        if entry.0.contains(&tool) {
            Some(IntentOutcome::Matched(tool))
        } else {
            let mut proposed: Vec<String> = entry.0.into_iter().collect();
            proposed.sort();
            Some(IntentOutcome::Diverged {
                proposed,
                executed: tool,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tools(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    #[test]
    fn proposed_then_executed_matches() {
        let mut tracker = IntentTracker::new(600);
        tracker.note_llm("artex-task-1", &tools(&["nmap", "curl"]), 1000);
        assert_eq!(
            tracker.evaluate_tool("artex-task-1", "nmap", 1100),
            Some(IntentOutcome::Matched("nmap".to_string()))
        );
        // Consumed: a second execution has no fresh proposal to compare.
        assert_eq!(tracker.evaluate_tool("artex-task-1", "nmap", 1101), None);
    }

    #[test]
    fn different_execution_is_divergence() {
        let mut tracker = IntentTracker::new(600);
        tracker.note_llm("artex-task-1", &tools(&["nmap"]), 1000);
        assert_eq!(
            tracker.evaluate_tool("artex-task-1", "curl", 1010),
            Some(IntentOutcome::Diverged {
                proposed: vec!["nmap".to_string()],
                executed: "curl".to_string()
            })
        );
    }

    #[test]
    fn window_expires_and_other_session_falls_back() {
        let mut tracker = IntentTracker::new(60);
        tracker.note_llm("artex-task-1", &tools(&["sqlmap"]), 1000);
        assert_eq!(
            tracker.evaluate_tool("other", "sqlmap", 1030),
            Some(IntentOutcome::Matched("sqlmap".to_string()))
        );
        tracker.note_llm("artex-task-1", &tools(&["sqlmap"]), 1000);
        assert_eq!(tracker.evaluate_tool("other", "sqlmap", 2000), None);
    }

    #[test]
    fn non_attack_proposals_are_ignored() {
        let mut tracker = IntentTracker::new(600);
        tracker.note_llm("s", &tools(&["ls", "cat"]), 1000);
        assert_eq!(tracker.evaluate_tool("s", "ls", 1001), None);
    }

    #[test]
    fn model_api_window() {
        let mut tracker = IntentTracker::new(60);
        tracker.note_model_api("api.deepseek.com", 1000);
        assert_eq!(
            tracker.recent_model_api(1030),
            Some("api.deepseek.com".to_string())
        );
        assert_eq!(tracker.recent_model_api(2000), None);
    }
}
