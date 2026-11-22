use crate::ioc::FrameworkMatch;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub scope: Scope,
    #[serde(default)]
    pub dlp_deny: Vec<DlpRule>,
    #[serde(default)]
    pub approval: Vec<ApprovalRule>,
    #[serde(default)]
    pub approval_ttl_seconds: u64,
    #[serde(default)]
    pub taint: TaintPolicy,
    #[serde(default)]
    pub context_taint: Option<ContextTaintPolicy>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextTaintPolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: String,
    #[serde(default = "default_context_ttl")]
    pub ttl_seconds: u64,
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub labels: Vec<String>,
}

fn default_context_ttl() -> u64 {
    1800
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    #[serde(default)]
    pub allow_hosts: Vec<String>,
    #[serde(default)]
    pub allow_ports: Vec<u16>,
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DlpRule {
    pub id: String,
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRule {
    pub id: String,
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaintPolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub source_rules: Vec<TaintRule>,
    #[serde(default)]
    pub sink_rules: Vec<TaintRule>,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaintRule {
    pub id: String,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Decision {
    pub decision: String,
    pub rule_id: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tainted: Option<bool>,
}

impl Decision {
    pub fn new(decision: &str, rule_id: &str, reason: &str) -> Self {
        Decision {
            decision: decision.to_string(),
            rule_id: rule_id.to_string(),
            reason: reason.to_string(),
            approval_file: None,
            approved: None,
            tainted: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TaintInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sink_rule: Option<String>,
    pub tainted: bool,
    #[serde(default)]
    pub labels: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BrokerEvent {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub ts: Option<String>,
    #[serde(default)]
    pub call_id: Option<String>,
    #[serde(default)]
    pub session: Option<String>,
    #[serde(default)]
    pub task: Option<String>,
    pub tool: String,
    #[serde(default)]
    pub argv: Vec<String>,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_command_line: Option<String>,
    #[serde(default)]
    pub decision: Option<String>,
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub exit_code: Option<i64>,
    #[serde(default)]
    pub taint: Option<TaintInfo>,
    #[serde(default)]
    pub framework_match: Vec<FrameworkMatch>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ToolBlock {
    pub qualified: String,
    pub server: String,
    pub arguments: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IngestPayload {
    pub source_app: String,
    pub correlation_id: String,
    pub session_id: String,
    pub tool: ToolBlock,
    pub event_type: String,
    pub outcome: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct LlmUsage {
    #[serde(default)]
    pub prompt_tokens: u64,
    #[serde(default)]
    pub completion_tokens: u64,
    #[serde(default)]
    pub total_tokens: u64,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ToolCallProposal {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub arguments: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct LlmTurnEvent {
    pub timestamp: String,
    pub task_id: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub reasoning: String,
    #[serde(default)]
    pub tool_calls: Vec<ToolCallProposal>,
    #[serde(default)]
    pub prompt_preview: String,
    #[serde(default)]
    pub system_prompt: String,
    #[serde(default)]
    pub latest_user_message: String,
    #[serde(default)]
    pub usage: LlmUsage,
    #[serde(default)]
    pub framework_match: Vec<FrameworkMatch>,
    /// Upstream model endpoint host (for model-API/tool sequence detection).
    #[serde(default)]
    pub upstream_host: String,
    /// Client user agent presented to the proxy, when available.
    #[serde(default)]
    pub client_user_agent: String,
}
