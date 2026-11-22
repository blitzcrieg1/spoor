use crate::model::*;
use serde_json::Value;

fn framework_tags(ev: &BrokerEvent) -> String {
    ev.framework_match
        .iter()
        .map(|m| format!("{}:{}", m.framework, m.indicator))
        .collect::<Vec<_>>()
        .join(",")
}

/// Agentmetry drops unknown `data` fields on ingest, so the indicator annotation
/// also travels in `reason`, where the trail keeps it verbatim.
fn with_framework(ev: &BrokerEvent, reason: &str) -> String {
    let tags = framework_tags(ev);
    if tags.is_empty() {
        reason.to_string()
    } else if reason.is_empty() {
        format!("framework={}", tags)
    } else {
        format!("framework={}; {}", tags, reason)
    }
}

fn broker_arguments(ev: &BrokerEvent, command: &str, phase: &str) -> Value {
    let mut arguments = serde_json::json!({ "command": command, "phase": phase });
    if let Some(call_id) = ev.call_id.as_deref().filter(|id| !id.is_empty()) {
        arguments["call_id"] = serde_json::json!(call_id);
    }
    if let Some(rule_id) = &ev.rule_id {
        arguments["rule_id"] = serde_json::json!(rule_id);
    }
    if let Some(parent) = ev.parent_command_line.as_deref() {
        arguments["parent_command_line"] = serde_json::json!(parent);
    }
    arguments
}

pub fn map_event(ev: &BrokerEvent) -> Vec<IngestPayload> {
    match ev.kind.as_str() {
        "decide" => {
            let session = ev
                .session
                .clone()
                .unwrap_or_else(|| "lab-session".to_string());
            let command = ev.command.clone().unwrap_or_else(|| {
                let mut parts = vec![ev.tool.clone()];
                parts.extend(ev.argv.iter().cloned());
                parts.join(" ")
            });
            let tool = ToolBlock {
                qualified: "Shell.run".to_string(),
                server: "artex".to_string(),
                arguments: broker_arguments(ev, &command, "authorization"),
            };
            let decision = ev.decision.clone().unwrap_or_default();
            let framework_data = if ev.framework_match.is_empty() {
                None
            } else {
                Some(serde_json::json!({"framework_match": ev.framework_match}))
            };
            match decision.as_str() {
                "allow" => {
                    let reason = match &ev.taint {
                        Some(taint) if taint.tainted => {
                            let rule = taint
                                .sink_rule
                                .as_deref()
                                .or(taint.source_rule.as_deref())
                                .unwrap_or("taint");
                            let labels = if taint.labels.is_empty() {
                                "unknown".to_string()
                            } else {
                                taint.labels.join(",")
                            };
                            format!("taint={}; rule={}; source=broker", labels, rule)
                        }
                        _ => String::new(),
                    };
                    let reason = with_framework(ev, &reason);
                    vec![IngestPayload {
                        source_app: "artex".to_string(),
                        correlation_id: session.clone(),
                        session_id: session,
                        tool,
                        event_type: "tool_authorized".to_string(),
                        outcome: "pending".to_string(),
                        reason,
                        task_id: None,
                        data: framework_data.clone(),
                    }]
                }
                "deny" => {
                    let reason = with_framework(
                        ev,
                        &ev.reason
                            .clone()
                            .unwrap_or_else(|| "policy deny".to_string()),
                    );
                    vec![IngestPayload {
                        source_app: "artex".to_string(),
                        correlation_id: session.clone(),
                        session_id: session,
                        tool,
                        event_type: "tool_denied".to_string(),
                        outcome: "denied".to_string(),
                        reason,
                        task_id: None,
                        data: framework_data.clone(),
                    }]
                }
                "ask" => {
                    let reason = with_framework(
                        ev,
                        &ev.reason
                            .clone()
                            .unwrap_or_else(|| "approval required".to_string()),
                    );
                    vec![IngestPayload {
                        source_app: "artex".to_string(),
                        correlation_id: session.clone(),
                        session_id: session,
                        tool,
                        event_type: "approval_request".to_string(),
                        outcome: "pending".to_string(),
                        reason,
                        task_id: None,
                        data: framework_data,
                    }]
                }
                _ => vec![],
            }
        }
        "report" => {
            let Some(exit) = ev.exit_code else {
                return vec![];
            };
            let session = ev
                .session
                .clone()
                .unwrap_or_else(|| "lab-session".to_string());
            let mut arguments =
                broker_arguments(ev, ev.command.as_deref().unwrap_or(&ev.tool), "completion");
            arguments["exit_code"] = serde_json::json!(exit);
            let tool = ToolBlock {
                qualified: "Shell.run".to_string(),
                server: "artex".to_string(),
                arguments,
            };
            let (event_type, outcome) = if exit == 0 {
                ("tool_called", "success")
            } else {
                ("tool_failed", "error")
            };
            vec![IngestPayload {
                source_app: "artex".to_string(),
                correlation_id: session.clone(),
                session_id: session,
                tool,
                event_type: event_type.to_string(),
                outcome: outcome.to_string(),
                reason: with_framework(ev, &format!("exit {}", exit)),
                task_id: None,
                data: None,
            }]
        }
        _ => vec![],
    }
}

pub fn map_artex_command(rec: &Value) -> IngestPayload {
    let session = match rec.get("exploration_id").and_then(|v| v.as_i64()) {
        Some(id) => format!("artex-task-{}", id),
        None => {
            let id = rec
                .get("id")
                .map(|v| match v.as_i64() {
                    Some(n) => n.to_string(),
                    None => v.as_str().unwrap_or("unknown").to_string(),
                })
                .unwrap_or_else(|| "unknown".to_string());
            format!("artex-api-{}", id)
        }
    };
    let tool = rec
        .get("tool")
        .and_then(|v| v.as_str())
        .unwrap_or("tool")
        .to_string();
    let raw = rec.get("command").and_then(|v| v.as_str()).unwrap_or("");
    let command = extract_command(raw);
    let is_error = rec
        .get("is_error")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let output = rec.get("output").and_then(|v| v.as_str()).unwrap_or("");
    let reason: String = if is_error {
        output.chars().take(200).collect()
    } else {
        String::new()
    };
    let body = if command.is_empty() {
        format!("tool:{}", tool)
    } else {
        command
    };
    IngestPayload {
        source_app: "artex".to_string(),
        correlation_id: session.clone(),
        session_id: session,
        tool: ToolBlock {
            qualified: "Shell.run".to_string(),
            server: "artex".to_string(),
            arguments: serde_json::json!({ "command": body }),
        },
        event_type: if is_error {
            "tool_failed"
        } else {
            "tool_called"
        }
        .to_string(),
        outcome: if is_error { "error" } else { "success" }.to_string(),
        reason,
        task_id: None,
        data: None,
    }
}

/// Build the external ingest payload for a Spoor model turn.
pub fn map_llm_event(ev: &LlmTurnEvent) -> IngestPayload {
    let summary = if !ev.tool_calls.is_empty() {
        let names: Vec<&str> = ev
            .tool_calls
            .iter()
            .map(|call| call.name.as_str())
            .collect();
        format!("proposed: {}", names.join(", "))
    } else if !ev.reasoning.is_empty() {
        crate::llm::truncate(&ev.reasoning, 200)
    } else {
        "llm turn".to_string()
    };
    let summary = if ev.framework_match.is_empty() {
        summary
    } else {
        let tags: Vec<String> = ev
            .framework_match
            .iter()
            .map(|m| format!("{}:{}", m.framework, m.indicator))
            .collect();
        format!("framework={}; {}", tags.join(","), summary)
    };
    let summary = if ev.upstream_host.is_empty() {
        summary
    } else {
        format!("model_api={}; {}", ev.upstream_host, summary)
    };
    IngestPayload {
        source_app: "artex".to_string(),
        correlation_id: ev.task_id.clone(),
        session_id: ev.task_id.clone(),
        tool: ToolBlock {
            qualified: "LLM.chat".to_string(),
            server: "artex".to_string(),
            arguments: serde_json::json!({
                "model": ev.model,
                "prompt_preview": ev.prompt_preview,
            }),
        },
        event_type: "llm_turn".to_string(),
        outcome: "success".to_string(),
        reason: summary,
        task_id: Some(ev.task_id.clone()),
        data: serde_json::to_value(ev).ok(),
    }
}

#[cfg(test)]
mod llm_tests {
    use super::*;
    use crate::model::{LlmUsage, ToolCallProposal};

    #[test]
    fn maps_llm_turn_to_ingest_payload() {
        let event = LlmTurnEvent {
            timestamp: "2026-11-21T23:25:00.000Z".to_string(),
            task_id: "artex-task-1".to_string(),
            model: "deepseek-chat".to_string(),
            reasoning: "port 3000 is open".to_string(),
            tool_calls: vec![ToolCallProposal {
                name: "sqlmap".to_string(),
                arguments: "-u http://x".to_string(),
            }],
            prompt_preview: "scan".to_string(),
            system_prompt: "sys".to_string(),
            latest_user_message: "scan".to_string(),
            usage: LlmUsage {
                prompt_tokens: 10,
                completion_tokens: 5,
                total_tokens: 15,
            },
            framework_match: vec![],
            upstream_host: "api.deepseek.com".to_string(),
            client_user_agent: "ARTEX-client/1.0".to_string(),
        };
        let payload = map_llm_event(&event);
        assert_eq!(payload.event_type, "llm_turn");
        assert_eq!(payload.source_app, "artex");
        assert_eq!(payload.correlation_id, "artex-task-1");
        assert_eq!(payload.task_id.as_deref(), Some("artex-task-1"));
        assert_eq!(
            payload.reason,
            "model_api=api.deepseek.com; proposed: sqlmap"
        );
        let data = payload.data.expect("data payload");
        assert_eq!(data["tool_calls"][0]["name"], "sqlmap");
        assert_eq!(data["usage"]["total_tokens"], 15);
    }

    #[test]
    fn framework_match_travels_in_reason() {
        let event: BrokerEvent = serde_json::from_value(serde_json::json!({
            "type": "decide",
            "tool": "curl",
            "command": "curl -A 'Mozilla/5.0 (spa-api-recon)' http://juice-shop:3000/x",
            "decision": "allow",
            "reason": "",
            "session": "lab-session",
            "framework_match": [{
                "framework": "artex",
                "indicator": "spa-api-recon",
                "kind": "user_agent",
                "confidence": "high"
            }]
        }))
        .unwrap();
        let payloads = map_event(&event);
        let payload = &payloads[0];
        assert_eq!(payload.reason, "framework=artex:spa-api-recon");
        assert!(payload.data.is_some());
    }

    #[test]
    fn parent_command_line_maps_to_canonical_tool_arguments() {
        let decide: BrokerEvent = serde_json::from_value(serde_json::json!({
            "type": "decide",
            "call_id": "call-1",
            "tool": "nmap",
            "command": "nmap -sV juice-shop",
            "parent_command_line": "/app/artex --worker",
            "decision": "allow",
            "session": "lab-session"
        }))
        .unwrap();
        let payloads = map_event(&decide);
        assert_eq!(payloads[0].event_type, "tool_authorized");
        assert_eq!(payloads[0].outcome, "pending");
        assert_eq!(payloads[0].tool.arguments["call_id"], "call-1");
        assert_eq!(payloads[0].tool.arguments["phase"], "authorization");
        assert_eq!(payloads[0].tool.arguments["command"], "nmap -sV juice-shop");
        assert_eq!(
            payloads[0].tool.arguments["parent_command_line"],
            "/app/artex --worker"
        );

        let report: BrokerEvent = serde_json::from_value(serde_json::json!({
            "type": "report",
            "call_id": "call-1",
            "tool": "nmap",
            "exit_code": 1,
            "parent_command_line": "/app/artex --worker",
            "session": "lab-session"
        }))
        .unwrap();
        let payloads = map_event(&report);
        assert_eq!(payloads[0].event_type, "tool_failed");
        assert_eq!(payloads[0].tool.arguments["call_id"], "call-1");
        assert_eq!(payloads[0].tool.arguments["phase"], "completion");
        assert_eq!(payloads[0].tool.arguments["exit_code"], 1);
        assert_eq!(
            payloads[0].tool.arguments["parent_command_line"],
            "/app/artex --worker"
        );
    }

    #[test]
    fn reports_successful_exit_and_ignores_report_without_exit_code() {
        let mut report: BrokerEvent = serde_json::from_value(serde_json::json!({
            "type": "report",
            "tool": "echo",
            "command": "echo hello",
            "exit_code": 0
        }))
        .unwrap();
        let payloads = map_event(&report);
        let payload = &payloads[0];
        assert_eq!(payload.event_type, "tool_called");
        assert_eq!(payload.outcome, "success");
        assert_eq!(payload.tool.arguments["command"], "echo hello");
        assert_eq!(payload.tool.arguments["exit_code"], 0);
        assert!(payload.tool.arguments.get("call_id").is_none());
        report.exit_code = None;
        assert!(map_event(&report).is_empty());
    }
}

fn extract_command(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::Object(map)) => {
            for key in ["command", "cmd", "input", "args"] {
                if let Some(Value::String(value)) = map.get(key) {
                    return value.clone();
                }
            }
            raw.to_string()
        }
        _ => raw.to_string(),
    }
}
