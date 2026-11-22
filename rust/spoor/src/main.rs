use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use spoor_core::artex::{ArtexClient, ArtexCommandPoller, ArtexTransport, FakeTransport, Headers};
use spoor_core::{
    map_artex_command, map_event, map_llm_event, BrokerEvent, Decision, DedupeStore, Engine,
    IngestPayload, LlmTurnEvent, TaintInfo, TaintState,
};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod proxy;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = match args.get(1).map(String::as_str) {
        Some("replay") => replay(&args),
        Some("broker") => {
            let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
            runtime.block_on(broker(&args));
            0
        }
        Some("watch") => {
            let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
            if runtime.block_on(watch(&args)) {
                0
            } else {
                1
            }
        }
        Some("proxy") => {
            let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
            runtime.block_on(run_proxy(&args));
            0
        }
        Some("serve") => {
            let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
            runtime.block_on(serve(&args));
            0
        }
        Some("export-tracesig") => export_tracesig(&args),
        _ => {
            usage();
            1
        }
    };
    std::process::exit(code);
}

fn usage() {
    eprintln!("usage:");
    eprintln!("  spoor replay <cases.jsonl> [--policy rust/policy.json]");
    eprintln!("  spoor broker [--port 8899] [--policy rust/policy.json]");
    eprintln!("  spoor watch [--once] [--dry-run] [--replay] [--policy rust/policy.json]");
    eprintln!("  spoor proxy [--listen 127.0.0.1:8088] [--upstream URL] [--data DIR] [--enforce]");
    eprintln!(
        "  spoor serve [--listen 127.0.0.1:8088] [--upstream URL] [--policy PATH] [--enforce]"
    );
    eprintln!(
        "  spoor export-tracesig [--broker PATH] [--artex PATH] [--agentmetry PATH] [-o PATH]"
    );
}

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn data_dir() -> PathBuf {
    PathBuf::from(std::env::var("BROKER_DATA_DIR").unwrap_or_else(|_| "data".into()))
}

fn ingest_url() -> String {
    std::env::var("AGENTMETRY_URL").unwrap_or_else(|_| "http://127.0.0.1:8000".into())
}

fn api_key() -> Option<String> {
    std::env::var("AGENTMETRY_API_KEY").ok()
}

// ------------------------------------------------------------------ replay

fn replay(args: &[String]) -> i32 {
    let mut cases_path = String::from("cases.jsonl");
    let mut index = 2;
    while index < args.len() {
        if args[index].starts_with("--") {
            index += 2;
        } else {
            cases_path = args[index].clone();
            break;
        }
    }
    let policy_path = arg_value(args, "--policy").unwrap_or_else(|| "rust/policy.json".to_string());
    let engine = match Engine::load(&policy_path) {
        Ok(engine) => engine,
        Err(err) => {
            eprintln!("cannot load policy {}: {}", policy_path, err);
            return 1;
        }
    };
    let text = match fs::read_to_string(&cases_path) {
        Ok(text) => text,
        Err(err) => {
            eprintln!("cannot read cases {}: {}", cases_path, err);
            return 1;
        }
    };
    let mut failures = 0;
    let mut total = 0;
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        total += 1;
        let case: Value = match serde_json::from_str(line) {
            Ok(case) => case,
            Err(err) => {
                eprintln!("case {}: invalid JSON: {}", index, err);
                failures += 1;
                continue;
            }
        };
        let (ok, actual, expected) = run_case(&engine, &case);
        if ok {
            println!(
                "case {:>2} {:<10} PASS",
                index,
                case["kind"].as_str().unwrap_or("?")
            );
        } else {
            failures += 1;
            println!(
                "case {:>2} {:<10} FAIL",
                index,
                case["kind"].as_str().unwrap_or("?")
            );
            println!("  expected: {}", expected);
            println!("  actual:   {}", actual);
        }
    }
    println!("{}/{} cases passed", total - failures, total);
    if failures > 0 {
        1
    } else {
        0
    }
}

fn run_case(engine: &Engine, case: &Value) -> (bool, Value, Value) {
    let expected = case.get("expected").cloned().unwrap_or(Value::Null);
    let actual = match case["kind"].as_str().unwrap_or("") {
        "policy" => {
            let tool = case["tool"].as_str().unwrap_or("");
            let argv = string_list(&case["argv"]);
            let decision = engine.evaluate(tool, &argv, None);
            normalize(serde_json::to_value(decision).unwrap())
        }
        "taint" => {
            let session = case["session"].as_str().unwrap_or("s").to_string();
            let mut state: TaintState = HashMap::new();
            let mut steps = Vec::new();
            if let Some(items) = case["steps"].as_array() {
                for step in items {
                    let tool = step["tool"].as_str().unwrap_or("");
                    let argv = string_list(&step["argv"]);
                    let command = format!("{} {}", tool, argv.join(" "));
                    let decision = engine.evaluate(tool, &argv, None);
                    let (decision, info) =
                        engine.apply_taint(&session, &command, decision, &mut state);
                    steps.push(taint_value(&decision, &info));
                }
            }
            Value::Array(steps)
        }
        "map" => {
            let event: BrokerEvent =
                serde_json::from_value(case["event"].clone()).unwrap_or(BrokerEvent {
                    kind: String::new(),
                    ts: None,
                    call_id: None,
                    session: None,
                    task: None,
                    tool: String::new(),
                    argv: vec![],
                    command: None,
                    parent_command_line: None,
                    decision: None,
                    rule_id: None,
                    reason: None,
                    exit_code: None,
                    taint: None,
                    framework_match: vec![],
                });
            serde_json::to_value(map_event(&event)).unwrap()
        }
        "artex" => {
            let payload = map_artex_command(&case["record"]);
            serde_json::to_value(payload).unwrap()
        }
        "artex_api" => run_artex_scenario(case),
        "dedupe" => {
            let mut store = DedupeStore::in_memory();
            let mut results = Vec::new();
            if let Some(items) = case["steps"].as_array() {
                for step in items {
                    let source = step["source"].as_str().unwrap_or("broker");
                    let tool = step["tool"].as_str().unwrap_or("");
                    let command = step["command"].as_str().unwrap_or("");
                    let time = step["event_time"].as_str();
                    let key = DedupeStore::key(tool, command, time);
                    let duplicate = store.is_cross_duplicate(source, &key);
                    store.mark(source, &key);
                    results.push(Value::Bool(duplicate));
                }
            }
            Value::Array(results)
        }
        _ => Value::Null,
    };
    (
        normalize(actual.clone()) == normalize(expected.clone()),
        actual,
        expected,
    )
}

fn run_artex_scenario(case: &Value) -> Value {
    let responses: Vec<(u16, String)> = case["responses"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    let status = item["status"].as_u64().unwrap_or(0) as u16;
                    let body = match &item["body"] {
                        Value::String(text) => text.clone(),
                        other => other.to_string(),
                    };
                    (status, body)
                })
                .collect()
        })
        .unwrap_or_default();
    let base = "http://artex:8787";
    let scenario = case["scenario"].as_str().unwrap_or("");
    match scenario {
        "login_ok" => {
            let mut client = ArtexClient::new(base, "ARTEX", "pw", FakeTransport::new(responses));
            let result = client.login();
            let token = result.unwrap_or_default();
            json!({"token": token, "calls": client.transport.calls})
        }
        "login_401" => {
            let mut client = ArtexClient::new(base, "ARTEX", "pw", FakeTransport::new(responses));
            let error = client.login().err().unwrap_or_default();
            json!({"error": error, "calls": client.transport.calls})
        }
        "commands_ok" | "relogin" => {
            let mut client = ArtexClient::new(base, "ARTEX", "pw", FakeTransport::new(responses));
            let (records, total) = client.list_commands(0, 200, None).unwrap_or((vec![], 0));
            json!({
                "records": records,
                "total": total,
                "calls": client.transport.calls,
                "auth": client.transport.auth,
            })
        }
        "poller_dedupe" | "poller_reset" => {
            let client = ArtexClient::new(base, "ARTEX", "pw", FakeTransport::new(responses));
            let state_path = PathBuf::from("target/replay-artex-state.json");
            let _ = fs::remove_file(&state_path);
            let mut poller = ArtexCommandPoller::new(client, state_path.clone(), None);
            let mut polls: Vec<Vec<i64>> = Vec::new();
            let first = poller.poll(true).unwrap_or_default();
            polls.push(
                first
                    .iter()
                    .map(|record| record["id"].as_i64().unwrap_or(0))
                    .collect(),
            );
            if scenario == "poller_reset" {
                poller.reset();
            }
            let second = poller.poll(true).unwrap_or_default();
            polls.push(
                second
                    .iter()
                    .map(|record| record["id"].as_i64().unwrap_or(0))
                    .collect(),
            );
            if scenario == "poller_dedupe" {
                let third = poller.poll(true).unwrap_or_default();
                polls.push(
                    third
                        .iter()
                        .map(|record| record["id"].as_i64().unwrap_or(0))
                        .collect(),
                );
            }
            let state = fs::read_to_string(&state_path)
                .ok()
                .and_then(|text| serde_json::from_str::<Value>(&text).ok())
                .unwrap_or(Value::Null);
            let _ = fs::remove_file(&state_path);
            json!({"polls": polls, "state": state})
        }
        _ => Value::Null,
    }
}

fn string_list(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn normalize(mut value: Value) -> Value {
    if let Value::Object(map) = &mut value {
        map.remove("approval_file");
        map.remove("approved");
    }
    value
}

fn taint_value(decision: &Decision, info: &Option<TaintInfo>) -> Value {
    let mut map = serde_json::Map::new();
    map.insert("decision".into(), json!(decision.decision));
    map.insert("rule_id".into(), json!(decision.rule_id));
    map.insert("reason".into(), json!(decision.reason));
    if let Some(info) = info {
        map.insert("tainted".into(), json!(info.tainted));
        map.insert("labels".into(), json!(info.labels));
        if let Some(rule) = &info.source_rule {
            map.insert("source_rule".into(), json!(rule));
        }
        if let Some(rule) = &info.sink_rule {
            map.insert("sink_rule".into(), json!(rule));
        }
    }
    Value::Object(map)
}

// ------------------------------------------------------------------ broker

#[derive(Clone)]
struct ContextEntry {
    tainted_at: u64,
    reason: String,
    source: String,
}

type ContextMap = Arc<Mutex<HashMap<String, ContextEntry>>>;

const MAX_CONTEXT_ENTRIES: usize = 10_000;
const MAX_PENDING_REPORTS: usize = 100_000;
const REPORT_TTL_SECONDS: u64 = 3600;

#[derive(Clone)]
struct BrokerState {
    engine: Arc<Engine>,
    taint: Arc<Mutex<TaintState>>,
    context: ContextMap,
    events: PathBuf,
    approvals: PathBuf,
    pending_reports: Arc<Mutex<HashMap<String, PendingCall>>>,
    strict_audit: bool,
    #[cfg(test)]
    audit_sync: SyncAudit,
}

impl BrokerState {
    fn new(engine: Engine, events: PathBuf, approvals: PathBuf, strict_audit: bool) -> Self {
        Self {
            engine: Arc::new(engine),
            taint: Arc::new(Mutex::new(HashMap::new())),
            context: Arc::new(Mutex::new(HashMap::new())),
            events,
            approvals,
            pending_reports: Arc::new(Mutex::new(HashMap::new())),
            strict_audit,
            #[cfg(test)]
            audit_sync: sync_jsonl,
        }
    }

    fn append_event(&self, event: &Value) -> bool {
        #[cfg(test)]
        let sync = self.audit_sync;
        #[cfg(not(test))]
        let sync = sync_jsonl;
        append_jsonl_with_sync(&self.events, event, Some(sync))
    }
}

#[derive(Clone)]
struct PendingCall {
    tool: String,
    command: String,
    session: String,
    parent_command_line: Option<String>,
    issued_at: u64,
}

async fn broker(args: &[String]) {
    broker_with_ready(args, None).await;
}

async fn broker_with_ready(args: &[String], ready: Option<tokio::sync::oneshot::Sender<()>>) {
    let port: u16 = arg_value(args, "--port")
        .and_then(|value| value.parse().ok())
        .unwrap_or(8899);
    let policy_path = arg_value(args, "--policy").unwrap_or_else(|| "rust/policy.json".to_string());
    let engine = Engine::load(&policy_path).expect("load policy");
    let data = data_dir();
    let approvals = std::env::var_os("BROKER_APPROVALS")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(&policy_path)
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join("..")
                .join("approvals")
        });
    let state = BrokerState::new(
        engine,
        data.join("broker-events.jsonl"),
        approvals,
        std::env::var("SPOOR_STRICT_AUDIT").ok().as_deref() == Some("1"),
    );
    let app = Router::new()
        .route("/health", get(health))
        .route("/decide", post(decide))
        .route("/preflight", post(preflight))
        .route("/context-taint", post(context_taint))
        .route("/report", post(report))
        .with_state(state);
    let listen = std::env::var("BROKER_LISTEN").unwrap_or_else(|_| format!("127.0.0.1:{}", port));
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .unwrap_or_else(|err| panic!("bind broker {}: {}", listen, err));
    println!(
        "[spoor-rs] broker on http://{}",
        listener.local_addr().expect("read broker address")
    );
    if let Some(ready) = ready {
        let _ = ready.send(());
    }
    axum::serve(listener, app).await.expect("serve");
}

async fn health() -> Json<Value> {
    Json(json!({"ok": true, "engine": "spoor-rs"}))
}

/// Policy-only decision for a proposed LLM tool call: no trail event, no taint
/// mutation. Used by `spoor proxy --enforce` so the proxy never executes a call.
async fn preflight(State(state): State<BrokerState>, Json(body): Json<Value>) -> Json<Value> {
    let tool = body["tool"].as_str().unwrap_or("tool").to_string();
    let argv = string_list(&body["argv"]);
    let session = default_session();
    let command = format!("{} {}", tool, argv.join(" "));
    let mut decision = state.engine.evaluate(&tool, &argv, Some(&state.approvals));
    if decision.decision == "allow" && !session.is_empty() {
        if let Some(_entry) = context_active(&state, &session) {
            decision = state.engine.context_escalate(decision, &command);
        }
    }
    Json(json!({
        "decision": decision.decision,
        "rule_id": decision.rule_id,
        "reason": decision.reason,
    }))
}

/// Record that untrusted external content entered this task's model context.
/// The proxy posts here; `decide`/`preflight` consult it.
async fn context_taint(State(state): State<BrokerState>, Json(body): Json<Value>) -> Json<Value> {
    // Session selection comes from the broker's trusted environment, never
    // the caller's JSON. This deployment intentionally uses one lab session.
    let session = default_session();
    let tainted = body["tainted"].as_bool().unwrap_or(true);
    let reason = body["reason"]
        .as_str()
        .unwrap_or("untrusted external content entered the model context")
        .to_string();
    let source = body["source"].as_str().unwrap_or("llm-proxy").to_string();
    let ttl = context_ttl(&state);
    let now = epoch_seconds();
    let mut map = state.context.lock().unwrap();
    map.retain(|_, entry| ttl > 0 && now.saturating_sub(entry.tainted_at) <= ttl);
    if tainted {
        if ttl == 0 {
            return Json(
                json!({"ok": false, "session": session, "tainted": false, "reason": "context taint TTL must be greater than zero"}),
            );
        }
        if map.len() >= MAX_CONTEXT_ENTRIES && !map.contains_key(&session) {
            return Json(
                json!({"ok": false, "session": session, "tainted": false, "reason": "context taint capacity reached"}),
            );
        }
        map.insert(
            session.clone(),
            ContextEntry {
                tainted_at: now,
                reason,
                source,
            },
        );
    }
    Json(json!({
        "ok": tainted,
        "session": session,
        "tainted": true,
        "reason": if tainted { "recorded" } else { "taint is sticky until TTL expiry" }
    }))
}

fn default_session() -> String {
    // The proxy and shim must share one fallback when the agent host does not
    // provide explicit task/session metadata.
    std::env::var("ARTEX_SESSION_ID")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "lab-session".to_string())
}

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn context_ttl(state: &BrokerState) -> u64 {
    state
        .engine
        .policy
        .context_taint
        .as_ref()
        .map(|policy| policy.ttl_seconds)
        .unwrap_or(1800)
}

fn context_active(state: &BrokerState, session: &str) -> Option<ContextEntry> {
    let ttl = context_ttl(state);
    if ttl == 0 {
        state.context.lock().unwrap().remove(session);
        return None;
    }
    let now = epoch_seconds();
    let mut map = state.context.lock().unwrap();
    if let Some(entry) = map.get(session) {
        if now.saturating_sub(entry.tainted_at) <= ttl {
            return Some(entry.clone());
        }
    }
    map.remove(session);
    None
}

async fn decide(State(state): State<BrokerState>, Json(body): Json<Value>) -> Json<Value> {
    let tool = body["tool"].as_str().unwrap_or("tool").to_string();
    let argv = string_list(&body["argv"]);
    let task = body["task"].as_str().unwrap_or("").to_string();
    let parent_command_line = bounded_parent_command_line(&body["parent_command_line"]);
    let session = default_session();
    let command = format!("{} {}", tool, argv.join(" ")).trim().to_string();
    let framework_match = spoor_core::ioc::scan(&command);
    let mut decision = state.engine.evaluate(&tool, &argv, Some(&state.approvals));
    let taint_info = {
        let mut taint = state.taint.lock().unwrap();
        let (next, info) = state
            .engine
            .apply_taint(&session, &command, decision, &mut taint);
        decision = next;
        info
    };
    if decision.decision == "allow" {
        if let Some(entry) = context_active(&state, &session) {
            decision = state.engine.context_escalate(decision, &command);
            eprintln!(
                "[spoor-rs] context-tainted session {} ({}: {})",
                session, entry.source, entry.reason
            );
        }
    }
    let call_id = call_id();
    if decision.decision == "allow" {
        let now = epoch_seconds();
        let mut pending = state.pending_reports.lock().unwrap();
        pending.retain(|_, pending_call| {
            now.saturating_sub(pending_call.issued_at) <= REPORT_TTL_SECONDS
        });
        if pending.len() >= MAX_PENDING_REPORTS {
            decision = Decision::new(
                "deny",
                "report-capacity",
                "pending call report capacity reached; refusing an untracked tool call",
            );
        } else {
            pending.insert(
                call_id.clone(),
                PendingCall {
                    tool: tool.clone(),
                    command: command.clone(),
                    session: session.clone(),
                    parent_command_line: parent_command_line.clone(),
                    issued_at: now,
                },
            );
        }
    }
    let mut response = json!({
        "call_id": call_id.clone(),
        "decision": decision.decision,
        "rule_id": decision.rule_id,
        "reason": decision.reason,
    });
    if let Some(path) = &decision.approval_file {
        response["approval_file"] = json!(path);
    }
    if let Some(approved) = decision.approved {
        response["approved"] = json!(approved);
    }
    let mut event = with_parent_command_line(
        json!({
            "type": "decide",
            "ts": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "call_id": call_id,
            "session": session,
            "task": task,
            "tool": tool,
            "argv": argv,
            "command": command,
            "decision": response["decision"],
            "rule_id": response["rule_id"],
            "reason": response["reason"],
        }),
        parent_command_line.as_deref(),
    );
    if let Some(info) = taint_info {
        event["taint"] = serde_json::to_value(info).unwrap_or(Value::Null);
        if decision.tainted == Some(true) {
            response["tainted"] = json!(true);
        }
    }
    if !framework_match.is_empty() {
        event["framework_match"] = serde_json::to_value(&framework_match).unwrap_or(Value::Null);
    }
    if !state.append_event(&event) {
        if state.strict_audit && decision.decision == "allow" {
            state.pending_reports.lock().unwrap().remove(&call_id);
            return Json(json!({
                "call_id": call_id,
                "decision": "deny",
                "rule_id": "audit-unavailable",
                "reason": "strict audit requires a synced decision record",
                "audit_recorded": false,
            }));
        }
        response["audit_recorded"] = json!(false);
    }
    Json(response)
}

async fn report(State(state): State<BrokerState>, Json(body): Json<Value>) -> Json<Value> {
    let call_id = body["call_id"].as_str().unwrap_or("");
    let tool = body["tool"].as_str().unwrap_or("");
    let Some(exit_code) = body["exit_code"].as_i64() else {
        return Json(json!({"ok": false, "reason": "invalid exit_code"}));
    };
    let Some(duration_ms) = body["duration_ms"].as_u64() else {
        return Json(json!({"ok": false, "reason": "invalid duration_ms"}));
    };
    let now = epoch_seconds();
    let mut pending = state.pending_reports.lock().unwrap();
    pending
        .retain(|_, pending_call| now.saturating_sub(pending_call.issued_at) <= REPORT_TTL_SECONDS);
    let Some(pending_call) = pending.get(call_id) else {
        return Json(json!({"ok": false, "reason": "unknown or expired call_id"}));
    };
    if pending_call.tool != tool {
        return Json(json!({"ok": false, "reason": "tool does not match call_id"}));
    }
    // Keep the decision-time session, command, and parent metadata.
    let mut event = with_parent_command_line(
        json!({
            "type": "report",
            "ts": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "call_id": call_id,
            "session": pending_call.session,
            "tool": tool,
            "command": pending_call.command,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
        }),
        pending_call.parent_command_line.as_deref(),
    );
    let framework_match = spoor_core::ioc::scan(&pending_call.command);
    if !framework_match.is_empty() {
        event["framework_match"] = serde_json::to_value(&framework_match).unwrap_or(Value::Null);
    }
    if !state.append_event(&event) {
        return Json(json!({"ok": false, "reason": "audit-unavailable"}));
    }
    pending.remove(call_id);
    Json(json!({"ok": true}))
}

fn bounded_parent_command_line(value: &Value) -> Option<String> {
    let raw = value.as_str()?.trim();
    if raw.is_empty() {
        return None;
    }
    let cleaned = raw
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if cleaned.is_empty() {
        return None;
    }
    let mut bounded = cleaned.chars().take(2048).collect::<String>();
    if cleaned.chars().count() > 2048 {
        bounded.push_str(" [truncated]");
    }
    Some(bounded)
}

fn with_parent_command_line(mut event: Value, parent: Option<&str>) -> Value {
    if let Some(parent) = parent {
        event["parent_command_line"] = json!(parent);
    }
    event
}

fn call_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    format!(
        "{:x}-{:x}-{:x}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
        NEXT_ID.fetch_add(1, Ordering::Relaxed),
    )
}

fn append_jsonl(path: &Path, value: &Value) -> bool {
    append_jsonl_with_sync(path, value, None)
}

fn append_durable_jsonl(path: &Path, value: &Value) -> bool {
    append_jsonl_with_sync(path, value, Some(sync_jsonl))
}

type SyncAudit = fn(&fs::File, &Path) -> std::io::Result<()>;

fn sync_jsonl(file: &fs::File, _parent: &Path) -> std::io::Result<()> {
    file.sync_all()?;
    #[cfg(unix)]
    fs::File::open(_parent)?.sync_all()?;
    Ok(())
}

fn append_jsonl_with_sync(path: &Path, value: &Value, sync: Option<SyncAudit>) -> bool {
    static APPEND_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let _guard = APPEND_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let result = (|| -> std::io::Result<()> {
        let parent = path
            .parent()
            .filter(|directory| !directory.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        file.write_all(format!("{}\n", value).as_bytes())?;
        if let Some(sync) = sync {
            sync(&file, parent)?;
        }
        Ok(())
    })();
    if let Err(err) = result {
        eprintln!(
            "[spoor-rs] audit append failed for {}: {}",
            path.display(),
            err
        );
        return false;
    }
    true
}

// ------------------------------------------------------------------- watch

async fn watch(args: &[String]) -> bool {
    let source = std::env::var("SPOOR_SOURCE").unwrap_or_else(|_| "broker".to_string());
    let once = has_flag(args, "--once");
    let dry_run =
        has_flag(args, "--dry-run") || std::env::var("SPOOR_DRY_RUN").ok().as_deref() == Some("1");
    let replay = has_flag(args, "--replay");
    let data = data_dir();
    let state = state_dir(&data);
    let dedupe = if source == "both" {
        Some(Arc::new(Mutex::new(DedupeStore::load(
            state.join("dedupe-keys.jsonl"),
        ))))
    } else {
        None
    };
    // Replay the dead-letter spool exactly once, before any concurrent watcher
    // starts, so both-mode threads cannot race on the same file.
    if !dry_run {
        replay_dead_letter(
            &state.join("failed-queue.rust.jsonl"),
            &ingest_url(),
            api_key().as_deref(),
        );
    }
    // LLM turns land in llm-events.jsonl (written by `spoor proxy`); tail them
    // alongside the broker trail. The tracker joins a proposal to the execution.
    let intent = Arc::new(Mutex::new(spoor_core::intent::IntentTracker::new(600)));
    let llm_state = state.clone();
    let llm_intent = intent.clone();
    let llm_handle =
        tokio::spawn(
            async move { run_llm_loop(&llm_state, dry_run, once, Some(llm_intent)).await },
        );
    let completed = match source.as_str() {
        "artex-api" => run_artex_loop(&data, &state, dry_run, once, replay, dedupe),
        "both" => {
            let data_clone = data.clone();
            let state_clone = state.clone();
            let dedupe_clone = dedupe.clone();
            let handle = std::thread::spawn(move || {
                run_artex_loop(
                    &data_clone,
                    &state_clone,
                    dry_run,
                    once,
                    replay,
                    dedupe_clone,
                )
            });
            let broker_completed = run_broker_loop(
                &data,
                &state,
                dry_run,
                once,
                replay,
                dedupe.clone(),
                Some(intent.clone()),
            )
            .await;
            let artex_completed = handle.join().unwrap_or(false);
            broker_completed && artex_completed
        }
        _ => {
            run_broker_loop(
                &data,
                &state,
                dry_run,
                once,
                replay,
                None,
                Some(intent.clone()),
            )
            .await
        }
    };
    let llm_completed = llm_handle.await.unwrap_or(false);
    completed && llm_completed
}

async fn run_proxy(args: &[String]) {
    let listen = arg_value(args, "--listen")
        .or_else(|| std::env::var("SPOOR_PROXY_LISTEN").ok())
        .unwrap_or_else(|| "127.0.0.1:8088".to_string());
    let upstream = arg_value(args, "--upstream")
        .or_else(|| std::env::var("LLM_UPSTREAM_URL").ok())
        .unwrap_or_else(|| "https://api.openai.com/v1".to_string());
    let data = arg_value(args, "--data")
        .map(PathBuf::from)
        .unwrap_or_else(|| state_dir(&data_dir()));
    let api_key = std::env::var("LLM_API_KEY").ok();
    let enforce = has_flag(args, "--enforce")
        || std::env::var("SPOOR_PROXY_ENFORCE").ok().as_deref() == Some("1");
    let preflight_url = Some(
        std::env::var("SPOOR_PREFLIGHT_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8899/preflight".to_string()),
    );
    let context_url = Some(
        std::env::var("SPOOR_CONTEXT_URL")
            .unwrap_or_else(|_| "http://host.docker.internal:8899/context-taint".to_string()),
    );
    if let Err(err) = proxy::run(
        &listen,
        upstream,
        data,
        api_key,
        enforce,
        preflight_url,
        context_url,
    )
    .await
    {
        eprintln!("[spoor-proxy] {}", err);
        std::process::exit(1);
    }
}

async fn serve(args: &[String]) {
    let listen = arg_value(args, "--listen")
        .or_else(|| std::env::var("SPOOR_PROXY_LISTEN").ok())
        .unwrap_or_else(|| "127.0.0.1:8088".to_string());
    let upstream = arg_value(args, "--upstream")
        .or_else(|| std::env::var("LLM_UPSTREAM_URL").ok())
        .unwrap_or_else(|| "https://api.openai.com/v1".to_string());
    let data = arg_value(args, "--data")
        .map(PathBuf::from)
        .unwrap_or_else(|| state_dir(&data_dir()));
    let api_key = std::env::var("LLM_API_KEY").ok();
    let enforce = has_flag(args, "--enforce")
        || std::env::var("SPOOR_PROXY_ENFORCE").ok().as_deref() == Some("1");
    let preflight_url = Some(
        std::env::var("SPOOR_PREFLIGHT_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8899/preflight".to_string()),
    );
    let context_url = Some(
        std::env::var("SPOOR_CONTEXT_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8899/context-taint".to_string()),
    );
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let broker_args = args.to_vec();
    tokio::spawn(async move {
        broker_with_ready(&broker_args, Some(ready_tx)).await;
    });
    if ready_rx.await.is_err() {
        eprintln!("[spoor-rs] broker failed to start; refusing to serve proxy");
        return;
    }
    let handle = tokio::spawn(async move {
        if let Err(err) = proxy::run(
            &listen,
            upstream,
            data,
            api_key,
            enforce,
            preflight_url,
            context_url,
        )
        .await
        {
            eprintln!("[spoor-proxy] {}", err);
        }
    });
    let _ = watch(args).await;
    let _ = handle.await;
}

async fn run_llm_loop(
    state: &Path,
    dry_run: bool,
    once: bool,
    intent: Option<Arc<Mutex<spoor_core::intent::IntentTracker>>>,
) -> bool {
    let events = state.join("llm-events.jsonl");
    let state_path = state.join("spoor.llm-state.json");
    let preview = state.join("ingest-preview.rust.jsonl");
    let failed = state.join("failed-queue.rust.jsonl");
    let base = ingest_url();
    let key = api_key();
    let mut offset = read_watcher_state(&state_path).offset;
    let mut signature = read_watcher_state(&state_path).signature;
    loop {
        let mut blocked = false;
        if !events.exists() {
            if once {
                return true;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        let size = fs::metadata(&events).map(|meta| meta.len()).unwrap_or(0);
        let current_signature = file_signature(&events);
        if size < offset
            || (offset > 0 && signature.is_empty())
            || (offset > 0 && signature != current_signature)
        {
            offset = 0;
        }
        if signature.is_empty() || offset == 0 {
            signature = current_signature.clone();
        }
        if let Ok(mut file) = fs::File::open(&events) {
            use std::io::{Seek, SeekFrom};
            if file.seek(SeekFrom::Start(offset)).is_ok() {
                let mut chunk = String::new();
                if file.read_to_string(&mut chunk).is_ok() {
                    let consumed = chunk.rfind('\n').map(|index| index + 1).unwrap_or(0);
                    if consumed > 0 {
                        let mut posted = 0u64;
                        let mut failed_count = 0u64;
                        let mut advanced = 0;
                        for line in chunk[..consumed].split_inclusive('\n') {
                            if line.trim().is_empty() {
                                advanced += line.len();
                                continue;
                            }
                            let event: LlmTurnEvent = match serde_json::from_str(line) {
                                Ok(event) => event,
                                Err(err) => {
                                    if !append_durable_jsonl(
                                        &state.join("llm-malformed.rust.jsonl"),
                                        &json!({
                                            "raw_line": line,
                                            "error": err.to_string(),
                                            "source": events.display().to_string(),
                                        }),
                                    ) {
                                        blocked = true;
                                        break;
                                    }
                                    advanced += line.len();
                                    continue;
                                }
                            };
                            if let Some(tracker) = &intent {
                                tracker
                                    .lock()
                                    .unwrap()
                                    .note_model_api(&event.upstream_host, epoch_seconds());
                                let tools: Vec<String> = event
                                    .tool_calls
                                    .iter()
                                    .map(|call| call.name.clone())
                                    .collect();
                                tracker.lock().unwrap().note_llm(
                                    &event.task_id,
                                    &tools,
                                    epoch_seconds(),
                                );
                            }
                            let payload = map_llm_event(&event);
                            match deliver_ingest(
                                &base,
                                &payload,
                                key.as_deref(),
                                dry_run,
                                &preview,
                                &failed,
                                None,
                                "llm",
                                None,
                            ) {
                                Delivery::Sent => posted += 1,
                                Delivery::Queued => failed_count += 1,
                                Delivery::Duplicate => {}
                                Delivery::Blocked => {
                                    blocked = true;
                                    break;
                                }
                            }
                            advanced += line.len();
                        }
                        offset += advanced as u64;
                        if advanced > 0 && !once && !dry_run {
                            let mut watcher = read_watcher_state(&state_path);
                            watcher.offset = offset;
                            watcher.signature = signature.clone();
                            watcher.posted += posted;
                            watcher.failed += failed_count;
                            write_watcher_state(&state_path, &watcher);
                        }
                    }
                }
            }
        }
        if blocked {
            eprintln!("[spoor-rs] LLM trail checkpoint held at byte {}", offset);
        }
        if once {
            return !blocked;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn state_dir(data: &Path) -> PathBuf {
    std::env::var("SPOOR_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| data.to_path_buf())
}

#[derive(Default, Clone)]
struct WatcherState {
    offset: u64,
    posted: u64,
    failed: u64,
    duplicates: u64,
    signature: String,
}

fn read_watcher_state(path: &Path) -> WatcherState {
    serde_json::from_str::<Value>(&fs::read_to_string(path).unwrap_or_default())
        .map(|value| WatcherState {
            offset: value["offset"].as_u64().unwrap_or(0),
            posted: value["posted"].as_u64().unwrap_or(0),
            failed: value["failed"].as_u64().unwrap_or(0),
            duplicates: value["duplicates"].as_u64().unwrap_or(0),
            signature: value["signature"].as_str().unwrap_or("").to_string(),
        })
        .unwrap_or_default()
}

fn file_signature(path: &Path) -> String {
    use std::hash::{Hash, Hasher};
    let Ok(file) = fs::File::open(path) else {
        return String::new();
    };
    use std::io::BufRead;
    let mut reader = std::io::BufReader::new(file);
    let mut first_line = Vec::new();
    while first_line.len() < 4096 {
        let Ok(available) = reader.fill_buf() else {
            break;
        };
        if available.is_empty() {
            break;
        }
        let limit = (4096 - first_line.len()).min(available.len());
        let count = available[..limit]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|index| index + 1)
            .unwrap_or(limit);
        let done = available[..count].last() == Some(&b'\n') || count == 4096 - first_line.len();
        first_line.extend_from_slice(&available[..count]);
        reader.consume(count);
        if done {
            break;
        }
    }
    let metadata = fs::metadata(path).ok();
    let created = metadata
        .as_ref()
        .and_then(|metadata| metadata.created().ok())
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|time| time.as_nanos())
        .unwrap_or(0);
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    created.hash(&mut hasher);
    first_line.hash(&mut hasher);
    #[cfg(unix)]
    if let Some(metadata) = metadata.as_ref() {
        use std::os::unix::fs::MetadataExt;
        metadata.dev().hash(&mut hasher);
        metadata.ino().hash(&mut hasher);
    }
    format!("{:016x}", hasher.finish())
}

fn replace_state_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("{}.tmp", call_id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)?;
    let written = file.write_all(contents).and_then(|_| file.sync_all());
    drop(file);
    let result = written.and_then(|_| fs::rename(&tmp, path));
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn write_watcher_state(path: &Path, state: &WatcherState) {
    let value = json!({
        "offset": state.offset,
        "posted": state.posted,
        "failed": state.failed,
        "duplicates": state.duplicates,
        "signature": state.signature,
        "last_ingest_utc": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    });
    if let Err(err) = replace_state_file(path, value.to_string().as_bytes()) {
        eprintln!("[spoor-rs] watcher checkpoint write failed: {}", err);
    }
}

fn replay_dead_letter(path: &Path, base: &str, key: Option<&str>) {
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    let mut remaining = Vec::new();
    let mut replayed = 0usize;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(payload) = serde_json::from_str::<IngestPayload>(line) else {
            remaining.push(line.to_string());
            continue;
        };
        if post_payload(base, &payload, key) {
            replayed += 1;
        } else {
            remaining.push(line.to_string());
        }
    }
    let retained = if remaining.is_empty() {
        fs::remove_file(path)
    } else {
        replace_state_file(path, (remaining.join("\n") + "\n").as_bytes())
    };
    if let Err(err) = retained {
        eprintln!("[spoor-rs] retry queue update failed: {}", err);
    }
    eprintln!(
        "[spoor-rs] replayed {} dead-letter payload(s), {} still failing",
        replayed,
        remaining.len()
    );
}

#[derive(PartialEq, Clone, Copy)]
enum Delivery {
    Sent,
    Duplicate,
    Queued,
    Blocked,
}

async fn run_broker_loop(
    data: &Path,
    state_dir: &Path,
    dry_run: bool,
    once: bool,
    replay: bool,
    dedupe: Option<Arc<Mutex<DedupeStore>>>,
    intent: Option<Arc<Mutex<spoor_core::intent::IntentTracker>>>,
) -> bool {
    let events = data.join("broker-events.jsonl");
    let state_path = state_dir.join("spoor.rust-state.json");
    let preview = state_dir.join("ingest-preview.rust.jsonl");
    let failed = state_dir.join("failed-queue.rust.jsonl");
    let base = ingest_url();
    let key = api_key();
    let mut state = if replay {
        WatcherState::default()
    } else {
        read_watcher_state(&state_path)
    };
    let mut signature = state.signature.clone();
    loop {
        let mut blocked = false;
        if !events.exists() {
            if once {
                eprintln!("[spoor-rs] no broker events yet: {}", events.display());
                return true;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        }
        let size = fs::metadata(&events).map(|meta| meta.len()).unwrap_or(0);
        let current_signature = file_signature(&events);
        if size < state.offset
            || (state.offset > 0 && signature.is_empty())
            || (state.offset > 0 && signature != current_signature)
        {
            state.offset = 0;
            eprintln!("[spoor-rs] broker trail rotated; offset reset to 0");
        }
        if signature.is_empty() || state.offset == 0 {
            signature = current_signature.clone();
        }
        let mut handled = 0usize;
        let mut duplicate_count = 0usize;
        let mut failed_count = 0usize;
        let mut bad = 0usize;
        let mut advanced = 0u64;
        if let Ok(mut file) = fs::File::open(&events) {
            use std::io::{Seek, SeekFrom};
            if file.seek(SeekFrom::Start(state.offset)).is_ok() {
                let mut chunk = String::new();
                if file.read_to_string(&mut chunk).is_ok() {
                    // Only consume complete lines: a partially flushed tail is
                    // left for the next read instead of desynchronising offset.
                    let consumed = match chunk.rfind('\n') {
                        Some(index) => index + 1,
                        None if once && !chunk.is_empty() => chunk.len(),
                        None => 0,
                    };
                    if consumed > 0 {
                        let complete = &chunk[..consumed];
                        'lines: for line in complete.split_inclusive('\n') {
                            if line.trim().is_empty() {
                                advanced += line.len() as u64;
                                continue;
                            }
                            let event: BrokerEvent = match serde_json::from_str(line) {
                                Ok(event) => event,
                                Err(_) => {
                                    bad += 1;
                                    if !append_durable_jsonl(
                                        &state_dir.join("broker-malformed.rust.jsonl"),
                                        &json!({
                                            "raw_line": line,
                                            "source": events.display().to_string(),
                                        }),
                                    ) {
                                        blocked = true;
                                        break;
                                    }
                                    advanced += line.len() as u64;
                                    continue;
                                }
                            };
                            let dedupe_key =
                                (dedupe.is_some() && event.kind == "report").then(|| {
                                    DedupeStore::key(
                                        &event.tool,
                                        event.command.as_deref().unwrap_or(""),
                                        event.ts.as_deref(),
                                    )
                                });
                            for mut payload in map_event(&event) {
                                if matches!(
                                    payload.event_type.as_str(),
                                    "tool_called" | "tool_failed"
                                ) {
                                    if let Some(tracker) = &intent {
                                        let key = event
                                            .session
                                            .clone()
                                            .unwrap_or_else(|| "lab-session".to_string());
                                        let now = epoch_seconds();
                                        let mut tags: Vec<String> = Vec::new();
                                        {
                                            let mut tracker = tracker.lock().unwrap();
                                            if spoor_core::intent::is_attack_tool(&event.tool) {
                                                if let Some(host) = tracker.recent_model_api(now) {
                                                    tags.push(format!("model_api={}", host));
                                                }
                                            }
                                            if let Some(outcome) =
                                                tracker.evaluate_tool(&key, &event.tool, now)
                                            {
                                                tags.push(match outcome {
                                                    spoor_core::intent::IntentOutcome::Matched(tool) => {
                                                        format!("intent_match={}", tool)
                                                    }
                                                    spoor_core::intent::IntentOutcome::Diverged {
                                                        proposed,
                                                        executed,
                                                    } => format!(
                                                        "intent_divergence=proposed:{};executed:{}",
                                                        proposed.join(","),
                                                        executed
                                                    ),
                                                });
                                            }
                                        }
                                        if !tags.is_empty() {
                                            payload.reason = if payload.reason.is_empty() {
                                                tags.join("; ")
                                            } else {
                                                format!("{}; {}", tags.join("; "), payload.reason)
                                            };
                                        }
                                    }
                                }
                                match deliver_ingest(
                                    &base,
                                    &payload,
                                    key.as_deref(),
                                    dry_run,
                                    &preview,
                                    &failed,
                                    dedupe.as_ref(),
                                    "broker",
                                    dedupe_key.clone(),
                                ) {
                                    Delivery::Sent => handled += 1,
                                    Delivery::Duplicate => duplicate_count += 1,
                                    Delivery::Queued => failed_count += 1,
                                    Delivery::Blocked => {
                                        blocked = true;
                                        break 'lines;
                                    }
                                }
                            }
                            advanced += line.len() as u64;
                        }
                        state.offset += advanced;
                        state.signature = signature.clone();
                    }
                    // Dry-run never persists committed state.
                    if !once && !dry_run && advanced > 0 {
                        state.posted += handled as u64;
                        state.failed += failed_count as u64;
                        state.duplicates += duplicate_count as u64;
                        write_watcher_state(&state_path, &state);
                    }
                }
            }
        }
        if bad > 0 {
            eprintln!("[spoor-rs] skipped {} malformed line(s)", bad);
        }
        if blocked {
            eprintln!(
                "[spoor-rs] broker trail checkpoint held at byte {}",
                state.offset
            );
        }
        if handled + duplicate_count + failed_count > 0 {
            println!(
                "[spoor-rs] {} {} payload(s), duplicates {}, failed {}",
                if dry_run { "previewed" } else { "posted" },
                handled,
                duplicate_count,
                failed_count
            );
        }
        if once {
            return !blocked;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn run_artex_loop(
    data: &Path,
    state_dir: &Path,
    dry_run: bool,
    once: bool,
    replay: bool,
    dedupe: Option<Arc<Mutex<DedupeStore>>>,
) -> bool {
    let interval = std::env::var("ARTEX_POLL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(10)
        .max(1);
    let password = match std::env::var("ARTEX_PASSWORD") {
        Ok(password) if !password.is_empty() => password,
        _ => {
            eprintln!("[spoor-rs] artex-api source needs ARTEX_PASSWORD");
            return false;
        }
    };
    let base = std::env::var("ARTEX_API_URL")
        .unwrap_or_else(|_| "http://host.docker.internal:8787".into());
    let username = std::env::var("ARTEX_USERNAME").unwrap_or_else(|_| "ARTEX".into());
    let task = std::env::var("SPOOR_TASK")
        .ok()
        .and_then(|value| value.trim().parse::<i64>().ok());
    let state_path = state_dir.join("spoor.artex-state.json");
    let preview = state_dir.join("ingest-preview.rust.jsonl");
    let failed = state_dir.join("failed-queue.rust.jsonl");
    let _ = data;
    let ingest = ingest_url();
    let key = api_key();
    let client = ArtexClient::new(&base, &username, &password, HttpTransport);
    let mut poller = ArtexCommandPoller::new(client, state_path, task);
    if replay {
        poller.reset();
        eprintln!("[spoor-rs] artex cursor reset for replay");
    }
    loop {
        let mut blocked = false;
        match poller.fetch() {
            Ok(records) => {
                let mut sent = 0usize;
                let mut duplicate_count = 0usize;
                let mut failed_count = 0usize;
                for record in records {
                    let payload = map_artex_command(&record);
                    let dedupe_key = dedupe.as_ref().map(|_| {
                        DedupeStore::key(
                            record["tool"].as_str().unwrap_or(""),
                            record["command"].as_str().unwrap_or(""),
                            record["created_at"].as_str(),
                        )
                    });
                    match deliver_ingest(
                        &ingest,
                        &payload,
                        key.as_deref(),
                        dry_run,
                        &preview,
                        &failed,
                        dedupe.as_ref(),
                        "artex-api",
                        dedupe_key,
                    ) {
                        Delivery::Sent => sent += 1,
                        Delivery::Duplicate => duplicate_count += 1,
                        Delivery::Queued => failed_count += 1,
                        Delivery::Blocked => {
                            blocked = true;
                            eprintln!("[spoor-rs] ARTEX cursor held before an unsaved event");
                            break;
                        }
                    }
                    poller.acknowledge(&record, !dry_run);
                }
                println!(
                    "[spoor-rs] {} {} artex command(s), duplicates {}, failed {}",
                    if dry_run { "previewed" } else { "posted" },
                    sent,
                    duplicate_count,
                    failed_count
                );
            }
            Err(err) => {
                blocked = true;
                eprintln!(
                    "[spoor-rs] artex api error: {} (retrying in {}s)",
                    err, interval
                );
            }
        }
        if once {
            return !blocked;
        }
        std::thread::sleep(Duration::from_secs(interval));
    }
}

fn deliver_ingest(
    base: &str,
    payload: &IngestPayload,
    key: Option<&str>,
    dry_run: bool,
    preview: &Path,
    failed: &Path,
    dedupe: Option<&Arc<Mutex<DedupeStore>>>,
    source: &str,
    dedupe_key: Option<String>,
) -> Delivery {
    // Hold the shared lock through post + mark so the two watcher threads
    // cannot both pass the duplicate check before either records the key.
    let mut store_guard = if dry_run {
        None
    } else {
        dedupe.map(|store| store.lock().unwrap())
    };
    if let (Some(store), Some(dedupe_key)) = (store_guard.as_mut(), dedupe_key.as_deref()) {
        // Direct history may duplicate an execution, but cannot replace the
        // paired completion of a broker call.
        let broker_completion =
            source == "broker" && payload.tool.arguments["call_id"].as_str().is_some();
        if !broker_completion && store.is_cross_duplicate(source, dedupe_key) {
            return Delivery::Duplicate;
        }
    }
    if dry_run {
        return if append_jsonl(preview, &serde_json::to_value(payload).unwrap()) {
            Delivery::Sent
        } else {
            Delivery::Blocked
        };
    }
    if post_payload(base, payload, key) {
        if let (Some(store), Some(dedupe_key)) = (store_guard.as_mut(), dedupe_key) {
            store.mark(source, &dedupe_key);
        }
        Delivery::Sent
    } else if append_durable_jsonl(failed, &serde_json::to_value(payload).unwrap()) {
        Delivery::Queued
    } else {
        Delivery::Blocked
    }
}

struct HttpTransport;

impl ArtexTransport for HttpTransport {
    fn call(
        &mut self,
        method: &str,
        url: &str,
        body: Option<&str>,
        headers: &Headers,
    ) -> (u16, String) {
        http_request(method, url, body, headers).unwrap_or((0, String::new()))
    }
}

fn http_request(
    method: &str,
    url: &str,
    body: Option<&str>,
    headers: &Headers,
) -> std::io::Result<(u16, String)> {
    http_request_with_host(method, url, body, headers, None)
}

fn http_request_with_host(
    method: &str,
    url: &str,
    body: Option<&str>,
    headers: &Headers,
    host_header: Option<&str>,
) -> std::io::Result<(u16, String)> {
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "only http:// URLs are supported",
        )
    })?;
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, port.parse::<u16>().unwrap_or(80)),
        None => (authority, 80),
    };
    let mut stream = std::net::TcpStream::connect((host, port))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    // Agentmetry's TrustedHost middleware rejects the container-facing hostname
    // (`host.docker.internal`), so the ingest call can present `localhost`
    // while still dialing the host gateway.
    let host_line = host_header.unwrap_or(authority);
    let mut request = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        method, path, host_line
    );
    for (name, value) in headers {
        request.push_str(&format!("{}: {}\r\n", name, value));
    }
    if let Some(body) = body {
        request.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    request.push_str("\r\n");
    if let Some(body) = body {
        request.push_str(body);
    }
    stream.write_all(request.as_bytes())?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let (head, body) = response.split_once("\r\n\r\n").unwrap_or((&response, ""));
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let chunked = head.to_lowercase().contains("transfer-encoding: chunked");
    let body = if chunked {
        decode_chunked(body).unwrap_or_else(|| body.to_string())
    } else {
        body.to_string()
    };
    Ok((status, body))
}

/// Decode a chunked HTTP body; returns None if the framing is malformed.
fn decode_chunked(body: &str) -> Option<String> {
    let mut out = String::new();
    let mut rest = body;
    loop {
        let line_end = rest.find("\r\n")?;
        let size_text = rest[..line_end].split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16).ok()?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            break;
        }
        if rest.len() < size {
            return None;
        }
        out.push_str(&rest[..size]);
        rest = &rest[size..];
        if let Some(stripped) = rest.strip_prefix("\r\n") {
            rest = stripped;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_broker(directory: &Path, strict_audit: bool) -> BrokerState {
        let policy = serde_json::from_str(include_str!("../../policy.json")).unwrap();
        BrokerState::new(
            Engine::from_policy(policy),
            directory.join("broker-events.jsonl"),
            directory.join("approvals"),
            strict_audit,
        )
    }

    fn fail_after_append(file: &fs::File, _: &Path) -> std::io::Result<()> {
        assert!(file.metadata()?.len() > 0);
        Err(std::io::Error::other("simulated audit sync failure"))
    }

    #[tokio::test]
    async fn strict_audit_refuses_allow_when_sync_fails_after_append() {
        let directory = tempfile::tempdir().unwrap();
        let mut state = test_broker(directory.path(), true);
        state.audit_sync = fail_after_append;
        let Json(response) = decide(State(state.clone()), Json(json!({"tool": "demo"}))).await;
        assert_eq!(response["decision"], "deny");
        assert_eq!(response["rule_id"], "audit-unavailable");
        assert_eq!(response["audit_recorded"], false);
        assert!(state.pending_reports.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn completion_stays_pending_when_sync_fails_after_append() {
        let directory = tempfile::tempdir().unwrap();
        let mut state = test_broker(directory.path(), false);
        let Json(decision) = decide(State(state.clone()), Json(json!({"tool": "demo"}))).await;
        assert_eq!(decision["decision"], "allow");
        let call_id = decision["call_id"].as_str().unwrap();
        state.audit_sync = fail_after_append;
        let Json(response) = report(
            State(state.clone()),
            Json(json!({"call_id": call_id, "tool": "demo", "exit_code": 0, "duration_ms": 1})),
        )
        .await;
        assert_eq!(response["ok"], false);
        assert_eq!(response["reason"], "audit-unavailable");
        assert!(state.pending_reports.lock().unwrap().contains_key(call_id));
    }

    #[test]
    fn decodes_chunked_bodies() {
        let body = "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(body).as_deref(), Some("hello world"));
    }

    #[test]
    fn malformed_chunked_returns_none() {
        assert_eq!(decode_chunked("zz\r\nhello\r\n"), None);
    }

    #[test]
    fn broker_event_parent_metadata_is_optional_and_bounded() {
        let base = json!({"type": "decide", "tool": "nmap"});
        let absent = with_parent_command_line(base.clone(), None);
        assert!(absent.get("parent_command_line").is_none());

        let present = with_parent_command_line(base, Some("/app/artex --worker"));
        assert_eq!(present["parent_command_line"], "/app/artex --worker");

        let long = json!("x".repeat(3000));
        let bounded = bounded_parent_command_line(&long).unwrap();
        assert!(bounded.ends_with("[truncated]"));
        assert!(bounded.chars().count() <= 2060);
        assert!(bounded_parent_command_line(&json!("\n\t")).is_none());
    }
}

fn post_payload(base: &str, payload: &IngestPayload, api_key: Option<&str>) -> bool {
    #[derive(serde::Serialize)]
    struct AgentmetryRequest<'a> {
        adapter: &'static str,
        #[serde(flatten)]
        event: &'a IngestPayload,
    }

    let body = match serde_json::to_string(&AgentmetryRequest {
        adapter: "spoor",
        event: payload,
    }) {
        Ok(body) => body,
        Err(err) => {
            eprintln!("[spoor-rs] could not serialize ingest payload: {}", err);
            return false;
        }
    };
    let url = format!("{}/api/v1/audit/ingest", base.trim_end_matches('/'));
    for attempt in 0..3u32 {
        match http_post(&url, &body, api_key) {
            Ok(code) if (200..300).contains(&code) => return true,
            Ok(code) if code == 400 || code == 401 || code == 403 || code == 404 => {
                eprintln!("[spoor-rs] ingest rejected {}", code);
                return false;
            }
            _ => {}
        }
        std::thread::sleep(Duration::from_millis(500 * (1 << attempt)));
    }
    false
}

fn http_post(url: &str, body: &str, api_key: Option<&str>) -> std::io::Result<u16> {
    let mut headers = Headers::new();
    if let Some(key) = api_key {
        headers.insert("X-API-Key".to_string(), key.to_string());
    }
    let host_header = std::env::var("AGENTMETRY_HOST_HEADER").ok();
    let (status, _) =
        http_request_with_host("POST", url, Some(body), &headers, host_header.as_deref())?;
    Ok(status)
}

// ------------------------------------------------------------ export

fn export_tracesig(args: &[String]) -> i32 {
    let broker = arg_value(args, "--broker").unwrap_or_else(|| "data/broker-events.jsonl".into());
    let artex = arg_value(args, "--artex");
    let agentmetry = arg_value(args, "--agentmetry");
    let out = arg_value(args, "-o")
        .or_else(|| arg_value(args, "--out"))
        .unwrap_or_else(|| "data/tracesig-trace.jsonl".into());
    let policy_path = arg_value(args, "--policy").unwrap_or_else(|| "rust/policy.json".to_string());
    let engine = match Engine::load(&policy_path) {
        Ok(engine) => engine,
        Err(err) => {
            eprintln!("cannot load policy: {}", err);
            return 1;
        }
    };
    let mut lines: Vec<String> = Vec::new();
    if let Ok(text) = fs::read_to_string(&broker) {
        export_broker_trail(&engine, &text, &mut lines);
    }
    if let Some(path) = &artex {
        match fs::read_to_string(path) {
            Ok(text) => export_artex_trail(&engine, &text, &mut lines),
            Err(err) => eprintln!("cannot read artex trail {}: {}", path, err),
        }
    }
    if let Some(path) = &agentmetry {
        match fs::read_to_string(path) {
            Ok(text) => export_agentmetry_trail(&engine, &text, &mut lines),
            Err(err) => eprintln!("cannot read agentmetry trail {}: {}", path, err),
        }
    }
    if lines.is_empty() {
        eprintln!(
            "[spoor-rs] no input events found (broker={}, artex={:?}, agentmetry={:?})",
            broker, artex, agentmetry
        );
        return 1;
    }
    let (lines, dropped) = dedupe_traces(lines);
    if let Some(parent) = Path::new(&out).parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(&out, lines.join("\n") + "\n");
    println!(
        "[spoor-rs] {} trace line(s), {} cross-source duplicate(s) dropped -> {}",
        lines.len(),
        dropped,
        out
    );
    0
}

fn dedupe_traces(lines: Vec<String>) -> (Vec<String>, usize) {
    let mut seen: HashMap<(String, String, String, String), String> = HashMap::new();
    let mut out = Vec::new();
    let mut dropped = 0usize;
    for line in lines {
        let value: Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(_) => {
                out.push(line);
                continue;
            }
        };
        let key = (
            value["session_id"].as_str().unwrap_or("").to_string(),
            value["tool"].as_str().unwrap_or("").to_string(),
            value["args"].as_str().unwrap_or("").to_string(),
            minute_of(value["raw"]["event_time"].as_str()),
        );
        let source = value["raw"]["bridge_source"]
            .as_str()
            .unwrap_or("")
            .to_string();
        if let Some(previous) = seen.get(&key) {
            if previous != &source {
                dropped += 1;
                continue;
            }
        } else {
            seen.insert(key, source);
        }
        out.push(line);
    }
    (out, dropped)
}

fn minute_of(timestamp: Option<&str>) -> String {
    let Some(raw) = timestamp else {
        return String::new();
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return String::new();
    }
    if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(raw) {
        return (parsed.timestamp() / 60).to_string();
    }
    raw.chars().take(16).collect()
}

fn export_artex_trail(engine: &Engine, text: &str, lines: &mut Vec<String>) {
    let mut seq: HashMap<String, u64> = HashMap::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let (session, tool, command, verdict, raw) = if value.get("correlation_id").is_some() {
            (
                value["correlation_id"]
                    .as_str()
                    .unwrap_or("artex-task-unknown")
                    .to_string(),
                "bash".to_string(),
                value["tool"]["arguments"]["command"]
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
                if value["event_type"].as_str() == Some("tool_denied") {
                    "deny"
                } else {
                    "allow"
                },
                json!({
                    "event_type": value["event_type"],
                    "outcome": value["outcome"],
                    "event_time": value["created_at"],
                    "bridge_source": "artex-api",
                    "export_version": "1",
                }),
            )
        } else {
            let exploration = value["exploration_id"]
                .as_i64()
                .map(|id| id.to_string())
                .unwrap_or_else(|| "None".to_string());
            (
                format!("artex-task-{}", exploration),
                value["tool"].as_str().unwrap_or("bash").to_string(),
                value["command"].as_str().unwrap_or("").to_string(),
                "allow",
                json!({
                    "exploration_id": value["exploration_id"],
                    "worker": value["worker"],
                    "is_error": value["is_error"],
                    "event_time": value["created_at"],
                    "bridge_source": "artex-api",
                    "export_version": "1",
                }),
            )
        };
        let labels = engine.derive_labels(&command);
        let counter = seq.entry(session.clone()).or_insert(0);
        let seq_value = *counter;
        *counter += 1;
        let reason = value["reason"].as_str().unwrap_or("");
        let preview: String = reason.chars().take(120).collect();
        let trace = json!({
            "session_id": session,
            "seq": seq_value,
            "tool": tool,
            "args": command,
            "labels": labels,
            "result_preview": preview,
            "verdict": verdict,
            "raw": raw,
        });
        lines.push(trace.to_string());
    }
}

fn export_broker_trail(engine: &Engine, text: &str, lines: &mut Vec<String>) {
    let mut seq: HashMap<String, u64> = HashMap::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if value["type"].as_str() != Some("decide") {
            continue;
        }
        let session = value["session"]
            .as_str()
            .unwrap_or("lab-session")
            .to_string();
        let tool = value["tool"].as_str().unwrap_or("tool").to_string();
        let command = value["command"].as_str().unwrap_or("").to_string();
        let labels = engine.derive_labels(&command);
        let counter = seq.entry(session.clone()).or_insert(0);
        let seq_value = *counter;
        *counter += 1;
        let verdict = match value["decision"].as_str().unwrap_or("allow") {
            "deny" => "deny",
            "ask" => "review",
            _ => "allow",
        };
        let reason = value["reason"].as_str().unwrap_or("");
        let preview: String = reason.chars().take(120).collect();
        let trace = json!({
            "session_id": session,
            "seq": seq_value,
            "tool": tool,
            "args": command,
            "labels": labels,
            "result_preview": preview,
            "verdict": verdict,
            "raw": {
                "call_id": value["call_id"],
                "rule_id": value["rule_id"],
                "task": value["task"],
                "event_time": value["ts"],
                "bridge_source": "broker",
                "export_version": "1",
            },
        });
        lines.push(trace.to_string());
    }
}

fn export_agentmetry_trail(engine: &Engine, text: &str, lines: &mut Vec<String>) {
    let mut seq: HashMap<String, u64> = HashMap::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let event = value.get("event").cloned().unwrap_or_else(|| value.clone());
        let action = &event["action"];
        let arguments = &event["tool"]["arguments"];
        if arguments["phase"] == "completion" {
            // TraceSig sequences use decisions, as in the broker export.
            continue;
        }
        let action_type = action["type"].as_str().unwrap_or("");
        if action_type != "tool_called" && action_type != "tool_failed" {
            continue;
        }
        let session = event["session_id"]
            .as_str()
            .or(event["correlation_id"].as_str())
            .unwrap_or("agentmetry-session")
            .to_string();
        let tool = event["tool"]["name"]
            .as_str()
            .or(event["tool"]["qualified"].as_str())
            .unwrap_or("tool")
            .to_string();
        let mut command = event["tool"]["command"]
            .as_str()
            .or_else(|| arguments["command"].as_str())
            .unwrap_or("")
            .to_string();
        if command.is_empty() {
            let qualified = event["tool"]["qualified"]
                .as_str()
                .unwrap_or(&tool)
                .to_string();
            let hash = event["tool"]["input_hash"].as_str().unwrap_or("");
            command = if hash.is_empty() {
                qualified
            } else {
                format!("{} (hash:{})", qualified, &hash[..hash.len().min(12)])
            };
        }
        // Agentmetry stores the tool as `bash` for shell calls; provenance
        // patterns match on the command text, same as the Python exporter.
        let labels = engine.derive_labels(&command);
        let counter = seq.entry(session.clone()).or_insert(0);
        let seq_value = *counter;
        *counter += 1;
        let verdict = match action["outcome"].as_str().unwrap_or("success") {
            "denied" => "deny",
            "pending"
                if event["source_topic"]
                    .as_str()
                    .is_some_and(|topic| topic.ends_with("/tool_authorized")) =>
            {
                "allow"
            }
            "pending" => "review",
            _ => "allow",
        };
        let reason = action["reason"].as_str().unwrap_or("");
        let preview: String = reason.chars().take(120).collect();
        let trace = json!({
            "session_id": session,
            "seq": seq_value,
            "tool": tool,
            "args": command,
            "labels": labels,
            "result_preview": preview,
            "verdict": verdict,
            "raw": {
                "event_id": event["event_id"],
                "action_type": action_type,
                "outcome": action["outcome"],
                "app": event["source"]["app"],
                "event_time": event["timestamp_utc"],
                "bridge_source": "agentmetry",
                "export_version": "1",
            },
        });
        lines.push(trace.to_string());
    }
}
