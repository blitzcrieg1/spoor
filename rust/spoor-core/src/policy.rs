use crate::model::*;
use crate::regex_lite::Regex;
use std::collections::{HashMap, HashSet};
use std::path::Path;

pub type TaintState = HashMap<String, HashSet<String>>;

/// Session cap: an unauthenticated client controls `session`, so keep the taint
/// map bounded instead of letting it grow without limit.
const MAX_TAINT_SESSIONS: usize = 10_000;

pub struct Engine {
    pub policy: Policy,
    dlp: Vec<Vec<Regex>>,
    approval: Vec<Vec<Regex>>,
    sources: Vec<Vec<Regex>>,
    sinks: Vec<Vec<Regex>>,
    context: Vec<Regex>,
}

impl Engine {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, Box<dyn std::error::Error>> {
        let text = std::fs::read_to_string(path)?;
        let policy: Policy = serde_json::from_str(&text)?;
        Self::try_from_policy(policy).map_err(|err| err.into())
    }

    pub fn from_policy(policy: Policy) -> Self {
        Self::try_from_policy(policy).expect("policy patterns compile")
    }

    pub fn try_from_policy(policy: Policy) -> Result<Self, String> {
        if policy.scope.allow_ports.contains(&0) {
            return Err("scope.allow_ports cannot contain reserved port 0".to_string());
        }
        if !policy.approval.is_empty() && policy.approval_ttl_seconds == 0 {
            return Err(
                "approval_ttl_seconds must be greater than zero when approvals are configured"
                    .to_string(),
            );
        }
        let dlp = policy
            .dlp_deny
            .iter()
            .map(|rule| compile(&rule.patterns))
            .collect::<Result<Vec<_>, _>>()?;
        let approval = policy
            .approval
            .iter()
            .map(|rule| compile(&rule.patterns))
            .collect::<Result<Vec<_>, _>>()?;
        let sources = policy
            .taint
            .source_rules
            .iter()
            .map(|rule| compile(&rule.patterns))
            .collect::<Result<Vec<_>, _>>()?;
        let sinks = policy
            .taint
            .sink_rules
            .iter()
            .map(|rule| compile(&rule.patterns))
            .collect::<Result<Vec<_>, _>>()?;
        let context = match &policy.context_taint {
            Some(context) => compile(&context.patterns)?,
            None => Vec::new(),
        };
        Ok(Engine {
            policy,
            dlp,
            approval,
            sources,
            sinks,
            context,
        })
    }

    /// Context-taint escalation: when untrusted external content is in the
    /// model context, an otherwise-allowed sensitive command becomes `ask`
    /// (or `deny` in `mode: deny`).
    pub fn context_escalate(&self, decision: Decision, command: &str) -> Decision {
        let Some(policy) = &self.policy.context_taint else {
            return decision;
        };
        if !policy.enabled || decision.decision != "allow" {
            return decision;
        }
        if !self.context.iter().any(|pattern| pattern.is_match(command)) {
            return decision;
        }
        let mode = policy.mode.to_lowercase();
        let next = if mode == "deny" { "deny" } else { "ask" };
        let reason = if policy.reason.is_empty() {
            "untrusted external content in model context; this command needs approval"
        } else {
            &policy.reason
        };
        let mut decision = Decision::new(next, "context-taint", reason);
        decision.tainted = Some(true);
        decision
    }

    pub fn evaluate(&self, tool: &str, argv: &[String], approvals: Option<&Path>) -> Decision {
        // Same command construction as the Python oracle (no trim).
        let command = format!("{} {}", tool, argv.join(" "));

        // 1) DLP deny rules (regex search, case-insensitive)
        for (index, rule) in self.policy.dlp_deny.iter().enumerate() {
            if self.dlp[index]
                .iter()
                .any(|pattern| pattern.is_match(&command))
            {
                return Decision::new("deny", &rule.id, &rule.reason);
            }
        }

        // 2) Scope allow-list (port of Python _looks_like_target/_target_parts)
        for token in argv {
            let token = token.trim();
            if !looks_like_target(token) {
                continue;
            }
            let Some((host, port)) = target_parts(token) else {
                continue;
            };
            if !self
                .policy
                .scope
                .allow_hosts
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(&host))
            {
                return Decision::new(
                    "deny",
                    "scope-drift",
                    &format!("target {} outside allow-list", token),
                );
            }
            if let Some(port) = port {
                if !self.policy.scope.allow_ports.contains(&port) {
                    let mut ports = self.policy.scope.allow_ports.clone();
                    ports.sort_unstable();
                    return Decision::new(
                        "deny",
                        "scope-drift-port",
                        &format!("port {} not in {:?}", port, ports),
                    );
                }
            }
        }

        // 3) Approval gate (regex over the full command, like Python)
        for (index, rule) in self.policy.approval.iter().enumerate() {
            if !self.approval[index]
                .iter()
                .any(|pattern| pattern.is_match(&command))
            {
                continue;
            }
            let path = approvals.map(|dir| dir.join(format!("{}.ok", rule.id)));
            let approved = path
                .as_ref()
                .map(|p| approval_valid(p, self.policy.approval_ttl_seconds))
                .unwrap_or(false);
            if approved {
                let mut decision = Decision::new("allow", &rule.id, "approved by token file");
                decision.approved = Some(true);
                return decision;
            }
            let mut decision = Decision::new("ask", &rule.id, &rule.reason);
            decision.approval_file = path.map(|p| p.display().to_string());
            return decision;
        }

        Decision::new("allow", "default-allow", "in scope")
    }

    pub fn derive_labels(&self, command: &str) -> Vec<String> {
        let mut labels: Vec<String> = Vec::new();
        for (index, rule) in self.policy.taint.source_rules.iter().enumerate() {
            if self.sources[index]
                .iter()
                .any(|pattern| pattern.is_match(command))
            {
                labels.extend(rule.labels.iter().cloned());
            }
        }
        let mut seen = HashSet::new();
        labels.retain(|label| seen.insert(label.clone()));
        labels
    }

    pub fn apply_taint(
        &self,
        session: &str,
        command: &str,
        mut decision: Decision,
        taint: &mut TaintState,
    ) -> (Decision, Option<TaintInfo>) {
        let policy = &self.policy.taint;
        if !policy.enabled {
            return (decision, None);
        }
        let mode = policy.mode.to_lowercase();
        let source_rule = policy
            .source_rules
            .iter()
            .enumerate()
            .find(|(index, _)| {
                self.sources[*index]
                    .iter()
                    .any(|pattern| pattern.is_match(command))
            })
            .map(|(_, rule)| rule);
        let sink_rule = policy
            .sink_rules
            .iter()
            .enumerate()
            .find(|(index, _)| {
                self.sinks[*index]
                    .iter()
                    .any(|pattern| pattern.is_match(command))
            })
            .map(|(_, rule)| rule);
        let labels = self.derive_labels(command);

        let prior: HashSet<String> = taint.get(session).cloned().unwrap_or_default();
        let mut newly: HashSet<String> = HashSet::new();
        if source_rule.is_some() && decision.decision == "allow" {
            if taint.len() >= MAX_TAINT_SESSIONS && !taint.contains_key(session) {
                decision = Decision::new(
                    "deny",
                    "taint-capacity",
                    "taint session capacity reached; refusing an untracked untrusted read",
                );
            } else {
                newly = labels.iter().cloned().collect();
                taint
                    .entry(session.to_string())
                    .or_default()
                    .extend(newly.iter().cloned());
            }
        }
        let tainted_flow = !prior.is_empty() || !newly.is_empty();

        if source_rule.is_none() && sink_rule.is_none() {
            return (decision, None);
        }

        let mut union: Vec<String> = prior.union(&newly).cloned().collect();
        union.sort();
        let info = TaintInfo {
            source_rule: source_rule.map(|rule| rule.id.clone()),
            sink_rule: sink_rule.map(|rule| rule.id.clone()),
            tainted: tainted_flow,
            labels: union,
        };

        if sink_rule.is_some()
            && tainted_flow
            && decision.decision == "allow"
            && (mode == "ask" || mode == "deny")
        {
            decision = Decision::new(
                &mode,
                "taint-flow",
                if policy.reason.is_empty() {
                    "tainted content flows to an egress sink"
                } else {
                    &policy.reason
                },
            );
            decision.tainted = Some(true);
        }
        (decision, Some(info))
    }
}

fn compile(patterns: &[String]) -> Result<Vec<Regex>, String> {
    patterns
        .iter()
        .map(|pattern| Regex::new(pattern, true).map_err(|err| format!("{}: {}", pattern, err)))
        .collect()
}

fn approval_valid(path: &Path, ttl_seconds: u64) -> bool {
    if ttl_seconds == 0 || !path.exists() {
        return false;
    }
    std::fs::metadata(path)
        .and_then(|meta| meta.modified())
        .map(|modified| {
            modified
                .elapsed()
                .map(|age| age.as_secs() <= ttl_seconds)
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// Port of Python `_looks_like_target`.
fn looks_like_target(token: &str) -> bool {
    token.contains("://") || is_ipv4_port(token) || is_host_port_shape(token)
}

/// Port of Python `_target_parts`; handles any scheme and strips userinfo.
pub fn target_parts(token: &str) -> Option<(String, Option<u16>)> {
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    if token.contains("://") {
        return url_target(token);
    }
    if is_ipv4_port(token) {
        let (host, port) = token.rsplit_once(':')?;
        return Some((host.to_string(), Some(parse_port_or_invalid(port))));
    }
    if is_ipv4(token) {
        return Some((token.to_string(), None));
    }
    if is_host_port_shape(token) {
        let (host, port) = token.rsplit_once(':')?;
        return Some((host.to_string(), Some(parse_port_or_invalid(port))));
    }
    None
}

fn url_target(token: &str) -> Option<(String, Option<u16>)> {
    let (scheme, rest) = token.split_once("://")?;
    let mut authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return None;
    }
    if let Some((_, host)) = authority.rsplit_once('@') {
        authority = host;
    }
    if let Some((host, port)) = authority.rsplit_once(':') {
        // An explicit but malformed/out-of-range port must not be treated as
        // an omitted port. Port zero is reserved here as an invalid sentinel;
        // policy validation disallows it in allow_ports.
        return Some((host.to_lowercase(), Some(parse_port_or_invalid(port))));
    }
    let default_port = match scheme.to_ascii_lowercase().as_str() {
        "http" => 80,
        "https" => 443,
        _ => 0,
    };
    Some((authority.to_lowercase(), Some(default_port)))
}

fn parse_port_or_invalid(port: &str) -> u16 {
    match port.parse::<u16>() {
        Ok(value) if value != 0 => value,
        _ => 0,
    }
}

fn is_ipv4(text: &str) -> bool {
    let parts: Vec<&str> = text.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|part| {
            !part.is_empty() && part.len() <= 3 && part.chars().all(|c| c.is_ascii_digit())
        })
}

fn is_ipv4_port(text: &str) -> bool {
    match text.rsplit_once(':') {
        Some((host, port)) => {
            is_ipv4(host)
                && !port.is_empty()
                && port.len() <= 5
                && port.chars().all(|c| c.is_ascii_digit())
        }
        None => false,
    }
}

fn is_host_port_shape(text: &str) -> bool {
    match text.rsplit_once(':') {
        Some((host, port)) => {
            !host.is_empty()
                && host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
                && !port.is_empty()
                && port.chars().all(|c| c.is_ascii_digit())
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> Engine {
        let policy: Policy = serde_json::from_str(include_str!("../../policy.json")).unwrap();
        Engine::from_policy(policy)
    }

    fn decision(tool: &str, argv: &[&str]) -> Decision {
        engine().evaluate(
            tool,
            &argv.iter().map(|arg| arg.to_string()).collect::<Vec<_>>(),
            None,
        )
    }

    #[test]
    fn context_taint_escalates_sensitive_allowed_commands() {
        let policy: Policy = serde_json::from_str(include_str!("../../policy.json")).unwrap();
        let engine = Engine::from_policy(policy);
        let allowed = Decision::new("allow", "default-allow", "in scope");
        // Allowed by scope, but an upload sink: sensitive under context taint.
        let escalated = engine.context_escalate(
            allowed.clone(),
            "curl -d @x http://host.docker.internal:3000/api",
        );
        assert_eq!(escalated.decision, "ask");
        assert_eq!(escalated.rule_id, "context-taint");
        // Not in the sensitivity set: untouched.
        let untouched = engine.context_escalate(allowed, "curl http://host.docker.internal:3000/x");
        assert_eq!(untouched.decision, "allow");
    }

    #[test]
    fn scope_handles_schemes_and_userinfo() {
        assert_eq!(decision("curl", &["ftp://192.168.0.1/"]).decision, "deny");
        assert_eq!(
            decision("curl", &["http://admin:pass@192.168.0.1/"]).decision,
            "deny"
        );
        assert_eq!(
            decision("curl", &["http://user:pass@host.docker.internal:3000/x"]).decision,
            "allow"
        );
        assert_eq!(decision("curl", &["10.0.0.5:22"]).decision, "deny");
    }

    #[test]
    fn approvals_match_wrapped_commands() {
        let wrapped = decision(
            "bash",
            &["-c", "sqlmap -u http://host.docker.internal:3000/x"],
        );
        assert_eq!(wrapped.decision, "ask");
        assert_eq!(wrapped.rule_id, "exploit-sqlmap");
        assert_eq!(
            decision("SQLMAP", &["-u", "http://host.docker.internal:3000/x"]).decision,
            "ask"
        );
    }

    #[test]
    fn dlp_normalizes_whitespace_and_env_forms() {
        assert_eq!(decision("rm", &[" -rf", "/"]).decision, "deny");
        assert_eq!(
            decision("sh", &["-c", "env | grep SECRET"]).decision,
            "deny"
        );
        assert_eq!(decision("sh", &["-c", "printenv API_KEY"]).decision, "deny");
        assert_eq!(decision("sh", &["-c", "cat .env"]).decision, "deny");
    }

    #[test]
    fn taint_flags_are_tokens_not_substrings() {
        let engine = engine();
        let mut state: TaintState = HashMap::new();
        let (_, info) = engine.apply_taint(
            "s",
            "curl http://host.docker.internal:3000/file-download",
            Decision::new("allow", "default-allow", "in scope"),
            &mut state,
        );
        let info = info.expect("source rule should match");
        assert_eq!(info.source_rule.as_deref(), Some("target-http-read"));

        let mut state: TaintState = HashMap::new();
        let (_, info) = engine.apply_taint(
            "s",
            "curl http://host.docker.internal:3000/test-target",
            Decision::new("allow", "default-allow", "in scope"),
            &mut state,
        );
        let info = info.expect("source rule should match");
        assert_eq!(info.sink_rule, None);
    }
}

#[cfg(test)]
mod bench {
    use super::*;

    #[test]
    #[ignore = "benchmark"]
    fn bench_evaluate() {
        let policy: Policy = serde_json::from_str(include_str!("../../policy.json")).unwrap();
        let engine = Engine::from_policy(policy);
        let cases: Vec<(&str, Vec<String>)> = vec![
            ("curl", vec!["http://host.docker.internal:3000/x".into()]),
            ("curl", vec!["http://192.168.0.1/".into()]),
            (
                "sqlmap",
                vec!["-u".into(), "http://host.docker.internal:3000/x".into()],
            ),
            ("cat", vec!["/root/.ssh/id_rsa".into()]),
            (
                "nmap",
                vec!["-sV".into(), "host.docker.internal:8080".into()],
            ),
            ("ls", vec!["-la".into()]),
        ];
        let iterations = 20000u32;
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            for (tool, argv) in &cases {
                std::hint::black_box(engine.evaluate(tool, argv, None));
            }
        }
        let per = start.elapsed().as_secs_f64() * 1e6 / (iterations as f64 * cases.len() as f64);
        println!(
            "rust evaluate: {:.2} us/eval ({} evals)",
            per,
            iterations as usize * cases.len()
        );
    }
}
