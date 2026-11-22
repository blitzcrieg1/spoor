//! Curated agentic-framework indicators (ThreatDefence ARTEX set).
//!
//! These are deliberate, high-signal strings from the public ARTEX code and
//! reporting: user agents, probe markers, and model-envelope fingerprints.
//! A match is a lead for annotation, never a verdict.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameworkMatch {
    pub framework: String,
    pub indicator: String,
    pub kind: String,
    pub confidence: String,
}

/// (value, kind, confidence, framework). Case-insensitive substring match.
const INDICATORS: &[(&str, &str, &str, &str)] = &[
    // ARTEX user agents (code defaults and reported variants)
    ("norma/0.4", "user_agent", "medium", "artex"),
    ("spa-api-recon", "user_agent", "high", "artex"),
    ("artex-readonly/", "user_agent", "high", "artex"),
    ("artex-pentest/", "user_agent", "high", "artex"),
    ("artex-audit/", "user_agent", "high", "artex"),
    ("artex-verify/", "user_agent", "high", "artex"),
    ("artex-spawn/", "user_agent", "high", "artex"),
    ("artex-worker/", "user_agent", "high", "artex"),
    ("artex-enrich/", "user_agent", "high", "artex"),
    ("artex-i21861-canary", "user_agent", "high", "artex"),
    ("artex-authorized-pentest", "user_agent", "high", "artex"),
    ("artexverify/", "user_agent", "medium", "artex"),
    ("scopeweaver", "user_agent", "high", "artex"),
    ("reconprobe/1.0", "user_agent", "medium", "artex"),
    ("azure-toolkit/1.0", "user_agent", "medium", "artex"),
    // Probe artifacts / web-shell markers
    ("x-artx-key", "header", "medium", "artex"),
    ("artex_write_probe", "command_marker", "medium", "artex"),
    ("artx_persist_ok", "command_marker", "medium", "artex"),
    ("artex_control_marker_zz9q", "command_marker", "medium", "artex"),
    ("artex-probe-", "command_marker", "high", "artex"),
    ("artex-probe-0001", "command_marker", "medium", "artex"),
    ("%artex_probe_unset%", "command_marker", "medium", "artex"),
    ("zzz-nonexistent-xyz123", "uri", "high", "artex"),
    ("zzz_nonexistent_abc.txt", "uri", "high", "artex"),
    ("notexist-xyz", "uri", "high", "artex"),
    ("eyjhbgciojnub25lin0.", "jwt", "medium", "artex"),
    ("callback?code=aaaa&state=notvalidb64", "uri", "high", "artex"),
    // ARTEX prompt envelopes (model-request fingerprints)
    ("<<<untrusted_output", "model_envelope", "high", "artex"),
    ("[[artex_data nonce=", "model_envelope", "high", "artex"),
    ("untrusted content handling (prompt-injection defense):", "model_envelope", "medium", "artex"),
    ("artex-data-marker-removed", "model_envelope", "medium", "artex"),
    // Other frameworks worth flagging in the same lab
    ("hexstrike-http-framework", "user_agent", "high", "hexstrike"),
    ("hexstrike-browseragent", "user_agent", "high", "hexstrike"),
    ("cyberstrikeai/", "user_agent", "high", "cyberstrikeai"),
    ("x-implant-token", "header", "high", "cyberstrikeai"),
    ("pentagi", "user_agent", "low", "pentagi"),
];

/// Scan one text blob (command, request/response body, or user agent).
pub fn scan(text: &str) -> Vec<FrameworkMatch> {
    let lower = text.to_ascii_lowercase();
    let mut matches: Vec<FrameworkMatch> = Vec::new();
    for (value, kind, confidence, framework) in INDICATORS {
        if lower.contains(value) {
            let entry = FrameworkMatch {
                framework: framework.to_string(),
                indicator: value.to_string(),
                kind: kind.to_string(),
                confidence: confidence.to_string(),
            };
            if !matches.contains(&entry) {
                matches.push(entry);
            }
        }
    }
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_artex_indicators() {
        let found = scan("curl -A 'Mozilla/5.0 (spa-api-recon)' http://juice-shop:3000/x");
        assert!(found.iter().any(|m| m.indicator == "spa-api-recon" && m.confidence == "high"));

        let found = scan("curl -H 'X-ARTX-KEY: probe' http://juice-shop:3000/zzz-nonexistent-xyz123");
        assert!(found.iter().any(|m| m.kind == "header"));
        assert!(found.iter().any(|m| m.kind == "uri"));
    }

    #[test]
    fn detects_model_envelopes_and_other_frameworks() {
        let found = scan("prefix <<<UNTRUSTED_OUTPUT abc>>>>> [[ARTEX_DATA nonce=00 field=x]]");
        assert!(found.iter().filter(|m| m.kind == "model_envelope").count() >= 2);

        let found = scan("HexStrike-HTTP-Framework/1.0 (Advanced Security Testing)");
        assert!(found.iter().any(|m| m.framework == "hexstrike"));
    }

    #[test]
    fn clean_commands_do_not_match() {
        assert!(scan("curl http://juice-shop:3000/api/Products").is_empty());
        assert!(scan("nmap -sV -p 3000 host.docker.internal").is_empty());
    }
}
