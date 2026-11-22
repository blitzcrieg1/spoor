use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(unix)]
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Instant;

#[cfg(unix)]
static CHILD_PID: AtomicI32 = AtomicI32::new(0);

#[cfg(target_os = "linux")]
const MAX_PARENT_CMDLINE_BYTES: u64 = 8192;
#[cfg(any(target_os = "linux", test))]
const MAX_PARENT_CMDLINE_CHARS: usize = 2048;

fn main() {
    let mut args = std::env::args().skip(1);
    let tool = match args.next() {
        Some(tool) => tool,
        None => {
            eprintln!("usage: spoor-shim <tool> [args...]");
            std::process::exit(2);
        }
    };
    let argv: Vec<String> = args.collect();
    let broker =
        std::env::var("ARTEX_BROKER_URL").unwrap_or_else(|_| "http://127.0.0.1:8899".into());
    let session = std::env::var("ARTEX_SESSION_ID")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "lab-session".to_string());
    let task = std::env::var("ARTEX_TASK_ID").unwrap_or_default();
    let parent_command_line = capture_parent_command_line();
    let payload = build_payload(
        &tool,
        &argv,
        &session,
        &task,
        parent_command_line.as_deref(),
    );

    let (status, body) = match post_json(
        &format!("{}/decide", broker.trim_end_matches('/')),
        &payload.to_string(),
    ) {
        Ok(result) => result,
        Err(err) => {
            eprintln!("[spoor-shim] broker unreachable: {}", err);
            std::process::exit(126);
        }
    };
    if status != 200 {
        eprintln!("[spoor-shim] broker returned {} - refusing to run", status);
        std::process::exit(126);
    }
    let (decision, call_id) = parse_decision(&body).unwrap_or(("deny".to_string(), String::new()));
    if decision != "allow" {
        eprintln!("[spoor-shim] {}: {}", decision, body);
        std::process::exit(126);
    }

    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(PathBuf::from));
    let real = match resolve_tool(&tool, exe_dir.as_deref()) {
        Some(path) => path,
        None => {
            eprintln!("[spoor-shim] allowed but real '{}' not found on PATH", tool);
            std::process::exit(127);
        }
    };
    // Keep the shim directory on PATH for child processes launched by a shell
    // or script. The direct executable path above avoids recursion here.
    let child_path = std::env::var("PATH").unwrap_or_default();
    let started = Instant::now();
    let status = match Command::new(&real)
        .args(&argv)
        .env("PATH", &child_path)
        .spawn()
    {
        Ok(mut child) => {
            #[cfg(unix)]
            install_signal_forwarding(child.id() as i32);
            let status = child.wait();
            #[cfg(unix)]
            CHILD_PID.store(0, Ordering::SeqCst);
            status.map(|status| exit_code(&status)).unwrap_or(127)
        }
        Err(err) => {
            eprintln!("[spoor-shim] failed to launch {}: {}", tool, err);
            127
        }
    };
    let report = build_report_payload(
        &call_id,
        &tool,
        status,
        started.elapsed().as_millis() as u64,
        parent_command_line.as_deref(),
    );
    let _ = post_json(
        &format!("{}/report", broker.trim_end_matches('/')),
        &report.to_string(),
    );
    std::process::exit(status);
}

fn build_payload(
    tool: &str,
    argv: &[String],
    session: &str,
    task: &str,
    parent_command_line: Option<&str>,
) -> Value {
    let mut payload = json!({
        "tool": tool,
        "argv": argv,
        "session": session,
        "task": task,
    });
    if let Some(parent) = parent_command_line {
        payload["parent_command_line"] = json!(parent);
    }
    payload
}

fn build_report_payload(
    call_id: &str,
    tool: &str,
    exit_code: i32,
    duration_ms: u64,
    parent_command_line: Option<&str>,
) -> Value {
    let mut payload = json!({
        "call_id": call_id,
        "tool": tool,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
    });
    if let Some(parent) = parent_command_line {
        payload["parent_command_line"] = json!(parent);
    }
    payload
}

/// Read the immediate parent command line inside Linux containers. The
/// metadata is bounded and common credential-bearing arguments are redacted.
#[cfg(target_os = "linux")]
fn capture_parent_command_line() -> Option<String> {
    let parent_pid = unsafe { libc::getppid() };
    if parent_pid <= 1 {
        return None;
    }
    let file = std::fs::File::open(format!("/proc/{}/cmdline", parent_pid)).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_PARENT_CMDLINE_BYTES)
        .read_to_end(&mut bytes)
        .ok()?;
    normalize_parent_command_line(&bytes)
}

/// The Windows host build has no Linux procfs; the field remains optional.
#[cfg(not(target_os = "linux"))]
fn capture_parent_command_line() -> Option<String> {
    None
}

#[cfg(any(target_os = "linux", test))]
fn normalize_parent_command_line(raw: &[u8]) -> Option<String> {
    let args = raw
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty())
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect::<Vec<_>>();
    if args.is_empty() {
        return None;
    }

    let mut safe_args = Vec::new();
    let mut redact_next = false;
    for arg in args {
        if redact_next {
            safe_args.push("[REDACTED]".to_string());
            redact_next = false;
            continue;
        }
        if let Some((key, _)) = arg.split_once('=') {
            if is_sensitive_key(key) {
                safe_args.push(format!("{}=[REDACTED]", key));
                continue;
            }
        }
        if !arg.chars().any(char::is_whitespace) && is_sensitive_key(&arg) {
            safe_args.push(arg);
            redact_next = true;
            continue;
        }
        safe_args.push(redact_inline_secrets(&arg));
    }

    let cleaned = safe_args.join(" ");
    let normalized = cleaned
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
    if normalized.is_empty() {
        return None;
    }
    let mut bounded = normalized
        .chars()
        .take(MAX_PARENT_CMDLINE_CHARS)
        .collect::<String>();
    if normalized.chars().count() > MAX_PARENT_CMDLINE_CHARS {
        bounded.push_str(" [truncated]");
    }
    Some(bounded)
}

#[cfg(any(target_os = "linux", test))]
fn is_sensitive_key(value: &str) -> bool {
    let key = value
        .trim_start_matches('-')
        .trim_end_matches(':')
        .to_ascii_lowercase();
    [
        "password",
        "passwd",
        "token",
        "api-key",
        "apikey",
        "secret",
        "credential",
        "authorization",
        "auth",
        "cookie",
        "private-key",
        "access-key",
    ]
    .iter()
    .any(|marker| key.contains(marker))
}

#[cfg(any(target_os = "linux", test))]
fn redact_inline_secrets(value: &str) -> String {
    let mut output = Vec::new();
    let mut redact_next = false;
    for word in value.split_whitespace() {
        if redact_next {
            output.push("[REDACTED]".to_string());
            redact_next = false;
            continue;
        }
        if let Some((key, _)) = word.split_once('=') {
            if is_sensitive_key(key) {
                output.push(format!("{}=[REDACTED]", key));
                continue;
            }
        }
        if let Some((key, _)) = word.split_once(':') {
            if is_sensitive_key(key) {
                output.push(format!("{}:[REDACTED]", key));
                continue;
            }
        }
        if is_sensitive_key(word) {
            output.push(word.to_string());
            redact_next = true;
            continue;
        }
        if word.eq_ignore_ascii_case("bearer") {
            output.push("Bearer".to_string());
            redact_next = true;
            continue;
        }
        output.push(redact_url_userinfo(word));
    }
    output.join(" ")
}

#[cfg(any(target_os = "linux", test))]
fn redact_url_userinfo(value: &str) -> String {
    let Some(scheme_end) = value.find("://") else {
        return value.to_string();
    };
    let authority_start = scheme_end + 3;
    let authority_tail = &value[authority_start..];
    let authority_end = authority_tail
        .find(|character| matches!(character, '/' | '?' | '#' | '\'' | '"'))
        .unwrap_or(authority_tail.len());
    let authority = &authority_tail[..authority_end];
    let Some(at) = authority.rfind('@') else {
        return value.to_string();
    };
    format!(
        "{}[REDACTED]@{}",
        &value[..authority_start],
        &authority_tail[at + 1..]
    )
}

fn parse_decision(body: &str) -> Option<(String, String)> {
    let value: Value = serde_json::from_str(body).ok()?;
    let decision = value["decision"].as_str()?.to_string();
    let call_id = value["call_id"].as_str().unwrap_or("").to_string();
    Some((decision, call_id))
}

fn resolve_tool(tool: &str, skip: Option<&Path>) -> Option<PathBuf> {
    for dir in std::env::split_paths(&std::env::var("PATH").unwrap_or_default()) {
        if let Some(skip) = skip {
            if same_dir(&dir, skip) {
                continue;
            }
        }
        let candidate = dir.join(tool);
        if is_executable(&candidate) {
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            let exe = dir.join(format!("{}.exe", tool));
            if is_executable(&exe) {
                return Some(exe);
            }
        }
    }
    None
}

fn is_executable(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match path.metadata() {
            Ok(meta) => meta.permissions().mode() & 0o111 != 0,
            Err(_) => false,
        }
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn exit_code(status: &std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        return 128 + status.signal().unwrap_or(0);
    }
    #[cfg(not(unix))]
    {
        127
    }
}

fn same_dir(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

#[cfg(unix)]
fn install_signal_forwarding(child_pid: i32) {
    CHILD_PID.store(child_pid, Ordering::SeqCst);
    unsafe extern "C" fn forward(signal: libc::c_int) {
        let pid = CHILD_PID.load(Ordering::Relaxed);
        if pid > 0 {
            unsafe {
                libc::kill(pid, signal);
            }
        }
    }
    unsafe {
        let handler = forward as *const () as libc::sighandler_t;
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGHUP, handler);
        libc::signal(libc::SIGQUIT, handler);
    }
}

fn post_json(url: &str, body: &str) -> std::io::Result<(u16, String)> {
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
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path,
        authority,
        body.len(),
        body
    );
    stream.write_all(request.as_bytes())?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let (head, body) = response.split_once("\r\n\r\n").unwrap_or((&response, ""));
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    Ok((status, body.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_shape_matches_broker_contract() {
        let payload = build_payload(
            "curl",
            &["http://host.docker.internal:3000/x".into()],
            "s",
            "7",
            Some("/app/artex --worker"),
        );
        assert_eq!(payload["tool"], "curl");
        assert_eq!(payload["argv"][0], "http://host.docker.internal:3000/x");
        assert_eq!(payload["session"], "s");
        assert_eq!(payload["task"], "7");
        assert_eq!(payload["parent_command_line"], "/app/artex --worker");
        let report = build_report_payload("call-1", "curl", 0, 12, Some("/app/artex --worker"));
        assert_eq!(report["parent_command_line"], "/app/artex --worker");
    }

    #[test]
    fn proc_cmdline_normalization_redacts_common_secrets() {
        let raw = b"/bin/sh\0-c\0curl --api-key abc123 -H 'Authorization: Bearer bearer-secret' https://user:pass@example.test/x\0";
        let value = normalize_parent_command_line(raw).unwrap();
        assert!(value.contains("/bin/sh -c"));
        assert!(value.contains("--api-key [REDACTED]"));
        assert!(value.contains("Bearer [REDACTED]"));
        assert!(value.contains("https://[REDACTED]@example.test/x"));
        assert!(!value.contains("abc123"));
        assert!(!value.contains("bearer-secret"));
        assert!(!value.contains("user:pass"));
    }

    #[test]
    fn proc_cmdline_normalization_is_bounded() {
        let raw = format!("parent\0{}\0", "x".repeat(MAX_PARENT_CMDLINE_CHARS + 100));
        let value = normalize_parent_command_line(raw.as_bytes()).unwrap();
        assert!(value.ends_with("[truncated]"));
        assert!(value.chars().count() <= MAX_PARENT_CMDLINE_CHARS + 12);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_procfs_parent_capture_returns_bounded_metadata() {
        let value = capture_parent_command_line().expect("Linux parent cmdline should be readable");
        assert!(!value.is_empty());
        assert!(value.chars().count() <= MAX_PARENT_CMDLINE_CHARS + 12);
    }

    #[test]
    fn decision_parsing() {
        assert_eq!(
            parse_decision(r#"{"decision":"allow","call_id":"abc"}"#),
            Some(("allow".to_string(), "abc".to_string()))
        );
        assert_eq!(
            parse_decision(r#"{"decision":"deny","call_id":"d1"}"#).map(|pair| pair.0),
            Some("deny".to_string())
        );
        assert_eq!(parse_decision("not json"), None);
    }
}
