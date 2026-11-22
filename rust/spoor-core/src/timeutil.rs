use chrono::DateTime;

pub fn minute_bucket(ts: &str) -> String {
    match DateTime::parse_from_rfc3339(ts) {
        Ok(dt) => (dt.timestamp() / 60).to_string(),
        Err(_) => ts.chars().take(16).collect(),
    }
}
