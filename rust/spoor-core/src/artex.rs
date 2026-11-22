use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};

pub type Headers = HashMap<String, String>;

pub trait ArtexTransport {
    fn call(
        &mut self,
        method: &str,
        url: &str,
        body: Option<&str>,
        headers: &Headers,
    ) -> (u16, String);
}

pub struct ArtexClient<T: ArtexTransport> {
    pub base_url: String,
    pub username: String,
    pub password: String,
    pub token: Option<String>,
    pub transport: T,
}

impl<T: ArtexTransport> ArtexClient<T> {
    pub fn new(base_url: &str, username: &str, password: &str, transport: T) -> Self {
        ArtexClient {
            base_url: base_url.trim_end_matches('/').to_string(),
            username: username.to_string(),
            password: password.to_string(),
            token: None,
            transport,
        }
    }

    pub fn login(&mut self) -> Result<String, String> {
        let body = serde_json::json!({
            "username": self.username,
            "password": self.password,
        })
        .to_string();
        let (status, text) = self.transport.call(
            "POST",
            &format!("{}/api/auth/login", self.base_url),
            Some(&body),
            &Headers::new(),
        );
        if status == 429 {
            return Err("login rate-limited (429) - wait and retry".to_string());
        }
        if status != 200 {
            return Err(format!(
                "login failed ({}): {}",
                status,
                truncate(&text, 200)
            ));
        }
        let token = serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|value| value["token"].as_str().map(String::from))
            .ok_or_else(|| "login response not JSON".to_string())?;
        if token.is_empty() {
            return Err("login response missing token".to_string());
        }
        self.token = Some(token.clone());
        Ok(token)
    }

    pub fn list_commands(
        &mut self,
        page: u32,
        size: u32,
        task_id: Option<i64>,
    ) -> Result<(Vec<Value>, u64), String> {
        if self.token.is_none() {
            self.login()?;
        }
        let mut query = format!("?page={}&size={}", page, size);
        if let Some(task) = task_id {
            query.push_str(&format!("&task={}", task));
        }
        let url = format!("{}/api/commands{}", self.base_url, query);
        let mut headers = Headers::new();
        headers.insert(
            "Authorization".to_string(),
            format!("Bearer {}", self.token.clone().unwrap_or_default()),
        );
        let (mut status, mut text) = self.transport.call("GET", &url, None, &headers);
        if status == 401 {
            self.login()?;
            let mut headers = Headers::new();
            headers.insert(
                "Authorization".to_string(),
                format!("Bearer {}", self.token.clone().unwrap_or_default()),
            );
            let (retry_status, retry_text) = self.transport.call("GET", &url, None, &headers);
            status = retry_status;
            text = retry_text;
        }
        if status != 200 {
            return Err(format!(
                "commands failed ({}): {}",
                status,
                truncate(&text, 200)
            ));
        }
        let data: Value = serde_json::from_str(&text)
            .map_err(|err| format!("commands response not JSON: {}", err))?;
        let records = data["commands"].as_array().cloned().unwrap_or_default();
        let total = data["total"].as_u64().unwrap_or(0);
        Ok((records, total))
    }
}

pub struct ArtexCommandPoller<T: ArtexTransport> {
    client: ArtexClient<T>,
    state_path: PathBuf,
    task_id: Option<i64>,
    page_size: u32,
    last_id: i64,
}

impl<T: ArtexTransport> ArtexCommandPoller<T> {
    pub fn new(client: ArtexClient<T>, state_path: PathBuf, task_id: Option<i64>) -> Self {
        let last_id = read_last_id(&state_path);
        ArtexCommandPoller {
            client,
            state_path,
            task_id,
            page_size: 200,
            last_id,
        }
    }

    pub fn reset(&mut self) {
        self.last_id = 0;
        self.save_last_id();
    }

    pub fn poll(&mut self, save: bool) -> Result<Vec<Value>, String> {
        let mut collected: Vec<Value> = Vec::new();
        let mut page = 0u32;
        while page < 10 {
            let (records, total) = self.client.list_commands(page, self.page_size, self.task_id)?;
            if records.is_empty() {
                break;
            }
            let new: Vec<Value> = records
                .iter()
                .filter(|record| id(record) > self.last_id)
                .cloned()
                .collect();
            let new_len = new.len();
            collected.extend(new);
            if new_len < records.len() {
                break;
            }
            if (records.len() as u64) < self.page_size as u64
                || ((page as u64 + 1) * self.page_size as u64) >= total
            {
                break;
            }
            page += 1;
        }
        collected.sort_by_key(id);
        if collected.len() > 0 {
            self.last_id = id(collected.last().unwrap());
            if save {
                self.save_last_id();
            }
        }
        Ok(collected)
    }

    fn save_last_id(&self) {
        if let Some(parent) = self.state_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(
            &self.state_path,
            serde_json::json!({"last_command_id": self.last_id}).to_string(),
        );
    }
}

fn read_last_id(path: &Path) -> i64 {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .and_then(|value| value["last_command_id"].as_i64())
        .unwrap_or(0)
}

fn id(value: &Value) -> i64 {
    value["id"].as_i64().unwrap_or(0)
}

fn truncate(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

/// Test/replay transport: pops canned responses and logs calls and auth headers.
pub struct FakeTransport {
    pub responses: VecDeque<(u16, String)>,
    pub calls: Vec<String>,
    pub auth: Vec<String>,
}

impl FakeTransport {
    pub fn new(responses: Vec<(u16, String)>) -> Self {
        FakeTransport {
            responses: responses.into_iter().collect(),
            calls: Vec::new(),
            auth: Vec::new(),
        }
    }
}

impl ArtexTransport for FakeTransport {
    fn call(
        &mut self,
        method: &str,
        url: &str,
        _body: Option<&str>,
        headers: &Headers,
    ) -> (u16, String) {
        self.calls.push(format!("{} {}", method, url));
        self.auth
            .push(headers.get("Authorization").cloned().unwrap_or_default());
        self.responses.pop_front().unwrap_or((500, "{}".to_string()))
    }
}
