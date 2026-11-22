use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::PathBuf;

pub struct DedupeStore {
    path: Option<PathBuf>,
    entries: HashMap<String, HashSet<String>>,
    max_keys: usize,
}

impl DedupeStore {
    fn new(path: Option<PathBuf>, max_keys: usize) -> Self {
        let mut entries: HashMap<String, HashSet<String>> = HashMap::new();
        if let Some(ledger) = &path {
            if let Ok(text) = fs::read_to_string(ledger) {
                for line in text.lines() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
                        if let (Some(key), Some(source)) = (
                            value.get("key").and_then(|v| v.as_str()),
                            value.get("source").and_then(|v| v.as_str()),
                        ) {
                            entries
                                .entry(key.to_string())
                                .or_default()
                                .insert(source.to_string());
                        }
                    }
                }
            }
        }
        DedupeStore {
            path,
            entries,
            max_keys,
        }
    }

    pub fn in_memory() -> Self {
        DedupeStore::new(None, 20_000)
    }

    pub fn load(path: PathBuf) -> Self {
        DedupeStore::new(Some(path), 20_000)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn key(tool: &str, command: &str, event_time: Option<&str>) -> String {
        let bucket = event_time
            .map(crate::timeutil::minute_bucket)
            .unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(format!("{}|{}|{}", tool, command, bucket));
        let digest = format!("{:x}", hasher.finalize());
        digest[..32].to_string()
    }

    pub fn is_cross_duplicate(&self, source: &str, key: &str) -> bool {
        self.entries
            .get(key)
            .map(|sources| !sources.is_empty() && !sources.contains(source))
            .unwrap_or(false)
    }

    pub fn mark(&mut self, source: &str, key: &str) {
        let sources = self.entries.entry(key.to_string()).or_default();
        if !sources.insert(source.to_string()) {
            return;
        }
        if let Some(path) = &self.path {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) {
                let _ = writeln!(
                    file,
                    "{}",
                    serde_json::json!({ "key": key, "source": source })
                );
            }
        }
        if self.entries.len() > self.max_keys {
            self.trim();
        }
    }

    fn trim(&mut self) {
        while self.entries.len() > self.max_keys {
            if let Some(key) = self.entries.keys().next().cloned() {
                self.entries.remove(&key);
            } else {
                break;
            }
        }
        if let Some(path) = &self.path {
            let mut text = String::new();
            for (key, sources) in &self.entries {
                for source in sources {
                    text.push_str(&serde_json::json!({ "key": key, "source": source }).to_string());
                    text.push('\n');
                }
            }
            let _ = fs::write(path, text);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_to_max_keys_and_rewrites_ledger() {
        let path = PathBuf::from("target/test-dedupe-trim.jsonl");
        let _ = fs::remove_file(&path);
        let mut store = DedupeStore::new(Some(path.clone()), 2);
        for index in 0..5 {
            store.mark("broker", &format!("key-{}", index));
        }
        assert_eq!(store.len(), 2);
        let reloaded = DedupeStore::load(path.clone());
        assert_eq!(reloaded.len(), 2);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn cross_source_rules() {
        let mut store = DedupeStore::in_memory();
        let key = DedupeStore::key("curl", "curl http://host.docker.internal:3000/x", None);
        store.mark("broker", &key);
        assert!(store.is_cross_duplicate("artex-api", &key));
        assert!(!store.is_cross_duplicate("broker", &key));
    }
}
