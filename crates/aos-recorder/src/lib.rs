//! Aegis OS Flight Recorder (`aos-recorder`)
//!
//! Records an immutable audit trail of all syscalls, policy evaluations,
//! snapshot IDs, IPC messages, and egress decisions per Organization and Agent.

use aos_core::{AuditEvent, FlightRecorder};
use async_trait::async_trait;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;

const MAX_IN_MEMORY_EVENTS: usize = 4096;

pub struct AegisFlightRecorder {
    events: Arc<RwLock<VecDeque<AuditEvent>>>,
    jsonl_log_path: Option<PathBuf>,
}

impl Default for AegisFlightRecorder {
    fn default() -> Self {
        Self::new(None)
    }
}

impl AegisFlightRecorder {
    pub fn new(jsonl_log_path: Option<PathBuf>) -> Self {
        let initial = jsonl_log_path
            .as_deref()
            .map(Self::load_events_from_disk)
            .unwrap_or_default();
        Self {
            events: Arc::new(RwLock::new(initial)),
            jsonl_log_path,
        }
    }

    fn load_events_from_disk(path: &Path) -> VecDeque<AuditEvent> {
        let Ok(raw) = std::fs::read_to_string(path) else {
            return VecDeque::new();
        };
        let mut ring = VecDeque::new();
        for line in raw.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(ev) = serde_json::from_str::<AuditEvent>(trimmed) {
                if ring.len() >= MAX_IN_MEMORY_EVENTS {
                    ring.pop_front();
                }
                ring.push_back(ev);
            }
        }
        ring
    }
}

#[async_trait]
impl FlightRecorder for AegisFlightRecorder {
    async fn record(&self, event: AuditEvent) -> anyhow::Result<()> {
        if let Some(ref path) = self.jsonl_log_path {
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            let mut file = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await?;
            let line = format!("{}\n", serde_json::to_string(&event)?);
            file.write_all(line.as_bytes()).await?;
        }
        let mut guard = self.events.write().await;
        if guard.len() >= MAX_IN_MEMORY_EVENTS {
            guard.pop_front();
        }
        guard.push_back(event);
        Ok(())
    }

    async fn query_events(
        &self,
        org_id: &str,
        agent_id: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<AuditEvent>> {
        if let Some(ref path) = self.jsonl_log_path {
            if path.exists() {
                let disk_events = Self::load_events_from_disk(path);
                if !disk_events.is_empty() {
                    let filtered: Vec<AuditEvent> = disk_events
                        .iter()
                        .rev()
                        .filter(|e| e.org_id == org_id && agent_id.is_none_or(|a| e.agent_id == a))
                        .take(limit)
                        .cloned()
                        .collect();
                    return Ok(filtered);
                }
            }
        }
        let events = self.events.read().await;
        let filtered: Vec<AuditEvent> = events
            .iter()
            .rev()
            .filter(|e| {
                e.org_id == org_id && agent_id.is_none_or(|a| e.agent_id == a)
            })
            .take(limit)
            .cloned()
            .collect();
        Ok(filtered)
    }
}
