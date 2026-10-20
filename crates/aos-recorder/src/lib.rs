//! Aegis OS Flight Recorder (`aos-recorder`)
//!
//! Records an immutable audit trail of all syscalls, policy evaluations,
//! snapshot IDs, IPC messages, and egress decisions per Organization and Agent.

use aos_core::{AuditEvent, FlightRecorder};
use async_trait::async_trait;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;

pub struct AegisFlightRecorder {
    events: Arc<RwLock<Vec<AuditEvent>>>,
    jsonl_log_path: Option<PathBuf>,
}

impl Default for AegisFlightRecorder {
    fn default() -> Self {
        Self::new(None)
    }
}

impl AegisFlightRecorder {
    pub fn new(jsonl_log_path: Option<PathBuf>) -> Self {
        Self {
            events: Arc::new(RwLock::new(Vec::new())),
            jsonl_log_path,
        }
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
        self.events.write().await.push(event);
        Ok(())
    }

    async fn query_events(
        &self,
        org_id: &str,
        agent_id: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<AuditEvent>> {
        let events = self.events.read().await;
        let filtered: Vec<AuditEvent> = events
            .iter()
            .rev()
            .filter(|e| {
                e.org_id == org_id && agent_id.map_or(true, |a| e.agent_id == a)
            })
            .take(limit)
            .cloned()
            .collect();
        Ok(filtered)
    }
}
