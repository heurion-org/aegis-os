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
    state_mutex: Arc<tokio::sync::Mutex<()>>,
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
            state_mutex: Arc::new(tokio::sync::Mutex::new(())),
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

    fn load_all_events_from_disk(path: &Path) -> Vec<AuditEvent> {
        let Ok(raw) = std::fs::read_to_string(path) else {
            return Vec::new();
        };
        raw.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .filter_map(|l| serde_json::from_str::<AuditEvent>(l).ok())
            .collect()
    }

    fn extract_task_id(event: &AuditEvent) -> Option<String> {
        if let Some(ref tid) = event.task_id {
            if !tid.is_empty() {
                return Some(tid.clone());
            }
        }
        for key in ["task_id", "correlation_id"] {
            if let Some(tid) = event.details.get(key).and_then(|v| v.as_str()) {
                if !tid.is_empty() {
                    return Some(tid.to_string());
                }
            }
        }
        if let Some(rest) = event.resource.strip_prefix("task:") {
            if !rest.is_empty() {
                return Some(rest.to_string());
            }
        }
        None
    }

    /// Verifies the tamper-evident SHA-256 hash chain across all recorded audit events.
    pub async fn verify_chain(&self, org_id: Option<&str>) -> anyhow::Result<serde_json::Value> {
        let all_events: Vec<AuditEvent> = if let Some(ref path) = self.jsonl_log_path {
            if path.exists() {
                Self::load_all_events_from_disk(path)
            } else {
                self.events.read().await.iter().cloned().collect()
            }
        } else {
            self.events.read().await.iter().cloned().collect()
        };

        let mut expected_prev = AuditEvent::GENESIS_HASH.to_string();
        let mut chain_started = false;
        let mut verified = true;
        let mut tampered_event_id: Option<String> = None;
        let mut tampered_index: Option<usize> = None;
        let mut chained_events = 0usize;
        let mut org_events = 0usize;

        for (idx, ev) in all_events.iter().enumerate() {
            if org_id.is_none_or(|o| ev.org_id == o) {
                org_events += 1;
            }
            let (Some(ref prev), Some(ref hash)) = (&ev.prev_hash, &ev.event_hash) else {
                // Legacy pre-hash-chain event; reset baseline if chain hasn't started.
                if !chain_started {
                    continue;
                } else {
                    verified = false;
                    tampered_event_id = Some(ev.event_id.clone());
                    tampered_index = Some(idx);
                    break;
                }
            };
            if !chain_started {
                chain_started = true;
                expected_prev = prev.clone();
            }
            chained_events += 1;
            let computed = ev.compute_hash(&expected_prev);
            if prev != &expected_prev || hash != &computed {
                verified = false;
                tampered_event_id = Some(ev.event_id.clone());
                tampered_index = Some(idx);
                break;
            }
            expected_prev = hash.clone();
        }

        Ok(serde_json::json!({
            "verified": verified,
            "total_events": all_events.len(),
            "chained_events": chained_events,
            "org_events": org_events,
            "head_hash": expected_prev,
            "tampered_event_id": tampered_event_id,
            "tampered_index": tampered_index,
        }))
    }

    /// Returns all audit events in chronological order correlated with `task_id` inside `org_id`.
    pub async fn trace_task(&self, org_id: &str, task_id: &str) -> anyhow::Result<Vec<AuditEvent>> {
        let all_events: Vec<AuditEvent> = if let Some(ref path) = self.jsonl_log_path {
            if path.exists() {
                Self::load_all_events_from_disk(path)
            } else {
                self.events.read().await.iter().cloned().collect()
            }
        } else {
            self.events.read().await.iter().cloned().collect()
        };

        Ok(all_events
            .into_iter()
            .filter(|ev| {
                ev.org_id == org_id
                    && (ev.task_id.as_deref() == Some(task_id)
                        || ev.details.get("task_id").and_then(|v| v.as_str()) == Some(task_id)
                        || ev.details.get("msg_id").and_then(|v| v.as_str()) == Some(task_id)
                        || ev.details.get("correlation_id").and_then(|v| v.as_str()) == Some(task_id)
                        || ev.resource == format!("task:{task_id}"))
            })
            .collect())
    }
}

#[async_trait]
impl FlightRecorder for AegisFlightRecorder {
    async fn record(&self, mut event: AuditEvent) -> anyhow::Result<()> {
        let _guard = self.state_mutex.lock().await;
        if event.task_id.is_none() {
            event.task_id = Self::extract_task_id(&event);
        }

        if let Some(ref path) = self.jsonl_log_path {
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            let _file_lock = aos_core::session::acquire_file_lock(path).await?;
            let disk_events = Self::load_events_from_disk(path);
            let prev_hash = disk_events
                .iter()
                .rev()
                .find_map(|e| e.event_hash.clone())
                .unwrap_or_else(|| AuditEvent::GENESIS_HASH.to_string());
            let event_hash = event.compute_hash(&prev_hash);
            event.prev_hash = Some(prev_hash);
            event.event_hash = Some(event_hash);

            let mut file = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await?;
            let line = format!("{}\n", serde_json::to_string(&event)?);
            file.write_all(line.as_bytes()).await?;
        } else {
            let prev_hash = self
                .events
                .read()
                .await
                .iter()
                .rev()
                .find_map(|e| e.event_hash.clone())
                .unwrap_or_else(|| AuditEvent::GENESIS_HASH.to_string());
            let event_hash = event.compute_hash(&prev_hash);
            event.prev_hash = Some(prev_hash);
            event.event_hash = Some(event_hash);
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

    async fn verify_chain(&self, org_id: Option<&str>) -> anyhow::Result<serde_json::Value> {
        AegisFlightRecorder::verify_chain(self, org_id).await
    }

    async fn trace_task(&self, org_id: &str, task_id: &str) -> anyhow::Result<Vec<AuditEvent>> {
        AegisFlightRecorder::trace_task(self, org_id, task_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn hash_chain_verifies_and_detects_tampering() {
        let dir = std::env::temp_dir().join(format!("aos-recorder-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("audit.jsonl");
        let rec = AegisFlightRecorder::new(Some(log_path.clone()));

        rec.record(AuditEvent {
            event_id: "ev-1".to_string(),
            timestamp_ms: 1000,
            org_id: "acme".to_string(),
            agent_id: "agy-lead".to_string(),
            action: "ipc_request".to_string(),
            resource: "task:t-100".to_string(),
            policy_decision: "allow".to_string(),
            snapshot_id: None,
            details: json!({"task_id": "t-100"}),
            task_id: None,
            prev_hash: None,
            event_hash: None,
        })
        .await
        .unwrap();

        rec.record(AuditEvent {
            event_id: "ev-2".to_string(),
            timestamp_ms: 2000,
            org_id: "acme".to_string(),
            agent_id: "claude-worker".to_string(),
            action: "coord_claim".to_string(),
            resource: "src/lib.rs".to_string(),
            policy_decision: "allow".to_string(),
            snapshot_id: None,
            details: json!({"task_id": "t-100", "paths": ["src/lib.rs"]}),
            task_id: None,
            prev_hash: None,
            event_hash: None,
        })
        .await
        .unwrap();

        let report = rec.verify_chain(Some("acme")).await.unwrap();
        assert_eq!(report["verified"], true);
        assert_eq!(report["chained_events"], 2);

        let trace = rec.trace_task("acme", "t-100").await.unwrap();
        assert_eq!(trace.len(), 2);
        assert_eq!(trace[0].event_id, "ev-1");
        assert_eq!(trace[1].event_id, "ev-2");
        assert_eq!(trace[1].prev_hash, trace[0].event_hash);

        // Tamper with the first line on disk
        let raw = std::fs::read_to_string(&log_path).unwrap();
        let tampered = raw.replacen("\"policy_decision\":\"allow\"", "\"policy_decision\":\"tampered\"", 1);
        std::fs::write(&log_path, tampered).unwrap();

        let bad_report = rec.verify_chain(Some("acme")).await.unwrap();
        assert_eq!(bad_report["verified"], false);
        assert_eq!(bad_report["tampered_event_id"], "ev-1");
    }
}
