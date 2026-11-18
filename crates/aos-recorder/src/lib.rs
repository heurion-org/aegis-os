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

    fn last_hash_from_disk(path: &Path) -> Option<String> {
        use std::io::{Read, Seek, SeekFrom};
        let mut file = std::fs::File::open(path).ok()?;
        let len = file.metadata().ok()?.len();
        let start = len.saturating_sub(65_536);
        file.seek(SeekFrom::Start(start)).ok()?;
        let mut tail = Vec::new();
        file.read_to_end(&mut tail).ok()?;
        for slice in tail.split(|&b| b == b'\n').rev() {
            let Ok(s) = std::str::from_utf8(slice) else {
                continue;
            };
            let trimmed = s.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(ev) = serde_json::from_str::<AuditEvent>(trimmed) {
                if let Some(h) = ev.event_hash {
                    return Some(h);
                }
            }
        }
        // If log exceeded 64 KiB and had a very large single trailing event, fall back to full strict scan.
        if start > 0 {
            if let Ok(all) = Self::read_events_strict(path) {
                return all.into_iter().rev().find_map(|e| e.event_hash);
            }
        }
        None
    }

    fn read_events_strict(path: &Path) -> Result<Vec<AuditEvent>, (usize, String)> {
        let raw = std::fs::read(path).map_err(|e| (0usize, format!("failed to read audit log: {e}")))?;
        let mut out = Vec::new();
        for (line_idx, slice) in raw.split(|&b| b == b'\n').enumerate() {
            let trimmed_bytes = match std::str::from_utf8(slice) {
                Ok(s) => s.trim(),
                Err(e) => {
                    return Err((
                        line_idx,
                        format!("invalid UTF-8 bytes on line {}: {}", line_idx + 1, e),
                    ));
                }
            };
            if trimmed_bytes.is_empty() {
                continue;
            }
            let ev = serde_json::from_str::<AuditEvent>(trimmed_bytes).map_err(|e| {
                (
                    line_idx,
                    format!("malformed audit JSON on line {}: {}", line_idx + 1, e),
                )
            })?;
            out.push(ev);
        }
        Ok(out)
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
        let _guard = self.state_mutex.lock().await;
        let _file_lock = if let Some(ref path) = self.jsonl_log_path {
            if let Some(parent) = path.parent() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }
            aos_core::session::acquire_file_lock(path).await.ok()
        } else {
            None
        };

        let all_events: Vec<AuditEvent> = if let Some(ref path) = self.jsonl_log_path {
            if path.exists() {
                match Self::read_events_strict(path) {
                    Ok(ev) => ev,
                    Err((bad_idx, reason)) => {
                        return Ok(serde_json::json!({
                            "verified": false,
                            "total_events": bad_idx,
                            "chained_events": 0,
                            "org_events": 0,
                            "head_hash": AuditEvent::GENESIS_HASH,
                            "tampered_event_id": serde_json::Value::Null,
                            "tampered_index": bad_idx,
                            "error": reason,
                        }));
                    }
                }
            } else {
                self.events.read().await.iter().cloned().collect()
            }
        } else {
            self.events.read().await.iter().cloned().collect()
        };

        let mut expected_prev = AuditEvent::GENESIS_HASH.to_string();
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
                verified = false;
                tampered_event_id = Some(ev.event_id.clone());
                tampered_index = Some(idx);
                break;
            };
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
        let _guard = self.state_mutex.lock().await;
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
            let prev_hash = Self::last_hash_from_disk(path)
                .unwrap_or_else(|| AuditEvent::GENESIS_HASH.to_string());
            let event_hash = event.compute_hash(&prev_hash);
            event.prev_hash = Some(prev_hash);
            event.event_hash = Some(event_hash);

            let needs_leading_newline = std::fs::read(path)
                .ok()
                .is_some_and(|b| !b.is_empty() && !b.ends_with(b"\n"));
            let mut file = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await?;
            let json_line = serde_json::to_string(&event)?;
            let line = if needs_leading_newline {
                format!("\n{json_line}\n")
            } else {
                format!("{json_line}\n")
            };
            file.write_all(line.as_bytes()).await?;
            file.flush().await?;
            file.sync_data().await?;
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

    #[tokio::test]
    async fn prefix_truncation_and_corrupt_json_fail_verification() {
        let dir = std::env::temp_dir().join(format!("aos-rec-sec-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("audit.jsonl");
        let rec = AegisFlightRecorder::new(Some(log_path.clone()));

        for idx in 1..=2 {
            rec.record(AuditEvent {
                event_id: format!("ev-{idx}"),
                timestamp_ms: idx * 1000,
                org_id: "acme".to_string(),
                agent_id: "agy-lead".to_string(),
                action: "fs_write".to_string(),
                resource: "main.rs".to_string(),
                policy_decision: "allow".to_string(),
                snapshot_id: None,
                details: json!({}),
                task_id: None,
                prev_hash: None,
                event_hash: None,
            })
            .await
            .unwrap();
        }
        assert_eq!(rec.verify_chain(None).await.unwrap()["verified"], true);

        // 1. Truncating the first event breaks anchoring to GENESIS_HASH and must fail.
        let full = std::fs::read_to_string(&log_path).unwrap();
        let second_only = full.lines().nth(1).unwrap().to_string() + "\n";
        std::fs::write(&log_path, &second_only).unwrap();
        assert_eq!(rec.verify_chain(None).await.unwrap()["verified"], false);

        // 2. Appending malformed JSON / non-UTF8 bytes must fail strict verification.
        std::fs::write(&log_path, format!("{full}{{corrupt-line\n")).unwrap();
        assert_eq!(rec.verify_chain(None).await.unwrap()["verified"], false);
    }
}
