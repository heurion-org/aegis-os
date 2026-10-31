use aos_memory::MemoryScopes;
use chrono::{Duration, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub agent_id: String,
    pub agent_name: Option<String>,
    pub task_id: Option<String>,
    pub status: String,
    pub created_at: String,
    pub expires_at: String,
    pub requested_scopes: MemoryScopes,
    pub granted_scopes: Option<MemoryScopes>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentRequest {
    pub request_id: String,
    pub session_id: String,
    pub agent_id: String,
    pub agent_name: Option<String>,
    pub task_id: Option<String>,
    pub requested_scopes: MemoryScopes,
    pub status: String,
    pub created_at: String,
    pub expires_at: String,
    pub approved_at: Option<String>,
    pub granted_scopes: Option<MemoryScopes>,
}

pub struct AuthStore {
    conn: Connection,
}

impl AuthStore {
    pub fn open(path: impl AsRef<std::path::Path>) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> anyhow::Result<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                agent_name TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                requested_scopes TEXT NOT NULL,
                granted_scopes TEXT,
                token_hash TEXT,
                task_id TEXT
            );
            CREATE TABLE IF NOT EXISTS consent_requests (
                request_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                agent_name TEXT,
                requested_scopes TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                approved_at TEXT,
                granted_scopes TEXT,
                token TEXT,
                token_delivered INTEGER NOT NULL DEFAULT 0,
                task_id TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_consent_status ON consent_requests(status);
            CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                session_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                action TEXT NOT NULL,
                resource TEXT NOT NULL,
                decision TEXT NOT NULL,
                reason TEXT NOT NULL,
                task_id TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
            "#,
        )?;
        self.ensure_column("sessions", "task_id", "TEXT")?;
        self.ensure_column("consent_requests", "task_id", "TEXT")?;
        self.ensure_column("audit_logs", "task_id", "TEXT")?;
        Ok(())
    }

    fn ensure_column(&self, table: &str, column: &str, decl: &str) -> anyhow::Result<()> {
        let mut stmt = self.conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let exists = stmt
            .query_map([], |row| row.get::<_, String>(1))?
            .filter_map(Result::ok)
            .any(|name| name == column);
        if !exists {
            self.conn.execute(
                &format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"),
                [],
            )?;
        }
        Ok(())
    }

    pub fn expire_pending_consents(&self) -> anyhow::Result<()> {
        let now = Utc::now();
        let mut stmt = self
            .conn
            .prepare("SELECT request_id, expires_at FROM consent_requests WHERE status = 'pending'")?;
        let rows: Vec<(String, String)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .filter_map(Result::ok)
            .collect();
        for (request_id, expires_at) in rows {
            if chrono::DateTime::parse_from_rfc3339(&expires_at)
                .map(|value| value.with_timezone(&Utc) <= now)
                .unwrap_or(false)
            {
                self.conn.execute(
                    "UPDATE consent_requests SET status = 'expired' WHERE request_id = ? AND status = 'pending'",
                    params![request_id],
                )?;
            }
        }
        Ok(())
    }

    pub fn create_session(
        &self,
        agent_id: &str,
        agent_name: Option<&str>,
        requested_scopes: &MemoryScopes,
        duration_minutes: i64,
        task_id: Option<&str>,
    ) -> anyhow::Result<Session> {
        let now = Utc::now();
        let session = Session {
            session_id: format!("sess-{}", Uuid::new_v4()),
            agent_id: agent_id.to_string(),
            agent_name: agent_name.map(str::to_string),
            task_id: task_id.map(str::to_string),
            status: "created".to_string(),
            created_at: now.to_rfc3339(),
            expires_at: (now + Duration::minutes(duration_minutes)).to_rfc3339(),
            requested_scopes: requested_scopes.clone(),
            granted_scopes: None,
        };
        self.conn.execute(
            "INSERT INTO sessions
             (session_id, agent_id, agent_name, status, created_at, expires_at, requested_scopes, task_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                session.session_id,
                session.agent_id,
                session.agent_name,
                session.status,
                session.created_at,
                session.expires_at,
                serde_json::to_string(&session.requested_scopes)?,
                session.task_id,
            ],
        )?;
        Ok(session)
    }

    pub fn grant_session(
        &self,
        session_id: &str,
        granted_scopes: &MemoryScopes,
        token_hash: &str,
    ) -> anyhow::Result<bool> {
        let updated = self.conn.execute(
            "UPDATE sessions SET status = 'active', granted_scopes = ?, token_hash = ?
             WHERE session_id = ? AND status = 'created'",
            params![
                serde_json::to_string(granted_scopes)?,
                token_hash,
                session_id
            ],
        )?;
        Ok(updated > 0)
    }

    pub fn revoke_session(&self, session_id: &str) -> anyhow::Result<bool> {
        let updated = self.conn.execute(
            "UPDATE sessions SET status = 'revoked' WHERE session_id = ? AND status != 'revoked'",
            params![session_id],
        )?;
        Ok(updated > 0)
    }

    pub fn revoke_sessions_for_task(&self, task_id: &str) -> anyhow::Result<Vec<Session>> {
        let sessions: Vec<Session> = self
            .list_sessions(false)?
            .into_iter()
            .filter(|session| session.task_id.as_deref() == Some(task_id))
            .filter(|session| session.status != "revoked")
            .collect();
        for session in &sessions {
            self.conn.execute(
                "UPDATE sessions SET status = 'revoked' WHERE session_id = ?",
                params![session.session_id],
            )?;
        }
        Ok(sessions)
    }

    pub fn get_session(&self, session_id: &str) -> anyhow::Result<Option<Session>> {
        let row = self
            .conn
            .query_row(
                "SELECT session_id, agent_id, agent_name, status, created_at, expires_at,
                        requested_scopes, granted_scopes, task_id
                 FROM sessions WHERE session_id = ?",
                params![session_id],
                row_to_session,
            )
            .optional()?;
        Ok(row)
    }

    pub fn list_sessions(&self, active_only: bool) -> anyhow::Result<Vec<Session>> {
        let sql = if active_only {
            "SELECT session_id, agent_id, agent_name, status, created_at, expires_at,
                    requested_scopes, granted_scopes, task_id
             FROM sessions WHERE status = 'active' ORDER BY created_at DESC"
        } else {
            "SELECT session_id, agent_id, agent_name, status, created_at, expires_at,
                    requested_scopes, granted_scopes, task_id
             FROM sessions ORDER BY created_at DESC"
        };
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map([], row_to_session)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn is_active(&self, session_id: &str) -> anyhow::Result<bool> {
        let row = self
            .conn
            .query_row(
                "SELECT status, expires_at FROM sessions WHERE session_id = ?",
                params![session_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        Ok(match row {
            Some((status, expires_at)) => {
                status == "active"
                    && chrono::DateTime::parse_from_rfc3339(&expires_at)
                        .map(|value| value > Utc::now())
                        .unwrap_or(false)
            }
            None => false,
        })
    }

    pub fn create_consent(
        &self,
        session: &Session,
        requested_scopes: &MemoryScopes,
    ) -> anyhow::Result<ConsentRequest> {
        let request = ConsentRequest {
            request_id: format!("consent-{}", Uuid::new_v4()),
            session_id: session.session_id.clone(),
            agent_id: session.agent_id.clone(),
            agent_name: session.agent_name.clone(),
            task_id: session.task_id.clone(),
            requested_scopes: requested_scopes.clone(),
            status: "pending".to_string(),
            created_at: Utc::now().to_rfc3339(),
            expires_at: session.expires_at.clone(),
            approved_at: None,
            granted_scopes: None,
        };
        self.conn.execute(
            "INSERT INTO consent_requests
             (request_id, session_id, agent_id, agent_name, requested_scopes, status,
              created_at, expires_at, task_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                request.request_id,
                request.session_id,
                request.agent_id,
                request.agent_name,
                serde_json::to_string(&request.requested_scopes)?,
                request.status,
                request.created_at,
                request.expires_at,
                request.task_id,
            ],
        )?;
        Ok(request)
    }

    pub fn get_consent(&self, request_id: &str) -> anyhow::Result<Option<ConsentRequest>> {
        self.expire_pending_consents()?;
        let row = self
            .conn
            .query_row(
                "SELECT request_id, session_id, agent_id, agent_name, requested_scopes,
                        status, created_at, expires_at, approved_at, granted_scopes, task_id
                 FROM consent_requests WHERE request_id = ?",
                params![request_id],
                row_to_consent,
            )
            .optional()?;
        Ok(row)
    }

    pub fn list_consent(&self, status: Option<&str>) -> anyhow::Result<Vec<ConsentRequest>> {
        self.expire_pending_consents()?;
        let mut stmt = self.conn.prepare(
            "SELECT request_id, session_id, agent_id, agent_name, requested_scopes,
                    status, created_at, expires_at, approved_at, granted_scopes, task_id
             FROM consent_requests
             WHERE (?1 IS NULL OR status = ?1)
             ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map(params![status], row_to_consent)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn approve_consent(
        &self,
        request_id: &str,
        granted_scopes: &MemoryScopes,
        token: &str,
    ) -> anyhow::Result<bool> {
        let updated = self.conn.execute(
            "UPDATE consent_requests
             SET status = 'approved', approved_at = ?, granted_scopes = ?, token = ?, token_delivered = 0
             WHERE request_id = ? AND status = 'pending'",
            params![
                Utc::now().to_rfc3339(),
                serde_json::to_string(granted_scopes)?,
                token,
                request_id
            ],
        )?;
        Ok(updated > 0)
    }

    pub fn deny_consent(&self, request_id: &str) -> anyhow::Result<bool> {
        let updated = self.conn.execute(
            "UPDATE consent_requests SET status = 'denied' WHERE request_id = ? AND status = 'pending'",
            params![request_id],
        )?;
        Ok(updated > 0)
    }

    pub fn log_audit(
        &self,
        session_id: &str,
        agent_id: &str,
        action: &str,
        resource: &str,
        decision: &str,
        reason: &str,
    ) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO audit_logs
             (id, timestamp, session_id, agent_id, action, resource, decision, reason, task_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, (SELECT task_id FROM sessions WHERE session_id = ?))",
            params![
                format!("evt-{}", Uuid::new_v4()),
                Utc::now().to_rfc3339(),
                session_id,
                agent_id,
                action,
                resource,
                decision,
                reason,
                session_id
            ],
        )?;
        Ok(())
    }

    pub fn list_audit(&self, limit: usize) -> anyhow::Result<Vec<Value>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, session_id, agent_id, action, resource, decision, reason, task_id
             FROM audit_logs ORDER BY timestamp DESC LIMIT ?",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(serde_json::json!({
                "id": row.get::<_, String>(0)?,
                "timestamp": row.get::<_, String>(1)?,
                "session_id": row.get::<_, String>(2)?,
                "agent_id": row.get::<_, String>(3)?,
                "action": row.get::<_, String>(4)?,
                "resource": row.get::<_, String>(5)?,
                "decision": row.get::<_, String>(6)?,
                "reason": row.get::<_, String>(7)?,
                "task_id": row.get::<_, Option<String>>(8)?,
            }))
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn take_consent_token(&self, request_id: &str) -> anyhow::Result<Option<String>> {
        let row = self
            .conn
            .query_row(
                "SELECT status, token, token_delivered FROM consent_requests WHERE request_id = ?",
                params![request_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((status, token, delivered)) = row else {
            return Ok(None);
        };
        if status != "approved" || delivered != 0 {
            return Ok(None);
        }
        let Some(token) = token else {
            return Ok(None);
        };
        self.conn.execute(
            "UPDATE consent_requests SET token_delivered = 1 WHERE request_id = ?",
            params![request_id],
        )?;
        Ok(Some(token))
    }
}

fn row_to_session(row: &rusqlite::Row<'_>) -> rusqlite::Result<Session> {
    let requested: String = row.get(6)?;
    let granted: Option<String> = row.get(7)?;
    Ok(Session {
        session_id: row.get(0)?,
        agent_id: row.get(1)?,
        agent_name: row.get(2)?,
        task_id: row.get(8)?,
        status: row.get(3)?,
        created_at: row.get(4)?,
        expires_at: row.get(5)?,
        requested_scopes: serde_json::from_str(&requested).unwrap_or_default(),
        granted_scopes: granted.and_then(|value| serde_json::from_str(&value).ok()),
    })
}

fn row_to_consent(row: &rusqlite::Row<'_>) -> rusqlite::Result<ConsentRequest> {
    let requested: String = row.get(4)?;
    let granted: Option<String> = row.get(9)?;
    Ok(ConsentRequest {
        request_id: row.get(0)?,
        session_id: row.get(1)?,
        agent_id: row.get(2)?,
        agent_name: row.get(3)?,
        task_id: row.get(10)?,
        requested_scopes: serde_json::from_str(&requested).unwrap_or_default(),
        status: row.get(5)?,
        created_at: row.get(6)?,
        expires_at: row.get(7)?,
        approved_at: row.get(8)?,
        granted_scopes: granted.and_then(|value| serde_json::from_str(&value).ok()),
    })
}
