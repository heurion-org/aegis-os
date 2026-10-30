//! UOMP memory-consent mapping for Aegis OS (`aos-memory`).
//!
//! This crate is the runtime-side bridge between the UOMP protocol and Aegis
//! policy/lease primitives. It intentionally contains no storage or transport:
//! the memory data plane and MCP gateway are wired in later phases.
//!
//! Mapping summary:
//! - UOMP `read`  -> Aegis action `memory.read`
//! - UOMP `write` -> Aegis action `memory.write`
//! - UOMP tag     -> Aegis resource `memory:tag:<tag>`
//! - UOMP key     -> Aegis resource `memory:key:<key>`
//!
//! A UOMP session with multiple tags/keys produces one Aegis `LeaseGrant` per
//! `(action, resource)` pair. Deny lists and field restrictions are enforced by
//! the memory module because Aegis lease patterns only express positive scope.

use std::collections::HashMap;

use aos_core::{AgentIdentity, LeaseGrant, PolicyContext};
use serde::{Deserialize, Serialize};

/// A UOMP read/write action mapped to an Aegis policy action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryAction {
    Read,
    Write,
    Delete,
}

impl MemoryAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "memory.read",
            Self::Write => "memory.write",
            Self::Delete => "memory.delete",
        }
    }

    fn slug(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Delete => "delete",
        }
    }
}

/// UOMP `ScopeAction` for one direction (read or write).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryScope {
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub keys: Vec<String>,
    #[serde(default)]
    pub deny_tags: Vec<String>,
    #[serde(default)]
    pub deny_keys: Vec<String>,
    #[serde(default)]
    pub allowed_fields: Vec<String>,
    #[serde(default)]
    pub fields: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub purposes: HashMap<String, String>,
}

impl MemoryScope {
    pub fn is_empty(&self) -> bool {
        self.tags.is_empty() && self.keys.is_empty()
    }
}

/// UOMP `Scopes`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryScopes {
    #[serde(default)]
    pub read: MemoryScope,
    #[serde(default)]
    pub write: MemoryScope,
}

/// Sensitivity carried by a memory item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    Low,
    Medium,
    High,
}

/// Minimal memory item shape used for deny/field filtering tests.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryItem {
    pub key: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_sensitivity")]
    pub sensitivity: Sensitivity,
    #[serde(default)]
    pub fields: HashMap<String, serde_json::Value>,
}

fn default_sensitivity() -> Sensitivity {
    Sensitivity::Low
}

/// Map a UOMP scope to Aegis resource patterns.
///
/// Tags and keys are both positive grants. Deny lists are deliberately not
/// emitted as leases; they are enforced by [`filter_item`].
pub fn scope_resources(scope: &MemoryScope) -> Vec<String> {
    let mut resources = Vec::with_capacity(scope.tags.len() + scope.keys.len());
    for tag in &scope.tags {
        if !tag.is_empty() {
            resources.push(format!("memory:tag:{tag}"));
        }
    }
    for key in &scope.keys {
        if !key.is_empty() {
            resources.push(format!("memory:key:{key}"));
        }
    }
    resources
}

/// Build the Aegis lease plan for an approved UOMP session.
///
/// One lease is produced for each `(action, resource)` pair. `ttl_secs <= 0`
/// maps to Aegis's one-shot lease sentinel (`expires_at_ms = -1`).
pub fn lease_plan(
    org_id: &str,
    agent_id: &str,
    session_id: &str,
    scopes: &MemoryScopes,
    ttl_secs: i64,
    granted_by: &str,
    now_ms: i64,
) -> Vec<LeaseGrant> {
    let expires_at_ms = if ttl_secs <= 0 {
        -1
    } else {
        now_ms + ttl_secs * 1000
    };

    let mut leases = Vec::new();
    for (action, scope) in [
        (MemoryAction::Read, &scopes.read),
        (MemoryAction::Write, &scopes.write),
    ] {
        for (index, resource) in scope_resources(scope).into_iter().enumerate() {
            leases.push(LeaseGrant {
                lease_id: format!(
                    "lease-{}-{}-{}",
                    sanitize_id(session_id),
                    action.slug(),
                    index
                ),
                org_id: org_id.to_string(),
                agent_id: agent_id.to_string(),
                action_pattern: action.as_str().to_string(),
                resource_pattern: resource,
                expires_at_ms,
                granted_by: granted_by.to_string(),
            });
        }
    }
    leases
}

/// Build the policy context used for the first UOMP access request.
pub fn policy_context(
    identity: &AgentIdentity,
    action: MemoryAction,
    resource: impl Into<String>,
) -> PolicyContext {
    PolicyContext {
        principal: identity.clone(),
        action: action.as_str().to_string(),
        target_org_id: identity.org_id.clone(),
        target_resource: resource.into(),
        metadata: serde_json::json!({
            "protocol": "uomp",
            "protocol_version": "1.0"
        }),
    }
}

/// Aegis lease matching for memory actions (exact or `prefix*`).
pub fn lease_covers(lease: &LeaseGrant, action: MemoryAction, resource: &str) -> bool {
    pattern_matches(&lease.action_pattern, action.as_str())
        && pattern_matches(&lease.resource_pattern, resource)
}

pub fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" || pattern == value {
        return true;
    }
    pattern
        .strip_suffix('*')
        .map(|prefix| value.starts_with(prefix))
        .unwrap_or(false)
}

/// Apply UOMP deny lists and field projection to one memory item.
///
/// Returns `None` when the item is outside the granted scope or explicitly
/// denied. Deny rules always win over positive tag/key grants.
pub fn filter_item(item: &MemoryItem, scope: &MemoryScope) -> Option<MemoryItem> {
    if scope.deny_keys.iter().any(|key| key == &item.key) {
        return None;
    }
    if item
        .tags
        .iter()
        .any(|tag| scope.deny_tags.iter().any(|denied| denied == tag))
    {
        return None;
    }

    let key_granted = scope.keys.iter().any(|key| key == &item.key);
    let tag_granted = item
        .tags
        .iter()
        .any(|tag| scope.tags.iter().any(|granted| granted == tag));
    if !key_granted && !tag_granted {
        return None;
    }

    let allowed = allowed_fields_for(item, scope);
    let mut filtered = item.clone();
    if let Some(allowed) = allowed {
        filtered
            .fields
            .retain(|field, _| allowed.iter().any(|name| name == field));
    }
    Some(filtered)
}

/// High-sensitivity keys under a requested tag that were not explicitly
/// selected. These require per-key approval before a tag grant is valid.
pub fn high_sensitivity_keys(scope: &MemoryScope, items: &[MemoryItem]) -> Vec<String> {
    let mut keys: Vec<String> = items
        .iter()
        .filter(|item| item.sensitivity == Sensitivity::High)
        .filter(|item| filter_item(item, scope).is_some())
        .filter(|item| !scope.keys.iter().any(|key| key == &item.key))
        .map(|item| item.key.clone())
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

fn allowed_fields_for<'a>(item: &MemoryItem, scope: &'a MemoryScope) -> Option<&'a [String]> {
    if let Some(fields) = scope.fields.get(&item.key) {
        if !fields.is_empty() {
            return Some(fields);
        }
    }
    if !scope.allowed_fields.is_empty() {
        return Some(&scope.allowed_fields);
    }
    None
}

fn sanitize_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

/// Configuration for a remote Agent entry point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteProfile {
    /// Stable gateway identifier (for audit).
    pub gateway_id: String,
    /// Expected `audience` claim in the UOMP token.
    pub audience: String,
    /// Allowed request endpoint prefixes. Empty means "any endpoint".
    #[serde(default)]
    pub allowed_endpoints: Vec<String>,
    /// Maximum accepted token lifetime, in seconds. UOMP recommends <= 600.
    #[serde(default = "default_remote_ttl_secs")]
    pub max_token_ttl_secs: i64,
}

fn default_remote_ttl_secs() -> i64 {
    600
}

/// Minimal UOMP remote token claims needed by the gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteTokenClaims {
    pub profile: String,
    pub audience: String,
    pub session_id: String,
    pub agent_id: String,
    pub expires_at_ms: i64,
    pub scopes: MemoryScopes,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RemoteAccessError {
    #[error("token profile must be 'remote'")]
    WrongProfile,
    #[error("token audience does not match this gateway")]
    AudienceMismatch,
    #[error("remote token has expired")]
    Expired,
    #[error("remote session has been revoked")]
    SessionRevoked,
    #[error("request endpoint is not allowed by this gateway")]
    EndpointNotAllowed,
    #[error("remote token lifetime exceeds the gateway limit")]
    TokenTtlTooLong,
    #[error("request is outside the token scope")]
    ScopeDenied,
}

/// Validate a remote request before forwarding it to local Memory Guard.
///
/// This is the pure policy core of Aegis Memory Gateway: transport (mTLS),
/// rate limiting, and proxying are handled by the runtime around it.
pub fn validate_remote_access(
    profile: &RemoteProfile,
    claims: &RemoteTokenClaims,
    session_revoked: bool,
    request_endpoint: &str,
    action: MemoryAction,
    resource: &str,
    now_ms: i64,
) -> Result<(), RemoteAccessError> {
    if claims.profile != "remote" {
        return Err(RemoteAccessError::WrongProfile);
    }
    if claims.audience != profile.audience {
        return Err(RemoteAccessError::AudienceMismatch);
    }
    if claims.expires_at_ms <= now_ms {
        return Err(RemoteAccessError::Expired);
    }
    if session_revoked {
        return Err(RemoteAccessError::SessionRevoked);
    }
    if claims.expires_at_ms - now_ms > profile.max_token_ttl_secs * 1000 {
        return Err(RemoteAccessError::TokenTtlTooLong);
    }
    if !profile.allowed_endpoints.is_empty()
        && !profile
            .allowed_endpoints
            .iter()
            .any(|allowed| request_endpoint.starts_with(allowed))
    {
        return Err(RemoteAccessError::EndpointNotAllowed);
    }
    if !scope_allows(&claims.scopes, action, resource) {
        return Err(RemoteAccessError::ScopeDenied);
    }
    Ok(())
}

/// Whether a UOMP scope grants a specific Aegis memory resource.
pub fn scope_allows(scopes: &MemoryScopes, action: MemoryAction, resource: &str) -> bool {
    let scope = match action {
        MemoryAction::Read => &scopes.read,
        MemoryAction::Write | MemoryAction::Delete => &scopes.write,
    };
    scope_resources(scope)
        .iter()
        .any(|pattern| pattern_matches(pattern, resource))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(tags: &[&str], keys: &[&str]) -> MemoryScope {
        MemoryScope {
            tags: tags.iter().map(|value| value.to_string()).collect(),
            keys: keys.iter().map(|value| value.to_string()).collect(),
            ..Default::default()
        }
    }

    fn item(key: &str, tags: &[&str], sensitivity: Sensitivity) -> MemoryItem {
        MemoryItem {
            key: key.to_string(),
            tags: tags.iter().map(|value| value.to_string()).collect(),
            sensitivity,
            fields: HashMap::from([
                ("title".to_string(), serde_json::json!("Title")),
                ("body".to_string(), serde_json::json!("Body")),
            ]),
        }
    }

    #[test]
    fn maps_tags_and_keys_to_resources() {
        let resources = scope_resources(&scope(&["notes/projects"], &["note.projects.plan"]));
        assert_eq!(
            resources,
            vec!["memory:tag:notes/projects", "memory:key:note.projects.plan"]
        );
    }

    #[test]
    fn builds_one_lease_per_action_and_resource() {
        let scopes = MemoryScopes {
            read: scope(&["notes/projects", "profile"], &["note.projects.plan"]),
            write: scope(&[], &["note.projects.plan"]),
        };
        let leases = lease_plan(
            "local",
            "claude-desktop",
            "sess_abc",
            &scopes,
            1800,
            "user",
            1_000,
        );

        assert_eq!(leases.len(), 4);
        assert_eq!(leases[0].action_pattern, "memory.read");
        assert_eq!(leases[0].resource_pattern, "memory:tag:notes/projects");
        assert_eq!(leases[0].expires_at_ms, 1_801_000);
        assert_eq!(leases[3].action_pattern, "memory.write");
        assert_eq!(leases[3].resource_pattern, "memory:key:note.projects.plan");
    }

    #[test]
    fn zero_ttl_is_one_shot() {
        let leases = lease_plan(
            "local",
            "agent",
            "sess",
            &MemoryScopes {
                read: scope(&["notes"], &[]),
                write: MemoryScope::default(),
            },
            0,
            "user",
            1_000,
        );
        assert_eq!(leases[0].expires_at_ms, -1);
    }

    #[test]
    fn deny_rules_win_over_tag_grants() {
        let mut granted = scope(&["notes/projects"], &[]);
        granted.deny_tags = vec!["notes/journal".to_string()];
        granted.deny_keys = vec!["note.projects.secret".to_string()];

        assert!(filter_item(
            &item("note.projects.plan", &["notes/projects"], Sensitivity::Low),
            &granted
        )
        .is_some());
        assert!(filter_item(
            &item("note.journal.private", &["notes/journal"], Sensitivity::Low),
            &granted
        )
        .is_none());
        assert!(filter_item(
            &item(
                "note.projects.secret",
                &["notes/projects"],
                Sensitivity::High
            ),
            &granted
        )
        .is_none());
    }

    #[test]
    fn field_projection_limits_visible_fields() {
        let mut granted = scope(&["notes/projects"], &[]);
        granted.allowed_fields = vec!["title".to_string()];

        let filtered = filter_item(
            &item("note.projects.plan", &["notes/projects"], Sensitivity::Low),
            &granted,
        )
        .expect("item should be visible");
        assert!(filtered.fields.contains_key("title"));
        assert!(!filtered.fields.contains_key("body"));
    }

    #[test]
    fn high_sensitivity_keys_require_explicit_selection() {
        let granted = scope(&["portfolio:holdings"], &[]);
        let items = vec![
            item("AAPL", &["portfolio:holdings"], Sensitivity::High),
            item("MSFT", &["portfolio:holdings"], Sensitivity::High),
            item("watchlist", &["portfolio:holdings"], Sensitivity::Medium),
        ];

        assert_eq!(
            high_sensitivity_keys(&granted, &items),
            vec!["AAPL".to_string(), "MSFT".to_string()]
        );

        let mut explicit = granted;
        explicit.keys = vec!["AAPL".to_string()];
        assert_eq!(
            high_sensitivity_keys(&explicit, &items),
            vec!["MSFT".to_string()]
        );
    }

    #[test]
    fn deserializes_uomp_scopes_json() {
        let json = r#"{
            "read": {
                "tags": ["notes/projects"],
                "keys": [],
                "deny_tags": ["notes/journal"],
                "deny_keys": []
            },
            "write": {
                "tags": [],
                "keys": []
            }
        }"#;
        let scopes: MemoryScopes = serde_json::from_str(json).expect("uomp scopes should parse");
        assert_eq!(scopes.read.tags, vec!["notes/projects".to_string()]);
        assert_eq!(scopes.read.deny_tags, vec!["notes/journal".to_string()]);
        assert!(scopes.write.tags.is_empty());
    }

    #[test]
    fn remote_profile_validates_token_audience_expiry_and_scope() {
        let profile = RemoteProfile {
            gateway_id: "gw-1".to_string(),
            audience: "https://gateway.example.com".to_string(),
            allowed_endpoints: vec!["/v1/memory".to_string()],
            max_token_ttl_secs: 600,
        };
        let claims = RemoteTokenClaims {
            profile: "remote".to_string(),
            audience: profile.audience.clone(),
            session_id: "sess-1".to_string(),
            agent_id: "remote-agent".to_string(),
            expires_at_ms: 1_300_000,
            scopes: MemoryScopes {
                read: scope(&["notes/projects"], &[]),
                write: MemoryScope::default(),
            },
        };

        assert_eq!(
            validate_remote_access(
                &profile,
                &claims,
                false,
                "/v1/memory?tag=notes/projects",
                MemoryAction::Read,
                "memory:tag:notes/projects",
                1_000_000,
            ),
            Ok(())
        );
        assert_eq!(
            validate_remote_access(
                &profile,
                &claims,
                false,
                "/v1/memory?tag=notes/journal",
                MemoryAction::Read,
                "memory:tag:notes/journal",
                1_000_000,
            ),
            Err(RemoteAccessError::ScopeDenied)
        );
        assert_eq!(
            validate_remote_access(
                &profile,
                &claims,
                true,
                "/v1/memory?tag=notes/projects",
                MemoryAction::Read,
                "memory:tag:notes/projects",
                1_000_000,
            ),
            Err(RemoteAccessError::SessionRevoked)
        );
        assert_eq!(
            validate_remote_access(
                &profile,
                &claims,
                false,
                "/admin",
                MemoryAction::Read,
                "memory:tag:notes/projects",
                1_000_000,
            ),
            Err(RemoteAccessError::EndpointNotAllowed)
        );
    }

    #[test]
    fn remote_profile_rejects_wrong_audience_and_long_ttl() {
        let profile = RemoteProfile {
            gateway_id: "gw-1".to_string(),
            audience: "https://gateway.example.com".to_string(),
            allowed_endpoints: vec![],
            max_token_ttl_secs: 600,
        };
        let mut claims = RemoteTokenClaims {
            profile: "remote".to_string(),
            audience: "https://other.example.com".to_string(),
            session_id: "sess-1".to_string(),
            agent_id: "remote-agent".to_string(),
            expires_at_ms: 1_100_000,
            scopes: MemoryScopes {
                read: scope(&["notes"], &[]),
                write: MemoryScope::default(),
            },
        };

        assert_eq!(
            validate_remote_access(
                &profile,
                &claims,
                false,
                "/v1/memory",
                MemoryAction::Read,
                "memory:tag:notes",
                1_000_000,
            ),
            Err(RemoteAccessError::AudienceMismatch)
        );

        claims.audience = profile.audience.clone();
        claims.expires_at_ms = 1_700_000;
        assert_eq!(
            validate_remote_access(
                &profile,
                &claims,
                false,
                "/v1/memory",
                MemoryAction::Read,
                "memory:tag:notes",
                1_000_000,
            ),
            Err(RemoteAccessError::TokenTtlTooLong)
        );
    }

    #[test]
    fn lease_matching_supports_exact_prefix_and_wildcard() {
        let lease = LeaseGrant {
            lease_id: "lease-1".to_string(),
            org_id: "local".to_string(),
            agent_id: "agent".to_string(),
            action_pattern: "memory.read".to_string(),
            resource_pattern: "memory:tag:notes/*".to_string(),
            expires_at_ms: 2_000,
            granted_by: "user".to_string(),
        };

        assert!(lease_covers(
            &lease,
            MemoryAction::Read,
            "memory:tag:notes/projects"
        ));
        assert!(!lease_covers(
            &lease,
            MemoryAction::Read,
            "memory:tag:journal"
        ));
        assert!(!lease_covers(
            &lease,
            MemoryAction::Write,
            "memory:tag:notes/projects"
        ));
    }
}
