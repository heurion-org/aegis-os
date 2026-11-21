//! Aegis OS Policy Kernel & Session Lease Manager (`aos-policy`)
//!
//! Implements the Cedar-aligned declarative permission model with dynamic Session Leases,
//! Google A2A cross-org IPC policies, and persistent Escalation Queues (`leases.json` & `escalations.json`).

use aos_core::{
    EscalationStatus, LeaseGrant, LeaseKind, PendingEscalation, PolicyContext, PolicyDecision,
    PolicyEngine,
};
use anyhow::Context;
use async_trait::async_trait;
use chrono::Utc;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Embedded baseline Cedar policy (`policy/default.cedar`).
pub const DEFAULT_CEDAR_POLICY: &str = include_str!("../../../policy/default.cedar");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CedarEffect {
    Permit,
    Forbid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CedarOperand {
    PrincipalOrgId,
    PrincipalAgentId,
    PrincipalRole,
    ResourceOrgId,
    ResourceOwnerAgentId,
    ResourceId,
    ResourcePath,
    Literal(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CedarExpr {
    And(Box<CedarExpr>, Box<CedarExpr>),
    Or(Box<CedarExpr>, Box<CedarExpr>),
    Not(Box<CedarExpr>),
    Eq(CedarOperand, CedarOperand),
    Ne(CedarOperand, CedarOperand),
    Like(CedarOperand, String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CedarCondition {
    When(CedarExpr),
    Unless(CedarExpr),
}

#[derive(Debug, Clone)]
pub struct CedarRule {
    pub id: String,
    pub effect: CedarEffect,
    /// Required principal entity type (`principal is Agent`, etc.).
    pub principal_type: Option<String>,
    /// Matched principal agent IDs (`principal == Agent::"<id>"`). Empty means any principal.
    pub principal_agents: Vec<String>,
    /// Action names matched by this rule (`Action::"<name>"`). Empty means any action (`action`).
    pub actions: Vec<String>,
    /// Optional resource entity type (`resource is WorkspaceResource`, etc.).
    pub resource_type: Option<String>,
    /// Optional resource pattern (`resource == "..."` or `resource like "..."`).
    pub resource_pattern: Option<String>,
    /// `when { ... resource.org_id == principal.org_id ... }`
    pub require_same_org: bool,
    /// `when { ... principal.org_id != resource.org_id ... }`
    pub require_diff_org: bool,
    /// Guard clauses (`when { ... }` / `unless { ... }`) evaluated against `PolicyContext`.
    pub conditions: Vec<CedarCondition>,
}

#[derive(Debug, Clone, Default)]
pub struct CedarPolicySet {
    pub rules: Vec<CedarRule>,
    pub parse_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CedarToken {
    Ident(String),
    Str(String),
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Comma,
    Semicolon,
    Dot,
    Bang,
    ColonColon,
    EqEq,
    NotEq,
    AndAnd,
    OrOr,
}

fn tokenize_cedar(src: &str) -> anyhow::Result<Vec<CedarToken>> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = src.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        let ch = chars[i];
        if ch.is_whitespace() {
            i += 1;
            continue;
        }
        // Line comment (`// ...`) only outside string literals
        if ch == '/' && chars.get(i + 1) == Some(&'/') {
            i += 2;
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        // Block comment (`/* ... */`) only outside string literals
        if ch == '/' && chars.get(i + 1) == Some(&'*') {
            i += 2;
            let mut closed = false;
            while i + 1 < chars.len() {
                if chars[i] == '*' && chars[i + 1] == '/' {
                    i += 2;
                    closed = true;
                    break;
                }
                i += 1;
            }
            if !closed {
                anyhow::bail!("Unterminated block comment in Cedar policy");
            }
            continue;
        }
        if ch == '"' {
            i += 1;
            let mut out = String::new();
            let mut closed = false;
            while i < chars.len() {
                let c = chars[i];
                if c == '"' {
                    i += 1;
                    closed = true;
                    break;
                }
                if c == '\\' {
                    i += 1;
                    let esc = chars
                        .get(i)
                        .copied()
                        .context("Unterminated escape in Cedar string literal")?;
                    match esc {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        other => out.push(other),
                    }
                    i += 1;
                } else {
                    out.push(c);
                    i += 1;
                }
            }
            if !closed {
                anyhow::bail!("Unterminated string literal in Cedar policy");
            }
            tokens.push(CedarToken::Str(out));
            continue;
        }
        if let Some(&next) = chars.get(i + 1) {
            let two = match (ch, next) {
                (':', ':') => Some(CedarToken::ColonColon),
                ('=', '=') => Some(CedarToken::EqEq),
                ('!', '=') => Some(CedarToken::NotEq),
                ('&', '&') => Some(CedarToken::AndAnd),
                ('|', '|') => Some(CedarToken::OrOr),
                _ => None,
            };
            if let Some(tok) = two {
                tokens.push(tok);
                i += 2;
                continue;
            }
        }
        match ch {
            '(' => tokens.push(CedarToken::LParen),
            ')' => tokens.push(CedarToken::RParen),
            '{' => tokens.push(CedarToken::LBrace),
            '}' => tokens.push(CedarToken::RBrace),
            '[' => tokens.push(CedarToken::LBracket),
            ']' => tokens.push(CedarToken::RBracket),
            ',' => tokens.push(CedarToken::Comma),
            ';' => tokens.push(CedarToken::Semicolon),
            '.' => tokens.push(CedarToken::Dot),
            '!' => tokens.push(CedarToken::Bang),
            _ if ch.is_ascii_alphabetic() || ch == '_' => {
                let start = i;
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                let ident: String = chars[start..i].iter().collect();
                tokens.push(CedarToken::Ident(ident));
                continue;
            }
            other => anyhow::bail!("Unexpected character '{}' in Cedar policy", other),
        }
        i += 1;
    }
    Ok(tokens)
}

struct CedarParser<'a> {
    tokens: &'a [CedarToken],
    pos: usize,
}

impl<'a> CedarParser<'a> {
    fn peek(&self) -> Option<&CedarToken> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> anyhow::Result<&CedarToken> {
        let tok = self
            .tokens
            .get(self.pos)
            .context("Unexpected end of Cedar policy")?;
        self.pos += 1;
        Ok(tok)
    }

    fn expect(&mut self, expected: &CedarToken) -> anyhow::Result<()> {
        let tok = self.next()?;
        if tok != expected {
            anyhow::bail!("Expected {:?} in Cedar policy, found {:?}", expected, tok);
        }
        Ok(())
    }

    fn expect_ident_value(&mut self) -> anyhow::Result<String> {
        match self.next()? {
            CedarToken::Ident(s) => Ok(s.clone()),
            other => anyhow::bail!("Expected identifier in Cedar policy, found {:?}", other),
        }
    }

    fn expect_str_value(&mut self) -> anyhow::Result<String> {
        match self.next()? {
            CedarToken::Str(s) => Ok(s.clone()),
            other => anyhow::bail!("Expected string literal in Cedar policy, found {:?}", other),
        }
    }

    fn consume_ident(&mut self, name: &str) -> bool {
        if matches!(self.peek(), Some(CedarToken::Ident(s)) if s == name) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn parse_principal_clause(&mut self) -> anyhow::Result<(Option<String>, Vec<String>)> {
        if !self.consume_ident("principal") {
            anyhow::bail!("Expected 'principal' clause in Cedar statement head");
        }
        if matches!(self.peek(), Some(CedarToken::Comma)) {
            return Ok((None, Vec::new()));
        }
        if self.consume_ident("is") {
            let ty = self.expect_ident_value()?;
            if ty != "Agent" {
                anyhow::bail!("Unsupported principal entity type '{}'", ty);
            }
            return Ok((Some(ty), Vec::new()));
        }
        if matches!(self.peek(), Some(CedarToken::EqEq)) {
            self.pos += 1;
            if let Some(CedarToken::Str(_)) = self.peek() {
                return Ok((None, vec![self.expect_str_value()?]));
            }
            let ty = self.expect_ident_value()?;
            self.expect(&CedarToken::ColonColon)?;
            let id = self.expect_str_value()?;
            return Ok((Some(ty), vec![id]));
        }
        if self.consume_ident("in") {
            if matches!(self.peek(), Some(CedarToken::LBracket)) {
                self.pos += 1;
                let mut ids = Vec::new();
                while !matches!(self.peek(), Some(CedarToken::RBracket)) {
                    let ty = self.expect_ident_value()?;
                    if ty != "Agent" {
                        anyhow::bail!("Unsupported principal entity type '{}' in set", ty);
                    }
                    self.expect(&CedarToken::ColonColon)?;
                    ids.push(self.expect_str_value()?);
                    if matches!(self.peek(), Some(CedarToken::Comma)) {
                        self.pos += 1;
                    } else {
                        break;
                    }
                }
                self.expect(&CedarToken::RBracket)?;
                if ids.is_empty() {
                    anyhow::bail!("Empty principal set in Cedar rule");
                }
                return Ok((Some("Agent".to_string()), ids));
            }
            let ty = self.expect_ident_value()?;
            self.expect(&CedarToken::ColonColon)?;
            let id = self.expect_str_value()?;
            return Ok((Some(ty), vec![id]));
        }
        anyhow::bail!("Unsupported 'principal' clause syntax: {:?}", self.peek());
    }

    fn parse_action_item(&mut self) -> anyhow::Result<String> {
        let ns = self.expect_ident_value()?;
        if ns != "Action" {
            anyhow::bail!("Expected Action::\"...\", found '{}::...'", ns);
        }
        self.expect(&CedarToken::ColonColon)?;
        self.expect_str_value()
    }

    fn parse_action_clause(&mut self) -> anyhow::Result<Vec<String>> {
        if !self.consume_ident("action") {
            anyhow::bail!("Expected 'action' clause in Cedar statement head");
        }
        if matches!(self.peek(), Some(CedarToken::Comma)) {
            return Ok(Vec::new());
        }
        if matches!(self.peek(), Some(CedarToken::EqEq)) {
            self.pos += 1;
            return Ok(vec![self.parse_action_item()?]);
        }
        if self.consume_ident("in") {
            if matches!(self.peek(), Some(CedarToken::LBracket)) {
                self.pos += 1;
                let mut actions = Vec::new();
                while !matches!(self.peek(), Some(CedarToken::RBracket)) {
                    actions.push(self.parse_action_item()?);
                    if matches!(self.peek(), Some(CedarToken::Comma)) {
                        self.pos += 1;
                    } else {
                        break;
                    }
                }
                self.expect(&CedarToken::RBracket)?;
                if actions.is_empty() {
                    anyhow::bail!("Empty action set in Cedar rule");
                }
                return Ok(actions);
            }
            return Ok(vec![self.parse_action_item()?]);
        }
        anyhow::bail!("Unsupported 'action' clause syntax: {:?}", self.peek());
    }

    fn parse_resource_clause(&mut self) -> anyhow::Result<(Option<String>, Option<String>)> {
        if !self.consume_ident("resource") {
            anyhow::bail!("Expected 'resource' clause in Cedar statement head");
        }
        if matches!(self.peek(), Some(CedarToken::RParen)) {
            return Ok((None, None));
        }
        if self.consume_ident("is") {
            let rt = self.expect_ident_value()?;
            return Ok((Some(rt), None));
        }
        if matches!(self.peek(), Some(CedarToken::EqEq)) {
            self.pos += 1;
            if matches!(self.peek(), Some(CedarToken::Str(_))) {
                return Ok((None, Some(self.expect_str_value()?)));
            }
            let rt = self.expect_ident_value()?;
            self.expect(&CedarToken::ColonColon)?;
            let id = self.expect_str_value()?;
            return Ok((Some(rt), Some(id)));
        }
        if self.consume_ident("like") {
            let pat = self.expect_str_value()?;
            return Ok((None, Some(pat)));
        }
        anyhow::bail!("Unsupported 'resource' clause syntax: {:?}", self.peek());
    }

    fn parse_operand(&mut self) -> anyhow::Result<CedarOperand> {
        match self.next()?.clone() {
            CedarToken::Str(s) => Ok(CedarOperand::Literal(s)),
            CedarToken::Ident(root) => {
                self.expect(&CedarToken::Dot)?;
                let field = self.expect_ident_value()?;
                match (root.as_str(), field.as_str()) {
                    ("principal", "org_id") => Ok(CedarOperand::PrincipalOrgId),
                    ("principal", "agent_id") => Ok(CedarOperand::PrincipalAgentId),
                    ("principal", "role") => Ok(CedarOperand::PrincipalRole),
                    ("resource", "org_id") => Ok(CedarOperand::ResourceOrgId),
                    ("resource", "owner_agent_id") => Ok(CedarOperand::ResourceOwnerAgentId),
                    ("resource", "id") => Ok(CedarOperand::ResourceId),
                    ("resource", "path") => Ok(CedarOperand::ResourcePath),
                    _ => anyhow::bail!("Unsupported Cedar attribute '{}.{}'", root, field),
                }
            }
            other => anyhow::bail!("Expected Cedar operand, found {:?}", other),
        }
    }

    fn parse_expr(&mut self) -> anyhow::Result<CedarExpr> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> anyhow::Result<CedarExpr> {
        let mut lhs = self.parse_and()?;
        while matches!(self.peek(), Some(CedarToken::OrOr)) {
            self.pos += 1;
            let rhs = self.parse_and()?;
            lhs = CedarExpr::Or(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> anyhow::Result<CedarExpr> {
        let mut lhs = self.parse_unary()?;
        while matches!(self.peek(), Some(CedarToken::AndAnd)) {
            self.pos += 1;
            let rhs = self.parse_unary()?;
            lhs = CedarExpr::And(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> anyhow::Result<CedarExpr> {
        if matches!(self.peek(), Some(CedarToken::Bang)) {
            self.pos += 1;
            return Ok(CedarExpr::Not(Box::new(self.parse_unary()?)));
        }
        if matches!(self.peek(), Some(CedarToken::LParen)) {
            self.pos += 1;
            let inner = self.parse_expr()?;
            self.expect(&CedarToken::RParen)?;
            return Ok(inner);
        }
        let lhs = self.parse_operand()?;
        if matches!(self.peek(), Some(CedarToken::EqEq)) {
            self.pos += 1;
            let rhs = self.parse_operand()?;
            return Ok(CedarExpr::Eq(lhs, rhs));
        }
        if matches!(self.peek(), Some(CedarToken::NotEq)) {
            self.pos += 1;
            let rhs = self.parse_operand()?;
            return Ok(CedarExpr::Ne(lhs, rhs));
        }
        if self.consume_ident("like") {
            let pat = self.expect_str_value()?;
            return Ok(CedarExpr::Like(lhs, pat));
        }
        anyhow::bail!(
            "Expected comparison operator ('==', '!=', 'like') in Cedar condition, found {:?}",
            self.peek()
        );
    }

    fn parse_statement(&mut self, idx: usize, is_default: bool) -> anyhow::Result<CedarRule> {
        let effect = if self.consume_ident("permit") {
            CedarEffect::Permit
        } else if self.consume_ident("forbid") {
            CedarEffect::Forbid
        } else {
            anyhow::bail!(
                "Expected 'permit' or 'forbid' in Cedar statement, found {:?}",
                self.peek()
            );
        };

        self.expect(&CedarToken::LParen)?;
        let (principal_type, principal_agents) = self.parse_principal_clause()?;
        self.expect(&CedarToken::Comma)?;
        let actions = self.parse_action_clause()?;
        self.expect(&CedarToken::Comma)?;
        let (resource_type, resource_pattern) = self.parse_resource_clause()?;
        self.expect(&CedarToken::RParen)?;

        let mut conditions = Vec::new();
        while let Some(CedarToken::Ident(kw)) = self.peek() {
            if kw == "when" || kw == "unless" {
                let is_when = kw == "when";
                self.pos += 1;
                self.expect(&CedarToken::LBrace)?;
                let expr = self.parse_expr()?;
                self.expect(&CedarToken::RBrace)?;
                if is_when {
                    conditions.push(CedarCondition::When(expr));
                } else {
                    conditions.push(CedarCondition::Unless(expr));
                }
            } else {
                anyhow::bail!("Unexpected trailing keyword '{}' in Cedar rule", kw);
            }
        }
        self.expect(&CedarToken::Semicolon)?;

        let mut require_same_org = false;
        let mut require_diff_org = false;
        for cond in &conditions {
            if let CedarCondition::When(expr) = cond {
                if expr_contains_org_cmp(expr, true) {
                    require_same_org = true;
                }
                if expr_contains_org_cmp(expr, false) {
                    require_diff_org = true;
                }
            }
        }

        let id = match (is_default, effect, resource_type.as_deref()) {
            (true, CedarEffect::Permit, Some("WorkspaceResource")) => {
                "cedar:default:cow_workspace_auto_allow".to_string()
            }
            (true, CedarEffect::Permit, Some("SandboxResource")) => {
                "cedar:default:sandbox_exec_auto_allow".to_string()
            }
            (true, CedarEffect::Permit, Some("OrgResource")) => {
                "cedar:default:intra_org_sharing_auto_allow".to_string()
            }
            (true, CedarEffect::Permit, Some("IpcResource")) => {
                "aegis:default:intra_org_ipc_auto_allow".to_string()
            }
            (true, CedarEffect::Forbid, None) if require_diff_org => {
                "cedar:default:cross_org_forbid".to_string()
            }
            (_, CedarEffect::Forbid, _) => format!("cedar:forbid:rule_{}", idx + 1),
            (_, CedarEffect::Permit, _) => format!("cedar:permit:rule_{}", idx + 1),
        };

        Ok(CedarRule {
            id,
            effect,
            principal_type,
            principal_agents,
            actions,
            resource_type,
            resource_pattern,
            require_same_org,
            require_diff_org,
            conditions,
        })
    }
}

fn expr_contains_org_cmp(expr: &CedarExpr, same: bool) -> bool {
    match expr {
        CedarExpr::And(a, b) | CedarExpr::Or(a, b) => {
            expr_contains_org_cmp(a, same) || expr_contains_org_cmp(b, same)
        }
        CedarExpr::Not(_) => false,
        CedarExpr::Eq(lhs, rhs) if same => matches!(
            (lhs, rhs),
            (CedarOperand::ResourceOrgId, CedarOperand::PrincipalOrgId)
                | (CedarOperand::PrincipalOrgId, CedarOperand::ResourceOrgId)
        ),
        CedarExpr::Ne(lhs, rhs) if !same => matches!(
            (lhs, rhs),
            (CedarOperand::ResourceOrgId, CedarOperand::PrincipalOrgId)
                | (CedarOperand::PrincipalOrgId, CedarOperand::ResourceOrgId)
        ),
        _ => false,
    }
}

fn resolve_cedar_operand<'a>(op: &'a CedarOperand, ctx: &'a PolicyContext) -> &'a str {
    match op {
        CedarOperand::PrincipalOrgId => ctx.principal.org_id.as_str(),
        CedarOperand::PrincipalAgentId => ctx.principal.agent_id.as_str(),
        CedarOperand::PrincipalRole => ctx.principal.role.as_str(),
        CedarOperand::ResourceOrgId => ctx.target_org_id.as_str(),
        CedarOperand::ResourceOwnerAgentId => ctx
            .metadata
            .get("owner_agent_id")
            .and_then(|v| v.as_str())
            .unwrap_or(ctx.principal.agent_id.as_str()),
        CedarOperand::ResourceId | CedarOperand::ResourcePath => ctx.target_resource.as_str(),
        CedarOperand::Literal(s) => s.as_str(),
    }
}

fn eval_cedar_expr(expr: &CedarExpr, ctx: &PolicyContext) -> bool {
    match expr {
        CedarExpr::And(a, b) => eval_cedar_expr(a, ctx) && eval_cedar_expr(b, ctx),
        CedarExpr::Or(a, b) => eval_cedar_expr(a, ctx) || eval_cedar_expr(b, ctx),
        CedarExpr::Not(inner) => !eval_cedar_expr(inner, ctx),
        CedarExpr::Eq(lhs, rhs) => resolve_cedar_operand(lhs, ctx) == resolve_cedar_operand(rhs, ctx),
        CedarExpr::Ne(lhs, rhs) => resolve_cedar_operand(lhs, ctx) != resolve_cedar_operand(rhs, ctx),
        CedarExpr::Like(lhs, pat) => {
            AegisPolicyKernel::matches_pattern(pat, resolve_cedar_operand(lhs, ctx))
        }
    }
}

fn infer_builtin_resource_type(action: &str) -> Option<&'static str> {
    if action.starts_with("fs_")
        || action.starts_with("workspace_")
        || matches!(
            action,
            "github_ci_inspect" | "github_pr_inspect" | "github_issue_inspect"
        )
    {
        Some("WorkspaceResource")
    } else if matches!(action, "proc_exec" | "proc_manage") {
        Some("SandboxResource")
    } else if action.starts_with("org_") {
        Some("OrgResource")
    } else if action.starts_with("ipc_")
        || action == "egress_http_request"
        || action.starts_with("coord_")
        || action.starts_with("app_")
    {
        Some("IpcResource")
    } else {
        None
    }
}

impl CedarPolicySet {
    pub fn try_parse(src: &str) -> anyhow::Result<Self> {
        Self::try_parse_with_mode(src, false)
    }

    pub fn try_parse_default(src: &str) -> anyhow::Result<Self> {
        Self::try_parse_with_mode(src, true)
    }

    fn try_parse_with_mode(src: &str, is_default: bool) -> anyhow::Result<Self> {
        let tokens = tokenize_cedar(src)?;
        let mut parser = CedarParser {
            tokens: &tokens,
            pos: 0,
        };
        let mut rules = Vec::new();
        let mut idx = 0usize;
        while parser.peek().is_some() {
            rules.push(parser.parse_statement(idx, is_default)?);
            idx += 1;
        }
        Ok(Self {
            rules,
            parse_error: None,
        })
    }

    /// Parses a Cedar policy source string, failing closed with a catch-all `forbid` rule if syntax
    /// is invalid so malformed policies never silently fail open.
    pub fn parse(src: &str) -> Self {
        match Self::try_parse(src) {
            Ok(set) => set,
            Err(err) => Self::fail_closed(format!("Cedar policy parse error: {err}")),
        }
    }

    fn fail_closed(reason: String) -> Self {
        Self {
            rules: vec![CedarRule {
                id: "cedar:forbid:parse_error".to_string(),
                effect: CedarEffect::Forbid,
                principal_type: None,
                principal_agents: Vec::new(),
                actions: Vec::new(),
                resource_type: None,
                resource_pattern: None,
                require_same_org: false,
                require_diff_org: false,
                conditions: Vec::new(),
            }],
            parse_error: Some(reason),
        }
    }

    pub fn try_extend_from_str(&mut self, extra_src: &str) -> anyhow::Result<()> {
        let parsed = Self::try_parse(extra_src)?;
        let offset = self.rules.len();
        for (i, mut rule) in parsed.rules.into_iter().enumerate() {
            if let Some(prefix) = rule.id.strip_suffix(&format!(":rule_{}", i + 1)) {
                rule.id = format!("{prefix}:rule_{}", offset + i + 1);
            }
            self.rules.push(rule);
        }
        Ok(())
    }

    pub fn extend_from_str(&mut self, extra_src: &str) {
        if let Err(err) = self.try_extend_from_str(extra_src) {
            self.fail_closed_in_place(format!("Cedar policy parse error: {err}"));
        }
    }

    fn fail_closed_in_place(&mut self, reason: String) {
        self.rules.retain(|r| r.effect == CedarEffect::Forbid);
        self.rules.insert(
            0,
            CedarRule {
                id: "cedar:forbid:parse_error".to_string(),
                effect: CedarEffect::Forbid,
                principal_type: None,
                principal_agents: Vec::new(),
                actions: Vec::new(),
                resource_type: None,
                resource_pattern: None,
                require_same_org: false,
                require_diff_org: false,
                conditions: Vec::new(),
            },
        );
        self.parse_error = Some(reason);
    }

    fn rule_matches(&self, rule: &CedarRule, ctx: &PolicyContext) -> bool {
        if let Some(ref pt) = rule.principal_type {
            if pt != "Agent" {
                return false;
            }
        }
        if !rule.principal_agents.is_empty()
            && !rule
                .principal_agents
                .iter()
                .any(|a| a == &ctx.principal.agent_id)
        {
            return false;
        }
        if !rule.actions.is_empty() && !rule.actions.iter().any(|a| a == &ctx.action) {
            return false;
        }
        if let Some(ref req_rt) = rule.resource_type {
            let explicit_rt = ctx.metadata.get("resource_type").and_then(|v| v.as_str());
            let effective_rt = explicit_rt.or_else(|| infer_builtin_resource_type(&ctx.action));
            match effective_rt {
                Some(rt) if rt != req_rt.as_str() => return false,
                None if rule.actions.is_empty()
                    || matches!(
                        req_rt.as_str(),
                        "WorkspaceResource"
                            | "SandboxResource"
                            | "OrgResource"
                            | "IpcResource"
                    ) =>
                {
                    return false;
                }
                _ => {}
            }
        }
        if let Some(ref pat) = rule.resource_pattern {
            if !AegisPolicyKernel::matches_pattern(pat, &ctx.target_resource) {
                return false;
            }
        }
        for cond in &rule.conditions {
            match cond {
                CedarCondition::When(expr) => {
                    if !eval_cedar_expr(expr, ctx) {
                        return false;
                    }
                }
                CedarCondition::Unless(expr) => {
                    if eval_cedar_expr(expr, ctx) {
                        return false;
                    }
                }
            }
        }
        true
    }

    /// Evaluates custom `forbid` rules (excluding the baseline cross-org rule which has A2A workstation peer handling).
    pub fn find_custom_forbid(&self, ctx: &PolicyContext) -> Option<&CedarRule> {
        self.rules.iter().find(|r| {
            r.effect == CedarEffect::Forbid
                && r.id != "cedar:default:cross_org_forbid"
                && self.rule_matches(r, ctx)
        })
    }

    /// Evaluates `permit` rules loaded from `policy/default.cedar` (and any custom Cedar policy file).
    pub fn find_permit(&self, ctx: &PolicyContext) -> Option<&CedarRule> {
        if self.parse_error.is_some() {
            return None;
        }
        self.rules
            .iter()
            .find(|r| r.effect == CedarEffect::Permit && self.rule_matches(r, ctx))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TaintSourceEntry {
    pub server_id: String,
    pub tool_name: String,
    pub summary: String,
    pub timestamp_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SessionTaintRecord {
    pub org_id: String,
    pub agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub first_tainted_at_ms: i64,
    pub updated_at_ms: i64,
    pub expires_at_ms: i64,
    pub sources: Vec<TaintSourceEntry>,
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct PersistedTaintState {
    taints: Vec<SessionTaintRecord>,
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct PersistedPolicyState {
    leases: Vec<LeaseGrant>,
    escalations: Vec<PendingEscalation>,
}

type HostExecLeaseEntry = (String, String, String);

pub struct AegisPolicyKernel {
    state_file: Option<PathBuf>,
    taints_file: Option<PathBuf>,
    state_mutex: Arc<tokio::sync::Mutex<()>>,
    leases: Arc<RwLock<Vec<LeaseGrant>>>,
    escalations: Arc<RwLock<Vec<PendingEscalation>>>,
    taints: Arc<RwLock<Vec<SessionTaintRecord>>>,
    /// Unforgeable in-memory lease registry for `host_exec`. Never persisted or hydrated from
    /// `policy_state.json`, preventing an unsandboxed same-UID child from forging disk leases.
    in_memory_host_exec_leases: Arc<RwLock<std::collections::HashMap<String, HostExecLeaseEntry>>>,
    forbidden_host_prefixes: Vec<String>,
    cedar_policies: CedarPolicySet,
}

impl Default for AegisPolicyKernel {
    fn default() -> Self {
        Self::new()
    }
}

impl AegisPolicyKernel {
    pub fn new() -> Self {
        Self::with_state_file(None)
    }

    pub fn with_state_file(state_file: Option<PathBuf>) -> Self {
        let taints_file = state_file
            .as_ref()
            .and_then(|p| p.parent().map(|dir| dir.join("session_taints.json")));
        let mut initial_leases = Vec::new();
        let mut initial_escalations = Vec::new();
        let mut initial_taints = Vec::new();

        if let Some(ref path) = state_file {
            if let Ok(bytes) = std::fs::read(path) {
                if let Ok(parsed) = serde_json::from_slice::<PersistedPolicyState>(&bytes) {
                    initial_leases = parsed.leases;
                    initial_escalations = parsed.escalations;
                }
            }
        }
        if let Some(ref path) = taints_file {
            if let Ok(bytes) = std::fs::read(path) {
                if let Ok(parsed) = serde_json::from_slice::<PersistedTaintState>(&bytes) {
                    initial_taints = parsed.taints;
                }
            }
        }

        let mut cedar_policies = CedarPolicySet::try_parse_default(DEFAULT_CEDAR_POLICY)
            .expect("embedded policy/default.cedar must parse cleanly");
        if let Ok(custom_path) = std::env::var("AOS_CEDAR_POLICY_FILE") {
            let trimmed = custom_path.trim();
            if !trimmed.is_empty() {
                match std::fs::read_to_string(trimmed) {
                    Ok(custom_src) => {
                        if let Err(err) = cedar_policies.try_extend_from_str(&custom_src) {
                            cedar_policies.fail_closed_in_place(format!(
                                "Failed to parse AOS_CEDAR_POLICY_FILE '{}': {}",
                                trimmed, err
                            ));
                        }
                    }
                    Err(err) => {
                        cedar_policies.fail_closed_in_place(format!(
                            "Failed to read AOS_CEDAR_POLICY_FILE '{}': {}",
                            trimmed, err
                        ));
                    }
                }
            }
        }

        Self {
            state_file,
            taints_file,
            state_mutex: Arc::new(tokio::sync::Mutex::new(())),
            leases: Arc::new(RwLock::new(initial_leases)),
            escalations: Arc::new(RwLock::new(initial_escalations)),
            taints: Arc::new(RwLock::new(initial_taints)),
            in_memory_host_exec_leases: Arc::new(RwLock::new(std::collections::HashMap::new())),
            forbidden_host_prefixes: vec![
                "~/.ssh".to_string(),
                "~/.aws".to_string(),
                "~/.gnupg".to_string(),
                "~/.kube".to_string(),
                "/etc/shadow".to_string(),
                "/etc/sudoers".to_string(),
                "/System".to_string(),
            ],
            cedar_policies,
        }
    }

    /// Appends additional declarative Cedar policy statements (`permit` / `forbid`), returning
    /// an error if parsing fails.
    pub fn try_add_cedar_policies(&mut self, cedar_src: &str) -> anyhow::Result<()> {
        self.cedar_policies.try_extend_from_str(cedar_src)
    }

    /// Appends additional declarative Cedar policy statements (`permit` / `forbid`) to this kernel,
    /// failing closed if `cedar_src` contains invalid or unsupported syntax.
    pub fn add_cedar_policies(&mut self, cedar_src: &str) {
        self.cedar_policies.extend_from_str(cedar_src);
    }

    /// Returns a reference to the loaded declarative Cedar policy set.
    pub fn cedar_policies(&self) -> &CedarPolicySet {
        &self.cedar_policies
    }

    async fn acquire_state_lock(&self) -> anyhow::Result<Option<std::fs::File>> {
        if let Some(ref path) = self.state_file {
            Ok(Some(aos_core::session::acquire_file_lock(path).await?))
        } else {
            Ok(None)
        }
    }

    async fn reload_from_disk(&self) {
        if let Some(ref path) = self.state_file {
            if let Ok(bytes) = tokio::fs::read(path).await {
                if let Ok(parsed) = serde_json::from_slice::<PersistedPolicyState>(&bytes) {
                    *self.leases.write().await = parsed.leases;
                    *self.escalations.write().await = parsed.escalations;
                }
            }
        }
        if let Some(ref path) = self.taints_file {
            if let Ok(bytes) = tokio::fs::read(path).await {
                if let Ok(parsed) = serde_json::from_slice::<PersistedTaintState>(&bytes) {
                    *self.taints.write().await = parsed.taints;
                }
            }
        }
    }

    async fn flush_to_disk_unlocked(&self) -> anyhow::Result<()> {
        if let Some(ref path) = self.state_file {
            let state = PersistedPolicyState {
                leases: self.leases.read().await.clone(),
                escalations: self.escalations.read().await.clone(),
            };
            aos_core::session::write_json_pretty_unlocked(path, &state).await?;
        }
        if let Some(ref path) = self.taints_file {
            let taint_state = PersistedTaintState {
                taints: self.taints.read().await.clone(),
            };
            aos_core::session::write_json_pretty_unlocked(path, &taint_state).await?;
        }
        Ok(())
    }

    fn matches_pattern(pattern: &str, value: &str) -> bool {
        if pattern == "*" || pattern == value {
            return true;
        }
        let pat: Vec<char> = pattern.chars().collect();
        let val: Vec<char> = value.chars().collect();
        let (mut pi, mut vi) = (0usize, 0usize);
        let mut star_pi: Option<usize> = None;
        let mut match_vi = 0usize;
        while vi < val.len() {
            if pi < pat.len() && (pat[pi] == '?' || pat[pi] == val[vi]) {
                pi += 1;
                vi += 1;
            } else if pi < pat.len() && pat[pi] == '*' {
                star_pi = Some(pi);
                match_vi = vi;
                pi += 1;
            } else if let Some(sp) = star_pi {
                pi = sp + 1;
                match_vi += 1;
                vi = match_vi;
            } else {
                return false;
            }
        }
        while pi < pat.len() && pat[pi] == '*' {
            pi += 1;
        }
        pi == pat.len()
    }

    /// Matches a lease `resource_pattern` against `target_resource` and, if the pattern includes a
    /// cryptographic diff/evidence pin (`sha256:<hex>` or `<resource>#sha256:<hex>`), verifies that
    /// `metadata.evidence_hash` matches the pinned SHA-256 digest (preventing TOCTOU diff-swap attacks).
    fn matches_resource_and_evidence(
        pattern: &str,
        value: &str,
        metadata: &serde_json::Value,
    ) -> bool {
        if let Some((base_pat, expected_hash)) = pattern.rsplit_once("#sha256:") {
            if !expected_hash.is_empty() {
                if !Self::matches_pattern(base_pat, value) {
                    return false;
                }
                return metadata.get("evidence_hash").and_then(|v| v.as_str())
                    == Some(expected_hash);
            }
        }
        if let Some(expected_hash) = pattern.strip_prefix("sha256:") {
            return metadata.get("evidence_hash").and_then(|v| v.as_str()) == Some(expected_hash);
        }
        Self::matches_pattern(pattern, value)
    }

    async fn expire_stale_escalations_unlocked(&self, now_ms: i64) -> bool {
        let mut changed = false;
        let mut list = self.escalations.write().await;
        for item in list.iter_mut() {
            if item.status == EscalationStatus::Pending
                && item.expires_at_ms.is_some_and(|exp| exp <= now_ms)
            {
                item.status = EscalationStatus::Expired;
                item.decided_by = Some("policy-ttl-watchdog".to_string());
                item.decided_at_ms = Some(now_ms);
                changed = true;
            }
        }
        changed
    }

    fn strip_nested_test_tmpdir(s: &str) -> &str {
        if std::env::var("AEGIS_ALLOW_NESTED_TEST_SANDBOX").as_deref() != Ok("1") {
            return s;
        }
        let temp_dir_str = std::env::temp_dir().to_string_lossy().into_owned();
        let temp_norm = temp_dir_str.trim_end_matches('/');
        let has_real_tmp_prefix = s.starts_with("/tmp/")
            || s.starts_with("/private/tmp/")
            || s.starts_with("/var/folders/")
            || s.starts_with("/private/var/folders/")
            || (!temp_norm.is_empty() && s.starts_with(&format!("{temp_norm}/")));
        if !has_real_tmp_prefix {
            return s;
        }
        let Some(idx) = s.find("/agent_home/.tmp") else {
            return s;
        };
        if s[..idx].contains("/../") || s[..idx].ends_with("/..") {
            return s;
        }
        let rest = &s[idx + "/agent_home/".len()..];
        match rest.find('/') {
            Some(slash) => &rest[slash..],
            None => "",
        }
    }

    /// Returns true if a relative workspace path can trigger automatic code execution on the host
    /// during git operations, directory entry (`direnv`), CI runs, or build-system invocation
    /// (`build.rs`, `Makefile`, `package.json`, `.cargo/config.toml`, `.vscode/tasks.json`).
    pub fn is_commit_poisoning_path(p: &str) -> bool {
        let p = Self::strip_nested_test_tmpdir(p);
        // Case-fold before matching: on case-insensitive filesystems (APFS/HFS+ default, NTFS)
        // `.GIT/hooks/x` or `.GitHub/Workflows/x.yml` lands on the real `.git/hooks/x` /
        // `.github/workflows/x.yml`. All literals below are therefore lowercase.
        let folded = p.trim_start_matches("./").trim_start_matches('/').to_lowercase();
        let norm = folded.as_str();
        let file_name = norm.rsplit('/').next().unwrap_or(norm);
        // A bare `.git` *file* (gitlink: `gitdir: <path>`) can redirect Git to another directory.
        file_name == ".git"
            || norm.starts_with(".git/")
            || norm.contains("/.git/")
            || norm == ".gitmodules"
            || norm.ends_with(".envrc")
            || norm.contains(".github/workflows")
            || norm == ".gitlab-ci.yml"
            || norm.contains(".cargo/config")
            || norm.contains(".vscode/tasks.json")
            || norm.contains(".vscode/launch.json")
            || norm == ".agents/hooks.json"
            || norm.ends_with("/.agents/hooks.json")
            || norm.starts_with(".aegis/")
            || norm.contains("/.aegis/")
            || norm.starts_with(".claude/")
            || norm.contains("/.claude/")
            || norm == ".claude.json"
            || norm.starts_with(".cursor/")
            || norm.contains("/.cursor/")
            || norm == ".mcp.json"
            || norm.starts_with(".gemini/")
            || norm.contains("/.gemini/")
            || norm.starts_with(".codex/")
            || norm.contains("/.codex/")
            || norm == "opencode.json"
            || norm == "opencode.jsonc"
            || norm.ends_with("/opencode.json")
            || norm.ends_with("/opencode.jsonc")
            || norm.starts_with(".opencode/")
            || norm.contains("/.opencode/")
            || file_name == "build.rs"
            || file_name == "makefile"
            || file_name == "gnumakefile"
            || file_name == "cmakelists.txt"
            || file_name == "package.json"
            || file_name == "setup.py"
            // Also execute code on routine dev commands (git hooks, test runners, build scripts).
            || norm.starts_with(".husky/")
            || norm.contains("/.husky/")
            || file_name == ".pre-commit-config.yaml"
            || file_name == ".gitattributes"
            || file_name == "pyproject.toml"
            || file_name == "setup.cfg"
            || file_name == "conftest.py"
            || file_name == "noxfile.py"
            || file_name == "tox.ini"
            || file_name == "cargo.toml"
            || file_name == "rust-toolchain.toml"
            || file_name == "rust-toolchain"
            || file_name == "build.gradle"
            || file_name == "build.gradle.kts"
            || file_name == "pom.xml"
            || file_name == "justfile"
            || file_name == "rakefile"
            || file_name == ".npmrc"
    }

    const PROTECTED_CLIENT_CONFIG_MARKERS: &'static [&'static str] = &[
        "/.git/",
        "/.gemini/",
        "/.claude/",
        "/.codex/",
        "/.cursor/",
        "/.opencode/",
        "/.hermes/",
        "/.aegis/",
        "/.agents/hooks.json",
        "/hooks.json",
        "/mcp_config.json",
    ];

    /// Returns true when a host path points to credentials, runtime internals, or dotenv secrets
    /// that must never be imported via `fs_import_file`.
    pub fn is_forbidden_import_source(p: &str) -> bool {
        let res = Self::strip_nested_test_tmpdir(p);
        // Case-fold: `~/.SSH/id_rsa` names the same file as `~/.ssh/id_rsa` on APFS/NTFS.
        let norm = res.replace('\\', "/").to_lowercase();
        let file_name = norm.rsplit('/').next().unwrap_or(&norm);
        if (file_name == ".env" || file_name.starts_with(".env."))
            && !matches!(
                file_name,
                ".env.example" | ".env.sample" | ".env.template" | ".env.dist" | ".env.schema"
            )
        {
            return true;
        }
        [
            "/.ssh/",
            "/.aws/",
            "/.gnupg/",
            "/.kube/",
            "/.docker/",
            "/.config/gh/",
            "/.config/gcloud/",
            "/.config/aegis-os/",
            "/.azure/",
            "/.netrc",
            "/.npmrc",
            "/.pypirc",
            "/.git-credentials",
            "/.vault-token",
            "/.cargo/credentials",
            "/Library/Keychains/",
            "/.aegis/",
            "/.orbstack/",
            "/.colima/",
            "/.lima/",
            "/dek.envelope.json",
            "/etc/shadow",
            "/etc/master.passwd",
        ]
        .iter()
        .map(|marker| marker.to_lowercase())
        .any(|marker| norm.contains(&marker) || norm.ends_with(marker.trim_end_matches('/')))
    }

    /// Matches an already-built policy context against active leases using the same semantics as
    /// `evaluate` (org/agent/action/resource/task/evidence pin). A matching OneShot lease is
    /// consumed, which is the desired fail-closed behaviour for a one-shot approval.
    ///
    /// Callers that need the full policy decision (Cedar forbid, commit guard, cross-tenant gate)
    /// must use `evaluate`; this helper only answers "is there an active lease for this effect?".
    pub async fn match_active_lease(&self, ctx: &PolicyContext) -> Option<LeaseGrant> {
        self.check_active_lease(ctx).await
    }

    /// Atomically verifies that every target in `targets` has an active sensitive lease for
    /// `sensitive_action`. Consumes matching `OneShot` leases only when ALL targets are covered;
    /// otherwise preserves all existing `OneShot` leases untouched and returns the unleased targets.
    async fn check_all_sensitive_targets_atomic(
        &self,
        ctx: &PolicyContext,
        sensitive_action: &str,
        targets: &[String],
        min_created_exclusive_ms: Option<i64>,
    ) -> Vec<String> {
        let _guard = self.state_mutex.lock().await;
        let _file_lock = self.acquire_state_lock().await.ok().flatten();
        self.reload_from_disk().await;
        let now_ms = Utc::now().timestamp_millis();
        let ctx_task_id = ctx
            .metadata
            .get("task_id")
            .and_then(|value| value.as_str());

        let mut missing = Vec::new();
        let mut oneshot_consume_indices: std::collections::BTreeSet<usize> =
            std::collections::BTreeSet::new();

        {
            let leases = self.leases.read().await;
            for target in targets {
                let mut matched_idx = None;
                let mut matched_oneshot = false;
                for (idx, lease) in leases.iter().enumerate() {
                    let kind = if lease.kind == LeaseKind::Ttl && lease.expires_at_ms == -1 {
                        LeaseKind::OneShot
                    } else {
                        lease.kind
                    };
                    let valid = if lease.expires_at_ms == -1 {
                        kind == LeaseKind::OneShot
                    } else {
                        lease.expires_at_ms > now_ms
                    };
                    let taint_epoch_ok = min_created_exclusive_ms
                        .is_none_or(|min_ms| lease.created_at_ms > min_ms);
                    let task_ok = match kind {
                        LeaseKind::TaskScoped => {
                            ctx_task_id.is_some() && lease.task_id.as_deref() == ctx_task_id
                        }
                        LeaseKind::Ttl | LeaseKind::OneShot => {
                            lease.task_id.is_none() || lease.task_id.as_deref() == ctx_task_id
                        }
                    };
                    if valid
                        && taint_epoch_ok
                        && task_ok
                        && lease.org_id == ctx.principal.org_id
                        && (lease.agent_id == "*" || lease.agent_id == ctx.principal.agent_id)
                        && Self::matches_pattern(&lease.action_pattern, sensitive_action)
                        && Self::matches_resource_and_evidence(
                            &lease.resource_pattern,
                            target,
                            &ctx.metadata,
                        )
                    {
                        matched_idx = Some(idx);
                        matched_oneshot = kind == LeaseKind::OneShot;
                        break;
                    }
                }
                if let Some(idx) = matched_idx {
                    if matched_oneshot {
                        oneshot_consume_indices.insert(idx);
                    }
                } else {
                    missing.push(target.clone());
                }
            }
        }

        if missing.is_empty() && !oneshot_consume_indices.is_empty() {
            {
                let mut leases = self.leases.write().await;
                for idx in oneshot_consume_indices.into_iter().rev() {
                    if idx < leases.len() {
                        leases.remove(idx);
                    }
                }
            }
            let _ = self.flush_to_disk_unlocked().await;
        }

        missing
    }

    async fn check_active_lease(&self, ctx: &PolicyContext) -> Option<LeaseGrant> {
        self.check_active_lease_with_constraints(ctx, None, false)
            .await
    }

    async fn check_active_lease_with_constraints(
        &self,
        ctx: &PolicyContext,
        min_created_exclusive_ms: Option<i64>,
        disallow_wildcard_resource: bool,
    ) -> Option<LeaseGrant> {
        if ctx.action == "host_exec" {
            return None;
        }
        let _guard = self.state_mutex.lock().await;
        let _file_lock = self.acquire_state_lock().await.ok().flatten();
        self.reload_from_disk().await;
        let now_ms = Utc::now().timestamp_millis();
        let ctx_task_id = ctx
            .metadata
            .get("task_id")
            .and_then(|value| value.as_str());
        let mut matched_idx = None;
        let mut matched_lease = None;
        {
            let leases = self.leases.read().await;
            for (idx, lease) in leases.iter().enumerate() {
                let kind = if lease.kind == LeaseKind::Ttl && lease.expires_at_ms == -1 {
                    LeaseKind::OneShot
                } else {
                    lease.kind
                };
                let valid = if lease.expires_at_ms == -1 {
                    kind == LeaseKind::OneShot
                } else {
                    lease.expires_at_ms > now_ms
                };
                let taint_epoch_ok = min_created_exclusive_ms
                    .is_none_or(|min_ms| lease.created_at_ms > min_ms);
                let wildcard_ok =
                    !disallow_wildcard_resource || lease.resource_pattern.trim() != "*";
                let task_ok = match kind {
                    LeaseKind::TaskScoped => {
                        ctx_task_id.is_some() && lease.task_id.as_deref() == ctx_task_id
                    }
                    LeaseKind::Ttl | LeaseKind::OneShot => {
                        lease.task_id.is_none() || lease.task_id.as_deref() == ctx_task_id
                    }
                };
                if valid
                    && taint_epoch_ok
                    && wildcard_ok
                    && task_ok
                    && lease.org_id == ctx.principal.org_id
                    && (lease.agent_id == "*" || lease.agent_id == ctx.principal.agent_id)
                    && Self::matches_pattern(&lease.action_pattern, &ctx.action)
                    && Self::matches_resource_and_evidence(
                        &lease.resource_pattern,
                        &ctx.target_resource,
                        &ctx.metadata,
                    )
                {
                    matched_idx = Some(idx);
                    matched_lease = Some(lease.clone());
                    break;
                }
            }
        }
        if let (Some(idx), Some(ref l)) = (matched_idx, &matched_lease) {
            let kind = if l.kind == LeaseKind::Ttl && l.expires_at_ms == -1 {
                LeaseKind::OneShot
            } else {
                l.kind
            };
            if kind == LeaseKind::OneShot {
                self.leases.write().await.remove(idx);
                let _ = self.flush_to_disk_unlocked().await;
            }
        }
        matched_lease
    }

    async fn check_verified_host_exec_lease(
        &self,
        ctx: &PolicyContext,
        ev_hash: &str,
    ) -> Option<LeaseGrant> {
        let _guard = self.state_mutex.lock().await;
        let _file_lock = self.acquire_state_lock().await.ok().flatten();
        self.reload_from_disk().await;
        let now_ms = Utc::now().timestamp_millis();
        let ctx_task_id = ctx
            .metadata
            .get("task_id")
            .and_then(|value| value.as_str());
        let expected_resource_pattern = format!("{}#sha256:{}", ctx.target_resource, ev_hash);
        let in_mem = self.in_memory_host_exec_leases.read().await;
        let mut matched_idx = None;
        let mut matched_lease = None;
        {
            let leases = self.leases.read().await;
            for (idx, lease) in leases.iter().enumerate() {
                let kind = if lease.kind == LeaseKind::Ttl && lease.expires_at_ms == -1 {
                    LeaseKind::OneShot
                } else {
                    lease.kind
                };
                let valid = if lease.expires_at_ms == -1 {
                    kind == LeaseKind::OneShot
                } else {
                    lease.expires_at_ms > now_ms
                };
                let task_ok = match kind {
                    LeaseKind::TaskScoped => {
                        ctx_task_id.is_some() && lease.task_id.as_deref() == ctx_task_id
                    }
                    LeaseKind::Ttl | LeaseKind::OneShot => {
                        lease.task_id.is_none() || lease.task_id.as_deref() == ctx_task_id
                    }
                };
                let mem_verified = in_mem.get(&lease.lease_id).is_some_and(|(o, a, r)| {
                    o == &lease.org_id && a == &lease.agent_id && r == &lease.resource_pattern
                });
                if valid
                    && task_ok
                    && mem_verified
                    && lease.org_id == ctx.principal.org_id
                    && lease.agent_id == ctx.principal.agent_id
                    && lease.action_pattern == "host_exec"
                    && lease.resource_pattern == expected_resource_pattern
                {
                    matched_idx = Some(idx);
                    matched_lease = Some(lease.clone());
                    break;
                }
            }
        }
        drop(in_mem);
        if let (Some(idx), Some(ref l)) = (matched_idx, &matched_lease) {
            let kind = if l.kind == LeaseKind::Ttl && l.expires_at_ms == -1 {
                LeaseKind::OneShot
            } else {
                l.kind
            };
            if kind == LeaseKind::OneShot {
                self.leases.write().await.remove(idx);
                self.in_memory_host_exec_leases
                    .write()
                    .await
                    .remove(&l.lease_id);
                let _ = self.flush_to_disk_unlocked().await;
            }
        }
        matched_lease
    }

    fn is_loopback_or_link_local_target(target: &str) -> bool {
        let trimmed = target.trim().to_ascii_lowercase();
        let host = if trimmed.starts_with('[') {
            trimmed
                .trim_start_matches('[')
                .split(']')
                .next()
                .unwrap_or("")
        } else if trimmed.matches(':').count() == 1 {
            trimmed.split(':').next().unwrap_or("")
        } else {
            trimmed.as_str()
        };
        let host = host.trim_end_matches('.');
        host == "localhost"
            || host == "127.0.0.1"
            || host == "::1"
            || host == "::"
            || host == "0.0.0.0"
            || host == "169.254.169.254"
            || host.starts_with("127.")
            || host.starts_with("169.254.")
            || host.contains("::ffff:127.")
            || host.ends_with(".localhost")
    }

    pub async fn record_untrusted_taint(
        &self,
        org_id: &str,
        agent_id: &str,
        session_id: Option<&str>,
        entry: TaintSourceEntry,
        ttl_secs: i64,
    ) -> anyhow::Result<SessionTaintRecord> {
        let _guard = self.state_mutex.lock().await;
        let _file_lock = self.acquire_state_lock().await?;
        self.reload_from_disk().await;
        let now_ms = Utc::now().timestamp_millis();
        let max_existing_lease_ms = self
            .leases
            .read()
            .await
            .iter()
            .filter(|l| {
                l.org_id == org_id
                    && (l.agent_id == "*" || l.agent_id == agent_id)
                    && (l.expires_at_ms > now_ms || l.expires_at_ms == -1)
            })
            .map(|l| l.created_at_ms)
            .max()
            .unwrap_or(0);
        let ttl_ms = ttl_secs.max(60) * 1000;
        let record = {
            let mut list = self.taints.write().await;
            list.retain(|t| t.expires_at_ms > now_ms);
            if let Some(existing) = list
                .iter_mut()
                .find(|t| t.org_id == org_id && t.agent_id == agent_id)
            {
                let updated_ms = now_ms
                    .max(existing.updated_at_ms)
                    .max(max_existing_lease_ms);
                existing.updated_at_ms = updated_ms;
                existing.expires_at_ms = now_ms + ttl_ms;
                if let Some(sid) = session_id {
                    if !sid.is_empty() {
                        existing.session_id = Some(sid.to_string());
                    }
                }
                let same_source = existing.sources.iter().any(|s| {
                    s.server_id == entry.server_id
                        && s.tool_name == entry.tool_name
                        && s.summary == entry.summary
                });
                if !same_source {
                    if existing.sources.len() >= 32 {
                        existing.sources.remove(0);
                    }
                    existing.sources.push(entry);
                }
                existing.clone()
            } else {
                let updated_ms = now_ms.max(max_existing_lease_ms);
                let rec = SessionTaintRecord {
                    org_id: org_id.to_string(),
                    agent_id: agent_id.to_string(),
                    session_id: session_id.filter(|s| !s.is_empty()).map(str::to_string),
                    first_tainted_at_ms: now_ms,
                    updated_at_ms: updated_ms,
                    expires_at_ms: now_ms + ttl_ms,
                    sources: vec![entry],
                };
                list.push(rec.clone());
                rec
            }
        };
        self.flush_to_disk_unlocked().await?;
        Ok(record)
    }

    pub async fn get_active_taint(
        &self,
        org_id: &str,
        agent_id: &str,
    ) -> Option<SessionTaintRecord> {
        let _guard = self.state_mutex.lock().await;
        let _file_lock = self.acquire_state_lock().await.ok().flatten();
        self.reload_from_disk().await;
        let now_ms = Utc::now().timestamp_millis();
        self.taints
            .read()
            .await
            .iter()
            .find(|t| t.org_id == org_id && t.agent_id == agent_id && t.expires_at_ms > now_ms)
            .cloned()
    }

    pub async fn list_active_taints(&self, org_id: Option<&str>) -> Vec<SessionTaintRecord> {
        let _guard = self.state_mutex.lock().await;
        let _file_lock = self.acquire_state_lock().await.ok().flatten();
        self.reload_from_disk().await;
        let now_ms = Utc::now().timestamp_millis();
        self.taints
            .read()
            .await
            .iter()
            .filter(|t| {
                t.expires_at_ms > now_ms && org_id.is_none_or(|o| o == "*" || t.org_id == o)
            })
            .cloned()
            .collect()
    }

    pub async fn clear_taint(&self, org_id: &str, agent_id: Option<&str>) -> anyhow::Result<usize> {
        let _guard = self.state_mutex.lock().await;
        let _file_lock = self.acquire_state_lock().await?;
        self.reload_from_disk().await;
        let removed = {
            let mut list = self.taints.write().await;
            let before = list.len();
            list.retain(|t| {
                let matches = (org_id == "*" || t.org_id == org_id)
                    && agent_id.is_none_or(|a| t.agent_id == a);
                !matches
            });
            before.saturating_sub(list.len())
        };
        if removed > 0 {
            self.flush_to_disk_unlocked().await?;
        }
        Ok(removed)
    }

    async fn record_tainted_escalation(
        &self,
        ctx: &PolicyContext,
        taint: &SessionTaintRecord,
        reason: String,
        suggested_lease_scope: String,
    ) -> anyhow::Result<PolicyDecision> {
        let mut tainted_meta = ctx.metadata.clone();
        if let Some(obj) = tainted_meta.as_object_mut() {
            let ev_entry = obj
                .entry("evidence".to_string())
                .or_insert_with(|| serde_json::json!({}));
            if let Some(ev_obj) = ev_entry.as_object_mut() {
                ev_obj.insert("session_taint".to_string(), serde_json::json!(taint));
            }
        }
        let tainted_ctx = PolicyContext {
            principal: ctx.principal.clone(),
            action: ctx.action.clone(),
            target_org_id: ctx.target_org_id.clone(),
            target_resource: ctx.target_resource.clone(),
            metadata: tainted_meta,
        };
        self.record_escalation(&tainted_ctx, reason, suggested_lease_scope)
            .await
    }

    async fn record_escalation(
        &self,
        ctx: &PolicyContext,
        reason: String,
        suggested_lease_scope: String,
    ) -> anyhow::Result<PolicyDecision> {
        let _guard = self.state_mutex.lock().await;
        let _file_lock = self.acquire_state_lock().await?;
        self.reload_from_disk().await;
        let now_ms = Utc::now().timestamp_millis();
        let _ = self.expire_stale_escalations_unlocked(now_ms).await;
        let escalation_id = format!("esc-{}", &Uuid::new_v4().to_string()[..8]);
        let ttl_ms = ctx
            .metadata
            .get("escalation_ttl_ms")
            .and_then(|v| v.as_i64())
            .unwrap_or(30 * 60 * 1000);
        let pending = PendingEscalation {
            escalation_id: escalation_id.clone(),
            org_id: ctx.principal.org_id.clone(),
            agent_id: ctx.principal.agent_id.clone(),
            action: ctx.action.clone(),
            target_resource: ctx.target_resource.clone(),
            reason: reason.clone(),
            suggested_lease_scope: suggested_lease_scope.clone(),
            status: EscalationStatus::Pending,
            created_at_ms: now_ms,
            task_id: ctx
                .metadata
                .get("task_id")
                .and_then(|value| value.as_str())
                .map(str::to_string),
            rationale: ctx
                .metadata
                .get("rationale")
                .or_else(|| ctx.metadata.get("reason"))
                .and_then(|v| v.as_str())
                .map(str::to_string),
            evidence_hash: ctx
                .metadata
                .get("evidence_hash")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            evidence: ctx.metadata.get("evidence").cloned(),
            expires_at_ms: Some(now_ms + ttl_ms),
            decided_by: None,
            decided_at_ms: None,
        };
        self.escalations.write().await.push(pending);
        self.flush_to_disk_unlocked().await?;

        Ok(PolicyDecision::Ask {
            escalation_id,
            reason,
            suggested_lease_scope,
        })
    }
}

#[async_trait]
impl PolicyEngine for AegisPolicyKernel {
    async fn evaluate(&self, ctx: &PolicyContext) -> anyhow::Result<PolicyDecision> {
        // 1. Multi-Tenant / Cross-Organization Boundary Check (R1):
        //    - Verified local workstation peer discovery & IPC (`workstation_peer_verified = true`) is allowed across directories/repos.
        //    - Cross-org CAS/KV reads among verified workstation peers escalate to `Ask` (or pass via an active session lease).
        //    - Unverified cross-tenant access is unconditionally Denied.
        if ctx.principal.org_id != ctx.target_org_id && !aos_core::ablated("tenant_gate") {
            let workstation_verified = ctx
                .metadata
                .get("workstation_peer_verified")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if workstation_verified {
                if let Some(lease) = self.check_active_lease(ctx).await {
                    return Ok(PolicyDecision::Allow {
                        matched_rule: format!("session_lease:{}", lease.lease_id),
                    });
                }
                if matches!(
                    ctx.action.as_str(),
                    "ipc_send"
                        | "ipc_request"
                        | "ipc_reply"
                        | "ipc_list_peers"
                        | "ipc_task_update"
                        | "ipc_task_get"
                        | "ipc_task_list"
                        | "ipc_wait"
                ) {
                    return Ok(PolicyDecision::Allow {
                        matched_rule: "aegis:workstation:cross_org_ipc_auto_allow".to_string(),
                    });
                }
                if matches!(ctx.action.as_str(), "org_artifact_fetch" | "org_kv_get") {
                    return self
                        .record_escalation(
                            ctx,
                            format!(
                                "Agent '{}/{}' requests cross-organization '{}' from '{}' ({})",
                                ctx.principal.org_id,
                                ctx.principal.agent_id,
                                ctx.action,
                                ctx.target_org_id,
                                ctx.target_resource
                            ),
                            format!(
                                "action={}, resource={}",
                                ctx.action, ctx.target_resource
                            ),
                        )
                        .await;
                }
            }
            return Ok(PolicyDecision::Deny {
                reason: format!(
                    "Cross-organization access denied: principal org '{}' != target org '{}'",
                    ctx.principal.org_id, ctx.target_org_id
                ),
            });
        }

        // 1b. Evaluate custom Cedar `forbid` rules (`forbid` always overrides `permit` and session leases):
        if let Some(forbid_rule) = self.cedar_policies.find_custom_forbid(ctx) {
            return Ok(PolicyDecision::Deny {
                reason: format!(
                    "Action '{}' on '{}' is forbidden by Cedar rule '{}'",
                    ctx.action, ctx.target_resource, forbid_rule.id
                ),
            });
        }

        // 2. Hard Red-Line Sensitive Host Resource Check & Loopback SSRF Gate:
        if ctx.action == "egress_unlisted_domain"
            && Self::is_loopback_or_link_local_target(&ctx.target_resource)
        {
            return Ok(PolicyDecision::Deny {
                reason: format!(
                    "Outbound egress escalation to loopback or link-local address '{}' is strictly forbidden by Aegis OS SSRF policy",
                    ctx.target_resource
                ),
            });
        }

        let redline_target = Self::strip_nested_test_tmpdir(&ctx.target_resource).to_lowercase();
        for forbidden in &self.forbidden_host_prefixes {
            let forbidden_folded = forbidden.to_lowercase();
            if redline_target.starts_with(&forbidden_folded)
                || redline_target.contains("/.ssh/")
                || redline_target.contains("/.aws/")
                || redline_target.contains("/.gnupg/")
                || redline_target.contains("/.kube/")
                || redline_target.ends_with("/.ssh")
                || redline_target.ends_with("/.aws")
                || redline_target.ends_with("/.gnupg")
                || redline_target.ends_with("/.kube")
            {
                return Ok(PolicyDecision::Deny {
                    reason: format!(
                        "Access to protected host path '{}' is strictly forbidden by Aegis OS Host Red-Line policy",
                        ctx.target_resource
                    ),
                });
            }
        }

        // Sandbox command hard red-lines must run BEFORE session-lease matching so even a wildcard
        // lease can never authorize privilege escalation (`sudo`/`doas`/`pkexec`/`su`) or credential scraping.
        if matches!(ctx.action.as_str(), "proc_exec" | "proc_manage") {
            if let Some(cmd) = ctx.metadata.get("command").and_then(|v| v.as_str()) {
                let trimmed = cmd.trim();
                let invokes_privesc = trimmed
                    .split([';', '|', '&', '\n', '(', '`'])
                    .map(|seg| seg.trim())
                    .any(|seg| {
                        let first = seg.split_whitespace().next().unwrap_or("");
                        let bin = first.rsplit('/').next().unwrap_or(first);
                        matches!(
                            bin.to_ascii_lowercase().as_str(),
                            "sudo" | "doas" | "pkexec" | "su"
                        )
                    });
                if invokes_privesc {
                    return Ok(PolicyDecision::Deny {
                        reason: "Privilege escalation ('sudo') is forbidden inside Aegis OS sandbox"
                            .to_string(),
                    });
                }
                let cmd_folded = trimmed.to_lowercase();
                if cmd_folded.contains("/.ssh")
                    || cmd_folded.contains("/.aws")
                    || cmd_folded.contains("/.gnupg")
                    || cmd_folded.contains("/.kube")
                {
                    return Ok(PolicyDecision::Deny {
                        reason: "Command attempts to access protected host credentials".to_string(),
                    });
                }
            }
        }

        // 2a. Hard Red-Line & Poisoning Guard for `fs_export_file` and `fs_import_file` (runs before
        // lease matching so even a wildcard lease can never export over git hooks/client configs or
        // import credentials / dotenv secrets).
        if ctx.action == "fs_export_file" {
            let res = Self::strip_nested_test_tmpdir(ctx.target_resource.as_str());
            let res_folded = res.to_lowercase();
            let poisoned = Self::is_commit_poisoning_path(res)
                || Self::PROTECTED_CLIENT_CONFIG_MARKERS
                    .iter()
                    .any(|marker| res_folded.contains(marker));
            if poisoned {
                return Ok(PolicyDecision::Deny {
                    reason: format!(
                        "Exporting to protected or build/hook-sensitive host path '{}' is strictly forbidden by Aegis OS policy",
                        ctx.target_resource
                    ),
                });
            }
        }
        if ctx.action == "fs_import_file" {
            let src_path = ctx
                .metadata
                .get("src_host_path")
                .and_then(|v| v.as_str())
                .unwrap_or(&ctx.target_resource);
            if Self::is_forbidden_import_source(&ctx.target_resource)
                || Self::is_forbidden_import_source(src_path)
            {
                return Ok(PolicyDecision::Deny {
                    reason: format!(
                        "Importing protected host credential or secret file '{}' is strictly forbidden by Aegis OS policy",
                        src_path
                    ),
                });
            }
            if ctx.metadata.get("import_to").and_then(|v| v.as_str()) == Some("shadow") {
                if let Some(dst_rel) = ctx.metadata.get("dst_path").and_then(|v| v.as_str()) {
                    let slash_norm = format!("/{}", dst_rel.trim_start_matches("./").trim_start_matches('/'))
                        .to_lowercase();
                    if Self::is_commit_poisoning_path(dst_rel)
                        || Self::PROTECTED_CLIENT_CONFIG_MARKERS
                            .iter()
                            .any(|marker| slash_norm.contains(marker))
                    {
                        return Ok(PolicyDecision::Deny {
                            reason: format!(
                                "Importing external file directly into sensitive workspace path '{}' is strictly forbidden by Aegis OS policy",
                                dst_rel
                            ),
                        });
                    }
                }
            }
        }

        // 2b. Commit-Time Poisoning & Integrity Guard: Even if an active general session lease exists,
        // committing modifications to git hooks, direnv, CI workflows, or build scripts (`build.rs`,
        // `Makefile`, `package.json`, `.cargo/config.toml`), OR passing `overwrite_binaries=true` /
        // `skip_verify=true` (when a host verification gate is configured) requires explicit human
        // escalation (`workspace_commit_sensitive`).
        if ctx.action == "workspace_commit" && !aos_core::ablated("commit_guard") {
            let mut sensitive_candidates: Vec<String> = Vec::new();
            let mut seen_sensitive: std::collections::BTreeSet<String> =
                std::collections::BTreeSet::new();
            if let Some(paths) = ctx.metadata.get("paths").and_then(|v| v.as_array()) {
                for p in paths.iter().filter_map(|x| x.as_str()) {
                    if Self::is_commit_poisoning_path(p) && seen_sensitive.insert(p.to_string()) {
                        sensitive_candidates.push(p.to_string());
                    }
                }
            }
            if ctx
                .metadata
                .get("overwrite_binaries")
                .and_then(|v| v.as_bool())
                == Some(true)
                && seen_sensitive.insert("flag:overwrite_binaries".to_string())
            {
                sensitive_candidates.push("flag:overwrite_binaries".to_string());
            }
            if ctx.metadata.get("skip_verify").and_then(|v| v.as_bool()) == Some(true)
                && ctx
                    .metadata
                    .get("has_configured_verify_cmd")
                    .and_then(|v| v.as_bool())
                    == Some(true)
                && seen_sensitive.insert("flag:skip_verify".to_string())
            {
                sensitive_candidates.push("flag:skip_verify".to_string());
            }
            let active_taint_for_commit = self
                .get_active_taint(&ctx.principal.org_id, &ctx.principal.agent_id)
                .await;
            let min_created_exclusive = active_taint_for_commit.as_ref().map(|t| t.updated_at_ms);
            let unleased_sensitive = if sensitive_candidates.is_empty() {
                Vec::new()
            } else {
                self.check_all_sensitive_targets_atomic(
                    ctx,
                    "workspace_commit_sensitive",
                    &sensitive_candidates,
                    min_created_exclusive,
                )
                .await
            };
            if !unleased_sensitive.is_empty() {
                let combined_resource = unleased_sensitive.join(", ");
                let mut sensitive_meta = ctx.metadata.clone();
                if let Some(obj) = sensitive_meta.as_object_mut() {
                    let ev_entry = obj
                        .entry("evidence".to_string())
                        .or_insert_with(|| serde_json::json!({}));
                    if let Some(ev_obj) = ev_entry.as_object_mut() {
                        ev_obj.insert(
                            "sensitive_targets".to_string(),
                            serde_json::json!(unleased_sensitive),
                        );
                    }
                }
                let batch_ctx = PolicyContext {
                    principal: ctx.principal.clone(),
                    action: "workspace_commit_sensitive".to_string(),
                    target_org_id: ctx.target_org_id.clone(),
                    target_resource: combined_resource.clone(),
                    metadata: sensitive_meta,
                };
                let reason = if unleased_sensitive.len() == 1
                    && unleased_sensitive[0] == "flag:overwrite_binaries"
                {
                    "Commit sets 'overwrite_binaries=true' to overwrite concurrently modified host binary assets (requires explicit human approval)".to_string()
                } else if unleased_sensitive.len() == 1
                    && unleased_sensitive[0] == "flag:skip_verify"
                {
                    "Commit sets 'skip_verify=true' to bypass the repository's configured pre-commit verification gate (requires explicit human approval)".to_string()
                } else {
                    format!(
                        "Commit touches sensitive build/hook target(s) '{}' (commit-time poisoning guard bypasses general session lease)",
                        combined_resource
                    )
                };
                if let Some(ref taint) = active_taint_for_commit {
                    return self
                        .record_tainted_escalation(
                            &batch_ctx,
                            taint,
                            format!("[UNTRUSTED MCP TAINT] {reason}"),
                            format!(
                                "action=workspace_commit_sensitive, resource={}",
                                combined_resource
                            ),
                        )
                        .await;
                }
                return self
                    .record_escalation(
                        &batch_ctx,
                        reason,
                        format!(
                            "action=workspace_commit_sensitive, resource={}",
                            combined_resource
                        ),
                    )
                    .await;
            }
        }

        // 2c. Sensitive Guard for `workspace_git`: poisoning paths, force-push, force-tag, and
        // `skip_verify` / `overwrite_binaries` (under `auto_commit_shadow`) require explicit
        // `workspace_git_sensitive` escalation and cannot ride on a general `workspace_git` lease.
        if ctx.action == "workspace_git" && !aos_core::ablated("commit_guard") {
            let mut sensitive_candidates: Vec<String> = Vec::new();
            let mut seen_sensitive_paths: std::collections::BTreeSet<String> =
                std::collections::BTreeSet::new();
            for key in ["paths", "shadow_paths"] {
                if let Some(arr) = ctx.metadata.get(key).and_then(|v| v.as_array()) {
                    for p in arr.iter().filter_map(|x| x.as_str()) {
                        if Self::is_commit_poisoning_path(p)
                            && seen_sensitive_paths.insert(p.to_string())
                        {
                            sensitive_candidates.push(p.to_string());
                        }
                    }
                }
            }
            for (meta_key, flag_res) in [
                ("force_push", "flag:force_push"),
                ("force_tag", "flag:force_tag"),
                ("overwrite_binaries", "flag:overwrite_binaries"),
            ] {
                if ctx.metadata.get(meta_key).and_then(|v| v.as_bool()) == Some(true)
                    && seen_sensitive_paths.insert(flag_res.to_string())
                {
                    sensitive_candidates.push(flag_res.to_string());
                }
            }
            if ctx.metadata.get("skip_verify").and_then(|v| v.as_bool()) == Some(true)
                && ctx
                    .metadata
                    .get("has_configured_verify_cmd")
                    .and_then(|v| v.as_bool())
                    == Some(true)
                && seen_sensitive_paths.insert("flag:skip_verify".to_string())
            {
                sensitive_candidates.push("flag:skip_verify".to_string());
            }
            let active_taint_for_git = self
                .get_active_taint(&ctx.principal.org_id, &ctx.principal.agent_id)
                .await;
            let min_created_exclusive = active_taint_for_git.as_ref().map(|t| t.updated_at_ms);
            let unleased_sensitive = if sensitive_candidates.is_empty() {
                Vec::new()
            } else {
                self.check_all_sensitive_targets_atomic(
                    ctx,
                    "workspace_git_sensitive",
                    &sensitive_candidates,
                    min_created_exclusive,
                )
                .await
            };
            if !unleased_sensitive.is_empty() {
                let combined_resource = unleased_sensitive.join(", ");
                let mut sensitive_meta = ctx.metadata.clone();
                if let Some(obj) = sensitive_meta.as_object_mut() {
                    let ev_entry = obj
                        .entry("evidence".to_string())
                        .or_insert_with(|| serde_json::json!({}));
                    if let Some(ev_obj) = ev_entry.as_object_mut() {
                        ev_obj.insert(
                            "git_target_resource".to_string(),
                            serde_json::json!(ctx.target_resource.clone()),
                        );
                        ev_obj.insert(
                            "sensitive_targets".to_string(),
                            serde_json::json!(unleased_sensitive),
                        );
                    }
                }
                let batch_ctx = PolicyContext {
                    principal: ctx.principal.clone(),
                    action: "workspace_git_sensitive".to_string(),
                    target_org_id: ctx.target_org_id.clone(),
                    target_resource: combined_resource.clone(),
                    metadata: sensitive_meta,
                };
                let reason = format!(
                    "[HIGH RISK] Git operation touches sensitive target(s)/flags '{}' (bypasses general session lease)",
                    combined_resource
                );
                let scope = format!("action=workspace_git_sensitive, resource={}", combined_resource);
                if let Some(ref taint) = active_taint_for_git {
                    return self
                        .record_tainted_escalation(
                            &batch_ctx,
                            taint,
                            format!("[UNTRUSTED MCP TAINT] {reason}"),
                            scope,
                        )
                        .await;
                }
                return self.record_escalation(&batch_ctx, reason, scope).await;
            }
        }

        // 2d. Package Manager Lifecycle Script Guard (`pkg_install_scripts`):
        // Even if a general `pkg_install` lease exists, `allow_scripts: true` runs arbitrary
        // build/postinstall code and always requires explicit `pkg_install_scripts` escalation.
        if ctx.action == "pkg_install"
            && ctx
                .metadata
                .get("allow_scripts")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        {
            let scripts_ctx = PolicyContext {
                principal: ctx.principal.clone(),
                action: "pkg_install_scripts".to_string(),
                target_org_id: ctx.target_org_id.clone(),
                target_resource: ctx.target_resource.clone(),
                metadata: ctx.metadata.clone(),
            };
            if let Some(lease) = self.check_active_lease(&scripts_ctx).await {
                return Ok(PolicyDecision::Allow {
                    matched_rule: format!("session_lease:{}", lease.lease_id),
                });
            }
            let manager = ctx
                .metadata
                .get("manager")
                .and_then(|v| v.as_str())
                .unwrap_or("pkg");
            return self
                .record_escalation(
                    &scripts_ctx,
                    format!(
                        "[HIGH RISK: LIFECYCLE SCRIPTS ENABLED] Agent '{}' requests '{}' package install on '{}' with lifecycle scripts enabled (bypasses general pkg_install lease)",
                        ctx.principal.agent_id, manager, ctx.target_resource
                    ),
                    format!(
                        "action=pkg_install_scripts, resource={}",
                        ctx.target_resource
                    ),
                )
                .await;
        }

        // 2e. Hard Guard for `host_exec` (Unsandboxed Host Sibling Execution):
        // Runs before generic leases and Cedar `permit` rules. Rejects wildcard leases, rejects
        // unverified on-disk leases, requires Enforced SessionBroker mode, and pins every lease
        // (even TTL) to the frozen bundle `evidence_hash`.
        if ctx.action == "host_exec" {
            if ctx
                .metadata
                .get("enforced_session_broker")
                .and_then(|v| v.as_bool())
                != Some(true)
            {
                return Ok(PolicyDecision::Deny {
                    reason: "host_exec is restricted to enforced SessionBroker sessions"
                        .to_string(),
                });
            }
            let Some(ev_hash) = ctx
                .metadata
                .get("evidence_hash")
                .and_then(|v| v.as_str())
                .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
            else {
                return Ok(PolicyDecision::Deny {
                    reason: "host_exec requires a 64-char SHA-256 frozen bundle evidence_hash"
                        .to_string(),
                });
            };
            if let Some(lease) = self.check_verified_host_exec_lease(ctx, ev_hash).await {
                return Ok(PolicyDecision::Allow {
                    matched_rule: format!("session_lease:{}", lease.lease_id),
                });
            }
            let summary = ctx
                .metadata
                .get("command_summary")
                .and_then(|v| v.as_str())
                .unwrap_or(&ctx.target_resource);
            return self
                .record_escalation(
                    ctx,
                    format!(
                        "[HIGH RISK: UNSANDBOXED HOST EXEC] Agent '{}' requests unsandboxed host execution '{}' (frozen bundle sha256: {}...)",
                        ctx.principal.agent_id,
                        summary,
                        &ev_hash[..12]
                    ),
                    format!(
                        "action=host_exec, resource={}#sha256:{}",
                        ctx.target_resource, ev_hash
                    ),
                )
                .await;
        }

        // 2f. Active Session Taint Guard (`UntrustedExternal` MCP Taint):
        // Once a session ingests untrusted external MCP data, pre-taint broad TTL leases (or custom
        // Cedar `permit` rules) cannot authorize host writes, Git/PR mutations, host file exports,
        // or unlisted egress domains without post-taint explicit human approval.
        if matches!(
            ctx.action.as_str(),
            "workspace_commit"
                | "workspace_commit_sensitive"
                | "workspace_git"
                | "workspace_git_sensitive"
                | "fs_export_file"
                | "egress_unlisted_domain"
                | "github_pr_create"
                | "github_pr_merge"
                | "github_comment_create"
                | "github_ci_rerun"
        ) {
            if let Some(taint) = self
                .get_active_taint(&ctx.principal.org_id, &ctx.principal.agent_id)
                .await
            {
                let disallow_wildcard = ctx.action == "egress_unlisted_domain";
                if let Some(lease) = self
                    .check_active_lease_with_constraints(
                        ctx,
                        Some(taint.updated_at_ms),
                        disallow_wildcard,
                    )
                    .await
                {
                    return Ok(PolicyDecision::Allow {
                        matched_rule: format!("session_lease:{}", lease.lease_id),
                    });
                }
                let src_summary = taint
                    .sources
                    .last()
                    .map(|s| format!("{}:{}", s.server_id, s.tool_name))
                    .unwrap_or_else(|| "external_mcp".to_string());
                let (reason, scope) = match ctx.action.as_str() {
                    "workspace_commit" | "workspace_commit_sensitive" => (
                        format!(
                            "[UNTRUSTED MCP TAINT] Session ingested untrusted external data ({}); committing shadow changes to '{}' requires explicit human approval",
                            src_summary, ctx.target_resource
                        ),
                        format!("action={}, resource={}", ctx.action, if ctx.action == "workspace_commit" { "*" } else { &ctx.target_resource }),
                    ),
                    "egress_unlisted_domain" => (
                        format!(
                            "[UNTRUSTED MCP TAINT] Session ingested untrusted external data ({}); outbound connection to unlisted domain '{}' requires explicit domain-pinned human approval",
                            src_summary, ctx.target_resource
                        ),
                        format!("action=egress_unlisted_domain, resource={}", ctx.target_resource),
                    ),
                    other => (
                        format!(
                            "[UNTRUSTED MCP TAINT] Session ingested untrusted external data ({}); high-impact boundary action '{}' on '{}' requires post-taint human approval",
                            src_summary, other, ctx.target_resource
                        ),
                        format!("action={}, resource={}", other, ctx.target_resource),
                    ),
                };
                return self
                    .record_tainted_escalation(ctx, &taint, reason, scope)
                    .await;
            }
        }

        // 3. Check if an active Session Lease already covers this action + resource:
        if let Some(lease) = self.check_active_lease(ctx).await {
            return Ok(PolicyDecision::Allow {
                matched_rule: format!("session_lease:{}", lease.lease_id),
            });
        }

        // 3b. Zero-prompt workspace switching strictly within the session's umbrella root:
        if ctx.action == "workspace_switch"
            && ctx
                .metadata
                .get("within_umbrella")
                .and_then(|v| v.as_bool())
                == Some(true)
        {
            return Ok(PolicyDecision::Allow {
                matched_rule: "aegis:umbrella:child_workspace_switch_allow".to_string(),
            });
        }

        // 3c. Cross-repo / unconfigured-origin GitHub read gate (runs before Cedar auto-permit):
        if matches!(
            ctx.action.as_str(),
            "github_ci_inspect" | "github_pr_inspect" | "github_issue_inspect"
        ) && ctx
            .metadata
            .get("cross_repo")
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            let origin_label = ctx
                .metadata
                .get("origin_repo")
                .and_then(|v| v.as_str())
                .unwrap_or("<no GitHub origin>");
            return self
                .record_escalation(
                    ctx,
                    format!(
                        "Agent '{}' requests cross-repo GitHub inspect '{}' on '{}' (workspace origin: {})",
                        ctx.principal.agent_id, ctx.action, ctx.target_resource, origin_label
                    ),
                    format!("action={}, resource={}", ctx.action, ctx.target_resource),
                )
                .await;
        }

        // 4. Evaluate Declarative Cedar `permit` Rules (`policy/default.cedar` + custom Cedar policies):
        if let Some(permit_rule) = self.cedar_policies.find_permit(ctx) {
            return Ok(PolicyDecision::Allow {
                matched_rule: permit_rule.id.clone(),
            });
        }

        // 5. Yellow-Zone Boundary Crossing Actions -> Record Escalation & Return Ask:
        match ctx.action.as_str() {
            "workspace_commit" => {
                let files_desc = ctx
                    .metadata
                    .get("paths")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        let names: Vec<&str> = arr.iter().filter_map(|x| x.as_str()).collect();
                        if names.is_empty() {
                            String::new()
                        } else if names.len() <= 6 {
                            format!(" ({} file(s): {})", names.len(), names.join(", "))
                        } else {
                            format!(
                                " ({} file(s): {}, +{} more)",
                                names.len(),
                                names[..6].join(", "),
                                names.len() - 6
                            )
                        }
                    })
                    .unwrap_or_default();
                let host_label = ctx
                    .metadata
                    .get("host_root")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&ctx.target_resource);
                self.record_escalation(
                    ctx,
                    format!(
                        "Agent '{}' requests to commit Copy-on-Write workspace changes{} back to host directory '{}'",
                        ctx.principal.agent_id, files_desc, host_label
                    ),
                    "action=workspace_commit, resource=*".to_string(),
                )
                .await
            }

            "fs_export_file" => {
                let src_label = ctx
                    .metadata
                    .get("src_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("artifact");
                let size_bytes = ctx
                    .metadata
                    .get("size_bytes")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let content_type = ctx
                    .metadata
                    .get("content_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("application/octet-stream");
                self.record_escalation(
                    ctx,
                    format!(
                        "Agent '{}' requests to export file '{}' ({} bytes, {}) to host path '{}'",
                        ctx.principal.agent_id,
                        src_label,
                        size_bytes,
                        content_type,
                        ctx.target_resource
                    ),
                    format!("action=fs_export_file, resource={}", ctx.target_resource),
                )
                .await
            }

            "workspace_switch" => {
                self.record_escalation(
                    ctx,
                    format!(
                        "Agent '{}' requests to switch active CoW workspace outside initial scope to '{}'",
                        ctx.principal.agent_id, ctx.target_resource
                    ),
                    format!("action=workspace_switch, resource={}", ctx.target_resource),
                )
                .await
            }

            "workspace_git" => {
                let host_root = ctx
                    .metadata
                    .get("host_root")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&ctx.target_resource);
                let commit_message = ctx
                    .metadata
                    .get("commit_message")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty());
                let paths_count = ctx
                    .metadata
                    .get("paths")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                let tag = ctx
                    .metadata
                    .get("tag")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty());
                let force_tag = ctx
                    .metadata
                    .get("force_tag")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let push = ctx
                    .metadata
                    .get("push")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let remote = ctx.metadata.get("remote").and_then(|v| v.as_str());
                let branch = ctx.metadata.get("branch").and_then(|v| v.as_str());

                let auto_commit_shadow = ctx
                    .metadata
                    .get("auto_commit_shadow")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let shadow_count = ctx
                    .metadata
                    .get("shadow_paths")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                let checkout_branch = ctx
                    .metadata
                    .get("checkout_branch")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty());
                let create_branch = ctx
                    .metadata
                    .get("create_branch")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let sync_op = ctx
                    .metadata
                    .get("sync")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty());
                let force_push = ctx
                    .metadata
                    .get("force_push")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let has_verify = ctx
                    .metadata
                    .get("verify_cmd")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| !s.trim().is_empty())
                    || ctx
                        .metadata
                        .get("has_configured_verify_cmd")
                        .and_then(|v| v.as_bool())
                        == Some(true);

                let mut ops = Vec::new();
                if auto_commit_shadow {
                    let verify_tag = if has_verify { " + verify" } else { "" };
                    ops.push(format!(
                        "land {} shadow file(s){}",
                        shadow_count.max(paths_count),
                        verify_tag
                    ));
                }
                if let Some(cb) = checkout_branch {
                    if create_branch {
                        ops.push(format!("create & switch branch '{}'", cb));
                    } else {
                        ops.push(format!("switch branch '{}'", cb));
                    }
                }
                if let Some(s) = sync_op {
                    ops.push(format!("sync '{}' ({})", remote.unwrap_or("origin"), s));
                }
                if let Some(msg) = commit_message {
                    let first_line = msg.lines().next().unwrap_or(msg).trim();
                    let headline: String = first_line.chars().take(72).collect();
                    ops.push(format!("commit {} file(s) (\"{}\")", paths_count, headline));
                }
                if let Some(t) = tag {
                    if force_tag {
                        ops.push(format!("force-tag '{}'", t));
                    } else {
                        ops.push(format!("tag '{}'", t));
                    }
                }
                if push {
                    let push_verb = if force_push {
                        "FORCE-PUSH (with-lease)"
                    } else {
                        "push"
                    };
                    ops.push(format!(
                        "{} to '{}' (branch: {}, tag: {})",
                        push_verb,
                        remote.unwrap_or("origin"),
                        branch.filter(|s| !s.is_empty()).unwrap_or("-"),
                        tag.unwrap_or("-")
                    ));
                }
                let summary = if ops.is_empty() {
                    "host git operation".to_string()
                } else {
                    ops.join(", ")
                };

                self.record_escalation(
                    ctx,
                    format!(
                        "Agent '{}' requests host Git operation on '{}': {}",
                        ctx.principal.agent_id, host_root, summary
                    ),
                    format!("action=workspace_git, resource={}", ctx.target_resource),
                )
                .await
            }

            "fs_import_file" => {
                let src_label = ctx
                    .metadata
                    .get("src_host_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&ctx.target_resource);
                let size_bytes = ctx
                    .metadata
                    .get("size_bytes")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let import_to = ctx
                    .metadata
                    .get("import_to")
                    .and_then(|v| v.as_str())
                    .unwrap_or("imports");
                let dst_label = ctx
                    .metadata
                    .get("dst_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("imported_file");
                self.record_escalation(
                    ctx,
                    format!(
                        "Agent '{}' requests to import host file '{}' ({} bytes) into '{}' ('{}')",
                        ctx.principal.agent_id, src_label, size_bytes, import_to, dst_label
                    ),
                    format!("action=fs_import_file, resource={}", ctx.target_resource),
                )
                .await
            }

            "github_ci_rerun" => {
                let repo = ctx
                    .metadata
                    .get("repo")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&ctx.target_resource);
                let run_id = ctx
                    .metadata
                    .get("run_id")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let failed_only = ctx
                    .metadata
                    .get("failed_only")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let job_id = ctx.metadata.get("job_id").and_then(|v| v.as_u64());
                let scope_desc = if let Some(j) = job_id {
                    format!("job {}", j)
                } else if failed_only {
                    "failed jobs only".to_string()
                } else {
                    "entire workflow run".to_string()
                };
                self.record_escalation(
                    ctx,
                    format!(
                        "Agent '{}' requests to rerun GitHub Actions run {} ({}) on '{}'",
                        ctx.principal.agent_id, run_id, scope_desc, repo
                    ),
                    format!("action=github_ci_rerun, resource={}", ctx.target_resource),
                )
                .await
            }

            "github_pr_create" => {
                let repo = ctx
                    .metadata
                    .get("repo")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&ctx.target_resource);
                let head = ctx
                    .metadata
                    .get("head")
                    .and_then(|v| v.as_str())
                    .unwrap_or("<current>");
                let base = ctx
                    .metadata
                    .get("base")
                    .and_then(|v| v.as_str())
                    .unwrap_or("<default>");
                let title = ctx
                    .metadata
                    .get("title")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let draft = ctx
                    .metadata
                    .get("draft")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                self.record_escalation(
                    ctx,
                    format!(
                        "Agent '{}' requests to create {}GitHub PR on '{}' ({} -> {}): \"{}\"",
                        ctx.principal.agent_id,
                        if draft { "draft " } else { "" },
                        repo,
                        head,
                        base,
                        title.chars().take(72).collect::<String>()
                    ),
                    format!("action=github_pr_create, resource={}", ctx.target_resource),
                )
                .await
            }

            "github_comment_create" => {
                let repo = ctx
                    .metadata
                    .get("repo")
                    .and_then(|v| v.as_str())
                    .unwrap_or("<repo>");
                let number = ctx
                    .metadata
                    .get("number")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let body_preview: String = ctx
                    .metadata
                    .get("body")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .chars()
                    .take(72)
                    .collect();
                self.record_escalation(
                    ctx,
                    format!(
                        "Agent '{}' requests to post GitHub comment on '{}#{}': \"{}\"",
                        ctx.principal.agent_id, repo, number, body_preview
                    ),
                    format!("action=github_comment_create, resource={}", ctx.target_resource),
                )
                .await
            }

            "github_pr_merge" => {
                let repo = ctx
                    .metadata
                    .get("repo")
                    .and_then(|v| v.as_str())
                    .unwrap_or("<repo>");
                let pr_number = ctx
                    .metadata
                    .get("pr_number")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let method = ctx
                    .metadata
                    .get("method")
                    .and_then(|v| v.as_str())
                    .unwrap_or("squash");
                let delete_branch = ctx
                    .metadata
                    .get("delete_branch")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                self.record_escalation(
                    ctx,
                    format!(
                        "[DESTRUCTIVE] Agent '{}' requests to {}-merge GitHub PR '{}#{}' (delete_branch={})",
                        ctx.principal.agent_id, method, repo, pr_number, delete_branch
                    ),
                    format!("action=github_pr_merge, resource={}", ctx.target_resource),
                )
                .await
            }

            "pkg_install" => {
                let manager = ctx
                    .metadata
                    .get("manager")
                    .and_then(|v| v.as_str())
                    .unwrap_or("pkg");
                let offline = ctx
                    .metadata
                    .get("offline")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let pkgs: String = ctx
                    .metadata
                    .get("packages")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        let items: Vec<&str> = arr.iter().filter_map(|x| x.as_str()).collect();
                        if items.is_empty() {
                            "<manifest dependencies>".to_string()
                        } else {
                            items.join(", ")
                        }
                    })
                    .unwrap_or_else(|| "<manifest dependencies>".to_string());
                self.record_escalation(
                    ctx,
                    format!(
                        "Agent '{}' requests {} package install ({}) [{} , offline={}]",
                        ctx.principal.agent_id, manager, ctx.target_resource, pkgs, offline
                    ),
                    format!("action=pkg_install, resource={}", ctx.target_resource),
                )
                .await
            }

            "egress_unlisted_domain" => {
                self.record_escalation(
                    ctx,
                    format!(
                        "Agent '{}' requests outbound network access to unlisted domain '{}'",
                        ctx.principal.agent_id, ctx.target_resource
                    ),
                    format!("action=egress_unlisted_domain, resource={}", ctx.target_resource),
                )
                .await
            }

            "mcp_mount_server" => {
                self.record_escalation(
                    ctx,
                    format!(
                        "Agent '{}' requests to mount dynamic child MCP server '{}'",
                        ctx.principal.agent_id, ctx.target_resource
                    ),
                    format!("action=mcp_mount_server, resource={}", ctx.target_resource),
                )
                .await
            }

            other => {
                if let Some(permit_rule) = self.cedar_policies.find_permit(ctx) {
                    return Ok(PolicyDecision::Allow {
                        matched_rule: permit_rule.id.clone(),
                    });
                }
                self.record_escalation(
                    ctx,
                    format!("Boundary syscall '{}' requires explicit lease", other),
                    format!("action={}, resource=*", other),
                )
                .await
            }
        }
    }

    async fn grant_lease(&self, mut lease: LeaseGrant) -> anyhow::Result<LeaseGrant> {
        if lease.action_pattern == "host_exec" || lease.action_pattern.starts_with("host_exec") {
            anyhow::bail!(
                "Direct grant_lease for 'host_exec' is forbidden; approve a SHA-256 pinned escalation instead"
            );
        }
        if lease.created_at_ms <= 0 {
            lease.created_at_ms = Utc::now().timestamp_millis();
        }
        let _guard = self.state_mutex.lock().await;
        let _file_lock = self.acquire_state_lock().await?;
        self.reload_from_disk().await;
        self.leases.write().await.push(lease.clone());
        self.flush_to_disk_unlocked().await?;
        Ok(lease)
    }

    async fn list_leases(
        &self,
        org_id: &str,
        agent_id: Option<&str>,
    ) -> anyhow::Result<Vec<LeaseGrant>> {
        let _guard = self.state_mutex.lock().await;
        let _file_lock = self.acquire_state_lock().await.ok().flatten();
        self.reload_from_disk().await;
        let now_ms = Utc::now().timestamp_millis();
        let leases = self.leases.read().await;
        Ok(leases
            .iter()
            .filter(|l| {
                (org_id == "*" || l.org_id == org_id)
                    && (l.expires_at_ms > now_ms || l.expires_at_ms == -1)
                    && agent_id.is_none_or(|a| l.agent_id == "*" || l.agent_id == a)
            })
            .cloned()
            .collect())
    }

    async fn list_escalations(&self, org_id: &str) -> anyhow::Result<Vec<PendingEscalation>> {
        let _guard = self.state_mutex.lock().await;
        let _file_lock = self.acquire_state_lock().await.ok().flatten();
        self.reload_from_disk().await;
        let now_ms = Utc::now().timestamp_millis();
        if self.expire_stale_escalations_unlocked(now_ms).await {
            let _ = self.flush_to_disk_unlocked().await;
        }
        let esc = self.escalations.read().await;
        Ok(esc
            .iter()
            .filter(|e| org_id == "*" || e.org_id == org_id)
            .cloned()
            .collect())
    }

    async fn approve_escalation(
        &self,
        escalation_id: &str,
        ttl_secs: i64,
        approved_by: &str,
    ) -> anyhow::Result<LeaseGrant> {
        let _guard = self.state_mutex.lock().await;
        let _file_lock = self.acquire_state_lock().await?;
        self.reload_from_disk().await;
        let now_ms = Utc::now().timestamp_millis();
        let _ = self.expire_stale_escalations_unlocked(now_ms).await;
        let target = {
            let mut list = self.escalations.write().await;
            let item = list
                .iter_mut()
                .find(|e| e.escalation_id == escalation_id)
                .with_context(|| format!("Escalation '{}' not found", escalation_id))?;
            if item.status != EscalationStatus::Pending {
                let status = item.status.clone();
                drop(list);
                let _ = self.flush_to_disk_unlocked().await;
                anyhow::bail!(
                    "Escalation '{}' is not pending (status: {:?}) and cannot be approved again",
                    escalation_id,
                    status
                );
            }
            item.status = EscalationStatus::Approved;
            item.decided_by = Some(approved_by.to_string());
            item.decided_at_ms = Some(now_ms);
            item.clone()
        };

        let is_oneshot = ttl_secs <= 0;
        let active_taint_ms = self
            .taints
            .read()
            .await
            .iter()
            .filter(|t| {
                t.org_id == target.org_id
                    && t.agent_id == target.agent_id
                    && t.expires_at_ms > now_ms
            })
            .map(|t| t.updated_at_ms)
            .max();
        let lease_created_at_ms = match active_taint_ms {
            Some(t_ms) => now_ms.max(t_ms.saturating_add(1)),
            None => now_ms,
        };
        let expires_at_ms = if is_oneshot {
            now_ms + 900_000
        } else {
            now_ms + (ttl_secs * 1000)
        };
        let base_resource_pattern = if matches!(
            target.action.as_str(),
            "workspace_commit_sensitive"
                | "workspace_git_sensitive"
                | "fs_export_file"
                | "fs_import_file"
                | "workspace_switch"
                | "workspace_git"
                | "github_ci_rerun"
                | "github_pr_create"
                | "github_comment_create"
                | "github_pr_merge"
                | "github_ci_inspect"
                | "github_pr_inspect"
                | "github_issue_inspect"
                | "pkg_install"
                | "pkg_install_scripts"
                | "host_exec"
                | "egress_unlisted_domain"
                | "mcp_mount_server"
                | "org_artifact_fetch"
                | "org_kv_get"
        ) || target.action.starts_with("memory.")
        {
            target.target_resource.clone()
        } else {
            "*".to_string()
        };
        let resource_pattern = if target.action == "host_exec" {
            let ev_hash = target
                .evidence_hash
                .as_deref()
                .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
                .context("host_exec escalation missing 64-char SHA-256 evidence_hash")?;
            format!("{}#sha256:{}", base_resource_pattern, ev_hash)
        } else if is_oneshot {
            if let Some(ref ev_hash) = target.evidence_hash {
                if base_resource_pattern == "*" {
                    format!("sha256:{}", ev_hash)
                } else {
                    format!("{}#sha256:{}", base_resource_pattern, ev_hash)
                }
            } else {
                base_resource_pattern
            }
        } else {
            base_resource_pattern
        };
        let task_id = target.task_id.clone();
        // One-shot must win over task scoping: an agent inside an active A2A task would
        // otherwise turn "Approve Once" into a replayable TaskScoped lease.
        let kind = if is_oneshot {
            LeaseKind::OneShot
        } else if task_id.is_some() {
            LeaseKind::TaskScoped
        } else {
            LeaseKind::Ttl
        };
        let lease = LeaseGrant {
            lease_id: format!("lease-{}", &Uuid::new_v4().to_string()[..8]),
            org_id: target.org_id.clone(),
            agent_id: target.agent_id.clone(),
            action_pattern: target.action.clone(),
            resource_pattern,
            created_at_ms: lease_created_at_ms,
            expires_at_ms,
            granted_by: approved_by.to_string(),
            kind,
            task_id: task_id.clone(),
        };

        let mut primary_lease = lease.clone();
        {
            let mut leases = self.leases.write().await;
            // When approving a sensitive commit or git escalation (which may batch multiple
            // targets like `"Cargo.toml, flag:force_push"`), split per-target sensitive leases and
            // mint the matching companion base lease in a single approval click.
            if matches!(
                target.action.as_str(),
                "workspace_commit_sensitive" | "workspace_git_sensitive"
            ) {
                let parts: Vec<String> = target
                    .evidence
                    .as_ref()
                    .and_then(|ev| ev.get("sensitive_targets"))
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|item| item.as_str().map(str::to_string))
                            .filter(|s| !s.is_empty())
                            .collect()
                    })
                    .unwrap_or_else(|| vec![target.target_resource.clone()]);
                if parts.len() > 1 {
                    for (idx, part) in parts.into_iter().enumerate() {
                        let part_pattern = if is_oneshot {
                            if let Some(ref ev_hash) = target.evidence_hash {
                                format!("{}#sha256:{}", part, ev_hash)
                            } else {
                                part
                            }
                        } else {
                            part
                        };
                        let part_lease = LeaseGrant {
                            lease_id: format!("lease-{}", &Uuid::new_v4().to_string()[..8]),
                            org_id: target.org_id.clone(),
                            agent_id: target.agent_id.clone(),
                            action_pattern: target.action.clone(),
                            resource_pattern: part_pattern,
                            created_at_ms: lease_created_at_ms,
                            expires_at_ms,
                            granted_by: approved_by.to_string(),
                            kind,
                            task_id: task_id.clone(),
                        };
                        if idx == 0 {
                            primary_lease = part_lease.clone();
                        }
                        leases.push(part_lease);
                    }
                } else {
                    // One combined target (even if its filename contains `, `) is already represented by `lease`.
                    leases.push(lease.clone());
                }
                let (companion_action, companion_base) = if target.action == "workspace_commit_sensitive" {
                    ("workspace_commit".to_string(), "*".to_string())
                } else {
                    let git_res = target
                        .evidence
                        .as_ref()
                        .and_then(|ev| ev.get("git_target_resource"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("*")
                        .to_string();
                    ("workspace_git".to_string(), git_res)
                };
                let companion_resource = if is_oneshot {
                    if let Some(ref ev_hash) = target.evidence_hash {
                        if companion_base == "*" {
                            format!("sha256:{}", ev_hash)
                        } else {
                            format!("{}#sha256:{}", companion_base, ev_hash)
                        }
                    } else {
                        companion_base
                    }
                } else {
                    companion_base
                };
                leases.push(LeaseGrant {
                    lease_id: format!("lease-{}", &Uuid::new_v4().to_string()[..8]),
                    org_id: target.org_id,
                    agent_id: target.agent_id,
                    action_pattern: companion_action,
                    resource_pattern: companion_resource,
                    created_at_ms: lease_created_at_ms,
                    expires_at_ms,
                    granted_by: approved_by.to_string(),
                    kind,
                    task_id,
                });
            } else if target.action == "pkg_install_scripts" {
                leases.push(lease.clone());
                leases.push(LeaseGrant {
                    lease_id: format!("lease-{}", &Uuid::new_v4().to_string()[..8]),
                    org_id: target.org_id,
                    agent_id: target.agent_id,
                    action_pattern: "pkg_install".to_string(),
                    resource_pattern: lease.resource_pattern.clone(),
                    created_at_ms: lease_created_at_ms,
                    expires_at_ms,
                    granted_by: approved_by.to_string(),
                    kind,
                    task_id,
                });
            } else {
                leases.push(lease.clone());
            }
        }
        if target.action == "host_exec" {
            self.in_memory_host_exec_leases.write().await.insert(
                primary_lease.lease_id.clone(),
                (
                    primary_lease.org_id.clone(),
                    primary_lease.agent_id.clone(),
                    primary_lease.resource_pattern.clone(),
                ),
            );
        }
        self.flush_to_disk_unlocked().await?;
        Ok(primary_lease)
    }

    async fn revoke_leases_for_task(&self, task_id: &str) -> anyhow::Result<usize> {
        let _guard = self.state_mutex.lock().await;
        let _file_lock = self.acquire_state_lock().await?;
        self.reload_from_disk().await;
        let (removed_ids, removed) = {
            let mut leases = self.leases.write().await;
            let before = leases.len();
            let removed_ids: Vec<String> = leases
                .iter()
                .filter(|lease| lease.task_id.as_deref() == Some(task_id))
                .map(|lease| lease.lease_id.clone())
                .collect();
            leases.retain(|lease| lease.task_id.as_deref() != Some(task_id));
            (removed_ids, before - leases.len())
        };
        if !removed_ids.is_empty() {
            let mut in_mem = self.in_memory_host_exec_leases.write().await;
            for id in &removed_ids {
                in_mem.remove(id);
            }
        }
        if removed > 0 {
            self.flush_to_disk_unlocked().await?;
        }
        Ok(removed)
    }

    async fn revoke_lease(&self, lease_id: &str) -> anyhow::Result<bool> {
        let _guard = self.state_mutex.lock().await;
        let _file_lock = self.acquire_state_lock().await?;
        self.reload_from_disk().await;
        self.in_memory_host_exec_leases
            .write()
            .await
            .remove(lease_id);
        let removed = {
            let mut leases = self.leases.write().await;
            let before = leases.len();
            leases.retain(|lease| lease.lease_id != lease_id);
            before > leases.len()
        };
        if removed {
            self.flush_to_disk_unlocked().await?;
        }
        Ok(removed)
    }

    async fn deny_escalation(
        &self,
        escalation_id: &str,
        denied_by: &str,
    ) -> anyhow::Result<PendingEscalation> {
        let _guard = self.state_mutex.lock().await;
        let _file_lock = self.acquire_state_lock().await?;
        self.reload_from_disk().await;
        let now_ms = Utc::now().timestamp_millis();
        let _ = self.expire_stale_escalations_unlocked(now_ms).await;
        let target = {
            let mut list = self.escalations.write().await;
            let item = list
                .iter_mut()
                .find(|e| e.escalation_id == escalation_id)
                .with_context(|| format!("Escalation '{}' not found", escalation_id))?;
            if item.status != EscalationStatus::Pending {
                anyhow::bail!(
                    "Escalation '{}' is not pending (status: {:?}) and cannot be denied",
                    escalation_id,
                    item.status
                );
            }
            item.status = EscalationStatus::Denied;
            item.decided_by = Some(denied_by.to_string());
            item.decided_at_ms = Some(now_ms);
            item.clone()
        };
        self.flush_to_disk_unlocked().await?;
        Ok(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_core::AgentIdentity;
    use serde_json::json;

    #[test]
    fn commit_guard_covers_code_executing_config() {
        for p in [
            ".husky/pre-commit",
            "web/.husky/pre-push",
            ".pre-commit-config.yaml",
            "pyproject.toml",
            "tests/conftest.py",
            "crates/x/Cargo.toml",
            "justfile",
            ".gitattributes",
        ] {
            assert!(AegisPolicyKernel::is_commit_poisoning_path(p), "{p}");
        }
        for p in ["src/main.rs", "README.md", "docs/husky.md", "Cargo.lock"] {
            assert!(!AegisPolicyKernel::is_commit_poisoning_path(p), "{p}");
        }
    }

    #[tokio::test]
    async fn test_zero_prompt_for_sandbox_and_intra_org_ipc() {
        let kernel = AegisPolicyKernel::new();
        let agent = AgentIdentity::new("acme", "coder-1", "Senior Engineer");

        let fs_ctx = PolicyContext {
            principal: agent.clone(),
            action: "fs_write".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "/workspace/src/main.rs".to_string(),
            metadata: json!({}),
        };
        assert!(matches!(
            kernel.evaluate(&fs_ctx).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));

        let ipc_ctx = PolicyContext {
            principal: agent.clone(),
            action: "ipc_send".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "agent:researcher-1".to_string(),
            metadata: json!({}),
        };
        assert!(matches!(
            kernel.evaluate(&ipc_ctx).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));

        let cross_org_ctx = PolicyContext {
            principal: agent.clone(),
            action: "ipc_send".to_string(),
            target_org_id: "other-org".to_string(),
            target_resource: "agent:spy".to_string(),
            metadata: json!({}),
        };
        assert!(matches!(
            kernel.evaluate(&cross_org_ctx).await.unwrap(),
            PolicyDecision::Deny { .. }
        ));
    }

    #[tokio::test]
    async fn revoking_task_leases_removes_only_bound_leases() {
        let kernel = AegisPolicyKernel::new();
        let now = Utc::now().timestamp_millis() + 60_000;
        for (id, task_id, kind) in [
            ("lease-1", Some("task-1"), LeaseKind::TaskScoped),
            ("lease-2", Some("task-2"), LeaseKind::TaskScoped),
            ("lease-3", None, LeaseKind::Ttl),
        ] {
            kernel
                .grant_lease(LeaseGrant {
                    lease_id: id.to_string(),
                    org_id: "acme".to_string(),
                    agent_id: "coder".to_string(),
                    action_pattern: "workspace_commit".to_string(),
                    resource_pattern: "*".to_string(),
                    created_at_ms: 0,
                    expires_at_ms: now,
                    granted_by: "user".to_string(),
                    kind,
                    task_id: task_id.map(str::to_string),
                })
                .await
                .unwrap();
        }
        assert_eq!(kernel.revoke_leases_for_task("task-1").await.unwrap(), 1);
        let leases = kernel.list_leases("acme", None).await.unwrap();
        assert_eq!(leases.len(), 2);
        assert!(leases.iter().all(|lease| lease.lease_id != "lease-1"));
    }

    #[tokio::test]
    async fn approving_task_escalation_creates_task_scoped_lease() {
        let kernel = AegisPolicyKernel::new();
        let agent = AgentIdentity::new("acme", "coder-1", "Coder");
        let ctx = PolicyContext {
            principal: agent,
            action: "workspace_commit".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "/workspace".to_string(),
            metadata: json!({ "task_id": "task-1" }),
        };
        let escalation_id = match kernel.evaluate(&ctx).await.unwrap() {
            PolicyDecision::Ask { escalation_id, .. } => escalation_id,
            other => panic!("expected Ask, got {other:?}"),
        };
        let lease = kernel
            .approve_escalation(&escalation_id, 60, "user")
            .await
            .unwrap();
        assert_eq!(lease.kind, LeaseKind::TaskScoped);
        assert_eq!(lease.task_id.as_deref(), Some("task-1"));
    }

    #[tokio::test]
    async fn one_shot_wins_over_task_scope_and_approved_ticket_cannot_be_reused() {
        let kernel = AegisPolicyKernel::new();
        let agent = AgentIdentity::new("acme", "coder-1", "Coder");
        let ctx = PolicyContext {
            principal: agent,
            action: "workspace_commit".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "/workspace".to_string(),
            metadata: json!({ "task_id": "task-1" }),
        };
        let escalation_id = match kernel.evaluate(&ctx).await.unwrap() {
            PolicyDecision::Ask { escalation_id, .. } => escalation_id,
            other => panic!("expected Ask, got {other:?}"),
        };
        let lease = kernel
            .approve_escalation(&escalation_id, 0, "user")
            .await
            .unwrap();
        assert_eq!(lease.kind, LeaseKind::OneShot);
        assert_eq!(lease.task_id.as_deref(), Some("task-1"));
        assert!(kernel
            .approve_escalation(&escalation_id, 0, "user")
            .await
            .is_err());
        assert!(kernel.deny_escalation(&escalation_id, "user").await.is_err());
    }

    #[tokio::test]
    async fn sensitive_batch_approval_grants_split_leases_without_combined_residue() {
        let kernel = AegisPolicyKernel::new();
        let agent = AgentIdentity::new("acme", "coder-1", "Coder");
        let ctx = PolicyContext {
            principal: agent,
            action: "workspace_commit".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "/workspace".to_string(),
            metadata: json!({ "paths": ["Cargo.toml", "package.json"] }),
        };
        let escalation_id = match kernel.evaluate(&ctx).await.unwrap() {
            PolicyDecision::Ask { escalation_id, .. } => escalation_id,
            other => panic!("expected Ask, got {other:?}"),
        };
        kernel
            .approve_escalation(&escalation_id, 0, "user")
            .await
            .unwrap();

        {
            let leases = kernel.leases.read().await;
            assert!(leases
                .iter()
                .all(|lease| !lease.resource_pattern.contains(", ")));
            for path in ["Cargo.toml", "package.json"] {
                assert!(leases.iter().any(|lease| {
                    lease.action_pattern == "workspace_commit_sensitive"
                        && lease.resource_pattern == path
                        && lease.kind == LeaseKind::OneShot
                }));
            }
        }

        assert!(matches!(
            kernel.evaluate(&ctx).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));
        assert!(matches!(
            kernel.evaluate(&ctx).await.unwrap(),
            PolicyDecision::Ask { .. }
        ));
    }

    #[tokio::test]
    async fn task_scoped_lease_requires_matching_task_id() {
        let kernel = AegisPolicyKernel::new();
        let agent = AgentIdentity::new("acme", "coder-1", "Coder");
        kernel
            .grant_lease(LeaseGrant {
                lease_id: "lease-task-1".to_string(),
                org_id: "acme".to_string(),
                agent_id: "coder-1".to_string(),
                action_pattern: "workspace_commit".to_string(),
                resource_pattern: "*".to_string(),
                created_at_ms: 0,
                expires_at_ms: Utc::now().timestamp_millis() + 60_000,
                granted_by: "user".to_string(),
                kind: LeaseKind::TaskScoped,
                task_id: Some("task-1".to_string()),
            })
            .await
            .unwrap();

        let ctx = |task_id: Option<&str>| PolicyContext {
            principal: agent.clone(),
            action: "workspace_commit".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "/workspace".to_string(),
            metadata: json!({ "task_id": task_id }),
        };
        assert!(matches!(
            kernel.evaluate(&ctx(Some("task-1"))).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));
        assert!(matches!(
            kernel.evaluate(&ctx(Some("task-2"))).await.unwrap(),
            PolicyDecision::Ask { .. }
        ));
        assert!(matches!(
            kernel.evaluate(&ctx(None)).await.unwrap(),
            PolicyDecision::Ask { .. }
        ));
    }

    #[tokio::test]
    async fn test_memory_escalation_preserves_resource_pattern() {
        let kernel = AegisPolicyKernel::new();
        let agent = AgentIdentity::new("local", "claude-desktop", "Memory Reader");

        let ctx = PolicyContext {
            principal: agent.clone(),
            action: "memory.read".to_string(),
            target_org_id: "local".to_string(),
            target_resource: "memory:tag:notes/projects".to_string(),
            metadata: json!({}),
        };

        let esc_id = match kernel.evaluate(&ctx).await.unwrap() {
            PolicyDecision::Ask { escalation_id, .. } => escalation_id,
            other => panic!("Expected Ask, got {:?}", other),
        };

        let lease = kernel
            .approve_escalation(&esc_id, 1800, "user")
            .await
            .unwrap();
        assert_eq!(lease.action_pattern, "memory.read");
        assert_eq!(lease.resource_pattern, "memory:tag:notes/projects");

        assert!(matches!(
            kernel.evaluate(&ctx).await.unwrap(),
            PolicyDecision::Allow { matched_rule } if matched_rule == format!("session_lease:{}", lease.lease_id)
        ));

        // A lease for one tag must not authorize a different tag.
        let other = PolicyContext {
            target_resource: "memory:tag:notes/journal".to_string(),
            ..ctx
        };
        assert!(matches!(
            kernel.evaluate(&other).await.unwrap(),
            PolicyDecision::Ask { .. }
        ));
    }

    #[tokio::test]
    async fn test_escalation_approval_and_lease_flow() {
        let kernel = AegisPolicyKernel::new();
        let agent = AgentIdentity::new("acme", "coder-1", "Senior Engineer");

        let commit_ctx = PolicyContext {
            principal: agent.clone(),
            action: "workspace_commit".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "/Users/dev/project".to_string(),
            metadata: json!({}),
        };

        // Initially triggers Ask and records escalation
        let esc_id = match kernel.evaluate(&commit_ctx).await.unwrap() {
            PolicyDecision::Ask { escalation_id, .. } => escalation_id,
            other => panic!("Expected Ask, got {:?}", other),
        };

        // Approve the escalation via `approve_escalation`
        let lease = kernel
            .approve_escalation(&esc_id, 3600, "dev-lead")
            .await
            .unwrap();

        // Subsequent commits pass automatically via the granted Lease!
        let decision = kernel.evaluate(&commit_ctx).await.unwrap();
        assert!(matches!(
            decision,
            PolicyDecision::Allow { matched_rule } if matched_rule == format!("session_lease:{}", lease.lease_id)
        ));

        // Even with the active 1-hour `workspace_commit` lease, touching `build.rs`, `Makefile`,
        // `package.json`, or `.cargo/config.toml` escalates via R0b!
        for poisoned in [
            "build.rs",
            "crates/foo/build.rs",
            "Makefile",
            "package.json",
            ".cargo/config.toml",
            ".agents/hooks.json",
            ".claude/settings.json",
            ".git/info/attributes",
        ] {
            let poisoned_ctx = PolicyContext {
                principal: agent.clone(),
                action: "workspace_commit".to_string(),
                target_org_id: "acme".to_string(),
                target_resource: "/Users/dev/project".to_string(),
                metadata: json!({ "paths": [poisoned] }),
            };
            let esc = kernel.evaluate(&poisoned_ctx).await.unwrap();
            let esc_id = match esc {
                PolicyDecision::Ask { escalation_id, .. } => escalation_id,
                other => panic!("Expected R0b Ask for {}, got {:?}", poisoned, other),
            };
            // Explicit one-shot approval of that sensitive path allows the commit once
            kernel.approve_escalation(&esc_id, 0, "dev-lead").await.unwrap();
            let approved = kernel.evaluate(&poisoned_ctx).await.unwrap();
            assert!(matches!(approved, PolicyDecision::Allow { .. }));
        }
    }

    #[tokio::test]
    async fn test_cedar_policy_parser_and_evaluation() {
        let mut kernel = AegisPolicyKernel::new();
        assert!(
            kernel.cedar_policies().rules.len() >= 5,
            "default.cedar should parse all 5 baseline rules"
        );

        // Add custom Cedar `permit` and `forbid` rules
        kernel.add_cedar_policies(
            r#"
            // Permit custom read-only telemetry action within same org
            permit (
                principal is Agent,
                action in [Action::"telemetry_ping"],
                resource is TelemetryResource
            ) when {
                resource.org_id == principal.org_id
            };

            // Explicitly forbid deleting production database migrations
            forbid (
                principal is Agent,
                action in [Action::"fs_delete"],
                resource like "/workspace/migrations/*"
            );
            "#,
        );

        let agent = AgentIdentity::new("acme", "coder-1", "Senior Engineer");

        // Custom Cedar permit rule allows `telemetry_ping` without prompt
        let ping_ctx = PolicyContext {
            principal: agent.clone(),
            action: "telemetry_ping".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "metrics:cpu".to_string(),
            metadata: json!({}),
        };
        assert!(matches!(
            kernel.evaluate(&ping_ctx).await.unwrap(),
            PolicyDecision::Allow { matched_rule } if matched_rule.starts_with("cedar:permit:")
        ));

        // Custom Cedar forbid rule blocks `fs_delete` on `/workspace/migrations/*`
        let del_migration = PolicyContext {
            principal: agent.clone(),
            action: "fs_delete".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "/workspace/migrations/001_init.sql".to_string(),
            metadata: json!({}),
        };
        assert!(matches!(
            kernel.evaluate(&del_migration).await.unwrap(),
            PolicyDecision::Deny { .. }
        ));
    }

    #[tokio::test]
    async fn oneshot_commit_lease_pins_evidence_hash_against_toctou_diff_swap() {
        let kernel = AegisPolicyKernel::new();
        let agent = AgentIdentity::new("acme", "coder-1", "Senior Engineer");

        let benign_ctx = PolicyContext {
            principal: agent.clone(),
            action: "workspace_commit".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "/workspace".to_string(),
            metadata: json!({
                "paths": ["docs/typo.md"],
                "evidence_hash": "1111111111111111111111111111111111111111111111111111111111111111",
                "rationale": "Fix documentation typo"
            }),
        };

        let esc_id = match kernel.evaluate(&benign_ctx).await.unwrap() {
            PolicyDecision::Ask { escalation_id, .. } => escalation_id,
            other => panic!("Expected Ask, got {:?}", other),
        };

        let lease = kernel
            .approve_escalation(&esc_id, 0, "dev-lead")
            .await
            .unwrap();
        assert_eq!(
            lease.resource_pattern,
            "sha256:1111111111111111111111111111111111111111111111111111111111111111"
        );

        // Bait-and-switch attempt: agent mutates `src/payment_engine.rs` after approval, changing `evidence_hash`
        let swapped_ctx = PolicyContext {
            principal: agent.clone(),
            action: "workspace_commit".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "/workspace".to_string(),
            metadata: json!({
                "paths": ["docs/typo.md", "src/payment_engine.rs"],
                "evidence_hash": "2222222222222222222222222222222222222222222222222222222222222222"
            }),
        };
        assert!(
            matches!(
                kernel.evaluate(&swapped_ctx).await.unwrap(),
                PolicyDecision::Ask { .. }
            ),
            "Mutated diff must NOT consume or match the One-Shot lease pinned to the benign diff hash"
        );

        // Retrying the original unmodified diff succeeds and consumes the One-Shot lease
        assert!(matches!(
            kernel.evaluate(&benign_ctx).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));
    }

    #[tokio::test]
    async fn overwrite_binaries_and_skip_verify_escalate_even_with_general_commit_lease() {
        let kernel = AegisPolicyKernel::new();
        let agent = AgentIdentity::new("acme", "coder-1", "Senior Engineer");

        kernel
            .grant_lease(LeaseGrant {
                lease_id: "lease-general".to_string(),
                org_id: "acme".to_string(),
                agent_id: "coder-1".to_string(),
                action_pattern: "workspace_commit".to_string(),
                resource_pattern: "*".to_string(),
                created_at_ms: 0,
                expires_at_ms: Utc::now().timestamp_millis() + 3_600_000,
                granted_by: "dev-lead".to_string(),
                kind: LeaseKind::Ttl,
                task_id: None,
            })
            .await
            .unwrap();

        // 1. `overwrite_binaries: true` escalates to `workspace_commit_sensitive`
        let bin_ctx = PolicyContext {
            principal: agent.clone(),
            action: "workspace_commit".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "/workspace".to_string(),
            metadata: json!({
                "paths": ["assets/diagram.png"],
                "overwrite_binaries": true
            }),
        };
        let bin_esc = match kernel.evaluate(&bin_ctx).await.unwrap() {
            PolicyDecision::Ask { escalation_id, .. } => escalation_id,
            other => panic!("Expected Ask for overwrite_binaries=true, got {:?}", other),
        };
        kernel
            .approve_escalation(&bin_esc, 0, "dev-lead")
            .await
            .unwrap();
        assert!(matches!(
            kernel.evaluate(&bin_ctx).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));

        // 2. `skip_verify: true` when `has_configured_verify_cmd: true` escalates to `workspace_commit_sensitive`
        let skip_ctx = PolicyContext {
            principal: agent.clone(),
            action: "workspace_commit".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "/workspace".to_string(),
            metadata: json!({
                "paths": ["src/lib.rs"],
                "skip_verify": true,
                "has_configured_verify_cmd": true
            }),
        };
        let skip_esc = match kernel.evaluate(&skip_ctx).await.unwrap() {
            PolicyDecision::Ask { escalation_id, .. } => escalation_id,
            other => panic!("Expected Ask for skip_verify=true, got {:?}", other),
        };
        kernel
            .approve_escalation(&skip_esc, 0, "dev-lead")
            .await
            .unwrap();
        assert!(matches!(
            kernel.evaluate(&skip_ctx).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));
    }

    #[tokio::test]
    async fn egress_escalation_scopes_lease_to_specific_domain_and_expired_ticket_cannot_approve() {
        let kernel = AegisPolicyKernel::new();
        let agent = AgentIdentity::new("acme", "coder-1", "Senior Engineer");

        let stripe_ctx = PolicyContext {
            principal: agent.clone(),
            action: "egress_unlisted_domain".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "api.stripe.com".to_string(),
            metadata: json!({}),
        };
        let esc_id = match kernel.evaluate(&stripe_ctx).await.unwrap() {
            PolicyDecision::Ask { escalation_id, .. } => escalation_id,
            other => panic!("Expected Ask, got {:?}", other),
        };
        let lease = kernel
            .approve_escalation(&esc_id, 900, "dev-lead")
            .await
            .unwrap();
        assert_eq!(lease.resource_pattern, "api.stripe.com");

        // `api.stripe.com` is now allowed, but `evil.example.com` still escalates!
        assert!(matches!(
            kernel.evaluate(&stripe_ctx).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));
        let evil_ctx = PolicyContext {
            target_resource: "evil.example.com".to_string(),
            metadata: json!({ "escalation_ttl_ms": -1000 }),
            ..stripe_ctx
        };
        let expired_esc = match kernel.evaluate(&evil_ctx).await.unwrap() {
            PolicyDecision::Ask { escalation_id, .. } => escalation_id,
            other => panic!("Expected Ask, got {:?}", other),
        };
        // Attempting to approve an expired ticket fails and marks it Expired
        assert!(kernel
            .approve_escalation(&expired_esc, 900, "dev-lead")
            .await
            .is_err());
        let list = kernel.list_escalations("acme").await.unwrap();
        let item = list.iter().find(|e| e.escalation_id == expired_esc).unwrap();
        assert_eq!(item.status, EscalationStatus::Expired);
    }

    #[tokio::test]
    async fn fs_export_file_pins_destination_and_evidence_and_blocks_redline_even_with_wildcard_lease() {
        let kernel = AegisPolicyKernel::new();
        let agent = AgentIdentity::new("acme", "coder-1", "Senior Engineer");

        // Even a wildcard lease for fs_export_file must never permit exporting over hooks/keys/build scripts.
        kernel
            .grant_lease(LeaseGrant {
                lease_id: "lease-wildcard".to_string(),
                org_id: "acme".to_string(),
                agent_id: "coder-1".to_string(),
                action_pattern: "fs_export_file".to_string(),
                resource_pattern: "*".to_string(),
                created_at_ms: 0,
                expires_at_ms: Utc::now().timestamp_millis() + 60_000,
                granted_by: "user".to_string(),
                kind: LeaseKind::Ttl,
                task_id: None,
            })
            .await
            .unwrap();

        for forbidden in [
            "/Users/alice/.ssh/authorized_keys",
            "/Users/alice/repo/.git/hooks/pre-commit",
            "/Users/alice/repo/build.rs",
            "/Users/alice/.gemini/config/hooks.json",
        ] {
            let deny_ctx = PolicyContext {
                principal: agent.clone(),
                action: "fs_export_file".to_string(),
                target_org_id: "acme".to_string(),
                target_resource: forbidden.to_string(),
                metadata: json!({}),
            };
            assert!(
                matches!(
                    kernel.evaluate(&deny_ctx).await.unwrap(),
                    PolicyDecision::Deny { .. }
                ),
                "expected Deny for {forbidden}"
            );
        }

        // Now test a clean kernel without wildcard lease for One-Shot pinning.
        let clean_kernel = AegisPolicyKernel::new();
        let hash_good = "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111";
        let hash_bad = "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222";
        let export_ctx = PolicyContext {
            principal: agent.clone(),
            action: "fs_export_file".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "/Users/alice/workspace/SYLVA/paper/main.pdf".to_string(),
            metadata: json!({
                "src_path": "$TMPDIR/main.pdf",
                "size_bytes": 185941,
                "content_type": "application/pdf",
                "evidence_hash": hash_good
            }),
        };
        let esc_id = match clean_kernel.evaluate(&export_ctx).await.unwrap() {
            PolicyDecision::Ask { escalation_id, reason, .. } => {
                assert!(reason.contains("185941 bytes"), "{reason}");
                assert!(reason.contains("application/pdf"), "{reason}");
                escalation_id
            }
            other => panic!("Expected Ask, got {other:?}"),
        };

        let lease = clean_kernel
            .approve_escalation(&esc_id, 0, "dev-lead")
            .await
            .unwrap();
        assert_eq!(lease.kind, LeaseKind::OneShot);
        assert_eq!(
            lease.resource_pattern,
            format!("/Users/alice/workspace/SYLVA/paper/main.pdf#sha256:{hash_good}")
        );

        // Different destination or swapped evidence hash must NOT match.
        let other_dst = PolicyContext {
            target_resource: "/Users/alice/workspace/SYLVA/paper/other.pdf".to_string(),
            ..export_ctx.clone()
        };
        assert!(matches!(
            clean_kernel.evaluate(&other_dst).await.unwrap(),
            PolicyDecision::Ask { .. }
        ));
        let swapped_hash = PolicyContext {
            metadata: json!({ "evidence_hash": hash_bad }),
            ..export_ctx.clone()
        };
        assert!(matches!(
            clean_kernel.evaluate(&swapped_hash).await.unwrap(),
            PolicyDecision::Ask { .. }
        ));

        // Exact destination + evidence hash matches once, then consumes the One-Shot lease.
        assert!(matches!(
            clean_kernel.evaluate(&export_ctx).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));
        assert!(matches!(
            clean_kernel.evaluate(&export_ctx).await.unwrap(),
            PolicyDecision::Ask { .. }
        ));
    }

    #[tokio::test]
    async fn workspace_switch_auto_allows_within_umbrella_and_escalates_outside() {
        let kernel = AegisPolicyKernel::new();
        let agent = AgentIdentity::new("aegis-os", "agy-1", "Lead");

        let inside_ctx = PolicyContext {
            principal: agent.clone(),
            action: "workspace_switch".to_string(),
            target_org_id: "aegis-os".to_string(),
            target_resource: "/Users/alice/workspace/SYLVA".to_string(),
            metadata: json!({ "within_umbrella": true }),
        };
        assert!(matches!(
            kernel.evaluate(&inside_ctx).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));

        let outside_ctx = PolicyContext {
            principal: agent,
            action: "workspace_switch".to_string(),
            target_org_id: "aegis-os".to_string(),
            target_resource: "/Users/alice/other/repo".to_string(),
            metadata: json!({ "within_umbrella": false }),
        };
        let esc_id = match kernel.evaluate(&outside_ctx).await.unwrap() {
            PolicyDecision::Ask { escalation_id, .. } => escalation_id,
            other => panic!("Expected Ask, got {other:?}"),
        };
        let lease = kernel.approve_escalation(&esc_id, 600, "dev-lead").await.unwrap();
        assert_eq!(lease.resource_pattern, "/Users/alice/other/repo");
        assert!(matches!(
            kernel.evaluate(&outside_ctx).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));
    }

    #[tokio::test]
    async fn workspace_git_escalates_pins_oneshot_sha256_and_isolates_push_scope() {
        let kernel = AegisPolicyKernel::new();
        let agent = AgentIdentity::new("aegis-os", "agy-1", "Lead");

        let local_ctx = PolicyContext {
            principal: agent.clone(),
            action: "workspace_git".to_string(),
            target_org_id: "aegis-os".to_string(),
            target_resource: "git:/repo#local".to_string(),
            metadata: json!({
                "host_root": "/repo",
                "paths": ["src/lib.rs"],
                "commit_message": "fix: update sandbox",
                "push": false,
                "evidence_hash": "abc12345",
            }),
        };

        let (esc_id, reason) = match kernel.evaluate(&local_ctx).await.unwrap() {
            PolicyDecision::Ask {
                escalation_id,
                reason,
                ..
            } => (escalation_id, reason),
            other => panic!("Expected Ask, got {other:?}"),
        };
        assert!(reason.contains("commit 1 file(s)"), "{reason}");

        // Approve Once (`ttl_secs = 0`) -> pins resource pattern with `#sha256:abc12345`.
        let oneshot_lease = kernel.approve_escalation(&esc_id, 0, "dev-lead").await.unwrap();
        assert_eq!(oneshot_lease.resource_pattern, "git:/repo#local#sha256:abc12345");
        assert_eq!(oneshot_lease.kind, LeaseKind::OneShot);

        // Tampered evidence_hash must NOT match the OneShot lease.
        let mut tampered_ctx = local_ctx.clone();
        tampered_ctx.metadata["evidence_hash"] = json!("deadbeef");
        assert!(matches!(
            kernel.evaluate(&tampered_ctx).await.unwrap(),
            PolicyDecision::Ask { .. }
        ));

        // Exact evidence_hash matches once and is consumed.
        assert!(matches!(
            kernel.evaluate(&local_ctx).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));
        assert!(matches!(
            kernel.evaluate(&local_ctx).await.unwrap(),
            PolicyDecision::Ask { .. }
        ));

        // Approve 10m TTL lease on `git:/repo#local` -> must NOT authorize `git:/repo#push:...`.
        let esc_id_2 = match kernel.evaluate(&local_ctx).await.unwrap() {
            PolicyDecision::Ask { escalation_id, .. } => escalation_id,
            other => panic!("Expected Ask, got {other:?}"),
        };
        let ttl_lease = kernel.approve_escalation(&esc_id_2, 600, "dev-lead").await.unwrap();
        assert_eq!(ttl_lease.resource_pattern, "git:/repo#local");
        assert!(matches!(
            kernel.evaluate(&local_ctx).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));

        let push_ctx = PolicyContext {
            principal: agent,
            action: "workspace_git".to_string(),
            target_org_id: "aegis-os".to_string(),
            target_resource: "git:/repo#push:origin:branch=main,tag=-,force_tag=false".to_string(),
            metadata: json!({
                "host_root": "/repo",
                "paths": ["src/lib.rs"],
                "commit_message": "fix: update sandbox",
                "push": true,
                "remote": "origin",
                "branch": "main",
                "force_tag": false,
                "evidence_hash": "abc12345",
            }),
        };
        assert!(matches!(
            kernel.evaluate(&push_ctx).await.unwrap(),
            PolicyDecision::Ask { .. }
        ));
    }

    #[tokio::test]
    async fn test_github_cross_repo_fs_import_and_git_sensitive_guards() {
        let kernel = AegisPolicyKernel::new();
        let agent = AgentIdentity::new("aegis-os", "agy-agent", "Lead");

        // 1. Same-repo `github_ci_inspect` auto-permits via Cedar; cross-repo escalates & pins.
        let same_ci = PolicyContext {
            principal: agent.clone(),
            action: "github_ci_inspect".to_string(),
            target_org_id: "aegis-os".to_string(),
            target_resource: "heurion-org/aegis-os".to_string(),
            metadata: json!({ "repo": "heurion-org/aegis-os", "origin_repo": "heurion-org/aegis-os", "cross_repo": false }),
        };
        assert!(matches!(
            kernel.evaluate(&same_ci).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));

        let cross_ci = PolicyContext {
            principal: agent.clone(),
            action: "github_ci_inspect".to_string(),
            target_org_id: "aegis-os".to_string(),
            target_resource: "other-org/private-repo".to_string(),
            metadata: json!({
                "repo": "other-org/private-repo",
                "origin_repo": "heurion-org/aegis-os",
                "cross_repo": true,
                "evidence_hash": "cihash1"
            }),
        };
        let esc_ci = match kernel.evaluate(&cross_ci).await.unwrap() {
            PolicyDecision::Ask { escalation_id, reason, .. } => {
                assert!(reason.contains("cross-repo"), "{reason}");
                escalation_id
            }
            other => panic!("Expected cross-repo Ask, got {other:?}"),
        };
        let ci_lease = kernel.approve_escalation(&esc_ci, 0, "user").await.unwrap();
        assert_eq!(ci_lease.resource_pattern, "other-org/private-repo#sha256:cihash1");
        assert!(matches!(
            kernel.evaluate(&cross_ci).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));

        // 2. `fs_import_file` denies `.ssh` and `.env.production`, allows `.env.example` ask, denies shadow `.git/hooks`.
        let ssh_import = PolicyContext {
            principal: agent.clone(),
            action: "fs_import_file".to_string(),
            target_org_id: "aegis-os".to_string(),
            target_resource: "/Users/alice/.ssh/id_ed25519".to_string(),
            metadata: json!({ "src_host_path": "/Users/alice/.ssh/id_ed25519", "import_to": "imports", "dst_path": "id_ed25519" }),
        };
        assert!(matches!(kernel.evaluate(&ssh_import).await.unwrap(), PolicyDecision::Deny { .. }));

        let env_import = PolicyContext {
            principal: agent.clone(),
            action: "fs_import_file".to_string(),
            target_org_id: "aegis-os".to_string(),
            target_resource: "/Users/alice/app/.env.production".to_string(),
            metadata: json!({ "src_host_path": "/Users/alice/app/.env.production", "import_to": "imports", "dst_path": ".env.production" }),
        };
        assert!(matches!(kernel.evaluate(&env_import).await.unwrap(), PolicyDecision::Deny { .. }));

        let hook_shadow_import = PolicyContext {
            principal: agent.clone(),
            action: "fs_import_file".to_string(),
            target_org_id: "aegis-os".to_string(),
            target_resource: "/Users/alice/Downloads/script.sh".to_string(),
            metadata: json!({ "src_host_path": "/Users/alice/Downloads/script.sh", "import_to": "shadow", "dst_path": ".git/hooks/pre-commit" }),
        };
        assert!(matches!(kernel.evaluate(&hook_shadow_import).await.unwrap(), PolicyDecision::Deny { .. }));

        let example_import = PolicyContext {
            principal: agent.clone(),
            action: "fs_import_file".to_string(),
            target_org_id: "aegis-os".to_string(),
            target_resource: "/Users/alice/Downloads/.env.example".to_string(),
            metadata: json!({
                "src_host_path": "/Users/alice/Downloads/.env.example",
                "import_to": "imports",
                "dst_path": ".env.example",
                "size_bytes": 128,
                "evidence_hash": "imphash1"
            }),
        };
        let esc_imp = match kernel.evaluate(&example_import).await.unwrap() {
            PolicyDecision::Ask { escalation_id, .. } => escalation_id,
            other => panic!("Expected Ask for .env.example import, got {other:?}"),
        };
        let imp_lease = kernel.approve_escalation(&esc_imp, 0, "user").await.unwrap();
        assert_eq!(imp_lease.resource_pattern, "/Users/alice/Downloads/.env.example#sha256:imphash1");
        assert!(matches!(kernel.evaluate(&example_import).await.unwrap(), PolicyDecision::Allow { .. }));

        // 3. `workspace_git_sensitive` bypasses general `workspace_git` TTL lease & grants companion lease in one click.
        let general_res = "git:/repo#push:origin:branch=main,tag=-,force_tag=false";
        kernel
            .grant_lease(LeaseGrant {
                lease_id: "lease-general-git".to_string(),
                org_id: "aegis-os".to_string(),
                agent_id: "agy-agent".to_string(),
                action_pattern: "workspace_git".to_string(),
                resource_pattern: general_res.to_string(),
                created_at_ms: 0,
                expires_at_ms: Utc::now().timestamp_millis() + 600_000,
                granted_by: "user".to_string(),
                kind: LeaseKind::Ttl,
                task_id: None,
            })
            .await
            .unwrap();

        let sensitive_git = PolicyContext {
            principal: agent,
            action: "workspace_git".to_string(),
            target_org_id: "aegis-os".to_string(),
            target_resource: general_res.to_string(),
            metadata: json!({
                "host_root": "/repo",
                "paths": [".github/workflows/ci.yml"],
                "force_push": true,
                "push": true,
                "evidence_hash": "gitsens1"
            }),
        };
        let esc_git = match kernel.evaluate(&sensitive_git).await.unwrap() {
            PolicyDecision::Ask { escalation_id, reason, .. } => {
                assert!(reason.contains("HIGH RISK") && reason.contains("force_push"), "{reason}");
                escalation_id
            }
            other => panic!("Expected workspace_git_sensitive Ask, got {other:?}"),
        };
        kernel.approve_escalation(&esc_git, 0, "user").await.unwrap();
        assert!(
            matches!(kernel.evaluate(&sensitive_git).await.unwrap(), PolicyDecision::Allow { .. }),
            "Single approval of workspace_git_sensitive must also authorize companion workspace_git"
        );
    }

    #[tokio::test]
    async fn test_pkg_install_policy_pinning_and_lifecycle_scripts_escalation() {
        let kernel = AegisPolicyKernel::with_state_file(None);
        let agent = AgentIdentity::new("aegis-os", "agy-agent", "Coder");
        let pkg_res = "pkg:npm:.#chalk";

        // 1. Standard `pkg_install` escalates and pins `#sha256:` on one-shot approval, rejecting tampering.
        let install_ctx = PolicyContext {
            principal: agent.clone(),
            action: "pkg_install".to_string(),
            target_org_id: "aegis-os".to_string(),
            target_resource: pkg_res.to_string(),
            metadata: json!({
                "manager": "npm",
                "packages": ["chalk"],
                "allow_scripts": false,
                "offline": false,
                "evidence_hash": "pkghash1"
            }),
        };
        let esc_id = match kernel.evaluate(&install_ctx).await.unwrap() {
            PolicyDecision::Ask { escalation_id, .. } => escalation_id,
            other => panic!("Expected pkg_install Ask, got {other:?}"),
        };
        let lease = kernel.approve_escalation(&esc_id, 0, "user").await.unwrap();
        assert_eq!(lease.resource_pattern, "pkg:npm:.#chalk#sha256:pkghash1");

        let tampered_ctx = PolicyContext {
            metadata: json!({
                "manager": "npm",
                "packages": ["chalk"],
                "allow_scripts": false,
                "offline": false,
                "evidence_hash": "tampered"
            }),
            ..install_ctx.clone()
        };
        assert!(
            matches!(kernel.evaluate(&tampered_ctx).await.unwrap(), PolicyDecision::Ask { .. }),
            "Tampered package install evidence must invalidate one-shot lease"
        );
        assert!(
            matches!(kernel.evaluate(&install_ctx).await.unwrap(), PolicyDecision::Allow { .. }),
            "Matching one-shot lease should still allow exact plan"
        );

        // 2. Grant general TTL `pkg_install` lease -> `allow_scripts: true` still escalates to `pkg_install_scripts`.
        kernel
            .grant_lease(LeaseGrant {
                lease_id: "lease-pkg-ttl".to_string(),
                org_id: "aegis-os".to_string(),
                agent_id: "agy-agent".to_string(),
                action_pattern: "pkg_install".to_string(),
                resource_pattern: "*".to_string(),
                created_at_ms: 0,
                expires_at_ms: Utc::now().timestamp_millis() + 600_000,
                granted_by: "user".to_string(),
                kind: LeaseKind::Ttl,
                task_id: None,
            })
            .await
            .unwrap();

        let scripts_ctx = PolicyContext {
            principal: agent,
            action: "pkg_install".to_string(),
            target_org_id: "aegis-os".to_string(),
            target_resource: "pkg:npm:.#esbuild".to_string(),
            metadata: json!({
                "manager": "npm",
                "packages": ["esbuild"],
                "allow_scripts": true,
                "offline": false,
                "evidence_hash": "scriptshash1"
            }),
        };
        let esc_scripts = match kernel.evaluate(&scripts_ctx).await.unwrap() {
            PolicyDecision::Ask { escalation_id, reason, .. } => {
                assert!(reason.contains("LIFECYCLE SCRIPTS"), "{reason}");
                escalation_id
            }
            other => panic!("Expected pkg_install_scripts Ask, got {other:?}"),
        };
        kernel
            .approve_escalation(&esc_scripts, 0, "user")
            .await
            .unwrap();
        assert!(
            matches!(kernel.evaluate(&scripts_ctx).await.unwrap(), PolicyDecision::Allow { .. }),
            "Single approval of pkg_install_scripts must authorize retry"
        );
    }

    #[tokio::test]
    async fn test_github_comment_and_pr_merge_escalation_and_pinning() {
        let kernel = AegisPolicyKernel::with_state_file(None);
        let agent = AgentIdentity::new("aegis-os", "agy-agent", "Coder");

        let comment_ctx = PolicyContext {
            principal: agent.clone(),
            action: "github_comment_create".to_string(),
            target_org_id: "aegis-os".to_string(),
            target_resource: "heurion-org/aegis-os#comment:42".to_string(),
            metadata: json!({
                "repo": "heurion-org/aegis-os",
                "number": 42,
                "body": "CI is now green.",
                "evidence_hash": "commenthash1"
            }),
        };
        let esc_c = match kernel.evaluate(&comment_ctx).await.unwrap() {
            PolicyDecision::Ask { escalation_id, reason, .. } => {
                assert!(reason.contains("#42"), "{reason}");
                escalation_id
            }
            other => panic!("Expected comment Ask, got {other:?}"),
        };
        let lease_c = kernel.approve_escalation(&esc_c, 0, "user").await.unwrap();
        assert_eq!(lease_c.resource_pattern, "heurion-org/aegis-os#comment:42#sha256:commenthash1");
        let tampered_c = PolicyContext {
            metadata: json!({ "repo": "heurion-org/aegis-os", "number": 42, "body": "evil", "evidence_hash": "tampered" }),
            ..comment_ctx.clone()
        };
        assert!(matches!(kernel.evaluate(&tampered_c).await.unwrap(), PolicyDecision::Ask { .. }));
        assert!(matches!(kernel.evaluate(&comment_ctx).await.unwrap(), PolicyDecision::Allow { .. }));

        let merge_ctx = PolicyContext {
            principal: agent,
            action: "github_pr_merge".to_string(),
            target_org_id: "aegis-os".to_string(),
            target_resource: "heurion-org/aegis-os#pr:42:merge".to_string(),
            metadata: json!({
                "repo": "heurion-org/aegis-os",
                "pr_number": 42,
                "method": "squash",
                "delete_branch": true,
                "evidence_hash": "mergehash1"
            }),
        };
        let esc_m = match kernel.evaluate(&merge_ctx).await.unwrap() {
            PolicyDecision::Ask { escalation_id, reason, .. } => {
                assert!(reason.contains("[DESTRUCTIVE]"), "{reason}");
                assert!(reason.contains("squash-merge"), "{reason}");
                escalation_id
            }
            other => panic!("Expected merge Ask, got {other:?}"),
        };
        let lease_m = kernel.approve_escalation(&esc_m, 0, "user").await.unwrap();
        assert_eq!(lease_m.resource_pattern, "heurion-org/aegis-os#pr:42:merge#sha256:mergehash1");
        let tampered_m = PolicyContext {
            metadata: json!({ "repo": "heurion-org/aegis-os", "pr_number": 42, "method": "merge", "delete_branch": false, "evidence_hash": "tampered" }),
            ..merge_ctx.clone()
        };
        assert!(matches!(kernel.evaluate(&tampered_m).await.unwrap(), PolicyDecision::Ask { .. }));
        assert!(matches!(kernel.evaluate(&merge_ctx).await.unwrap(), PolicyDecision::Allow { .. }));
    }

    #[tokio::test]
    async fn test_host_exec_hard_guards_in_memory_leases_ttl_pinning_and_loopback_ssrf() {
        let tmp_dir = std::env::temp_dir().join(format!("aos-policy-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let state_path = tmp_dir.join("policy_state.json");
        let mut kernel = AegisPolicyKernel::with_state_file(Some(state_path.clone()));
        let agent = AgentIdentity::new("aegis-os", "agy-agent", "Coder");

        // 1. Loopback & link-local SSRF targets are hard-denied on `egress_unlisted_domain`.
        for target in [
            "127.0.0.1:8080",
            "localhost",
            "sub.localhost:9000",
            "[::1]:8443",
            "169.254.169.254",
            "0.0.0.0",
        ] {
            let ssrf_ctx = PolicyContext {
                principal: agent.clone(),
                action: "egress_unlisted_domain".to_string(),
                target_org_id: "aegis-os".to_string(),
                target_resource: target.to_string(),
                metadata: serde_json::json!({}),
            };
            assert!(
                matches!(kernel.evaluate(&ssrf_ctx).await.unwrap(), PolicyDecision::Deny { .. }),
                "loopback/metadata target '{target}' must be denied"
            );
        }

        // 2. Wildcard leases and broad Cedar `permit` rules must NEVER authorize `host_exec`.
        kernel.add_cedar_policies("permit(principal, action, resource);");
        kernel
            .grant_lease(LeaseGrant {
                lease_id: "lease-wild".to_string(),
                org_id: "aegis-os".to_string(),
                agent_id: "*".to_string(),
                action_pattern: "*".to_string(),
                resource_pattern: "*".to_string(),
                created_at_ms: 0,
                expires_at_ms: Utc::now().timestamp_millis() + 3_600_000,
                granted_by: "test".to_string(),
                kind: LeaseKind::Ttl,
                task_id: None,
            })
            .await
            .unwrap();
        assert!(
            kernel
                .grant_lease(LeaseGrant {
                    lease_id: "lease-direct".to_string(),
                    org_id: "aegis-os".to_string(),
                    agent_id: "agy-agent".to_string(),
                    action_pattern: "host_exec".to_string(),
                    resource_pattern: "*".to_string(),
                    created_at_ms: 0,
                    expires_at_ms: Utc::now().timestamp_millis() + 3_600_000,
                    granted_by: "test".to_string(),
                    kind: LeaseKind::Ttl,
                    task_id: None,
                })
                .await
                .is_err(),
            "direct grant_lease for host_exec must fail"
        );

        let hash_v1 = "a".repeat(64);
        let hash_v2 = format!("{}b", "a".repeat(63));
        // Missing enforced_session_broker -> Deny
        let non_broker = PolicyContext {
            principal: agent.clone(),
            action: "host_exec".to_string(),
            target_org_id: "aegis-os".to_string(),
            target_resource: "host_exec:/usr/bin/python3:scripts/bench.py".to_string(),
            metadata: serde_json::json!({ "evidence_hash": hash_v1 }),
        };
        assert!(matches!(
            kernel.evaluate(&non_broker).await.unwrap(),
            PolicyDecision::Deny { .. }
        ));

        let ctx_v1 = PolicyContext {
            principal: agent.clone(),
            action: "host_exec".to_string(),
            target_org_id: "aegis-os".to_string(),
            target_resource: "host_exec:/usr/bin/python3:scripts/bench.py".to_string(),
            metadata: serde_json::json!({
                "enforced_session_broker": true,
                "evidence_hash": hash_v1,
                "command_summary": "python3 scripts/bench.py"
            }),
        };
        let esc_id = match kernel.evaluate(&ctx_v1).await.unwrap() {
            PolicyDecision::Ask { escalation_id, reason, .. } => {
                assert!(reason.contains("UNSANDBOXED HOST EXEC"), "{reason}");
                escalation_id
            }
            other => panic!("wildcard/Cedar must not bypass host_exec Ask, got {other:?}"),
        };

        // 3. Forging a `host_exec` lease directly into `policy_state.json` on disk must be ignored
        // because `in_memory_host_exec_leases` does not contain it.
        let disk_raw = std::fs::read(&state_path).unwrap();
        let mut parsed: serde_json::Value = serde_json::from_slice(&disk_raw).unwrap();
        parsed["leases"].as_array_mut().unwrap().push(serde_json::json!({
            "lease_id": "lease-forged",
            "org_id": "aegis-os",
            "agent_id": "agy-agent",
            "action_pattern": "host_exec",
            "resource_pattern": format!("host_exec:/usr/bin/python3:scripts/bench.py#sha256:{}", hash_v1),
            "expires_at_ms": Utc::now().timestamp_millis() + 3_600_000,
            "granted_by": "rogue-child",
            "kind": "ttl"
        }));
        std::fs::write(&state_path, serde_json::to_vec_pretty(&parsed).unwrap()).unwrap();
        assert!(
            matches!(kernel.evaluate(&ctx_v1).await.unwrap(), PolicyDecision::Ask { .. }),
            "disk-forged host_exec lease must be rejected by in-memory gate"
        );

        // 4. Approving `host_exec` with TTL=3600s STILL pins `#sha256:<hash>`!
        let ttl_lease = kernel.approve_escalation(&esc_id, 3600, "human").await.unwrap();
        assert!(
            ttl_lease.resource_pattern.ends_with(&format!("#sha256:{}", hash_v1)),
            "TTL host_exec lease must stay SHA-256 pinned: {}",
            ttl_lease.resource_pattern
        );
        // Same frozen bundle hash can re-run repeatedly within TTL...
        assert!(matches!(
            kernel.evaluate(&ctx_v1).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));
        assert!(matches!(
            kernel.evaluate(&ctx_v1).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));
        // ...and a 1-hex-char drift in evidence_hash immediately forces re-escalation!
        let ctx_v2 = PolicyContext {
            metadata: serde_json::json!({
                "enforced_session_broker": true,
                "evidence_hash": hash_v2
            }),
            ..ctx_v1.clone()
        };
        assert!(
            matches!(kernel.evaluate(&ctx_v2).await.unwrap(), PolicyDecision::Ask { .. }),
            "1-bit hash drift must invalidate TTL host_exec lease"
        );
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[tokio::test]
    async fn workspace_git_auto_commit_shadow_oneshot_sensitive_does_not_double_consume() {
        let kernel = AegisPolicyKernel::new();
        let agent = AgentIdentity::new("aegis-os", "agy-agent", "Lead");
        let ctx = PolicyContext {
            principal: agent,
            action: "workspace_git".to_string(),
            target_org_id: "aegis-os".to_string(),
            target_resource: "git:/repo#push:origin:branch=main,tag=v0.4.10,force_tag=false"
                .to_string(),
            metadata: serde_json::json!({
                "host_root": "/repo",
                "paths": ["Cargo.toml", "src/lib.rs"],
                "shadow_paths": ["Cargo.toml", "src/lib.rs"],
                "auto_commit_shadow": true,
                "commit_message": "chore(release): release v0.4.10",
                "tag": "v0.4.10",
                "push": true,
                "evidence_hash": "deadbeef12345678",
            }),
        };

        let esc_id = match kernel.evaluate(&ctx).await.unwrap() {
            PolicyDecision::Ask { escalation_id, reason, .. } => {
                assert!(reason.contains("Cargo.toml"), "{reason}");
                escalation_id
            }
            other => panic!("Expected Ask for Cargo.toml, got {other:?}"),
        };

        // Single OneShot approval (`ttl_secs = 0`) must cover `Cargo.toml` across both `paths`
        // and `shadow_paths` without consuming the OneShot lease twice.
        kernel.approve_escalation(&esc_id, 0, "human").await.unwrap();
        assert!(
            matches!(kernel.evaluate(&ctx).await.unwrap(), PolicyDecision::Allow { .. }),
            "OneShot sensitive workspace_git lease must not be double-consumed across paths and shadow_paths"
        );
    }
}

#[cfg(test)]
mod casefold_guard_tests {
    use super::AegisPolicyKernel as K;

    #[test]
    fn commit_poisoning_guard_is_case_insensitive() {
        // On APFS/NTFS these land on the real `.git/hooks`, workflows, agent configs, ...
        for p in [
            ".GIT/hooks/pre-commit",
            "sub/.Git/hooks/post-checkout",
            ".GitHub/Workflows/x.yml",
            ".Claude/settings.json",
            ".Agents/hooks.json",
            ".ENVRC",
            "MAKEFILE",
            "Build.RS",
            ".VSCode/tasks.json",
            "Cargo.TOML",
            "vendor/.git",
        ] {
            assert!(K::is_commit_poisoning_path(p), "{p} must be treated as sensitive");
        }
        for p in ["src/main.rs", "docs/makefile-notes.md", "README.md"] {
            assert!(!K::is_commit_poisoning_path(p), "{p} must not be treated as sensitive");
        }
    }

    #[test]
    fn import_source_denylist_is_case_insensitive() {
        assert!(K::is_forbidden_import_source("/Users/x/.SSH/id_rsa"));
        assert!(K::is_forbidden_import_source("/Users/x/library/keychains/login.keychain-db"));
        assert!(K::is_forbidden_import_source("/Users/x/proj/.ENV"));
        assert!(!K::is_forbidden_import_source("/Users/x/proj/.env.example"));
    }
}

#[cfg(test)]
mod stage2_security_tests {
    use super::*;
    use aos_core::AgentIdentity;
    use serde_json::json;

    #[tokio::test]
    async fn cedar_parser_handles_urls_globs_principal_owner_unless_and_fails_closed() {
        // 1. Quotes with `//` and `;`, mid-string globs, `principal == Agent::"..."`,
        // `resource.owner_agent_id`, `unless { ... }`, and custom cross-org forbid rule.
        let mut kernel = AegisPolicyKernel::new();
        kernel
            .try_add_cedar_policies(
                r#"
                permit (
                    principal == Agent::"uploader-1",
                    action in [Action::"custom_upload"],
                    resource like "/workspace/*/artifacts/*.bin"
                ) when {
                    resource.org_id == principal.org_id &&
                    resource.id != "https://blocked.example.com/a;b"
                } unless {
                    resource.path like "*.tmp"
                };

                forbid (
                    principal is Agent,
                    action in [Action::"custom_upload"],
                    resource like "*.pem"
                );
                "#,
            )
            .expect("valid Cedar policy with URL and mid-globs must parse");

        let uploader = AgentIdentity::new("acme", "uploader-1", "Bot");
        let other = AgentIdentity::new("acme", "other-agent", "Bot");

        // Matching mid-glob + allowed agent + allowed org -> Allow
        let ok_ctx = PolicyContext {
            principal: uploader.clone(),
            action: "custom_upload".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "/workspace/sub1/artifacts/pkg.bin".to_string(),
            metadata: json!({}),
        };
        assert!(matches!(
            kernel.evaluate(&ok_ctx).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));

        // Different agent does not match `principal == Agent::"uploader-1"`
        let wrong_agent_ctx = PolicyContext {
            principal: other.clone(),
            ..ok_ctx.clone()
        };
        assert!(!matches!(
            kernel.evaluate(&wrong_agent_ctx).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));

        // `.pem` matches suffix glob -> Deny by forbid rule
        let pem_ctx = PolicyContext {
            principal: uploader.clone(),
            action: "custom_upload".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "/workspace/key.pem".to_string(),
            metadata: json!({}),
        };
        assert!(matches!(
            kernel.evaluate(&pem_ctx).await.unwrap(),
            PolicyDecision::Deny { .. }
        ));

        // `owner_agent_id` mismatch blocks default WorkspaceResource permit
        let cross_agent_fs = PolicyContext {
            principal: other,
            action: "fs_read".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "/workspace/file.txt".to_string(),
            metadata: json!({ "owner_agent_id": "uploader-1" }),
        };
        assert!(!matches!(
            kernel.evaluate(&cross_agent_fs).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));

        // 2. Malformed Cedar must return Err from `try_add_cedar_policies` AND fail closed via `add_cedar_policies`
        assert!(CedarPolicySet::try_parse("permit(principal, action, resource) when { unknown.field == \"x\" };").is_err());
        let mut fail_closed_kernel = AegisPolicyKernel::new();
        fail_closed_kernel.add_cedar_policies("permit(principal, action, resource) when { bogus.x == \"1\" };");
        let benign_fs = PolicyContext {
            principal: uploader,
            action: "fs_read".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "/workspace/readme.md".to_string(),
            metadata: json!({}),
        };
        assert!(
            matches!(fail_closed_kernel.evaluate(&benign_fs).await.unwrap(), PolicyDecision::Deny { .. }),
            "invalid Cedar policy must fail closed rather than permit"
        );
    }

    #[tokio::test]
    async fn sensitive_commit_preserves_oneshot_atomically_and_blocks_comma_injection() {
        let kernel = AegisPolicyKernel::new();
        let agent = AgentIdentity::new("acme", "coder-1", "Engineer");

        // Grant OneShot for Cargo.toml only, then request commit touching BOTH Cargo.toml and Makefile.
        kernel
            .grant_lease(LeaseGrant {
                lease_id: "lease-cargo-oneshot".to_string(),
                org_id: "acme".to_string(),
                agent_id: "coder-1".to_string(),
                action_pattern: "workspace_commit_sensitive".to_string(),
                resource_pattern: "Cargo.toml".to_string(),
                created_at_ms: 0,
                expires_at_ms: Utc::now().timestamp_millis() + 60_000,
                granted_by: "human".to_string(),
                kind: LeaseKind::OneShot,
                task_id: None,
            })
            .await
            .unwrap();
        let two_files_ctx = PolicyContext {
            principal: agent.clone(),
            action: "workspace_commit".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "/workspace".to_string(),
            metadata: json!({ "paths": ["Cargo.toml", "Makefile"] }),
        };
        assert!(matches!(
            kernel.evaluate(&two_files_ctx).await.unwrap(),
            PolicyDecision::Ask { .. }
        ));
        // Cargo.toml OneShot lease must still exist because Makefile failed!
        let single_cargo_ctx = PolicyContext {
            principal: agent.clone(),
            action: "workspace_commit_sensitive".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "Cargo.toml".to_string(),
            metadata: json!({}),
        };
        assert!(
            kernel.match_active_lease(&single_cargo_ctx).await.is_some(),
            "Cargo.toml OneShot lease must not be burned when Makefile fails"
        );

        // Comma injection in a single filename must NOT split into `flag:skip_verify`
        let comma_ctx = PolicyContext {
            principal: agent.clone(),
            action: "workspace_commit".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "/workspace".to_string(),
            metadata: json!({
                "paths": [".github/workflows/x, flag:skip_verify"],
                "skip_verify": false,
            }),
        };
        let esc_id = match kernel.evaluate(&comma_ctx).await.unwrap() {
            PolicyDecision::Ask { escalation_id, .. } => escalation_id,
            other => panic!("Expected Ask, got {other:?}"),
        };
        kernel.approve_escalation(&esc_id, 600, "human").await.unwrap();
        let leases = kernel.list_leases("acme", Some("coder-1")).await.unwrap();
        assert!(
            !leases.iter().any(|l| l.resource_pattern == "flag:skip_verify"),
            "comma in filename must not mint flag:skip_verify lease: {leases:?}"
        );
    }

    #[tokio::test]
    async fn proc_exec_redline_overrides_wildcard_lease_and_casefolds() {
        let kernel = AegisPolicyKernel::new();
        let agent = AgentIdentity::new("acme", "coder-1", "Engineer");
        kernel
            .grant_lease(LeaseGrant {
                lease_id: "lease-wild-proc".to_string(),
                org_id: "acme".to_string(),
                agent_id: "*".to_string(),
                action_pattern: "*".to_string(),
                resource_pattern: "*".to_string(),
                created_at_ms: 0,
                expires_at_ms: Utc::now().timestamp_millis() + 60_000,
                granted_by: "human".to_string(),
                kind: LeaseKind::Ttl,
                task_id: None,
            })
            .await
            .unwrap();

        for cmd in ["SUDO id", "$(sudo whoami)", "cat ~/.KUBE/config", "ls /Users/x/.SSH/"] {
            let ctx = PolicyContext {
                principal: agent.clone(),
                action: "proc_exec".to_string(),
                target_org_id: "acme".to_string(),
                target_resource: "sandbox:cmd".to_string(),
                metadata: json!({ "command": cmd }),
            };
            assert!(
                matches!(kernel.evaluate(&ctx).await.unwrap(), PolicyDecision::Deny { .. }),
                "command '{cmd}' must be denied even under wildcard lease"
            );
        }

        let sys_ctx = PolicyContext {
            principal: agent,
            action: "fs_read".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "/system/Library/CoreServices".to_string(),
            metadata: json!({}),
        };
        assert!(
            matches!(kernel.evaluate(&sys_ctx).await.unwrap(), PolicyDecision::Deny { .. }),
            "/system mixed-case prefix must trigger Host Red-Line"
        );
    }

    #[tokio::test]
    async fn session_taint_blocks_pre_taint_leases_and_allows_post_taint_approval() {
        let tmp_dir = std::env::temp_dir().join(format!("aos-policy-taint-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let state_path = tmp_dir.join("policy_state.json");
        let kernel = AegisPolicyKernel::with_state_file(Some(state_path.clone()));
        let agent = AgentIdentity::new("acme", "coder-1", "Engineer");

        // 1. Pre-taint broad TTL leases for `workspace_commit` and `egress_unlisted_domain`
        let now = Utc::now().timestamp_millis();
        kernel
            .grant_lease(LeaseGrant {
                lease_id: "lease-pre-commit".to_string(),
                org_id: "acme".to_string(),
                agent_id: "coder-1".to_string(),
                action_pattern: "workspace_commit".to_string(),
                resource_pattern: "*".to_string(),
                created_at_ms: now,
                expires_at_ms: now + 3_600_000,
                granted_by: "human".to_string(),
                kind: LeaseKind::Ttl,
                task_id: None,
            })
            .await
            .unwrap();
        kernel
            .grant_lease(LeaseGrant {
                lease_id: "lease-pre-egress-wild".to_string(),
                org_id: "acme".to_string(),
                agent_id: "coder-1".to_string(),
                action_pattern: "egress_unlisted_domain".to_string(),
                resource_pattern: "*".to_string(),
                created_at_ms: now,
                expires_at_ms: now + 3_600_000,
                granted_by: "human".to_string(),
                kind: LeaseKind::Ttl,
                task_id: None,
            })
            .await
            .unwrap();

        let commit_ctx = PolicyContext {
            principal: agent.clone(),
            action: "workspace_commit".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "/workspace".to_string(),
            metadata: json!({ "paths": ["src/main.rs"] }),
        };
        let egress_ctx = PolicyContext {
            principal: agent.clone(),
            action: "egress_unlisted_domain".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "webhook.evil.example".to_string(),
            metadata: json!({}),
        };

        assert!(matches!(
            kernel.evaluate(&commit_ctx).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));
        assert!(matches!(
            kernel.evaluate(&egress_ctx).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));

        // 2. Agent reads untrusted external MCP data -> session becomes tainted.
        kernel
            .record_untrusted_taint(
                "acme",
                "coder-1",
                Some("ses-taint-1"),
                TaintSourceEntry {
                    server_id: "gmail-mcp".to_string(),
                    tool_name: "read_email".to_string(),
                    summary: "message msg-42".to_string(),
                    timestamp_ms: Utc::now().timestamp_millis(),
                },
                3600,
            )
            .await
            .unwrap();

        // Both `workspace_commit` and `egress_unlisted_domain` are forced back to `Ask`
        // with `[UNTRUSTED MCP TAINT]` provenance evidence.
        let esc_commit = match kernel.evaluate(&commit_ctx).await.unwrap() {
            PolicyDecision::Ask {
                escalation_id,
                reason,
                ..
            } => {
                assert!(reason.contains("[UNTRUSTED MCP TAINT]"), "{reason}");
                assert!(reason.contains("gmail-mcp:read_email"), "{reason}");
                escalation_id
            }
            other => panic!("expected tainted Ask for workspace_commit, got {other:?}"),
        };
        let esc_egress = match kernel.evaluate(&egress_ctx).await.unwrap() {
            PolicyDecision::Ask {
                escalation_id,
                reason,
                ..
            } => {
                assert!(reason.contains("[UNTRUSTED MCP TAINT]"), "{reason}");
                assert!(reason.contains("webhook.evil.example"), "{reason}");
                escalation_id
            }
            other => panic!("expected tainted Ask for egress_unlisted_domain, got {other:?}"),
        };

        // 3. Approving escalations mints post-taint leases and attaches session_taint evidence.
        let esc_list = kernel.list_escalations("acme").await.unwrap();
        let esc_rec = esc_list
            .iter()
            .find(|e| e.escalation_id == esc_commit)
            .unwrap();
        assert!(
            esc_rec
                .evidence
                .as_ref()
                .and_then(|ev| ev.get("session_taint"))
                .is_some(),
            "expected session_taint in escalation evidence"
        );

        let post_commit_lease = kernel
            .approve_escalation(&esc_commit, 600, "human")
            .await
            .unwrap();
        let post_egress_lease = kernel
            .approve_escalation(&esc_egress, 600, "human")
            .await
            .unwrap();
        assert_eq!(post_egress_lease.resource_pattern, "webhook.evil.example");
        assert!(
            post_commit_lease.created_at_ms
                > kernel
                    .get_active_taint("acme", "coder-1")
                    .await
                    .unwrap()
                    .updated_at_ms
        );

        // Reloading from disk into a fresh kernel instance preserves taint and post-taint leases.
        let reloaded = AegisPolicyKernel::with_state_file(Some(state_path));
        assert!(matches!(
            reloaded.evaluate(&commit_ctx).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));
        assert!(matches!(
            reloaded.evaluate(&egress_ctx).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));

        // 4. Another untrusted read re-arms taint and invalidates the earlier commit lease.
        reloaded
            .record_untrusted_taint(
                "acme",
                "coder-1",
                None,
                TaintSourceEntry {
                    server_id: "github-mcp".to_string(),
                    tool_name: "get_issue".to_string(),
                    summary: "issue #99".to_string(),
                    timestamp_ms: Utc::now().timestamp_millis(),
                },
                3600,
            )
            .await
            .unwrap();
        assert!(matches!(
            reloaded.evaluate(&commit_ctx).await.unwrap(),
            PolicyDecision::Ask { .. }
        ));

        // 5. Clearing taint removes the active taint record.
        let cleared = reloaded.clear_taint("acme", Some("coder-1")).await.unwrap();
        assert_eq!(cleared, 1);
        assert!(reloaded.get_active_taint("acme", "coder-1").await.is_none());
        assert!(matches!(
            reloaded.evaluate(&commit_ctx).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
