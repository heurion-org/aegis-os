use super::*;

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
    ContextAttr(String),
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
                if (root == "true" || root == "false")
                    && !matches!(self.peek(), Some(CedarToken::Dot))
                {
                    return Ok(CedarOperand::Literal(root));
                }
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
                    ("context", _) => Ok(CedarOperand::ContextAttr(field)),
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

pub(crate) fn expr_contains_org_cmp(expr: &CedarExpr, same: bool) -> bool {
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

fn resolve_cedar_operand<'a>(
    op: &'a CedarOperand,
    ctx: &'a PolicyContext,
) -> Option<std::borrow::Cow<'a, str>> {
    use std::borrow::Cow;
    match op {
        CedarOperand::PrincipalOrgId => Some(Cow::Borrowed(ctx.principal.org_id.as_str())),
        CedarOperand::PrincipalAgentId => Some(Cow::Borrowed(ctx.principal.agent_id.as_str())),
        CedarOperand::PrincipalRole => Some(Cow::Borrowed(ctx.principal.role.as_str())),
        CedarOperand::ResourceOrgId => Some(Cow::Borrowed(ctx.target_org_id.as_str())),
        CedarOperand::ResourceOwnerAgentId => Some(Cow::Borrowed(
            ctx.metadata
                .get("owner_agent_id")
                .and_then(|v| v.as_str())
                .unwrap_or(ctx.principal.agent_id.as_str()),
        )),
        CedarOperand::ResourceId | CedarOperand::ResourcePath => {
            Some(Cow::Borrowed(ctx.target_resource.as_str()))
        }
        CedarOperand::ContextAttr(key) => match ctx.metadata.get(key) {
            Some(serde_json::Value::String(s)) => Some(Cow::Borrowed(s.as_str())),
            Some(serde_json::Value::Bool(b)) => Some(Cow::Borrowed(if *b { "true" } else { "false" })),
            Some(serde_json::Value::Number(n)) => Some(Cow::Owned(n.to_string())),
            _ => None,
        },
        CedarOperand::Literal(s) => Some(Cow::Borrowed(s.as_str())),
    }
}

fn eval_cedar_expr(expr: &CedarExpr, ctx: &PolicyContext) -> bool {
    match expr {
        CedarExpr::And(a, b) => eval_cedar_expr(a, ctx) && eval_cedar_expr(b, ctx),
        CedarExpr::Or(a, b) => eval_cedar_expr(a, ctx) || eval_cedar_expr(b, ctx),
        CedarExpr::Not(inner) => !eval_cedar_expr(inner, ctx),
        CedarExpr::Eq(lhs, rhs) => matches!(
            (resolve_cedar_operand(lhs, ctx), resolve_cedar_operand(rhs, ctx)),
            (Some(a), Some(b)) if a.as_ref() == b.as_ref()
        ),
        CedarExpr::Ne(lhs, rhs) => matches!(
            (resolve_cedar_operand(lhs, ctx), resolve_cedar_operand(rhs, ctx)),
            (Some(a), Some(b)) if a.as_ref() != b.as_ref()
        ),
        CedarExpr::Like(lhs, pat) => resolve_cedar_operand(lhs, ctx)
            .is_some_and(|v| AegisPolicyKernel::matches_pattern(pat, v.as_ref())),
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
        || matches!(
            action,
            "mcp_list_installed"
                | "mcp_discover"
                | "mcp_hot_list_tools"
                | "mcp_hot_call_tool"
        )
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

    pub(crate) fn fail_closed_in_place(&mut self, reason: String) {
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
