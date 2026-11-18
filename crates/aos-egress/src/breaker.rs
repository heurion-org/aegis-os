//! Session-level and shared-pool budget & loop circuit breakers for L7 model proxies.
//!
//! Enforces:
//! - Lock-free `SharedBudgetPool` (`AtomicU64` CAS) preventing overspend across concurrent agents.
//! - Per-session `BudgetPolicy` (max USD cost in integer `micro_usd`, max tokens, max requests).
//! - Consecutive identical/failing tool-turn `LoopDetected` circuit tripping.
//! - Multi-provider token usage extraction (Anthropic, OpenAI Chat/Responses, Gemini) across both
//!   SSE streams and non-streaming JSON responses.

use crate::pricing::ModelPricingTable;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Budget & loop protection thresholds attached to a session or `SharedBudgetPool`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cost_micro_usd: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_requests: Option<u32>,
    /// Number of consecutive identical or failing identical tool calls before tripping.
    /// Set to `0` to disable loop detection while keeping token/USD caps active.
    #[serde(default = "default_loop_streak")]
    pub max_identical_loop_streak: u32,
}

fn default_loop_streak() -> u32 {
    4
}

impl Default for BudgetPolicy {
    fn default() -> Self {
        Self {
            max_tokens: None,
            max_cost_micro_usd: None,
            max_requests: None,
            max_identical_loop_streak: default_loop_streak(),
        }
    }
}

/// Structured reason explaining why a session or shared pool tripped its circuit breaker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum CircuitTripReason {
    SessionBudgetExceeded {
        spent_micro_usd: u64,
        limit_micro_usd: u64,
    },
    PoolBudgetExceeded {
        pool_id: String,
        spent_micro_usd: u64,
        limit_micro_usd: u64,
    },
    TokenLimitExceeded {
        used_tokens: u64,
        limit_tokens: u64,
    },
    RequestLimitExceeded {
        requests: u32,
        limit_requests: u32,
    },
    LoopDetected {
        streak: u32,
        threshold: u32,
        tool_signature: String,
    },
}

/// Point-in-time usage & protection telemetry for an agent session.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageSnapshot {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cached_input_tokens: u64,
    pub requests: u32,
    pub cost_micro_usd: u64,
    pub pseudonyms_active: usize,
    pub pseudonym_replacements: u64,
    pub dlp_blocks: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tripped: Option<CircuitTripReason>,
}

/// Structured event emitted to host runtime/audit sinks when the gateway intervenes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum EgressGuardEvent {
    CircuitTripped {
        org_id: String,
        agent_id: String,
        reason: CircuitTripReason,
        usage: UsageSnapshot,
    },
    BudgetExtended {
        org_id: String,
        agent_id: String,
        add_micro_usd: u64,
        add_tokens: u64,
        add_requests: u32,
    },
    DlpBlocked {
        org_id: String,
        agent_id: String,
        domain: String,
        placeholder: String,
    },
}

/// Token consumption extracted from a single upstream model API response (streaming or JSON).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsageReport {
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cached_input_tokens: u64,
}

impl UsageReport {
    pub fn total_tokens(&self) -> u64 {
        self.input_tokens
            .saturating_add(self.output_tokens)
            .saturating_add(self.cached_input_tokens)
    }
}

/// Reservation ticket returned by `SharedBudgetPool::try_reserve`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PoolReservation {
    pub reserved_cost_micro_usd: u64,
    pub reserved_tokens: u64,
}

/// Lock-free atomic budget pool shared across concurrent sessions / exploration paths.
pub struct SharedBudgetPool {
    pool_id: String,
    max_cost_micro_usd: AtomicU64,
    max_tokens: AtomicU64,
    spent_cost_micro_usd: AtomicU64,
    used_tokens: AtomicU64,
}

impl SharedBudgetPool {
    pub fn new(
        pool_id: impl Into<String>,
        max_cost_micro_usd: Option<u64>,
        max_tokens: Option<u64>,
    ) -> Self {
        Self {
            pool_id: pool_id.into(),
            max_cost_micro_usd: AtomicU64::new(max_cost_micro_usd.unwrap_or(u64::MAX)),
            max_tokens: AtomicU64::new(max_tokens.unwrap_or(u64::MAX)),
            spent_cost_micro_usd: AtomicU64::new(0),
            used_tokens: AtomicU64::new(0),
        }
    }

    pub fn pool_id(&self) -> &str {
        &self.pool_id
    }

    pub fn spent_cost_micro_usd(&self) -> u64 {
        self.spent_cost_micro_usd.load(Ordering::Acquire)
    }

    pub fn used_tokens(&self) -> u64 {
        self.used_tokens.load(Ordering::Acquire)
    }

    pub fn extend(&self, add_cost_micro_usd: u64, add_tokens: u64) {
        if add_cost_micro_usd > 0 {
            let mut cur = self.max_cost_micro_usd.load(Ordering::Acquire);
            while cur != u64::MAX {
                let next = cur.saturating_add(add_cost_micro_usd);
                match self.max_cost_micro_usd.compare_exchange_weak(
                    cur,
                    next,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(actual) => cur = actual,
                }
            }
        }
        if add_tokens > 0 {
            let mut cur = self.max_tokens.load(Ordering::Acquire);
            while cur != u64::MAX {
                let next = cur.saturating_add(add_tokens);
                match self.max_tokens.compare_exchange_weak(
                    cur,
                    next,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(actual) => cur = actual,
                }
            }
        }
    }

    /// Atomically reserves `min_cost` micro-USD and `min_tokens` tokens using CAS loops so
    /// concurrent callers cannot overshoot pool caps. Also checks an optional per-lane `soft_cap_bps`
    /// (`6000` = 60%) against `lane_spent_after`.
    pub fn try_reserve(
        &self,
        min_cost_micro_usd: u64,
        min_tokens: u64,
        soft_cap_bps: Option<u16>,
        lane_spent_after: u64,
    ) -> Result<PoolReservation, CircuitTripReason> {
        let max_cost = self.max_cost_micro_usd.load(Ordering::Acquire);
        if let Some(bps) = soft_cap_bps {
            if max_cost != u64::MAX {
                let soft_limit =
                    u64::try_from(u128::from(max_cost) * u128::from(bps) / 10_000)
                        .unwrap_or(max_cost);
                if lane_spent_after > soft_limit {
                    return Err(CircuitTripReason::PoolBudgetExceeded {
                        pool_id: self.pool_id.clone(),
                        spent_micro_usd: lane_spent_after,
                        limit_micro_usd: soft_limit,
                    });
                }
            }
        }

        // 1. Reserve cost atomically.
        let mut cur_cost = self.spent_cost_micro_usd.load(Ordering::Acquire);
        loop {
            let next_cost = cur_cost.saturating_add(min_cost_micro_usd);
            if max_cost != u64::MAX && next_cost > max_cost {
                return Err(CircuitTripReason::PoolBudgetExceeded {
                    pool_id: self.pool_id.clone(),
                    spent_micro_usd: cur_cost,
                    limit_micro_usd: max_cost,
                });
            }
            match self.spent_cost_micro_usd.compare_exchange_weak(
                cur_cost,
                next_cost,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => cur_cost = actual,
            }
        }

        // 2. Reserve tokens atomically; roll back cost if tokens exceed cap.
        let max_tok = self.max_tokens.load(Ordering::Acquire);
        let mut cur_tok = self.used_tokens.load(Ordering::Acquire);
        loop {
            let next_tok = cur_tok.saturating_add(min_tokens);
            if max_tok != u64::MAX && next_tok > max_tok {
                Self::saturating_sub_atomic(&self.spent_cost_micro_usd, min_cost_micro_usd);
                return Err(CircuitTripReason::TokenLimitExceeded {
                    used_tokens: cur_tok,
                    limit_tokens: max_tok,
                });
            }
            match self.used_tokens.compare_exchange_weak(
                cur_tok,
                next_tok,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => cur_tok = actual,
            }
        }

        Ok(PoolReservation {
            reserved_cost_micro_usd: min_cost_micro_usd,
            reserved_tokens: min_tokens,
        })
    }

    /// Reconciles pre-flight reservations with actual upstream usage.
    pub fn settle(
        &self,
        reservation: PoolReservation,
        actual_cost_micro_usd: u64,
        actual_tokens: u64,
    ) {
        if actual_cost_micro_usd >= reservation.reserved_cost_micro_usd {
            self.spent_cost_micro_usd.fetch_add(
                actual_cost_micro_usd - reservation.reserved_cost_micro_usd,
                Ordering::AcqRel,
            );
        } else {
            Self::saturating_sub_atomic(
                &self.spent_cost_micro_usd,
                reservation.reserved_cost_micro_usd - actual_cost_micro_usd,
            );
        }

        if actual_tokens >= reservation.reserved_tokens {
            self.used_tokens.fetch_add(
                actual_tokens - reservation.reserved_tokens,
                Ordering::AcqRel,
            );
        } else {
            Self::saturating_sub_atomic(
                &self.used_tokens,
                reservation.reserved_tokens - actual_tokens,
            );
        }
    }

    pub fn release(&self, reservation: PoolReservation) {
        Self::saturating_sub_atomic(&self.spent_cost_micro_usd, reservation.reserved_cost_micro_usd);
        Self::saturating_sub_atomic(&self.used_tokens, reservation.reserved_tokens);
    }

    fn saturating_sub_atomic(target: &AtomicU64, delta: u64) {
        if delta == 0 {
            return;
        }
        let mut cur = target.load(Ordering::Acquire);
        loop {
            let next = cur.saturating_sub(delta);
            match target.compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
    }
}

/// Active pre-flight reservation for a single HTTP request in `SessionBreakerState`.
#[derive(Debug, Clone)]
pub struct PreFlightReservation {
    pub model: String,
    pub reserved_cost_micro_usd: u64,
    pub reserved_tokens: u64,
    pub pool_reservation: Option<PoolReservation>,
}

struct SessionBreakerInner {
    policy: BudgetPolicy,
    shared_pool: Option<Arc<SharedBudgetPool>>,
    soft_cap_bps: Option<u16>,
    input_tokens: u64,
    output_tokens: u64,
    cached_input_tokens: u64,
    requests: u32,
    spent_cost_micro_usd: u64,
    inflight_cost_micro_usd: u64,
    inflight_tokens: u64,
    last_tool_turn: Option<String>,
    loop_streak: u32,
    tripped: Option<CircuitTripReason>,
}

/// Per-agent session breaker state managing request caps, cost caps, loop streaks, and pool linkage.
pub struct SessionBreakerState {
    org_id: String,
    agent_id: String,
    dlp_blocks: AtomicU32,
    inner: Mutex<SessionBreakerInner>,
}

impl SessionBreakerState {
    pub fn new(
        org_id: impl Into<String>,
        agent_id: impl Into<String>,
        policy: BudgetPolicy,
        shared_pool: Option<Arc<SharedBudgetPool>>,
        soft_cap_bps: Option<u16>,
    ) -> Self {
        Self {
            org_id: org_id.into(),
            agent_id: agent_id.into(),
            dlp_blocks: AtomicU32::new(0),
            inner: Mutex::new(SessionBreakerInner {
                policy,
                shared_pool,
                soft_cap_bps,
                input_tokens: 0,
                output_tokens: 0,
                cached_input_tokens: 0,
                requests: 0,
                spent_cost_micro_usd: 0,
                inflight_cost_micro_usd: 0,
                inflight_tokens: 0,
                last_tool_turn: None,
                loop_streak: 0,
                tripped: None,
            }),
        }
    }

    pub fn update_policy(
        &self,
        policy: BudgetPolicy,
        shared_pool: Option<Arc<SharedBudgetPool>>,
        soft_cap_bps: Option<u16>,
    ) {
        let mut g = self.inner.lock().expect("breaker lock poisoned");
        g.policy = policy;
        g.shared_pool = shared_pool;
        g.soft_cap_bps = soft_cap_bps;
    }

    pub fn record_dlp_block(&self) {
        self.dlp_blocks.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self, pseudonyms_active: usize, pseudonym_replacements: u64) -> UsageSnapshot {
        let g = self.inner.lock().expect("breaker lock poisoned");
        UsageSnapshot {
            input_tokens: g.input_tokens,
            output_tokens: g.output_tokens,
            cached_input_tokens: g.cached_input_tokens,
            requests: g.requests,
            cost_micro_usd: g.spent_cost_micro_usd,
            pseudonyms_active,
            pseudonym_replacements,
            dlp_blocks: self.dlp_blocks.load(Ordering::Relaxed),
            tripped: g.tripped.clone(),
        }
    }

    /// Extends session (and linked pool) budgets and resets any active tripwire.
    pub fn extend_budget(
        &self,
        add_micro_usd: u64,
        add_tokens: u64,
        add_requests: u32,
    ) -> EgressGuardEvent {
        let mut g = self.inner.lock().expect("breaker lock poisoned");
        if add_micro_usd > 0 {
            g.policy.max_cost_micro_usd = Some(
                g.policy
                    .max_cost_micro_usd
                    .unwrap_or(g.spent_cost_micro_usd)
                    .saturating_add(add_micro_usd),
            );
        }
        if add_tokens > 0 {
            let current = g
                .input_tokens
                .saturating_add(g.output_tokens)
                .saturating_add(g.cached_input_tokens);
            g.policy.max_tokens = Some(
                g.policy
                    .max_tokens
                    .unwrap_or(current)
                    .saturating_add(add_tokens),
            );
        }
        if add_requests > 0 {
            g.policy.max_requests = Some(
                g.policy
                    .max_requests
                    .unwrap_or(g.requests)
                    .saturating_add(add_requests),
            );
        }
        g.tripped = None;
        g.loop_streak = 0;
        g.last_tool_turn = None;
        let pool = g.shared_pool.clone();
        drop(g);

        if let Some(ref pool) = pool {
            pool.extend(add_micro_usd, add_tokens);
        }
        EgressGuardEvent::BudgetExtended {
            org_id: self.org_id.clone(),
            agent_id: self.agent_id.clone(),
            add_micro_usd,
            add_tokens,
            add_requests,
        }
    }

    /// Pre-flight checks loop streaks, request counts, session caps, and shared pool caps.
    /// Emits `Some(EgressGuardEvent::CircuitTripped)` ONLY on the initial trip transition.
    pub fn pre_flight_check_and_reserve(
        &self,
        req_body: &[u8],
        pricing: &ModelPricingTable,
    ) -> Result<PreFlightReservation, Box<(CircuitTripReason, Option<EgressGuardEvent>)>> {
        let parsed = serde_json::from_slice::<Value>(req_body).ok();
        let model = parsed
            .as_ref()
            .and_then(|v| v.get("model").and_then(|m| m.as_str()))
            .unwrap_or("default")
            .to_string();
        let tool_turn = parsed
            .as_ref()
            .and_then(extract_latest_tool_turn_fingerprint);

        let est_in = ((req_body.len() / 4) as u64).max(1);
        let est_cost = pricing.estimate_preflight_cost_micro_usd(&model, est_in);

        let mut g = self.inner.lock().expect("breaker lock poisoned");
        if let Some(ref existing) = g.tripped {
            return Err(Box::new((existing.clone(), None)));
        }

        let make_trip_err = |g: &mut SessionBreakerInner, reason: CircuitTripReason| {
            g.tripped = Some(reason.clone());
            let snap = self.snapshot_locked(g);
            Box::new((
                reason.clone(),
                Some(EgressGuardEvent::CircuitTripped {
                    org_id: self.org_id.clone(),
                    agent_id: self.agent_id.clone(),
                    reason,
                    usage: snap,
                }),
            ))
        };

        if let Some(max_req) = g.policy.max_requests {
            if g.requests >= max_req {
                let reason = CircuitTripReason::RequestLimitExceeded {
                    requests: g.requests,
                    limit_requests: max_req,
                };
                return Err(make_trip_err(&mut g, reason));
            }
        }

        if g.policy.max_identical_loop_streak > 0 {
            if let Some(ref turn) = tool_turn {
                if g.last_tool_turn.as_ref() == Some(&turn.signature) {
                    g.loop_streak = g.loop_streak.saturating_add(1);
                } else {
                    g.last_tool_turn = Some(turn.signature.clone());
                    g.loop_streak = 1;
                }
                if g.loop_streak >= g.policy.max_identical_loop_streak {
                    let reason = CircuitTripReason::LoopDetected {
                        streak: g.loop_streak,
                        threshold: g.policy.max_identical_loop_streak,
                        tool_signature: turn.display_name.clone(),
                    };
                    return Err(make_trip_err(&mut g, reason));
                }
            } else {
                g.last_tool_turn = None;
                g.loop_streak = 0;
            }
        }

        let cur_tokens = g
            .input_tokens
            .saturating_add(g.output_tokens)
            .saturating_add(g.cached_input_tokens)
            .saturating_add(g.inflight_tokens);
        if let Some(max_tok) = g.policy.max_tokens {
            if cur_tokens.saturating_add(est_in) > max_tok {
                let reason = CircuitTripReason::TokenLimitExceeded {
                    used_tokens: cur_tokens,
                    limit_tokens: max_tok,
                };
                return Err(make_trip_err(&mut g, reason));
            }
        }

        let cur_cost = g
            .spent_cost_micro_usd
            .saturating_add(g.inflight_cost_micro_usd);
        if let Some(max_cost) = g.policy.max_cost_micro_usd {
            if cur_cost.saturating_add(est_cost) > max_cost {
                let reason = CircuitTripReason::SessionBudgetExceeded {
                    spent_micro_usd: cur_cost,
                    limit_micro_usd: max_cost,
                };
                return Err(make_trip_err(&mut g, reason));
            }
        }

        let pool_reservation = if let Some(ref pool) = g.shared_pool {
            let lane_after = cur_cost.saturating_add(est_cost);
            match pool.try_reserve(est_cost, est_in, g.soft_cap_bps, lane_after) {
                Ok(res) => Some(res),
                Err(reason) => {
                    return Err(make_trip_err(&mut g, reason));
                }
            }
        } else {
            None
        };

        g.requests = g.requests.saturating_add(1);
        g.inflight_tokens = g.inflight_tokens.saturating_add(est_in);
        g.inflight_cost_micro_usd = g.inflight_cost_micro_usd.saturating_add(est_cost);

        Ok(PreFlightReservation {
            model,
            reserved_cost_micro_usd: est_cost,
            reserved_tokens: est_in,
            pool_reservation,
        })
    }

    pub fn settle_reservation(
        &self,
        res: PreFlightReservation,
        usage: &UsageReport,
        pricing: &ModelPricingTable,
    ) -> Option<EgressGuardEvent> {
        let model_name = if usage.model.is_empty() {
            res.model.as_str()
        } else {
            usage.model.as_str()
        };
        let actual_tokens = usage.total_tokens();
        let actual_cost = if actual_tokens > 0 {
            pricing.compute_cost_micro_usd(
                model_name,
                usage.input_tokens,
                usage.output_tokens,
                usage.cached_input_tokens,
            )
        } else {
            0
        };

        let mut g = self.inner.lock().expect("breaker lock poisoned");
        let pool = g.shared_pool.clone();
        g.inflight_tokens = g.inflight_tokens.saturating_sub(res.reserved_tokens);
        g.inflight_cost_micro_usd = g
            .inflight_cost_micro_usd
            .saturating_sub(res.reserved_cost_micro_usd);
        g.input_tokens = g.input_tokens.saturating_add(usage.input_tokens);
        g.output_tokens = g.output_tokens.saturating_add(usage.output_tokens);
        g.cached_input_tokens = g.cached_input_tokens.saturating_add(usage.cached_input_tokens);
        g.spent_cost_micro_usd = g.spent_cost_micro_usd.saturating_add(actual_cost);
        let trip_event = if g.tripped.is_none() {
            let total_tokens = g
                .input_tokens
                .saturating_add(g.output_tokens)
                .saturating_add(g.cached_input_tokens);
            if let Some(max_tok) = g.policy.max_tokens {
                if total_tokens > max_tok {
                    let reason = CircuitTripReason::TokenLimitExceeded {
                        used_tokens: total_tokens,
                        limit_tokens: max_tok,
                    };
                    g.tripped = Some(reason.clone());
                    let snap = self.snapshot_locked(&g);
                    Some(EgressGuardEvent::CircuitTripped {
                        org_id: self.org_id.clone(),
                        agent_id: self.agent_id.clone(),
                        reason,
                        usage: snap,
                    })
                } else {
                    None
                }
            } else {
                None
            }
            .or_else(|| {
                if let Some(max_cost) = g.policy.max_cost_micro_usd {
                    if g.spent_cost_micro_usd > max_cost {
                        let reason = CircuitTripReason::SessionBudgetExceeded {
                            spent_micro_usd: g.spent_cost_micro_usd,
                            limit_micro_usd: max_cost,
                        };
                        g.tripped = Some(reason.clone());
                        let snap = self.snapshot_locked(&g);
                        return Some(EgressGuardEvent::CircuitTripped {
                            org_id: self.org_id.clone(),
                            agent_id: self.agent_id.clone(),
                            reason,
                            usage: snap,
                        });
                    }
                }
                None
            })
        } else {
            None
        };
        drop(g);

        if let (Some(ref pool), Some(pool_res)) = (pool, res.pool_reservation) {
            pool.settle(pool_res, actual_cost, actual_tokens);
        }
        trip_event
    }

    pub fn cancel_reservation(&self, res: PreFlightReservation) {
        let mut g = self.inner.lock().expect("breaker lock poisoned");
        let pool = g.shared_pool.clone();
        g.requests = g.requests.saturating_sub(1);
        g.inflight_tokens = g.inflight_tokens.saturating_sub(res.reserved_tokens);
        g.inflight_cost_micro_usd = g
            .inflight_cost_micro_usd
            .saturating_sub(res.reserved_cost_micro_usd);
        drop(g);

        if let (Some(ref pool), Some(pool_res)) = (pool, res.pool_reservation) {
            pool.release(pool_res);
        }
    }

    fn snapshot_locked(&self, g: &SessionBreakerInner) -> UsageSnapshot {
        UsageSnapshot {
            input_tokens: g.input_tokens,
            output_tokens: g.output_tokens,
            cached_input_tokens: g.cached_input_tokens,
            requests: g.requests,
            cost_micro_usd: g.spent_cost_micro_usd,
            pseudonyms_active: 0,
            pseudonym_replacements: 0,
            dlp_blocks: self.dlp_blocks.load(Ordering::Relaxed),
            tripped: g.tripped.clone(),
        }
    }
}

/// Automatically injects `stream_options.include_usage = true` for streaming OpenAI Chat
/// Completions calls when budget accounting is enabled so upstream reports final token usage.
pub fn maybe_inject_openai_include_usage(domain: &str, path: &str, body: &[u8]) -> Option<Vec<u8>> {
    let is_openai_chat = domain.eq_ignore_ascii_case("api.openai.com")
        && path.contains("/chat/completions")
        || path.ends_with("/v1/chat/completions");
    if !is_openai_chat || body.is_empty() {
        return None;
    }
    let mut val: Value = serde_json::from_slice(body).ok()?;
    let obj = val.as_object_mut()?;
    if obj.get("stream").and_then(|v| v.as_bool()) != Some(true) {
        return None;
    }
    match obj.get_mut("stream_options") {
        Some(Value::Object(so)) => {
            if so.get("include_usage").and_then(|v| v.as_bool()) == Some(true) {
                return None;
            }
            so.insert("include_usage".to_string(), Value::Bool(true));
        }
        Some(_) => return None,
        None => {
            obj.insert("stream_options".to_string(), json!({ "include_usage": true }));
        }
    }
    serde_json::to_vec(&val).ok()
}

/// Formats an SDK-compatible HTTP `429 Too Many Requests` JSON response when tripped.
pub fn format_tripwire_http_429(reason: &CircuitTripReason) -> String {
    let msg = match reason {
        CircuitTripReason::SessionBudgetExceeded {
            spent_micro_usd,
            limit_micro_usd,
        } => format!(
            "Aegis OS budget circuit breaker tripped: session spent ${:.4} >= limit ${:.4}. Stop retrying and report progress to the user.",
            *spent_micro_usd as f64 / 1_000_000.0,
            *limit_micro_usd as f64 / 1_000_000.0,
        ),
        CircuitTripReason::PoolBudgetExceeded {
            pool_id,
            spent_micro_usd,
            limit_micro_usd,
        } => format!(
            "Aegis OS shared pool '{pool_id}' budget tripped (${:.4} / ${:.4}). Stop retrying and summarize work completed.",
            *spent_micro_usd as f64 / 1_000_000.0,
            *limit_micro_usd as f64 / 1_000_000.0,
        ),
        CircuitTripReason::TokenLimitExceeded {
            used_tokens,
            limit_tokens,
        } => format!(
            "Aegis OS token circuit breaker tripped ({used_tokens} / {limit_tokens} tokens). Stop retrying and report progress."
        ),
        CircuitTripReason::RequestLimitExceeded {
            requests,
            limit_requests,
        } => format!(
            "Aegis OS request circuit breaker tripped ({requests} / {limit_requests} requests). Stop retrying and report progress."
        ),
        CircuitTripReason::LoopDetected {
            streak,
            threshold,
            tool_signature,
        } => format!(
            "Aegis OS loop detector tripped: repeated tool call '{tool_signature}' {streak} times (threshold {threshold}). Change approach or ask the user for guidance."
        ),
    };
    let body = json!({
        "type": "error",
        "error": {
            "type": "rate_limit_error",
            "code": "aegis_circuit_tripped",
            "message": msg,
        },
        "aegis_trip_reason": reason,
    })
    .to_string();
    format!(
        "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nRetry-After: 300\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

struct ToolTurnFingerprint {
    signature: String,
    display_name: String,
}

fn sha256_short(input: &str) -> String {
    let mut h = Sha256::new();
    h.update(input.as_bytes());
    hex::encode(&h.finalize()[..12])
}

fn result_looks_like_failure(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("\"is_error\":true")
        || lower.contains("\"is_error\": true")
        || lower.contains("error:")
        || lower.contains("failed")
        || lower.contains("denied")
        || lower.contains("forbidden")
        || lower.contains("timed out")
        || lower.contains("traceback")
        || lower.contains("exception")
        || (lower.contains("exit code") && !lower.contains("exit code 0") && !lower.contains("exit code: 0"))
}

fn extract_latest_tool_turn_fingerprint(req: &Value) -> Option<ToolTurnFingerprint> {
    // 1. Anthropic Messages API (`messages[]` with assistant `tool_use` + user `tool_result`).
    if let Some(messages) = req.get("messages").and_then(|v| v.as_array()) {
        if let Some(last) = messages.last() {
            let role = last.get("role").and_then(|v| v.as_str()).unwrap_or("");
            if role == "user" {
                if let Some(blocks) = last.get("content").and_then(|v| v.as_array()) {
                    if let Some(tr) = blocks
                        .iter()
                        .rev()
                        .find(|b| b.get("type").and_then(|t| t.as_str()) == Some("tool_result"))
                    {
                        let tool_use_id = tr.get("tool_use_id").and_then(|v| v.as_str()).unwrap_or("");
                        let is_err = tr.get("is_error").and_then(|v| v.as_bool()) == Some(true);
                        let res_text = tr
                            .get("content")
                            .map(|c| c.to_string())
                            .unwrap_or_default();
                        let failing = is_err || result_looks_like_failure(&res_text);
                        for prev in messages.iter().rev().skip(1) {
                            if prev.get("role").and_then(|v| v.as_str()) != Some("assistant") {
                                continue;
                            }
                            if let Some(pblocks) = prev.get("content").and_then(|v| v.as_array()) {
                                if let Some(tu) = pblocks.iter().find(|b| {
                                    b.get("type").and_then(|t| t.as_str()) == Some("tool_use")
                                        && (tool_use_id.is_empty()
                                            || b.get("id").and_then(|i| i.as_str()) == Some(tool_use_id))
                                }) {
                                    let name = tu.get("name").and_then(|v| v.as_str()).unwrap_or("tool");
                                    let input_str = tu.get("input").map(|v| v.to_string()).unwrap_or_default();
                                    let key = if failing {
                                        format!("anthropic:{name}:fail:{}", sha256_short(&input_str))
                                    } else {
                                        format!(
                                            "anthropic:{name}:same:{}:{}",
                                            sha256_short(&input_str),
                                            sha256_short(&res_text)
                                        )
                                    };
                                    return Some(ToolTurnFingerprint {
                                        signature: sha256_short(&key),
                                        display_name: name.to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }

            // 2. OpenAI Chat Completions (`role: "tool"` + matching `assistant.tool_calls`).
            if role == "tool" {
                let call_id = last.get("tool_call_id").and_then(|v| v.as_str()).unwrap_or("");
                let res_text = last
                    .get("content")
                    .map(|c| c.to_string())
                    .unwrap_or_default();
                let failing = result_looks_like_failure(&res_text);
                for prev in messages.iter().rev().skip(1) {
                    if prev.get("role").and_then(|v| v.as_str()) != Some("assistant") {
                        continue;
                    }
                    if let Some(tcs) = prev.get("tool_calls").and_then(|v| v.as_array()) {
                        if let Some(tc) = tcs.iter().find(|tc| {
                            call_id.is_empty() || tc.get("id").and_then(|i| i.as_str()) == Some(call_id)
                        }) {
                            let name = tc
                                .pointer("/function/name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("tool");
                            let args_str = tc
                                .pointer("/function/arguments")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let key = if failing {
                                format!("openai:{name}:fail:{}", sha256_short(args_str))
                            } else {
                                format!(
                                    "openai:{name}:same:{}:{}",
                                    sha256_short(args_str),
                                    sha256_short(&res_text)
                                )
                            };
                            return Some(ToolTurnFingerprint {
                                signature: sha256_short(&key),
                                display_name: name.to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    // 3. OpenAI Responses API (`input[]` trailing `function_call_output`).
    if let Some(input_items) = req.get("input").and_then(|v| v.as_array()) {
        if let Some(last) = input_items.last() {
            if last.get("type").and_then(|v| v.as_str()) == Some("function_call_output") {
                let call_id = last.get("call_id").and_then(|v| v.as_str()).unwrap_or("");
                let out_str = last.get("output").map(|v| v.to_string()).unwrap_or_default();
                let failing = result_looks_like_failure(&out_str);
                for prev in input_items.iter().rev().skip(1) {
                    if prev.get("type").and_then(|v| v.as_str()) == Some("function_call")
                        && (call_id.is_empty()
                            || prev.get("call_id").and_then(|v| v.as_str()) == Some(call_id))
                    {
                        let name = prev.get("name").and_then(|v| v.as_str()).unwrap_or("tool");
                        let args_str = prev.get("arguments").and_then(|v| v.as_str()).unwrap_or("");
                        let key = if failing {
                            format!("responses:{name}:fail:{}", sha256_short(args_str))
                        } else {
                            format!(
                                "responses:{name}:same:{}:{}",
                                sha256_short(args_str),
                                sha256_short(&out_str)
                            )
                        };
                        return Some(ToolTurnFingerprint {
                            signature: sha256_short(&key),
                            display_name: name.to_string(),
                        });
                    }
                }
            }
        }
    }

    // 4. Gemini (`contents[]` trailing `functionResponse` + prior `functionCall`).
    if let Some(contents) = req.get("contents").and_then(|v| v.as_array()) {
        if let Some(last) = contents.last() {
            if let Some(parts) = last.get("parts").and_then(|v| v.as_array()) {
                if let Some(fr) = parts.iter().rev().find_map(|p| p.get("functionResponse")) {
                    let name = fr.get("name").and_then(|v| v.as_str()).unwrap_or("tool");
                    let resp_str = fr.get("response").map(|v| v.to_string()).unwrap_or_default();
                    let failing = result_looks_like_failure(&resp_str);
                    for prev in contents.iter().rev().skip(1) {
                        if let Some(pparts) = prev.get("parts").and_then(|v| v.as_array()) {
                            if let Some(fc) = pparts.iter().rev().find_map(|p| p.get("functionCall")) {
                                if fc.get("name").and_then(|v| v.as_str()) == Some(name) {
                                    let args_str = fc.get("args").map(|v| v.to_string()).unwrap_or_default();
                                    let key = if failing {
                                        format!("gemini:{name}:fail:{}", sha256_short(&args_str))
                                    } else {
                                        format!(
                                            "gemini:{name}:same:{}:{}",
                                            sha256_short(&args_str),
                                            sha256_short(&resp_str)
                                        )
                                    };
                                    return Some(ToolTurnFingerprint {
                                        signature: sha256_short(&key),
                                        display_name: name.to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

/// Accumulates token usage metrics across SSE frames or non-streaming JSON responses.
#[derive(Debug, Default)]
pub struct UsageAccumulator {
    report: UsageReport,
}

impl UsageAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn into_report(self) -> UsageReport {
        self.report
    }

    pub fn observe_json(&mut self, val: &Value) {
        if let Some(m) = val
            .get("model")
            .or_else(|| val.pointer("/message/model"))
            .or_else(|| val.get("modelVersion"))
            .and_then(|v| v.as_str())
        {
            if !m.trim().is_empty() {
                self.report.model = m.to_string();
            }
        }

        // Anthropic `message_start` wraps usage under `/message/usage`; `message_delta` and
        // non-streaming JSON place it under `/usage`.
        for u in [val.pointer("/message/usage"), val.get("usage")]
            .into_iter()
            .flatten()
        {
            if let Some(inp) = u
                .get("input_tokens")
                .or_else(|| u.get("prompt_tokens"))
                .and_then(|v| v.as_u64())
            {
                self.report.input_tokens = self.report.input_tokens.max(inp);
            }
            if let Some(out) = u
                .get("output_tokens")
                .or_else(|| u.get("completion_tokens"))
                .and_then(|v| v.as_u64())
            {
                self.report.output_tokens = self.report.output_tokens.max(out);
            }
            let cached = u
                .get("cache_read_input_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .saturating_add(
                    u.get("cache_creation_input_tokens")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                )
                .max(
                    u.pointer("/prompt_tokens_details/cached_tokens")
                        .or_else(|| u.pointer("/input_tokens_details/cached_tokens"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                );
            if cached > 0 {
                self.report.cached_input_tokens = self.report.cached_input_tokens.max(cached);
            }
        }

        // OpenAI Responses API `response.completed` wraps usage at `/response/usage`.
        if let Some(ru) = val.pointer("/response/usage") {
            if let Some(m) = val.pointer("/response/model").and_then(|v| v.as_str()) {
                if !m.trim().is_empty() {
                    self.report.model = m.to_string();
                }
            }
            if let Some(inp) = ru.get("input_tokens").and_then(|v| v.as_u64()) {
                self.report.input_tokens = self.report.input_tokens.max(inp);
            }
            if let Some(out) = ru.get("output_tokens").and_then(|v| v.as_u64()) {
                self.report.output_tokens = self.report.output_tokens.max(out);
            }
            if let Some(cached) = ru
                .pointer("/input_tokens_details/cached_tokens")
                .and_then(|v| v.as_u64())
            {
                self.report.cached_input_tokens = self.report.cached_input_tokens.max(cached);
            }
        }

        // Gemini `usageMetadata`.
        if let Some(gm) = val.get("usageMetadata") {
            if let Some(inp) = gm.get("promptTokenCount").and_then(|v| v.as_u64()) {
                self.report.input_tokens = self.report.input_tokens.max(inp);
            }
            if let Some(out) = gm.get("candidatesTokenCount").and_then(|v| v.as_u64()) {
                self.report.output_tokens = self.report.output_tokens.max(out);
            }
            if let Some(cached) = gm.get("cachedContentTokenCount").and_then(|v| v.as_u64()) {
                self.report.cached_input_tokens = self.report.cached_input_tokens.max(cached);
            }
        }
    }

    pub fn observe_body_bytes(&mut self, body: &[u8]) {
        if body.is_empty() {
            return;
        }
        if let Ok(val) = serde_json::from_slice::<Value>(body) {
            self.observe_json(&val);
            return;
        }
        let text = String::from_utf8_lossy(body);
        for line in text.lines() {
            if let Some(rest) = line.trim_end_matches('\r').strip_prefix("data:") {
                let payload = rest.trim();
                if payload != "[DONE]" {
                    if let Ok(val) = serde_json::from_str::<Value>(payload) {
                        self.observe_json(&val);
                    }
                }
            }
        }
    }
}

/// Incremental HTTP `Transfer-Encoding: chunked` decoder yielding exact de-chunked body slices.
#[derive(Debug, Default)]
pub struct HttpChunkedDecoder {
    buf: Vec<u8>,
    state: ChunkDecodeState,
}

#[derive(Debug, Default)]
enum ChunkDecodeState {
    #[default]
    SizeLine,
    Data {
        remaining: usize,
    },
    Trailer,
    Done,
}

impl HttpChunkedDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_done(&self) -> bool {
        matches!(self.state, ChunkDecodeState::Done)
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        loop {
            match self.state {
                ChunkDecodeState::Done => break,
                ChunkDecodeState::SizeLine => {
                    let Some(pos) = self.buf.windows(2).position(|w| w == b"\r\n") else {
                        break;
                    };
                    let line = String::from_utf8_lossy(&self.buf[..pos]).to_string();
                    self.buf.drain(..pos + 2);
                    let hex_part = line.split(';').next().unwrap_or("").trim();
                    let size = usize::from_str_radix(hex_part, 16)
                        .map_err(|_| format!("invalid chunked size line: '{line}'"))?;
                    if size == 0 {
                        self.state = ChunkDecodeState::Trailer;
                    } else {
                        self.state = ChunkDecodeState::Data { remaining: size };
                    }
                }
                ChunkDecodeState::Data { remaining } => {
                    if self.buf.len() < remaining + 2 {
                        let take = self.buf.len().min(remaining);
                        if take > 0 {
                            out.extend_from_slice(&self.buf[..take]);
                            self.buf.drain(..take);
                            self.state = ChunkDecodeState::Data {
                                remaining: remaining - take,
                            };
                        }
                        break;
                    }
                    if remaining > 0 {
                        out.extend_from_slice(&self.buf[..remaining]);
                        self.buf.drain(..remaining);
                    }
                    if self.buf.len() >= 2 && &self.buf[..2] == b"\r\n" {
                        self.buf.drain(..2);
                        self.state = ChunkDecodeState::SizeLine;
                    } else if self.buf.first() == Some(&b'\n') {
                        self.buf.drain(..1);
                        self.state = ChunkDecodeState::SizeLine;
                    } else {
                        break;
                    }
                }
                ChunkDecodeState::Trailer => {
                    if self.buf.starts_with(b"\r\n") {
                        self.buf.drain(..2);
                        self.state = ChunkDecodeState::Done;
                        break;
                    }
                    if let Some(pos) = self.buf.windows(2).position(|w| w == b"\r\n") {
                        self.buf.drain(..pos + 2);
                    } else {
                        break;
                    }
                }
            }
        }
        Ok(out)
    }
}

/// Zero-latency passthrough usage extractor used when budget tracking is active without body rewriting.
pub struct StreamingUsageTap {
    chunked: Option<HttpChunkedDecoder>,
    is_sse: bool,
    line_buf: Vec<u8>,
    json_buf: Vec<u8>,
    accumulator: UsageAccumulator,
}

impl StreamingUsageTap {
    pub fn new(is_chunked: bool, is_sse: bool) -> Self {
        Self {
            chunked: if is_chunked {
                Some(HttpChunkedDecoder::new())
            } else {
                None
            },
            is_sse,
            line_buf: Vec::new(),
            json_buf: Vec::new(),
            accumulator: UsageAccumulator::new(),
        }
    }

    pub fn push_wire_bytes(&mut self, bytes: &[u8]) {
        let decoded = if let Some(ref mut dec) = self.chunked {
            match dec.push(bytes) {
                Ok(v) => v,
                Err(_) => return,
            }
        } else {
            bytes.to_vec()
        };
        if decoded.is_empty() {
            return;
        }
        if self.is_sse {
            self.line_buf.extend_from_slice(&decoded);
            while let Some(pos) = self.line_buf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = self.line_buf.drain(..=pos).collect();
                let s = String::from_utf8_lossy(&line);
                if let Some(rest) = s.trim_end_matches(['\r', '\n']).strip_prefix("data:") {
                    let payload = rest.trim();
                    if payload != "[DONE]" {
                        if let Ok(val) = serde_json::from_str::<Value>(payload) {
                            self.accumulator.observe_json(&val);
                        }
                    }
                }
            }
        } else if self.json_buf.len() < 2usize * 1024 * 1024 {
            let avail = (2usize * 1024 * 1024).saturating_sub(self.json_buf.len());
            let take = avail.min(decoded.len());
            self.json_buf.extend_from_slice(&decoded[..take]);
        }
    }

    pub fn finish(mut self) -> UsageReport {
        if self.is_sse && !self.line_buf.is_empty() {
            let s = String::from_utf8_lossy(&self.line_buf);
            if let Some(rest) = s.trim_end_matches(['\r', '\n']).strip_prefix("data:") {
                let payload = rest.trim();
                if payload != "[DONE]" {
                    if let Ok(val) = serde_json::from_str::<Value>(payload) {
                        self.accumulator.observe_json(&val);
                    }
                }
            }
        } else if !self.is_sse && !self.json_buf.is_empty() {
            self.accumulator.observe_body_bytes(&self.json_buf);
        }
        self.accumulator.into_report()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shared_budget_pool_100_concurrent_requests_never_overshoots() {
        let pool = Arc::new(SharedBudgetPool::new(
            "pool-race",
            Some(1_000), // 1,000 micro-USD ($0.001)
            Some(5_000), // 5,000 tokens
        ));
        let pricing = Arc::new(ModelPricingTable::new());
        let mut handles = Vec::new();
        let granted_count = Arc::new(AtomicU32::new(0));

        // 100 concurrent lanes each requesting 100 micro-USD + 400 tokens => at most 10 succeed!
        for _ in 0..100 {
            let p = pool.clone();
            let cnt = granted_count.clone();
            let _pr = pricing.clone();
            handles.push(tokio::spawn(async move {
                if let Ok(res) = p.try_reserve(100, 400, None, 0) {
                    cnt.fetch_add(1, Ordering::AcqRel);
                    // Simulate settlement equal to reservation.
                    p.settle(res, 100, 400);
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(granted_count.load(Ordering::Acquire), 10);
        assert_eq!(pool.spent_cost_micro_usd(), 1_000);
        assert_eq!(pool.used_tokens(), 4_000);
    }

    #[test]
    fn loop_detector_trips_on_4_identical_failing_tool_turns_and_extend_unblocks() {
        let pricing = ModelPricingTable::new();
        let breaker = SessionBreakerState::new(
            "acme",
            "coder-1",
            BudgetPolicy {
                max_tokens: None,
                max_cost_micro_usd: Some(500_000),
                max_requests: None,
                max_identical_loop_streak: 4,
            },
            None,
            None,
        );
        let req_body = serde_json::to_vec(&json!({
            "model": "claude-sonnet-4-5",
            "messages": [
                {
                    "role": "assistant",
                    "content": [{
                        "type": "tool_use",
                        "id": "tu_1",
                        "name": "proc_exec",
                        "input": { "command": "cargo test --locked" }
                    }]
                },
                {
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": "tu_1",
                        "is_error": true,
                        "content": "error: linker cc failed"
                    }]
                }
            ]
        }))
        .unwrap();

        for i in 1..=3 {
            let res = breaker
                .pre_flight_check_and_reserve(&req_body, &pricing)
                .unwrap_or_else(|e| panic!("turn {i} should pass: {e:?}"));
            breaker.settle_reservation(
                res,
                &UsageReport {
                    model: "claude-sonnet-4-5".to_string(),
                    input_tokens: 100,
                    output_tokens: 20,
                    cached_input_tokens: 0,
                },
                &pricing,
            );
        }

        // Turn 4 trips LoopDetected!
        let err = breaker
            .pre_flight_check_and_reserve(&req_body, &pricing)
            .unwrap_err();
        assert!(matches!(
            err.0,
            CircuitTripReason::LoopDetected {
                streak: 4,
                threshold: 4,
                ..
            }
        ));
        assert!(err.1.is_some(), "initial trip must emit CircuitTripped event");

        // Subsequent call while tripped remains blocked and avoids duplicate initial event.
        let err2 = breaker
            .pre_flight_check_and_reserve(&req_body, &pricing)
            .unwrap_err();
        assert!(err2.1.is_none());

        // Human extends budget & resets tripwire.
        let ev = breaker.extend_budget(100_000, 0, 0);
        assert!(matches!(ev, EgressGuardEvent::BudgetExtended { .. }));
        let res_after = breaker
            .pre_flight_check_and_reserve(&req_body, &pricing)
            .expect("extend_budget resets tripped state");
        breaker.cancel_reservation(res_after);
    }

    #[test]
    fn openai_streaming_auto_injects_include_usage_and_accounts_tokens() {
        let req = serde_json::to_vec(&json!({
            "model": "gpt-4o",
            "stream": true,
            "messages": [{"role": "user", "content": "hi"}]
        }))
        .unwrap();
        let injected =
            maybe_inject_openai_include_usage("api.openai.com", "/v1/chat/completions", &req)
                .unwrap();
        let v: Value = serde_json::from_slice(&injected).unwrap();
        assert_eq!(v["stream_options"]["include_usage"], true);

        let mut tap = StreamingUsageTap::new(false, true);
        tap.push_wire_bytes(
            b"data: {\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n",
        );
        tap.push_wire_bytes(
            b"data: {\"model\":\"gpt-4o\",\"choices\":[],\"usage\":{\"prompt_tokens\":1200,\"completion_tokens\":300,\"prompt_tokens_details\":{\"cached_tokens\":200}}}\n\n",
        );
        tap.push_wire_bytes(b"data: [DONE]\n\n");
        let report = tap.finish();
        assert_eq!(report.model, "gpt-4o");
        assert_eq!(report.input_tokens, 1200);
        assert_eq!(report.output_tokens, 300);
        assert_eq!(report.cached_input_tokens, 200);
    }
}
