use super::*;

impl PaasControlPlane {
    /// Configure or upgrade a tenant's commercial plan tier (`Community`, `Pro`, `Team`, `Enterprise`).
    pub async fn set_tenant_plan(
        &self,
        org_id: &str,
        plan_tier: PlanTier,
    ) -> anyhow::Result<TenantUsageRecord> {
        let now = Utc::now().timestamp_millis();
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let org_owned = org_id.to_string();
        self.with_state_mut(|state| {
            let rec = if let Some(existing) = state.tenants.iter_mut().find(|t| t.org_id == org_owned) {
                existing.plan_tier = plan_tier;
                existing.max_concurrent_agents = plan_tier.max_concurrent_agents();
                if existing.active_agents.len() > existing.max_concurrent_agents {
                    existing
                        .active_agents
                        .truncate(existing.max_concurrent_agents);
                }
                existing.updated_at_ms = now;
                existing.clone()
            } else {
                let created = TenantUsageRecord {
                    org_id: org_owned.clone(),
                    plan_tier,
                    max_concurrent_agents: plan_tier.max_concurrent_agents(),
                    total_syscalls: 0,
                    sandbox_exec_ms: 0,
                    cow_saved_bytes: 0,
                    wake_count: 0,
                    quota_day_utc: today,
                    daily_syscalls: 0,
                    daily_exec_ms: 0,
                    active_agents: Vec::new(),
                    updated_at_ms: now,
                };
                state.tenants.push(created.clone());
                created
            };
            Ok(rec)
        })
        .await
    }

    /// Record MCP syscall, sandbox execution duration, and CoW storage savings for tenant billing/metering.
    pub async fn record_usage(
        &self,
        org_id: &str,
        workspace_id: Option<&str>,
        syscalls_delta: u64,
        exec_ms_delta: u64,
        cow_saved_delta: u64,
    ) -> anyhow::Result<()> {
        let now = Utc::now().timestamp_millis();
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let org_owned = org_id.to_string();
        let ws_owned = workspace_id.map(str::to_string);
        self.with_state_mut(|state| {
            if let Some(t) = state.tenants.iter_mut().find(|t| t.org_id == org_owned) {
                if t.quota_day_utc != today {
                    t.quota_day_utc = today.clone();
                    t.daily_syscalls = 0;
                    t.daily_exec_ms = 0;
                }
                t.total_syscalls = t.total_syscalls.saturating_add(syscalls_delta);
                t.sandbox_exec_ms = t.sandbox_exec_ms.saturating_add(exec_ms_delta);
                t.cow_saved_bytes = t.cow_saved_bytes.saturating_add(cow_saved_delta);
                t.daily_syscalls = t.daily_syscalls.saturating_add(syscalls_delta);
                t.daily_exec_ms = t.daily_exec_ms.saturating_add(exec_ms_delta);
                t.updated_at_ms = now;
            } else {
                state.tenants.push(TenantUsageRecord {
                    org_id: org_owned.clone(),
                    plan_tier: PlanTier::Community,
                    max_concurrent_agents: PlanTier::Community.max_concurrent_agents(),
                    total_syscalls: syscalls_delta,
                    sandbox_exec_ms: exec_ms_delta,
                    cow_saved_bytes: cow_saved_delta,
                    wake_count: 0,
                    quota_day_utc: today,
                    daily_syscalls: syscalls_delta,
                    daily_exec_ms: exec_ms_delta,
                    active_agents: Vec::new(),
                    updated_at_ms: now,
                });
            }
            if let Some(ref ws_id) = ws_owned {
                if let Some(ws) = state
                    .workspaces
                    .iter_mut()
                    .find(|w| w.org_id == org_owned && w.workspace_id == *ws_id)
                {
                    ws.last_active_ms = now;
                    ws.status = WorkspaceLifecycleState::Active;
                    ws.hibernated_at_ms = None;
                }
            }
            Ok(())
        })
        .await
    }

    /// Enforce commercial paywall quotas on `/v1/mcp` tool invocations:
    /// 1. Dynamic concurrent Agent limit (`max_concurrent_agents`: Free=1, Pro=8, Team=32)
    /// 2. Daily MCP syscall quota (`max_daily_syscalls`: Free=200/day, Pro=20,000/day)
    /// 3. Daily sandbox CPU execution time quota (`max_daily_exec_ms`: Free=10m/day, Pro=10h/day)
    pub async fn check_and_enforce_paywall(
        &self,
        org_id: &str,
        agent_id: &str,
        tool_name: &str,
    ) -> Result<PlanTier, Value> {
        let now = Utc::now().timestamp_millis();
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let clean_agent = agent_id.trim().to_string();
        let org_owned = org_id.to_string();
        let tool_owned = tool_name.to_string();

        let (
            tier,
            max_agents,
            daily_syscalls,
            max_syscalls,
            daily_exec_ms,
            max_exec_ms,
            active_agents_snapshot,
            violation,
        ) = self
            .with_state_mut(|state| {
                if !state.tenants.iter().any(|t| t.org_id == org_owned) {
                    state.tenants.push(TenantUsageRecord {
                        org_id: org_owned.clone(),
                        plan_tier: PlanTier::Community,
                        max_concurrent_agents: PlanTier::Community.max_concurrent_agents(),
                        total_syscalls: 0,
                        sandbox_exec_ms: 0,
                        cow_saved_bytes: 0,
                        wake_count: 0,
                        quota_day_utc: today.clone(),
                        daily_syscalls: 0,
                        daily_exec_ms: 0,
                        active_agents: Vec::new(),
                        updated_at_ms: now,
                    });
                }
                let t = state
                    .tenants
                    .iter_mut()
                    .find(|t| t.org_id == org_owned)
                    .unwrap();
                if t.quota_day_utc != today {
                    t.quota_day_utc = today;
                    t.daily_syscalls = 0;
                    t.daily_exec_ms = 0;
                }
                let tier = t.plan_tier;
                let max_ag = t.max_concurrent_agents.max(tier.max_concurrent_agents());
                let max_sys = tier.max_daily_syscalls();
                let max_ex = tier.max_daily_exec_ms();

                if !clean_agent.is_empty()
                    && clean_agent != "cloud-coder-1"
                    && t.active_agents.len() == 1
                    && t.active_agents[0] == "cloud-coder-1"
                {
                    t.active_agents[0] = clean_agent.clone();
                }

                let mut viol: Option<(&'static str, String, String)> = None;
                if !clean_agent.is_empty() && !t.active_agents.iter().any(|a| a == &clean_agent) {
                    if t.active_agents.len() >= max_ag {
                        let existing_list = t.active_agents.join(", ");
                        viol = Some((
                            "PAYWALL_CONCURRENT_AGENTS_LIMIT",
                            format!(
                                "Tenant '{}' ({} plan) allows at most {} active Agent runtime (currently active: [{}]), cannot attach parallel Agent '{}'. Upgrade to Aegis Cloud Pro ($29/mo) for 8 parallel Agent runtimes.",
                                org_owned,
                                tier.as_str(),
                                max_ag,
                                existing_list,
                                clean_agent
                            ),
                            format!(
                                "当前租户 '{}'（{} 免费档）最多允许 {} 个并发 Agent 运行时（当前已挂载：[{}]），无法同时接入新 Agent '{}'。升级 Aegis Cloud Pro ($29/月) 即可解锁 8 个 Agent 并行运行时与 16 个线上工作区。",
                                org_owned,
                                tier.as_str(),
                                max_ag,
                                existing_list,
                                clean_agent
                            ),
                        ));
                    } else {
                        t.active_agents.push(clean_agent.clone());
                        t.updated_at_ms = now;
                    }
                }

                if viol.is_none() && t.daily_syscalls >= max_sys {
                    viol = Some((
                        "PAYWALL_DAILY_SYSCALL_LIMIT",
                        format!(
                            "Daily MCP syscall quota reached for tenant '{}' on {} plan ({}/{} syscalls used today). Upgrade to Aegis Cloud Pro ($29/mo) for 20,000 daily syscalls.",
                            org_owned,
                            tier.as_str(),
                            t.daily_syscalls,
                            max_sys
                        ),
                        format!(
                            "当前租户 '{}' 今日免费系统调用额度已用尽（已用 {}/{} 次）。升级 Aegis Cloud Pro ($29/月) 即可解锁每日 20,000 次系统调用与 64GB 独享 OS 运行时。",
                            org_owned, t.daily_syscalls, max_sys
                        ),
                    ));
                }

                if viol.is_none() && tool_owned == "proc_exec" && t.daily_exec_ms >= max_ex {
                    viol = Some((
                        "PAYWALL_DAILY_EXEC_TIME_LIMIT",
                        format!(
                            "Daily sandbox CPU execution quota reached for tenant '{}' on {} plan ({} ms / {} ms used today). Upgrade to Aegis Cloud Pro ($29/mo) for 10 hours/day of 64GB sandbox compute.",
                            org_owned,
                            tier.as_str(),
                            t.daily_exec_ms,
                            max_ex
                        ),
                        format!(
                            "当前租户 '{}' 今日免费沙箱 CPU 执行时长已达上限（已用 {}s / {}s）。升级 Aegis Cloud Pro ($29/月) 即可解锁每日 10 小时 64GB 独享沙箱算力。",
                            org_owned,
                            t.daily_exec_ms / 1000,
                            max_ex / 1000
                        ),
                    ));
                }

                Ok((
                    tier,
                    max_ag,
                    t.daily_syscalls,
                    max_sys,
                    t.daily_exec_ms,
                    max_ex,
                    t.active_agents.clone(),
                    viol,
                ))
            })
            .await
            .unwrap_or_else(|_| {
                (
                    PlanTier::Community,
                    1,
                    0,
                    PlanTier::Community.max_daily_syscalls(),
                    0,
                    PlanTier::Community.max_daily_exec_ms(),
                    Vec::new(),
                    None,
                )
            });

        if let Some((code, reason_en, reason_zh)) = violation {
            let checkout = self.build_checkout_info(org_id, PlanTier::Pro, None, None);
            let checkout_url = checkout
                .get("checkout_url")
                .and_then(|v| v.as_str())
                .unwrap_or(Self::DEFAULT_POLAR_PRO_CHECKOUT_URL);
            let notice = format!(
                "[AEGIS CLOUD PAYWALL — {}]\n{}\n{}\n\n👉 立即升级 Aegis Cloud Pro ($29/mo · 16 Workspaces · 8 Parallel Agents · 64GB Online OS Runtime):\n   • Web Console: https://heurion.org/aegis-cloud/dashboard\n   • Direct Checkout: {}\n   • 在终端一行命令自动打开结账、等待付款、认领密钥并挂载当前工作区 (密钥存本机，不经过大模型):\n     aegis-os cloud subscribe --plan pro --wait",
                code, reason_zh, reason_en, checkout_url
            );
            return Err(json!({
                "status": "paywall_exceeded",
                "http_status": 402,
                "code": code,
                "org_id": org_id,
                "agent_id": clean_agent,
                "current_plan": tier.as_str(),
                "reason": reason_en,
                "reason_zh": reason_zh,
                "quotas": {
                    "daily_syscalls_used": daily_syscalls,
                    "daily_syscalls_limit": max_syscalls,
                    "daily_exec_ms_used": daily_exec_ms,
                    "daily_exec_ms_limit": max_exec_ms,
                    "active_agents": active_agents_snapshot,
                    "max_concurrent_agents": max_agents
                },
                "upgrade": {
                    "target_plan": "pro",
                    "monthly_price_usd": 29,
                    "checkout_url": checkout_url,
                    "dashboard_url": "https://heurion.org/aegis-cloud/dashboard",
                    "cli_command": "aegis-os cloud subscribe --plan pro --wait"
                },
                "agent_notice": notice
            }));
        }

        Ok(tier)
    }

    /// Return read-only subscription & daily quota status for the Web Console or CLI (never exposes raw `ak_live_*` secrets).
    pub async fn get_subscription_and_quota_status(
        &self,
        org_id: Option<&str>,
        customer_email: Option<&str>,
    ) -> Value {
        self.reload().await;
        let email_norm = customer_email
            .map(|e| e.trim().to_lowercase())
            .filter(|e| !e.is_empty());
        let org_norm = org_id
            .map(|o| o.trim().to_string())
            .filter(|o| !o.is_empty() && o != "*" && o != "default-org");

        let state = self.state.read().await;
        let matched_sub = state
            .subscriptions
            .iter()
            .rev()
            .find(|s| {
                email_norm
                    .as_ref()
                    .is_some_and(|em| s.customer_email.as_ref() == Some(em))
                    || org_norm.as_ref() == Some(&s.org_id)
            })
            .cloned();

        let resolved_org = matched_sub
            .as_ref()
            .map(|s| s.org_id.clone())
            .or_else(|| org_norm.clone())
            .or_else(|| {
                email_norm
                    .as_deref()
                    .and_then(|e| e.split('@').next())
                    .map(|p| {
                        p.chars()
                            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
                            .collect::<String>()
                    })
            })
            .unwrap_or_else(|| "aegis-os".to_string());

        let tenant = state
            .tenants
            .iter()
            .find(|t| t.org_id == resolved_org)
            .cloned();

        let tier = tenant
            .as_ref()
            .map(|t| t.plan_tier)
            .or_else(|| matched_sub.as_ref().map(|s| s.plan_tier))
            .unwrap_or(PlanTier::Community);

        let today = Utc::now().format("%Y-%m-%d").to_string();
        let (daily_sys, daily_ex, active_agents) = match tenant {
            Some(ref t) if t.quota_day_utc == today => (
                t.daily_syscalls,
                t.daily_exec_ms,
                t.active_agents.clone(),
            ),
            Some(ref t) => (0, 0, t.active_agents.clone()),
            None => (0, 0, Vec::new()),
        };

        json!({
            "found_subscription": matched_sub.is_some(),
            "subscription_status": matched_sub.as_ref().map(|s| s.status.as_str()).unwrap_or("none"),
            "provider": matched_sub.as_ref().map(|s| s.provider.as_str()).unwrap_or("none"),
            "org_id": resolved_org,
            "customer_email": matched_sub.as_ref().and_then(|s| s.customer_email.clone()).or(email_norm),
            "plan_tier": tier.as_str(),
            "monthly_price_usd": tier.monthly_price_usd(),
            "desktop_entitlements": tier.desktop_entitlements(),
            "key_claim_ready": matched_sub.as_ref().is_some_and(|s| s.status == "active" && s.claimable_api_key.is_some()),
            "quotas": {
                "daily_syscalls_used": daily_sys,
                "daily_syscalls_limit": tier.max_daily_syscalls(),
                "daily_exec_ms_used": daily_ex,
                "daily_exec_ms_limit": tier.max_daily_exec_ms(),
                "active_agents": active_agents,
                "active_agents_count": active_agents.len(),
                "max_concurrent_agents": tier.max_concurrent_agents(),
                "max_workspaces": tier.max_workspaces(),
                "max_exec_timeout_ms": tier.max_exec_timeout_ms(),
                "idle_hibernate_timeout_ms": tier.idle_hibernate_timeout_ms()
            },
            "claim_command": "aegis-os cloud subscribe --claim && aegis-os cloud up  # uses the claim token saved when the checkout was started"
        })
    }

    pub async fn list_tenants(&self, org_id: Option<&str>) -> Vec<TenantUsageRecord> {
        self.reload().await;
        self.state
            .read()
            .await
            .tenants
            .iter()
            .filter(|t| org_id.is_none_or(|o| o == "*" || t.org_id == o))
            .cloned()
            .collect()
    }

    pub async fn get_tenant_plan(&self, org_id: &str) -> PlanTier {
        self.reload().await;
        self.state
            .read()
            .await
            .tenants
            .iter()
            .find(|t| t.org_id == org_id)
            .map(|t| t.plan_tier)
            .unwrap_or(PlanTier::Community)
    }

    pub async fn get_desktop_entitlements_payload(&self, org_id: &str) -> Value {
        let clean_org = if org_id.trim().is_empty() || org_id == "*" || org_id == "default-org" {
            "aegis-os"
        } else {
            org_id.trim()
        };
        let tier = self.get_tenant_plan(clean_org).await;
        let entitlements = tier.desktop_entitlements();
        let now_ms = Utc::now().timestamp_millis();
        let expires_at_ms = now_ms + 24 * 60 * 60 * 1000;
        let signing_secret = self.state.read().await.ticket_signing_secret.clone();
        let claims = DesktopEntitlementClaims {
            org_id: clean_org.to_string(),
            issued_at_ms: now_ms,
            expires_at_ms,
            entitlements: entitlements.clone(),
        };
        match issue_desktop_entitlement_token(&signing_secret, &claims) {
            Ok((token, pubkey_b64)) => json!({
                "org_id": clean_org,
                "entitlements": entitlements,
                "token": token,
                "pubkey_b64": pubkey_b64,
                "expires_at_ms": expires_at_ms,
            }),
            Err(err) => json!({
                "org_id": clean_org,
                "entitlements": entitlements,
                "error": err.to_string(),
            }),
        }
    }

    /// Official Polar.sh hosted checkout link for Aegis Cloud Pro ($29/mo).
    pub const DEFAULT_POLAR_PRO_CHECKOUT_URL: &'static str =
        "https://buy.polar.sh/polar_cl_jCPpzbp4eOAyRbkDP4YzNIFVnYLddbvJZI5Fc27zL0x";

    /// Generate hosted Merchant-of-Record (Polar.sh / Lemon Squeezy) checkout URLs pre-filled with `org_id` and `email`.
    pub fn build_checkout_info(
        &self,
        org_id: &str,
        plan_tier: PlanTier,
        customer_email: Option<&str>,
        claim_id: Option<&str>,
    ) -> Value {
        let base_url = match plan_tier {
            PlanTier::Team => std::env::var("AOS_CHECKOUT_URL_TEAM")
                .unwrap_or_else(|_| Self::DEFAULT_POLAR_PRO_CHECKOUT_URL.to_string()),
            PlanTier::Enterprise => std::env::var("AOS_CHECKOUT_URL_ENTERPRISE")
                .unwrap_or_else(|_| Self::DEFAULT_POLAR_PRO_CHECKOUT_URL.to_string()),
            _ => std::env::var("AOS_CHECKOUT_URL_PRO")
                .unwrap_or_else(|_| Self::DEFAULT_POLAR_PRO_CHECKOUT_URL.to_string()),
        };
        let sep = if base_url.contains('?') { '&' } else { '?' };
        let email_qs = customer_email
            .filter(|e| !e.trim().is_empty())
            .map(|e| format!("&customer_email={}", e.trim()))
            .unwrap_or_default();
        let claim_qs = claim_id
            .map(|c| format!("&metadata[claim_id]={}", c))
            .unwrap_or_default();
        let checkout_url = format!(
            "{}{}reference_id={}&metadata[org_id]={}&metadata[plan_tier]={}{}{}",
            base_url,
            sep,
            org_id,
            org_id,
            plan_tier.as_str(),
            email_qs,
            claim_qs
        );

        let ls_base = std::env::var("AOS_LEMONSQUEEZY_CHECKOUT_URL").unwrap_or_else(|_| {
            format!(
                "https://aegis-os.lemonsqueezy.com/checkout/buy/aegis-cloud-{}",
                plan_tier.as_str()
            )
        });
        let ls_url = format!(
            "{}?checkout[custom][org_id]={}&checkout[custom][plan_tier]={}{}{}",
            ls_base,
            org_id,
            plan_tier.as_str(),
            customer_email
                .filter(|e| !e.trim().is_empty())
                .map(|e| format!("&checkout[email]={}", e.trim()))
                .unwrap_or_default(),
            claim_id
                .map(|c| format!("&checkout[custom][claim_id]={}", c))
                .unwrap_or_default()
        );

        json!({
            "org_id": org_id,
            "plan_tier": plan_tier,
            "monthly_price_usd": plan_tier.monthly_price_usd(),
            "max_concurrent_agents": plan_tier.max_concurrent_agents(),
            "max_exec_timeout_ms": plan_tier.max_exec_timeout_ms(),
            "checkout_url": checkout_url,
            "providers": {
                "polar_sh": checkout_url,
                "lemonsqueezy": ls_url
            },
            "next_step": "Complete checkout in browser; our `/v1/billing/webhook` automatically upgrades your tenant and mints an `ak_live_*` key. Then run `aegis-os cloud subscribe --claim` to activate locally."
        })
    }

    /// Most pending checkouts kept per org; older ones are dropped (bounds unauthenticated growth).
    const MAX_PENDING_CLAIMS_PER_ORG: usize = 5;

    /// Starts a checkout: like [`Self::build_checkout_info`], plus a one-time `claim_token` that is
    /// the only credential able to collect the API key minted when this checkout is paid.
    /// Rejects unauthenticated checkouts targeting an existing org (one with API keys or active subscriptions)
    /// to prevent checkout hijack / enumeration attacks (`CHECKOUT_ORG_EXISTS`).
    pub async fn create_checkout(
        &self,
        org_id: &str,
        plan_tier: PlanTier,
        customer_email: Option<&str>,
        caller_org: Option<&str>,
        is_operator: bool,
    ) -> anyhow::Result<Value> {
        let org_clean = org_id.trim();
        Self::validate_identifier("org_id", org_clean)?;
        let org_owned = org_clean.to_string();
        let caller_org_owned = caller_org.map(str::to_string);
        let claim_id = format!("clm-{}", &Uuid::new_v4().simple().to_string()[..12]);
        let claim_token = format!("ct_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let token_sha256 = Self::sha256_hex(&claim_token);
        let claim_id_clone = claim_id.clone();

        self.with_state_mut(move |state| {
            let org_exists = state.api_keys.iter().any(|k| k.org_id == org_owned)
                || state
                    .subscriptions
                    .iter()
                    .any(|s| s.org_id == org_owned && s.status == "active");
            if org_exists
                && !is_operator
                && caller_org_owned.as_deref() != Some(org_owned.as_str())
            {
                bail!(
                    "CHECKOUT_ORG_EXISTS: Org '{}' already exists; authenticate with a Bearer key for that org or an operator token to create a new checkout",
                    org_owned
                );
            }

            state.pending_claims.push(PendingClaimRecord {
                claim_id: claim_id_clone,
                token_sha256,
                org_id: org_owned.clone(),
                created_at_ms: Utc::now().timestamp_millis(),
            });
            let for_org = state
                .pending_claims
                .iter()
                .filter(|c| c.org_id == org_owned)
                .count();
            let mut excess = for_org.saturating_sub(Self::MAX_PENDING_CLAIMS_PER_ORG);
            state.pending_claims.retain(|c| {
                if excess > 0 && c.org_id == org_owned {
                    excess -= 1;
                    false
                } else {
                    true
                }
            });
            Ok(())
        })
        .await?;

        let mut info = self.build_checkout_info(org_clean, plan_tier, customer_email, Some(&claim_id));
        if let Some(obj) = info.as_object_mut() {
            obj.insert("claim_id".into(), json!(claim_id));
            obj.insert("claim_token".into(), json!(claim_token));
            obj.insert(
                "claim_hint".into(),
                json!("Keep `claim_token` secret: after paying, it is the only way to collect your API key (`aegis-os cloud subscribe --claim`)."),
            );
        }
        Ok(info)
    }

    /// Process a Polar.sh, Lemon Squeezy, or Stripe billing webhook payload:
    /// - On subscription activation (`subscription.created`, `subscription.active`, `subscription_created`, `checkout.session.completed`):
    ///   upgrades the tenant's `PlanTier`, mints a scoped `ak_live_*` API key, and stores a `BillingSubscriptionRecord`.
    /// - On subscription cancellation (`subscription.canceled`, `subscription.revoked`, `subscription_cancelled`, `customer.subscription.deleted`):
    ///   revokes the subscription API key, downgrades the tenant to `PlanTier::Community`, and hibernates active Cloud Workspaces.
    pub async fn handle_billing_webhook(
        &self,
        kernel: &AegisRuntimeKernel,
        payload: &Value,
    ) -> anyhow::Result<Value> {
        self.reload().await;

        // Detect provider & event type across Polar.sh, Lemon Squeezy, and Stripe
        let event_type = payload
            .get("type")
            .and_then(|v| v.as_str())
            .or_else(|| {
                payload
                    .get("meta")
                    .and_then(|m| m.get("event_name"))
                    .and_then(|v| v.as_str())
            })
            .unwrap_or("subscription.created")
            .to_lowercase();

        let provider = if payload.get("meta").and_then(|m| m.get("event_name")).is_some() {
            "lemonsqueezy"
        } else if payload
            .get("data")
            .and_then(|d| d.get("object"))
            .is_some()
        {
            "stripe"
        } else {
            "polar"
        };

        // Never downgrade/hibernate an existing paid org when an unpaid checkout session expires.
        if event_type.contains("checkout") && event_type.contains("expir") {
            return Ok(json!({
                "status": "ignored",
                "provider": provider,
                "event_type": event_type,
                "reason": "unpaid checkout session expiration does not affect existing subscriptions"
            }));
        }

        let data_node = payload
            .get("data")
            .and_then(|d| d.get("object"))
            .or_else(|| payload.get("data"))
            .unwrap_or(payload);

        let metadata_node = data_node
            .get("metadata")
            .or_else(|| {
                payload
                    .get("meta")
                    .and_then(|m| m.get("custom_data"))
            })
            .or_else(|| payload.get("metadata"));

        let customer_email = data_node
            .get("customer_email")
            .or_else(|| data_node.get("user_email"))
            .or_else(|| {
                data_node
                    .get("customer")
                    .and_then(|c| c.get("email"))
            })
            .or_else(|| {
                data_node
                    .get("user")
                    .and_then(|u| u.get("email"))
            })
            .or_else(|| {
                data_node
                    .get("attributes")
                    .and_then(|a| a.get("user_email"))
            })
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_lowercase());

        let org_id = metadata_node
            .and_then(|m| m.get("org_id"))
            .and_then(|v| v.as_str())
            .or_else(|| data_node.get("reference_id").and_then(|v| v.as_str()))
            .or_else(|| data_node.get("client_reference_id").and_then(|v| v.as_str()))
            .or_else(|| payload.get("org_id").and_then(|v| v.as_str()))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                customer_email
                    .as_deref()
                    .and_then(|e| e.split('@').next())
                    .map(|prefix| {
                        prefix
                            .chars()
                            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
                            .collect::<String>()
                    })
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "aegis-os".to_string())
            });

        let raw_plan = metadata_node
            .and_then(|m| m.get("plan_tier").or_else(|| m.get("plan")))
            .and_then(|v| v.as_str())
            .or_else(|| {
                data_node
                    .get("product")
                    .and_then(|p| p.get("name"))
                    .and_then(|v| v.as_str())
            })
            .or_else(|| {
                data_node
                    .get("attributes")
                    .and_then(|a| a.get("variant_name").or_else(|| a.get("product_name")))
                    .and_then(|v| v.as_str())
            })
            .or_else(|| payload.get("plan_tier").and_then(|v| v.as_str()))
            .unwrap_or("pro");

        let plan_tier = if raw_plan.to_ascii_lowercase().contains("team") {
            PlanTier::Team
        } else if raw_plan.to_ascii_lowercase().contains("enterprise") {
            PlanTier::Enterprise
        } else if raw_plan.to_ascii_lowercase().contains("community")
            || raw_plan.to_ascii_lowercase().contains("free")
        {
            PlanTier::Community
        } else {
            PlanTier::Pro
        };

        let explicit_sub_id = data_node.get("id").and_then(|v| {
            v.as_str()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .or_else(|| v.as_i64().map(|n| n.to_string()))
        });
        let sub_id = explicit_sub_id
            .clone()
            .unwrap_or_else(|| format!("sub-{}", &Uuid::new_v4().to_string()[..8]));

        let is_cancel = event_type.contains("cancel")
            || event_type.contains("revok")
            || event_type.contains("delet")
            || event_type.contains("expir");

        let now = Utc::now().timestamp_millis();

        if is_cancel {
            let Some(req_sub_id) = explicit_sub_id else {
                return Ok(json!({
                    "status": "ignored",
                    "provider": provider,
                    "event_type": event_type,
                    "reason": "cancellation webhook missing explicit subscription id"
                }));
            };
            let req_sub_owned = req_sub_id.clone();
            let (revoked_keys, target_orgs, ws_to_hibernate) = self
                .with_state_mut(move |state| {
                    let mut revoked = Vec::new();
                    let mut orgs: Vec<String> = Vec::new();
                    for sub in state.subscriptions.iter_mut() {
                        // Exact match by provider subscription_id only; never bulk-revoke by unverified metadata.org_id.
                        if sub.subscription_id == req_sub_owned {
                            sub.status = "canceled".to_string();
                            sub.claimable_api_key = None;
                            sub.updated_at_ms = now;
                            if let Some(ref kid) = sub.issued_key_id {
                                revoked.push(kid.clone());
                            }
                            if !orgs.contains(&sub.org_id) {
                                orgs.push(sub.org_id.clone());
                            }
                        }
                    }
                    if !revoked.is_empty() {
                        state.api_keys.retain(|k| !revoked.contains(&k.key_id));
                    }
                    let ws: Vec<(String, String)> = state
                        .workspaces
                        .iter()
                        .filter(|w| {
                            orgs.contains(&w.org_id)
                                && w.status == WorkspaceLifecycleState::Active
                        })
                        .map(|w| (w.org_id.clone(), w.workspace_id.clone()))
                        .collect();
                    Ok((revoked, orgs, ws))
                })
                .await?;

            if target_orgs.is_empty() {
                return Ok(json!({
                    "status": "ignored",
                    "provider": provider,
                    "event_type": event_type,
                    "subscription_id": req_sub_id,
                    "reason": "no matching active subscription_id"
                }));
            }

            let mut primary_plan = PlanTier::Community;
            for matched_org in &target_orgs {
                // Only downgrade to Community if the org has no remaining active subscription.
                let still_paid = {
                    let state = self.state.read().await;
                    state
                        .subscriptions
                        .iter()
                        .any(|s| s.org_id == *matched_org && s.status == "active")
                };
                if !still_paid {
                    let tenant = self.set_tenant_plan(matched_org, PlanTier::Community).await?;
                    primary_plan = tenant.plan_tier;
                }
            }
            let mut hibernated = Vec::new();
            for (ws_org, ws_id) in ws_to_hibernate {
                if self.hibernate_workspace(kernel, &ws_org, &ws_id).await.is_ok() {
                    hibernated.push(ws_id);
                }
            }

            return Ok(json!({
                "status": "subscription_canceled",
                "provider": provider,
                "event_type": event_type,
                "subscription_id": req_sub_id,
                "org_id": target_orgs.first().cloned().unwrap_or(org_id),
                "downgraded_plan": primary_plan,
                "revoked_key_ids": revoked_keys,
                "hibernated_workspaces": hibernated
            }));
        }

        // Subscription activated / renewed -> Upgrade tenant plan & mint scoped `ak_live_*` key
        let tenant = self.set_tenant_plan(&org_id, plan_tier).await?;
        let label = format!(
            "{} {} Subscription ({})",
            provider.to_uppercase(),
            plan_tier.as_str().to_uppercase(),
            sub_id
        );
        let (raw_key, key_rec) = self
            .issue_api_key(
                &org_id,
                "agy-agent",
                "Aegis Cloud Subscriber",
                None,
                &label,
            )
            .await?;

        let sub_record = BillingSubscriptionRecord {
            subscription_id: sub_id.clone(),
            provider: provider.to_string(),
            org_id: org_id.clone(),
            customer_email: customer_email.clone(),
            plan_tier,
            status: "active".to_string(),
            issued_key_id: Some(key_rec.key_id.clone()),
            claimable_api_key: Some(raw_key),
            claim_id: metadata_node
                .and_then(|m| m.get("claim_id"))
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            updated_at_ms: now,
        };

        let org_owned = org_id.clone();
        let sub_id_owned = sub_id.clone();
        self.with_state_mut(move |state| {
            state
                .subscriptions
                .retain(|s| !(s.org_id == org_owned && s.subscription_id == sub_id_owned));
            state.subscriptions.push(sub_record);
            Ok(())
        })
        .await?;

        Ok(json!({
            "status": "subscription_activated",
            "provider": provider,
            "event_type": event_type,
            "subscription_id": sub_id,
            "org_id": org_id,
            "customer_email": customer_email,
            "plan_tier": tenant.plan_tier,
            "max_concurrent_agents": tenant.max_concurrent_agents,
            "max_exec_timeout_ms": plan_tier.max_exec_timeout_ms(),
            // The raw key is never echoed to the billing provider; the buyer collects it with
            // their claim token.
            "key_id": key_rec.key_id
        }))
    }

    /// Collects the `ak_live_*` key minted for a paid checkout. Requires the one-time claim token
    /// returned by [`Self::create_checkout`]; an org id or email alone is not proof of payment.
    pub async fn claim_subscription_key(&self, claim_token: &str) -> anyhow::Result<Value> {
        let token = claim_token.trim();
        if token.is_empty() {
            bail!("Missing claim_token (returned by `aegis-os cloud subscribe` when the checkout was started)");
        }
        let hash = Self::sha256_hex(token);
        let (mut out, has_approver, pending_org_id) = self
            .with_state_mut(move |state| {
                let pending = state
                    .pending_claims
                    .iter()
                    .find(|c| Self::hex_digests_match(&c.token_sha256, &hash))
                    .cloned()
                    .context("Unknown or already used claim token")?;
                let sub = state
                    .subscriptions
                    .iter_mut()
                    .rev()
                    .find(|s| {
                        s.status == "active"
                            && s.claim_id.as_deref() == Some(pending.claim_id.as_str())
                    })
                    .context("Checkout not paid yet: no active subscription for this claim token (retry after the payment webhook arrives)")?;
                let claimed_key = sub
                    .claimable_api_key
                    .take()
                    .context("Subscription API key has already been claimed (use `aegis-os cloud keys --create` to mint an additional key)")?;
                let out = json!({
                    "status": "subscription_claimed",
                    "subscription_id": sub.subscription_id,
                    "provider": sub.provider,
                    "org_id": sub.org_id,
                    "customer_email": sub.customer_email,
                    "plan_tier": sub.plan_tier,
                    "api_key": claimed_key
                });
                state
                    .pending_claims
                    .retain(|c| c.claim_id != pending.claim_id);
                let has_approver = state.approvers.iter().any(|a| a.org_id == pending.org_id);
                Ok((out, has_approver, pending.org_id))
            })
            .await?;

        // The claim token can sit on disk where an agent may read it, so the claim itself never
        // hands out the approver secret. Instead the enrollment link goes to the billing email,
        // which comes from the payment provider.
        if !has_approver {
            out["approver_enrollment"] = match out["customer_email"].as_str().map(str::to_string) {
                Some(email) => match self
                    .request_approver_email_enrollment(&pending_org_id, &email)
                    .await
                {
                    Ok(_) => json!({ "status": "email_sent", "email": crate::approver::mask_email(&email) }),
                    Err(e) => json!({ "status": "not_sent", "reason": e.to_string() }),
                },
                None => json!({ "status": "not_sent", "reason": "no billing email on the subscription" }),
            };
        }
        Ok(out)
    }
}
