# Aegis OS 外部 MCP 对接架构与交互设计 | External MCP Integration Architecture & Option B Spec

> 本文档定义 Aegis OS 对接开放 MCP 生态（Official MCP Registry / `.well-known` / 团队项目清单 / 本地 `stdio` 与远端 Streamable HTTP）的整体架构、运行期沙箱拓扑、以及 **方案 B（会话内审批安装 + 临时热桥接 + 下次启动自动扶正）** 交互规范。
>
> **状态标注约定 | Status Legend**：
> - **`[Implemented v0.9.3]`**：已在 `v0.9.3` 底座实现的能力。
> - **`[Implemented v0.10.0]`**：本次 `v0.10.0` 落地完成的开放发现、统一安装/可见性、`stdio` 沙箱化与 **方案 B 控制面/热桥接** 能力（见 §4 与 §5）。

---

## 1. 核心定位：控制面 vs. 数据面分离 | Architecture Positioning (Control Plane vs. Data Plane)

Aegis OS 已在 **`v0.9.3`** 彻底移除早期的静态封闭目录模型（`AAP-1.0` / `app_store` / `aegis-os app`），明确将自身定位为 **开放 MCP 生态的零信任入口与托管边界（Zero-Trust Gateway & Custody Boundary）**，而不自建封闭应用商店：

1. **数据面（Data Plane · 1:1 零信任代理桩） `[Implemented v0.9.3]`**
   - 对沙箱内的 `claude`、`agy` / `agy-cli`、`opencode`、`codex`、`cursor` 等客户端而言，每个已启用的外部 MCP 都是其原生配置中的一等公民 MCP Server。
   - 沙箱内部仅运行无凭证的轻量转发桩；所有策略裁决、PII 假名化、会话污点追踪、事务发件箱（Outbox）审批与真实密钥注入均在宿主机 `SessionBroker` 的 `McpProxySessionPool` 完成。
2. **控制面（Control Plane · `aegis-os` 内核 MCP 原语） `[Implemented v0.10.0]`**
   - 负责“查看已装、按安全评级检索、向人类提交安装/鉴权审批、会话内临时热桥接”。
   - 严格贯彻**人机权限分离**：Agent 仅拥有只读发现与提交安装提案的能力；安全确认、域名核验及 OAuth 2.1 / API Key 凭证封装必须由人类在宿主机端完成，原始密钥永不进入沙箱或 LLM 上下文。

---

## 2. 受限沙箱内的运行时拓扑 | Confined Sandbox Topology `[Implemented v0.9.3]`

在 `aegis-os run` 启动期间，`crates/aos-cli/src/launcher.rs` 中的 `stage_confined_mcp_configs()` 完成客户端配置隔离装配与凭据清洗：

- **剔除宿主机明文泄露**：剥离 `$AGENT_HOME` 内未收编客户端配置中的明文 API Key / Token；仅写入权限 `0o600` 的会话临时凭据 `$AGENT_HOME/.run/aegis-broker.json`（含临时 `control_socket` 与 `session_token`）。
- **多客户端原生格式自动分发**：按目标客户端原语写入隔离配置，实现“一次注册，多端共用”：
  - `claude` → `$AGENT_HOME/.claude.json`（`mcpServers`）
  - `agy` / `agy-cli` → `$AGENT_HOME/.gemini/config/mcp_config.json` 与 `.gemini/antigravity-cli/mcp_config.json`
  - `opencode` → `$AGENT_HOME/.config/opencode/opencode.json`（原生 `mcp` + `type: "remote"` 结构）
  - `cursor` → `$AGENT_HOME/.cursor/mcp.json`
  - `codex` → `$AGENT_HOME/.codex/config.toml`（`[mcp_servers.<id>]` + `http_headers`）
- **双模式沙箱转发路径**：
  - **Enforced 模式（Linux `bwrap` / macOS Seatbelt）**：客户端以 `stdio` 启动无凭证转发桩 `aegis-os mcp proxy <server_id>`（`crates/aos-cli/src/mcp_guard.rs`）；沙箱内严禁直连 Vault（Fail-Closed），请求经 Unix Socket 转发至宿主机 `SessionBroker` `/v1/mcp-proxy/<server_id>`，并支持 SSE / 进度通知流式透传。
  - **Isolated MicroVM 模式（`--isolated`）**：客户端直接配置为本地回环 HTTP 端点 `http://127.0.0.1:<proxy_port>/__aegis/mcp/<server_id>`（携带 `X-Aegis-Token`），经 `AF_VSOCK` 隧道直达宿主机 `SessionBroker`（`crates/aos-cli/src/session_broker.rs`）。

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│ Confined Sandbox (bwrap / Seatbelt / Zero-NIC MicroVM)                      │
│ • Isolated $AGENT_HOME  • No Host Secrets  • No Direct External Tokens      │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ claude / agy / opencode / codex / cursor                            │   │
│   │ Reads Aegis-staged client config (.claude.json / mcp_config.json /  │   │
│   │ opencode.json / config.toml)                                        │   │
│   └───────────┬─────────────────────────────────────────┬───────────────┘   │
│               │ Native MCP (`aegis-os`)                 │ Native MCP (<id>) │
│               ▼                                         ▼                   │
│     [Control Plane Stub]                     [1:1 Data Plane Stub]          │
│     • Enforced: `aegis-os mcp-stdio`         • Enforced: `aegis-os mcp proxy`│
│     • Isolated: `/__aegis/mcp/_kernel`       • Isolated: `/__aegis/mcp/<id>` │
└───────────────┬─────────────────────────────────────────┬───────────────────┘
                │ Session X-Aegis-Token only (Unix Sock / AF_VSOCK)           │
================╪====================== TRUST BOUNDARY =======================╪
                ▼                                         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Host Trusted Plane (`SessionBroker` + Vault + `McpProxySessionPool`)       │
│                                                                             │
│   /__aegis/mcp/_kernel                       /__aegis/mcp/<server_id>       │
│   • CoW VFS / GitHub / IPC / Policy          1. Policy + SQL/Annotation Risk │
│   • Control Plane (`mcp_list_installed`,     2. Outbound DLP Pseudonymizer  │
│     `mcp_discover`, `mcp_request_install`,   3. Dynamic Untrusted Taint     │
│     Option B Hot Session Bridge)             4. Pending Outbox Gate (SHA256)│
│                                              5. Host Vault Token Injection  │
│                                              6. SSRF-Pinned HTTP / Sandboxed│
│                                                 Upstream Dispatch           │
└─────────────────────────────────────────────────────────┬───────────────────┘
                                                          ▼
                                     External MCP Server (HTTP+OAuth / stdio)
```

---

## 3. 开放生态分发格式与四大核心支柱 | Ecosystem Distribution & Four Pillars

当前开放 MCP 生态以 **Official MCP Registry (`registry.modelcontextprotocol.io`)** 作为标准元数据根目录，同时涵盖 **Remote Streamable HTTP + OAuth 2.1**、**包管理器 (`npm` / `pypi`)**、**单文件扩展 (`.mcpb`)**、**OCI 容器镜像** 与 **域名自描述（`.well-known/mcp-bundle.json`、SEP-2127 `/.well-known/ai-catalog.json` / `<url>/server-card`、仓库 `.mcp.json`）**。Aegis 按以下 4 个支柱对齐：

### 3.1 多源联邦发现 | Federated Discovery
1. **官方注册中心与企业私有镜像 `[Implemented v0.10.0+]`**：通过 `crates/aos-mcp-gateway/src/mcp_registry.rs` (`McpRegistryClient`) 查询 `https://registry.modelcontextprotocol.io/v0.1/servers`（支持 `metadata.nextCursor` 多页游标翻页、conditional `ETag` / `304 Not Modified`、15 分钟 TTL 本地缓存 `mcp_registry_cache.json`、`isLatest` 优先及 `deprecated`/`deleted` 去重过滤）。支持通过 `aegis-os mcp registry add/remove/list/airgapped` 管理 `mcp_registries.json` 企业私有目录，并可开启**气隙模式 (`disable_public_registry: true`)** 强制阻断公共 Registry 回退及任意未授权外网 URL 安装。
2. **域名自描述与直连端点**：
   - 开放声明式 Bundle（`https://<domain>/.well-known/mcp-bundle.json`，`aegis-mcp-bundle/v1`，含多端点、Auth Realm 与 `.agents/skills/<id>/SKILL.md`）**`[Implemented v0.9.3]`**。
   - 任意 Streamable HTTP URL 自动探测 `/.well-known/oauth-protected-resource`（RFC 9728）、origin-root 回退探测（RFC 9728 / RFC 8414）、`401 WWW-Authenticate` 与 SEP-2127 `<url>/server-card` **`[Implemented v0.10.0]`**。
3. **仓库级团队清单（Zero-Secret）与全生命周期运维 `[Implemented v0.10.0+]`**：识别项目根目录 `.aegis/mcp.json` / `.mcp.json`，启动 `aegis-os run` 时只做差异提示（`mcp-hint` Banner）；支持 `aegis-os mcp sync [--clients] [--dry-run]`、`aegis-os mcp upgrade [<id> | --all]`（保留 Vault 密文与策略覆盖）、`aegis-os mcp remove <id> [--purge-auth]` 与 `aegis-os mcp doctor --probe` 实机连通性探测。
4. **本机存量收编 `[Implemented v0.9.3]`**：通过 `aegis-os mcp scan` 与 `aegis-os mcp adopt --all` 发现并收编已有 `claude` / `agy` / `opencode` / `cursor` / `codex` 配置，将明文凭据迁移至 Vault 并无损备份。

### 3.2 安全优先筛选与上下文推荐 | Security-First Selection & Context Recommendation `[Implemented v0.10.0]`
针对开源社区同名实现杂乱、本地脚本黑盒执行的痛点，检索结果与候选卡片按 **Aegis Trust Tier** 排序，并由 Cedar 策略引擎（`context.mcp_trust_tier`、`context.mcp_domain_verified`、`context.mcp_registry_type`）强制把关准入：

| 信任分级 | 分发载体与鉴权形态 | 安全与摩擦特征 | 默认建议 |
|---|---|---|---|
| **Tier 1（首选）** | 域名/OIDC 所有权已验证的 **Remote Streamable HTTP + OAuth 2.1** | 零本地第三方代码执行、支持 RFC 9728/8414 自动发现与 host-pinning | 优先推荐 |
| **Tier 2（次选）** | **Remote HTTP + Static Token / API Key** | 零本地代码执行，宿主机一次性密封入 AES-256-GCM Vault | 稳健可用 |
| **Tier 3（需强隔离）** | 本地 `stdio`（`npm` / `pypi` 精确版本钉住、`.mcpb` ZIP 包、`oci` 镜像） | 需本地拉起包进程；强制显示风险警告，Cedar 默认拦截自动放行并默认入 Aegis 沙箱运行 | 审慎安装 |

- **上下文推荐 (`aegis-os mcp recommend`)**：基于仓库只读特征（如 `.git/config` 托管平台、数据库配置或项目 `.mcp.json`）推荐 2–3 个高匹配官方实现。
- **安装前风险预检卡（Pre-Install Dry-Run）**：展示域名白名单、精确包版本、`allowed_hosts` 与默认零信任策略（`trust=untrusted`、`dlp=pseudonymize`、`allow_elicitation=false`、写操作进 Outbox），并在端点允许时预检读写工具分类数量。

### 3.3 统一安装、零配置鉴权瀑布流与 `stdio` 沙箱化 | Unified Install, Auto-Auth Waterfall & Sandboxed `stdio`
- **Auth Realms 与 AES-256-GCM Vault `[Implemented v0.9.3]`**：`crates/aos-mcp-gateway/src/mcp_oauth.rs` 已实现组织级 Auth Realm、`allowed_hosts` DNS 标签锁定、RFC 9728/8414（含 origin-root 回退）自动发现、RFC 7591 动态注册、PKCE 浏览器登录、RFC 8628 Device Code 登录、静态 `--token-stdin` 密封，以及**磁盘 Vault 热重载（运行中会话免重启恢复授权）**。
- **单一安装入口 (`aegis-os mcp install <target>`) `[Implemented v0.10.0+]`**：统一收敛现有 `bundle install` / `add` / `adopt` 入口，支持 `--scope org`（默认全局共享）或 `--scope workspace`（写入无密钥 `.aegis/mcp.json`），自动识别短名、Bundle URL、Streamable HTTP URL、`npm:<pkg>@<ver>`、`pypi:<pkg>==<ver>`、`.mcpb` 归档（`crates/aos-mcp-gateway/src/mcp_mcpb.rs` 抗 Zip-Slip/Symlink 校验与不可变解压）与 `oci:<image>@sha256:...`（强制 `--cap-drop=ALL --security-opt=no-new-privileges --read-only` 加固容器标志），并自动推导包含 apex 域名在内的精确 `allowed_hosts` 与记录来源溯源字段（`registry_name` / `installed_version` / `manifest_sha256`）。
- **本地 `stdio` OS 与网络白名单沙箱化 `[Implemented v0.10.0+]`**：`mcp_firewall.rs` (`build_stdio_sandbox_plan_full` + `spawn_upstream_stdio`) 在宿主机支持时自动以 Linux `bwrap --tmpfs $HOME --bind <iso_home>` 或 macOS `sandbox-exec` 收紧 `~/.ssh`、`~/.aws`、`~/.gnupg`、`~/.kube`、`~/.aegis`，并严格 `env_clear()` 仅注入 Vault 解封环境；通过 `--isolate-network` / `--allow-host <host>`（Linux `--unshare-net` + `egress-shim` 宿主机 `AegisEgressGateway` 代理桥；macOS Seatbelt localhost 白名单代理）切断 `stdio` 子进程任意外网连接。

### 3.4 四层统一可见性与动态推送 / 全通道治理 | Four-Layer Inventory, Push & Full-Channel Governance
| 可见性 / 治理维度 | 载体与内容 | 状态 |
|---|---|---|
| **1. CLI 统一总览与运维** | `aegis-os mcp status`、`doctor [--probe]`、`sync`、`upgrade`、`remove`、`registry`、`search`、`recommend` | `[Implemented]` |
| **2. 启动态 Banner** | `aegis-os run` 启动横幅打印 `mcps:` 状态与 `mcp-hint:` 仓库清单提示（零网络调用） | `[Implemented]` |
| **3. 宿主机 Web `/approve` 全功能控制台** | `/approve` 集成 `Installed External MCP Servers` 面板、OAuth 2.1 PKCE/Device Code/Static Token 录入、策略在线编辑（`trust`/`dlp`/`tool_overrides`/`allowed_hosts`/`net_iso`）与 Outbox 审批队列 | `[Implemented]` |
| **4. Agent 侧自省与热推送** | `aegis://mcp/installed` 资源 + `mcp_list_installed` 工具 + `notifications/{tools,resources}/list_changed` 热推送与工具注解缓存失效重建 | `[Implemented]` |
| **5. 全 MCP 通道统一防线** | `tools/list`、`resources/{read,list}`、`resources/templates/list`、`prompts/{list,get}`、`completion/complete` 与 SSE/`stdio` 通知统一执行注入清洗、`Pseudonymize`/`Block` (`-32004`)、参数假名还原、污点传播与防篡改审计；`elicitation/create` 与 `sampling/*` 默认 Fail-Closed 拦截（`-32601`） | `[Implemented]` |

---

## 4. 沙箱内 Agent 互动闭环 —— 方案 B | In-Sandbox Agent Flow: Option B `[Implemented v0.10.0]`

主流客户端（`claude`、`agy`、`opencode`）通常仅在进程启动时读取一次 MCP 配置文件。为兼顾**运行时安全隔离**、**原生一等公民体验**以及**会话内即装即用不中断对话**，系统采用 **方案 B（会话内审批安装 + 临时热桥接 + 下次启动自动扶正）**。

### 4.1 控制面最小原语清单（`aegis-os` 内核 MCP 扩展）
1. **`aegis://mcp/installed` 资源与 `mcp_list_installed` 工具（只读 / Zero-Prompt）**
   - 返回当前会话已挂载与待登录 MCP 摘要（`server_id`、`source`、`transport`、`status`: `ready | needs_auth | needs_reload`、`trust_level`、`writes_require_outbox`、`skill_path`），严禁包含任何凭据原文或明文请求头。
2. **`mcp_discover` 工具（只读 / Zero-Prompt）**
   - 按关键词/意图检索 Official MCP Registry 与已配置私有目录，按 **Trust Tier 1 → 2 → 3** 返回候选清单、验证状态与风险等级。
3. **`mcp_request_install` 工具（审批门控 / SHA-256 Pinning）**
   - 提交候选 `server_id` / Registry 标识、`scope`（`org` 或 `workspace`）与用途说明。
   - 宿主机 `SessionBroker` 下载并校验 `server.json` / `.well-known` 清单、计算安装规格的 **SHA-256** 指纹，生成 `escalation_id` 并拉起宿主机 **Web Approval Console (`/approve?id=...`)**（无头终端回退 CLI / TOTP 审批）。
   - **宿主机页内顺手鉴权**：审批卡片同时提供 **「批准并登录 OAuth 2.1」** 按钮或 **静态 API Key 密码框（仅宿主机侧读取并直接写入 AES-256-GCM Vault）**，彻底阻断密钥经由聊天框、剪贴板或 Agent 环境变量泄露的风险。
4. **临时热桥接原语：`mcp_hot_list_tools` & `mcp_hot_call_tool`（方案 B 核心）**
   - 人类在宿主机批准安装后，宿主机同步完成：(1) 写入注册表与 Vault、(2) 更新隔离 `$AGENT_HOME` 下所有客户端配置、(3) 将该 `server_id` 加入**当前会话的 Hot-Bridge 白名单**（若客户端支持，下发 `notifications/tools/list_changed`）。
   - 若客户端进程尚未重启/重载原生配置，Agent 可通过 `mcp_hot_list_tools` / `mcp_hot_call_tool` 立即调用该新装 MCP，完成手头任务。
   - **100% 同等防线**：热桥接底层直接复用宿主机同一个 `McpProxySessionPool`，强制经过策略评估、DLP 假名化、污点传播、Outbox 人工批示与 Vault 域名注入，**绝不绕过防火墙**。
   - **自动扶正与退场**：热桥接仅允许路由**本会话刚批准且客户端配置尚未加载**的 `server_id`；用户下次启动 `aegis-os run`（或客户端执行 `/mcp reload`）时，`stage_confined_mcp_configs()` 将其自动装配为 1:1 原生代理桩，热桥接对其自动退场隐身。

### 4.2 端到端交互时序图 | End-to-End Sequence (Option B)

```text
User (in agy/claude/opencode)       Confined Agent           Host SessionBroker & Web Console
             │                             │                                │
  "查一下 Linear 上未关闭的 Bug"              │                                │
             ├────────────────────────────▶│                                │
             │                             ├─ 1. Read `aegis://mcp/installed`
             │                             │     (linear not installed)     │
             │                             ├─ 2. `mcp_discover("linear")` ──▶ Query Registry (v0.1)
             │                             │◀─ Tier 1: `app.linear/mcp` ────┤
             │                             ├─ 3. `mcp_request_install(...)`─▶ Freeze manifest SHA-256
             │                             │                                ├─ Open Host Web /approve?id=...
             │                             │◀─ Waiting human approval... ───┤
             │                                                              │
  [Host Browser] 审阅 Trust Tier / 域名 / 写操作进 Outbox                     │
  点击「批准安装并完成 OAuth 2.1 授权」（或宿主机填入 API Key）─────────────────▶│
             │                                                              ├─ PKCE OAuth -> Seal Vault
             │                                                              ├─ Register Policy + Stage Configs
             │                             ◀─ Result: `ready_via_hot_bridge`┤  Bind `linear` to Hot-Bridge ACL
             │                             │                                │
             │                             ├─ 4. `mcp_hot_call_tool(        │
             │                             │      server="linear", tool=...) ─▶ Full McpProxySessionPool
             │                             │                                │  (DLP + Outbox + Vault + HTTP)
             │◀─ 返回脱敏后的 Linear Issue 列表 ◀── Res: sanitized issue list ──┤
             │                                                              │
  [Next Session: `aegis-os run`]                                            │
             └─ `stage_confined_mcp_configs()` promotes `linear` ───────────▶ Native 1:1 proxy stub active;
                                                                              Hot-Bridge entry retired.
```

### 4.3 安全不变量 | Security Invariants (Option B)

| 安全不变量 | 强制机制 |
|---|---|
| **严禁 Agent 自批与自装** | `mcp_request_install` 强制绑定人类令牌 / Web `/approve` Ticket，仅确认清单 SHA-256 后落盘。 |
| **凭据零触达沙箱与 LLM** | OAuth 2.1 PKCE / Device Code 与静态 Key 输入全在宿主机端完成并封装进 Vault，沙箱内外只传递会话临时 Token。 |
| **默认不可信隔离边界** | 外部新装 MCP 默认策略强制 `trust=untrusted`、`dlp=pseudonymize`、写操作进 Outbox 审批并触发动态会话污点保护。 |
| **热桥接作用域最小化** | `mcp_hot_list_tools` / `mcp_hot_call_tool` 严格 Fail-Closed：仅允许调用“当前会话由人类刚刚批准新装”的 `server_id`，禁止任意跨服跳转。 |
| **非工具通道与主动请求隔离** | `tools/list`、`resources/*`、`prompts/*`、`completion/complete` 与 SSE/`stdio` 通知统一执行净室清洗、DLP 假名化/阻断（`dlp_mode=block` → `-32004`）、会话污点传播与哈希链审计；`elicitation/create` 等服务端主动请求默认 Fail-Closed 拦截（`-32601`）。 |

---

## 5. 实现交付状态 | Implementation Status

1. **Phase 1 — 统一可见性与安装收敛 `[Done]`**：`aegis-os mcp status`、`aegis-os mcp doctor`（含 `--probe`）、`aegis-os mcp install`、`aegis-os run` 启动 Banner 摘要（`print_mcp_startup_banner`）、`aegis://mcp/installed` 与 `mcp_list_installed`。
2. **Phase 2 — 开放发现与宿主机一体化审批鉴权 `[Done]`**：`mcp_registry.rs` 接入 Official MCP Registry (`v0.1` `nextCursor` 翻页 / `ETag` `304` 缓存 / `isLatest` 去重)、SEP-2127 `/server-card`、RFC 9728/8414 origin-root 回退探测与 `.aegis/mcp.json` / `.mcp.json` 上下文推荐（`mcp search` / `mcp recommend` / `mcp_discover`），`mcp_request_install` SHA-256 审批门控与 `/approve` 全功能控制台（OAuth 2.1 PKCE/Device Code、Vault API Key 直封、Policy 在线编辑、`Installed MCPs` 与 Outbox 管理）。
3. **Phase 3 — 方案 B 热桥接与本地 `stdio` 沙箱化 `[Done]`**：`mcp_hot_list_tools` / `mcp_hot_call_tool`（共享 `SessionBroker` `McpProxySessionPool`，严格限制当前会话已批准服务器 ACL）+ `mcp_post_install_hook` 同步写回隔离 `$AGENT_HOME` 客户端配置并在下次启动自动扶正，配合 `build_stdio_sandbox_plan_full` 对本地 `stdio` MCP 实施 Home 与 `--isolate-network` / `--allow-host` 出网白名单隔离、`.mcpb` ZIP 安全校验（`mcp_mcpb.rs`）及加固 `oci:` 容器标志。
4. **Phase 4 — 企业治理、运行时动态推送与全通道防线 `[Done]`**：私有 Enterprise Registry 气隙锁定（`mcp registry`）、Cedar `context.mcp_*` 信任分级准入、溯源元数据与保密升级生命周期（`mcp sync` / `upgrade` / `remove`）、`notifications/{tools,resources}/list_changed` 热推送与注解缓存重建（`stdio` 后台读线程 + Streamable HTTP `POST`/`GET` SSE + Option B/`SessionBroker` SSE）、非工具 MCP 通道统一净化/DLP/污点/审计与 `elicitation/create` 默认 Fail-Closed 拦截。
