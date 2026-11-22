# Aegis OS (`aegis-os`) 技术参考与用户手册 · Architecture, Threat Model & User Manual (`v0.10.0`)

> 本文档为 Aegis OS 仓库的唯一权威主文档（中文 + English 双语整合），涵盖 **架构设计**、**威胁模型**、**实际代码实现与威胁缓解对照（基线 `v0.9.1` + `v0.9.2`–`v0.10.0` 增量与外部 MCP 方案 B 实现）** 以及 **完整用户手册**。
>
> *This is the single authoritative reference for Aegis OS (`v0.10.0`, bilingual Chinese + English), covering **Architecture Design**, **Threat Model**, **Actual Implementation & Threat Countermeasures**, and the **User Manual**.*

---

## 目录 · Table of Contents

- [1. 架构设计 | Architecture Design](#1-架构设计--architecture-design)
  - [1.1 核心设计原则 | Core Design Principles](#11-核心设计原则--core-design-principles)
  - [1.2 信任边界与进程拓扑 | Trust Boundary & Process Topology](#12-信任边界与进程拓扑--trust-boundary--process-topology)
  - [1.3 十四模块 Rust 工作空间矩阵 | 14-Crate Rust Workspace Matrix](#13-十四模块-rust-工作空间矩阵--14-crate-rust-workspace-matrix)
  - [1.4 事务型 CoW VFS、四级合并与 `OrgVault` 加密卷 | Transactional CoW VFS, 4-Tier Merge & Encrypted `OrgVault`](#14-事务型-cow-vfs四级合并与-orgvault-加密卷--transactional-cow-vfs-4-tier-merge--encrypted-orgvault)
  - [1.5 五级策略引擎与协议面 (`MCP` / `A2A` / `UOMP`) | 5-Tier Policy Engine & Protocol Surface](#15-五级策略引擎与协议面-mcp--a2a--uomp--5-tier-policy-engine--protocol-surface)
- [2. 威胁模型 | Threat Model](#2-威胁模型--threat-model)
  - [2.1 核心受保护资产 | Protected Assets](#21-核心受保护资产--protected-assets)
  - [2.2 四级攻击者模型 (`A1`–`A4`) | Four-Tier Adversary Model](#22-四级攻击者模型-a1a4--four-tier-adversary-model)
  - [2.3 攻击向量分类 (`V1`–`V6` 及控制面/数据面威胁) | Attack Vectors](#23-攻击向量分类-v1v6-及控制面数据面威胁--attack-vectors)
  - [2.4 运行模式安全承诺矩阵与明确非目标 | Mode Security Matrix & Non-Goals](#24-运行模式安全承诺矩阵与明确非目标--mode-security-matrix--non-goals)
- [3. 实际实现情况与针对威胁模型的设计 | Implementation Status & Threat Countermeasures](#3-实际实现情况与针对威胁模型的设计--implementation-status--threat-countermeasures)
  - [3.1 威胁 → 代码级防御实现对照总表 (`v0.9.1`) | Threat-to-Implementation Mapping](#31-威胁--代码级防御实现对照总表-v091--threat-to-implementation-mapping)
  - [3.2 当前版本 (`v0.9.1`) 真实完备度、性能基准与已知边界 | Readiness, Benchmarks & Known Limits](#32-当前版本-v091-真实完备度性能基准与已知边界--readiness-benchmarks--known-limits)
- [4. 用户手册 | User Manual](#4-用户手册--user-manual)
  - [4.1 安装、环境自检、升级与卸载 | Install, Doctor, Upgrade & Uninstall](#41-安装环境自检升级与卸载--install-doctor-upgrade--uninstall)
  - [4.2 单 Agent 受控开发与本地硬件虚拟化 MicroVM (`Enforced` & `Isolated Mode`) | Single-Agent Enforced & Isolated MicroVM Workflow](#42-单-agent-受控开发与本地硬件虚拟化-microvm-enforced--isolated-mode--single-agent-enforced--isolated-microvm-workflow)
  - [4.3 审批控制、自定义 Cedar 策略与受控越界能力 | Approvals, Cedar Policy & Brokered Capabilities](#43-审批控制自定义-cedar-策略与受控越界能力--approvals-cedar-policy--brokered-capabilities)
  - [4.4 多 Agent 协同与多路径并行探索 (`A2A` / `IPC` / `CAS` / `Explore`) | Multi-Agent Collaboration & Parallel Path Explorer](#44-多-agent-协同与多路径并行探索-a2a--ipc--cas--explore--multi-agent-collaboration--parallel-path-explorer)
  - [4.5 `OrgVault` 加密卷、`UOMP` 记忆网关、`aegis-os mcp` 与 `Aegis Cloud` / 发布运维 | Vault, Memory, MCP, Cloud & Release Ops](#45-orgvault-加密卷uomp-记忆网关aegis-os-mcp-与-aegis-cloud--发布运维--vault-memory-mcp-cloud--release-ops)
  - [4.6 CLI 命令速查与常见故障排查 | CLI Quick Reference & Troubleshooting](#46-cli-命令速查与常见故障排查--cli-quick-reference--troubleshooting)

---

## 1. 架构设计 | Architecture Design

### 1.1 核心设计原则 | Core Design Principles

1. **事务边界替代逐次弹窗 | Transaction Boundaries over Per-Tool Prompts**：Agent 在隔离的 Copy-on-Write（CoW）影子工作区内自由读写与执行测试（零弹窗）；仅当变更需要提交回宿主机，或跨越身份/网络/凭据边界时，才触发策略评估与人类审批。
2. **内核沙箱优于进程内 Hook | Kernel Enforcement over In-Process Hooks**：客户端自带的 Hook 与 MCP 规则与 Agent 运行在同一 UID 进程空间内，仅作为 UX 兼容层（Advisory）；真正安全边界必须由父进程拉起 OS 内核沙箱（Linux `bwrap` / macOS Seatbelt / 本地 Zero-NIC 硬件虚拟化 MicroVM / Cloud microVM）+ 双令牌 Broker + 独立出口代理构成（Enforced / Isolated）。
3. **效果优先模型 | Effects over Tool Names**：策略引擎不依赖各家客户端五花八门的工具名，而围绕统一抽象原语 `EffectKind × Scope × Reversibility`（`fs.read`、`fs.write`、`proc.exec`、`net.request`、`secret.use`、`workspace_commit`）做授权决策。
4. **默认 Fail-Closed | Fail-Closed by Default**：沙箱引擎、代理、Broker 任一前置条件缺失，或自定义 Cedar 策略存在语法/未知字段错误时，系统拒绝放行而非静默降级。
5. **领域无关内核 + 领域 Profile | Domain-Agnostic Kernel + Domain Profiles**：代码（`code`）、文档（`docs`）、数据（`data`）、二进制（`binary`）、应用状态（`app_state`）、长期记忆（`memory`）与混合仓库（`mixed`）共用同一 CoW/认领/校验/提交事务内核，合并与预检语义由 `DomainProfile` 定义。

---

### 1.2 信任边界与进程拓扑 | Trust Boundary & Process Topology

```text
Host User Space (Trusted Control Plane & Supervisor)
┌──────────────────────────────────────────────────────────────────────┐
│ Human Operator Control Plane                                         │
│   aegis-os commit / approve / policy  |  Web /approve (#key / ast_*) │
│         │ Unix Socket / Localhost Loopback (human.token / TOTP)      │
│ ┌───────▼──────────────────────────────────────────────────────────┐ │
│ │ Aegis Session Supervisor & Policy Broker (Trusted)               │ │
│ │  - Dual-token separation: agent.token vs. human.token            │ │
│ │  - Cedar Policy Kernel (R0a..R4) + TOCTOU SHA-256 Frozen Stage   │ │
│ │  - L4 CONNECT / L7 Model Base-URL Proxy ($AOS_SECRET_* inject,     │ │
│ │    reversible PII pseudonymization & budget/loop circuit breaker)  │ │
│ │  - Hash-chained Audit Flight Recorder (outside sandbox)          │ │
│ └───────┬──────────────────────────────────────────────────────────┘ │
│         │ Kernel / Hypervisor Confinement                            │
│         │ (bwrap --bind-fd / Seatbelt / vfkit|cloud-hypervisor + vsock) │
│ ┌───────▼──────────────────────────────────────────────────────────┐ │
│ │ Untrusted Agent Process Tree                                     │ │
│ │   claude / opencode / agy / hermes / codex                       │ │
│ │   ├─ Native fs / shell (Host repo RO; Shadow RW; $HOME masked)   │ │
│ │   ├─ .aegis-bin/git shim (RO host objects + private index)       │ │
│ │   ├─ aegis-os mcp-bridge  ──▶ Supervisor Broker                  │ │
│ │   └─ Child processes, repo build scripts & third-party plugins   │ │
│ └──────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

**不变量 · Key Invariants**:
- Agent 进程树内的一切代码（含第三方 MCP Server、插件、仓库 `build.rs` / `Makefile` / `package.json` 脚本）均被视为**不可信**。
- 宿主机项目唯一受控写入路径为 Broker 的 `workspace_commit` / `workspace_git` / `fs_export_file`（经冻结快照与 SHA-256 `evidence_hash` 校验）。
- 审批接口仅接受人类凭证（`human.token`、带签名的短期单笔 `ScopedEscalationTicket` `ast_*` 或 Cloud TOTP），`agent.token` 无法自批。
- 审计账本 `audit.jsonl` 位于沙箱外部，仅支持追加写，且每次验证校验 `GENESIS_HASH` 与完整 JSONL 链。

---

### 1.3 十四模块 Rust 工作空间矩阵 | 14-Crate Rust Workspace Matrix

| Crate | 中文职责 | Primary Responsibility (English) |
|---|---|---|
| `aos-core` | 核心领域模型（`EffectKind`、`AgentIdentity`、`LeaseGrant`）、任务级文件认领表、`DomainProfile`（6 类合并与 DLP 校验） | Shared core traits/types (`EffectKind`, `WorkspaceDomain`, identity/leases), glob file claims, `DomainProfile` merge & DLP verifiers |
| `aos-vfs` | 事务型 CoW 影子工作区、`ensure_no_symlink_components` 防穿越、4 级 LCS Diff3 自动合并、冻结提交、`OrgVault` OS 加密卷、`SealedSecretBlob` (`AES-256-GCM`) 凭据密封、组织共享 CAS/KV | Transactional CoW VFS (`clonefile`/`FICLONE`/atomic copy fallback), 4-tier LCS Diff3 merge, frozen commit staging, encrypted `OrgVault`, `SealedSecretBlob` secret sealing, Org CAS/KV |
| `aos-sandbox` | OS 原生沙箱与本地 MicroVM 驱动：Linux `bwrap --bind-fd --unshare-net`、macOS Seatbelt Profile、本地硬件虚拟化 Zero-NIC MicroVM（macOS `vfkit`/`krunkit` + Linux `cloud-hypervisor`/`virtiofsd` + `virtio-vsock`）、SHA-256 镜像验签与隔离环境变量过滤 | Native kernel & local MicroVM sandbox drivers (Linux `bwrap`, macOS Seatbelt, Zero-NIC `vfkit`/`krunkit` & `cloud-hypervisor`+`virtiofsd` over `virtio-vsock`), SHA-256 VM image verification, fail-closed enforcement |
| `aos-guest-init` | Linux MicroVM Guest PID-1 Init 与 `AF_VSOCK` 守护进程：初始化 `lo`、挂载 `virtiofs` 共享（`aegis_ws` 映射至宿主机规范路径、`aegis_home`、`aegis_ro`、`aegis_pub`）、port `10700` Token 鉴权 JSONL RPC 与 port `18080` + `bridge_token` 出口流量转发 | Linux MicroVM PID-1 guest init (`lo` setup, `virtiofs` mounts `aegis_ws`/`aegis_home`/`aegis_ro`/`aegis_pub`), authenticated JSONL RPC on `AF_VSOCK` `10700`, `127.0.0.1:<proxy_port>` -> `18080` egress relay with 32-byte `bridge_token` |
| `aos-egress` | 本地 L4 `CONNECT` 与 Model API L7 反向代理（含 `--isolated` `/__aegis/mcp/` 本机 Broker 转发）、SSRF 私网阻断、DLP、共享可逆 PII 假名化（`pseudonym.rs`）及原子 `SharedBudgetPool`/循环熔断网关 | L4 `CONNECT` & L7 Base-URL reverse proxy (plus `/__aegis/mcp/` isolated VM broker relay), private/metadata IP blocking, URL/header/body DLP, shared session PII pseudonymization (`pseudonym.rs`), and atomic `SharedBudgetPool`/tool-loop circuit breakers |
| `aos-policy` | 引用感知 Fail-Closed Cedar 策略解析器、`R0a`–`R4` 五级策略内核、敏感路径防投毒、跨边界动态会话污点账本（`SessionTaintRecord` / `session_taints.json`）、原子 `OneShot`/TTL/任务租约与审批队列 | Quote-aware fail-closed Cedar parser & evaluator, `R0a`–`R4` policy kernel, cross-boundary dynamic session taint guard (`SessionTaintRecord`), atomic sensitive leases, escalation queue |
| `aos-ipc` | A2A Peer 发现与心跳活性、分层任务 DAG 状态机、P2P 邮箱、`artifact://` 校验、原子 `0o600` 持久化与 `reply()` 单事务入队 | Peer registry, hierarchical A2A task DAG state machine, mailboxes, correlated RPC/pub-sub, atomic `0o600` state persistence |
| `aos-recorder` | 不可篡改 SHA-256 哈希链飞行记录器、`trace_task` 与严格链校验（`GENESIS_HASH` 防截断与 `sync_data` 落盘） | Hash-chained JSONL audit flight recorder with strict `GENESIS_HASH` verification and `sync_data` persistence |
| `aos-memory` | UOMP 长期记忆作用域匹配、`deny` 优先语义、`RemoteProfile` 声明与防溢出 `ttl` 租约规划 | UOMP memory scope matcher, deny-wins rules, `RemoteProfile` validation, overflow-safe TTL calculations |
| `aos-memory-store` | 基于 SQLite (`WAL` + `busy_timeout(5s)`) 的记忆持久化、`BEGIN IMMEDIATE` 原子审批 `staged_writes` 与密文 payload 存储 | SQLite (`WAL` + `busy_timeout`) memory store with `BEGIN IMMEDIATE` `staged_writes` approval and encrypted payload blobs |
| `aos-memory-server` | 本地 UOMP Memory Guard HTTP 服务：Ed25519 JWT 签发/验证、`verify_active_session`（`token_hash`+库内 scope）、consent 流 | Local UOMP Memory Guard server (`EdDSA` JWT issuer, `verify_active_session` DB binding, consent & payload APIs) |
| `aos-memory-gateway` | 面向远程 Agent 的 TLS 1.3 / mTLS UOMP 代理网关：限流、并发信号量、I/O 超时、防 HTTP 走私帧校验 | TLS 1.3 / mTLS UOMP remote memory gateway with concurrency semaphore, rate limiting, timeouts, and framing checks |
| `aos-mcp-gateway` | 默认 55 项（3 档 `GatewayToolProfile`）MCP 工具 + 8 动态资源、Streamable HTTP/GET SSE 异步客户端（`mcp_http.rs`）、开放/企业私有 Registry 发现与气隙锁定（`mcp_registry.rs`）、`.mcpb` 安全校验（`mcp_mcpb.rs`）、OAuth 2.1 Auth Realms（`mcp_oauth.rs`）、声明式 MCP Bundle（`mcp_bundle.rs`）、全通道零信任 MCP 防火墙/暂存箱（`mcp_firewall.rs`）与方案 B 会话热桥接 | MCP JSON-RPC + A2A server (3 `GatewayToolProfile` tiers, 8 resources), async Streamable HTTP/SSE (`mcp_http.rs`), Open & Enterprise/Airgapped MCP Registry (`mcp_registry.rs`), `.mcpb` verifier (`mcp_mcpb.rs`), OAuth 2.1 Auth Realms (`mcp_oauth.rs`), Declarative Bundles (`mcp_bundle.rs`), Full-Channel Zero-Trust MCP Firewall/Outbox (`mcp_firewall.rs`) & Option B Hot Session Bridge |
| `aos-cli` | `aegis-os` 单一二进制入口：`install`、`run`（含 `--isolated`/`--tool-profile` 及 `agy`/`claude` 沙箱 MCP 桥接）、`vm`、`explore`、`mcp`（`status`/`doctor --probe`/`search`/`recommend`/`install`/`sync`/`upgrade`/`remove`/`registry`/`scan`/`adopt`/`add`/`policy`/`proxy`/`login`/`logout`/`auth-status`/`bundle`/`outbox`/`audit`/`taint`）、`approve`、`diff`/`verify`/`commit`、`vault`、`cloud`、`upgrade`/`uninstall` | Single `aegis-os` binary: installer, `run` (`--isolated`, `--tool-profile`, confined `agy`/`claude` MCP bridge), `vm`, `explore`, `mcp` Lifecycle/Firewall/OAuth/Registry/Bundles/Audit, unified `approve`, CoW `diff`/`commit`/`verify`, `vault`, `cloud`, `upgrade`/`uninstall` |

---

### 1.4 事务型 CoW VFS、四级合并与 `OrgVault` 加密卷 | Transactional CoW VFS, 4-Tier Merge & Encrypted `OrgVault`

#### 持久化目录布局 | Runtime Layout (`~/.aegis` 或 `AOS_RUNTIME_DIR`)
```text
<runtime_dir>/                              # default: ~/.aegis
  vaults/
    <org>.sparsebundle | <org>.luks.img     # Per-org OS encrypted volume image
    <org>.dek.enc.json                      # AES-256-GCM wrapped DEK envelope (Aad = org_id)
    <org>.vault.json                        # Mount & backend metadata
  orgs/<org>/                               # Mounted OrgVault volume (0o500 when locked)
    agents/<agent>/cow_workspace/
      upper_workspace/                      # Writable CoW shadow (Agent R/W)
      baseline/                             # Rebase & 3-way merge baseline
  sessions/<session_id>/                    # session.json, agent.token, human.token, proxy cfg
  host_commit.lock                          # Serialized host commits & epoch state
```

#### CoW 与四级合并流水线 | CoW & 4-Tier Merge Pipeline
1. **安全 CoW 复制与无符号链接校验**：macOS 使用 APFS `clonefile(..., CLONE_NOFOLLOW)`，Linux 使用 Btrfs/XFS `FICLONE`，跨卷/无 reflink 回退至 `O_RDONLY | O_NOFOLLOW` + 同目录唯一临时文件 + `sync_all` + `rename`；`refresh_from_host`、`stage_commit_inner`、`apply_staged_actions` 在操作 `shadow_root`、`baseline_root`、`host_source_root` 前均通过 `ensure_no_symlink_components` 拒绝穿越与符号链接。
2. **Git 视图分离与防投毒 Shim**：宿主机 `.git/objects` 只读挂载，Agent 会话使用私有 `GIT_INDEX_FILE`；`.aegis-bin/git` Shim 强制 `-c core.fsmonitor=false -c core.hooksPath=/dev/null` 阻断 `git status` 夹带代码执行。
3. **四级归并 | 4-Tier Auto-Merge**：
   - Tier 1：宿主未改或 Agent 未改 → Fast-Forward（并刷新 `mtime` 触发增量编译）。
   - Tier 2：不同行修改、相同修改、超集增量或可交换导入声明 → LCS Diff3 自动合并。
   - Tier 3：重叠冲突 → 保持干净隔离并上报告警（绝不向代码注入 `<<<<<<<` 冲突标记）。
   - Tier 4：二进制文件 → 排他锁 + 基线 SHA-256 校验，需显式 `--overwrite-binaries`。
4. **`OrgVault` 密钥封装 (`KEK -> DEK`)**：主 KEK 按 `AOS_VAULT_MASTER_KEY` → macOS Keychain（通过 `/usr/bin/security -i` 标准输入写入）→ Linux Secret Service → `0o600 ~/.config/aegis-os/master.kek` 顺序解析；每组织独立 DEK 由 `AES-256-GCM` 密封并绑定 `Aad = org_id`。

---

### 1.5 五级策略引擎与协议面 (`MCP` / `A2A` / `UOMP`) | 5-Tier Policy Engine & Protocol Surface

| 优先级 Tier | 评估逻辑 | Evaluation Semantics |
|---|---|---|
| **R0a** | 宿主红线（大小写折叠 `~/.ssh`、`~/.aws`、`~/.gnupg`、`~/.kube`、`/etc/shadow`、`/System`、`proc_exec` 提权命令、回环/Link-Local SSRF、自定义 Cedar `forbid`）；硬拒绝 | Host red-lines (case-folded credentials/system paths, `proc_exec` privesc before lease check, SSRF, Cedar `forbid`); hard `Deny` |
| **R0b** | 提交与 Git 防投毒守卫：涉及 `.git/`、`.github/workflows`、`.envrc`、`build.rs`、`Makefile`、`Cargo.toml`、`package.json`、`.agents/hooks.json` 或 `skip_verify` / `overwrite_binaries` 时强制升级 | Commit/Git poisoning & flag guard (`workspace_commit_sensitive` / `workspace_git_sensitive`); bypasses general session leases |
| **R1** | 跨组织租户隔离门禁（非信任工作站 Peer 的跨租户访问直接拒绝） | Cross-tenant gate (`Deny` unverified cross-org access) |
| **R2** | 会话级 / 任务级 / 单次原子租约：`OneShot`、`TaskScoped`、`Ttl`；支持 `#sha256:<evidence_hash>` 防 TOCTOU 锚定（`host_exec` 仅认内存表） | Session/Task/OneShot leases with `#sha256:` pinning & atomic multi-target check |
| **R3** | 声明式 Cedar `permit` 绿区（如自己 CoW 工作区 `fs_*`、`proc_exec`、同组织 IPC/CAS） | Declarative Cedar green-zone rules (`policy/default.cedar` + custom) |
| **R4** | 黄区边界升级：生成带结构化 `evidence` 的待批工单（CLI / Web `/approve` / Cloud TOTP） | Human escalation with 30m default ticket TTL |

**协议能力总览 | Protocol Surface (3 `GatewayToolProfile` Tiers: `standard`=55 default, `collab`=27, `minimal`=10 + 8 Resources)**:
- **VFS 与宿主机桥 (15)**：`fs_read`、`fs_write`、`fs_edit`、`fs_delete`、`fs_glob`、`fs_export_file`、`fs_import_file`、`workspace_status`、`workspace_sync`、`workspace_snapshot`、`workspace_diff`、`workspace_rollback`、`workspace_commit`、`workspace_export_pr`、`workspace_switch`。
- **Git / GitHub 宿主机代理 (9)**：`workspace_git_inspect`、`workspace_git`、`github_ci_inspect`、`github_ci_rerun`、`github_pr_inspect`、`github_issue_inspect`、`github_pr_create`、`github_comment_create`、`github_pr_merge`。
- **沙箱执行与包管理 (3)**：`proc_exec`、`pkg_install`（`npm`/`pnpm`/`yarn`/`bun`/`pip`/`uv`/`cargo`/`go`）、`host_exec`。
- **IPC / 文件认领 / A2A / 组织 CAS (19)**：`ipc_{send,recv,request,reply,ack,wait,publish,subscribe,list_peers}`、`coord_{claim,release}`、`ipc_{update_card,task_update,task_get,task_list}`、`org_{artifact_publish,artifact_fetch,kv_put,kv_get}`；含 HTTP A2A 端点 `/.well-known/agent.json`、`/a2a`、`/v1/a2a`。
- **Egress / Policy / UOMP (4)**：`egress_http_request`、`policy_list_escalations`、`runtime_configure_mode`、`memory_policy_evaluate`。
- **外部 MCP 控制面与方案 B 热桥接 (5)**：`mcp_list_installed`、`mcp_discover`、`mcp_request_install`（SHA-256 锁定 + Web `/approve` 宿主机内联 Vault 凭据直封）、`mcp_hot_list_tools`、`mcp_hot_call_tool`。
- **8 个动态 MCP 资源**：`aegis://workspace/status`、`aegis://ipc/inbox`、`aegis://org/peers`、`aegis://global/peers`、`aegis://a2a/agent-cards`、`aegis://a2a/tasks`、`aegis://org/shared/catalog`、`aegis://mcp/installed`。
- **外部 MCP 数据面与控制面边界 | External MCP Data/Control Plane**：受限沙箱内的 `agy`、`claude`、`opencode`、`codex`、`cursor` 通过无凭证 1:1 代理桩（`aegis-os mcp proxy <id>` / `/__aegis/mcp/<id>`）经宿主机 `SessionBroker` (`McpProxySessionPool`) 原生调用外部 MCP；开放生态发现（Official MCP Registry / `.well-known`）、审批安装与 `v0.10.0` **方案 B（会话内临时热桥接 + 下次启动自动扶正）** 详见 [外部 MCP 对接架构设计 (`EXTERNAL_MCP_DESIGN.md`)](EXTERNAL_MCP_DESIGN.md)。

---

## 2. 威胁模型 | Threat Model

### 2.1 核心受保护资产 | Protected Assets

1. **宿主机仓库与可执行供应链文件**：源码、未提交工作区、Git 对象与钩子（`.git/hooks`、`.envrc`、`.github/workflows`、构建脚本 `build.rs`/`Makefile`）。
2. **宿主机凭据与环境秘钥**：`~/.ssh`、`~/.aws`、`~/.gnupg`、`~/.kube`、`~/.config/gh`、macOS Keychain、项目/主目录 `.env*` 文件。
3. **模型 API 真实密钥与运行时秘密**：仅存在于宿主机侧的 `$AOS_SECRET_*`、云端计费/TOTP 状态、主 KEK（`master.kek`）与组织 DEK 信封（`*.dek.enc.json`）。
4. **控制平面鉴权与完整性资产**：`human.token`、`AOS_ADMIN_SECRET`、短期单笔票据 `ast_*`、Cedar 策略集合、多租户工作区与 UOMP 长期记忆及不可篡改审计日志 `audit.jsonl`。

---

### 2.2 四级攻击者模型 (`A1`–`A4`) | Four-Tier Adversary Model

| 等级 Level | 对手画像 Adversary Profile | 典型能力 Capabilities | 期望覆盖模式 Required Mode |
|---|---|---|---|
| **A1** | 诚实但会误操作的 Agent | 幻觉误删、误改无关文件、误读 `.env` | Advisory 即可 |
| **A2** | 遭间接 Prompt Injection 劫持的 Agent | 受文档/Issue/网页恶意指令诱导发起越界工具调用 | Enforced |
| **A3** | 完全被控 Agent / 仓库恶意脚本（含 `V1`–`V6` Payload） | 任意系统调用、符号链接竞争、原始 Socket 外连、自篡改 CLI 插件/MCP 配置 | Enforced |
| **A4** | 本机恶意用户 / 同 UID 本地恶意软件 | 强杀守护进程、直接替换全局二进制、篡改本机配置 | Isolated（云端/独立 microVM 覆盖） |

---

### 2.3 攻击向量分类 (`V1`–`V6` 及控制面/数据面威胁) | Attack Vectors

| 向量编号 | 威胁场景 | Threat Scenario |
|---|---|---|
| **V1** | 宿主机越界写入与符号链接逃逸 | Agent 修改 Shadow 中的符号链接或中间目录链接，借同步/提交阶段向宿主机任意文件写覆（含跨文件系统克隆半写丢文件）。 |
| **V2** | 凭据窃取与动态库/Keychain 注入 | 读取 `$HOME/.ssh`、Keychain CLI 弹出/读取、经 `DYLD_INSERT_LIBRARIES` / `LD_PRELOAD` 注入扩展权限、或绕过 DLP 的多处私钥特征遮蔽与 `security add-generic-password -w` 命令行泄密。 |
| **V3** | 自篡改配置与 Git / Hook RCE | 重写 `.claude/settings.json` / `.agents/hooks.json` / `opencode.json` 关闭 Hook；写入 `.git/config` `fsmonitor` 触发宿主机 RCE；利用 APFS 大小写不敏感路径（`.Git/hooks`）或逗号文件名绕过敏感守卫。 |
| **V4** | 网络外泄、SSRF 与 HTTP 走私 | 原始 Socket 直连外网；借助 DNS 重绑定 / `::ffff:127.0.0.1` / `100.64.0.1` / `169.254.169.254` 进行 SSRF；在 URL Path/Query/Header 夹带密钥外传；发送冲突 `Content-Length` + `Transfer-Encoding` 进行 HTTP 请求走私。 |
| **V5** | 提交 TOCTOU、控制面越权与策略绕过 | 人工审批后篡改影子文件实现 diff-swap；利用终端转义符伪造审批界面；匿名访问控制面状态或重放 TOTP；伪造 Cedar `"https://..."` / 通配符 / 未知条件致 Fail-Open；`OneShot` 租约半消耗或跨参数重放。 |
| **V6** | 沙箱间信号窥探、并发撕裂与跨租户混淆 | 同机跨沙箱发送 `signal` / 读取 `process-info*`、访问系统剪贴板、伪造 `exit 71` 触发无沙箱测试回退；PaaS/CAS/KV/SQLite 并发覆盖；IPC `list_tasks` 跨边错配与半崩溃丢响应；UOMP 越权使用撤销会话或远程 `audience` 令牌直连本地 Guard；审计日志截断首行绕过链校验。 |

---

### 2.4 运行模式安全承诺矩阵与明确非目标 | Mode Security Matrix & Non-Goals

| 模式 Mode | 启动命令 | 强制执行点 | 抵抗 `A1` | 抵抗 `A2` | 抵抗 `A3` | 抵抗 `A4` |
|---|---|---|---|---|---|---|
| **Advisory** | `aegis-os install` 后直接运行 Agent | Hook / MCP / Rules | ✅ | ⚠️ 部分 | ❌ | ❌ |
| **Enforced** | `aegis-os run -- <agent>` 或 `install --enforce` Shim | 父进程内核沙箱 (`bwrap`/Seatbelt) + Broker + 代理 | ✅ | ✅ | ✅ | ⚠️ 主动绕过可检测 |
| **Isolated** | `aegis-os run --isolated -- <agent>` / `explore run --isolated` / Aegis Cloud | 本地 Zero-NIC 硬件虚拟化 MicroVM (`vfkit` / `cloud-hypervisor` + `virtio-vsock`) 或远端云沙箱 | ✅ | ✅ | ✅ | ✅（独立内核/托管环境） |

**明确非目标 | Explicit Non-Goals**:
- 不承诺在**本机用户拥有与 Supervisor 同等 UID 且主动关闭/卸载 Aegis** 的前提下阻止人工物理绕过；
- 不承诺防御 OS 内核 0-day、硬件侧信道攻击或固件木马；
- 不承诺隐藏模型 API 对正常授权上下文源代码的传输（Agent 读取授权项目代码并发送至其配置的模型提供商属于预期功能，边界仅保护未授权密文与非目标主机）。

---

## 3. 实际实现情况与针对威胁模型的设计 | Implementation Status & Threat Countermeasures

### 3.1 威胁 → 代码级防御实现对照总表 (`v0.9.1`) | Threat-to-Implementation Mapping

| 威胁类别 | 核心代码模块 | 具体安全设计与 `v0.9.1` 加固实现 |
|---|---|---|
| **V1 宿主机写逃逸与符号链接穿越** | `crates/aos-vfs/src/lib.rs`<br>`crates/aos-mcp-gateway/src/{lib,mcp_bundle}.rs`<br>`crates/aos-core/src/lib.rs` | - `CoWWorkspace::ensure_no_symlink_components` 在 `refresh_from_host`、`stage_commit_inner`、`apply_staged_actions` 对基准目录、影子目录与宿主机目标路径逐级校验 `symlink_metadata`，拒止一切 `..` 与符号链接组件。<br>- `cow_clone_file_inner` 使用同目录随机临时文件先行克隆（macOS `clonefile(CLONE_NOFOLLOW)` / `O_RDONLY \| O_NOFOLLOW` 回退）并 `sync_all` 后再原子 `rename`，杜绝先删目标导致断电/失败丢文件。<br>- `TransactionalWorkspace::commit_frozen_to_host_with_options` 提交前强制比对冻结目录内容哈希与已审 `evidence_hash` 防 TOCTOU；`--isolated` MicroVM 下通过 `virtio-fs` 仅挂载 CoW `shadow` 根（`aegis_ws`）及会话级 `aegis_home`（`aegis_ro` 只读）；`mcp_bundle` 安装技能使用 `O_NOFOLLOW` 与父链无符号链接写盘并严格限制规模；受限 `agy`/`claude` 会话所有 MCP 配置均仅在 `agent_home` 内部编排，绝不污染 CoW `shadow` 代码树。 |
| **V2 `$HOME`/Keychain/环境/MCP 明文凭据窃取、OAuth 2.1 Auth Realms 与受限代理桥接** | `crates/aos-sandbox/src/lib.rs`<br>`crates/aos-vfs/src/vault.rs`<br>`crates/aos-mcp-gateway/src/{mcp_firewall,mcp_oauth}.rs`<br>`crates/aos-cli/src/{launcher,session_broker}.rs` | - Linux `bwrap` 用 `--tmpfs` 遮蔽 `$HOME`、`/run`；macOS Seatbelt 在 `tighten_home_read` 下默认拒读宿主机 `$HOME`，显式封锁 `~/.ssh`、`~/.aws`、`~/.gnupg`、`~/.kube`、`*/.env*`、Keychain、`human.token` 与 `master.kek`。<br>- **`aegis-os mcp adopt` 明文收编 + `mcp_oauth.rs` 云端 Auth Realms**：`SealedSecretBlob` (`AES-256-GCM`) 密封静态秘钥与 OAuth 2.1（PKCE `S256` / RFC 8628 Device Code / 动态刷新令牌）凭据，DNS 标签与 IPv6 方括号剥离严格校验 `allowed_hosts`，校验证书与 RFC 9728/8414 `issuer`/`resource` 一致性，扩域/改端点（`upsert_realm_config`）自动清空旧访问/刷新令牌，支持缺省 `registration_endpoint` 的 Bundle 经 RFC 8414 自动发现并用单flight刷新锁与磁盘热加载生效。<br>- **受限 `agy` / `claude` / `opencode` / `codex` 沙箱 MCP 清洗与只读加固**：`sanitize_seeded_agent_home` 与 `scrub_unadopted_mcp_secrets_in_agent_home` 全面清除 `.claude.json`（含项目级 `projects[*].mcpServers`）、`.claude/settings.json`、`opencode.jsonc` 及 Codex 内联环境中的敏感秘钥；`.run/aegis-broker.json` 以 `O_NOFOLLOW`、`0o600` 写入并纳入 `PROTECTED_AGENT_CONFIGS`；`--isolated` MicroVM 在获取动态 `guest_proxy_port` 后注入 `http://127.0.0.1:<port>/__aegis/mcp/*` 与 `http://` 控制桥。<br>- `DefaultOsKekProvider` 加 `master.kek.lock` 与 `EphemeralRuntimeKekProvider`；`DomainProfile::contains_secret_signature` 与 MCP 入站净化器对误吐的 `AKIA`、`ghp_`、`sk-`、PEM 私钥执行兜底脱敏。 |
| **V3 配置自篡改、Git/Hook RCE 与间接 Prompt Injection 致命三要素** | `crates/aos-sandbox/src/lib.rs`<br>`crates/aos-policy/src/lib.rs`<br>`crates/aos-mcp-gateway/src/mcp_firewall.rs`<br>`crates/aos-cli/src/{launcher,routing}.rs` | - 客户代理关键配置文件（`.claude/settings.json`、`.mcp.json`、`opencode.json`、`.gemini/config/mcp_config.json`、`.gemini/antigravity-cli/mcp_config.json`、`.cursor/mcp.json`、`.codex/config.toml`、`.hermes/config.yaml`、`.run/aegis-broker.json`）只读锁定或剥离写入权限；`.aegis-bin/git` Shim 锁定 `core.fsmonitor=false`、`core.hooksPath=/dev/null`。<br>- **全通道 MCP 入站净室清洗与动态会话污点 (`SessionTaintRecord`)**：`mcp_firewall.rs` 覆盖 `tools/call`、`tools/list`、`resources/{read,list}`、`resources/templates/list`、`prompts/{list,get}`、`completion/complete` 及 SSE/`stdio` 推送通知，自动剥离 HTML `<script>/<style>/<!--...-->`、隐藏 CSS、1×1 追踪像素与含 `U+00AD`/Unicode Tags 在内的零宽/双相控制符；读取 `UntrustedExternal` MCP 数据立即记录单调时间戳污点（Step `2c`/`2f`），收紧宽泛 `workspace_commit`/`git`/`fs_export_file`/`egress_unlisted_domain`/GitHub 写租约；服务端主动请求（`elicitation/create`、`sampling/*`）默认 Fail-Closed 拦截（`-32601`）。 |
| **V4 网络外泄、SSRF、Streamable HTTP/SSE 遥测 MCP 代理、双向 PII 脱敏与预算熔断** | `crates/aos-egress/src/{lib,pseudonym,breaker,pricing}.rs`<br>`crates/aos-mcp-gateway/src/{mcp_http,mcp_firewall}.rs`<br>`crates/aos-cli/src/{launcher,session_broker,mcp_guard}.rs` | - `is_forbidden_outbound_ip`、`is_forbidden_mcp_ip`（DNS Pin 绑定校验 + 禁重定向泄密）拦截回环/私网/CGNAT/云元数据；本地 `stdio` MCP 支持 `--isolate-network --allow-host`（Linux `--unshare-net` + `egress-shim` / macOS Seatbelt localhost 白名单代理）封锁未授权外网；Zero-NIC `--isolated` MicroVM 物理移除网卡经 `AF_VSOCK` `18080` 出站，经 `http://<proxy>/__aegis/mcp/{_kernel,<server_id>}` 无缝中继至宿主机 `SessionBroker`。<br>- **`mcp_http.rs` 异步 Streamable HTTP/GET SSE MCP 客户端**：`tokio-rustls` + `webpki-roots` 有界行读取（拒绝重复 `Content-Length`、`Transfer-Encoding`+`Content-Length` 走私）、`text/event-stream` SSE (`POST` + 可选 `GET` 流) 实时转发 `notifications/progress`、`notifications/{tools,resources}/list_changed` 并自动失效重建 `tool_annotations` 缓存、`401` 刷新重放、`404` 锁安全重握手；仅对 TrustedInternal / Bundle 端点透传 `X-Aegis-{Agent,Session,Turn}-Id`。<br>- **可逆 PII 假名化与 Block 模式 (`pseudonym.rs`)**：L7 + 全 MCP 通道实现响应端 `Pseudonymize` / `Block`（`-32004`）与请求参数/资源 URI/Prompt 变量宿主机精确还原。 |
| **V5 控制面越权、TOCTOU、Cedar/租约与 MCP 事务暂存箱 (External CoW)** | `crates/aos-mcp-gateway/src/{paas,lib,approver,mcp_firewall,mcp_registry,mcp_mcpb}.rs`<br>`crates/aos-policy/src/lib.rs`<br>`crates/aos-cli/src/{cloud,hooks,explore,mcp_guard}.rs` | - **MCP 风险分级与 SHA-256 锁定事务暂存箱 (`McpOutboxTicket`)**：`classify_mcp_tool` 按「`tool_overrides` → SQL CTE/多语句剖析 → MCP `annotations`（监听 `list_changed` 动态失效刷新）→ 动词分词（未知工具 Fail-Closed 为 `StagedWrite`）」自动分层；128-bit UUID `ticket_id` 冻结参数与 `payload_sha256`，支持 CLI 与 Web `/approve` 全功能台审批直发。<br>- **Cedar Trust Tier 准入、气隙锁定与 `.mcpb`/OCI 加固**：Cedar 支持 `context.mcp_trust_tier`/`mcp_domain_verified`/`mcp_registry_type` 规则；`mcp registry --airgapped` 封锁公共回退；`.mcpb` 安全解压防 Zip-Slip/Symlink 穿越、`npm`/`pypi`/`oci` 严格定版与加锁 OCI 标志。 |
| **V6 跨进程探测、状态撕裂、跨租户混淆与 MCP 审计黑匣子** | `crates/aos-sandbox/src/{lib,microvm/mod}.rs`<br>`crates/aos-recorder/src/lib.rs`<br>`crates/aos-ipc/src/lib.rs`<br>`crates/aos-memory-*`<br>`crates/aos-cli/src/vm.rs` | - macOS Seatbelt 禁跨沙箱 `signal`/`process-info*`/剪贴板；`--isolated` Zero-NIC MicroVM 启动强制校验 `verify_cached_vm_images`（OpenSSH `.sig` 验签 + SHA-256）；缺少前提严格 Fail-Closed。<br>- **MCP 全通道防篡改黑匣子**：覆盖 `mcp.tool.*`、`mcp.tools.list`、`mcp.resource*`、`mcp.prompts*`、`mcp.completion.complete`、`mcp.notification.*`、`mcp.elicitation.*` 及 `mcp.outbox.*`，全量记录 SHA-256 与脱敏统计写入 `AegisFlightRecorder`，`aegis-os mcp audit --verify` 严格校验 `GENESIS_HASH` 与全链完整性。 |

---

### 3.2 当前版本 (`v0.9.1`) 真实完备度、性能基准与已知边界 | Readiness, Benchmarks & Known Limits

#### 实测验证基线 (`v0.9.1`) | Verified Quality & Benchmark Baseline

| 评估维度 | 实测指标与来源 |
|---|---|
| **`v0.9.1` 源码全仓门禁** | `cargo clippy --workspace --all-targets -- -D warnings`: **0 warnings / 0 errors**；`cargo check --workspace --locked`: exit **0**；`cargo test --workspace`（14 crates）：**346 passed, 0 failed**（`aos-egress` 中 2 项需外网直连 Anthropic API 用例按原标注 `#[ignore]` 跳过）。 |
| **`V1–V6` 越界利用套件 (Paper 2)** | **0/30 (0.0%)** 逃逸（macOS Seatbelt 与 Linux `bwrap --bind-fd` 均全拦截），对比 Advisory Hooks **93.3%**、厂商自带沙箱 **73.3%–83.3%**、`nerdctl` 容器 **80.0%**。 |
| **四大真实 Agent 投毒实测** | `claude`、`opencode`、`agy`、`hermes` 跨 60 格子矩阵实测：`aegis_enforced` 宿主机被攻破率 **0% (0/4)**（对比 `vendor_default` **100% (4/4)**），正常多文件编程通过率 **100% (8/8)**。 |
| **启动、代理与提交门开销** | Enforced 启动延迟 **9.91 ms**（Linux `bwrap`） / **20.38 ms**（macOS Seatbelt）；L7 模型反代首 Token 仅增加 **+0.221 ms**；500 MB 紧凑 Git 仓库 APFS 增量仅 **4.76 MB**（节省 **99.05%**），Btrfs `FICLONE` 净增量 **0.00 MB**。 |
| **弹窗削减与多 Agent 自动合并** | 52 份真实会话、28,087 次工具调用统计弹窗减少 **90.7%–97.9%**；4 级 LCS 自动归并率 **98.7%**。 |

#### 当前已知边界与后续演进 | Known Limits & Roadmap

1. **macOS `cwd` 与 Linux 路径重映射差异**：Linux `bwrap --bind-fd` 将 CoW Shadow 直接覆盖挂载到宿主机原路径；macOS 无 rootless bind-mount，Seatbelt 会话 `cwd` 位于 `upper_workspace`、宿主机目录只读挂载（完整 macOS 用户态 VFS 路径重映射计划于 Phase 4）。
2. **Ubuntu 24.04+ 非特权 Userns AppArmor 限制**：若系统开启 `kernel.apparmor_restrict_unprivileged_userns=1` 且未安装 `/etc/apparmor.d/bwrap`，`aegis-os run` 将 Fail-Closed 拒绝启动并打印配置指引。
3. **非模型类普通 HTTPS**：模型提供商 API 走 L7 反向代理（无 TLS MITM，完整扫描请求体/头/URL）；其他白名单 HTTPS 站点走 L4 `CONNECT` 域名白名单过滤。
4. **高级领域 CRDT 与非 MicroVM 下 macOS 路径重映射**：本地 `--isolated` Zero-NIC 硬件虚拟化 MicroVM（`vfkit`/`krunkit` & `cloud-hypervisor`+`virtiofsd`）、`virtio-vsock` 交互式流式 PTY 终端与镜像自动化构建打包（`./scripts/build_vm_images.sh` + CI 发布签名产物 `aegis-vm-*`）已完整就绪；Office/Data 块级 CRDT 与非 MicroVM 模式 macOS 用户态 VFS 路径重映射归入后续演进。
5. **`v0.9.2`–`v0.9.3` 增量与 `v0.10.0` 外部 MCP 演进 | `v0.9.2`–`v0.9.3` Milestones & `v0.10.0` External MCP Roadmap**：`v0.9.2` 优化了 `ext4` CoW 启动复制与大仓库/嵌套多仓（umbrella workspace）启动卡死防护及 PTY `EINTR`/`FD_CLOEXEC` 加固；`v0.9.3` 彻底废弃移除旧 `AAP-1.0` / `app_store` / `aegis-os app` 子系统，修复热升级后 Linux `current_exe()` `(deleted)` 恢复，且 14-crate 全仓测试持续通过。`v0.10.0` 已完整落地开放 MCP Registry 发现、`stdio` OS 沙箱化、Web `/approve` 宿主机内联 Vault 凭据直封与 **方案 B 会话热桥接**，架构详情见 [EXTERNAL_MCP_DESIGN.md](EXTERNAL_MCP_DESIGN.md)。

---

## 4. 用户手册 | User Manual

### 4.1 安装、环境自检、升级与卸载 | Install, Doctor, Upgrade & Uninstall

#### 1) 安装 | Installation
```bash
# macOS / Linux (Homebrew)
brew tap heurion-org/aegis-os https://github.com/heurion-org/aegis-os.git
brew install aegis-os

# 或使用 OpenSSH 签名验证的一键安装脚本 / Signed one-line installer
curl -fsSL https://heurion.org/aegis-cloud/install.sh | sh

# 或从本地源码构建 / Build from source
git clone https://github.com/heurion-org/aegis-os.git && cd aegis-os
cargo install --path crates/aos-cli --force
```

**Ubuntu 24.04+ 前置配置（启用 `bwrap` 非特权命名空间）| Ubuntu 24.04+ AppArmor Setup**:
```bash
sudo apt-get update && sudo apt-get install -y bubblewrap
printf 'abi <abi/4.0>,\ninclude <tunables/global>\nprofile bwrap /usr/bin/bwrap flags=(unconfined) {\n  userns,\n}\n' | sudo tee /etc/apparmor.d/bwrap >/dev/null
sudo apparmor_parser -r /etc/apparmor.d/bwrap
```

#### 2) 集成安装与体检 | Client Integration, Doctor & Security Audit
```bash
# 模式 A：全局 Enforced PATH Shim（推荐，claude/opencode/agy/hermes/codex 自动经过 aegis-os run）
aegis-os install --enforce

# 模式 B：仅安装 Advisory Hooks/MCP 集成（降低弹窗疲劳，不提供内核隔离）
aegis-os install

# 5 秒本地暴露扫描与强制级别检查
aegis-os doctor
aegis-os audit-me              # 加 --share 可生成 Markdown 风险徽章卡片
```

#### 3) 升级与精准卸载 | Upgrade & Uninstall
```bash
aegis-os upgrade --check       # 检查新版本（OpenSSH 签名校验）与客户端配置漂移
aegis-os upgrade               # 原地升级二进制并刷新 Hook/MCP/Shim（--refresh-only 仅刷新配置）

aegis-os uninstall             # 卸载 PATH Shim 与客户端集成（保留 ~/.aegis 加密卷）
aegis-os uninstall --workspace-clean --purge --yes   # 同时清理工作区配置并销毁加密 OrgVault 与本地主 KEK
```

---

### 4.2 单 Agent 受控开发与本地硬件虚拟化 MicroVM (`Enforced` & `Isolated Mode`) | Single-Agent Enforced & Isolated MicroVM Workflow

#### 配置模型 API 边界秘密（可选，推荐）| Configuring Boundary Secrets
在宿主机环境变量设置对应提供商真实密钥时，Enforced 沙箱内部可不暴露原始永久 Key，而是经过 L7 本地反向代理在边界替换注入：
```bash
export AOS_SECRET_ANTHROPIC="sk-ant-..."
export AOS_SECRET_OPENAI="sk-..."
export AOS_SECRET_GEMINI="AIza..."
```

#### 启动与提交闭环 | Launch, Inspect, Verify & Commit Loop
```bash
# 1. 进入目标项目根目录，使用内核强制沙箱启动任意受支持 Agent（含 agy / claude）
cd /path/to/your-project
aegis-os run -- claude
aegis-os run -- agy
# 指定 Gateway MCP 工具暴露档位（minimal=10 / collab=27 / standard=50）：
aegis-os run --tool-profile minimal -- claude
# 启用 Stage 1 智能 DLP 假名化与预算 / 死循环熔断保护（默认 dlp-mode=block）：
aegis-os run --dlp-mode pseudonymize --budget-usd 5.0 --max-tokens 2000000 --max-loop-streak 4 -- claude
# 或通过项目级 .aegis/dlp.json 自定义脱敏规则与费率覆盖：
aegis-os run --dlp-config .aegis/dlp.json -- opencode
# 或指定领域 profile / 只读观察模式：
aegis-os run --profile docs -- opencode --model ...
aegis-os run --read-only -- claude

# 2. 查看当前会话状态与沙箱位置
aegis-os status --json
aegis-os last

# 3. 审阅沙箱相对宿主机的完整差异与密码学哈希 evidence_hash
aegis-os diff --render
aegis-os diff --json

# 4. 在沙箱内运行领域验证门（可配置项目根目录 .aegis/verify.json 或 AOS_VERIFY_CMD）
aegis-os verify
aegis-os verify --cmd "cargo test --workspace"

# 5. 使用 SHA-256 防 TOCTOU 锚定提交已审变更回宿主机（涉及构建/CI/Hook 文件需加 --allow-sensitive）
aegis-os commit --expected-diff-hash <sha256>
# 或放弃本次影子修改 / 事后追溯完整审计轨迹
aegis-os discard
aegis-os why
```

- **智能 DLP 与预算策略配置 (`.aegis/dlp.json`)**：可在项目根目录配置 `pseudonym_mode`（`block` / `pseudonymize` / `off`）、`budget_usd`、`max_tokens`、`max_identical_loop_streak`、`custom_literals`（自定义敏字字面量脱敏）与 `pricing`（模型费率覆盖）。会话 Token/USD/假名化统计与熔断记录持久化于 `~/.aegis/sessions/<sid>/egress_usage.json` 与 `effects.jsonl`，运行中可通过携带 `human.token` 访问 `SessionBroker` 的 `GET /v1/egress/usage` 与 `POST /v1/egress/extend-budget` 实时查看或扩容预算。
- **受限 `agy` / `claude` 沙箱 MCP 自动桥接**：`aegis-os run` 会清理并保护 `agent_home` 中的各客户端 MCP 配置（`Enforced` 模式写入 `/run/aegis/bin/aegis-os` 或 macOS Seatbelt 可执行 `aegis-os` `mcp-stdio` + `mcp proxy` 条目，并生成 `0o600` `$HOME/.run/aegis-broker.json` 兜底凭据防子进程清空环境变量；`--isolated` MicroVM 模式自动配置 `http://<proxy>/__aegis/mcp/{_kernel,<server_id>}` 经 `AF_VSOCK` 与 `AegisEgressGateway` 无缝桥接至宿主机 `SessionBroker`）。若云端 MCP Auth Realm 尚未登录或令牌过期，在宿主机另开终端执行 `aegis-os mcp login <realm>` 即可热加载生效，**无需重启受限的 `agy`/`claude` 会话**。

#### 本地硬件虚拟化 Zero-NIC MicroVM (`--isolated`) | Local Hardware-Isolated MicroVM
```bash
# 1. 检查宿主机 Hypervisor (Apple Hypervisor / Linux KVM)、VMM (vfkit/krunkit 或 cloud-hypervisor+virtiofsd) 与镜像状态
aegis-os doctor
aegis-os vm status
aegis-os vm status --json

# 2. 从 Release 下载或从本地构建包导入 SHA-256 / OpenSSH 签名的 Guest Linux 内核与 initramfs
aegis-os vm pull
./scripts/build_vm_images.sh --out ./target/vm-bundle   # 如需离线自建静态 musl initramfs + 内核镜像
aegis-os vm pull --from-dir ./target/vm-bundle
aegis-os vm verify

# 3. 以独立 Zero-NIC MicroVM 启动（支持 TTY 交互式 PTY / SIGWINCH；缺少前置条件或镜像时严格 Fail-Closed）
aegis-os run --isolated --vcpus 2 --mem-mb 2048 -- claude
```

---

### 4.3 审批控制、自定义 Cedar 策略与受控越界能力 | Approvals, Cedar Policy & Brokered Capabilities

#### 1) CLI 与浏览器控制台审批 | CLI & Web Console Approvals
```bash
# 本地独立 Terminal 持续监听并交互审批，或单次批准（默认带 TTL 租约 / 支持浏览器 /approve）
aegis-os policy watch
aegis-os policy diff
aegis-os approve               # 自动探测 Local vs. Cloud；加 --web 打开 Web 控制台，--deny 拒绝
aegis-os policy lease --action-pattern workspace_commit --ttl 1800
```
- Web 控制台启动命令：`aegis-os daemon --listen 127.0.0.1:7080 --egress-listen 127.0.0.1:18080`（默认强制鉴权，使用 `#key=` 管理员密码或单笔作用域 `ast_*` 票据访问 `/approve` 与 `/dashboard`；`--insecure-no-auth` **仅限本地调试**，生产严禁使用）。

#### 2) 自定义 Cedar 策略 (`AOS_CEDAR_POLICY_FILE`) | Custom Cedar Policies
`aos-policy` 在启动时读取环境变量 `AOS_CEDAR_POLICY_FILE` 指定的 Cedar 文件（语法无效直接 Fail-Closed 拦截全部绿区放行）：
```cedar
// 例 1：允许特定 Agent 上传工作区子目录制品，排除特定 URL 与临时后缀
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

// 例 2：硬禁止删除生产迁移或私钥文件（支持任意位置通配符）
forbid (
    principal is Agent,
    action in [Action::"fs_delete"],
    resource like "/workspace/migrations/*"
);
forbid (
    principal is Agent,
    action,
    resource like "*.pem"
);
```

#### 3) 依赖安装、Loopback 预览与宿主文件桥 | `pkg_install`, Loopback & Host Bridge
- **`pkg_install`**：支持 `npm`/`pnpm`/`yarn`/`bun`/`pip`/`uv`/`cargo`/`go`；仅开放生态白名单域名，自动隔离宿主机 `node_modules`/`.venv`；若 `allow_scripts: true` 将强制升级 `pkg_install_scripts` 审批。
- **Loopback 开发预览 (`$AOS_DEV_PORT`)**：Linux `--unshare-net` 环境下通过 `egress-shim --preview` 授权令牌安全映射回宿主机浏览器预览；macOS 下通过 Seatbelt 单端口 `localhost:<port>` 出站规则严格隔离其他本机端口。
- **`fs_import_file` / `fs_export_file` / `host_exec`**：通过 SHA-256 锚定与防符号链接校验在外部文件与影子间安全传输；不可嵌套沙箱的任务（如 Simulator）由人类经 `/approve` 放行 `host_exec` 冻结只读包在隔离进程组中运行。

---

### 4.4 多 Agent 协同与多路径并行探索 (`A2A` / `IPC` / `CAS` / `Explore`) | Multi-Agent Collaboration & Parallel Path Explorer

```bash
# 查看实时协作面板（Agent、任务状态、文件认领、租约）
aegis-os top

# 查看组织 A2A 任务板与单个任务含审计验证报告的详情
aegis-os a2a board
aegis-os a2a show <task_id> --json

# 节点发现、收件箱、P2P 消息与 A2A 任务委派
aegis-os ipc peers
aegis-os ipc inbox
aegis-os ipc send --to reviewer --subject "Check PR" --message "Please inspect auth module"
aegis-os ipc request --to researcher --subject "Audit" --message "Inspect deps"

# 内容寻址 SHA-256 Artifact 发布与拉取（消除下游读到半写入文件）
aegis-os publish
aegis-os artifacts list
aegis-os artifacts fetch <artifact_uri> --out ./verified.bin

# Stage 2：多路径并行探索（基于冻结 CoW 基线 + SharedBudgetPool + Clean-Room VerifyGate + TradeoffBrief）
aegis-os explore run --prompt "修复会话缓存竞争问题" --path "minimal=最小改动加锁" --path "refactor=改用事件队列重构" --verify-cmd "cargo test -p aos-memory-store" --budget-usd 5.0
aegis-os explore run --prompt "排查间歇性测试超时" --diverge 3 --confirm-plan --verify-cmd "cargo test"
# Stage 3：使用硬件虚拟化 Zero-NIC MicroVM 运行每条探索路径及 Clean-Room VerifyGate
aegis-os explore run --isolated --vcpus 2 --mem-mb 2048 --prompt "隔离运行不可信构建脚本" --path "fix=修复构建" --verify-cmd "cargo test"
aegis-os explore status
aegis-os explore diff --path minimal
aegis-os explore apply --path minimal                                  # 整路径防 TOCTOU 提交回宿主机
aegis-os explore apply --pick minimal:src/** --pick refactor:tests/**  # 跨路径筛选（含 3-Way 行级合并与重跑 VerifyGate）
aegis-os explore resume --path minimal -- claude                       # 零拷贝克隆并进入交互式 run 会话微调
aegis-os explore discard --yes
```
在 MCP 侧，协作 Agent 通过 `coord_claim` / `coord_release` 申请路径锁、`org_artifact_publish` / `org_artifact_fetch` 移交大产物，并通过 `ipc_request` / `ipc_reply` 自动流转任务状态与挂载任务绑定租约。`aegis-os explore`（别名 `paths`）为每条路径创建独立 `__explore_*` 隔离组织空间与 CoW 影子副本，防止同组 `pub` 串读，并在合入前于 Clean-Room 离线沙箱验证代码与测试。

---

### 4.5 `OrgVault` 加密卷、`UOMP` 记忆网关、`aegis-os mcp` 与 `Aegis Cloud` / 发布运维 | Vault, Memory, MCP, Cloud & Release Ops

#### 1) `OrgVault` 加密卷管理 | Encrypted Vault Operations
```bash
aegis-os vault status                    # 检查加密后端 (APFS SparseBundle / LUKS / gocryptfs / Plain0700) 与孤儿影子
aegis-os vault unlock                    # 解锁并挂载组织加密卷至 ~/.aegis/orgs/<org>
aegis-os vault lock                      # 卸载并将空壳收紧为 0o500
aegis-os vault recover --from-agent <id> # 接管异常退出残余的隔离影子修改
```

#### 2) `UOMP` 本地记忆服务端与远程 TLS 1.3 / mTLS 网关 | UOMP Memory Guard & Gateway
```bash
# 导入目录并在本地启动 UOMP Memory Guard（默认监听 127.0.0.1:9374）
aegis-os memory import ~/notes --tag notes
aegis-os memory serve --listen 127.0.0.1:9374

# 为远程 Agent（如 Aegis Cloud）启动强校验 audience 与 mTLS 的独立网关（切勿明文暴露）
aegis-os memory-gateway \
  --listen 127.0.0.1:9443 \
  --guard-url http://127.0.0.1:9374 \
  --public-key ~/.uomp/.secrets/ed25519-public.jwk \
  --audience https://memory.example.com \
  --allowed-endpoint /v1/memory \
  --allowed-endpoint /v1/payload \
  --tls-cert /etc/aegis-memory/server.pem \
  --tls-key /etc/aegis-memory/server-key.pem \
  --client-ca /etc/aegis-memory/client-ca.pem \
  --audit-log ~/.aegis-os/memory-gateway-audit.jsonl

# 审批待落盘写入 & 吊销会话 / 审计查询
aegis-os memory staged list --status pending
aegis-os memory staged approve <id>
aegis-os memory revoke <session-id>
```

#### 3) 通用零信任 MCP 防火墙、云端 Streamable HTTP/OAuth 2.1 Auth Realms 与声明式 MCP Bundles (`aegis-os mcp`) | Zero-Trust MCP Firewall, Cloud MCP Auth Realms, Bundles & Aegis Cloud PaaS

> **受限客户端协同机制与 `v0.10.0` 方案 B 设计 | Confined Client Topology & Option B Design**：
> 启动 `aegis-os run` 时，`stage_confined_mcp_configs()` 会自动清洗 `$AGENT_HOME` 中的明文凭据并按原生格式（`.claude.json`、`mcp_config.json`、`opencode.json`、`config.toml` 等）下发无凭证 1:1 转发桩（`aegis-os mcp proxy <id>` 或 MicroVM `/__aegis/mcp/<id>`）；所有防火墙裁决、DLP 假名化、会话污点、Outbox 审批与 Vault 令牌注入均在宿主机 `SessionBroker` 执行，且宿主端登录后正在运行的会话自动热加载凭据。面向 `v0.10.0` 的开放 Registry 发现、审批页内联 OAuth/Vault 录入及 **方案 B（会话内临时热桥接 + 下次启动自动扶正）** 完整规范详见 [docs/EXTERNAL_MCP_DESIGN.md](EXTERNAL_MCP_DESIGN.md)。

```bash
# 0. 开放/企业 MCP Registry 发现、场景推荐、统一安装与全生命周期运维
aegis-os mcp status                                    # 统一清单、Auth 到期、Outbox、污点与未收编配置漂移告警
aegis-os mcp doctor --probe                            # 过期凭据、明文暴露、stdio 沙箱就绪度与实机连通探测
aegis-os mcp search linear                             # 按 Trust Tier 1->2->3 检索 Registry（含游标翻页 / ETag 缓存）
aegis-os mcp recommend                                 # 基于 .aegis/mcp.json / .mcp.json 与项目上下文推荐
aegis-os mcp install app.linear/mcp --scope workspace  # 统一安装（Registry/Bundle/HTTPS/.mcpb/oci/npm/pypi）与鉴权瀑布流
aegis-os mcp sync --clients                            # 从无密钥 .aegis/mcp.json 同步 Vault 与客户端代理配置
aegis-os mcp upgrade --all                             # 保密升级：同步上游新版本并完整保留 Vault 密文与策略覆盖
aegis-os mcp remove <server_id> --purge-auth           # 移除纳管服务、清理客户端配置并按需清除孤立凭据
aegis-os mcp registry add https://mcp.internal.corp/v0 && aegis-os mcp registry airgapped true # 企业私有镜像与气隙模式

# 1. 一键安装声明式开放 MCP Bundle (`aegis-mcp-bundle/v1`)：同步 Auth Realm、多云端服务、SKILL.md 与本地客户端配置
aegis-os mcp bundle install heurion                     # 等价于 https://heurion.org/.well-known/mcp-bundle.json
aegis-os mcp bundle install heurion --profile trading   # 按 profile 过滤子集服务；加 --no-client-sync 可跳过修改本地客户端
aegis-os mcp bundle list && aegis-os mcp bundle show heurion-suite
aegis-os mcp bundle remove heurion-suite --purge-auth

# 2. 标准 OAuth 2.1 Auth Realms 登录/刷新/状态（PKCE 浏览器 / RFC 8628 Device Code / Bearer Fallback；支持运行中会话热生效）
aegis-os mcp login heurion                              # 浏览器 OAuth 2.1 PKCE + RFC 9728/8414 自动发现 + RFC 7591 动态注册
aegis-os mcp login heurion --device-code                # 无头终端 / SSH Device Code 登录
aegis-os mcp login heurion --token <TOKEN> --allow-host heurion.org --allow-host '*.heurion.org' # 静态 Bearer/API Key 登录（或用 --token-stdin，加密封入 mcp_auth_realms.json）
aegis-os mcp auth-status && aegis-os mcp logout heurion

# 3. 扫描并Zero-Trust收编本地各客户端 (.claude.json/.mcp.json/agy/agy-cli/cursor/opencode/codex)
aegis-os mcp scan
aegis-os mcp adopt --all                      # 收编并将明文凭据 AES-256-GCM 密封入 Vault，重写为 mcp proxy
aegis-os mcp unadopt --all                    # 从加密备份无损还原客户端原始 MCP 配置

# 4. 手动纳管 stdio（支持网络白名单隔离）或 Streamable HTTP/SSE MCP 服务，及调优信任/DLP/主动请求策略
aegis-os mcp add github --command npx --arg -y --arg @modelcontextprotocol/server-github@0.6.2 --isolate-network --allow-host api.github.com --env GITHUB_PERSONAL_ACCESS_TOKEN=ghp_...
aegis-os mcp add heurion-macro --url https://heurion.org/mcp/macro --auth-realm heurion --timeout-ms 300000
aegis-os mcp list
aegis-os mcp policy heurion-macro --trust untrusted --dlp pseudonymize --allow-elicitation false --auth-realm heurion --stage-tool execute_order

# 5. 事务发件箱 / 会话污点 / 防篡改审计黑匣子
aegis-os mcp outbox list
aegis-os mcp outbox show <ticket_id>          # 展示去假名化预览、SHA-256 承诺与污点溯源警告
aegis-os mcp approve <ticket_id>              # 与顶层 `aegis-os approve <outbox-id>` 打通：宿主机直发投递
aegis-os mcp taint list && aegis-os mcp taint clear
aegis-os mcp audit --server heurion-macro --verify   # 检索并校验 SHA-256 哈希链审计账本完整性

# 6. 云端托管沙箱 (Scale-to-Zero / 仅源码同步 / 云端 TOTP 审批 / PR 导出)
aegis-os cloud login --endpoint https://heurion.org
aegis-os cloud up --agents coder,reviewer
aegis-os cloud push
aegis-os cloud diff --patch
aegis-os cloud approvals
aegis-os cloud approve --web
aegis-os cloud pull
aegis-os cloud down
```

#### 4) 签名发布流程 (Maintainer Release Workflow)
1. 更新 `Cargo.toml` `[workspace.package] version` 并运行 `cargo clippy --workspace --all-targets -- -D warnings && cargo check --workspace --locked` 同步 `Cargo.lock`。
2. 提交版本变更并推送 Git Tag：`git commit -m "chore(release): release vX.Y.Z" && git tag vX.Y.Z && git push origin main && git push origin vX.Y.Z`。
3. `.github/workflows/release.yml` 自动完成 4 目标架构测试/交叉编译，并在 GitHub `release` 审批后使用私钥通过 OpenSSH 命名空间 `aegis-os-release` 对所有产物流（含 `SHA256SUMS`）签名发布、更新 `Formula/aegis-os.rb` PR 与远端节点升级。

---

### 4.6 CLI 命令速查与常见故障排查 | CLI Quick Reference & Troubleshooting

| 问题现象 Symptom | 常见原因与排查方案 Root Cause & Resolution |
|---|---|
| `aegis-os run` 在 Ubuntu 24.04 启动被拒 | 系统限制非特权 `userns`。按 §4.1 创建 `/etc/apparmor.d/bwrap` 并 `apparmor_parser -r` 生效即可。 |
| `cargo` / 编译器未重编已同步文件 | 确认通过 `workspace_sync` / `refresh_from_host` / `workspace_commit` 同步，这些路径会自动更新 `mtime` 通知增量编译器。 |
| `host_exec` 期间提示 `423 Locked` | 设计如此：物理互锁保护宿主机免于并发审批篡改；等待 `host_exec` 执行完毕退出即自动解除并轮换动态密钥。 |
| macOS 出现 Keychain 锁屏/写入拒绝 | Enforced 模式下已禁用弹窗（`exit 44`）；如需云/主机 Keychain KEK，请使用环境变量 `AOS_VAULT_MASTER_KEY` 或先在非沙箱环境解锁登录钥匙串。 |
| `verify_chain` 报告审计链未通过 | 检查 `~/.aegis/audit.jsonl` 是否存在截断首行、非 UTF-8 字符或损坏 JSON；严禁手工编辑账本。 |
| `run --isolated` 或 `vm status` 显示 `NOT READY` | `--isolated` 严格 Fail-Closed：macOS 需安装 `vfkit`/`krunkit` 并启用 Apple Hypervisor；Linux 需开启 `/dev/kvm` 读写权限并安装 `cloud-hypervisor` 与 `virtiofsd`；随后执行 `aegis-os vm pull`（或 `--from-dir`）完成镜像校验。 |
| 受限会话内云端 MCP 提示 `mcp login` | 受限沙箱内的 `agy`/`claude` 不直接触发宿主浏览器 OAuth；请在宿主机终端执行 `aegis-os mcp login <realm>`（或 `--device-code`），运行中的会话会自动热加载新凭据并继续调用，无需重启沙箱。 |
