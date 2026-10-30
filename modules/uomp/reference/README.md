# UOMP Reference Implementation

> **Migration notice (2026-10):** UOMP is becoming the native memory module of [Aegis OS](https://github.com/heurion-org/aegis-os). The product entry point is `aegis-os memory ...`; this vendored directory remains the reference/legacy implementation during the native cutover. Native code lives in `crates/aos-memory`, `crates/aos-memory-store`, and `crates/aos-memory-gateway`.
>
> **迁移说明（2026-10）：** UOMP 正在成为 [Aegis OS](https://github.com/heurion-org/aegis-os) 的原生 memory module。产品入口是 `aegis-os memory ...`；这个 vendored 目录在原生迁移完成前保留为参考/兼容实现。原生代码位于 `crates/aos-memory`、`crates/aos-memory-store` 和 `crates/aos-memory-gateway`。


**The open memory consent protocol for AI agents.**

UOMP defines how agents ask for personal memory — scope, duration, revocation, and audit. This repository is the reference CLI and local implementation; [Aegis OS](https://github.com/heurion-org/aegis-os) is the reference runtime that enforces the protocol with sandboxing, policy, leases, and trusted approval.

Your memory stays where it is. Agents get temporary, scoped, revocable access — and you can see exactly what they read.

<p align="center">
  <a href="https://www.uomp.org">Website</a> •
  <a href="https://www.uomp.org/spec/">Protocol Spec</a> •
  <a href="https://github.com/heurion-org/aegis-os/issues">Issues</a>
</p>

<p align="center">
  <a href="https://www.uomp.org"><img src="https://img.shields.io/badge/website-uomp.org-0A0A0A?logo=google-chrome&logoColor=white" alt="Website" /></a>
  <a href="https://www.uomp.org/spec/"><img src="https://img.shields.io/badge/spec-Draft--00-6B7280" alt="Spec" /></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License" /></a>
</p>

<p align="center">
  <a href="#english">English</a> | <a href="#中文">中文</a>
</p>

> **Status: early reference implementation, agent-first.** Set up an MCP client once with `uomp setup`; when the agent first asks for notes, UOMP opens a local approval page, and the agent continues after you approve. The local loop covers import, scoped consent, background server, audit, and revoke. Claude Desktop/Cursor validation and a packaged CLI are next. This is not production-ready yet.

---

<h2 id="english">English</h2>

### What UOMP is

UOMP is the missing layer between a user's personal context and the agents that want to use it.

Today, an agent that needs your notes, preferences, portfolio, or calendar has two bad options:

1. Ask you to upload everything to its vendor's cloud.
2. Ask for a long-lived, over-scoped API key.

Both are all-or-nothing. There is no standard way to say:

> "Read these notes for 30 minutes. Not those. Show me what you read. Stop now."

UOMP makes that sentence executable.

### Why now

- **MCP is standardizing how agents connect to tools and data** — but it does not define who is allowed to read what, for how long, or how to revoke it.
- **Personal context is fragmenting** across ChatGPT, Claude, Cursor, and vertical agents. Every app wants its own memory.
- **Memory vendors optimize recall.** Very few optimize user consent, least privilege, and audit across agents.

The opportunity is not another memory store. It is the control plane for memory access.

### What UOMP is — and what it isn't

| UOMP is | UOMP is not |
|---|---|
| An open protocol for agent memory consent | A new memory database or vector store |
| A way to govern access to memory you already have | A replacement for Mem0, Letta, Obsidian, or Notion |
| Aegis OS is the reference runtime | A model, agent framework, or cloud |
| Session-based, revocable, and auditable | A blockchain or FHE product today |
| Complementary to MCP | A marketplace or agent registry |

The core idea: **don't move the data; govern access to it.**

The name "User-Owned Memory Protocol" is historical. The value is the control plane, not a new storage format.

### Product thesis

1. Users will adopt a consent layer only if it gives them something useful immediately — not because it is a protocol.
2. The first useful thing is: **connect the memory you already have to the agents you already use, with control.**
3. Start with one user, one source, and one agent. Expand only after retention.

North star:

> Make it normal for a user to say: "This agent can read this part of my memory, for this task, for 30 minutes — and I can see and revoke it."

### The first real use case

**Give Claude Desktop or Cursor temporary access to your Obsidian vault.**

1. Set up: `uomp setup claude --vault ~/Obsidian/MyVault`. UOMP imports the vault, starts the local server in the background, and writes the Claude Desktop MCP entry. No access is granted yet.
2. Restart Claude Desktop, then ask it to read the project notes.
3. Claude requests `notes/projects`; UOMP opens the local approval page. Approve for 30 minutes.
4. Claude reads through Memory Guard. Every access is logged. Revoke and the next request fails with `403`.

The Markdown/Obsidian import and agent-initiated consent loop now work end-to-end. Validating the MCP bridge with Claude Desktop and Cursor, and packaging the CLI, are next.

### How it works

```
Agent (MCP client or SDK)
   │  uom.json: declares the scopes it wants
   ▼
Auth Service ── issues a short-lived capability token
   │
   ▼
Memory Guard ── checks session status, scope, expiry, and revocation
   │
   ├── existing memory source (SQLite, files, Obsidian, vector DB adapter)
   └── audit log
```

Design principles:

- **Local-first by default.** Guard listens on `127.0.0.1`; data does not leave the machine unless remote access is explicitly enabled.
- **Least privilege.** Scopes are expressed as tags, keys, and fields — not "all memory."
- **Session-bound.** Tokens expire; `revoke` and `close` take effect on the next request.
- **Auditable.** Every access decision is logged.
- **Interoperable.** UOMP is a layer over existing memory sources, not a new silo.

### Aegis OS integration (optional)

UOMP can delegate memory policy evaluation to Aegis OS. When configured, the Auth Service calls Aegis `memory_policy_evaluate`; an `ask` becomes a UOMP consent request. Approval and denial go through Aegis's trusted `/v1/approvals/decide` endpoint before the UOMP token is issued or the session is closed.

```bash
export UOMP_AEGIS_MCP_URL=http://127.0.0.1:7080/mcp
export UOMP_AEGIS_TOKEN=...   # trusted operator token; never put this in an Agent env
export UOMP_AEGIS_ORG=local
export UOMP_AEGIS_AGENT=uomp
```

Without these variables, UOMP runs standalone with its local Auth + Guard. The adapter is in [`packages/aegis-adapter`](./packages/aegis-adapter) and the runtime mapping is in [`aegis-os/crates/aos-memory`](https://github.com/heurion-org/aegis-os/tree/main/crates/aos-memory).

For remote Agents, run `aegis-os memory-gateway --public-key <jwk> --audience <url> --guard-url http://127.0.0.1:9374` behind a TLS 1.3 / mTLS terminator. It verifies the UOMP JWT and forwards scoped `/v1/memory` requests to the local Guard.

The product entry point is `aegis-os memory ...`, which delegates to this reference CLI (`uomp`) during the migration. `uomp` remains the protocol reference/debug CLI.

The remote path has an end-to-end test: `pnpm test:e2e` starts UOMP, mints a remote token, starts the Aegis gateway with mTLS, reads through it, and verifies scope denial and revocation. It requires `cargo build -p aos-cli` and `openssl`.

### What works today

| Capability | Status |
|---|---|
| Local memory store | SQLite; CSV/JSON and Obsidian/Markdown import |
| Local knowledge import | Markdown folders; frontmatter tags; path-derived scopes; `--dry-run` |
| Setup + import | `uomp setup --vault <path>` imports Markdown and writes the client config; no access is granted |
| One-command install | `install.sh` source build (Node 22 + git, macOS/Linux) |
| Demo & diagnostics | `uomp demo` (isolated) and `uomp doctor` |
| Agent manifest | `uom.json` with requested scopes |
| Authorization | Agent-requested, user-approved in the local consent page; pre-authorize with `uomp connect` for scripts |
| MCP client setup | `uomp setup claude\|cursor\|opencode` writes the client config and starts the local server |
| Server lifecycle | Background server from `setup`/`connect` or `uomp start`; `uomp status`, `uomp stop` |
| Disconnect | `uomp disconnect claude\|cursor\|opencode` removes the client entry and revokes its session |
| Agent-initiated consent | First tool call requests a tag/key; approval page + desktop notification; `pending` / `approve` / `deny` fallback |
| MCP runtime | stdio server with `list_memory`, `search_memory`, and `read_memory` (experimental) |
| Capability tokens | EdDSA-signed JWT, 30-minute default |
| Enforcement | Memory Guard: scope filtering, aggregation, audit log |
| Revocation | `revoke` / `close` invalidate the next request |
| Remote access | Aegis Cloud remote Agent + Aegis Memory Gateway (optional; standalone gateway/relay retired) |
| SDK | TypeScript (`@uomp/sdk`) |
| Examples | Calendar agent and stock analyst |
| Writes | Staged in SQLite; `uomp staged list/approve/deny`; high-sensitivity writes rejected |
| Payloads | Encrypted envelope upload/list/get/delete; `uomp payload list/get/delete` |
| Remote onboarding | Agent posts `/v1/remote/requests`; user approves locally; agent polls a one-time remote token |
| Unified approvals | `uomp approvals` shows pending UOMP requests and Aegis escalations; Aegis approve/deny via the same command |
| Admin operations | Session create/grant/revoke require a local admin token |

### What we are building next

1. **MCP hardening** — validate with Claude Desktop/Cursor, then add resources, prompts, and more client config presets.
2. **Packaged CLI release** — npm or a standalone binary, so users do not need a local build.
3. **More local connectors** — beyond Obsidian/Markdown.
4. **Python SDK** — meet agent developers where most agents are built.
5. **Design partner program** — 10 users with a real weekly workflow.

### How we will measure the first milestone

- 10 design partners using UOMP with their own data.
- 3+ agents connected per user.
- 3+ uses per week for 4 consecutive weeks.
- Time to first authorized read under 5 minutes.
- At least 50% of users revoke a session — control must be felt, not just claimed.

If these numbers do not hold, we change the workflow, not add features.

### Not on the critical path

These are experiments or research directions, not the current product roadmap:

- FHE (homomorphic encryption)
- On-chain audit
- New storage backends (S3/IPFS)
- Agent registry/marketplace
- Agent write workflows

They remain in the repository and design docs, but we will not let them delay the first retained-user workflow. See [`docs/on-chain-audit-design.md`](docs/on-chain-audit-design.md) and [`docs/store-abstraction-design.md`](docs/store-abstraction-design.md) for the research context.

### Quick start

Requirements: Node.js >= 22, git, and macOS or Linux. **Windows is not supported.**

**Install**

```bash
curl -fsSL https://www.uomp.org/install.sh | bash
```

The installer clones UOMP into `~/.uomp/cli`, builds the CLI, and links `uomp` into `~/.local/bin`. If that directory is not on your `PATH`, the script prints the line to add. The data directory is created on first `setup`/`connect`; `uomp init` is only needed if you want to prepare it separately.

From a source checkout, run `pnpm install && pnpm build`, then use `pnpm cli ...` instead of `uomp ...`.

**See the loop first**

```bash
uomp demo
```

This runs import → authorize → allowed read → denied read → audit → revoke against a temporary data directory. It does not touch your real `~/.uomp`.

If something is not working, run:

```bash
uomp doctor
```

It checks Node, git, data-directory permissions, keys, databases, session env files, and the local server port.

**Set up a client once**

```bash
uomp setup claude --vault ~/Obsidian/MyVault
```

This imports the Markdown vault, starts the local Auth + Guard server in the background, and writes the Claude Desktop MCP entry. It does **not** grant any access yet. Restart Claude Desktop.

Open Claude and ask it to read your project notes. The first tool call requests `notes/projects`; UOMP opens a local approval page (Linux/macOS also send a desktop notification). Approve for 30 minutes and the same tool call continues. Use `uomp pending` / `uomp approve <request-id>` if the page does not open.

Use `--vault-tag <tag>` to change the base tag (default `notes`). `uomp setup cursor` / `uomp setup opencode` handle the other clients.

No terminal needs to stay open. `uomp status` shows the background server and active sessions; `uomp stop` stops the server (it does not revoke sessions); `uomp disconnect claude` removes the client entry and revokes its session. If you used `--config`, pass the same path to `disconnect`.

**Or import separately**

```bash
uomp import ~/Obsidian/MyVault
uomp import ~/Obsidian/MyVault --dry-run
```

Directory paths become scopes: `projects/uomp/plan.md` is tagged `notes`, `notes/projects`, and `notes/projects/uomp`. Frontmatter `tags`, `title`, and `sensitivity` are preserved.

**Advanced: pre-authorize / scripts**

`uomp connect` skips the first-use approval page and creates a session immediately:

```bash
uomp connect claude --vault ~/Obsidian/MyVault --scope notes/projects
```

Use this for scripts/CI or when you explicitly want to choose scopes before the agent runs. High-sensitivity tags (for example `portfolio:holdings`) are never selected by default; in an interactive run without `--scope` you choose keys individually. For scripts, use `--allow-key <key...>` (preferred) or `--allow-high <tag...>` (explicit bulk override).

`--foreground` keeps the server in this terminal; `--print-config` prints the JSON without writing it; `--skip-config` grants only.

**Authorize an agent package**

```bash
uomp connect ./examples/calendar-agent --scope preference
```

This starts the local Auth + Guard server in the background, creates a 30-minute session, and writes the token to `~/.uomp/sessions/<sessionId>.env` with mode `0600`. It prints the exact `source` command and the revoke command. The full token is not printed by default. `uomp authorize` remains available as the lower-level/script entry point.

**Run the agent in a second terminal**

```bash
source ~/.uomp/sessions/<sessionId>.env
node ./examples/calendar-agent/index.js
```

The server stays in the background. `uomp status` shows it and the active sessions; `uomp stop` stops it. Add `--foreground` if you want the server logs in this terminal. Use `uomp sessions` to see active sessions and `uomp revoke <sessionId>` to invalidate one immediately. `uomp audit` shows every allow/deny decision; filter with `--since 24h`, `--result deny`, or `--key <key>`. Both commands support `--json` for scripts.

If you prefer to run the server separately:

```bash
# Terminal 1
uomp serve
# or run it in the background: uomp start

# Terminal 2
uomp connect claude --scope notes/projects --no-server

# Agent packages:
uomp connect ./examples/calendar-agent --scope preference --no-server
source ~/.uomp/sessions/<sessionId>.env
node ./examples/calendar-agent/index.js
```

**Sensitive-data demo: stock analyst**

```bash
uomp import ./examples/stock-analyst/sample-risk.json --replace
uomp import ./examples/stock-analyst/sample-holdings.csv \
  --tag portfolio:holdings --sensitivity high --replace

uomp connect ./examples/stock-analyst \
  --scope portfolio:holdings profile:risk \
  --allow-high portfolio:holdings

# In a second terminal, source the env file printed above, then run:
source ~/.uomp/sessions/<sessionId>.env
node ./examples/stock-analyst/index.js
```

`portfolio:holdings` is high-sensitivity. `--allow-high` is an explicit bulk override for this demo. For per-key control, use `--allow-key <key...>` or run `uomp connect` without `--scope` and select keys interactively.

**Developer shortcut**

```bash
uomp agent run ./examples/calendar-agent
```

> Admin operations (`createSession`, `grant`, `revoke`) require the local admin token stored at `~/.uomp/.secrets/admin-token`. The Node SDK only reads `UOMP_ADMIN_TOKEN` when the base URL is loopback.

### Manual MCP setup (unsupported clients)

`uomp connect` handles Claude Desktop, Cursor, and OpenCode. For other stdio clients, or if you want to edit the config yourself, use the manual two-step flow:

```bash
# Terminal 1
uomp serve

# Terminal 2
uomp import ~/Obsidian/MyVault
uomp authorize --scope notes/projects --output ~/.uomp/mcp-client.env --no-server
uomp mcp --session ~/.uomp/mcp-client.env --print-config
```

Paste the JSON into the client's `mcpServers` entry. The entry points at the session env file, not the token itself, so the client config contains no secret. The MCP server re-reads the env file before every tool call; re-run `authorize` to the same `--output` path to renew without restarting the client. A custom `--output` file is not removed by `uomp revoke`.

The stdio MCP server provides `list_memory`, `search_memory`, and `read_memory`. `list_memory` and `search_memory` return keys and metadata only; `read_memory` returns content. Every call still goes through Memory Guard scope, expiry, revocation, and audit. Validated with the official MCP SDK and OpenCode v2.2.0; Claude Desktop/Cursor validation is still pending.

### Security model

UOMP enforces:

- the token's tag/key/field scope;
- session expiry;
- immediate revocation after `revoke` or `close`;
- an audit record for every request.

UOMP does **not** protect against:

- a malicious process running as the same OS user (it can read `~/.uomp` and the admin token);
- an authorized agent retaining plaintext it received;
- a compromised user machine;
- a malicious agent that ignores the scopes it was granted.

This is why the project does not claim "trustless." The goal is **informed consent, least privilege, revocation, and audit** — not a guarantee that an authorized agent forgets what it saw.

### Project structure

```
packages/
  core/       shared types and constants
  store/      memory store and adapter interfaces
  token/      capability token issuance and verification
  auth/       session and admin authorization
  guard/      scope enforcement and audit
  sdk/        TypeScript client
  cli/        `uomp` command-line tool
apps/
  server/     combined Auth + Guard service
  gateway/    historical remote gateway (deprecated)
  relay/      historical cloud relay (deprecated)
examples/
  calendar-agent/
  stock-analyst/
  mcp-client/
specs/
  draft-00.md
```

### Get involved

We are looking for **10 design partners** who:

- use at least two AI agents regularly;
- keep personal or project knowledge in local files, Obsidian, or a similar tool;
- are willing to try a weekly workflow and give direct feedback.

Open an issue or read the protocol draft:

- [Issues](https://github.com/heurion-org/aegis-os/issues)
- [Protocol draft](https://www.uomp.org/spec/)

### License

Apache 2.0. See [`LICENSE`](LICENSE).

---

<h2 id="中文">中文</h2>

### UOMP 是什么

**UOMP 是 Agent 记忆同意的开放协议。**

UOMP 定义 Agent 如何请求个人记忆——范围、时效、撤销与审计。这个仓库是协议的参考 CLI 和本地实现；[Aegis OS](https://github.com/heurion-org/aegis-os) 是执行协议的参考运行时，提供沙箱、策略、租约与可信审批。

你的记忆留在原来的地方。Agent 只获得临时、限定范围、可撤销的访问权限，并且你能看到它到底读了什么。

今天，一个需要你的笔记、偏好、持仓或日历的 Agent，通常只有两个选择：

1. 让你把所有数据上传到它的云端；
2. 向你要一个长期、过宽的 API key。

两者都是“全有或全无”。用户没有一个标准方式表达：

> “这 30 分钟可以读这些笔记，不能读那些；告诉我你读了什么；现在停止。”

UOMP 就是让这句话可执行的那一层。

### 为什么是现在

- **MCP 正在标准化 Agent 连接工具和数据的方式**，但它没有定义“谁可以读什么、读多久、如何撤销”。
- **个人上下文正在分裂**：ChatGPT、Claude、Cursor 和垂直 Agent 各存一份记忆。
- **记忆厂商优化的是召回率**，很少有人优化跨 Agent 的用户同意、最小权限和审计。

机会不是再做一个记忆库，而是做记忆访问的控制面。

### UOMP 是什么，不是什么

| UOMP 是 | UOMP 不是 |
|---|---|
| Agent 记忆同意的开放协议 | 新的记忆数据库或向量库 |
| 治理你已有记忆的访问方式 | Mem0、Letta、Obsidian、Notion 的替代品 |
| Aegis OS 是参考运行时 | 模型、Agent 框架或云服务 |
| 基于会话、可撤销、可审计 | 今天的区块链或 FHE 产品 |
| MCP 的补充层 | Agent 市场或 Registry |

核心思想：**不要搬数据，治理对数据的访问。**

“User-Owned Memory Protocol”这个名字是历史产物。真正的价值在控制面，而不是新的存储格式。

### 产品判断

1. 用户只会采用一个授权层，前提是它立刻带来实际价值——而不是因为它是一个协议。
2. 第一个实际价值是：**把你已经有的记忆，接给你已经在用的 Agent，并且保持控制。**
3. 先做一个用户、一个数据源、一个 Agent。留存成立后再扩展。

北极星：

> 让用户习惯说：“这个 Agent 可以为这次任务读这部分记忆，30 分钟，我能看见，也能随时撤销。”

### 第一个真实场景

**让 Claude Desktop 或 Cursor 临时访问你的 Obsidian 笔记库。**

1. 运行 `uomp setup claude --vault ~/Obsidian/MyVault`。UOMP 导入笔记库、在后台启动本地服务，并把 MCP 配置写入 Claude Desktop；此时还没有授权任何范围。
2. 重启 Claude Desktop，让它读取项目笔记。
3. Claude 请求 `notes/projects`；UOMP 打开本地审批页。你批准 30 分钟。
4. Claude 通过 Memory Guard 读取，每次访问都有日志。你撤销后，下一个请求直接 `403`。

Markdown/Obsidian 导入和 Agent 主动申请授权的闭环现在已经跑通。接下来是用 Claude Desktop / Cursor 验证，以及打包 CLI。

### 工作方式

```
Agent（MCP 客户端或 SDK）
   │  uom.json：声明它想要的范围
   ▼
Auth Service ── 签发短期 Capability Token
   │
   ▼
Memory Guard ── 校验会话状态、范围、过期时间、是否已撤销
   │
   ├── 已有的记忆源（SQLite、文件、Obsidian、向量库适配器）
   └── 审计日志
```

设计原则：

- **默认本地优先。** Guard 监听 `127.0.0.1`；除非显式开启远程访问，数据不离开本机。
- **最小权限。** 范围用 tags、keys、fields 表达，而不是“全部记忆”。
- **会话绑定。** Token 会过期；`revoke` / `close` 在下一个请求立即生效。
- **可审计。** 每次访问决策都有日志。
- **可互操作。** UOMP 是已有记忆源之上的一层，不是新的数据孤岛。

### Aegis OS 集成（可选）

UOMP 可以把记忆策略评估委托给 Aegis OS。配置后，Auth Service 会调用 Aegis 的 `memory_policy_evaluate`；返回 `ask` 时创建 UOMP 审批请求。批准和拒绝都通过 Aegis 的可信 `/v1/approvals/decide` 端点完成，再签发 UOMP token 或关闭会话。

```bash
export UOMP_AEGIS_MCP_URL=http://127.0.0.1:7080/mcp
export UOMP_AEGIS_TOKEN=...   # 可信 operator token；不要放进 Agent 环境
export UOMP_AEGIS_ORG=local
export UOMP_AEGIS_AGENT=uomp
```

不设置这些变量时，UOMP 仍按本地 Auth + Guard 独立运行。适配器在 [`packages/aegis-adapter`](./packages/aegis-adapter)，运行时映射在 [`aegis-os/crates/aos-memory`](https://github.com/heurion-org/aegis-os/tree/main/crates/aos-memory)。

远程 Agent 使用 `aegis-os memory-gateway --public-key <jwk> --audience <url> --guard-url http://127.0.0.1:9374`，并在前面加 TLS 1.3 / mTLS 终止器。它会验证 UOMP JWT，并把带范围的 `/v1/memory` 请求转发给本地 Guard。

产品入口是 `aegis-os memory ...`，迁移期委托给这个参考 CLI（`uomp`）。`uomp` 保留为协议参考/调试 CLI。

远程路径有端到端测试：`pnpm test:e2e` 会启动 UOMP、签发 remote token、启动带 mTLS 的 Aegis Gateway、通过它读取，并验证 scope 拒绝和撤销。需要先执行 `cargo build -p aos-cli`，并安装 `openssl`。

### 今天已经可用

| 能力 | 状态 |
|---|---|
| 本地记忆存储 | SQLite，支持 CSV/JSON 和 Obsidian/Markdown 导入 |
| 本地知识导入 | Markdown 目录、frontmatter tags、按路径生成范围、`--dry-run` |
| 设置 + 导入 | `uomp setup --vault <path>` 导入 Markdown 并写客户端配置；不授权任何范围 |
| 一条命令安装 | `install.sh` 源码构建（Node 22 + git，macOS/Linux） |
| Demo 与诊断 | `uomp demo`（隔离数据）和 `uomp doctor` |
| Agent 声明 | `uom.json`，声明请求范围 |
| 授权 | Agent 发起请求，用户在本地审批页批准；脚本可用 `uomp connect` 预授权 |
| MCP 客户端配置 | `uomp setup claude\|cursor\|opencode` 自动写配置并启动本地服务 |
| 服务生命周期 | `setup` / `connect` 或 `uomp start` 后台启动；`uomp status`、`uomp stop` |
| 断开客户端 | `uomp disconnect claude\|cursor\|opencode` 移除客户端条目并撤销会话 |
| Agent 主动申请授权 | 第一次工具调用请求 tag/key；审批页 + 桌面通知；`pending` / `approve` / `deny` 兜底 |
| MCP 运行时 | stdio server，提供 `list_memory`、`search_memory` 和 `read_memory`（实验） |
| Capability Token | EdDSA 签名 JWT，默认 30 分钟 |
| 执行 | Memory Guard：范围过滤、聚合、审计日志 |
| 撤销 | `revoke` / `close` 后下一个请求失效 |
| 远程访问 | Aegis Cloud 远程 Agent + Aegis Memory Gateway（可选；独立 gateway/relay 已退役） |
| SDK | TypeScript（`@uomp/sdk`） |
| 示例 | Calendar Agent、Stock Analyst |
| 写入 | SQLite staging；`uomp staged list/approve/deny`；高敏写入拒绝 |
| Payload | 加密 envelope 上传/列出/读取/删除；`uomp payload list/get/delete` |
| 远程接入 | Agent 调用 `/v1/remote/requests`；用户本地批准；Agent 轮询一次性 remote token |
| 统一审批视图 | `uomp approvals` 同时显示 UOMP 请求和 Aegis escalation；Aegis 审批也走同一命令 |
| 管理员操作 | create/grant/revoke 需要本机管理员令牌 |

### 下一步做什么

1. **MCP 完善**：先用 Claude Desktop / Cursor 验证，再补 resources、prompts 和更多客户端配置预设。
2. **打包发布 CLI**：npm 或独立二进制，用户不需要本地构建。
3. **更多本地连接器**：在 Obsidian/Markdown 之外继续扩展。
4. **Python SDK**：去 Agent 开发者最多的地方。
5. **设计伙伴计划**：10 个有真实每周工作流的用户。

### 第一个里程碑怎么衡量

- 10 个设计伙伴用自己的数据使用 UOMP。
- 每个用户连接 3 个以上 Agent。
- 连续 4 周、每周使用 3 次以上。
- 首次授权到第一次读取的时间小于 5 分钟。
- 至少 50% 的用户使用过撤销——控制权必须被真实感受到。

如果这些数字不成立，就换场景，不要加功能。

### 不在当前主线上

以下是实验或研究方向，不是当前产品路线图：

- FHE（全同态加密）
- 链上审计
- 新的存储后端（S3/IPFS）
- Agent Registry / 市场
- Agent 写入流程

它们会留在仓库和设计文档里，但不会拖慢第一个留存闭环。研究背景见 [`docs/on-chain-audit-design.md`](docs/on-chain-audit-design.md) 和 [`docs/store-abstraction-design.md`](docs/store-abstraction-design.md)。

### 快速开始

环境要求：Node.js >= 22、git、macOS 或 Linux。**不支持 Windows。**

**安装**

```bash
curl -fsSL https://www.uomp.org/install.sh | bash
```

安装脚本会把 UOMP 克隆到 `~/.uomp/cli`，构建 CLI，并把 `uomp` 链接到 `~/.local/bin`。如果这个目录不在 `PATH` 里，脚本会打印需要添加的那一行。数据目录会在第一次 `setup` / `connect` 时创建；只有想提前准备时才需要 `uomp init`。

从源码运行时，执行 `pnpm install && pnpm build`，然后用 `pnpm cli ...` 代替 `uomp ...`。

**先看完整闭环**

```bash
uomp demo
```

它会在临时数据目录里跑完：导入 → 授权 → 允许读取 → 拒绝读取 → 审计 → 撤销。不会碰你真实的 `~/.uomp`。

如果哪里不对，运行：

```bash
uomp doctor
```

它会检查 Node、git、数据目录权限、密钥、数据库、会话 env 文件和本地 server 端口。

**一次性设置客户端**

```bash
uomp setup claude --vault ~/Obsidian/MyVault
```

这条命令会导入 Markdown 笔记库、在后台启动本地 Auth + Guard server，并把 UOMP 条目合并进 Claude Desktop 配置（已有文件会先备份）。**它不会授权任何访问。** 重启 Claude Desktop。

打开 Claude，让它读你的项目笔记。第一次工具调用会请求 `notes/projects`；UOMP 打开本地审批页（Linux/macOS 还会发桌面通知）。你批准 30 分钟后，当前调用继续。页面没有打开时，用 `uomp pending` / `uomp approve <request-id>`。

用 `--vault-tag <tag>` 可以改基础 tag（默认 `notes`）。`uomp setup cursor` / `uomp setup opencode` 处理其他客户端。

不需要保持终端打开。`uomp status` 查看后台服务和活跃会话；`uomp stop` 停止服务（不会撤销会话）；`uomp disconnect claude` 移除客户端条目并撤销会话。如果你用了 `--config`，`disconnect` 也要传同一个路径。

**或者单独导入**

```bash
uomp import ~/Obsidian/MyVault
uomp import ~/Obsidian/MyVault --dry-run
```

目录路径会变成授权范围：`projects/uomp/plan.md` 会带上 `notes`、`notes/projects`、`notes/projects/uomp` 三个 tag。Frontmatter 里的 `tags`、`title`、`sensitivity` 会保留。

**高级：预授权 / 脚本**

`uomp connect` 会跳过首次审批页，直接创建会话：

```bash
uomp connect claude --vault ~/Obsidian/MyVault --scope notes/projects
```

适合脚本/CI，或者你明确想在 Agent 运行前选好范围。高敏 tag（例如 `portfolio:holdings`）默认不会被选中；交互运行且不传 `--scope` 时会逐个选择 key。脚本里用 `--allow-key <key...>`（优先）或 `--allow-high <tag...>`（显式批量覆盖）。

`--foreground` 让 server 留在当前终端；`--print-config` 只打印 JSON 不写文件；`--skip-config` 只授权不写配置。

**授权一个 Agent 包**

```bash
uomp connect ./examples/calendar-agent --scope preference
```

这条命令会在后台启动本地 Auth + Guard server，创建 30 分钟会话，并把 token 写入 `~/.uomp/sessions/<sessionId>.env`（权限 `0600`）。它会打印需要执行的 `source` 命令和撤销命令；默认不打印完整 token。`uomp authorize` 仍然作为底层/脚本入口保留。

**在第二个终端运行 Agent**

```bash
source ~/.uomp/sessions/<sessionId>.env
node ./examples/calendar-agent/index.js
```

服务在后台运行。`uomp status` 查看服务和活跃会话；`uomp stop` 停止服务。想把日志留在当前终端就加 `--foreground`。`uomp sessions` 查看活跃会话，`uomp revoke <sessionId>` 立即撤销。`uomp audit` 查看每次允许/拒绝决策；可以用 `--since 24h`、`--result deny` 或 `--key <key>` 过滤。两个命令都支持 `--json`，方便脚本处理。

如果你想分开运行 server：

```bash
# 终端 1
uomp serve
# 或后台运行：uomp start

# 终端 2
uomp connect claude --scope notes/projects --no-server

# Agent 包：
uomp connect ./examples/calendar-agent --scope preference --no-server
source ~/.uomp/sessions/<sessionId>.env
node ./examples/calendar-agent/index.js
```

**高敏感数据示例：Stock Analyst**

```bash
uomp import ./examples/stock-analyst/sample-risk.json --replace
uomp import ./examples/stock-analyst/sample-holdings.csv \
  --tag portfolio:holdings --sensitivity high --replace

uomp connect ./examples/stock-analyst \
  --scope portfolio:holdings profile:risk \
  --allow-high portfolio:holdings

# 在第二个终端 source 上面打印的 env 文件，然后运行：
source ~/.uomp/sessions/<sessionId>.env
node ./examples/stock-analyst/index.js
```

`portfolio:holdings` 是高敏 tag。`--allow-high` 是这个 demo 的显式批量覆盖；需要逐 key 控制时用 `--allow-key <key...>`，或者不带 `--scope` 运行 `uomp connect` 交互选择。

**开发者快捷方式**

```bash
uomp agent run ./examples/calendar-agent
```

> 管理员操作（`createSession`、`grant`、`revoke`）需要本机管理员令牌，默认存放在 `~/.uomp/.secrets/admin-token`。Node SDK 仅在 base URL 为 loopback 时读取 `UOMP_ADMIN_TOKEN`。

### 手动配置 MCP（不支持的客户端）

`uomp connect` 已经处理 Claude Desktop、Cursor 和 OpenCode。其他 stdio 客户端，或者你想自己编辑配置时，走手动两步：

```bash
# 终端 1
uomp serve

# 终端 2
uomp import ~/Obsidian/MyVault
uomp authorize --scope notes/projects --output ~/.uomp/mcp-client.env --no-server
uomp mcp --session ~/.uomp/mcp-client.env --print-config
```

把输出的 JSON 粘贴到客户端的 `mcpServers` 条目。条目引用的是会话 env 文件，不是 token 本身，所以客户端配置里没有秘密。MCP server 会在每次工具调用前重新读取 env 文件；重新对同一个 `--output` 路径执行 `authorize` 即可续期，不需要重启客户端。自定义 `--output` 文件不会被 `uomp revoke` 自动删除。

stdio MCP server 提供 `list_memory`、`search_memory` 和 `read_memory`。`list_memory` 和 `search_memory` 只返回 key 和元数据，`read_memory` 返回内容。每次调用仍然经过 Memory Guard 的范围、过期、撤销和审计。已用官方 MCP SDK 和 OpenCode v2.2.0 验证；Claude Desktop / Cursor 的验证仍在进行。

### 安全模型

UOMP 会强制执行：

- Token 的 tag/key/field 范围；
- 会话过期；
- `revoke` / `close` 后立即失效；
- 每次请求的审计记录。

UOMP 不能防护：

- 以同一 OS 用户运行的恶意进程（它可以读 `~/.uomp` 和管理员令牌）；
- 被授权的 Agent 保留它收到的明文；
- 被攻陷的用户机器；
- 无视授权范围的恶意 Agent。

所以这个项目不会宣称“trustless”。目标是 **知情同意、最小权限、可撤销、可审计**，而不是保证被授权的 Agent 会忘记它看到过什么。

### 项目结构

```
packages/
  core/       共享类型和常量
  store/      记忆存储和适配器接口
  token/      Capability Token 签发与验证
  auth/       会话与管理员授权
  guard/      范围执行与审计
  sdk/        TypeScript 客户端
  cli/        `uomp` 命令行工具
apps/
  server/     Auth + Guard 组合服务
  gateway/    历史远程 Gateway（已退役）
  relay/      历史 Cloud Relay（已退役）
examples/
  calendar-agent/
  stock-analyst/
  mcp-client/
specs/
  draft-00.md
```

### 参与进来

我们在找 **10 个设计伙伴**：

- 经常使用至少两个 AI Agent；
- 个人或项目知识保存在本地文件、Obsidian 或类似工具里；
- 愿意尝试一个每周工作流，并直接给反馈。

欢迎开 issue 或阅读协议草案：

- [Issues](https://github.com/heurion-org/aegis-os/issues)
- [协议草案](https://www.uomp.org/spec/)

### License

Apache 2.0，见 [`LICENSE`](LICENSE)。
