# UOMP CLI/SDK 设计文档

> **状态：历史设计文档（CLI-first 之前）。** 当前 CLI 主路径是让 Agent 客户端做入口：用户只运行一次 `uomp setup <client>`，之后由 Agent 在需要时发起请求，UOMP 打开本地审批页。`connect` 是高级预授权入口，`authorize` 和 `mcp --print-config` 是手动/脚本 fallback；`discover`、`inspect`、`registry` 默认隐藏。远程 Gateway / Cloud Relay 已退役；远程 Agent 使用 Aegis Cloud + Aegis Memory Gateway。当前用法见 [README](../README.md#quick-start)。
>
> 下面保留原始设计分析，作为股票分析 Agent 场景的历史参考。

## 当前 CLI（2026-10）

```bash
# 一次性初始化（可选；setup 会自动创建）
uomp init

# 一次性设置客户端：导入 + 写配置 + 后台服务，不授权
uomp setup claude --vault ~/Obsidian/MyVault

# 之后由客户端发起请求，UOMP 打开审批页；终端兜底：
uomp pending
uomp approve <request-id>
uomp deny <request-id>

# 管理
uomp status
uomp audit
uomp disconnect claude
uomp stop
uomp revoke <session-id>

# 高级：预授权 / 脚本
uomp connect claude --vault ~/Obsidian/MyVault --scope notes/projects
uomp connect ./examples/stock-analyst --scope portfolio:holdings --allow-key AAPL MSFT
```

手动 fallback（不支持的客户端）：

```bash
uomp serve
uomp authorize --scope notes/projects --output ~/.uomp/mcp-client.env --no-server
uomp mcp --session ~/.uomp/mcp-client.env --print-config
```

---

> 本文档以**股票分析 Agent** 为具体范例，检查 UOMP 的 CLI 和 SDK 能否满足这类场景的需求，找出设计缺口，并给出针对此类 Agent 的通用 CLI/SDK 设计。
>
> 核心结论：
> - 股票分析 Agent 不是唯一目标，而是第一个**验收范例**。
> - CLI 和 SDK 的设计必须是**通用的**，但所有通用能力都要能回答“它能不能让股票分析 Agent 跑起来”。
> - 关键边界：**Agent User 的 CLI 不负责启动 Agent 进程**，只做发现、连接、授权。

---

## 1. 为什么用股票分析 Agent 作为验收范例

股票分析 Agent 是一个**高敏感数据 + 外部 Agent + 本地决策**的典型场景：

- **数据敏感**：持仓信息属于用户核心财务隐私。
- **Agent 外部**：分析 Agent 由第三方或开源社区开发，不运行在用户本机。
- **数据混合**：需要同时访问用户私有数据（持仓、风险偏好）和公开数据（行情、基本面）。
- **输出本地**：分析结论应保留在用户本地，不泄露。
- **用户可控**：用户必须能精确控制 Agent 读到什么、读到多细、读多久。

如果 CLI/SDK 能很好地支持股票分析 Agent，那么日历、健康、教育等其他场景的 Agent 也能沿用同一套设计。

---

## 2. 股票分析 Agent 的完整用户故事

### 2.1 角色

- **小王**：普通投资者，不会写代码。
- **stock-analyst**：一个开源股票分析 Agent，由 example-org 发布。

### 2.2 用户旅程

```text
1. 小王把自己的持仓从券商 APP 导出为 CSV。
2. 他用 uomp import 把持仓导入本地 Memory Store。
3. 他在 Registry 或本地目录发现 stock-analyst。
4. 他用 uomp inspect 验证这个 Agent 的身份和声明。
5. 他用 uomp authorize 授权 stock-analyst 读取持仓和风险偏好。
6. CLI 给他一段 export UOM_TOKEN=... 命令。
7. 小王把这段命令复制到**运行 Agent 的终端里**。
   - Phase 1 的示例通常在本机运行 Agent，但 CLI/SDK 的设计不假设 Agent 和用户必须在同一台机器上。
   - 如果 Agent 运行在远程服务器，用户可通过 `apps/gateway` 暴露 Memory Guard；Token 的 `audience` 指向 Gateway endpoint，`UOMP_BASE_URL` 也对应 Gateway URL。
8. Agent 启动后：
     - 通过 SDK 读取 portfolio:holdings 和 profile:risk
     - 通过 SDK 调用 Yahoo Finance / Alpha Vantage 获取公开数据
     - 在本地生成 Markdown 分析报告
9. 小王通过 uomp sessions 看到 Agent 正在活跃访问。
10. 分析完成后，小王用 uomp revoke 撤销会话。
```

### 2.3 Agent 声明

```json
{
  "uomp_version": "1.0",
  "agent": {
    "id": "stock-analyst",
    "version": "0.1.0",
    "name": "持仓分析助手",
    "publisher": "example-org"
  },
  "requested_scopes": {
    "read": {
      "tags": ["portfolio:holdings", "portfolio:watchlist", "profile:risk"],
      "fields": {
        "portfolio:holdings": ["symbol", "quantity", "cost_basis", "market_value"]
      },
      "purposes": {
        "portfolio:holdings": "计算仓位权重、行业分布和盈亏分析"
      }
    }
  },
  "external_data_sources": ["yahoo-finance", "alpha-vantage"],
  "identity": {
    "did": "did:ethr:0xabc123...",
    "verification_methods": ["did", "gpg"],
    "proof": { ... }
  }
}
```

---

## 3. 从范例推导出的 CLI/SDK 需求

把上面的用户故事拆开后，得到以下需求：

| 步骤 | 需求 | 对应 CLI/SDK 能力 |
|------|------|-------------------|
| 导入持仓 CSV | 通用数据导入、字段映射、敏感度标记 | `uomp import` |
| 发现 Agent | 从 Registry 或本地路径找到 Agent | `uomp discover` / `uomp registry search` |
| 验证 Agent | 确认 Agent 身份、校验包完整性、评估风险 | `uomp inspect` |
| 授权 | 展示字段级数据暴露摘要、支持编辑/脱敏 | `uomp connect` / `uomp authorize` |
| Token 交付 | 安全地把 Token 交给用户，不自动注入 | 终端打印 + `--output` |
| Agent 读取私有数据 | Agent 用 Token 访问 Memory Guard | SDK `agent.memory.read` |
| Agent 读取公开数据 | Agent 调用外部行情 API | SDK `agent.market.*` |
| Agent 输出报告 | 保存到本地文件，不写入 Memory Store | SDK `agent.output.save` |
| 监控 | 用户查看会话和审计 | `uomp sessions` / `uomp audit` |
| 撤销 | 用户主动结束授权 | `uomp revoke` |
| 开发者调试 | 本地快速验证 Agent | `uomp agent run` / `uomp agent test` |

---

## 4. 设计缺口检查与填补

### 4.1 缺口 1：CLI 不应启动 Agent

**问题**：早期 CLI 有 `uomp run <agent>`，会把授权和启动 Agent 打包在一起。这意味着用户授权后就立刻执行了一段外部代码，安全感不足。

**填补**：用户 CLI 只保留 `discover`、`connect`、`authorize`。启动 Agent 是用户自己的行为，CLI 只输出 Token。开发者才有 `uomp agent run`。

### 4.2 缺口 1.5：CLI 不应假设 Agent 和用户在同一台机器上

**问题**：如果 CLI/SDK 的设计假设 Agent 必须运行在本机，就无法支持远程 Agent 服务（如云上部署的股票分析服务）。

**填补**：

- Token 交付方式是位置无关的：CLI 只输出 `UOM_TOKEN` 和 `UOMP_BASE_URL`，用户可以把它们复制到任何运行 Agent 的终端或环境中。
- `UOMP_BASE_URL` 默认是 `http://127.0.0.1:9374`，但用户可以配置为远程 Guard 端点。
- 远程场景下，用户可通过 `apps/gateway` 自托管 Gateway（mTLS + Token 转发），把本地 Memory Guard 安全暴露给远程 Agent；相关脚本为 `scripts/generate-gateway-certs.sh` 和 `scripts/test-gateway-remote.sh`。
- Phase 1 示例为方便起见让 Agent 运行在本机，但协议和 CLI/SDK 设计不限制 Agent 位置；远程 Gateway 参考实现已可用。

### 4.3 缺口 2：导入命令必须通用且支持字段映射

**问题**：持仓 CSV 来自不同券商，列名不统一（`股票代码`、`symbol`、`Code` 等）。如果 import 命令要求严格格式，用户无法使用。

**填补**：`uomp import` 设计为通用导入器，支持：
- 自动推断常见字段别名
- `--map` 自定义映射
- `--tag` / `--sensitivity` 显式标记
- 多种格式（CSV/JSON）

### 4.4 缺口 3：授权前需要字段级摘要

**问题**：如果只告诉用户“Agent 要读 portfolio:holdings”，用户不知道 Agent 会读到成本价、股数等敏感字段。

**填补**：高敏感 tag 必须展示字段级摘要。Agent 在 `uom.json` 中用 `fields` 和 `purposes` 声明。CLI 授权面板展示：

```text
portfolio:holdings（8 条记录）
  字段: symbol, quantity, cost_basis, market_value
  用途: 计算仓位权重、行业分布和盈亏分析
  脱敏选项: 仅保留 symbol 和 weight
```

### 4.5 缺口 4：Token 交付方式要明确

**问题**：如果 CLI 自动把 Token 注入 Agent 进程，用户会失去对 Token 流向的感知。

**填补**：Phase 1 只支持两种交付方式：
- 终端打印 `export` 命令，用户手动复制。
- `--output` 保存到 `.env` 文件，用户手动 `source`。

### 4.6 缺口 5：Agent SDK 需要市场数据封装

**问题**：股票 Agent 需要调用 Yahoo Finance / Alpha Vantage 等公开 API。如果每个 Agent 都自己写一遍，开发成本高。

**填补**：SDK 提供可选的 `agent.market.*` 辅助方法，但明确说明：
- 这些数据不走 Memory Guard。
- Agent 不能把用户持仓作为参数传给外部 API。
- 最终分析逻辑在本地完成。

### 4.7 缺口 6：输出报告默认保存到本地文件

**问题**：如果 Agent 把分析报告写回 Memory Store，会增加授权复杂度和泄露风险。

**填补**：MVP 阶段 Agent 不应写入 Memory Store。SDK 提供 `agent.output.save(path, content)`，直接保存到用户本地文件。

### 4.8 缺口 7：会话监控需要足够信息

**问题**：用户授权后需要知道 Agent 是否真的在访问、访问了什么。

**填补**：`uomp sessions` 显示最后访问时间、访问端点、Agent 来源 IP、状态（活跃/空闲/未启动）。

---

## 5. CLI 设计

### 5.1 命令总览

#### Agent User 命令

| 命令 | 作用 |
|------|------|
| `uomp import <file>` | 导入任意私有数据到 Memory Store |
| `uomp data` | 查看本地 Memory Store 中的数据 |
| `uomp discover <path-or-registry>` | 发现 Agent，显示清单信息 |
| `uomp setup <client>` | 一次性设置 MCP 客户端：导入 + 写配置 + 后台服务，不授权 |
| `uomp connect <claude\|cursor\|opencode\|agent>` | 高级预授权：连接 MCP 客户端或 Agent 包，写配置/env 并启动服务 |
| `uomp inspect <agent>` | 验证身份，缓存清单，评估风险 |
| `uomp authorize <agent>` | 创建 Session 并签发 Token（手动/脚本 fallback） |
| `uomp status` | 查看后台服务、活跃会话和客户端配置状态 |
| `uomp start` | 后台启动 UOMP 服务 |
| `uomp stop` | 停止后台 UOMP 服务 |
| `uomp disconnect <client>` | 移除客户端配置并撤销对应会话 |
| `uomp pending` | 查看待审批的按需授权请求 |
| `uomp approve <request-id>` | 审批请求并写入会话 token |
| `uomp deny <request-id>` | 拒绝请求并关闭会话 |
| `uomp sessions` | 查看活跃会话 |
| `uomp revoke <session-id>` | 撤销会话 |
| `uomp audit` | 查看访问审计日志 |
| `uomp config` | 配置默认偏好 |
| `uomp dry-run <agent>` | 模拟授权，不读真实数据 |
| `uomp registry search <keyword>` | 从 Registry 搜索 Agent |

> `uomp gateway` 已退役；远程 Agent 使用 Aegis Cloud + Aegis Memory Gateway。

#### Agent Developer 命令

| 命令 | 作用 |
|------|------|
| `uomp agent init <name>` | 初始化一个 Agent 项目 |
| `uomp agent validate` | 验证 `uom.json` 和文件结构 |
| `uomp agent test` | 使用测试数据本地调试 Agent |
| `uomp agent run <agent>` | 开发者本地启动 Agent（仅测试） |
| `uomp agent publish` | 打包 Agent 供发布 |

### 5.2 核心流程

#### 5.2.1 导入私有数据

`uomp import` 是通用导入命令，遵循 [UOMP Spec §12 Memory Import Format](https://www.uomp.org/spec/)。

```bash
# 通用用法
$ uomp import data.csv --tag <tag> --sensitivity <level>

# 股票示例：导入持仓
$ uomp import holdings.csv --tag portfolio:holdings --sensitivity high

# 股票示例：导入风险偏好
$ uomp import risk.json --tag profile:risk --sensitivity medium
```

#### 5.2.2 发现 Agent

```bash
# 本地路径
$ uomp discover ./examples/stock-analyst

# 本地 Registry
$ uomp registry search stock
$ uomp discover registry://stock-analyst
```

输出示例：

```text
Agent: stock-analyst v0.1
发布者: example-org  [DID 已验证]
描述: 基于持仓和市场公开信息生成投资策略分析

权限请求:
  [高敏感] portfolio:holdings   - 当前持仓
  [中敏感] portfolio:watchlist - 自选股
  [中敏感] profile:risk        - 风险偏好

写入权限: 无
```

#### 5.2.3 检查 Agent

```bash
$ uomp inspect ./examples/stock-analyst
```

“检查”完成：

1. 读取并解析 `uom.json`。
2. 验证发布者身份（DID / GPG / Registry）。
3. 校验包完整性（checksum + signature）。
4. 缓存清单到 `~/.uomp/agents/<agent-id>/<version>/`。
5. 给出风险评分。
6. **不启动 Agent，不签发 Token**。

#### 5.2.4 连接并授权 Agent

```bash
$ uomp connect ./examples/stock-analyst --scope portfolio:holdings profile:risk --allow-high portfolio:holdings
```

CLI 展示范围摘要，用户确认后创建 Session、签发 Token，并写入 `0600` 会话 env 文件（MCP 客户端会同时写客户端配置）：

```text
Session granted: sess_abc123
  Scope     portfolio:holdings · profile:risk
  Expires   2026-07-12 10:30 (30 min)

Env file
  /home/me/.uomp/sessions/sess_abc123.env

Revoke with: uomp revoke sess_abc123
```

Token 默认不打印到终端；需要时用 `--print-token`。

#### 5.2.5 编辑范围与脱敏

用户选 `e` 后进入交互：

```text
选择本次要授权的数据:
  [x] portfolio:holdings   （当前持仓）
  [ ] portfolio:watchlist  （不授权）
  [x] profile:risk         （风险偏好）

高敏感数据选项:
  [ ] 暴露成本价和具体股数
  [x] 仅暴露持仓代码和权重（脱敏模式）
```

#### 5.2.6 查看会话

```bash
$ uomp sessions
```

输出：

```text
活跃会话:
  sess_abc123  stock-analyst  剩余 7 分钟   状态: 活跃
               已授权: [portfolio:holdings, profile:risk]
               最后访问: 10:02:15  /memory/read
               Agent 地址: 127.0.0.1 (本机)
```

#### 5.2.7 撤销与审计

```bash
$ uomp revoke sess_abc123
$ uomp audit --agent stock-analyst --today
```

### 5.3 错误信息设计

| 场景 | 输出 |
|------|------|
| Token 未授权某 tag | `Agent 请求读取 "portfolio:holdings"，但当前会话未授权。请运行: uomp authorize <agent> --include portfolio:holdings` |
| Agent 请求写入 | `当前 Agent 请求写入数据，但 UOMP MVP 禁止 Agent 写入。` |
| 会话已过期 | `会话 sess_abc123 已过期。请重新运行: uomp authorize <agent>` |
| 高敏感未确认 | `"portfolio:holdings" 为高敏感数据，需要用户在授权时显式确认。` |

---

## 6. SDK 设计

### 6.1 Agent Developer SDK

Agent 开发者 SDK 是核心，让开发者专注于业务逻辑。

```ts
import { UompAgent } from '@uomp/sdk';

const agent = await UompAgent.fromEnv();

// 读取用户授权的数据
const holdings = await agent.memory.read({ tags: ['portfolio:holdings'] });
const risk = await agent.memory.read({ tags: ['profile:risk'] });

// 读取公开市场数据
const quotes = await agent.market.quotes(['AAPL', 'TSLA']);
const fundamentals = await agent.market.fundamentals(['AAPL']);

// 生成分析
const report = analyze({ holdings, risk, quotes, fundamentals });

// 保存报告到本地文件
await agent.output.save('./output/report.md', report);
```

### 6.2 SDK API 清单

#### `UompAgent`

| 方法 | 作用 |
|------|------|
| `fromEnv()` | 从 `UOM_TOKEN` / `UOMP_BASE_URL` 初始化 |
| `whoami()` | 返回当前 Agent 的 manifest 和已授权 scope |
| `memory.read(opts)` | 读取 Memory Guard 数据 |
| `memory.write(opts)` | 写入 Memory Store（需授权，MVP 建议禁用） |
| `memory.query(opts)` | 复杂查询 |
| `market.quotes(symbols)` | 获取行情 |
| `market.fundamentals(symbols)` | 获取基本面 |
| `market.news(symbols)` | 获取新闻 |
| `market.macro(indicators)` | 获取宏观数据 |
| `output.save(path, content)` | 保存结果到本地文件 |
| `audit.log(event)` | 上报自定义审计事件 |

#### `UompAgentConfig`

```ts
interface UompAgentConfig {
  token?: string;
  baseUrl?: string;
  manifestPath?: string;
  dataSource?: {
    market?: string;
    apiKey?: string;
  };
}
```

### 6.3 错误处理

```ts
try {
  await agent.memory.read({ tags: ['portfolio:holdings'] });
} catch (err) {
  if (err.code === 'SCOPE_DENIED') {
    console.log('请要求用户授权 portfolio:holdings');
  }
  if (err.code === 'TOKEN_EXPIRED') {
    console.log('会话已过期，请重新授权');
  }
}
```

### 6.4 数据脱敏辅助

SDK 提供辅助函数，避免开发者把敏感数据传给外部 LLM：

```ts
import { redactHoldings } from '@uomp/sdk/utils';

const safe = redactHoldings(holdings, { keep: ['symbol', 'weight'] });
```

### 6.5 Agent User SDK（未来 GUI 使用）

```ts
import { UompClient } from '@uomp/client';

const client = new UompClient({ dataDir: '~/.uomp' });

await client.memory.import({ file: '~/holdings.csv', tag: 'portfolio:holdings', sensitivity: 'high' });
const manifest = await client.discover('./examples/stock-analyst');
const session = await client.authorize({ agentPath: './examples/stock-analyst', durationMinutes: 10 });
await session.revoke();
```

---

## 7. Registry 设计

Phase 1 实现本地 Registry 索引，沿用 ERC-8004 接口设计，后续对接链上合约。

### 7.1 Agent 打包格式

```text
stock-analyst-0.1.0/
  uom.json
  dist/
  README.md
  LICENSE
  signature.json
```

### 7.2 本地 Registry 索引

- 存储位置：`~/.uomp/registry/index.json`
- CLI 命令：`registry search/list/add/remove/verify/sync`
- 索引包含：id、version、publisher、metadata URI、source URL、checksum、signature、verified、tags

### 7.3 发现流程

```text
uomp registry search stock
  -> 读取本地索引
  -> 返回匹配列表
uomp discover registry://stock-analyst
  -> 下载/使用缓存
  -> 校验 checksum + signature
  -> uomp inspect 完成验证
  -> uomp connect 授权
```

### 7.4 验证层级

| 层级 | 验证内容 |
|------|----------|
| L1 本地校验 | `uom.json`、checksum、signature |
| L2 Registry 验证 | Registry 上 `isVerified=true` |
| L3 用户信任 | 用户之前授权过同一发布者 |

---

## 8. 数据源设计（以股票为例）

股票分析 Agent 需要的数据分为用户私有数据和公开数据。

### 8.1 用户私有数据

| 数据项 | tag | sensitivity | 导入方式 |
|--------|-----|-------------|----------|
| 当前持仓 | `portfolio:holdings` | high | `uomp import holdings.csv` |
| 自选股 | `portfolio:watchlist` | medium | `uomp import watchlist.csv` |
| 风险偏好 | `profile:risk` | medium | `uomp import risk.json` |

### 8.2 公开数据

Agent 自行通过 SDK `market.*` 调用外部 API：

| 数据源 | 覆盖范围 | 适用市场 |
|--------|----------|----------|
| Yahoo Finance | 行情、历史 K 线 | 美股 |
| Alpha Vantage | 行情、基本面 | 美股 |
| Tushare | 行情、基本面、宏观 | A股 |
| AKShare | A股/港股/基金 | A股 |

### 8.3 数据源使用原则

1. 用户私有数据必须走 Memory Guard。
2. 公开数据 Agent 可自行获取，但要在 `uom.json` 声明。
3. Agent 不能把用户持仓作为参数传给第三方 LLM 或数据源。
4. 如需调用云端 LLM，先对持仓脱敏。

---

## 9. 安全与隐私要点

1. **用户 CLI 不启动 Agent**：避免“授权即执行”。
2. **Token 交付安全**：终端打印 + `--output` 保存文件，不自动注入。
3. **字段级暴露摘要**：高敏感 tag 必须展示字段和用途。
4. **连接时全面验证**：身份、签名、checksum、Registry、风险评分。
5. **持仓默认高敏感**：`portfolio:holdings` 标记为 high。
6. **报告本地保存**：分析结论默认写到本地文件，不写入 Memory Store。
7. **会话短期**：默认 10-30 分钟。
8. **审计完整**：每次读取、外部 API 调用、报告生成都要记录。

---

## 10. 未来扩展：远程 Agent 与链上审计

当前 Phase 1 只考虑本机 Agent。但长期来看，UOMP 必须支持远程 Agent 部署和链上审计锚定。

### 10.1 远程 Agent 部署

大多数 Agent 最终会以**服务**形式运行在远程服务器上，而不是跟用户在同一台设备上：

- 用户通过轻量 CLI 或本机界面授权。
- Agent 运行在云端或第三方服务器。
- Agent 不跟用户设备处于同一本地网络。

值得强调的是，CLI/SDK 的设计从第一阶段就不假设 Agent 和用户同机：

- `uomp authorize` 只输出 Token 和 Guard URL，不替用户启动 Agent。
- Token 交付方式（终端打印 / 文件保存）与 Agent 所在位置无关。
- Agent 只要能访问 `UOMP_BASE_URL`，就可以运行在任何地方。

这要求 UOMP 支持 Remote Profile：

1. Memory Guard 通过 TLS 1.3 + mTLS 暴露。
2. Capability Token 的 `profile` claim 为 `"remote"`，`audience` 绑定到远程 Guard 端点。
3. 远程 Agent 持有用户签发的客户端证书。
4. 用户必须显式开启 Remote Profile，默认关闭。
5. 远程 Guard SHOULD 部署在用户自托管的网关、反向隧道或可信服务上。

### 10.2 远程 Agent 的 Payload 交付

当 Agent 运行在远程时，它生成的分析报告、通知、建议等 Payload 需要安全地交付给用户。可选方案：

| 方案 | 说明 | 优点 | 缺点 |
|------|------|------|------|
| 端到端加密 | 用用户公钥加密 Payload，只有用户私钥能解密 | 最安全 | 需要用户端密钥管理 |
| 安全回调 URL | 用户提供一个 HTTPS 回调端点，Agent POST Payload | 简单 | 回调端点可能被攻击或泄露 |
| 链下存储 + 链上 hash | Payload 存在 IPFS/加密云存储，链上只存 hash 和授权 | 可验证、可审计 | 需要链下存储可用性 |
| 本地中转网关 | 用户自托管网关，Agent POST 到网关，用户主动拉取 | 用户可控 | 需要用户有公网入口 |

建议长期方案：

- 默认使用**端到端加密 + 本地中转网关**。
- 报告类 Payload 存到用户指定的本地或加密云存储，链上只存 hash 用于审计。
- 即时通知类 Payload 使用加密回调或推送通道。

### 10.3 审计日志上链

MVP 审计日志存在本地 SQLite。未来需要把审计事件直接记录到区块链上，实现不可篡改的审计证明。

支持两条链：

- **EVM**：以太坊及兼容链（Polygon、Base、Arbitrum 等）。
- **Starknet**：适合高频、低成本的审计事件上链。

上链内容：

审计事件以链上 event 的形式写入，主要包含两类事件：

1. **授权事件**：Session 创建、授权、撤销。
   - `session_id`
   - `agent_id`
   - `action`（created / granted / revoked / expired）
   - `granted_tags`
   - `granted_keys`
   - `expires_at`
   - `timestamp`

2. **访问事件**：Agent 对 Memory Guard 的读取记录。
   - `session_id`
   - `agent_id`
   - `action`（read）
   - `tags`
   - `keys`
   - `allowed`
   - `timestamp`

注意事项：

- 完整访问日志仍保留在本地，链上记录的是关键事件的不可篡改证明。
- 对于隐私敏感字段（如具体 key），可选择在链上使用不可逆标识符或 commitment，但事件本身必须能证明授权和访问行为发生过。
- 使用 L2 或 Starknet 降低单次 event 成本。
- 访问事件可以批量提交，授权事件建议实时提交。

用户和监管方可以通过链上 event 验证：

- 某个 Agent 是否获得过授权。
- 授权范围和有效期。
- Agent 是否实际执行过读取操作。

## 11. 实现阶段

### Phase 1：通用 CLI/SDK + 股票示例（已实现）

参考实现位于 [`reference`](../README.md)，完整可运行流程见 [`examples/stock-analyst/README.md`](../examples/stock-analyst/README.md)。

已实现能力：

- CLI 支持 `discover`、`connect`、`authorize`、`sessions`、`revoke`、`audit`、`import`。
- `authorize`/`connect` 展示数据暴露摘要；高敏感 tag 默认不选，选中后逐 key 确认，非交互模式需显式 `--allow-key` 或 `--allow-high`。
- Token 交付：写入 `0600` 会话 env 文件；`--print-token` 才打印。
- 本地 Registry 索引（`registry search/list/add/remove`）。
- Agent Developer SDK（`UompAgent.fromEnv()`、`memory.readTag`、`memory.readKey`、`output.save`）。
- 股票分析 Agent demo：导入 CSV/JSON → 授权 → 独立运行 → 生成本地 Markdown 报告。
- 会话与审计查询。

### Phase 2：体验打磨（2-3 周）

- `uomp import` 字段映射、格式识别、预览
- `uomp dry-run` 模拟授权
- `uomp config` 用户配置
- SDK 数据脱敏辅助函数
- 更友好的错误信息
- 开发者命令 `uomp agent run` / `uomp agent test`
- `uomp registry sync` 对接链上 ERC-8004 合约

### Phase 3：生产准备（后续）

- 多数据源适配器
- 本地 LLM 支持
- GUI 应用

### Phase 4：远程 Agent 与链上审计（长期）

- Remote Profile 参考实现（TLS 1.3 + mTLS）
- 远程 Agent Payload 交付方案（端到端加密 + 本地中转网关）
- 审计事件（授权 + 读取）记录到 EVM 链
- 审计事件记录到 Starknet
- 链上审计 event 的查询与验证工具

---

## 12. 待决策问题

1. **字段级摘要是否必须？**
   - 建议：高敏感 tag 必须展示字段和用途。
2. **Token 交付方式**
   - Phase 1 用终端打印 + `--output` 保存文件。
3. **Registry 实现**
   - Phase 1 本地 JSON 索引，沿用 ERC-8004 接口。
4. **Agent 写入限制**
   - MVP 禁止 Agent 写入；报告保存到本地文件。
5. **是否需要 Python SDK？**
   - 建议：先做好 TypeScript SDK，Python SDK 后续跟进。
6. **远程 Agent Payload 交付的默认方案？**
   - 候选：端到端加密、本地中转网关、链下存储 + 链上 hash。
7. **审计事件上链频率？**
   - 授权事件（created/granted/revoked）建议实时上链。
   - 读取访问事件可以批量上链，以降低成本。
   - 需要平衡实时性、成本和隐私。

---

## 13. 下一步行动

1. Phase 1 已跑通股票分析示例，继续打磨错误提示与字段映射体验。
2. 推进 Phase 2：`uomp dry-run`、`uomp config`、更完善的 `import` 预览/脱敏、链上 Registry 同步。
3. 补充更多验收范例（日历、健康、教育类 Agent）以验证通用性。
