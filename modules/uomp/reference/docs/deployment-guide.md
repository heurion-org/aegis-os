# UOMP 部署模式指南

> **状态（2026-10）：** 当前主线是本地 CLI + MCP 闭环。**远程 Gateway / Cloud Relay 已退役**：远程 Agent 使用 Aegis Cloud，本地入口使用 Aegis Memory Gateway。第 1 节仅保留为历史参考；本地部署请看第 2 节和 [README Quick start](../README.md#quick-start)。

## 概述

UOMP 当前支持两种部署模式：本地模式（推荐）和远程模式（高级）。

| 模式 | 用户需要做什么 | 适用场景 |
|------|--------------|---------|
| **本地模式（推荐）** | 安装 CLI | Node.js Agent 在同一台机器 |
| **远程模式（高级）** | 启动 Gateway + Tunnel | Agent 在云服务 / 另一台机器 |

---

## 1. CLI 远程模式（已退役，历史参考）

Agent 运行在云服务 / 另一台机器上，通过 Gateway 回连用户本地 Memory Guard。

### 1.1 架构

```
┌──────────────┐   mTLS + Token   ┌──────────────┐   HTTP   ┌──────────────┐
│ Remote Agent │ ────────────────► │   Gateway    │ ───────► │ Memory Guard │
│ (DO / VPS)   │    Cloudflare     │   (用户本地)  │          │   :9374      │
│              │     Tunnel        │   :9443      │          └──────────────┘
└──────────────┘                   └──────────────┘
```

### 1.2 用户侧操作

```bash
# 1. 启动 Auth + Guard 服务（终端 1）
uomp serve

# 2. 启动 Gateway + Cloudflare Tunnel（终端 2）
uomp gateway start

# 输出：
# ═══ Public Gateway URL ═══
#   https://happy-frogs-sing.trycloudflare.com
# export UOMP_BASE_URL="https://happy-frogs-sing.trycloudflare.com"

# 3. 导入数据（如果还没导入）
uomp import ./holdings.csv --tag portfolio:holdings --sensitivity high --replace

# 4. 授权远程 Agent（本地 server 已在上一步启动）
uomp authorize ./examples/stock-analyst \
  --scope portfolio:holdings profile:risk \
  --allow-high portfolio:holdings \
  --output /tmp/uomp-remote.env \
  --no-server

# 5. 设置环境变量
source /tmp/uomp-remote.env
# 确保 UOMP_BASE_URL 指向 Gateway 公网地址
export UOMP_BASE_URL="https://happy-frogs-sing.trycloudflare.com"
```

### 1.3 Agent 侧代码（Node.js SDK）

```ts
import { UompClient } from '@uomp/sdk';

// 自动从环境变量 UOM_TOKEN + UOMP_BASE_URL 初始化
// Gateway 模式下 SDK 自动加载 ~/.uomp/.gateway-certs/ 做 mTLS
const uomp = UompClient.fromEnv();

// 读取数据
const holdings = await uomp.memory.getByTag('portfolio:holdings');
const risk = await uomp.memory.getByTag('profile:risk');

// 聚合查询（不暴露原始数据）
const totalMarketValue = await uomp.aggregate.sum(
  'portfolio:holdings',
  'value.market_value'
);

// 分析...
const analysis = doAnalysis(holdings, risk, quotes);

// 上传报告到 Gateway
const payloadId = await uomp.payload.upload(JSON.stringify(analysis));

// 提交删除证明 + 关闭 Session
await uomp.session.finalize();

console.log(`Total P&L: ${analysis.totalPnl}`);
console.log(`Report payload: ${payloadId}`);
```

### 1.4 显式配置（非环境变量）

```ts
const uomp = new UompClient({
  token: 'eyJhbG...',
  baseUrl: 'https://happy-frogs-sing.trycloudflare.com',
  agentId: 'stock-analyst',
  sessionId: 'sess_xxx',
});

// SDK 自动检测 https:// → 加载 mTLS 证书
// 自动从 JWT 解析 sessionId / agentId / scopes
console.log(uomp.tokenInfo?.scopes);    // 授权范围
console.log(uomp.tokenInfo?.expiresAt); // 过期时间
```

### 1.5 Gateway 管理命令

```bash
# 启动 Gateway + Cloudflare Tunnel（推荐）
uomp gateway start

# 仅 Gateway，不暴露公网（适合 VPS 有公网 IP）
uomp gateway start --no-tunnel

# 查看 Gateway 状态
uomp gateway status
```

---

## 2. 本地模式（Agent 与 Guard 同机）

### 2.1 架构

```
┌──────────┐   HTTP   ┌──────────────┐   ┌──────────────┐
│  Agent   │ ───────► │ Memory Guard │──►│ Memory Store │
│ :local   │          │  :9374       │   │ SQLite       │
└──────────┘          └──────────────┘   └──────────────┘
```

### 2.2 操作

```bash
# 1. 启动服务
uomp serve

# 2. 授权到固定 env 文件
uomp authorize ./my-agent --scope my:data --output ~/.uomp/my-agent.env --no-server

# 3. 运行
source ~/.uomp/my-agent.env && node ./my-agent/index.js
```

---

## 3. 两种模式对比

| | 远程模式 | 本地模式 |
|------|:---:|:---:|
| 用户安装 CLI | ✅ | ✅ |
| 需要启动 Gateway | ✅ | ❌ |
| 需要公网 IP | ❌（Cloudflare Tunnel） | ❌ |
| Token 从哪里来 | `uomp authorize` | `uomp authorize` |
| 数据存在哪里 | SQLite（本地） | SQLite（本地） |
| 读操作离线可用 | ❌ | N/A |
| 写操作 | Gateway | 直连 Guard |
| 适用 Agent | 云 Agent、SaaS | Node.js Agent |
