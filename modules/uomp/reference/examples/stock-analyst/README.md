# 股票分析 Agent / Stock Analyst

[English](#english) | [中文](#中文)

---

## 中文

### 概述

UOMP 参考实现中的旗舰示例 Agent。v1.0 升级为**自服务 HTTP API**，可部署到 Digital Ocean 等云平台，任何人都可以连接并授权分析。

**v1.0 新增**（三个 Tier 全部完成）：
- **Tier 1**：Sharpe ratio、VaR(95%)、相关矩阵、再平衡建议、配置化、JSON 输出
- **Tier 2**：最大回撤分析（历史）、RSI-14、MACD、MA-50/200、SPY 基准对比（Alpha）、情景分析
- **Tier 3**：HTML 报告（暗色主题）、HTTP API 服务器、自服务 Web UI、Docker 化部署

### 文件结构

```
examples/stock-analyst/
├── uom.json              # Agent 声明
├── server.js             # HTTP 服务器（主入口）
├── index.js              # CLI 模式（兼容旧用法）
├── lib/
│   ├── config.js         # 可配置阈值与参数
│   ├── market.js         # 多数据源行情（重试 + 限流）
│   ├── analysis.js       # 全部分析逻辑
│   └── report.js         # JSON / Markdown / HTML 报告
├── .do/app.yaml          # Digital Ocean App Platform 配置
├── Dockerfile            # 容器化部署
├── sample-holdings.csv   # 示例数据
├── sample-risk.json      # 示例风险偏好
└── README.md
```

### 快速开始（本地）

```bash
pnpm build
pnpm --filter @uomp/server start

# 导入数据
pnpm cli import ./examples/stock-analyst/sample-risk.json --replace
pnpm cli import ./examples/stock-analyst/sample-holdings.csv \
  --tag portfolio:holdings --sensitivity high --replace

# 启动 Agent 服务
node examples/stock-analyst/server.js

# 授权并调用（另一个终端）
pnpm cli authorize ./examples/stock-analyst \
  --scope portfolio:holdings profile:risk --allow-high portfolio:holdings --output /tmp/uomp.env --no-server
source /tmp/uomp.env
curl -X POST http://localhost:3080/analyze \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"$UOM_TOKEN\",\"gateway_url\":\"$UOMP_BASE_URL\"}"
```

`portfolio:holdings` 是高敏 tag。`--allow-high` 会显式授予该 tag 下所有 key；需要逐 key 控制时改用 `--allow-key <key...>`，或者不带 `--scope` 运行交互授权。

### 远程 Gateway 模式

```bash
# 1. 生成证书 + 启动 Gateway
./scripts/generate-gateway-certs.sh
node apps/gateway/dist/index.js

# 2. 启动 Agent 服务
node examples/stock-analyst/server.js

# 3. 获取 Agent 指纹（供 allowlist）
curl http://localhost:3080/fingerprint

# 4. 把指纹加入 ~/.uomp/remote-profile.json 的 agent_allowlist

# 5. 授权并调用
pnpm cli authorize ./examples/stock-analyst \
  --scope portfolio:holdings profile:risk --allow-high portfolio:holdings --output /tmp/uomp.env --no-server
source /tmp/uomp.env
curl -X POST http://localhost:3080/analyze \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"$UOM_TOKEN\",\"gateway_url\":\"https://localhost:9443\"}"
```

### 自服务 Web UI

访问 `http://localhost:3080/`，粘贴 Token 和 Gateway URL 即可分析：

```
┌──────────────────────────────────────────┐
│  UOMP Stock Analyst v1.0.0                │
│                                           │
│  Capability Token (UOM_TOKEN)             │
│  ┌─────────────────────────────────────┐  │
│  │ eyJhbG...                           │  │
│  └─────────────────────────────────────┘  │
│                                           │
│  Gateway URL (UOMP_BASE_URL)              │
│  ┌─────────────────────────────────────┐  │
│  │ https://my-gateway.example.com      │  │
│  └─────────────────────────────────────┘  │
│                                           │
│  [ Analyze Portfolio ]                    │
│                                           │
│  ── Results ──────────────────────────    │
│  Holdings: 10 | P&L: +72.7%              │
│  HHI: 1306 | Vol: 0.16% | Sharpe: 1.21  │
│  Signals: 8 | [Download HTML Report]     │
└──────────────────────────────────────────┘
```

### Digital Ocean 部署

1. 把仓库推送到 GitHub
2. 在 DO App Platform 创建 App，选择此仓库
3. 指定 Dockerfile 路径 `examples/stock-analyst/Dockerfile`
4. 部署完成后，访问 `/fingerprint` 获取 Agent 证书指纹
5. 用户将此指纹加入他们的 `agent_allowlist`

```bash
# 用户侧设置
echo '{
  "profile": "remote",
  "gateway": {
    "endpoint": "https://my-gateway.example.com",
    "tls": { "mtls_required": true },
    "agent_allowlist": ["<agent-fingerprint-from-/fingerprint>"]
  }
}' > ~/.uomp/remote-profile.json
```

### API 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/` | Web UI |
| GET | `/health` | 健康检查 |
| GET | `/fingerprint` | 客户端证书指纹（加入 allowlist） |
| POST | `/analyze` | 执行分析 |

`POST /analyze` 请求体：

```json
{
  "token": "eyJhbG...",
  "gateway_url": "http://127.0.0.1:9374",
  "session_id": "sess_xxx",
  "finnhub_key": "",
  "config": { "thresholds": { "stop_loss_pct": 10 } }
}
```

### 分析维度

| 维度 | 说明 |
|------|------|
| 盈亏分析 | 逐股 P&L、P&L%、权重、组合总盈亏 |
| 行业分布 | 实际 vs 目标配置偏差 |
| 集中度 | HHI 指数（> 2500 警告） |
| 风险指标 | 年化波动率、Sharpe、VaR(95%)、Beta、Alpha |
| 相关矩阵 | 持仓间 Pearson 相关系数 |
| 技术指标 | RSI-14、MACD、MA-50/200 |
| 交易信号 | 止损/止盈 + RSI 超买/超卖 |
| 回撤分析 | 单股历史最大回撤 period |
| 再平衡建议 | 按目标配置生成买卖方案 |
| 情景分析 | 大盘跌幅 5%/10%/20%/30% 组合影响 |
| 基准对比 | vs SPY 的 Alpha 和信息比率 |

---

## English

### Overview

Flagship example Agent in the UOMP reference implementation. v1.0 upgrades to a **self-serve HTTP API** deployable to Digital Ocean and other cloud platforms — anyone can connect, authorize, and analyze.

**v1.0 highlights** (all three Tiers complete):

- **Tier 1**: Sharpe ratio, VaR(95%), correlation matrix, rebalance suggestions, configurable params, JSON output
- **Tier 2**: Max drawdown (historical), RSI-14, MACD, MA-50/200, SPY benchmark (Alpha), scenario analysis
- **Tier 3**: HTML report (dark theme), HTTP API server, self-serve Web UI, Dockerized deployment

### Quick Start

```bash
pnpm build && pnpm --filter @uomp/server start
pnpm cli import ./examples/stock-analyst/sample-risk.json --replace
pnpm cli import ./examples/stock-analyst/sample-holdings.csv \
  --tag portfolio:holdings --sensitivity high --replace
node examples/stock-analyst/server.js
pnpm cli authorize ./examples/stock-analyst \
  --scope portfolio:holdings profile:risk --allow-high portfolio:holdings --output /tmp/uomp.env --no-server
source /tmp/uomp.env
curl -X POST http://localhost:3080/analyze \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"$UOM_TOKEN\",\"gateway_url\":\"$UOMP_BASE_URL\"}"
```

`portfolio:holdings` is high-sensitivity. `--allow-high` explicitly grants every key under the tag; use `--allow-key <key...>` for individual keys, or run without `--scope` for the interactive prompt.

### Self-Serve Web UI

Visit `http://localhost:3080/` — paste your token and Gateway URL, click Analyze.

### Digital Ocean Deployment

1. Push repository to GitHub
2. Create App on DO App Platform with Dockerfile path `examples/stock-analyst/Dockerfile`
3. After deployment, get the agent fingerprint from `GET /fingerprint`
4. Users add this fingerprint to their `agent_allowlist`

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Web UI |
| GET | `/health` | Health check |
| GET | `/fingerprint` | Client cert fingerprint for allowlist |
| POST | `/analyze` | Run analysis |

### Analysis Dimensions

| Dimension | Description |
|-----------|-------------|
| P&L | Per-stock and portfolio P&L, P&L%, weight |
| Sector | Allocation vs target, deviation |
| Concentration | HHI index (red flag > 2500) |
| Risk metrics | Volatility, Sharpe, VaR(95%), Beta, Alpha |
| Correlation | Pearson matrix between all holdings |
| Technical | RSI-14, MACD, MA-50/200 |
| Signals | Stop-loss/take-profit + RSI overbought/oversold |
| Drawdown | Historical max drawdown per stock |
| Rebalance | Buy/sell suggestions to match target allocation |
| Scenarios | Portfolio impact of -5/-10/-20/-30% market shocks |
| Benchmark | Alpha and Info Ratio vs SPY |
