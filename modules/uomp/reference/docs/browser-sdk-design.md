# UOMP Browser SDK 设计文档

> 状态：已暂缓。浏览器/钱包不在当前路线图上，本文档保留为研究记录。独立 Gateway / Cloud Relay 已退役；远程 Agent 使用 Aegis Cloud + Aegis Memory Gateway。

> 线上 Demo：https://www.uomp.org/dashboard/

---

## 1. 核心挑战

| 挑战 | 说明 |
|------|------|
| **mTLS** | 浏览器不支持客户端证书。`window.fetch` 无法发起 mTLS 请求 |
| **CORS** | Gateway 需要返回正确的 CORS 头才能被跨域浏览器请求 |
| **无 Node.js API** | `fs`、`https.Agent`、`Buffer` 等 Node 专属 API 不可用 |
| **Token 安全** | 浏览器的 localStorage/sessionStorage 容易受到 XSS 攻击 |

---

## 2. 架构方案

```
┌──────────────────────┐       HTTPS        ┌──────────────────────┐
│   Browser App        │ ────────────────►  │   UOMP Gateway       │
│  (Web / Extension)   │   Capability Token │   :9443              │
│                      │                    │  (mTLS: optional)    │
│  @uomp/sdk (browser) │                    │  + CORS headers      │
└──────────────────────┘                    └──────────────────────┘
```

### 关键设计决策

1. **Gateway 新增 `--browser` 模式**：禁用 mTLS 对来自浏览器的请求，同时添加 CORS 头
2. **浏览器 Agent 的信任模型**：用户运行 Gateway 时显式允许浏览器访问（`agent_allowlist` 中加 `browser:*` 标识）
3. **SDK 双构建**：同一套 `@uomp/sdk` 源码，针对 Node 和 browser 分别构建

---

## 3. SDK 改动

### 3.1 双入口

```
packages/sdk/
├── src/               # 共享源码
│   ├── index.ts       # Node.js 入口（现有）
│   ├── browser.ts     # Browser 入口（新增）
│   ├── client.ts      # 无需改动
│   ├── transport.ts   # 分支：Node=mTLS, Browser=fetch
│   └── ...
├── package.json       # 新增 exports 字段
```

`package.json` exports：

```json
{
  "exports": {
    ".": {
      "node": "./dist/index.js",
      "browser": "./dist/browser.js",
      "default": "./dist/browser.js"
    }
  }
}
```

### 3.2 Transport 层分支

```ts
// transport.ts
export class Transport {
  constructor(options, jwtToken) {
    if (typeof window !== 'undefined') {
      // Browser mode: use window.fetch, no mTLS
      this._isBrowser = true;
    } else {
      // Node mode: load mTLS certs if https://
      this._isBrowser = false;
      if (baseUrl.startsWith('https://')) this.loadMtlsCert();
    }
  }

  async request(path, init) {
    const f = this._isBrowser ? window.fetch : (this.mtlsAgent ? this.nativeRequest : fetch);
    // ...
  }
}
```

### 3.3 Token 安全

浏览器中 token 默认存在 `sessionStorage`（标签页关闭即清除），不持久化到 `localStorage`：

```ts
// browser.ts
const TOKEN_KEY = 'uomp_token';

function loadToken(): string {
  return sessionStorage.getItem(TOKEN_KEY) || '';
}

function saveToken(token: string) {
  sessionStorage.setItem(TOKEN_KEY, token);
}
```

---

## 4. Gateway 改动

### 4.1 CORS 支持

```ts
// apps/gateway/src/index.ts
if (config.allowBrowser) {
  app.use('*', async (c, next) => {
    c.header('Access-Control-Allow-Origin', '*');
    c.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    c.header('Access-Control-Allow-Headers', 'Authorization,Content-Type,X-UOMP-Agent-Id');
    if (c.req.method === 'OPTIONS') return new Response(null, { status: 204 });
    await next();
  });
}
```

### 4.2 Browser 信任模型

在 `remote-profile.json` 中标记允许浏览器访问：

```json
{
  "gateway": {
    "tls": { "mtls_required": false },
    "allow_browser": true,
    "cors_origins": ["https://my-app.example.com"]
  }
}
```

Gateway 对来自浏览器的请求：
- 不要求 mTLS 客户端证书
- 校验 Capability Token（签名 + 有效期 + 撤销状态）
- Token audience 仍必须匹配 Gateway endpoint
- 拒绝非 Token 的请求（不只是 CORS）

---

## 5. 使用示例

### 5.1 Web App 直接集成

```ts
import { UompClient } from '@uomp/sdk';

// Token 通过 URL hash 或 sessionStorage 传入
// 例如：https://my-app.example.com/#token=eyJhbG...

const token = new URLSearchParams(
  window.location.hash.slice(1)
).get('token') || '';

const uomp = new UompClient({
  token,
  baseUrl: 'https://my-gateway.example.com',
});

const holdings = await uomp.memory.getByTag('portfolio:holdings');
// → 浏览器自动用 window.fetch 发起请求，Gateway 返回 JSON + CORS 头
```

### 5.2 用户侧流程

```
1. 用户运行 uomp gateway start --browser
2. Gateway 打印：
   ═══ Browser URL ═══
   https://xxx.trycloudflare.com
   CORS: enabled (allow all origins)
   
3. 用户访问 https://my-app.example.com
4. Web App 通过 UOMP token 连接 Gateway
5. Agent 读取数据、分析、展示结果
```

### 5.3 React 组件示例

```tsx
function PortfolioAnalysis() {
  const [uomp, setUomp] = useState<UompClient | null>(null);
  const [holdings, setHoldings] = useState([]);

  useEffect(() => {
    const token = sessionStorage.getItem('uomp_token');
    if (!token) return;
    const client = new UompClient({
      token,
      baseUrl: 'https://my-gateway.example.com',
    });
    setUomp(client);
    client.memory.getByTag('portfolio:holdings').then(setHoldings);
  }, []);

  return (
    <div>
      {holdings.map(h => (
        <div key={h.key}>{h.value.symbol}: {h.value.market_value}</div>
      ))}
    </div>
  );
}
```

---

## 6. 安全边界

| 场景 | 防护 |
|------|------|
| Token 泄露（XSS） | Token 在 sessionStorage，标签页关闭即清除；短有效期（10 分钟） |
| 跨域请求伪造 | CORS + Capability Token 校验 |
| 恶意 Web App 冒充 | `gateway.cors_origins` 白名单 |
| 重放攻击 | Token 绑定 Gateway audience，Gateway 校验签名 |

---

## 7. 实现路线

| Phase | 内容 | 时间 |
|-------|------|------|
| Phase 1 | `packages/sdk/browser.ts` 入口 + Transport browser 分支 | 1-2 小时 |
| Phase 2 | Gateway CORS + `--browser` 模式 | 1 小时 |
| Phase 3 | Token 安全存储（sessionStorage） + URL hash 透传 | 30 分钟 |
| Phase 4 | React hooks 封装 (`useUomp`, `useMemory`) | 后续 |
| Phase 5 | Chrome Extension 适配 | 后续 |

---

## 相关文档

- [SDK 设计文档](./sdk-design.md)
- [远程授权设计](./remote-authorization-design.md)
- [协议规范](https://www.uomp.org/spec/)
