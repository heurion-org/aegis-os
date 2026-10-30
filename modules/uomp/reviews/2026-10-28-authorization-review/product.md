# 产品信任审查 — UOMP 本地 CLI 授权流程

- 角色：product-partner
- 仓库：`/home/jz/workspace/uomp-mvp` @ `93d1b1f`
- 类型：只读
- 说明：以下“用户会……”为基于界面路径的推断；代码/文档引用为事实。尚无真实用户访谈数据。

## 结论

三个问题同源：**把“确认”做成了“默认同意”，面板展示的范围小于实际授予范围。**

问题 1、2 建议阻断发布；问题 3 发布前修。

## 1｜Quick start 授权后立即执行 Agent，且默认全选

**用户看到的场景**

README Quick start 的第一步是 `pnpm cli agent run ./examples/calendar-agent`（`README.md:138-142`）。面板只有名称、描述、发布者和默认全选的 tag（`run.ts:112-124`），没有敏感度、字段、时长。回车后直接 `spawn('node', [index.js])` 并注入 token（`run.ts:79-89`）。

**实际发生什么**

设计文档写明“CLI 不启动 Agent，避免授权即执行”（`docs/cli-sdk-design.md:108-112`），README 也说 shortcut 仅用于本地开发（`README.md:481`），但 Quick start 把它当成首次体验。用户以为在授权读取，实际同时同意了执行第三方代码。

**为什么破坏信任**

回车被当成“下一步”，不是“签约 + 执行”。一旦 Agent 行为异常，用户会认为 CLI 诱导。

**最小修复**

Quick start 改成标准模式；`agent run` 在确认页明确写“将立即执行 `<绝对路径>`”，默认只授权，`--yes` 才 spawn。

**验收标准**

- 确认前不 spawn Agent
- 无 `--yes` 时只输出 token 和运行命令，并显示完整路径
- Quick start 不再把 shortcut 作为第一步

## 2｜`--scope` 静默授权：无面板、无确认，还会自动扩到全部 high key

**用户看到的场景**

README 远程示例：`uomp authorize ... --scope portfolio:holdings profile:risk --output /tmp/uomp.env`（`README.md:497`）。帮助文案称 “Additional read scopes”（`cli.ts:76`），用户以为只是追加两个 tag。

**实际发生什么**

传入 `--scope` 即走 `buildScopesFromTags`，完全跳过面板（`authorize.ts:65-67`、`187-204`），不显示摘要；随后把 high tag 下所有 item 的 key 写入 token（`authorize.ts:206-218`）。它实际是**替换** manifest 请求列表，不是追加。

**为什么破坏信任**

名字像“缩小范围”，实际是“跳过确认 + 扩大 key”。这违背 PRD 的“最小授权、高敏感按 Key 显式授权”（`/home/jz/workspace/user-memory-prd.md:22,55`），用户事后无法复盘。

**最小修复**

任何非 `--yes` 路径都展示一次摘要并等待确认；`--yes` 仅用于自动化，摘要写入 stderr 和审计；high key 列出数量与名称，默认不授权；帮助改为 “Replace requested tags”。

**验收标准**

- 非 `--yes` 路径必有一次摘要：tags、key 数、high 数、到期时间
- 摘要必须等待显式确认
- 帮助文案不再使用 “Additional”

## 3｜字段摘要只是展示，实际返回整条记录；敏感度靠关键词猜

**用户看到的场景**

high tag 会打印 `Fields: ...` 和用途（`authorize.ts:143-152`；设计文档承诺可脱敏，`cli-sdk-design.md:139-146`），用户以为只能读这些字段。其余 tag 一律显示绿色 low：`inferSensitivity` 只识别 `holdings`/`transactions`/`profile:`/`watchlist`（`core/index.ts:113-117`），`health`、`location:home` 都会显示绿色并默认勾选。

**实际发生什么**

`grantSession` 没有传 `allowedFields`（`authorize.ts:81`），Guard 在该参数为空时返回整条 item（`guard:337-348`）。`fields` 只在 manifest 声明且 tag 被判 high 时展示。导入默认 sensitivity 也用同一函数（`import.ts:92`），健康数据会 low 入库、low 展示、按 tag 放行。

**为什么破坏信任**

典型的“以为范围小、实际大”。用户基于不准确的摘要同意，事后发现读到成本价、病历等未展示字段，会认为面板误导。

**最小修复**

- 授权前用真实 store 统计每个 tag 的条数、high 数、字段并集，并明确标注“将返回整条记录”
- high 默认不选，逐 key 确认
- 若保留字段限制，`grant` 必须传 `allowedFields`，并由 Guard 强制执行
- 敏感度按 item 自带 `sensitivity` 聚合；未知 tag 导入时要求用户确认，不能默认 low

**验收标准**

- 面板字段/条数与 Guard 实际返回一致
- high 默认未选中
- 摘要外字段不可读，或明确标注“整条记录”

## 建议的授权面板

**信息层级**

1. **谁**：名称、版本、发布者、来源。身份三档：已验证（附方式）/ 未验证 / 仅自声明。仅自声明不得用绿色 “verified”；当前 GPG 校验是占位（`identity/index.ts:70-80`）。
2. **要什么**：按 tag 显示条数、high 数、字段并集、用途（标注“Agent 自述”）。
3. **总账**：`2 个 tag、37 条、12 条高敏感；30 分钟；最多 100 次读取；不可写入`。
4. **之后**：只给 token 还是立即执行、token 明文出现位置、如何撤销。
5. **边界**：Agent 读到明文后可能留存，UOMP 无法撤回已读数据（`README.md:312`）。

**默认值**

- high 默认不选
- medium/low 可预选，但必须有独立“确认授权”页；回车不能从勾选直接到签发
- 时长默认 30 分钟并明示
- 超过 30 分钟、`--output`、远程 Gateway 均二次确认
- `--yes` 默认关闭

**危险确认**

- 摘要页输入 `yes` 才签发
- 新增 high key 用红色显示数量
- 授权后 `uomp sessions` 显示 granted tags/keys、到期、剩余次数（当前 `sessions.ts:44` 只有 id/agent/status，与 `cli-sdk-design.md:315` 不一致）

**验收标准**

首次用户不读 README 也能复述：几个 tag、多少条、哪些高敏感、多久、能否写入；`sessions` 可复核；任何扩权都需要第二次显式确认。

## 待验证

- “不敢点授权”的判断需要用 5 名非技术用户做可用性测试
- 面板文案的最佳措辞需要通过回述准确率验证
