# 外部研究 — 敏感数据临时授权的同意设计

- 角色：researcher
- 范围：OAuth scope consent、移动端权限、临时/会话级访问
- 说明：来源以官方文档与标准为主；“降低焦虑”的因果多来自厂商设计说明，缺少公开对照实验。

## 结论

业界做法高度一致：**把“授权范围”表述成用户能核对的“对象 + 动作 + 期限”三元组，并在使用现场以增量方式请求，而不是在启动时一次性请求全部权限。**

Google 与 Microsoft 都记录了“请求的 scope 越多，用户同意的概率越低”，并因此推荐增量授权；Android 要求“仅在上下文中请求、不阻断用户”，并规定同一权限被拒绝两次后不再弹窗。真正降低授权焦虑的关键是：用户随时看得见授权状态、随时能撤销、默认会过期。

> 注意：passkey 是**认证**凭证，不是授权凭证，不作为“临时数据授权”的先例。

## 5 条可借鉴模式

| # | 模式 | 为什么有效 | 来源 | 置信度 |
|---|---|---|---|---|
| 1 | **最小 scope + 增量授权**：先只请求当前动作所需 scope，后续再追加 | 用户每次只需评估一件事；Google 明确写出 scope 数量与同意概率可能成反比 | [Google OAuth](https://developers.google.com/identity/protocols/oauth2/web-server)、[Microsoft consent](https://learn.microsoft.com/en-us/entra/identity-platform/consent-types-developer) | 高（原文）/ 中（因果） |
| 2 | **“仅本次”选项**：在允许与拒绝之外给出 “Only this time” | 给犹豫用户低风险出口，避免在“永久允许”和“永久拒绝”间二选一 | [Android permissions](https://developer.android.com/training/permissions/requesting) | 高 |
| 3 | **显式期限 + 显式受众**：同时选定“多久过期”和“谁能用” | 期限把永久敞口变成可计算的暴露窗口；受众区分公开与定向 | [1Password share](https://support.1password.com/share-items/)、[Google Drive expiration](https://support.google.com/drive/answer/2494893) | 高（功能）/ 中（效果） |
| 4 | **高敏感操作的二次确认窗口**：短时 sudo 态，超时或空闲后重新认证 | 把“一次性通过”与“持续可信”解耦 | [GitHub sudo mode](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/sudo-mode) | 高 |
| 5 | **结构化、可枚举的授权对象 + 有界会话**：`authorization_details` 声明资源与动作，会话时长限制在区间内 | 用户可逐项核对“它到底能读什么”，不依赖自然语言承诺 | [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html)、[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)、[AWS STS](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use.html) | 高 |

## 3 条反模式

| 反模式 | 后果 | 来源 | 置信度 |
|---|---|---|---|
| **启动即全量授权**（一次请求所有将来可能用到的权限） | Microsoft 原文：会让用户和管理员不愿批准；用户整体拒绝，后续真实需求也拿不到授权 | [Microsoft consent](https://learn.microsoft.com/en-us/entra/identity-platform/consent-types-developer) | 高 |
| **反复弹窗、阻断式施压** | Android：同一权限被拒两次后不再展示弹窗，等同永久拒绝，只能去设置页恢复 | [Android permissions](https://developer.android.com/training/permissions/requesting) | 高 |
| **无到期 / 无限期凭证** | 默认永久等于把风险敞口留到未来；GitHub 仍强烈建议设置到期 | [GitHub PAT](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens) | 高 |

## 对 UOMP 的 3 条建议

1. **把 tag/key 授权渲染成可核算的“授权卡”**：一句话说清“允许 `<Agent>` 读取 tag=finance（共 N 条，如 invoice-2025、payroll-q3）”，同时显示总数与样例 key 名（绝不显示值）。让用户核对对象，而不是核对权限术语。置信度：中高。
2. **30 分钟会话要“可见 + 可断 + 需续确认”**：常驻显示剩余时间，一键 revoke；续期必须重新确认，不做静默续期。置信度：中高。
3. **按敏感度分层，不要做成二元开关**：普通 key 提供“仅本次”和“30 分钟”；高敏感 key 追加二次确认（passphrase 或确认码），优先支持单条 key 授权而不是整 tag 批量。不提供“永久允许”。置信度：中。

## 反例与风险

- “降低焦虑”的效果主要来自厂商设计文档与规范陈述，**未找到公开对照实验或用户研究数据**；实际收益需用 UOMP 自己的授权放弃率与撤销率验证。
- Android 的一次性权限在高频场景会造成反复打扰；30 分钟对 CLI 长任务可能过短，需要实测中断率。
- 1Password 的共享是**副本**语义（改原条目不会同步）；UOMP 应按“引用 + 可撤销句柄”设计，而不是复制数据，否则会造成“撤销了却还有旧副本”的错觉。

## 建议下一步

可以停止外部研究。剩余不确定性属于内部验证：先做 5 人可用性测试，测量三个指标——授权卡回述准确率、30 分钟任务中断率、10 秒内找到撤销入口的比例。
