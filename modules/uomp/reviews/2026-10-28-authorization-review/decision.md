# 决策记录 — UOMP 授权流程第一轮

- 日期：2026-10-28
- 主控：conductor
- 输入：`brief.md`、`product.md`、`review.md`、`research.md`
- 仓库：`/home/jz/workspace/uomp-mvp` @ `93d1b1f`

## 决策

**当前版本不对外发布，也不做“先美化授权面板”的改动。**

先完成“授权可信闭环”修复包：撤销必须真实生效，授权不能被本地进程自签，用户取消的范围必须真的取消。再做面板与文案。原因很简单：在一个撤销无效、scope 可被绕过的系统上把面板做得更可信，只会放大误导。

## 依据

四个 P0 均有静态代码证据：

1. **撤销无效**：Guard 不查黑名单/会话状态，`uomp revoke` 后 token 仍可用至过期（`guard:269-289`、`auth:315-318`、`config:31-33`）。
2. **授权可自签**：`/v1/sessions` 与 `/grant` 无鉴权，且不校验 `granted ⊆ requested`；Gateway 还显式跳过这两条路径（`auth:98-139,239-273`、`gateway:175-176`）。
3. **取消 tag 不等于取消 key**：manifest 里的 `read.keys` 无条件进入 token，Guard 先看 key 再看 tag（`authorize:166-171,187-193`、`guard:301-306`）。
4. **高敏默认全授权**：选中一个 high tag 会自动加入该 tag 下全部 key，且 checkbox 默认全选（`authorize:155-162,206-218`）。

## 修复顺序

### 第一步：P0 安全闭环（建议 2–3 天）

| 优先级 | 改动 | 最小验收 |
|---|---|---|
| P0-A | Guard 每次请求校验会话状态与黑名单；Auth 提供本地 introspection 或共享只读 DB | revoke 后下一个请求 403；有集成测试 |
| P0-B | create/grant 需要用户在场的一次性 nonce；校验 `granted ⊆ requested`；Gateway 不代理 create/grant | 未带 nonce 的 grant 被拒；越界 scope 被拒 |
| P0-C | token keys 只来自用户显式选择，与选中 tag 求交；不继承 manifest keys | 取消全部 tag 后，任何 key 都不可读 |
| P0-D | high tag 默认不选；逐 key 确认并显示 key 清单 | 默认授权集合为空；回车不能签发 high key |

### 第二步：诚实与可核对（建议 1–2 天）

- 授权摘要使用真实 store 统计：tag 条数、high 数、字段并集、时长、读写能力
- 明确标注“将返回整条记录”，不要把 `fields` 当承诺
- 移除或降级未实现能力：GPG “verified” 绿色提示、删除证明、100 次查询上限
- `uomp sessions` 显示 granted tags/keys、到期、剩余次数

### 第三步：测试基线（与第一步并行）

仓库目前没有任何 `*.test.ts`。至少补 8 个集成测试：

1. revoke 后读请求 403
2. 过期 token 403
3. 非 active 会话 403
4. grant 超出 requested 被拒
5. 无 nonce 的 grant 被拒
6. 取消 tag 后 manifest key 不可读
7. high tag 默认不授权任何 key
8. allowedFields 对聚合查询同样生效

## 本轮不做

- 完整威胁模型重构（同 UID 恶意进程、私钥保护）→ 单独立项
- FHE / 远程 Gateway 强化 → 等 P0 闭环后再评估
- 官网文案改版 → 等产品行为稳定
- 删除证明的密码学实现 → 先如实标注为 self-attestation

## 团队运行复盘

**有效的部分**

- `product-partner` 找到了 3 个真实的信任问题，且都落到界面与默认值
- `critic` 找到 4 个 P0，包含撤销失效和授权自签这两个会直接摧毁产品承诺的问题
- `researcher` 提供了可操作的同意设计模式，并明确指出 passkey 不是合适类比
- 三个角色并行，约一轮就形成了可决策的材料

**需要修正的部分**

- `product-partner` 把 `run.ts` 说成会自动加入 high key；实际自动加 key 在 `authorize.ts`。已在 `product.md` 修正
- `critic` 触及工具步数上限，未运行任何测试；所有结论都按“静态审查”标注
- 三个角色都提到“面板默认全选”，有重叠；这是收敛问题，不是错误

**结论**：团队配置可用。下一轮应让 `builder` 只修 P0-A，并让 `critic` 在改动后复审同一个攻击路径，验证闭环。

## 需要用户决策

三条路线，建议选 A：

- **A（推荐）**：先修 P0-A + P0-B，并补测试 1/4/5；两天内得到“撤销真实生效、授权不可自签”的可验证版本
- **B**：先修 P0-C + P0-D + 授权面板；适合近期要做用户演示，但撤销问题仍在
- **C**：先补 8 个测试，把当前行为全部固化；适合准备重构，但短期用户看不到变化

---

# 执行结果 — 2026-10-28 收尾

## 状态

路线 A 已落地。分支 `fix/auth-revocation-integrity`，**未提交、未推送**，所有改动留在工作区。

最终补丁：`.agent/2026-10-28-authorization-review/final-diff.patch`（已包含新文件 `packages/auth/src/admin.ts` 与 `tests/`；`git apply --check --reverse` 通过）。

## 已修复

| 类别 | 内容 |
|---|---|
| P0-A | Guard 在 JWT 验签后强制检查会话状态与黑名单；`revoke`/`close` 后返回 `403 SESSION_NOT_ACTIVE`；缺少 session provider 时 fail closed，返回 `503 SESSION_VALIDATION_UNAVAILABLE` |
| P0-B | `POST /v1/sessions`、`/grant`、`/revoke` 需要 `x-uomp-admin-token`；`grant` 校验 tags/keys 子集、deny 保留、`allowed_fields` 子集；Gateway 不再跳过 create/grant |
| 加固 | grant/close/revoke 条件 UPDATE，避免 revoked 被并发覆盖；管理员令牌 `wx` 原子创建 + `0600`；zod 结构化 scope 校验；SDK 管理员令牌仅发往 loopback |
| 路径一致性 | `uomp agent run` 不再清空 manifest 的 `denyTags`/`denyKeys`；`authorize` 与 `run` 统一通过 `buildReadScope` 构造授权范围；`allowedFields` 在直调 grant 时也生效 |
| 写入口 | Guard 的 PUT/DELETE 先校验会话，撤销后返回 403，不再把无效 token 当成 503 |
| 测试 | 从 0 个增加到 15 个集成测试，覆盖 revoke/close、未授权会话、provider fail-closed、管理员令牌、scope 越界、deny 保留、write 越界、字段子集、token 文件权限、写入口撤销、manifest deny/字段继承 |

## 验证结果

```bash
cd /home/jz/workspace/uomp-mvp
pnpm build                    # exit 0
pnpm -r typecheck             # exit 0
node --test tests/integration/*.test.mjs   # 15 pass / 0 fail
bash -n scripts/test-gateway-remote.sh     # exit 0
bash -n scripts/test-stock-analyst.sh      # exit 0
```

## 终审结论

最终 `critic` 未发现新的 P0 逻辑洞。其提出的 P1（`run.ts` 清空 deny 列表）已修复并加回归测试；P0 为补丁打包问题（未跟踪文件未进 diff），已通过生成完整补丁解决。P2 中的 SDK 令牌外发、PUT/DELETE 状态码、字段级授权、测试缺口已同批处理。

## 残留风险（明确不在本轮范围）

1. **同 UID 威胁模型未改**：同用户进程仍可读 `~/.uomp/.secrets/admin-token` 与私钥，从而自签或调用管理员接口。
2. **P0-C 未修**：manifest 的 `read.keys` 仍会无条件进入 token；取消 tag 不等于取消 key。
3. **P0-D 未修**：高敏 tag 仍默认选中，授权面板仍全选。
4. **`close` / `deletion-proof` 未完整鉴权**：`close` 可被本地进程调用，属于可用性风险而非提权；`deletion-proof` 仍是 self-attestation。
5. **CLI 直调 `grantSession` 仍不做 HTTP 级子集校验**：用户显式加 scope 是产品行为；但本地代码调用可传更宽范围，依赖同 UID 信任边界。
6. **32 位 token hash 未升级**：黑名单按 session 查询，当前不构成直接绕过，但应升级为 SHA-256。
7. **管理员操作无审计事件**：create/grant/revoke 尚未写 audit log。
8. **文档边缘项**：`specs/draft-00.md` 中仍有未带管理员令牌的 curl 示例；Gateway `/v1/payload/*` 路由可能被 `/v1/*` 先行匹配（既有问题，未实测）。

## 合并建议

代码层面可以进入 review/合并流程；合并前只需确认：补丁包含两个新文件、CI 跑通上述三条命令。**是否 commit / push 等待用户确认。**

