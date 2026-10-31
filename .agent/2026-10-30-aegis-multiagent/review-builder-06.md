# Review — Builder-06（Consent/Revocation 收尾）

日期：2026-10-31
审查者：Conductor 复核
上游：`builder-06.md`
状态：**通过（剩余已知限制）**

---

## 1. 结论

Builder-06 完成了 review-builder-05 的主要 P1/P2：

- audit `task_id`：完成
- `memory sessions --task-id`：完成
- task-scoped revoke token：完成（HMAC + 120s + task 绑定）
- gateway mock test：完成

验证：

```bash
cargo test -p aos-memory-server  # 2 passed
cargo test -p aos-ipc             # 17 passed
cargo test -p aos-mcp-gateway     # 27 passed
cargo test -p aos-policy          # 7 passed
cargo test -p aos-memory          # 10 passed
cargo test -p aos-cli             # 16 passed
cargo check --workspace           # Finished
```

---

## 2. P0

无。

---

## 3. P1（仍建议后续处理）

### P1-1 真实多进程 / kill -9 未验证

- 现有并发测试是“同进程多实例”，不是 8 个 OS 进程 × 100 任务。
- kill -9 恢复只做了代码路径设计（stale/损坏文件保护），没有真实进程测试。
- 建议：在 CI 或 release 前跑一次 `scripts/a2a_stress.sh`（待补）。

### P1-2 Session revoke → task input-required 只覆盖 CLI

- 直接调用 `POST /v1/sessions/:id/revoke` 不会通知 Aegis。
- 建议：memory server 增加可选 webhook，或 gateway 轮询 revoked sessions。

### P1-3 `revoke-by-task` 仍 best-effort

- Gateway 调用失败不阻塞任务终态，没有重试/告警。
- 建议：加一次重试 + audit failure event。

---

## 4. P2

1. 多 active task 时 task context 不注入，task-scoped lease 不可用。
2. `memory pending` 输出仍无 header，task_id 列容易看错。
3. `revoke_sessions_for_task` 全表扫描，未建 `task_id` 索引。
4. `request_task_input` 不发 input-required 通知。
5. `AOS_MEMORY_TASK_SECRET` 需要手动同步到 gateway 和 memory server。
6. 没有 `memory sessions --task-id` 的自动化 CLI 测试。

---

## 5. Gate 决定

**通过。** 可以进入收尾提交：

- 当前 Phase 0 的 #1–#7 代码链路已闭环。
- 剩余项是生产化/压测/反向事件化，不阻塞 Phase 0 dogfood。

建议 commit 批次：

1. `feat(memory): add task-aware audit and session filtering`
2. `feat(memory): add task-scoped revoke token`
3. `test(gateway): cover terminal task memory revoke`
4. `docs(agent): record consent/revocation finishing`

---

## 6. 最可能的失败场景

8 个真实 OS 进程并发写 `ipc_state.json` 时，`flock` + 原子写可能暴露同进程测试看不到的时序问题；同时 kill -9 后 stale 任务清理依赖 `pid + start_time`，如果 launcher 不写 `start_time`，可能误判。必须在 release 前跑真实多进程测试。
