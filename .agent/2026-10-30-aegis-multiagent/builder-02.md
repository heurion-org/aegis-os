# Builder-02 — A2A 状态机 + IPC 持久化可靠性

日期：2026-10-31
范围：`product.md` #2（状态机全量）与 #3（持久化原子写/锁）
状态：代码完成，测试通过，未 commit / push

## 1. 状态机（#2）

### 改动

`crates/aos-core/src/lib.rs`：

- `A2ATaskState::can_transition_to(next)`：合法生命周期边
  - `submitted` → `working | completed | failed | canceled | rejected`
  - `working` → `input-required | completed | failed | canceled | rejected`
  - `input-required` → `working | completed | failed | canceled | rejected`
  - terminal → 仅自身（幂等 no-op）
- `A2ATask.failure_kind: Option<String>`（`serde(default)`，旧状态文件无损加载）

`crates/aos-ipc/src/lib.rs`：

- `update_task_state`：
  - 同状态重复调用 = 幂等 no-op，不追加 history
  - 非法转移直接拒绝
  - `failed` 时写入 `failure_kind`（取 message，缺省 `unknown`）
  - `canceled` 仅 requester（上一 slice）
- `reply`：
  - 终态任务拒绝 reply
  - 只允许合法转移到 `completed` / `failed`
  - `failed` 时 `failure_kind = "agent_error"`
- `ack`：保持 `submitted -> working`

### 测试

`crates/aos-ipc/src/lib.rs`：

- `a2a_task_state_machine_and_failure_kind`
  - `submitted -> input-required` 被拒
  - `ack -> working -> input-required -> working -> completed`
  - terminal 自转移幂等，不增加 history
  - `completed -> working` 被拒
  - failed reply 写入 `failure_kind=agent_error`
  - 终态后再次 reply 被拒

## 2. 持久化（#3）

### 改动

`crates/aos-ipc/Cargo.toml` / workspace：

- 增加 `libc` 依赖（Unix `flock`；项目不支持 Windows）

`crates/aos-ipc/src/lib.rs`：

- `state_lock()`：
  - 基于 `ipc_state.lock` 的 `flock(LOCK_EX)`
  - 通过 `tokio::task::spawn_blocking` 获取，避免阻塞 async runtime
  - 进程退出自动释放
- `flush_to_disk()`：
  - 先写 `ipc_state.json.tmp`
  - `rename` 原子替换
  - 读者只会看到旧/新完整 JSON，不会看到截断文件
- 所有读-改-写方法都持有 writer lock：
  - `register_peer`
  - `update_peer_metadata`
  - `update_agent_card`
  - `update_task_state`
  - `send`
  - `recv_inbox`
  - `ack`
  - `reply`
  - `mark_delivered`
  - `touch_peer`
  - `refresh_and_prune_peers`
- `reply` 在提交 task/mailbox 后 **drop lock**，再调用 `send`，避免同一任务重入 `flock` 死锁。

### 测试

- `concurrent_state_file_writes_do_not_lose_tasks`：8 个 `AegisIpcBus` 实例并发写同一 state file，最终 8 个 task 全部存在。
- `state_lock_sequential_register_peer`：顺序 register/metadata/list 正常。
- 现有 `test_end_to_end_multi_agent_ipc_and_cow_workflow` 通过，确认 `ipc_reply` 不再死锁。

## 3. 验证

```bash
cargo test -p aos-ipc
# 15 passed; 0 failed

cargo test -p aos-mcp-gateway
# 26 passed; 0 failed

cargo check --workspace
# Finished dev profile
```

## 4. Critic 复审后的补丁（2026-10-31）

Critic 首轮复审发现 1 个 P0 + 5 个 P1，已补：

1. **P0 同实例读者回滚写者**：增加进程内 `state_mutex`，所有 `reload_from_disk` 调用（含 `get_task`/`list_tasks`/`peek_inbox`）都先取该 guard；`flock` 只负责跨进程。新增 `same_instance_reader_does_not_roll_back_writer` 回归测试。
2. **P1 reply 先消费消息后校验**：把 mailbox `Replied` 更新移到 task 校验之后；新增 `rejected_reply_does_not_consume_message`。
3. **P1 reply 响应投递失败**：在 task/mailbox 变更前预校验附件；非法附件现在不会把任务置终态。磁盘/send 失败仍是残余风险（需要 outbox 才能完全解决）。
4. **P1 stale 任务**：`A2ATask.stale` + `sweep_stale_tasks()`；`list_tasks` 自动 sweep（5 分钟阈值）；live assignee 下次转移会清掉 stale。新增 `stale_tasks_are_marked_without_killing_them`。
5. **P1 flock 无超时**：改为 `LOCK_NB` + 20ms 退避 + 5s deadline；超时返回明确错误。
6. **P1 损坏状态文件被静默清空**：`state_error` 记录读/解析失败；`flush_to_disk` 拒绝覆盖损坏文件。新增 `corrupt_state_file_is_not_overwritten`。

## 5. 风险 / 未完成

1. **并发测试是“同进程多实例”，不是“多 OS 进程”**：`flock` 是跨进程的，但 Phase 0 还需要一次真实 8 进程 × 100 任务压测 + kill -9 恢复测试。
2. **reply 响应投递仍非原子**：任务已终态、`send` 失败时响应可能丢失；当前只预校验附件。需要 outbox / 确定性 response id 才能完全解决。
3. **`touch_peer` 的 drop/reacquire**：未知 peer 时先释放锁再 `register_peer`，存在极小窗口；可接受，后续可合并为内部 `register_peer_locked`。
4. **锁粒度较大**：整个读-改-写期间持锁；本地低并发可接受，后续可评估 per-org/per-task 锁。
5. **`flock` 在 NFS/网络盘行为不保证**；runtime 目录应在本地文件系统。
6. **`failure_kind` 目前是自由字符串**：后续可改为 enum（`policy_denied | conflict | timeout | agent_error | revoked`）。
7. **没有 `revision`/CAS**：`updated_at_ms` 不能当版本号；#5 task-scoped lease 前建议补。
8. **没有 operator 身份**：`update_task_state` 目前只认 requester/assignee；#4 board 若需要服务身份，需要显式 operator。
9. **未做 #4 Task Board、#5 task-scoped lease、#6/#7 consent/撤销传播**。
10. **未 commit / push**。

## 5. 下一步

1. critic 复审本 slice，重点：
   - 状态机边是否覆盖 A2A 语义
   - `reply` 的 drop/reacquire 是否有竞态
   - `flock` + `spawn_blocking` 是否会在高并发下耗尽 blocking pool
2. 复审通过后进入 #4 Task Board 与 #5 task-scoped lease。
3. 补真实多进程压测 + kill -9 恢复测试。
