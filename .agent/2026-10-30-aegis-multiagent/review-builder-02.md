# Review — Builder-02（#2 状态机 / #3 IPC 持久化）

日期：2026-10-31
审查者：Critic（首轮）+ Conductor 复核
上游：`builder-02.md`
状态：**有条件通过**；#3 的 P0/P1 已修，允许进入 #4 只读 board；#5 前建议补 `revision`/CAS

---

## 1. 结论

Builder-02 首轮实现有 1 个 P0 和 5 个 P1，均已修复并加回归测试：

- **P0**：同实例读者 `reload_from_disk` 会回滚写者未 flush 的内存修改。
- **P1**：reply 先消费消息后校验；reply 响应投递失败；无 stale 任务；`flock` 无超时；损坏状态文件被静默清空。

当前：

```bash
cargo test -p aos-ipc
# 15 passed; 0 failed

cargo test -p aos-mcp-gateway
# 26 passed; 0 failed

cargo check --workspace
# Finished dev profile
```

**Gate：有条件通过。** #4 只读 Task Board 可以开始；#5 task-scoped lease 前建议补 `revision`/CAS 与 operator 身份。

---

## 2. P0（已修复）

### P0-1 同实例读者回滚写者

- **原问题**：`get_task` / `list_tasks` / `peek_inbox` 无锁 `reload_from_disk`，会用磁盘旧状态覆盖写者尚未 flush 的内存修改。
- **修复**：`AegisIpcBus` 增加 `state_mutex`；所有调用 `reload_from_disk` 的方法（含读者）先取进程内 guard；`flock` 继续负责跨进程。
- **回归测试**：`same_instance_reader_does_not_roll_back_writer`（10 个任务 × 50 次读并发）。
- **残余**：跨进程读者仍可能读到旧状态，但不会回滚写者内存；原子 rename 保证文件完整。

---

## 3. P1（已修复 / 部分）

### P1-1 reply 先消费消息后校验

- **修复**：mailbox `Replied` 更新移到 task 终态/转移校验之后。
- **测试**：`rejected_reply_does_not_consume_message`。

### P1-2 reply 响应投递失败

- **修复**：在 task/mailbox 变更前预校验附件；非法附件不会把任务置终态。
- **残余**：任务已终态后 `send` 仍可能因磁盘/进程失败丢失响应。需要 outbox 或确定性 response id + 幂等重发；列为 #5 前可选加固。

### P1-3 无 stale/孤儿任务

- **修复**：`A2ATask.stale` + `sweep_stale_tasks()`；`list_tasks` 自动 sweep（5 分钟阈值）；live assignee 下次转移清除 stale。
- **测试**：`stale_tasks_are_marked_without_killing_them`。
- **说明**：只标记，不改 state，符合 S4“不自动判死”。

### P1-4 flock 无超时

- **修复**：`LOCK_NB` + 20ms 退避 + 5s deadline；超时返回明确错误。
- **残余**：没有 holder pid 诊断；后续可写入 lock 文件内容。

### P1-5 损坏状态文件被静默清空

- **修复**：`state_error` 记录读/解析失败；`flush_to_disk` 拒绝覆盖损坏文件。
- **测试**：`corrupt_state_file_is_not_overwritten`。
- **残余**：没有 `.bak` 自动备份；后续可加。

---

## 4. 仍未解决（进入 #4/#5 前评估）

| # | 问题 | 影响 | 建议 |
|---|---|---|---|
| 1 | 无 `revision`/CAS | #5 lease 无法安全判定任务版本；同毫秒更新无法排序 | #5 前加 `revision: u64` + `expected_revision` |
| 2 | 无 operator 身份 | #4 board 若作为独立服务无法推进/关闭任务 | 引入显式 `operator:<id>`，不要用 `org_id="*"` |
| 3 | 角色 → 状态矩阵缺失 | requester 可直接置 `completed`，board 指标不可信 | 定义 assignee 负责 working/completed/failed；requester 负责 canceled/rejected |
| 4 | `failure_kind` 自由文本 | 失败率看板基数爆炸 | 改为 enum + 长度限制 |
| 5 | `submitted -> input-required` 被拒 | 必须在 ack 前伪造“已开始工作” | 允许该边，或明确产品语义 |
| 6 | 无真实多进程 8×100 / kill -9 测试 | M3 硬性 AC 未完全验证 | #4 前补 |
| 7 | 原子 rename 无 fsync | 掉电可能丢状态 | 加 `sync_all` + 父目录 sync |
| 8 | 锁粒度过大 / 全量 flush | #4/#5 高频操作瓶颈 | 先加指标；长期分片 |
| 9 | `ack` 绕过状态机 | 未来改边会静默分叉 | 内部走 transition helper |
| 10 | 同 org agent 级可见性未做 | 同 org 任意 agent 可读彼此任务 | Phase 0.5/Phase 1 |

---

## 5. Gate 决定

**有条件通过。**

- **#4 Task Board（只读）**：可以开始；board 只读 `tasks/list`/`tasks/get`，不依赖 CAS。
- **#5 Task-scoped lease**：建议先补 `revision`/CAS 与 operator 身份；否则 lease 的“任务终态自动失效”缺少可靠的版本原语。
- **#6/#7 consent/撤销传播**：依赖 #5 的 task-scoped lease，排在 #5 后。

---

## 6. 最可能的失败场景（更新后）

真实多进程 8×100 压测中，两个进程同时更新同一任务：
- 进程 A 读到 `working`，进程 B 读到 `working`；
- A 写 `completed`，B 写 `failed`；
- `flock` 串行化写，但后写者覆盖先写者（没有 CAS）；
- 最终状态取决于调度，审计 history 可能只保留一条。
这不是 lost update（写入没有丢），而是 **last-writer-wins 的业务冲突**。#5 的 lease 判定需要 CAS 或 `revision` 才能避免。

---

## 7. 验证记录

Conductor 在当前工作树执行：

```bash
cargo test -p aos-ipc          # 15 passed
cargo test -p aos-mcp-gateway  # 26 passed
cargo check --workspace        # Finished
```

Critic 首轮复审因环境限制未能运行测试；上述结果为 conductor 复核。
