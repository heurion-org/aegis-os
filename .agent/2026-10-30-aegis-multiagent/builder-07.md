# Builder-07 — 真实多进程 A2A 压测 + kill -9

日期：2026-10-31
范围：review-builder-06 的 P1-1（真实 8 进程 × 100 任务 / kill -9）
状态：完成，测试稳定通过，未 commit / push

## 1. 测试实现

新增：

```text
crates/aos-ipc/tests/multi_process.rs
```

测试二进制通过 `current_exe()` 重新执行自己：

- Parent 模式：
  - 启动 8 个 OS 进程
  - 每个进程写 100 个 A2A task 到同一个 `ipc_state.json`
  - 汇总后断言 800 个 task、800 个唯一 subject
- Child 模式（`AOS_IPC_STRESS_STATE` 存在时）：
  - `stress`：100 次 `send`
  - `kill9`：发送一个 task、ack 到 `working`、sleep 60s 等父进程 kill

kill -9 验证：

1. 父进程轮询直到 task 进入 `working`
2. `Child::kill()`（SIGKILL）
3. `sweep_stale_tasks(now+1s, threshold=0)`
4. 断言 task 仍是 `working`，但 `stale=true`

写事务中途 kill：

1. `flush_to_disk` 在 debug build 中支持 `AOS_IPC_WRITE_DELAY_MS`（temp write 与 rename 之间）
2. 父进程等待 `ipc_state.json.tmp` 出现
3. SIGKILL
4. 重新打开 state file，断言旧 task 仍在、新 task 不在、JSON 可解析

## 2. 压测发现

首次 8 进程 × 100 任务时，多个 worker 在 5s `flock` deadline 内超时：

```text
child failed: timed out waiting for IPC state lock ... Resource temporarily unavailable
```

说明全量 JSON 重写 + 8 进程争用下，5s 太短。

修复：

- `state_lock` deadline 从 **5s → 30s**
- 仍保留 `LOCK_NB` + 20ms 退避，避免永久阻塞

## 3. 结果

```bash
cargo test -p aos-ipc --test multi_process -- --nocapture
# 1 passed; 0 failed; finished in ~21.3s
```

连续运行：

```text
run 1: 1 passed (22.26s)
run 2: 1 passed (21.94s)
run 3: 1 passed (22.05s)
```

其他测试：

```bash
cargo test -p aos-ipc             # 17 passed
cargo test -p aos-mcp-gateway     # 27 passed
cargo test -p aos-memory-server   # 2 passed
cargo check --workspace           # Finished
```

## 4. 风险 / 未完成

1. **`AOS_IPC_WRITE_DELAY_MS` 是 debug-only 测试钩子**：release build 忽略；不要在生产环境依赖。
2. **没有模拟磁盘满 / 权限错误**。
3. **30s deadline 是经验值**：800 任务/8 进程通过；更大规模需重新压测。
4. **测试耗时 ~22s**：默认 `cargo test -p aos-ipc` 会跑它，CI 时间会增加；如需可标 `#[ignore]` 单独跑。
5. **未 commit / push**。

## 5. 下一步

1. 增加“写事务中途 kill -9”测试（检查 `.tmp` 残留与旧状态可读）。
2. 决定是否把 multi_process 测试设为 `#[ignore]`（release gate 单独跑）。
3. 统一 commit / push。
