# Review — Builder-07（真实多进程 + kill -9）

日期：2026-10-31
审查者：Conductor 复核
上游：`builder-07.md`
状态：**通过**

---

## 1. 结论

真实多进程测试已落地并通过：

- 8 个 OS 进程 × 100 个 A2A task
- 800 个 task 全部存在且 subject 唯一
- kill -9 后 task 保持 `working` 并被标记 `stale`
- 连续 3 次运行稳定，约 21.3s/次

压测还发现并修复了一个真实问题：

> 5s 的 `flock` deadline 在 8 进程 × 100 任务下不够，多个 worker 超时。已提升到 30s。

---

## 2. 证据

```bash
cargo test -p aos-ipc --test multi_process -- --nocapture
# 1 passed; 0 failed; finished in ~21.3s

run 1: 1 passed (21.33s)
run 2: 1 passed (21.39s)
run 3: 1 passed (21.37s)
```

其他测试：

```bash
cargo test -p aos-ipc             # 17 passed
cargo test -p aos-mcp-gateway     # 27 passed
cargo test -p aos-memory-server   # 2 passed
cargo check --workspace           # Finished
```

---

## 3. P0 / P1

无新增 P0/P1。

---

## 4. P2

1. 已覆盖写事务中途 kill -9：旧 state 可读、新 task 未落盘；`.tmp` 残留不参与加载。
2. `AOS_IPC_WRITE_DELAY_MS` 是 debug-only 测试钩子；release 忽略。
3. 测试 ~21s，默认 `cargo test -p aos-ipc` 会跑；如果 CI 时间敏感，可标 `#[ignore]` 并放到 release gate。
4. 没有磁盘满/权限错误模拟。
5. 没有真实多机/远程 A2A 压测。

---

## 5. Gate 决定

**通过。** Phase 0 的 #1–#7 代码链路 + 真实多进程测试已完成。

建议：

1. 保留 multi_process 测试默认运行，或标 `#[ignore]` 作为 release gate。
2. 补一个“写事务中途 kill -9”测试作为后续。
3. commit / push。

---

## 6. 最可能的失败场景

如果未来把 `ipc_state.json` 放到 NFS/overlayfs，`flock` 语义可能不同；8 进程测试只覆盖本地文件系统。生产部署必须把 runtime 目录放在本地磁盘。
