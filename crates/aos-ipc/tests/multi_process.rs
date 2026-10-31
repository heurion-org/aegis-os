//! Real multi-process stress test for the A2A IPC state file.
//!
//! The test binary re-executes itself as a child worker when `AOS_IPC_STRESS_STATE` is set.
//! Parent mode launches 8 OS processes x 100 tasks, then a kill -9 child to verify stale marking.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use aos_core::{A2ATaskState, IpcBus, IpcEnvelope, IpcKind, MessageDeliveryStatus};
use aos_ipc::AegisIpcBus;
use serde_json::json;

const ORG: &str = "stress";
const CHILD_TASKS: usize = 100;
const WORKERS: usize = 8;

fn envelope(from: &str, subject: String) -> IpcEnvelope {
    IpcEnvelope {
        msg_id: String::new(),
        org_id: ORG.to_string(),
        from_agent: from.to_string(),
        to_target: "collector".to_string(),
        kind: IpcKind::TaskRequest {
            timeout_secs: Some(60),
        },
        subject,
        payload: json!({}),
        attachments: vec![],
        status: MessageDeliveryStatus::Unread,
        created_at_ms: 0,
    }
}

fn run_child() -> anyhow::Result<()> {
    let state = PathBuf::from(std::env::var("AOS_IPC_STRESS_STATE")?);
    let mode = std::env::var("AOS_IPC_STRESS_MODE").unwrap_or_else(|_| "stress".to_string());
    let worker = std::env::var("AOS_IPC_STRESS_WORKER").unwrap_or_else(|_| "0".to_string());
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let bus = AegisIpcBus::with_state_file(Some(state));
        if mode == "kill9" {
            let task = bus
                .send(envelope("kill9-worker", "kill9-task".to_string()))
                .await?;
            bus.ack(ORG, "collector", &task.msg_id).await?;
            // Wait to be killed by the parent. The task is intentionally left in `working`.
            std::thread::sleep(Duration::from_secs(60));
            return Ok::<(), anyhow::Error>(());
        }
        if mode == "slow-write" {
            // The write hook sleeps between temp write and rename; the parent kills us there.
            bus.send(envelope("slow-writer", "slow-write-task".to_string()))
                .await?;
            return Ok::<(), anyhow::Error>(());
        }
        for i in 0..CHILD_TASKS {
            bus.send(envelope(
                &format!("worker-{worker}"),
                format!("task-{worker}-{i}"),
            ))
            .await?;
        }
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

fn spawn_child(
    state: &std::path::Path,
    mode: &str,
    worker: usize,
    extra_env: &[(&str, &str)],
) -> std::process::Child {
    let exe = std::env::current_exe().unwrap();
    let mut command = Command::new(exe);
    command
        .env("AOS_IPC_STRESS_STATE", state)
        .env("AOS_IPC_STRESS_MODE", mode)
        .env("AOS_IPC_STRESS_WORKER", worker.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in extra_env {
        command.env(key, value);
    }
    command.spawn().unwrap()
}

#[test]
fn multi_process_stress_and_kill9_recovery() {
    if std::env::var_os("AOS_IPC_STRESS_STATE").is_some() {
        if let Err(error) = run_child() {
            eprintln!("child failed: {error:#}");
            std::process::exit(1);
        }
        return;
    }

    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("ipc_state.json");
    let workers = std::env::var("AOS_IPC_STRESS_WORKERS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(WORKERS);

    // N OS processes x 100 tasks, all sharing one state file. Release CI uses a smaller
    // worker count on constrained runners; set AOS_IPC_STRESS_WORKERS=8 for the full stress.
    let mut children = Vec::new();
    for worker in 0..workers {
        children.push(spawn_child(&state, "stress", worker, &[]));
    }
    for (worker, child) in children.into_iter().enumerate() {
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "worker {worker} failed ({:?}): {}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let count = runtime.block_on(async {
        let bus = AegisIpcBus::with_state_file(Some(state.clone()));
        let tasks = bus.list_tasks(Some(ORG), None).await.unwrap();
        assert_eq!(
            tasks.len(),
            workers * CHILD_TASKS,
            "multi-process writers lost tasks"
        );
        let subjects: std::collections::HashSet<String> =
            tasks.iter().map(|task| task.subject.clone()).collect();
        assert_eq!(subjects.len(), workers * CHILD_TASKS);
        tasks.len()
    });
    assert_eq!(count, workers * CHILD_TASKS);

    // kill -9 a child that left a task in `working`; the task must become stale, not disappear.
    let mut kill_child = spawn_child(&state, "kill9", 0, &[]);
    let deadline = Instant::now() + Duration::from_secs(10);
    let task_id = loop {
        let found = runtime.block_on(async {
            let bus = AegisIpcBus::with_state_file(Some(state.clone()));
            bus.list_tasks(Some(ORG), None)
                .await
                .unwrap()
                .into_iter()
                .find(|task| task.subject == "kill9-task" && task.state == A2ATaskState::Working)
                .map(|task| task.id)
        });
        if let Some(id) = found {
            break id;
        }
        assert!(Instant::now() < deadline, "kill9 child never created a task");
        std::thread::sleep(Duration::from_millis(50));
    };
    kill_child.kill().unwrap();
    let _ = kill_child.wait();

    runtime.block_on(async {
        let bus = AegisIpcBus::with_state_file(Some(state.clone()));
        let marked = bus
            .sweep_stale_tasks(chrono::Utc::now().timestamp_millis() + 1_000, 0)
            .await
            .unwrap();
        assert!(marked >= 1);
        let task = bus.get_task(&task_id).await.unwrap().unwrap();
        assert_eq!(task.state, A2ATaskState::Working);
        assert!(task.stale, "killed worker task must be marked stale");
    });

    // kill -9 between temp write and rename: the old state must remain readable.
    runtime.block_on(async {
        let bus = AegisIpcBus::with_state_file(Some(state.clone()));
        bus.send(envelope("seed", "seed-task".to_string()))
            .await
            .unwrap();
    });
    let mut slow_child = spawn_child(
        &state,
        "slow-write",
        0,
        &[("AOS_IPC_WRITE_DELAY_MS", "5000")],
    );
    let tmp = state.with_extension("json.tmp");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !tmp.exists() {
        assert!(Instant::now() < deadline, "slow writer never created .tmp");
        std::thread::sleep(Duration::from_millis(20));
    }
    slow_child.kill().unwrap();
    let _ = slow_child.wait();
    runtime.block_on(async {
        let bus = AegisIpcBus::with_state_file(Some(state.clone()));
        let tasks = bus.list_tasks(Some(ORG), None).await.unwrap();
        assert!(tasks.iter().any(|task| task.subject == "seed-task"));
        assert!(!tasks.iter().any(|task| task.subject == "slow-write-task"));
    });
}
