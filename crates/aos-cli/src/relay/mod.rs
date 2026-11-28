pub mod client;
pub mod device;
pub mod handoff;
pub mod host;
#[cfg(test)]
mod tests;

use crate::cli_args::{DeviceAction, HandoffAction};
use anyhow::Result;
use aos_core::AgentIdentity;
use std::path::Path;

pub(crate) async fn handle_devices_command(
    action: DeviceAction,
    runtime_dir: &Path,
    identity: &AgentIdentity,
) -> Result<()> {
    match action {
        DeviceAction::Pair {
            name,
            ttl_secs,
            no_wait,
        } => {
            device::cmd_devices_pair(runtime_dir, identity, name.as_deref(), ttl_secs, !no_wait)
                .await
        }
        DeviceAction::Join { pair_code, name } => {
            device::cmd_devices_join(runtime_dir, &pair_code, name.as_deref()).await
        }
        DeviceAction::List { json } => device::cmd_devices_list(runtime_dir, json).await,
        DeviceAction::Revoke { device_id } => {
            device::cmd_devices_revoke(runtime_dir, &device_id).await
        }
    }
}

pub(crate) async fn handle_handoff_command(
    action: HandoffAction,
    runtime_dir: &Path,
    workspace: &Path,
    identity: &AgentIdentity,
) -> Result<()> {
    match action {
        HandoffAction::Push {
            session_id,
            note,
            pin,
        } => {
            handoff::cmd_handoff_push(
                runtime_dir,
                workspace,
                &identity.agent_id,
                session_id.as_deref(),
                note.as_deref(),
                pin,
            )
            .await
        }
        HandoffAction::Pull {
            session_id,
            apply,
            dir,
        } => handoff::cmd_handoff_pull(runtime_dir, workspace, &session_id, apply, dir.as_deref())
            .await,
        HandoffAction::List { json } => handoff::cmd_handoff_list(runtime_dir, json).await,
        HandoffAction::Rm { handoff_id } => {
            handoff::cmd_handoff_rm(runtime_dir, &handoff_id).await
        }
    }
}
