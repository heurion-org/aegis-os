//! Shared Ring-0, credential store, protected client config, and runtime state path markers.
//!
//! All path matching normalizes Windows separators (`\\` -> `/`) and ASCII-lowercases candidates
//! so case-insensitive filesystems (macOS APFS, Windows NTFS) cannot bypass Ring-0 guards via
//! mixed-case paths such as `~/.SSH/id_rsa` or `/.GEMINI/config/hooks.json`.

/// Normalize separators and ASCII case for Ring-0 marker comparisons.
pub fn normalize_for_match(input: &str) -> String {
    input.replace('\\', "/").to_ascii_lowercase()
}

pub const CREDENTIAL_MARKERS: &[&str] = &[
    "/.ssh",
    "~/.ssh",
    "/.aws",
    "~/.aws",
    "/.gnupg",
    "~/.gnupg",
    "/.kube",
    "~/.kube",
    "/.docker",
    "/.azure",
    "/.config/gcloud",
    "/.config/aegis-os",
    "/.config/gh/",
    "/master.kek",
    "/.master.kek",
    "/.ephemeral.kek",
    "/library/keychains",
    "/.git-credentials",
    "/.netrc",
    "/.npmrc",
    "/.pypirc",
    "/.vault-token",
    "/.cargo/credentials",
    "/custom_vault",
    "/.secrets",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/master.passwd",
    "/oauth_creds.json",
    "/.credentials.json",
    "/.codex/auth.json",
    "/.hermes/auth.json",
    "/opencode/auth.json",
    "/plugins_secrets.json",
    "/.orbstack/",
    "/.colima/",
    "/.lima/",
];

pub const PROTECTED_CLIENT_CONFIG_MARKERS: &[&str] = &[
    "/.gemini/config/hooks.json",
    "/.gemini/config/mcp_config.json",
    "/.gemini/settings.json",
    "/.gemini/antigravity-cli/settings.json",
    "/.claude/settings.json",
    "/.claude/settings.local.json",
    "/.claude/hooks",
    "/.claude.json",
    "/.mcp.json",
    "/.codex/config.toml",
    "/.codex/hooks",
    "/opencode.json",
    "/opencode.jsonc",
    "/.config/opencode/opencode.json",
    "/.config/opencode/opencode.jsonc",
    "/.cursor/mcp.json",
    "/.vscode/mcp.json",
    "/.hermes/config.yaml",
    "/.agents/hooks.json",
    "/.agent/hooks.json",
    "/.aegis-bin",
    "/.git/hooks/",
    "/.git/config",
    "/.bashrc",
    "/.zshrc",
    "/.profile",
    "/.zprofile",
];

pub const RUNTIME_STATE_MARKERS: &[&str] = &[
    "/aegis-os-runtime/policy.json",
    "/aegis-os-runtime/paas_state.json",
    "/aegis-os-runtime/ipc_state.json",
    "/aegis-os-runtime/hook_commit_tickets.json",
    "/aegis-os-runtime/session_bindings.json",
    "/aegis-os-runtime/active_workspace.txt",
    "/aegis-os-runtime/audit.jsonl",
    "/aegis-os-runtime/routing_decisions.jsonl",
    "/aegis-os-runtime/stop_budgets.json",
    "/human.token",
    "/agent.token",
    "/approval.json",
    "/advisory.jsonl",
    "/pending_escalations.jsonl",
    "/effects.jsonl",
    "/policy_state.json",
    "/dek.envelope.json",
    ".dek.enc.json",
    ".sparsebundle",
    ".luks.img",
    ".gocryptfs",
    "/aegis-broker.json",
    "/mcp_auth_realms.json",
    "/mcp_firewall_state.json",
    "/mcp_bundles.json",
    "/session_taints.json",
];

fn contains_any_marker(input: &str, markers: &[&str]) -> bool {
    let norm = normalize_for_match(input);
    markers.iter().any(|m| norm.contains(m))
}

pub fn contains_credential_marker(input: &str) -> bool {
    contains_any_marker(input, CREDENTIAL_MARKERS)
}

pub fn contains_protected_client_config_marker(input: &str) -> bool {
    contains_any_marker(input, PROTECTED_CLIENT_CONFIG_MARKERS)
}

pub fn contains_runtime_state_marker(input: &str) -> bool {
    contains_any_marker(input, RUNTIME_STATE_MARKERS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring0_markers_match_case_insensitively_across_separators() {
        assert!(contains_credential_marker("~/.SSH/id_rsa"));
        assert!(contains_credential_marker("/Users/alice/.AWS/credentials"));
        assert!(contains_credential_marker("/Library/KEYCHAINS/login.keychain-db"));
        assert!(contains_credential_marker(r"C:\Users\alice\.ssh\id_ed25519"));

        assert!(contains_protected_client_config_marker(
            "/Users/alice/.GEMINI/config/hooks.json"
        ));
        assert!(contains_protected_client_config_marker(
            "/Users/alice/.CLAUDE/Settings.json"
        ));
        assert!(contains_runtime_state_marker(
            "/Users/alice/.aegis/sessions/ses_1/HUMAN.TOKEN"
        ));
        assert!(contains_runtime_state_marker(
            "/tmp/AEGIS-OS-RUNTIME/policy.json"
        ));

        assert!(!contains_credential_marker("/Users/alice/repo/src/main.rs"));
        assert!(!contains_protected_client_config_marker(
            "/Users/alice/.gemini/antigravity-cli/brain/123/notes.md"
        ));
    }
}
