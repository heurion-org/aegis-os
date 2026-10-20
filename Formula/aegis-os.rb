class AegisOs < Formula
  desc "Multi-tenant Agent OS Runtime with CoW VFS, Sandbox & IPC for AGY, Claude Code, and Codex"
  homepage "https://github.com/heurion-org/aegis-os"
  url "https://github.com/heurion-org/aegis-os/archive/refs/tags/v0.2.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/aos-cli")
    # Install short alias `aos` alongside `aegis-os`
    bin.install_symlink "aegis-os" => "aos"
  end

  def caveats
    <<~EOS
      To enable Aegis OS out-of-the-box for AGY, Claude Code, and OpenAI Codex CLI, run:
        aegis-os install

      After running `aegis-os install` once:
      - Starting `agy`, `claude`, or `codex` in ANY project folder automatically attaches to Aegis OS.
      - All agents opened in the same project directory automatically join the same Aegis OS Organization
        and can collaborate via `ipc_list_peers`, `ipc_request`, `ipc_reply`, and `org_artifact_publish`.
      - All file edits happen in isolated Copy-on-Write shadow workspaces with ZERO authorization prompts.
    EOS
  end

  test do
    assert_match "aegis-os", shell_output("#{bin}/aegis-os --version")
    system "#{bin}/aegis-os", "install", "--home-dir", testpath, "--dry-run"
  end
end
