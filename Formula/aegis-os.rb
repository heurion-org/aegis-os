class AegisOs < Formula
  desc "Multi-tenant Agent OS Runtime & Cloud PaaS with CoW VFS, Sandbox & IPC for AGY, Claude Code, and Codex"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.7.1"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.7.1/aegis-os-v0.7.1-aarch64-apple-darwin.tar.gz"
      sha256 "24b22a271da530f03754b9bb927b32673cab75bca398d52c5c5889b129c58422"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.7.1/aegis-os-v0.7.1-x86_64-apple-darwin.tar.gz"
      sha256 "437dbba70c048e1c81e0f09dea05ead77f9fc65a6987d7585205bf5192dc30bb"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.7.1/aegis-os-v0.7.1-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "c124dbffb7567240cd119b84c8add779bfca709e047b6a11642320ef7a8f210b"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.7.1/aegis-os-v0.7.1-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "78dc8f4d20ca29c221cb2c40fa9019d4be06432ca9f717ac583204ab112dbed2"
    end
  end

  head do
    depends_on "rust" => :build
  end

  def install
    if File.exist?("aegis-os")
      bin.install "aegis-os"
    else
      system "cargo", "install", *std_cargo_args(path: "crates/aos-cli")
    end
    # Install short alias `aos` alongside `aegis-os`
    bin.install_symlink "aegis-os" => "aos"
  end

  def caveats
    <<~EOS
      Run this once to wire Aegis OS into Antigravity (`agy`), Claude Code (`claude`), and Codex (`codex`):
        aegis-os install

      Homebrew's post-install sandbox cannot update your home-directory client configs, so this step is explicit.

      Zero-CLI Quickstart:
      - Simply launch `agy`, `claude`, or `codex` in ANY project directory (starts silently in Free Local CoW Sandbox mode).
      - Boundary commits (`workspace_commit`) auto-open the `/approve` web console (or prompt in-terminal on headless SSH) and auto-resume.
      - Useful 1-line commands (`aos` is installed as a short alias for `aegis-os`):
        * Approve latest boundary escalation from terminal: `aos approve` (or `aos approve --web`)
        * Subscribe & mount 64GB Cloud Sandbox in 1 step: `aos cloud subscribe --plan pro --email you@company.com --wait`
        * Connect a first-party AAP-1.0 app in 1 step:    `aos app connect heurion`
    EOS
  end

  test do
    assert_match "aegis-os", shell_output("#{bin}/aegis-os --version")
    system "#{bin}/aegis-os", "install", "--home-dir", testpath, "--dry-run"
  end
end
