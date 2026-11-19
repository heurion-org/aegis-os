class AegisOs < Formula
  desc "Multi-tenant Agent OS Runtime & Cloud PaaS with CoW VFS, Sandbox & IPC for AGY, Claude Code, and Codex"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.5.0"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.5.0/aegis-os-v0.5.0-aarch64-apple-darwin.tar.gz"
      sha256 "d75f34dcd566ce8cdc31b0786037df38bd0111e3d7ff98736d7b798d038ed2f9"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.5.0/aegis-os-v0.5.0-x86_64-apple-darwin.tar.gz"
      sha256 "3d37ae5b3a774517804ba075162a9fcfdab5bd8fc192fec69a80400a131d5768"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.5.0/aegis-os-v0.5.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "5477f3859233013a368c2c9e0b08e7dbb9aed7a3003e1d11f60fbf91e606ce41"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.5.0/aegis-os-v0.5.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "ea06fe6b959a6fc80c811d352324d6cc64ee1eb4a75d585ebabadff24ea317ae"
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
