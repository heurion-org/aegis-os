class AegisOs < Formula
  desc "Multi-tenant Agent OS Runtime & Cloud PaaS with CoW VFS, Sandbox & IPC for AGY, Claude Code, and Codex"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.8.0"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.8.0/aegis-os-v0.8.0-aarch64-apple-darwin.tar.gz"
      sha256 "1ace4c0ddbd7b0469d93ec0e060a0e395772e1f98cb977672de43f8ddf080c59"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.8.0/aegis-os-v0.8.0-x86_64-apple-darwin.tar.gz"
      sha256 "920d6ed0b4ec251c50581c5a5e97fc06797c123bbd65ba610078d158d5260399"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.8.0/aegis-os-v0.8.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "1fe3b4777d49780f1b94e54836e021ec53f7836bdf523323bbb6cd4756c8f510"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.8.0/aegis-os-v0.8.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "d5175243d7ae1d35c7b30448e6fde378d0225a9920aeb00497dca00b9d6f6e41"
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
