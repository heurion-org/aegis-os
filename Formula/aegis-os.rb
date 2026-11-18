class AegisOs < Formula
  desc "Multi-tenant Agent OS Runtime & Cloud PaaS with CoW VFS, Sandbox & IPC for AGY, Claude Code, and Codex"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.4.11"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.11/aegis-os-v0.4.11-aarch64-apple-darwin.tar.gz"
      sha256 "4acd8c1ac2843b67a1f47e5ab63da9d696ebf8a3070dd766652e805eac64768f"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.11/aegis-os-v0.4.11-x86_64-apple-darwin.tar.gz"
      sha256 "cccde16f5aae2b11e0c59e17a3b7e6d86cb7c2d22176ba72a37b217321e7385f"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.11/aegis-os-v0.4.11-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "50f3312cce58898ccad0a2682627e8d4c4292595075768db9778529445db6a4a"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.11/aegis-os-v0.4.11-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "1f50d6c8a5c45f627bfaffe1d610351c24893047c2ba19320210b9f7f7fb5d8e"
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
