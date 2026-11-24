class AegisOs < Formula
  desc "Multi-tenant Agent OS Runtime & Cloud PaaS with CoW VFS, Sandbox & IPC for AGY, Claude Code, and Codex"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.11.0"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.11.0/aegis-os-v0.11.0-aarch64-apple-darwin.tar.gz"
      sha256 "e8ab75e5a06a4cfa0400029ca16837f2c84cc2de32ba6e0f8c330c1d74fbc56d"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.11.0/aegis-os-v0.11.0-x86_64-apple-darwin.tar.gz"
      sha256 "6f2c62b2921087488a846eff6e4181e0f52922b8eeed6735234f6ce64c4b7df8"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.11.0/aegis-os-v0.11.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "56f0cd80c9949cb9298d9449bfa94736e02a0651888e839e953cd1dec60a4777"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.11.0/aegis-os-v0.11.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "a2633c10cf5a63d137c2bba429e33a1b58e080882e059be3de5b0896a9d1bc06"
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
