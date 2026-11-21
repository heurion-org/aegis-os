class AegisOs < Formula
  desc "Multi-tenant Agent OS Runtime & Cloud PaaS with CoW VFS, Sandbox & IPC for AGY, Claude Code, and Codex"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.9.0"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.9.0/aegis-os-v0.9.0-aarch64-apple-darwin.tar.gz"
      sha256 "3b90c3c1c32aa7aa4a2bc16cf8c7a43e228b54e16c902d2a6c56a27c127037eb"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.9.0/aegis-os-v0.9.0-x86_64-apple-darwin.tar.gz"
      sha256 "e25063d9004935de2c3b485f486ea8c513e26f15ebc3bd4c012b8cde35280d1c"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.9.0/aegis-os-v0.9.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "23fae084453c37811587a3098c5c98915180b3a802a91683e7e9438e84b8f1ca"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.9.0/aegis-os-v0.9.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "1009f59b09f2fd8cf05ee446f37e64fec1af9b1e47e4b04a9f1f46e1750c7e1e"
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
