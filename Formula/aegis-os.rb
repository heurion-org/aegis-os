class AegisOs < Formula
  desc "Multi-tenant Agent OS Runtime & Cloud PaaS with CoW VFS, Sandbox & IPC for AGY, Claude Code, and Codex"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.4.6"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.6/aegis-os-v0.4.6-aarch64-apple-darwin.tar.gz"
      sha256 "313c96143d3240d9e18497581f1d48c4c63ec60f9a22e2d07dbfd2e9fc15b0ae"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.6/aegis-os-v0.4.6-x86_64-apple-darwin.tar.gz"
      sha256 "3cf0433cbcec736d87350175c46b579e31519df6033a62f4e4089c9ec6b3b90b"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.6/aegis-os-v0.4.6-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "c9afd635de2207b4dbeed8b8ac3cbb640cd278c90e82314ad35961f198b387c3"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.6/aegis-os-v0.4.6-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "0cd020b8d567fde9600170c9a565385624cb053e93fef1be0ba134cd9bd65509"
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
