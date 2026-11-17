class AegisOs < Formula
  desc "Multi-tenant Agent OS Runtime & Cloud PaaS with CoW VFS, Sandbox & IPC for AGY, Claude Code, and Codex"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.4.9"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.9/aegis-os-v0.4.9-aarch64-apple-darwin.tar.gz"
      sha256 "00a312d22d4a1e6846b1f3a1e104277b97727c64aba31ba658813741a9673e67"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.9/aegis-os-v0.4.9-x86_64-apple-darwin.tar.gz"
      sha256 "c009a0209506d91df3f667ac48a317911eb6ca00a1ebc7f1d2f86f13feef0671"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.9/aegis-os-v0.4.9-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "8fd31cc5dcda95b4c2f60271295a3909beda2dbfe03d9cfd7d370ed1f04d8864"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.9/aegis-os-v0.4.9-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "732ba769b077512ab5d3f841ddfea1ce5b95c2f878334cd136731553cddd4279"
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
