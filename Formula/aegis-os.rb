class AegisOs < Formula
  desc "Multi-tenant Agent OS Runtime & Cloud PaaS with CoW VFS, Sandbox & IPC for AGY, Claude Code, and Codex"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.10.0"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.10.0/aegis-os-v0.10.0-aarch64-apple-darwin.tar.gz"
      sha256 "ff96f6caaf2100f4561fa82514493cbcd131a4d4cc2e2470c2b7173fc9a5bc4b"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.10.0/aegis-os-v0.10.0-x86_64-apple-darwin.tar.gz"
      sha256 "dc5e4f1a58ee379a0ef92bd6f86108294c99123fb8933cc303927eeef83f97e8"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.10.0/aegis-os-v0.10.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "65b02ef6195607fe51fa223e58418f6873c75d8d9dec7091d7b58c89e4c1313e"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.10.0/aegis-os-v0.10.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "7c7de79733cf8b7a6d0837d6cb45608a2d0fa2ecdf6f27ff49214ca5eb92b39f"
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
