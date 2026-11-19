class AegisOs < Formula
  desc "Multi-tenant Agent OS Runtime & Cloud PaaS with CoW VFS, Sandbox & IPC for AGY, Claude Code, and Codex"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.7.0"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.7.0/aegis-os-v0.7.0-aarch64-apple-darwin.tar.gz"
      sha256 "3fcf620fd7f66f1ba90c152d89eaf70fa525a7975d4c8021c31520e5d2951286"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.7.0/aegis-os-v0.7.0-x86_64-apple-darwin.tar.gz"
      sha256 "6056edfdad9d6f1b1112a3760ea3111acc7f9324945b615a52f7a033da271fc5"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.7.0/aegis-os-v0.7.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "4e1580fbb35f2024a27ffd987adad02c27124b891d57ef91aff3850e8e9694d0"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.7.0/aegis-os-v0.7.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "93d7d9acca825a5d3c2109b79f12a1cb0f628b44898e0f645b226027ac1c0658"
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
