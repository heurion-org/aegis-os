class AegisOs < Formula
  desc "Multi-tenant Agent OS Runtime & Cloud PaaS with CoW VFS, Sandbox & IPC for AGY, Claude Code, and Codex"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.9.1"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.9.1/aegis-os-v0.9.1-aarch64-apple-darwin.tar.gz"
      sha256 "c0351f18f07f7139792aec0f3b194c184fc446501006f103648228bda2630feb"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.9.1/aegis-os-v0.9.1-x86_64-apple-darwin.tar.gz"
      sha256 "6e94e9b3a62f570a1a6768b021ecfadff402144c54dd0860de40f9b1b9d5fffa"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.9.1/aegis-os-v0.9.1-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "0ad6fe6e2c72331bea9b6fac40f3cae4e7955dbccd3ec9220b4ce7f3e1b238ce"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.9.1/aegis-os-v0.9.1-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "cf770db4c9ed3e80515f3afcb120ed6032f888e2d196dc951c91998fc1bf7966"
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
