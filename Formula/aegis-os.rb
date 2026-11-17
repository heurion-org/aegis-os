class AegisOs < Formula
  desc "Multi-tenant Agent OS Runtime & Cloud PaaS with CoW VFS, Sandbox & IPC for AGY, Claude Code, and Codex"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.4.8"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.8/aegis-os-v0.4.8-aarch64-apple-darwin.tar.gz"
      sha256 "5f108cbb2ede04090b813a8dc38b04717d91ab34a3dedfa5c86604e148af4d88"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.8/aegis-os-v0.4.8-x86_64-apple-darwin.tar.gz"
      sha256 "b0f75af8b1465b6a7db664cea72e8cf2d4f4c308bc377d2a7315a5293048401a"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.8/aegis-os-v0.4.8-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "52e584d7333d7952afbcae5d307ae98036422b3120a622edb300efbc5a604804"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.8/aegis-os-v0.4.8-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "81bd76de03c585b707172b66f1d6b6af7548cea0c7ff4fc6dd2bc33eb1320c68"
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
