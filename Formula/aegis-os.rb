class AegisOs < Formula
  desc "Multi-tenant Agent OS Runtime & Cloud PaaS with CoW VFS, Sandbox & IPC for AGY, Claude Code, and Codex"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.9.2"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.9.2/aegis-os-v0.9.2-aarch64-apple-darwin.tar.gz"
      sha256 "d589de19ecb54a17ee6c1792654a2c7533710bedd739f8f67e04356cbe9df84e"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.9.2/aegis-os-v0.9.2-x86_64-apple-darwin.tar.gz"
      sha256 "64c2bb4840cc90d838b38651a783019eae633bd00278c14c60209c4592230dd1"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.9.2/aegis-os-v0.9.2-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "14125d5e9301ae303bcedbe97c788a2256a2cbf60b77115990436c2a1214490a"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.9.2/aegis-os-v0.9.2-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "0b5354bc1fa2380d2bcd1fd641749f8c7cb30c1f3479107a8deb4a9375339e8b"
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
