class AegisOs < Formula
  desc "Multi-tenant Agent OS Runtime & Cloud PaaS with CoW VFS, Sandbox & IPC for AGY, Claude Code, and Codex"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.9.3"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.9.3/aegis-os-v0.9.3-aarch64-apple-darwin.tar.gz"
      sha256 "8a157af2d2bdac16b7978884792614731cb162322c4fb1a5a4ee30f7bb248c26"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.9.3/aegis-os-v0.9.3-x86_64-apple-darwin.tar.gz"
      sha256 "ed24b35c8c077f9a65a6b28bfced7ba62c49de0e02152cb7d4945a099ab2e254"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.9.3/aegis-os-v0.9.3-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "a041c30abdba0845d9b75eb811e7c34ad0c35b698b13807d977c3e53be49cde5"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.9.3/aegis-os-v0.9.3-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "b98cf8ccf544539d7fd50951ab7cf99264cb04b961aa1b9873b8052d3ca6ac34"
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
