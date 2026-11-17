class AegisOs < Formula
  desc "Multi-tenant Agent OS Runtime & Cloud PaaS with CoW VFS, Sandbox & IPC for AGY, Claude Code, and Codex"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.4.7"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.7/aegis-os-v0.4.7-aarch64-apple-darwin.tar.gz"
      sha256 "f56d39d3b5be1ecc909184e072b3296b543f41e01abcc16cfb421e0eb8a19de9"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.7/aegis-os-v0.4.7-x86_64-apple-darwin.tar.gz"
      sha256 "70b8b4df7b5f36d78ad128a35e7cf0f4945ccec665ff23ea09840b44a5a27be4"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.7/aegis-os-v0.4.7-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "d96e742dc7756ff2b7af2e3069c54f700d5e9a94e0ef7fa24536e4b8fdf2017b"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.7/aegis-os-v0.4.7-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "c3005d421ca107b6fd179c794b106d1f77758a894e5018abf5f2f196d94fb84b"
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
