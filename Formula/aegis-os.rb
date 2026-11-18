class AegisOs < Formula
  desc "Multi-tenant Agent OS Runtime & Cloud PaaS with CoW VFS, Sandbox & IPC for AGY, Claude Code, and Codex"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.4.10"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.10/aegis-os-v0.4.10-aarch64-apple-darwin.tar.gz"
      sha256 "222d2fd509624dda080a0f47102a36a905af6a1a9e25179bda989d764955f2cc"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.10/aegis-os-v0.4.10-x86_64-apple-darwin.tar.gz"
      sha256 "2b3d3c9475d6bfb6e287b301ea46beb910ebe0c89b2c3f2fd03bfe0a801d0600"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.10/aegis-os-v0.4.10-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "ed2e061bc3e0b3fcdf2d2c37836cff69ba04e2f4a0319eda1f51102f9592b894"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.10/aegis-os-v0.4.10-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "a48778607ad081fb75047c6adf7513e1281688589fcf7090bfd8ed8ad1373fac"
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
