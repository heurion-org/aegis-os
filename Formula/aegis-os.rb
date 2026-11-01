class AegisOs < Formula
  desc "Multi-tenant Agent OS Runtime & Cloud PaaS with CoW VFS, Sandbox & IPC for AGY, Claude Code, and Codex"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.4.4"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.4/aegis-os-v0.4.4-aarch64-apple-darwin.tar.gz"
      sha256 "5f90ac0247f2979cc744b000fa601558a0906ede41fd058f3c4f43b5af355795"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.4/aegis-os-v0.4.4-x86_64-apple-darwin.tar.gz"
      sha256 "7f8c3c2621f6b70c9a6137cbcdbb5cbd3d422ea4027f4b506cef319a58fbdc9f"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.4/aegis-os-v0.4.4-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "00543f577c1a958a430219425f153db87d6bffd4f9ca96712ce0b901e468fa84"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.4/aegis-os-v0.4.4-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "8a18380f361c9d7a4602d222b39035feed028b9c6af1b7ab8fc581e672a051ed"
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

  def post_install
    # Automatically wire Aegis OS into Antigravity (`agy`), Claude Code (`claude`), and Codex (`codex`)
    # so users never need to run `aegis-os` manually from the terminal after `brew install`.
    system "#{bin}/aegis-os", "install"
  end

  def caveats
    <<~EOS
      Aegis OS has been automatically integrated into Antigravity (`agy`), Claude Code (`claude`), and Codex (`codex`).

      Zero-CLI Quickstart:
      - Simply launch `agy`, `claude`, or `codex` in ANY project directory (no need to run `aos` manually).
      - On first launch, your coding agent will automatically ask if you have an Aegis Cloud subscription:
        * With subscription: guides you to activate Zero-Local-Load Cloud Sandbox mode (`runtime_configure_mode(mode="cloud")`).
        * Without subscription: automatically activates Free Local CoW Sandbox mode (`runtime_configure_mode(mode="local")`).
    EOS
  end

  test do
    assert_match "aegis-os", shell_output("#{bin}/aegis-os --version")
    system "#{bin}/aegis-os", "install", "--home-dir", testpath, "--dry-run"
  end
end
