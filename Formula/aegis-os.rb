class AegisOs < Formula
  desc "Multi-tenant Agent OS Runtime & Cloud PaaS with CoW VFS, Sandbox & IPC for AGY, Claude Code, and Codex"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.4.2"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.2/aegis-os-v0.4.2-aarch64-apple-darwin.tar.gz"
      sha256 "8a5b7b1178aea56661ef988751d009303809116dbae9f500bc4c683a53f521c3"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.2/aegis-os-v0.4.2-x86_64-apple-darwin.tar.gz"
      sha256 "9f27aa5793c9d1d717c3e55d511c01f8ff51a0527b01e30eedc316f708384b79"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.2/aegis-os-v0.4.2-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "5162bd229bfc782ff831813f5843f098de9369261bc8ccf1571e5e4c19decc56"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.2/aegis-os-v0.4.2-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "78eaab68d7bc23ea13a3fa46810c437a52445ee6b039784f54bfc7272b9dc838"
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
