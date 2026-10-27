class AegisOs < Formula
  desc "Multi-tenant Agent OS Runtime & Cloud PaaS with CoW VFS, Sandbox & IPC for AGY, Claude Code, and Codex"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.4.1"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.1/aegis-os-v0.4.1-aarch64-apple-darwin.tar.gz"
      sha256 "6463a9a99849f0c463ac83ad8461c2663ddaf987a39677423f0612ab1ec85728"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.1/aegis-os-v0.4.1-x86_64-apple-darwin.tar.gz"
      sha256 "d35c9a6b467a8a2e0d9adbfaf803ed9fd05614dba6ffea6479092b313c465be0"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.1/aegis-os-v0.4.1-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "fef0bb11c1f4895aa2c8e212e57a577788798ad4c06bb0bc0906eae9afdb3b24"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.1/aegis-os-v0.4.1-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "3a43a160e1e28bd3911ee36a4ecacb9640a7988e3814c5ec2c3ce6d0f85f4ee9"
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
