class AegisOs < Formula
  desc "Multi-tenant Agent OS Runtime & Cloud PaaS with CoW VFS, Sandbox & IPC for AGY, Claude Code, and Codex"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.4.3"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.3/aegis-os-v0.4.3-aarch64-apple-darwin.tar.gz"
      sha256 "4692666a171351e7cbf4f1d11b81076d9c67355d145d2cf0f5ff325d2eb8c3ac"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.3/aegis-os-v0.4.3-x86_64-apple-darwin.tar.gz"
      sha256 "a1d9bf8e9f8384217617c1f38ba6cd53d20c2077155d301177703929fecb3be8"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.3/aegis-os-v0.4.3-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "c13f90bc7cd0632cad5e5b199154308a2d85ad2a685a655a1d64a12d3d1c07ad"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.3/aegis-os-v0.4.3-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "329a2986b0f0fc55fe40a3dd578a79f57b60b75f52ddd9b130b04abe8f27ec2b"
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
