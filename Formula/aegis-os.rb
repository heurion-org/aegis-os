class AegisOs < Formula
  desc "Multi-tenant Agent OS Runtime & Cloud PaaS with CoW VFS, Sandbox & IPC for AGY, Claude Code, and Codex"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.4.0"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.0/aegis-os-v0.4.0-aarch64-apple-darwin.tar.gz"
      sha256 "17193b5a3f95030a260918dcf475db9d92f93583b7bbbe4e741d24f49f5d2c43"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.0/aegis-os-v0.4.0-x86_64-apple-darwin.tar.gz"
      sha256 "89bed702fe632308db34ee3bda394bf32c1ed0b4588d6dde670f30a91bcf9f8c"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.0/aegis-os-v0.4.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "d2a5dcf735005cde7bb7de2a376b710130c8fa11b665a8ff4d52766d1e7ef0cb"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.0/aegis-os-v0.4.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "22a1c7137c77d79c5f90a19182646d0c9653800af031a2986b4adf7e8d821d97"
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
