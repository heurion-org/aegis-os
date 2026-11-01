class AegisOs < Formula
  desc "Multi-tenant Agent OS Runtime & Cloud PaaS with CoW VFS, Sandbox & IPC for AGY, Claude Code, and Codex"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.4.5"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.5/aegis-os-v0.4.5-aarch64-apple-darwin.tar.gz"
      sha256 "3a07ff1d0f1773917ae75a4806ddf47969c4f934cc2317c27e92ff9687adddfe"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.5/aegis-os-v0.4.5-x86_64-apple-darwin.tar.gz"
      sha256 "c6aeb6305236c4a5f62038e3f82c5c9193e8b98c5d29671d4aed2c6d6d955b14"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.5/aegis-os-v0.4.5-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "4ead8a6379f3a6d9657c1425688e12d13cb48229e6013c35b81238738d70b590"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.4.5/aegis-os-v0.4.5-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "3c8504734293276ccf7b5685bb7fd11fb8de07899edbe80ae7a2675b076fb4fa"
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

      After that, simply launch `agy`, `claude`, or `codex` in ANY project directory:
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
