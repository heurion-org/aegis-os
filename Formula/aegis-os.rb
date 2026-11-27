class AegisOs < Formula
  desc "Kernel-enforced sandbox, CoW shadow workspace, and MCP firewall for Claude Code, Codex, OpenCode, Hermes, and AGY"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.13.1"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.13.1/aegis-os-v0.13.1-aarch64-apple-darwin.tar.gz"
      sha256 "c1bc98dbd966c6d91e4b788c3533d0029f337d5a2b1f74a31e81781a5d4a434b"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.13.1/aegis-os-v0.13.1-x86_64-apple-darwin.tar.gz"
      sha256 "e50b761f42416f29f80b7a1f94b169b197b389e8f979996928b5951adc5198f0"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.13.1/aegis-os-v0.13.1-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "3d61a1e4c65cec1266002b4dc256af672038f505838c3f30b454869aa9c2e7f0"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.13.1/aegis-os-v0.13.1-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "d041d7579597c5cc6993bf5d7df41c79735d234a2b403f9a2af35ae60d6c273f"
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
      Quickstart (`aos` is installed as a short alias for `aegis-os`):

      1. Run a 5-second local exposure & prompt-fatigue audit:
           aegis-os audit-me

      2. Launch any coding agent inside the kernel-enforced CoW sandbox:
           aegis-os run -- claude          # or: codex / opencode / agy / hermes
           aegis-os diff                   # inspect shadow changes (--json supported)
           aegis-os commit                 # SHA-256 TOCTOU-pinned promotion to host

      3. Optional: wire transparent shims & advisory integrations:
           aegis-os install --enforce      # create ~/.aegis/bin shims
           aegis-os install                # advisory hooks / MCP / rules only
    EOS
  end

  test do
    assert_match "aegis-os", shell_output("#{bin}/aegis-os --version")
    system "#{bin}/aegis-os", "install", "--home-dir", testpath, "--dry-run"
  end
end
