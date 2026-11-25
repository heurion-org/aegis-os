class AegisOs < Formula
  desc "Kernel-enforced sandbox, CoW shadow workspace, and MCP firewall for Claude Code, Codex, OpenCode, Hermes, and AGY"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.12.1"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.12.1/aegis-os-v0.12.1-aarch64-apple-darwin.tar.gz"
      sha256 "25e81898414c180e01c739c2e3fb1fadd4fc55ca634061e2b19e1d8cb9fab421"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.12.1/aegis-os-v0.12.1-x86_64-apple-darwin.tar.gz"
      sha256 "24f4ba79aa3125c68ef222f9162fe8250fd539c10979b2df7da27210b5323ae9"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.12.1/aegis-os-v0.12.1-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "b390f9ee48b1422dc4e2696a8bcc872fe423fb40e67666cac3ae888c9379d762"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.12.1/aegis-os-v0.12.1-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "cef4e044369ac6e393c60f371563eae63507cdcb0087be19b4308cbd464a4b2b"
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
