class AegisOs < Formula
  desc "Kernel-enforced sandbox, CoW shadow workspace, and MCP firewall for Claude Code, Codex, OpenCode, Hermes, and AGY"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.12.0"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.12.0/aegis-os-v0.12.0-aarch64-apple-darwin.tar.gz"
      sha256 "3b523e3c6821c0fb4a5e451d856984a6bfc352b75f6cee7573471d45ae1bac2c"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.12.0/aegis-os-v0.12.0-x86_64-apple-darwin.tar.gz"
      sha256 "a8ae58ffd57062b503c0d71d4bcb0876ff82a371d6dcce550ee540b39b4cc8d6"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.12.0/aegis-os-v0.12.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "dc2296fcc1ed0058665b7509fd8523ef92443320e4c8db3b0de782c815bd9d7c"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.12.0/aegis-os-v0.12.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "cdc703aa6df80ee86d437c5185f3edcb2bd07df98d363d17c6647d5daf38a378"
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
