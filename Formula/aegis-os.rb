class AegisOs < Formula
  desc "Kernel-enforced sandbox, CoW shadow workspace, and MCP firewall for Claude Code, Codex, OpenCode, Hermes, and AGY"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.10.0"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.10.0/aegis-os-v0.10.0-aarch64-apple-darwin.tar.gz"
      sha256 "ff96f6caaf2100f4561fa82514493cbcd131a4d4cc2e2470c2b7173fc9a5bc4b"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.10.0/aegis-os-v0.10.0-x86_64-apple-darwin.tar.gz"
      sha256 "dc5e4f1a58ee379a0ef92bd6f86108294c99123fb8933cc303927eeef83f97e8"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.10.0/aegis-os-v0.10.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "65b02ef6195607fe51fa223e58418f6873c75d8d9dec7091d7b58c89e4c1313e"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.10.0/aegis-os-v0.10.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "7c7de79733cf8b7a6d0837d6cb45608a2d0fa2ecdf6f27ff49214ca5eb92b39f"
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
