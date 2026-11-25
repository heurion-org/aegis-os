class AegisOs < Formula
  desc "Kernel-enforced sandbox, CoW shadow workspace, and MCP firewall for Claude Code, Codex, OpenCode, Hermes, and AGY"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.12.2"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.12.2/aegis-os-v0.12.2-aarch64-apple-darwin.tar.gz"
      sha256 "32ce0b5ad057b72efa712c8a32eab36d804b2c1b2cc964ce1d0b2aced1af1a41"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.12.2/aegis-os-v0.12.2-x86_64-apple-darwin.tar.gz"
      sha256 "ab25024b95bddcc50eabcf6f42f67c05aca2ee38f87d2f8998045870199ae0cc"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.12.2/aegis-os-v0.12.2-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "1cfd594bb8940202588d236b442ad9a96c9b7854aebe9b332e3883e58700e2a9"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.12.2/aegis-os-v0.12.2-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "abce853b3e09a347ffe31e9e439d2de3cfe0b7d84218f93dcaf63246351ad659"
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
