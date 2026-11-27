class AegisOs < Formula
  desc "Kernel-enforced sandbox, CoW shadow workspace, and MCP firewall for Claude Code, Codex, OpenCode, Hermes, and AGY"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.13.2"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.13.2/aegis-os-v0.13.2-aarch64-apple-darwin.tar.gz"
      sha256 "4b9d68956f651e5fc2fce6aa88fa9156d40614c7a708502be7911ddff2f529a1"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.13.2/aegis-os-v0.13.2-x86_64-apple-darwin.tar.gz"
      sha256 "7fb0c27c062671d84fd9b0ceb88268d92d18b3faa95c75029421e05b41b91a35"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.13.2/aegis-os-v0.13.2-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "8a1158345af01158098b3711f19e764a35bc493dd446d144662bb6eef7532f8e"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.13.2/aegis-os-v0.13.2-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "2ebe1fa4d3cb7bbdd2956508745544f48279683ca48b768e8c4d3ab0b1863f34"
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
